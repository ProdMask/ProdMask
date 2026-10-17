package scan_test

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/config"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// These tests build fake WordPress/WooCommerce, Magento 2 and Laravel
// databases on a real server and scan them. They need a user that can
// create databases, e.g.
//
//	PRODMASK_TEST_DSN='root:secret@tcp(127.0.0.1:3307)/' go test ./pkg/scan
//
// The databases (prodmask_fixture_*) are kept afterwards for manual runs.
// Set PRODMASK_TEST_OUT to a folder to also keep the rendered reports.

const canary = "zq7canary4x"

// testServer connects to the server in PRODMASK_TEST_DSN as a user that can
// create databases, or skips the test.
func testServer(t *testing.T) (*sql.DB, *mysql.Config) {
	t.Helper()
	dsn := os.Getenv("PRODMASK_TEST_DSN")
	if dsn == "" {
		t.Skip("PRODMASK_TEST_DSN is not set")
	}
	adminCfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminCfg.MultiStatements = true
	adminCfg.DBName = ""
	connector, err := mysql.NewConnector(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	t.Cleanup(func() { admin.Close() })
	return admin, adminCfg
}

// openScan opens a read-only scan session on one database.
func openScan(ctx context.Context, t *testing.T, adminCfg *mysql.Config, database string) *dbconn.Session {
	t.Helper()
	cfg := adminCfg.Clone()
	cfg.MultiStatements = false
	cfg.DBName = database
	sess, err := dbconn.Open(ctx, cfg, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func runScan(ctx context.Context, t *testing.T, sess *dbconn.Session, preset string) *model.Result {
	t.Helper()
	res, err := scan.Run(ctx, sess, scan.Options{
		SampleRows: scan.DefaultSampleRows, MetaSampleRows: scan.DefaultMetaSampleRows,
		Samples: true, Preset: preset, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestFixtures(t *testing.T) {
	admin, adminCfg := testServer(t)

	checks := map[string]func(*testing.T, *model.Result){
		"wordpress": checkWordPress,
		"magento2":  checkMagento,
		"laravel":   checkLaravel,
	}
	writes := map[string]string{
		"wordpress": "INSERT INTO wp_options (option_name, option_value) VALUES ('prodmask_must_fail', 'x')",
		"magento2":  "UPDATE customer_entity SET firstname = 'x' WHERE entity_id = 1",
		"laravel":   "DELETE FROM migrations WHERE id = 1",
	}
	moreChecks := map[string]func(context.Context, *testing.T, *dbconn.Session){
		"wordpress": checkWordPressMore,
	}
	for _, platform := range fixture.Platforms {
		t.Run(platform, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			database := "prodmask_fixture_" + platform
			if err := fixture.Build(ctx, admin, platform, database, fixture.Options{Canary: canary}); err != nil {
				t.Fatalf("build fixture: %v", err)
			}
			sess := openScan(ctx, t, adminCfg, database)

			if _, err := sess.DB.ExecContext(ctx, writes[platform]); err == nil {
				t.Fatal("the scan session accepted a write")
			}
			if check := moreChecks[platform]; check != nil {
				check(ctx, t, sess)
			}

			res := runScan(ctx, t, sess, "auto")

			outputs := render(t, res)
			for name, out := range outputs {
				if strings.Contains(out, canary) {
					t.Errorf("the %s output contains a sampled value", name)
				}
			}
			if dir := os.Getenv("PRODMASK_TEST_OUT"); dir != "" {
				for name, out := range outputs {
					path := filepath.Join(dir, platform+"."+name)
					if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
						t.Error(err)
					}
				}
			}
			for _, w := range res.Warnings {
				if !strings.Contains(w, "scan user can change") {
					t.Errorf("unexpected warning: %s", w)
				}
			}
			checks[platform](t, res)
		})
	}
}

func render(t *testing.T, res *model.Result) map[string]string {
	t.Helper()
	var text, md, js, yml bytes.Buffer
	if err := report.Text(&text, res, report.TextOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if err := report.Markdown(&md, res); err != nil {
		t.Fatal(err)
	}
	if err := report.JSON(&js, res); err != nil {
		t.Fatal(err)
	}
	if err := config.Write(&yml, res); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"txt": text.String(), "md": md.String(), "json": js.String(), "yml": yml.String()}
}

type want struct {
	table, column, key, path string
	cat                      model.Category
	min                      model.Severity
}

func expectFindings(t *testing.T, res *model.Result, wants []want) {
	t.Helper()
	for _, w := range wants {
		found := false
		for _, f := range res.Findings {
			if f.Table == w.table && f.Column == w.column && f.MetaKey == w.key && f.Path == w.path &&
				f.Category == w.cat && f.Severity >= w.min && f.Confidence > model.ConfidenceLow {
				found = true
				break
			}
		}
		if !found {
			var near []string
			for _, f := range res.Findings {
				if f.Table == w.table && f.Column == w.column && f.MetaKey == w.key {
					near = append(near, f.Path+":"+string(f.Category)+":"+f.Severity.String()+":"+f.Confidence.String())
				}
			}
			t.Errorf("missing %s finding at %s.%s[%s] %s (at least %s); found there: %v",
				w.cat, w.table, w.column, w.key, w.path, w.min, near)
		}
	}
}

func expectSideEffect(t *testing.T, res *model.Result, kind string, sev model.Severity, count int64) {
	t.Helper()
	for _, se := range res.SideEffects {
		if se.Kind == kind && se.Severity == sev && (count == 0 || se.Count == count) {
			return
		}
	}
	t.Errorf("missing %s side effect (%s, count %d) in %+v", kind, sev, count, res.SideEffects)
}

func expectRel(t *testing.T, res *model.Result, child, column, parent, status string) {
	t.Helper()
	for _, r := range res.Relationships {
		if r.ChildTable == child && strings.Join(r.ChildColumns, ",") == column && r.ParentTable == parent && r.Status == status {
			return
		}
	}
	t.Errorf("missing %s relationship %s.%s → %s", status, child, column, parent)
}

func expectAction(t *testing.T, res *model.Result, table string) {
	t.Helper()
	for _, ts := range res.Tables {
		if ts.Name == table && ts.Action == "truncate" {
			return
		}
	}
	t.Errorf("missing truncate advice for %s", table)
}

func expectPlatforms(t *testing.T, res *model.Result, names ...string) {
	t.Helper()
	got := map[string]bool{}
	for _, p := range res.Platforms {
		got[p.Name] = true
	}
	for _, n := range names {
		if !got[n] {
			t.Errorf("platform %s not detected (got %+v)", n, res.Platforms)
		}
	}
}

func checkWordPress(t *testing.T, res *model.Result) {
	expectPlatforms(t, res, "wordpress", "woocommerce")
	expectFindings(t, res, []want{
		{"wp_users", "user_email", "", "", model.CatEmail, model.SeverityHigh},
		{"wp_users", "user_pass", "", "", model.CatPasswordHash, model.SeverityHigh},
		{"wp_users", "display_name", "", "", model.CatPersonName, model.SeverityMedium},
		{"wp_usermeta", "meta_value", "billing_phone", "", model.CatPhone, model.SeverityHigh},
		{"wp_usermeta", "meta_value", "session_tokens", "", model.CatSecret, model.SeverityHigh},
		{"wp_usermeta", "meta_value", "session_tokens", "*.ip", model.CatIPAddress, model.SeverityMedium},
		{"wp_postmeta", "meta_value", "_billing_email", "", model.CatEmail, model.SeverityHigh},
		{"wp_postmeta", "meta_value", "_customer_ip_address", "", model.CatIPAddress, model.SeverityMedium},
		{"wp_comments", "comment_author_IP", "", "", model.CatIPAddress, model.SeverityMedium},
		{"wp_comments", "comment_agent", "", "", model.CatUserAgent, model.SeverityMedium},
		{"wp_commentmeta", "meta_value", "akismet_as_submitted", "user_ip", model.CatIPAddress, model.SeverityMedium},
		{"wp_options", "option_value", "woocommerce_stripe_settings", "secret_key", model.CatSecret, model.SeverityCritical},
		{"wp_options", "option_value", "wp_mail_smtp", "sendgrid.api_key", model.CatSecret, model.SeverityCritical},
		{"wp_options", "option_value", "as3cf_settings", "access-key-id", model.CatSecret, model.SeverityCritical},
		{"wp_wc_orders", "customer_note", "", "", model.CatFreeText, model.SeverityHigh},
		{"wp_wc_order_addresses", "phone", "", "", model.CatPhone, model.SeverityHigh},
		{"wp_woocommerce_sessions", "session_value", "", "customer.email", model.CatEmail, model.SeverityHigh},
		{"wp_woocommerce_api_keys", "consumer_secret", "", "", model.CatSecret, model.SeverityCritical},
		{"wp_woocommerce_payment_tokens", "token", "", "", model.CatPaymentToken, model.SeverityMedium},
	})
	expectSideEffect(t, res, "payments", model.SeverityHigh, 0)
	expectSideEffect(t, res, "payments", model.SeverityCritical, 6)
	expectSideEffect(t, res, "email", model.SeverityHigh, 0)
	expectSideEffect(t, res, "webhooks", model.SeverityHigh, 2)
	expectSideEffect(t, res, "scheduled_jobs", model.SeverityMedium, 40)
	expectRel(t, res, "wp_postmeta", "post_id", "wp_posts", model.RelConfirmed)
	expectRel(t, res, "wp_usermeta", "user_id", "wp_users", model.RelConfirmed)
	expectRel(t, res, "wp_woocommerce_order_items", "order_id", "wp_wc_orders", model.RelConfirmed)
	expectRel(t, res, "wp_wc_order_addresses", "order_id", "wp_wc_orders", model.RelConfirmed)
	expectAction(t, res, "wp_woocommerce_sessions")
	expectOrderKeysNulled(t, res, "wp_posts", model.SeverityMedium)
}

// checkWordPressMore checks that the fixture stores legacy orders the way
// WooCommerce does, with each order's key in post_password, and that a scan
// with the WordPress preset alone doesn't suggest keeping those keys either.
func checkWordPressMore(ctx context.Context, t *testing.T, sess *dbconn.Session) {
	var orders, keyed int
	err := sess.DB.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(p.post_password = m.meta_value), 0)
		FROM wp_posts p JOIN wp_postmeta m ON m.post_id = p.ID AND m.meta_key = '_order_key'
		WHERE p.post_type = 'shop_order'`).Scan(&orders, &keyed)
	if err != nil {
		t.Fatal(err)
	}
	if orders == 0 || keyed != orders {
		t.Errorf("%d of %d legacy orders keep their order key in post_password", keyed, orders)
	}
	expectOrderKeysNulled(t, runScan(ctx, t, sess, "wordpress"), "wp_posts", model.SeverityLow)
}

// A multisite network where only the second site runs WooCommerce. Each
// site's posts table nulls its order rows, and only the shop's is rated as
// holding order keys.
func TestWordPressMultisite(t *testing.T) {
	admin, adminCfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const db = "prodmask_fixture_multisite"
	stmts := []string{
		"DROP DATABASE IF EXISTS " + db,
		"CREATE DATABASE " + db + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		"CREATE TABLE " + db + ".wp_users (ID bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, user_login varchar(60) NOT NULL DEFAULT '')",
	}
	for _, p := range []string{"wp_", "wp_2_"} {
		stmts = append(stmts,
			"CREATE TABLE "+db+"."+p+"options (option_id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, "+
				"option_name varchar(191) NOT NULL DEFAULT '', option_value longtext NOT NULL, UNIQUE KEY option_name (option_name))",
			"CREATE TABLE "+db+"."+p+"posts (ID bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, "+
				"post_type varchar(20) NOT NULL DEFAULT 'post', post_password varchar(255) NOT NULL DEFAULT '')",
			"CREATE TABLE "+db+"."+p+"postmeta (meta_id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, "+
				"post_id bigint unsigned NOT NULL DEFAULT 0, meta_key varchar(255) DEFAULT NULL, meta_value longtext)",
			"INSERT INTO "+db+"."+p+"options (option_name, option_value) VALUES ('db_version', '60421')",
			"INSERT INTO "+db+"."+p+"posts (post_type, post_password) VALUES ('page', 'members only')",
		)
	}
	stmts = append(stmts,
		"INSERT INTO "+db+".wp_2_options (option_name, option_value) VALUES ('woocommerce_version', '9.3.3')",
		"INSERT INTO "+db+".wp_2_posts (post_type, post_password) VALUES ('shop_order', 'wc_order_"+strings.Repeat("x", 13)+"')",
	)
	for _, s := range stmts {
		if _, err := admin.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	res := runScan(ctx, t, openScan(ctx, t, adminCfg, db), "auto")
	expectPlatforms(t, res, "wordpress", "woocommerce")
	expectOrderKeysNulled(t, res, "wp_posts", model.SeverityLow)
	expectOrderKeysNulled(t, res, "wp_2_posts", model.SeverityMedium)
}

const orderRows = "post_type IN ('shop_order', 'shop_order_refund', 'shop_order_placehold', 'shop_subscription')"

// expectOrderKeysNulled checks that the scan suggests keeping a site's post
// passwords, but not the order keys WooCommerce stores in the same column.
func expectOrderKeysNulled(t *testing.T, res *model.Result, table string, sev model.Severity) {
	t.Helper()
	var f *model.Finding
	for i := range res.Findings {
		if g := &res.Findings[i]; g.Table == table && g.Column == "post_password" && g.Category == model.CatSecret {
			f = g
		}
	}
	if f == nil {
		t.Errorf("no secret finding for %s.post_password", table)
		return
	}
	rows := model.RowMask{Where: orderRows, Mask: "null", Note: "WooCommerce order keys; anyone with one in a link can view the order"}
	if f.Mask != "keep" || f.Severity != sev || len(f.RowMasks) != 1 || f.RowMasks[0] != rows {
		t.Errorf("%s.post_password: got mask %q, severity %s, row masks %+v; want keep, %s, null for order rows",
			table, f.Mask, f.Severity, f.RowMasks, sev)
	}
	var yml bytes.Buffer
	if err := config.Write(&yml, res); err != nil {
		t.Fatal(err)
	}
	section := configTable(yml.String(), table)
	want := "      post_password:\n        mask: keep  # secret, key or token, high confidence;"
	wantRows := "          - where: \"" + orderRows + "\"\n            mask: \"null\"  # WooCommerce order keys;"
	if !strings.Contains(section, want) || !strings.Contains(section, wantRows) {
		t.Errorf("the starter config does not null order keys in %s.post_password:\n%s", table, section)
	}
}

// configTable returns one table's section of a starter config.
func configTable(yml, table string) string {
	start := strings.Index(yml, "\n  "+table+":\n")
	if start < 0 {
		return ""
	}
	lines := strings.SplitAfter(yml[start+1:], "\n")
	section := lines[0]
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "    ") {
			break
		}
		section += l
	}
	return section
}

func checkMagento(t *testing.T, res *model.Result) {
	expectPlatforms(t, res, "magento2")
	expectFindings(t, res, []want{
		{"customer_entity", "email", "", "", model.CatEmail, model.SeverityHigh},
		{"customer_entity", "taxvat", "", "", model.CatNationalID, model.SeverityHigh},
		{"customer_entity", "password_hash", "", "", model.CatPasswordHash, model.SeverityHigh},
		{"customer_entity", "dob", "", "", model.CatDateOfBirth, model.SeverityHigh},
		{"customer_entity_varchar", "value", "mobile_phone", "", model.CatPhone, model.SeverityHigh},
		{"customer_address_entity", "street", "", "", model.CatAddress, model.SeverityHigh},
		{"customer_grid_flat", "billing_full", "", "", model.CatAddress, model.SeverityHigh},
		{"core_config_data", "value", "payment/braintree/private_key", "", model.CatSecret, model.SeverityHigh},
		{"sales_order", "remote_ip", "", "", model.CatIPAddress, model.SeverityMedium},
		{"sales_order", "x_forwarded_for", "", "", model.CatIPAddress, model.SeverityMedium},
		{"sales_order", "customer_note", "", "", model.CatFreeText, model.SeverityMedium},
		{"sales_order_payment", "cc_number_enc", "", "", model.CatCardNumber, model.SeverityHigh},
		{"sales_order_payment", "cc_owner", "", "", model.CatPersonName, model.SeverityMedium},
		{"newsletter_subscriber", "subscriber_email", "", "", model.CatEmail, model.SeverityHigh},
		{"quote", "remote_ip", "", "", model.CatIPAddress, model.SeverityMedium},
	})
	expectSideEffect(t, res, "payments", model.SeverityHigh, 0)
	expectSideEffect(t, res, "email", model.SeverityMedium, 0)
	expectSideEffect(t, res, "email", model.SeverityHigh, 7)
	expectSideEffect(t, res, "scheduled_jobs", model.SeverityMedium, 50)
	expectRel(t, res, "sales_order", "customer_id", "customer_entity", model.RelConfirmed)
	expectRel(t, res, "customer_address_entity", "parent_id", "customer_entity", model.RelDeclared)
	expectAction(t, res, "customer_visitor")
	expectAction(t, res, "cron_schedule")
}

func checkLaravel(t *testing.T, res *model.Result) {
	expectPlatforms(t, res, "laravel")
	expectFindings(t, res, []want{
		{"users", "email", "", "", model.CatEmail, model.SeverityHigh},
		{"users", "name", "", "", model.CatPersonName, model.SeverityMedium},
		{"users", "password", "", "", model.CatPasswordHash, model.SeverityHigh},
		{"users", "remember_token", "", "", model.CatSecret, model.SeverityHigh},
		{"users", "stripe_id", "", "", model.CatPaymentToken, model.SeverityMedium},
		{"sessions", "ip_address", "", "", model.CatIPAddress, model.SeverityMedium},
		{"jobs", "payload", "", "data.command.email", model.CatEmail, model.SeverityHigh},
		{"failed_jobs", "exception", "", "", model.CatFreeText, model.SeverityMedium},
		{"notifications", "data", "", "customer.email", model.CatEmail, model.SeverityHigh},
		{"notifications", "data", "", "shipping.line1", model.CatAddress, model.SeverityHigh},
		{"orders", "shipping_address", "", "phone", model.CatPhone, model.SeverityHigh},
		{"orders", "notes", "", "", model.CatFreeText, model.SeverityMedium},
		{"password_reset_tokens", "email", "", "", model.CatEmail, model.SeverityHigh},
	})
	expectSideEffect(t, res, "queued_jobs", model.SeverityMedium, 12)
	expectRel(t, res, "orders", "user_id", "users", model.RelDeclared)
	expectRel(t, res, "posts", "user_id", "users", model.RelConfirmed)
	expectRel(t, res, "comments", "commentable_id", "posts", model.RelConfirmed)
	expectRel(t, res, "comments", "commentable_id", "orders", model.RelConfirmed)
	expectRel(t, res, "notifications", "notifiable_id", "users", model.RelConfirmed)
	expectAction(t, res, "sessions")
	expectAction(t, res, "jobs")
}
