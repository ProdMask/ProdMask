package scan_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/config"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/introspect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/sample"
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
		// Secrets in settings, some of them deep inside big arrays.
		{"wp_options", "option_value", "secret_key", "", model.CatSecret, model.SeverityHigh},
		{"wp_options", "option_value", "wp_mail_smtp_mail_key", "", model.CatSecret, model.SeverityHigh},
		{"wp_options", "option_value", "wpgmza_temp_api", "", model.CatSecret, model.SeverityCritical},
		{"wp_options", "option_value", "fixture_hashids_salt", "", model.CatSecret, model.SeverityHigh},
		{"wp_options", "option_value", "rank-math-options-titles", "facebook_secret", model.CatSecret, model.SeverityHigh},
		// Visitor IPs as array keys.
		{"wp_options", "option_value", "limit_login_lockouts", "{}", model.CatIPAddress, model.SeverityMedium},
		{"wp_options", "option_value", "limit_login_logged", "{}", model.CatIPAddress, model.SeverityMedium},
		{"wp_options", "option_value", "limit_login_retries", "{}", model.CatIPAddress, model.SeverityMedium},
		{"wp_options", "option_value", "limit_login_retries_valid", "{}", model.CatIPAddress, model.SeverityMedium},
		// Staff addresses in settings, and keys only a full read finds.
		{"wp_options", "option_value", "woocommerce_new_order_settings", "recipient", model.CatEmail, model.SeverityHigh},
		{"wp_options", "option_value", "woocommerce_cancelled_order_settings", "recipient", model.CatEmail, model.SeverityHigh},
		{"wp_options", "option_value", "fixture_admin_recipient", "", model.CatEmail, model.SeverityHigh},
		{"wp_postmeta", "meta_value", "customer_email", "[]", model.CatEmail, model.SeverityHigh},
		{"wp_postmeta", "meta_value", "_mail", "recipient", model.CatEmail, model.SeverityHigh},
		{"wp_postmeta", "meta_value", "_bbp_author_ip", "", model.CatIPAddress, model.SeverityMedium},
		// Key names that hold data, and logins and names that are addresses.
		{"wp_usermeta", "meta_value", "um_email_as_username_*", "", model.CatEmail, model.SeverityHigh},
		{"wp_usermeta", "meta_key", "um_email_as_username_*", "", model.CatEmail, model.SeverityHigh},
		{"wp_users", "user_login", "", "", model.CatEmail, model.SeverityHigh},
		{"wp_users", "display_name", "", "", model.CatEmail, model.SeverityHigh},
		{"wp_um_metadata", "um_value", "mobile_number", "", model.CatPhone, model.SeverityHigh},
	})
	checkWordPressKeys(t, res)
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

// findingAt returns the first confident finding at a location, or nil.
func findingAt(res *model.Result, table, column, key, path string) *model.Finding {
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Table == table && f.Column == column && f.MetaKey == key && f.Path == path && f.Confidence > model.ConfidenceLow {
			return f
		}
	}
	return nil
}

func expectSideEffectLike(t *testing.T, res *model.Result, kind string, sev model.Severity, summary string) {
	t.Helper()
	for _, se := range res.SideEffects {
		if se.Kind == kind && se.Severity == sev && strings.Contains(se.Summary, summary) {
			return
		}
	}
	t.Errorf("missing %s side effect (%s) saying %q", kind, sev, summary)
}

// checkWordPressKeys checks key families, row subjects, the names that only
// look sensitive, and the new side effects.
func checkWordPressKeys(t *testing.T, res *model.Result) {
	t.Helper()
	if f := findingAt(res, "wp_options", "option_value", "um_cache_userdata_*", ""); f == nil || f.Mask != "delete" ||
		f.Keys != 60 || f.KeysPartial {
		t.Errorf("Ultimate Member caches: got %+v", f)
	}
	for _, column := range []string{"meta_key", "meta_value"} {
		f := findingAt(res, "wp_usermeta", column, "um_email_as_username_*", "")
		if f == nil || f.Keys != 6 || f.KeysPartial || f.KeyName != (column == "meta_key") {
			t.Errorf("UM email keys, %s: got %+v", column, f)
		}
	}
	found := false
	for _, f := range res.Findings {
		if f.Table == "wp_posts" && f.Column == "post_title" && f.Where == requestRows && f.Category == model.CatEmail &&
			f.Confidence > model.ConfidenceLow {
			found = true
		}
	}
	if !found {
		t.Error("privacy request titles are not reported")
	}
	// A login column where a sixth of the values are addresses keeps its mask.
	if f := findingAt(res, "wp_users", "user_login", "", ""); f == nil {
		t.Error("no user_login finding")
	}
	for _, f := range res.Findings {
		if f.Table == "wp_users" && f.Column == "user_login" && f.Category == model.CatEmail && f.Mask != "fake_username" {
			t.Errorf("user_login email finding suggests %q", f.Mask)
		}
	}
	// Names that only look sensitive.
	for _, l := range []struct{ table, column, key string }{
		{"wp_options", "option_value", "fixture_db_version"},
		{"wp_options", "option_value", "woocommerce_registration_generate_password"},
		{"wp_options", "option_value", "woocommerce_myaccount_lost_password_endpoint"},
		{"wp_options", "option_value", "woocommerce_myaccount_edit_address_endpoint"},
		{"wp_options", "option_value", "woocommerce_email_background_color"},
		{"wp_options", "option_value", "woocommerce_eu_vat_number_validate"},
		{"wp_options", "option_value", "_transient_fixture_customer_email"},
		{"wp_usermeta", "meta_value", "default_password_nag"},
		{"wp_wc_admin_notes", "name", ""},
		{"wp_wt_iew_mapping_template", "data", ""},
	} {
		for _, f := range res.Findings {
			if f.Table == l.table && f.Column == l.column && f.MetaKey == l.key && f.Confidence > model.ConfidenceLow {
				t.Errorf("%s.%s[%s] → %s: %s at %s confidence, want nothing confident", l.table, l.column, l.key, f.Path,
					f.Category, f.Confidence)
			}
		}
	}
	kinds := map[string]string{}
	for _, ts := range res.Tables {
		kinds[ts.Name] = ts.Kind
	}
	if kinds["wp_um_metadata"] != "key/value" || kinds["wp_woocommerce_sessions"] != "table" {
		t.Errorf("table kinds: um_metadata %q, woocommerce_sessions %q", kinds["wp_um_metadata"], kinds["wp_woocommerce_sessions"])
	}
	expectSideEffect(t, res, "scheduled_jobs", model.SeverityMedium, 5)
	expectSideEffectLike(t, res, "backups", model.SeverityHigh, "Amazon S3")
	expectSideEffectLike(t, res, "email", model.SeverityMedium, "WooCommerce emails store staff about new and cancelled orders")
	expectSideEffectLike(t, res, "email", model.SeverityMedium, "1 plugin setting sends notification emails")
	expectSideEffectLike(t, res, "email", model.SeverityMedium, "1 Contact Form 7 form emails its submissions")
	expectSideEffectLike(t, res, "email", model.SeverityHigh, "2 WooCommerce Memberships emails are enabled")
	expectSideEffectLike(t, res, "connection", model.SeverityHigh, "Jetpack")
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
			"INSERT INTO "+db+"."+p+"options (option_name, option_value) VALUES ('db_version', '60421'), "+
				"('fixture_admin_recipient', 'manager@fixture-store.gr')",
			"INSERT INTO "+db+"."+p+"posts (post_type, post_password) VALUES ('page', 'members only')",
		)
	}
	stmts = append(stmts,
		"INSERT INTO "+db+".wp_2_options (option_name, option_value) VALUES ('woocommerce_version', '9.3.3'), "+
			"('fixture_b_recipient', 'staff@fixture-store.gr'), ('fixture_a_recipient', 'owner@fixture-store.gr')",
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
	// Each example once, in order, whichever site it came from.
	expectSideEffectLike(t, res, "email", model.SeverityMedium, "4 plugin settings on 2 sites send notification emails "+
		"to staff addresses (for example fixture_a_recipient, fixture_admin_recipient, fixture_b_recipient)")
}

const (
	orderRows   = "post_type IN ('shop_order', 'shop_order_refund', 'shop_order_placehold', 'shop_subscription')"
	requestRows = "post_type = 'user_request'"
)

// expectOrderKeysNulled checks that the scan suggests keeping a site's post
// passwords, but not the order keys WooCommerce stores in the same column,
// nor the hashed confirmation keys of privacy requests.
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
	rows := []model.RowMask{
		{Where: orderRows, Mask: "null", Note: "WooCommerce order keys; anyone with one in a link can view the order"},
		{Where: requestRows, Mask: "null", Note: "the hashed confirmation key of a privacy request"},
	}
	if f.Mask != "keep" || f.Severity != sev || !reflect.DeepEqual(f.RowMasks, rows) {
		t.Errorf("%s.post_password: got mask %q, severity %s, row masks %+v; want keep, %s, null for orders and privacy requests",
			table, f.Mask, f.Severity, f.RowMasks, sev)
	}
	var yml bytes.Buffer
	if err := config.Write(&yml, res); err != nil {
		t.Fatal(err)
	}
	section := configTable(yml.String(), table)
	want := "      post_password:\n        mask: keep  # secret, key or token, high confidence;"
	wantRows := "          - where: \"" + orderRows + "\"\n            mask: \"null\"  # WooCommerce order keys;"
	wantRequests := "          - where: \"" + requestRows + "\"\n            mask: \"null\"  # the hashed confirmation key"
	if !strings.Contains(section, want) || !strings.Contains(section, wantRows) || !strings.Contains(section, wantRequests) {
		t.Errorf("the starter config does not null order and request keys in %s.post_password:\n%s", table, section)
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
		// Sparse columns stay reported though every sampled value is empty.
		{"admin_user", "rp_token", "", "", model.CatSecret, model.SeverityHigh},
		{"customer_address_entity", "fax", "", "", model.CatPhone, model.SeverityHigh},
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

// buildWordPress makes a fresh copy of the WordPress fixture.
func buildWordPress(ctx context.Context, t *testing.T, admin *sql.DB, database string) {
	t.Helper()
	if err := fixture.Build(ctx, admin, "wordpress", database, fixture.Options{Canary: canary}); err != nil {
		t.Fatalf("build fixture: %v", err)
	}
}

// With small windows, keys deep inside a big key/value table are found
// only by listing the keys and looking each one up.
func TestWordPressLookups(t *testing.T) {
	admin, adminCfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	const db = "prodmask_fixture_wp_lookups"
	buildWordPress(ctx, t, admin, db)
	var rows, keys int
	if err := admin.QueryRowContext(ctx, "SELECT COUNT(*), COUNT(DISTINCT meta_key) FROM "+db+".wp_postmeta").Scan(&rows, &keys); err != nil {
		t.Fatal(err)
	}
	if rows <= 20000 {
		t.Fatalf("wp_postmeta has %d rows; the fixture must be too big to read whole", rows)
	}
	sess := openScan(ctx, t, adminCfg, db)
	res, err := scan.Run(ctx, sess, scan.Options{SampleRows: 30, MetaSampleRows: 30, Samples: true, Preset: "auto", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ts := range res.Tables {
		if ts.Name == "wp_postmeta" && ts.Keys != keys {
			t.Errorf("wp_postmeta: %d keys read, want %d", ts.Keys, keys)
		}
	}
	// The four replies sit at a quarter and three quarters of the table,
	// outside every 30-row window: only lookups read them.
	if f := findingAt(res, "wp_postmeta", "meta_value", "_bbp_author_ip", ""); f == nil || f.Sampled != 4 {
		t.Errorf("_bbp_author_ip: got %+v", f)
	}
	for _, w := range res.Warnings {
		if !strings.Contains(w, "scan user can change") {
			t.Errorf("unexpected warning: %s", w)
		}
	}
}

// A run that only samples key/value tables, as for tables too big to list,
// still finds the keys presets know through probes: indexed lookups, or,
// once the key columns have lost their indexes, one pass over each table.
func TestWordPressSampled(t *testing.T) {
	admin, adminCfg := testServer(t)
	for _, unindexed := range []bool{false, true} {
		name, db := "indexed", "prodmask_fixture_wp_sampled"
		if unindexed {
			name, db = "unindexed", "prodmask_fixture_wp_unindexed"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			buildWordPress(ctx, t, admin, db)
			if unindexed {
				_, err := admin.ExecContext(ctx, "ALTER TABLE "+db+".wp_options DROP INDEX option_name; "+
					"ALTER TABLE "+db+".wp_usermeta DROP INDEX meta_key; ALTER TABLE "+db+".wp_postmeta DROP INDEX meta_key")
				if err != nil {
					t.Fatal(err)
				}
			}
			sess := openScan(ctx, t, adminCfg, db)
			res, err := scan.Run(ctx, sess, scan.Options{SampleRows: 30, MetaSampleRows: 30, Samples: true, SampleKeysOnly: true,
				Preset: "auto", Version: "test"})
			if err != nil {
				t.Fatal(err)
			}
			checkSampled(t, res)
			if unindexed {
				checkProbeLimits(ctx, t, sess, db)
			}
		})
	}
}

func checkSampled(t *testing.T, res *model.Result) {
	t.Helper()
	// The 60 caches sit outside the window: the prefix probe reads 20.
	if f := findingAt(res, "wp_options", "option_value", "um_cache_userdata_*", ""); f == nil || f.Keys != 20 || !f.KeysPartial {
		t.Errorf("Ultimate Member caches: got %+v", f)
	}
	if f := findingAt(res, "wp_usermeta", "meta_value", "um_email_as_username_*", ""); f == nil || f.Keys != 6 || f.KeysPartial {
		t.Errorf("UM email keys: got %+v", f)
	}
	expectFindings(t, res, []want{
		{"wp_options", "option_value", "secret_key", "", model.CatSecret, model.SeverityHigh},
		{"wp_options", "option_value", "wp_mail_smtp_mail_key", "", model.CatSecret, model.SeverityHigh},
		{"wp_postmeta", "meta_value", "_bbp_author_ip", "", model.CatIPAddress, model.SeverityMedium},
		{"wp_postmeta", "meta_value", "customer_email", "[]", model.CatEmail, model.SeverityHigh},
		{"wp_postmeta", "meta_value", "_mail", "recipient", model.CatEmail, model.SeverityHigh},
	})
	sampled := 0
	for _, w := range res.Warnings {
		switch {
		case strings.Contains(w, "were sampled, not listed"):
			sampled++
		case strings.Contains(w, "no index on option_name"): // the unindexed copy skips the settings checks
		case !strings.Contains(w, "scan user can change"):
			t.Errorf("unexpected warning: %s", w)
		}
	}
	if sampled == 0 {
		t.Error("no warning says the keys were sampled")
	}
	outputs := render(t, res)
	for name, out := range outputs {
		if strings.Contains(out, canary) {
			t.Errorf("the %s output contains a sampled value", name)
		}
	}
	for _, name := range []string{"txt", "md"} {
		if !strings.Contains(outputs[name], "at least 20 keys") {
			t.Errorf("the %s report does not say the cache count is partial", name)
		}
	}
	if !strings.Contains(outputs["json"], `"keys_partial": true`) {
		t.Error("the JSON report does not flag the partial count")
	}
}

// checkProbeLimits reads wp_options of a copy without its option_name index
// under a 1,000-byte cap. The 60 caches come before secret_key in the table,
// and each holds a few hundred bytes. No test value is printed.
func checkProbeLimits(ctx context.Context, t *testing.T, sess *dbconn.Session, db string) {
	t.Helper()
	schema, err := introspect.Load(ctx, sess.DB, db)
	if err != nil {
		t.Fatal(err)
	}
	tbl := schema.Table("wp_options")
	key, value := tbl.Column("option_name"), tbl.Column("option_value")
	sm := &sample.Sampler{DB: sess.DB, MaxValueLen: 4096, Timeout: time.Minute}

	// One pass: the busy family can't crowd out the rare key, the cap keeps
	// the first lookups whole, and no row comes back without its value.
	lookups := []sample.Lookup{{Key: "secret_key", Limit: 1}, {Key: "um_cache_userdata_", Prefix: true, Limit: 20}}
	got, err := sm.ProbeScan(ctx, tbl, key, value, lookups, 4096, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if rows := got.Rows[0]; len(rows) != 1 || rows[0].Value == "" || !got.Complete[0] {
		t.Errorf("secret_key: %d rows, complete %v", len(rows), got.Complete[0])
	}
	if n := len(got.Rows[1]); n == 0 || n >= 20 || got.Complete[1] {
		t.Errorf("caches: %d rows, complete %v; the cap should have cut them", n, got.Complete[1])
	}
	for i, rows := range got.Rows {
		for _, r := range rows {
			if r.Value == "" && !r.Null {
				t.Errorf("lookup %d returned a row whose value wasn't read", i)
			}
		}
	}

	// Batched lookups: those before the cut ran to their end, the rest
	// didn't run.
	lookups = nil
	for i := 1; i <= 60; i++ {
		lookups = append(lookups, sample.Lookup{Key: fmt.Sprintf("um_cache_userdata_%d", i), Limit: 1})
	}
	got, err = sm.KeyValuesBatch(ctx, tbl, key, value, lookups, 4096, 1000)
	if err != nil {
		t.Fatal(err)
	}
	done := 0
	for done < len(got.Complete) && got.Complete[done] {
		done++
	}
	if done == 0 || done >= 50 {
		t.Errorf("%d lookups complete; the cap should cut the first batch", done)
	}
	for i := done; i < len(lookups); i++ {
		if got.Complete[i] || (i > done && len(got.Rows[i]) > 0) {
			t.Errorf("lookup %d after the cut: complete %v, %d rows", i, got.Complete[i], len(got.Rows[i]))
		}
	}
}

// Lookups and probes bind their keys, so they run as prepared statements:
// the server's statement time limit must stop those too.
func TestPreparedStatementTimeout(t *testing.T) {
	_, adminCfg := testServer(t)
	ctx := context.Background()
	cfg := adminCfg.Clone()
	cfg.MultiStatements = false
	cfg.DBName = "information_schema"
	sess, err := dbconn.Open(ctx, cfg, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if !sess.ServerTimeout {
		t.Skip("the server has no statement timeout")
	}
	start := time.Now()
	rows, err := sess.DB.QueryContext(ctx, "SELECT SLEEP(?)", 5)
	if err == nil {
		for rows.Next() {
		}
		err = rows.Err()
		rows.Close()
	}
	// MariaDB fails the statement; MySQL ends a lone SLEEP early instead.
	if took := time.Since(start); took > 4*time.Second {
		t.Fatalf("a prepared statement ran for %s under a 1s limit (%s)", took.Round(time.Millisecond), dbconn.ErrorText(err))
	}
}
