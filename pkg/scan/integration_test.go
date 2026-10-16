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

func TestFixtures(t *testing.T) {
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
	defer admin.Close()

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
	for _, platform := range fixture.Platforms {
		t.Run(platform, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			database := "prodmask_fixture_" + platform
			if err := fixture.Build(ctx, admin, platform, database, fixture.Options{Canary: canary}); err != nil {
				t.Fatalf("build fixture: %v", err)
			}
			cfg := adminCfg.Clone()
			cfg.MultiStatements = false
			cfg.DBName = database
			sess, err := dbconn.Open(ctx, cfg, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()

			if _, err := sess.DB.ExecContext(ctx, writes[platform]); err == nil {
				t.Fatal("the scan session accepted a write")
			}

			res, err := scan.Run(ctx, sess, scan.Options{
				SampleRows: scan.DefaultSampleRows, MetaSampleRows: scan.DefaultMetaSampleRows,
				Samples: true, Preset: "auto", Version: "test",
			})
			if err != nil {
				t.Fatal(err)
			}

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
