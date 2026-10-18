package scan_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
		"generic":   checkGeneric,
	}
	// Warnings a fixture is built to cause.
	expectedWarnings := map[string][]string{
		"generic": {"1 key of form_entries holds findings but isn't shown"},
	}
	writes := map[string]string{
		"wordpress": "INSERT INTO wp_options (option_name, option_value) VALUES ('prodmask_must_fail', 'x')",
		"magento2":  "UPDATE customer_entity SET firstname = 'x' WHERE entity_id = 1",
		"laravel":   "DELETE FROM migrations WHERE id = 1",
		"generic":   "DELETE FROM kv WHERE id = 1",
	}
	moreChecks := map[string]func(context.Context, *testing.T, *dbconn.Session){
		"wordpress": checkWordPressMore,
	}
	for _, platform := range fixture.Platforms {
		t.Run(platform, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			database := "prodmask_fixture_" + platform
			var planted fixture.Planted
			if err := fixture.Build(ctx, admin, platform, database, fixture.Options{Canary: canary, Planted: &planted}); err != nil {
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
			checkGolden(t, platform, res)

			outputs := render(t, res)
			for name, out := range outputs {
				if strings.Contains(out, canary) {
					t.Errorf("the %s output contains a sampled value", name)
				}
			}
			checkPlanted(t, platform, &planted, outputs)
			if platform == "generic" {
				checkGenericSecrets(t, res)
			}
			checkConfigTables(t, outputs["yml"])
			if dir := os.Getenv("PRODMASK_TEST_OUT"); dir != "" {
				for name, out := range outputs {
					path := filepath.Join(dir, platform+"."+name)
					if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
						t.Error(err)
					}
				}
			}
			for _, w := range res.Warnings {
				expected := strings.Contains(w, "scan user can change")
				for _, e := range expectedWarnings[platform] {
					expected = expected || strings.Contains(w, e)
				}
				if !expected {
					t.Errorf("unexpected warning: %s", w)
				}
			}
			checks[platform](t, res)
		})
	}
}

// checkGeneric checks the schema no preset knows: the shapes the old
// backups review found, and the tables that must stay plain.
func checkGeneric(t *testing.T, res *model.Result) {
	if len(res.Platforms) != 0 {
		t.Errorf("platforms detected: %+v", res.Platforms)
	}
	expectFindings(t, res, []want{
		// Passwords typed into a POST log, and a plain SMTP password.
		{"admin_login_logs", "admin_post_details", "", "password", model.CatSecret, model.SeverityCritical},
		{"admin_login_logs", "admin_post_details", "", "newpass", model.CatSecret, model.SeverityCritical},
		{"admin_login_logs", "admin_post_details", "", "set_password", model.CatSecret, model.SeverityCritical},
		{"settings", "setting_value", "smtp_password", "", model.CatSecret, model.SeverityCritical},
		{"admin", "pass", "", "", model.CatPasswordHash, model.SeverityHigh},
		{"members", "members_pass_hash", "", "", model.CatPasswordHash, model.SeverityHigh},
		// Names the rules missed, and IPs stored as bytes.
		{"members", "member_login_key", "", "", model.CatSecret, model.SeverityHigh},
		{"members", "hwid", "", "", model.CatDeviceID, model.SeverityMedium},
		{"members", "members_seo_name", "", "", model.CatUsername, model.SeverityMedium},
		{"members", "bday_day", "", "", model.CatDateOfBirth, model.SeverityHigh},
		{"members", "regip", "", "", model.CatIPAddress, model.SeverityMedium},
		{"members", "lastip", "", "", model.CatIPAddress, model.SeverityMedium},
		{"members", "poster_ip", "", "", model.CatIPAddress, model.SeverityMedium},
		{"game_logs", "summonername", "", "", model.CatUsername, model.SeverityMedium},
		// Messages, identifier lists and emails inside URLs.
		{"message_topics", "mt_title", "", "", model.CatFreeText, model.SeverityMedium},
		{"inline_notifications", "notify_text", "", "", model.CatFreeText, model.SeverityMedium},
		{"banfilters", "ban_content", "", "", model.CatFreeText, model.SeverityMedium},
		{"donations", "data", "", "callback_url", model.CatFreeText, model.SeverityMedium},
		// PayPal IPN fields by their parts.
		{"paypal_ipn", "ipn_data", "", "address_street", model.CatAddress, model.SeverityHigh},
		{"paypal_ipn", "ipn_data", "", "address_city", model.CatCity, model.SeverityMedium},
		{"paypal_ipn", "ipn_data", "", "address_zip", model.CatPostcode, model.SeverityMedium},
		{"paypal_ipn", "ipn_data", "", "address_name", model.CatPersonName, model.SeverityMedium},
		// Key/value tables found without a preset.
		{"setting", "value", "company_email", "", model.CatEmail, model.SeverityHigh},
		{"settings", "setting_value", "admin_email", "", model.CatEmail, model.SeverityHigh},
		{"form_entries", "field_value", "Phone number", "", model.CatPhone, model.SeverityHigh},
		{"form_entries", "field_value", "(key hidden)", "", model.CatPhone, model.SeverityHigh},
		{"cache_store", "cs_value", "settings", "email_in", model.CatEmail, model.SeverityHigh},
		// Tables that hold people keep their columns.
		{"contacts", "contact_name", "", "", model.CatPersonName, model.SeverityMedium},
		{"customers", "customer_name", "", "", model.CatPersonName, model.SeverityMedium},
		{"member_settings", "member_value", "", "", model.CatEmail, model.SeverityHigh},
		{"kv", "value", "", "", model.CatPhone, model.SeverityHigh},
	})
	// The demoted table's keys may be the people's names the guard read: a
	// weak match, so the starter config only suggests hashing them.
	if f := weakFindingAt(res, "kv", "key", model.CatPersonName); f == nil || f.Confidence != model.ConfidenceLow || f.Mask != "hash" {
		t.Errorf("kv.key: got %+v, want a low-confidence person name to hash", f)
	}
	// Labels, group names, wallets and hashed or binary IDs: no finding.
	for _, f := range res.Findings {
		if f.Confidence == model.ConfidenceLow {
			continue
		}
		switch {
		case f.Table == "ab_language_definitions", f.Table == "ab_customer_groups", f.Table == "content_cache_posts",
			f.Path == "input_address", f.Path == "address_status", f.Column == "device_uuid":
			t.Errorf("unexpected finding: %+v", f)
		}
	}
	// Hashed addresses aren't read as hex: medium by name, values not read.
	if f := findingAt(res, "members", "ip_hash", "", ""); f == nil || f.Confidence != model.ConfidenceMedium ||
		f.Sampled != 0 || !slices.Contains(f.Reasons, "values not sampled") {
		t.Errorf("members.ip_hash: got %+v, want medium by name, values not read", f)
	}
	tables := map[string]model.TableSummary{}
	for _, ts := range res.Tables {
		tables[ts.Name] = ts
	}
	for name, kind := range map[string]string{"setting": "key/value", "settings": "key/value", "form_entries": "key/value",
		"ab_language_definitions": "key/value", "cache_store": "key/value", "kv": "table", "contacts": "table",
		"customers": "table", "member_settings": "table"} {
		if tables[name].Kind != kind {
			t.Errorf("%s: kind %q, want %q", name, tables[name].Kind, kind)
		}
	}
	if ts := tables["form_entries"]; ts.HiddenKeys != 1 {
		t.Errorf("form_entries: %d hidden keys, want 1", ts.HiddenKeys)
	}
	for _, name := range []string{"content_cache_posts", "cache_store"} {
		if ts := tables[name]; ts.PossibleAction != "truncate" || ts.Action != "" {
			t.Errorf("%s: actions %q / %q, want a possible truncate only", name, ts.Action, ts.PossibleAction)
		}
	}
	// The binary columns' documentation addresses appear in no output, in
	// any form, including the hex of the ones stored as text.
	outputs := render(t, res)
	forms := []string{"192.0.2.", "198.51.100.", "203.0.113.", "2001:db8", "c00002", "c63364", "cb0071", "20010db8"}
	for _, prefix := range []string{"192.0.2.", "198.51.100.", "203.0.113."} {
		forms = append(forms, hex.EncodeToString([]byte(prefix)))
	}
	for name, out := range outputs {
		lower := strings.ToLower(out)
		for _, form := range forms {
			if strings.Contains(lower, form) {
				t.Errorf("the %s output contains %q", name, form)
			}
		}
	}
	// The starter config: a cache with nothing else is commented out, and
	// the hidden key gets a comment, not a rule.
	yml := outputs["yml"]
	for _, want := range []string{"\n  # content_cache_posts:\n  #   action: truncate  # looks like a cache",
		"\n  cache_store:\n    # action: truncate  # looks like a cache",
		"    # 1 key not shown holds: phone number; its values are copied unmasked unless you add a rule for it " +
			"(key column field_key, value column field_value)\n"} {
		if !strings.Contains(yml, want) {
			t.Errorf("the starter config is missing %q:\n%s", want, configTable(yml, "form_entries"))
		}
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
		// PayPal's NVP credentials stored as typed; the sandbox's rate high.
		{"wp_options", "option_value", "woocommerce_paypal_settings", "api_password", model.CatSecret, model.SeverityCritical},
		{"wp_options", "option_value", "woocommerce_paypal_settings", "sandbox_api_password", model.CatSecret, model.SeverityHigh},
		{"wp_options", "option_value", "woocommerce_paypal_settings", "api_signature", model.CatSecret, model.SeverityHigh},
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

// weakFindingAt returns a column's finding of a category, low confidence
// included.
func weakFindingAt(res *model.Result, table, column string, cat model.Category) *model.Finding {
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Table == table && f.Column == column && f.MetaKey == "" && f.Path == "" && f.Category == cat {
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
	checkGolden(t, "multisite", res)
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

// checkConfigTables checks the starter config's tables: section as a YAML
// parser would read it: every line sits inside it, every live table has a
// live line under it, and it holds either live tables or {}.
func checkConfigTables(t *testing.T, yml string) {
	t.Helper()
	_, section, ok := strings.Cut(yml, "\ntables:\n")
	if !ok {
		t.Fatal("the starter config has no tables: section")
	}
	section, _, _ = strings.Cut(section, "\n\n")
	lines := strings.Split(section, "\n")
	live, empty := 0, false
	for i, l := range lines {
		switch {
		case l == "":
			continue
		case !strings.HasPrefix(l, "  "):
			t.Errorf("starter config line %q is outside tables:", l)
			continue
		case strings.HasPrefix(l, "  {}"):
			empty = true
			continue
		case strings.HasPrefix(l, "   ") || strings.HasPrefix(l, "  #"):
			continue
		}
		live++
		next := ""
		for _, m := range lines[i+1:] {
			if !strings.HasPrefix(strings.TrimSpace(m), "#") {
				next = m
				break
			}
		}
		if !strings.HasPrefix(next, "    ") {
			t.Errorf("starter config table %q has nothing under it", l)
		}
	}
	if (live == 0) != empty {
		t.Errorf("the starter config's tables: holds %d live tables and {} %v", live, empty)
	}
}

// The key-shape guard decides before any key is looked up or probed, and a
// demoted table gets the plain table's window: when its keys are listed
// because it is too big to read whole, and when listing is turned off.
func TestKeyShapeGuardModes(t *testing.T) {
	admin, adminCfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	database := "prodmask_fixture_generic_modes"
	if err := fixture.Build(ctx, admin, "generic", database, fixture.Options{Canary: canary}); err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	// 30,000 rows keyed by eight people's names, with the key column indexed.
	db := "`" + database + "`."
	setup := "CREATE TABLE " + db + "kv_big (id int NOT NULL AUTO_INCREMENT, `key` varchar(191) NOT NULL, value text, " +
		"PRIMARY KEY (id), KEY k (`key`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;" +
		"CREATE TABLE " + db + "digits (d int);" +
		"INSERT INTO " + db + "digits VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9);" +
		"INSERT INTO " + db + "kv_big (`key`, value) SELECT ELT(1 + (a.d + 10*b.d) % 8, 'Jane Doe', 'John Roe', 'Ann Lee', " +
		"'Bob Ray', 'Tim Fox', 'Maria Day', 'Helen Smith', 'Kostas Ioannou'), '+30 210 555 0100' " +
		"FROM " + db + "digits a, " + db + "digits b, " + db + "digits c, " + db + "digits d, " + db + "digits e " +
		"WHERE a.d + 10*b.d + 100*c.d + 1000*d.d + 10000*e.d < 30000;" +
		"DROP TABLE " + db + "digits"
	if _, err := admin.ExecContext(ctx, setup); err != nil {
		t.Fatalf("build kv_big: %v", err)
	}
	rows, err := admin.QueryContext(ctx, "ANALYZE TABLE "+db+"kv_big")
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
	sess := openScan(ctx, t, adminCfg, database)
	if !sess.ServerTimeout {
		t.Skip("the server enforces no statement timeout, so keys aren't listed")
	}
	summary := func(res *model.Result, name string) model.TableSummary {
		for _, ts := range res.Tables {
			if ts.Name == name {
				return ts
			}
		}
		return model.TableSummary{}
	}
	opts := scan.Options{SampleRows: 30, MetaSampleRows: 300, Samples: true, Preset: "auto", Version: "test"}
	res, err := scan.Run(ctx, sess, opts)
	if err != nil {
		t.Fatal(err)
	}
	// Listed and demoted: no lookups, and the plain table's 30-row window.
	if ts := summary(res, "kv_big"); ts.Kind != "table" || ts.RowsSampled != 30 {
		t.Errorf("listed: kind %q, %d rows sampled, want a plain table and 30 rows", ts.Kind, ts.RowsSampled)
	}
	if f := weakFindingAt(res, "kv_big", "key", model.CatPersonName); f == nil || f.Confidence != model.ConfidenceLow {
		t.Errorf("kv_big.key: got %+v, want the people's names at low confidence", f)
	}
	opts.SampleKeysOnly = true
	if res, err = scan.Run(ctx, sess, opts); err != nil {
		t.Fatal(err)
	}
	// Sampled and demoted: no probes, and no word of sampled keys.
	for _, name := range []string{"kv", "kv_big"} {
		if ts := summary(res, name); ts.Kind != "table" {
			t.Errorf("sampled: %s is a %q, want a plain table", name, ts.Kind)
		}
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "kv was") || strings.Contains(w, "kv_big") || strings.Contains(w, "keys of kv ") {
			t.Errorf("warning about a demoted table: %s", w)
		}
	}
	// Keys read from the window alone stay hidden: form_entries holds the
	// canary in a key.
	if ts := summary(res, "form_entries"); ts.Kind != "key/value" || ts.HiddenKeys == 0 {
		t.Errorf("sampled: form_entries is a %q with %d hidden keys", ts.Kind, ts.HiddenKeys)
	}
	outputs := render(t, res)
	for name, out := range outputs {
		if strings.Contains(out, canary) {
			t.Errorf("the %s output of the sampled scan contains a sampled value", name)
		}
	}
	checkConfigTables(t, outputs["yml"])
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
	checkGolden(t, "wp_lookups", res)
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
			checkGolden(t, "wp_sampled_"+name, res)
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
