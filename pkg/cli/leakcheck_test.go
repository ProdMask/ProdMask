package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/leak"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
)

// keyShaped is what a key looks like, typed in the wrong place.
func keyShaped() string { return hex.EncodeToString([]byte("0123456789abcdefGHIJKLMNOPQRSTUV")) }

func TestLeakCheckHelp(t *testing.T) {
	app := New("1.2.3")
	for _, args := range [][]string{{"leak-check", "-h"}, {"leak-check", "--help"}, {"leak-check", "help"}} {
		code, stdout, stderr := run(app, args...)
		if code != ExitOK || stdout != "" || !strings.HasPrefix(stderr, "Usage: prodmask leak-check key|hash|compare [flags]\n") {
			t.Errorf("%q: status %d\n%s%s", args, code, stdout, stderr)
		}
	}
	if code, _, stderr := run(app, "leak-check"); code != ExitUsage || !strings.HasPrefix(stderr, "Usage:") {
		t.Errorf("no verb: status %d\n%s", code, stderr)
	}
	for verb, want := range map[string][]string{
		"key":     {"Usage: prodmask leak-check key --out FILE", "-out"},
		"hash":    {"Usage: prodmask leak-check hash --dsn PRODUCTION --out FILE [flags]", "Exit status: 0 done, 1 error or nothing to hash, 2 bad usage.", "-allow-email", "-key-file"},
		"compare": {"Usage: prodmask leak-check compare --dsn STAGING --hashes FILE [flags]", "3 a sampled value at or above --fail-on", "-fail-except", "-max-time", "never point it at production"},
	} {
		code, stdout, stderr := run(app, "leak-check", verb, "-h")
		if code != ExitOK || stdout != "" {
			t.Errorf("%s -h: status %d", verb, code)
		}
		for _, w := range want {
			if !strings.Contains(stderr, w) {
				t.Errorf("%s -h has no %q:\n%s", verb, w, stderr)
			}
		}
	}
}

// Whatever is typed in the wrong place may be a key or a DSN with its
// password: no error repeats it.
func TestLeakCheckNeverEchoesArguments(t *testing.T) {
	t.Setenv(keyEnv, "")
	secret := keyShaped()
	dir := t.TempDir()
	key := filepath.Join(dir, "leak.key")
	if code, _, stderr := run(New("1.2.3"), "leak-check", "key", "--out", key); code != ExitOK {
		t.Fatalf("key: %d\n%s", code, stderr)
	}
	hashesMissing := filepath.Join(dir, secret)
	cases := [][]string{
		{secret},
		{"--" + secret},
		{"hash", secret},
		{"hash", "--" + secret},
		{"hash", "--force", secret},
		{"hash", "--timeout", secret},
		{"hash", "--timeout=" + secret},
		{"hash", "--preset", secret, "--out", filepath.Join(dir, "x")},
		{"hash", "--allow-email", secret, "--out", filepath.Join(dir, "x")},
		{"hash", "--dsn", secret, "--key-file", key, "--out", filepath.Join(dir, "x")},
		{"hash", "--dsn", "mysql://ro:12/" + secret + "@db.example.test:3306/shop", "--key-file", key, "--out", filepath.Join(dir, "x")},
		{"hash", "--key-file", secret, "--dsn", "mysql://u@127.0.0.1:1/x", "--out", filepath.Join(dir, "x")},
		{"hash", "--key", secret},
		{"hash", "--key=" + secret},
		{"compare", secret},
		{"compare", "--" + secret},
		{"compare", "--force", secret},
		{"compare", "--max-time", secret},
		{"compare", "--max-time=" + secret},
		{"compare", "--fail-on", secret, "--hashes", "x"},
		{"compare", "--format", secret, "--hashes", "x"},
		{"compare", "--hashes", secret},
		{"compare", "--hashes", hashesMissing, "--key-file", key},
		{"compare", "--hashes", hashesMissing, "--key-file", secret},
		{"compare", "--allow-email", secret, "--hashes", "x"},
		{"compare", "--dsn", secret, "--hashes", "x"},
		{"compare", "--key", secret},
		{"key", secret},
		{"key", "--" + secret},
		{"key", "--out", filepath.Join(dir, "no", "such", secret)},
	}
	for _, args := range cases {
		code, stdout, stderr := run(New("1.2.3"), append([]string{"leak-check"}, args...)...)
		if code == ExitOK {
			t.Errorf("%d arguments: status 0", len(args))
		}
		if strings.Contains(stdout+stderr, secret[:12]) {
			t.Errorf("%d arguments, the first %.6q: the secret is shown:\n%s%s", len(args), args[0], stdout, stderr)
		}
	}
	// The errors still say what's wrong.
	if _, _, stderr := run(New("1.2.3"), "leak-check", "compare", "--max-time", "soon"); !strings.Contains(stderr, "the value of --max-time isn't valid") {
		t.Errorf("bad value: %s", stderr)
	}
	if _, _, stderr := run(New("1.2.3"), "leak-check", "hash", "--out", "x", "--nope"); !strings.Contains(stderr, "argument 3 is no flag it knows") {
		t.Errorf("unknown flag: %s", stderr)
	}
	if _, _, stderr := run(New("1.2.3"), "leak-check", "hash", "extra"); !strings.Contains(stderr, "argument 1 is unexpected") {
		t.Errorf("extra argument: %s", stderr)
	}
	if _, _, stderr := run(New("1.2.3"), "leak-check", "hash", "--out"); !strings.Contains(stderr, "--out needs a value") {
		t.Errorf("missing value: %s", stderr)
	}
	if _, _, stderr := run(New("1.2.3"), "leak-check", "nope"); !strings.Contains(stderr, "none of key, hash or compare") {
		t.Errorf("unknown verb: %s", stderr)
	}
}

func TestLeakCheckUsageErrors(t *testing.T) {
	t.Setenv(keyEnv, "")
	t.Setenv("PRODMASK_DSN", "mysql://u@127.0.0.1:1/never")
	dir := t.TempDir()
	key := filepath.Join(dir, "leak.key")
	if code, _, stderr := run(New("1.2.3"), "leak-check", "key", "--out", key); code != ExitOK {
		t.Fatalf("key: %d\n%s", code, stderr)
	}
	existing := filepath.Join(dir, "exists")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"key"}, "--out is required"},
		{[]string{"key", "--out", key}, "never overwritten"},
		{[]string{"hash", "--dsn", "mysql://u@x/d"}, "--out is required"},
		{[]string{"hash", "--out", filepath.Join(dir, "n"), "--key-file", key}, "--dsn is required; it never comes from $PRODMASK_DSN"},
		{[]string{"hash", "--out", existing, "--dsn", "mysql://u@x/d"}, "already exists; use --force"},
		{[]string{"hash", "--out", filepath.Join(dir, "n"), "--dsn", "mysql://u@x/d"}, "no key: pass --key-file or set $PRODMASK_LEAK_KEY"},
		{[]string{"hash", "--out", filepath.Join(dir, "n"), "--allow-email", "com"}, "neither an address nor a domain"},
		{[]string{"hash", "--out", filepath.Join(dir, "n"), "--preset", "nope"}, "--preset isn't valid"},
		{[]string{"hash", "--out", filepath.Join(dir, "n"), "--timeout", "100ms"}, "--timeout must be at least 1s"},
		{[]string{"compare"}, "--hashes is required"},
		{[]string{"compare", "--hashes", "x", "--format", "markdown"}, "it's text or json"},
		{[]string{"compare", "--hashes", "x", "--fail-on", "extreme"}, "--fail-on isn't valid"},
		{[]string{"compare", "--hashes", "x", "--timeout", "1ms"}, "--timeout must be at least 1s"},
		{[]string{"compare", "--hashes", "x", "--max-time", "-1s"}, "--max-time can't be negative"},
		{[]string{"compare", "--hashes", "x", "--out", existing}, "already exists; use --force"},
		{[]string{"compare", "--hashes", "x"}, "no key: pass --key-file"},
		{[]string{"compare", "--hashes", filepath.Join(dir, "no-such"), "--key-file", key}, "can't read the file given to --hashes"},
		{[]string{"compare", "--hashes", existing, "--key-file", key}, "isn't a prodmask leak-check hash file"},
	}
	for _, c := range cases {
		code, stdout, stderr := run(New("1.2.3"), append([]string{"leak-check"}, c.args...)...)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%q: status %d\n%s%s", c.args, code, stdout, stderr)
		}
	}
}

func TestLeakKeyEnv(t *testing.T) {
	t.Setenv(keyEnv, "too short")
	code, _, stderr := run(New("1.2.3"), "leak-check", "hash", "--out", filepath.Join(t.TempDir(), "n"), "--dsn", "mysql://u@127.0.0.1:1/x")
	if code != ExitUsage || !strings.Contains(stderr, "a key is at least 64 hex characters") || strings.Contains(stderr, "too short") {
		t.Errorf("status %d\n%s", code, stderr)
	}
}

// leakStatus is the last word: on stderr, so a CI log has it even with --out.
func TestLeakStatus(t *testing.T) {
	result := func(found int, state string, sum model.LeakSummary, left ...model.LeakLeftOut) *model.LeakResult {
		return &model.LeakResult{Summary: sum, LeftOut: left, Columns: []model.LeakColumn{{Table: "t", Column: "c", Kind: model.LeakEmail,
			Severity: model.SeverityHigh, State: state, Found: found, Sample: model.SampleSpread}}}
	}
	read := model.LeakSummary{Columns: 1, ColumnsRead: 1, Sampled: 3000, RowsRead: 100}
	withHit := read
	withHit.Found = 5
	cases := []struct {
		name      string
		res       *model.LeakResult
		threshold model.Severity
		code      int
		lines     []string
	}{
		{"nothing found, no gate", result(0, model.LeakRead, read), model.SeverityNone, ExitOK,
			[]string{"prodmask: 0 of 3,000 sampled production values found. That isn't proof that none are there: see the report."}},
		{"nothing found, gate", result(0, model.LeakRead, read), model.SeverityHigh, ExitOK,
			[]string{"prodmask: 0 of 3,000 sampled production values found. That isn't proof that none are there: see the report."}},
		{"hits, no gate", result(5, model.LeakRead, withHit), model.SeverityNone, ExitOK,
			[]string{"prodmask: 5 of 3,000 sampled production values found on staging."}},
		{"hits, gate", result(5, model.LeakRead, withHit), model.SeverityHigh, ExitFindings,
			[]string{"prodmask: 5 of 3,000 sampled production values found on staging."}},
		{"hits below the gate", result(5, model.LeakRead, withHit), model.SeverityCritical, ExitOK,
			[]string{"5 of 3,000"}},
		{"a hit in part, gate", result(5, model.LeakStopped, model.LeakSummary{Columns: 1, SampledInPart: 3000, FoundInPart: 5, RowsRead: 9}), model.SeverityHigh, ExitFindings,
			[]string{"prodmask: 5 of 3,000 sampled production values found on staging."}},
		{"read only in part, no hit, gate", result(0, model.LeakStopped, model.LeakSummary{Columns: 1, SampledInPart: 3000, RowsRead: 9}), model.SeverityHigh, ExitError,
			[]string{"prodmask: 0 of 3,000 sampled production values found. That isn't proof", "so the gate fails"}},
		{"nothing read, no gate", result(0, model.LeakNotOnStaging, model.LeakSummary{Columns: 1, NothingRead: true}), model.SeverityNone, ExitError,
			[]string{"prodmask: nothing was read on staging, so nothing is known about it."}},
		{"nothing read, gate", result(0, model.LeakNotOnStaging, model.LeakSummary{Columns: 1, NothingRead: true}), model.SeverityHigh, ExitError,
			[]string{"prodmask: nothing was read on staging", "prodmask: 1 columns at or above --fail-on high couldn't be checked in full, so the gate fails: see the report."}},
		{"a column not read, no gate", result(0, model.LeakNotOnStaging, model.LeakSummary{Columns: 2, ColumnsRead: 1, Sampled: 10, RowsRead: 5}), model.SeverityNone, ExitOK,
			[]string{"prodmask: 0 of 10 sampled production values found. That isn't proof that none are there: see the report. 1 of 2 columns weren't read in whole."}},
		{"a column not read, gate", result(0, model.LeakNotOnStaging, model.LeakSummary{Columns: 2, ColumnsRead: 1, Sampled: 10, RowsRead: 5}), model.SeverityHigh, ExitError,
			[]string{"so the gate fails"}},
		{"not sampled on production, gate", result(0, model.LeakRead, read, model.LeakLeftOut{Location: "t", NotRead: true}), model.SeverityHigh, ExitError,
			[]string{"so the gate fails"}},
		{"not sampled on production, no gate", result(0, model.LeakRead, read, model.LeakLeftOut{Location: "t", NotRead: true}), model.SeverityNone, ExitOK,
			[]string{"see the report. 1 of 2 columns weren't read in whole."}},
	}
	for _, c := range cases {
		var b bytes.Buffer
		failOn := "none"
		if c.threshold != model.SeverityNone {
			failOn = c.threshold.String()
		}
		if got := leakStatus(&b, c.res, c.threshold, failOn); got != c.code {
			t.Errorf("%s: status %d, want %d\n%s", c.name, got, c.code, b.String())
		}
		for _, l := range c.lines {
			if !strings.Contains(b.String(), l) {
				t.Errorf("%s: no %q in\n%s", c.name, l, b.String())
			}
		}
	}
}

// TestHashSummaryCleansNames checks that what hash lists once it has written
// the file shows each character of a name from the database that could steer
// the terminal, and each byte that isn't UTF-8, as ?, and that it lists only
// what compare will count as not read.
func TestHashSummaryCleansNames(t *testing.T) {
	f := &leak.File{
		Database: "prod\x1b]0;owned\x07\xff",
		Columns: []leak.FileColumn{
			{Table: "wp\x1b[2Jusers", Column: "user_email\r", Kind: model.LeakEmail, Values: 2},
			{Table: "wp_usermeta", Column: "meta_value", MetaKey: "billing_\xe2\x80\xaephone", Kind: model.LeakPhone, Values: 1},
		},
		LeftOut: []model.LeakLeftOut{
			{Location: "logs\xc2\x9b2J.body", Why: "too big\x1b[1m", NotRead: true},
			{Location: "sessions.data", Why: "allowed"},
		},
	}
	var b bytes.Buffer
	writeHashSummary(&b, f)
	want := "Hash file written: 3 values sampled from 2 columns of prod?]0;owned??.\n" +
		"  wp?[2Jusers.user_email?  " + model.LeakEmail.Label() + "  2\n" +
		"  wp_usermeta.meta_value[billing_?phone]  " + model.LeakPhone.Label() + "  1\n" +
		"  logs?2J.body  too big?[1m: compare will count it as not read\n" +
		"Treat the file as personal data: keep it as you keep production data, and delete it after the check.\n"
	if got := b.String(); got != want {
		t.Errorf("the summary is\n%q\nwant\n%q", got, want)
	}
}

// TestLeakCheckEndToEnd runs the three verbs as a user would, on fixture
// databases: a full copy, then a masked one. It needs PRODMASK_TEST_DSN.
func TestLeakCheckEndToEnd(t *testing.T) {
	dsn := testdb.DSN(t)
	t.Setenv(keyEnv, "")
	t.Setenv("PRODMASK_PASSWORD", "")
	adminCfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("PRODMASK_TEST_DSN doesn't parse")
	}
	adminCfg.DBName = ""
	adminCfg.MultiStatements = true
	connector, err := mysql.NewConnector(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const prod, staging = "prodmask_cli_fixture_leak_prod", "prodmask_cli_fixture_leak_stag"
	const canary = "cAnArY7x9Q"
	planted := &fixture.Planted{}
	for _, db := range []string{prod, staging} {
		if err := fixture.Build(ctx, admin, "wordpress", db, fixture.Options{Canary: canary, Planted: planted}); err != nil {
			t.Fatalf("build: %v", err)
		}
		defer admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS `"+db+"`")
	}
	dsnOf := func(db string) string {
		c := adminCfg.Clone()
		c.DBName = db
		c.MultiStatements = false
		return c.FormatDSN()
	}
	// Sampled values the outputs must not hold, read straight from the fixture.
	var sampled []string
	for _, q := range []string{
		"SELECT user_email FROM `" + prod + "`.wp_users",
		"SELECT user_pass FROM `" + prod + "`.wp_users",
		"SELECT meta_value FROM `" + prod + "`.wp_usermeta WHERE meta_key = 'billing_phone'",
	} {
		rows, err := admin.QueryContext(ctx, q)
		if err != nil {
			t.Fatalf("read the fixture: %v", err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			sampled = append(sampled, s)
		}
		rows.Close()
	}
	if len(sampled) < 100 {
		t.Fatalf("%d sampled values", len(sampled))
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "leak.key")
	hashes := filepath.Join(dir, "hashes.json")
	app := New("1.2.3")
	if code, stdout, stderr := run(app, "leak-check", "key", "--out", keyPath); code != ExitOK || stdout != "" {
		t.Fatalf("key: status %d\n%s%s", code, stdout, stderr)
	}
	keyText, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := strings.TrimSpace(string(keyText))

	var outputs [][2]string
	note := func(name string, s ...string) { outputs = append(outputs, [2]string{name, strings.Join(s, "\n")}) }

	code, stdout, stderr := run(app, "leak-check", "hash", "--dsn", dsnOf(prod), "--key-file", keyPath, "--out", hashes)
	note("hash", stdout, stderr)
	if code != ExitOK || !strings.Contains(stdout, "Hash file written:") || !strings.Contains(stdout, "wp_users.user_email  email address") ||
		!strings.Contains(stdout, "Treat the file as personal data") {
		t.Fatalf("hash: status %d\n%s%s", code, stdout, stderr)
	}
	if code, _, stderr := run(app, "leak-check", "hash", "--dsn", dsnOf(prod), "--key-file", keyPath, "--out", hashes); code != ExitUsage ||
		!strings.Contains(stderr, "already exists") {
		t.Errorf("hash again: status %d\n%s", code, stderr)
	}
	file, err := os.ReadFile(hashes)
	if err != nil {
		t.Fatal(err)
	}
	note("file", string(file))

	// A full copy, with the key from the environment.
	t.Setenv(keyEnv, keyHex)
	code, stdout, stderr = run(app, "leak-check", "compare", "--dsn", dsnOf(staging), "--hashes", hashes, "--fail-on", "high", "--no-color")
	note("compare text", stdout, stderr)
	if code != ExitFindings || !strings.Contains(stdout, report.LeakHeadline) || !strings.Contains(stdout, "wp_users.user_email") ||
		!strings.Contains(stdout, "prodmask.com/leak-check") || !strings.Contains(stderr, "sampled production values found on staging.") ||
		!strings.Contains(stderr, "Reading whole columns on "+staging) {
		t.Errorf("compare: status %d\n%s%s", code, stdout, stderr)
	}
	t.Setenv(keyEnv, "")

	// JSON, to a file, with no gate.
	reportPath := filepath.Join(dir, "report.json")
	code, stdout, stderr = run(app, "leak-check", "compare", "--dsn", dsnOf(staging), "--key-file", keyPath, "--hashes", hashes, "--format", "json", "--out", reportPath)
	if code != ExitOK || stdout != "" || !strings.Contains(stderr, "sampled production values found on staging.") {
		t.Errorf("compare json: status %d\n%s%s", code, stdout, stderr)
	}
	reportJSON, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	note("report json", string(reportJSON), stderr)
	if !strings.Contains(string(reportJSON), `"line"`) || strings.Contains(string(reportJSON), "prodmask.com") {
		t.Errorf("report: %.300s", reportJSON)
	}

	// A build with an edition passes it to the report: the text names it, with
	// the version's build metadata dropped, and has no line about prodmask Pro;
	// the JSON gives the edition beside the whole version.
	pro := New("1.2.3+pro")
	pro.Edition = "Pro"
	code, stdout, stderr = run(pro, "leak-check", "compare", "--dsn", dsnOf(staging), "--key-file", keyPath, "--hashes", hashes, "--no-color")
	note("a Pro build's compare text", stdout, stderr)
	if code != ExitOK || !strings.HasPrefix(stdout, "prodmask Pro 1.2.3 leak-check · "+staging+" · ") ||
		!strings.Contains(stdout, report.LeakHeadline) || strings.Contains(stdout, "prodmask.com") {
		t.Errorf("a Pro build's compare: status %d\n%s%s", code, stdout, stderr)
	}
	proPath := filepath.Join(dir, "pro.json")
	code, _, stderr = run(pro, "leak-check", "compare", "--dsn", dsnOf(staging), "--key-file", keyPath, "--hashes", hashes, "--format", "json", "--out", proPath)
	proJSON, err := os.ReadFile(proPath)
	note("a Pro build's report json", string(proJSON), stderr)
	if code != ExitOK || err != nil || !strings.Contains(string(proJSON), `"version": "1.2.3+pro",`) ||
		!strings.Contains(string(proJSON), `"edition": "Pro",`) {
		t.Errorf("a Pro build's compare json: status %d, %v\n%s%.300s", code, err, stderr, proJSON)
	}

	// A wrong key is refused before anything's read.
	other := filepath.Join(dir, "other.key")
	if code, _, stderr := run(app, "leak-check", "key", "--out", other); code != ExitOK {
		t.Fatalf("key: %s", stderr)
	}
	code, stdout, stderr = run(app, "leak-check", "compare", "--dsn", "mysql://u@127.0.0.1:1/never", "--key-file", other, "--hashes", hashes)
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "isn't the one the hash file was made with") || strings.Contains(stderr, "Connecting") {
		t.Errorf("wrong key: status %d\n%s%s", code, stdout, stderr)
	}

	// Everything that counts, cleared on staging: a zero, which isn't proof.
	const cleared = `
		UPDATE {d}.wp_users SET user_email = CONCAT('user', ID, '@example.test'), user_pass = '', user_login = CONCAT('u', ID), user_nicename = CONCAT('u', ID), display_name = CONCAT('u', ID), user_url = '', user_activation_key = '';
		UPDATE {d}.wp_usermeta SET meta_value = '';
		UPDATE {d}.wp_postmeta SET meta_value = '';
		UPDATE {d}.wp_options SET option_value = '';
		UPDATE {d}.wp_comments SET comment_author_email = '', comment_content = '';
		UPDATE {d}.wp_commentmeta SET meta_value = '';
		UPDATE {d}.wp_posts SET post_password = '';
		UPDATE {d}.wp_wc_orders SET billing_email = '', transaction_id = '', customer_note = '';
		UPDATE {d}.wp_wc_orders_meta SET meta_value = '';
		UPDATE {d}.wp_wc_order_addresses SET email = '', phone = '';
		UPDATE {d}.wp_wc_customer_lookup SET email = '';
		UPDATE {d}.wp_wc_webhooks SET secret = '';
		UPDATE {d}.wp_woocommerce_api_keys SET consumer_key = '', consumer_secret = '';
		UPDATE {d}.wp_woocommerce_payment_tokens SET token = '';
		UPDATE {d}.wp_woocommerce_sessions SET session_value = '';
		UPDATE {d}.wp_um_metadata SET um_value = '';
	`
	if _, err := admin.ExecContext(ctx, strings.ReplaceAll(cleared, "{d}", "`"+staging+"`")); err != nil {
		t.Fatalf("clear staging: %v", err)
	}
	code, stdout, stderr = run(app, "leak-check", "compare", "--dsn", dsnOf(staging), "--key-file", keyPath, "--hashes", hashes, "--fail-on", "high", "--no-color")
	note("compare masked", stdout, stderr)
	if code != ExitOK || !strings.Contains(stdout, "That isn't proof that none are there.") ||
		!strings.Contains(stderr, "That isn't proof that none are there: see the report.") {
		t.Errorf("masked: status %d\n%s%s", code, stdout, stderr)
	}

	// A dropped column fails the gate, until it's excepted.
	if _, err := admin.ExecContext(ctx, "ALTER TABLE `"+staging+"`.wp_comments DROP COLUMN comment_author_email"); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run(app, "leak-check", "compare", "--dsn", dsnOf(staging), "--key-file", keyPath, "--hashes", hashes, "--fail-on", "high", "--no-color")
	if code != ExitError || !strings.Contains(stdout, "wp_comments.comment_author_email") || !strings.Contains(stdout, "not on staging") ||
		!strings.Contains(stderr, "so the gate fails") {
		t.Errorf("a dropped column: status %d\n%s%s", code, stdout, stderr)
	}
	code, _, stderr = run(app, "leak-check", "compare", "--dsn", dsnOf(staging), "--key-file", keyPath, "--hashes", hashes, "--fail-on", "high",
		"--fail-except", "wp_comments.comment_author_email")
	if code != ExitOK {
		t.Errorf("excepted: status %d\n%s", code, stderr)
	}

	// No output holds a value, a canary or the key.
	for _, o := range outputs {
		name, text := o[0], o[1]
		if strings.Contains(text, canary) {
			t.Errorf("%s holds the canary", name)
		}
		if strings.Contains(text, keyHex) || strings.Contains(strings.ToLower(text), keyHex[:32]) {
			t.Errorf("%s holds the key", name)
		}
		for _, v := range sampled {
			if v != "" && strings.Contains(text, v) {
				t.Errorf("%s holds a sampled value of %d characters", name, len(v))
			}
		}
		for _, v := range planted.Values {
			if strings.Contains(text, v) {
				t.Errorf("%s holds a planted value of %d characters", name, len(v))
			}
		}
		for _, r := range planted.Random {
			for i := 0; i+8 <= len(r); i += 4 {
				if strings.Contains(text, r[i:i+8]) {
					t.Errorf("%s holds a piece of a planted value", name)
					break
				}
			}
		}
	}
}

// The words the product must never use, and those that would read as "staging
// is fine". A word that names a kind of check, or a sentence about the tool's
// own limits, is fine; these aren't.
func TestLeakWordingNeverReassures(t *testing.T) {
	banned := []string{"anonymised", "anonymized", "anonymise", "anonymize", "pii-free", "compliant", "compliance",
		"clean", "passed", "verified", "no leak", "guarantee"}
	var texts []string
	for _, args := range [][]string{{"leak-check", "-h"}, {"leak-check", "key", "-h"}, {"leak-check", "hash", "-h"}, {"leak-check", "compare", "-h"}} {
		_, stdout, stderr := run(New("1.2.3"), args...)
		texts = append(texts, stdout+stderr)
	}
	texts = append(texts, strings.Join(report.LeakLimits(3000), "\n"))
	for _, c := range []model.LeakColumn{
		{State: model.LeakRead, Sample: model.SampleSpread, Sampled: 10, Values: 5, ShownAt95: 100, CatchIfAllReal: 0.2},
		{State: model.LeakRead, Sample: model.SampleSpread, Sampled: 10, Values: 500, ShownAt95: 100},
		{State: model.LeakRead, Sample: model.SampleSpread, Sampled: 10},
		{State: model.LeakRead, Sample: model.SampleSpread, Sampled: 10, Exact: true},
		{State: model.LeakRead, Sample: model.SampleCut, Sampled: 10, Values: 5},
	} {
		line := report.LeakLine(c)
		if !strings.HasPrefix(line, "0 of ") {
			t.Errorf("a zero line must start with its count: %q", line)
		}
		texts = append(texts, line)
	}
	if doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "leak-check.md")); err == nil {
		texts = append(texts, string(doc))
	} else {
		t.Errorf("read the docs: %v", err)
	}
	for _, text := range texts {
		lower := strings.ToLower(text)
		for _, w := range banned {
			if strings.Contains(lower, w) {
				t.Errorf("%q in:\n%.400s", w, text)
			}
		}
	}
}
