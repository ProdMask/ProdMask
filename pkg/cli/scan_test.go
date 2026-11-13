package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/fixture"
)

// Whatever is typed in the wrong place may be a DSN with its password or a key:
// no error repeats it, on any flag scan has. The flags come from scan's own help,
// so a new one can't be missed.
func TestScanNeverEchoesArguments(t *testing.T) {
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	const password = "c0rrect-h0rse-b4ttery"
	key := keyShaped()
	secrets := []struct{ value, mark string }{
		{"mysql://ro:" + password + "@db.example.test:3306/shop", password},
		{"ro:" + password + "@tcp(db.example.test:3306)/shop", password},
		{key, key[:12]},
	}

	_, _, help := run(New("1.2.3"), "scan", "-h")
	var flags []string
	for _, m := range regexp.MustCompile(`(?m)^  -([a-z-]+)`).FindAllStringSubmatch(help, -1) {
		flags = append(flags, m[1])
	}
	if len(flags) < 13 || !slices.Contains(flags, "dsn") || !slices.Contains(flags, "no-color") {
		t.Fatalf("read %d flags from scan -h: %q", len(flags), flags)
	}

	// A failure prints <secret> in place of the fake value.
	check := func(wantCode int, mark string, args ...string) {
		t.Helper()
		typed := strings.ReplaceAll(strings.Join(args, " "), mark, "<secret>")
		code, stdout, stderr := run(New("1.2.3"), args...)
		if code != wantCode {
			t.Errorf("prodmask %s: status %d, want %d", typed, code, wantCode)
		}
		if strings.Contains(stdout+stderr, mark) {
			t.Errorf("prodmask %s: the secret is shown:\n%s", typed, strings.ReplaceAll(stdout+stderr, mark, "<secret>"))
		}
	}
	for _, s := range secrets {
		// On every flag, as its value or after it.
		for _, f := range flags {
			if f == "dsn" && s.mark == password {
				continue // the right place for a DSN: it would connect
			}
			check(ExitUsage, s.mark, "scan", "--"+f, s.value)
			check(ExitUsage, s.mark, "scan", "-"+f, s.value)
			check(ExitUsage, s.mark, "scan", "--"+f+"="+s.value)
		}
		for _, args := range [][]string{
			// As an argument of its own.
			{s.value},
			{"--", s.value},
			{"--no-samples", "--verbose", s.value},
			{"--preset", "auto", s.value},
			// As a flag.
			{"--" + s.value},
			{"-" + s.value},
			{"---" + s.value},
			{"--" + s.value + "=1"},
			{"--=" + s.value},
			{"-=" + s.value},
			{"--preset", "auto", "--" + s.value},
		} {
			check(ExitUsage, s.mark, append([]string{"scan"}, args...)...)
		}
		// In place of the command.
		check(ExitUsage, s.mark, s.value)
		check(ExitUsage, s.mark, "--"+s.value)
		// Help, whatever follows it.
		check(ExitOK, s.mark, "scan", "-h="+s.value)
		check(ExitOK, s.mark, "scan", "--help="+s.value)
	}

	// A DSN's scheme can be the start of a secret, and a file's name can be a
	// secret too: one that exists gets as far as being refused.
	check(ExitUsage, key[:12], "scan", "--dsn", "k"+key+"://db.example.test/shop")
	// In its right place, a password that a / cuts short would read as the
	// database's name, and get printed on the way to connecting.
	check(ExitUsage, password, "scan", "--dsn", "mysql://ro:12/"+password+"@db.example.test:3306/shop")
	existing := filepath.Join(t.TempDir(), key)
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	check(ExitUsage, key[:12], "scan", "--out", existing)
	check(ExitUsage, key[:12], "scan", "--config-out", existing)
}

// statelessToken returns a GitHub App installation token as GitHub has minted
// them since 2026, ghs_APPID_JWT, assembled at run time.
func statelessToken(seed uint64) string {
	r := rand.New(rand.NewPCG(seed, seed*31+7))
	part := func(n int) string {
		const set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
		b := make([]byte, n)
		for i := range b {
			b[i] = set[r.IntN(len(set))]
		}
		return string(b)
	}
	return "gh" + "s_1234567_ey" + "J" + part(33) + ".ey" + "J" + part(204) + "." + part(263)
}

// TestScanFailOnStatelessGitHub runs prodmask scan end to end against stateless
// GitHub tokens in columns whose names say nothing, one whole and one cut by the
// 4096 characters the scan reads of a value. It needs PRODMASK_TEST_DSN.
func TestScanFailOnStatelessGitHub(t *testing.T) {
	dsn := os.Getenv("PRODMASK_TEST_DSN")
	if dsn == "" {
		t.Skip("PRODMASK_TEST_DSN is not set")
	}
	adminCfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminCfg.DBName = ""
	connector, err := mysql.NewConnector(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	defer admin.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	const database = "prodmask_cli_fixture_stateless"
	drop := "DROP DATABASE IF EXISTS `" + database + "`"
	for _, s := range []string{
		drop,
		"CREATE DATABASE `" + database + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		"CREATE TABLE `" + database + "`.deploy_steps (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, step_output text, build_log text) ENGINE=InnoDB",
	} {
		if _, err := admin.ExecContext(ctx, s); err != nil {
			t.Fatalf("build the table: %v", err)
		}
	}
	defer admin.ExecContext(ctx, drop)
	whole, cut := statelessToken(1), statelessToken(2)
	if _, err := admin.ExecContext(ctx, "INSERT INTO `"+database+"`.deploy_steps (step_output, build_log) VALUES (?, ?)",
		whole, strings.Repeat("step ok\n", 500)+cut); err != nil {
		t.Fatalf("fill the table: %v", err)
	}

	cfg := adminCfg.Clone()
	cfg.DBName = database
	t.Setenv("PRODMASK_DSN", cfg.FormatDSN())
	t.Setenv("PRODMASK_PASSWORD", "")
	report := filepath.Join(t.TempDir(), "report.json")
	code, stdout, stderr := run(New("1.2.3"), "scan", "--format", "json", "--out", report, "--fail-on", "critical")
	if code != ExitFindings || !strings.Contains(stderr, "prodmask: found critical-severity items (--fail-on critical)\n") {
		t.Fatalf("scan --fail-on critical: got status %d\nstderr: %q", code, stderr)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Findings []struct {
			Column, Category, Severity string
			Reasons                    []string
		}
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("report.json: %v", err)
	}
	for _, column := range []string{"step_output", "build_log"} {
		found := false
		for _, f := range res.Findings {
			found = found || f.Column == column && f.Category == "secret" && f.Severity == "critical" &&
				strings.Contains(strings.Join(f.Reasons, " "), "GitHub token (1 live)")
		}
		if !found {
			t.Errorf("%s has no critical GitHub token finding: %+v", column, res.Findings)
		}
	}
	for name, out := range map[string]string{"report.json": string(raw), "stdout": stdout, "stderr": stderr} {
		if strings.Contains(out, "gh"+"s_") || strings.Contains(out, whole[100:124]) || strings.Contains(out, cut[60:84]) {
			t.Errorf("the %s contains a sampled value", name)
		}
	}
}

// TestScanCommand runs prodmask scan end to end against a fixture database,
// like pkg/scan's integration test. It needs PRODMASK_TEST_DSN.
func TestScanCommand(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	const database, canary = "prodmask_cli_fixture_laravel", "zq7canary4x"
	if err := fixture.Build(ctx, admin, "laravel", database, fixture.Options{Canary: canary}); err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	cfg := adminCfg.Clone()
	cfg.MultiStatements = false
	cfg.DBName = database
	t.Setenv("PRODMASK_DSN", cfg.FormatDSN())
	t.Setenv("PRODMASK_PASSWORD", "")

	dir := t.TempDir()
	report, starter := filepath.Join(dir, "report.json"), filepath.Join(dir, "prodmask.yml")
	code, stdout, stderr := run(New("1.2.3"), "scan", "--format", "json", "--out", report, "--config-out", starter, "--fail-on", "low")
	if code != ExitFindings || stdout != "" {
		t.Fatalf("scan --fail-on low: got status %d\nstdout: %q\nstderr: %q", code, stdout, stderr)
	}
	for _, want := range []string{"(read-only)...\n", "Report written.\n", "prodmask: found high-severity items (--fail-on low)\n"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q:\n%s", want, stderr)
		}
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Version, Database string
		Findings          []json.RawMessage
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("report.json: %v", err)
	}
	if res.Version != "1.2.3" || res.Database != database || len(res.Findings) == 0 {
		t.Errorf("report.json: version %q, database %q, %d findings", res.Version, res.Database, len(res.Findings))
	}
	if yml, err := os.ReadFile(starter); err != nil || !strings.Contains(string(yml), "# Written by prodmask 1.2.3 on ") {
		t.Errorf("prodmask.yml: %v\n%s", err, yml)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("want only the two output files in %s, got %d entries", dir, len(entries))
	}

	// A build with an edition passes it to the reports: they name it, with the
	// version's build metadata dropped, and have no line about prodmask Pro.
	// The JSON report and the starter config keep the whole version.
	pro := New("1.2.3+pro")
	pro.Edition = "Pro"
	proDir := t.TempDir()
	proReport, proStarter := filepath.Join(proDir, "report.json"), filepath.Join(proDir, "prodmask.yml")
	if code, _, stderr := run(pro, "scan", "--format", "json", "--out", proReport, "--config-out", proStarter); code != ExitOK {
		t.Fatalf("a Pro build's scan: got status %d\nstderr: %q", code, stderr)
	}
	var proRes struct{ Version, Edition string }
	proRaw, err := os.ReadFile(proReport)
	if err != nil || json.Unmarshal(proRaw, &proRes) != nil || proRes.Version != "1.2.3+pro" || proRes.Edition != "Pro" {
		t.Errorf("a Pro build's report.json: version %q, edition %q", proRes.Version, proRes.Edition)
	}
	proYml, err := os.ReadFile(proStarter)
	if err != nil || !strings.Contains(string(proYml), "# Written by prodmask 1.2.3+pro on ") {
		t.Errorf("a Pro build's prodmask.yml: %v\n%s", err, proYml)
	}
	code, proText, proStderr := run(pro, "scan", "--no-color")
	if code != ExitOK || !strings.HasPrefix(proText, "prodmask Pro 1.2.3 scan · "+database+" · ") || strings.Contains(proText, "prodmask.com") {
		t.Errorf("a Pro build's text report: got status %d\nstdout: %q\nstderr: %q", code, proText, proStderr)
	}

	code, _, again := run(New("1.2.3"), "scan", "--format", "json", "--out", report)
	if code != ExitUsage || !strings.Contains(again, "already exists; use --force to overwrite it") {
		t.Errorf("scan over an existing report: got status %d\nstderr: %q", code, again)
	}

	// A file's path may be a secret typed in the wrong place. It's still used,
	// but no output repeats it, whether the write works or fails. A failed write
	// quotes the folder, as it would quote the host and password of a DSN.
	key := keyShaped()
	missing := filepath.Join(dir, key, "file")
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--no-color", "--out", filepath.Join(dir, key+".txt")}, ExitOK, "Report written.\n"},
		{[]string{"--no-color", "--config-out", filepath.Join(dir, key+".yml")}, ExitOK, "Starter masking config written to the file given to --config-out."},
		{[]string{"--no-color", "--out", missing}, ExitError, "prodmask: can't write the report\n"},
		{[]string{"--no-color", "--config-out", missing}, ExitError, "prodmask: can't write the file given to --config-out\n"},
	} {
		code, stdout, stderr := run(New("1.2.3"), append([]string{"scan"}, c.args...)...)
		if code != c.code || !strings.Contains(stdout+stderr, c.want) {
			t.Errorf("scan %s: got status %d, want %d and %q", c.args[1], code, c.code, c.want)
		}
		if strings.Contains(stdout+stderr, key[:12]) {
			t.Errorf("scan %s: the secret is shown", c.args[1])
		}
	}
	for _, name := range []string{key + ".txt", key + ".yml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("a file named as typed wasn't written: %v", err)
		}
	}

	code, md, mdErr := run(New("1.2.3"), "scan", "--format", "markdown", "--preset", "laravel")
	if code != ExitOK || !strings.HasPrefix(md, "# prodmask scan: `"+database+"`\n") {
		t.Errorf("scan --format markdown: got status %d\n%s", code, md)
	}

	yml, _ := os.ReadFile(starter)
	for name, out := range map[string]string{
		"report.json": string(raw), "prodmask.yml": string(yml), "JSON scan's stderr": stderr,
		"Markdown report": md, "Markdown scan's stderr": mdErr,
		"Pro build's report.json": string(proRaw), "Pro build's prodmask.yml": string(proYml),
		"Pro build's text report": proText + proStderr,
	} {
		if strings.Contains(out, canary) {
			t.Errorf("the %s contains a sampled value", name)
		}
	}
}
