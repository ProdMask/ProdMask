package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/fixture"
)

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
	for _, want := range []string{"(read-only)...\n", "Report written to " + report + "\n", "prodmask: found high-severity items (--fail-on low)\n"} {
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

	code, _, again := run(New("1.2.3"), "scan", "--format", "json", "--out", report)
	if code != ExitUsage || !strings.Contains(again, "already exists; use --force to overwrite it") {
		t.Errorf("scan over an existing report: got status %d\nstderr: %q", code, again)
	}

	code, md, mdErr := run(New("1.2.3"), "scan", "--format", "markdown", "--preset", "laravel")
	if code != ExitOK || !strings.HasPrefix(md, "# prodmask scan: `"+database+"`\n") {
		t.Errorf("scan --format markdown: got status %d\n%s", code, md)
	}

	yml, _ := os.ReadFile(starter)
	for name, out := range map[string]string{
		"report.json": string(raw), "prodmask.yml": string(yml), "JSON scan's stderr": stderr,
		"Markdown report": md, "Markdown scan's stderr": mdErr,
	} {
		if strings.Contains(out, canary) {
			t.Errorf("the %s contains a sampled value", name)
		}
	}
}
