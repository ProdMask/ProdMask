package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/fixture"
)

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
