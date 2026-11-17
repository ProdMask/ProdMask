package cli

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
)

// TestScanWarnsOfDroppedDSNVariables scans through a DSN whose session
// variables hold a canary in a value. Each report, text, Markdown and JSON,
// warns naming the variables, and neither it nor stderr holds the canary.
// It needs PRODMASK_TEST_DSN; testdb.DSN skips or fails it without one.
func TestScanWarnsOfDroppedDSNVariables(t *testing.T) {
	dsn := testdb.DSN(t)
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const database, canary = "prodmask_cli_fixture_dsnvars", "zq7" + "dsnvarscanary"
	for _, q := range []string{
		"DROP DATABASE IF EXISTS " + database,
		"CREATE DATABASE " + database,
		"CREATE TABLE " + database + ".customers (id INT PRIMARY KEY, email VARCHAR(100))",
		"INSERT INTO " + database + ".customers VALUES (1, 'jo@example.com')",
	} {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+database) })

	cfg := adminCfg.Clone()
	cfg.DBName = database
	cfg.Params = map[string]string{"wait_timeout": "123", "sql_mode": "'" + canary + "'"}
	t.Setenv("PRODMASK_DSN", cfg.FormatDSN())
	t.Setenv("PRODMASK_PASSWORD", "")
	const want = "the DSN's session variables aren't used: sql_mode, wait_timeout"
	for _, format := range []string{"text", "markdown", "json"} {
		code, stdout, stderr := run(New("1.2.3"), "scan", "--format", format)
		if code != ExitOK {
			t.Errorf("scan --format %s: status %d\n%s", format, code, stderr)
		}
		if !strings.Contains(stdout, want) {
			t.Errorf("the %s report doesn't warn %q", format, want)
		}
		if strings.Contains(stdout+stderr, canary) {
			t.Errorf("the %s report or stderr holds the canary", format)
		}
	}
}
