package mcp

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
	"github.com/ProdMask/ProdMask/pkg/fixture"
)

const copyDB = "prodmask_fixture_kit_copy"

// copyFixture recreates a database shaped like a prodmask Pro copy: Pro-shaped
// fakes (names, phones in the 555-01xx fiction range, 198.18/15 addresses,
// Luhn cards), a secret, and, when marker is set, a _prodmask table of Pro's
// shape holding that run id.
func copyFixture(ctx context.Context, t *testing.T, runID string) (*sql.DB, *mysql.Config, map[string]string) {
	t.Helper()
	cfg, err := mysql.ParseDSN(testdb.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName = ""
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	t.Cleanup(func() { admin.Close() })
	fakes := map[string]string{
		"first_name": "Mirela", "last_name": "Dalton", "email": "mirela.dalton4@fixture-mail.gr",
		"phone": "+1 312-555-0147", "last_ip": "198.18.7.21", "card": fixture.Samples(9, 1)["card"][0],
	}
	secret := "sk_" + "live_" + strings.Repeat("Qz7", 8)
	stmts := []string{
		"DROP DATABASE IF EXISTS " + copyDB,
		"CREATE DATABASE " + copyDB,
		"CREATE TABLE " + copyDB + ".customers (id INT PRIMARY KEY, first_name VARCHAR(40), last_name VARCHAR(40), " +
			"email VARCHAR(80), phone VARCHAR(40), last_ip VARCHAR(45), card VARCHAR(20), api_note VARCHAR(80))",
		"INSERT INTO " + copyDB + ".customers VALUES (1, '" + fakes["first_name"] + "', '" + fakes["last_name"] + "', '" +
			fakes["email"] + "', '" + fakes["phone"] + "', '" + fakes["last_ip"] + "', '" + fakes["card"] + "', 'key " + secret + "')",
	}
	if runID != "" {
		stmts = append(stmts,
			"CREATE TABLE "+copyDB+"._prodmask (`run_id` varchar(12) NOT NULL, `state` varchar(16) NOT NULL, "+
				"`form` varchar(16) NOT NULL, `target` varchar(64) NOT NULL, `masking` varchar(16) NOT NULL, "+
				"`liveness` varchar(8) NOT NULL, `tool` varchar(100) NOT NULL, `started_at` datetime(6) NOT NULL, "+
				"`finished_at` datetime(6) DEFAULT NULL, PRIMARY KEY (`run_id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 "+
				"COMMENT='prodmask: this database is a prodmask copy, which prodmask may replace'",
			"INSERT INTO "+copyDB+"._prodmask VALUES ('"+runID+"', 'complete', 'database', 'shop_copy', 'stable', 'off', "+
				"'prodmask Pro 1.0.0', '2026-11-18 10:00:00', '2026-11-18 10:05:00')")
	}
	for _, q := range stmts {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q[:min(len(q), 60)], err)
		}
	}
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+copyDB) })
	cfg = cfg.Clone()
	cfg.DBName = copyDB
	fakes["secret"] = secret
	return admin, cfg, fakes
}

// TestCopy serves a Pro-shaped copy: with --copy and a marker that holds,
// the fakes show as stored and the secret doesn't; without --copy they're
// replaced; --copy without the marker, or with a run id of another shape,
// refuses to serve.
func TestCopy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const statement = "SELECT * FROM customers"

	_, cfg, fakes := copyFixture(ctx, t, "abcdefgh2345")
	c := startClient(t, Options{Config: cfg, Copy: true})
	text, isErr := c.tool("query", map[string]any{"sql": statement})
	if isErr {
		t.Fatalf("a checked copy: %s", text)
	}
	for _, col := range []string{"first_name", "last_name", "email", "phone", "last_ip", "card"} {
		if !strings.Contains(text, fakes[col]) {
			t.Errorf("with --copy, %s isn't shown as stored", col)
		}
	}
	if strings.Contains(text, fakes["secret"]) || !strings.Contains(text, standingCopy) {
		t.Errorf("with --copy, the secret shows, or the note is missing: %s", text)
	}

	plain := startClient(t, Options{Config: cfg, AllowWrite: true})
	text, isErr = plain.tool("query", map[string]any{"sql": statement})
	if isErr {
		t.Fatalf("without --copy: %s", text)
	}
	for _, col := range []string{"first_name", "last_name", "email", "phone", "card", "last_ip"} {
		if strings.Contains(text, fakes[col]) {
			t.Errorf("without --copy, %s shows as stored", col)
		}
	}

	for _, runID := range []string{"", "ABCDEFGH2345"} {
		_, cfg, _ := copyFixture(ctx, t, runID)
		c := startClient(t, Options{Config: cfg, Copy: true})
		text, isErr := c.tool("query", map[string]any{"sql": statement})
		if !isErr || !strings.Contains(text, "won't serve this database as a prodmask copy") {
			t.Errorf("--copy with run id %q: %s", runID, text)
		}
		if about, _ := c.tool("about", nil); !strings.Contains(about, `"serving": false`) {
			t.Errorf("about, --copy with run id %q: %s", runID, about)
		}
	}
}

// TestShowAccounts creates a view and a trigger as the admin: SHOW CREATE
// VIEW, SHOW CREATE TRIGGER and SHOW TRIGGERS hold no account or host. A
// 1292 warning shows as "message withheld", with no surname.
func TestShowAccounts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, cfg, password := mcpFixture(ctx, t, "x")
	var user string
	if err := admin.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&user); err != nil {
		t.Fatal(err)
	}
	account, host, _ := strings.Cut(user, "@")
	for _, q := range []string{
		"CREATE VIEW " + mcpDB + ".v AS SELECT id FROM " + mcpDB + ".customers",
		"CREATE TRIGGER " + mcpDB + ".tr BEFORE INSERT ON " + mcpDB + ".customers FOR EACH ROW SET NEW.note = NEW.note",
		"GRANT TRIGGER ON " + mcpDB + ".* TO 'pm_mcp_reader'@'%'",
	} {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// The reader needs TRIGGER to see triggers, so it's served with the flag.
	c := startClient(t, Options{Config: as(cfg, "pm_mcp_reader", password), AllowWrite: true})
	for _, q := range []string{"SHOW CREATE VIEW v", "SHOW CREATE TRIGGER tr", "SHOW TRIGGERS"} {
		text, isErr := c.tool("query", map[string]any{"sql": q})
		if isErr {
			t.Errorf("%s: %s", q, text)
			continue
		}
		if !strings.Contains(text, "[account]") || strings.Contains(text, "`"+account+"`@") || strings.Contains(text, account+"@"+host) {
			t.Errorf("%s holds the definer's account: %s", q, text)
		}
	}
	text, isErr := c.tool("query", map[string]any{"sql": "SELECT COUNT(*) FROM customers WHERE first_name = 0"})
	if isErr || !strings.Contains(text, "warning 1292, message withheld") || strings.Contains(text, "Ada") || strings.Contains(text, "Bo'") {
		t.Errorf("a 1292 warning: %s", text)
	}
}
