package mcp

import (
	"context"
	"database/sql"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
)

// refusedPayloads reads the statements the agent's rules must refuse from
// their table in pkg/dbconn/agent_test.go, so both tests use the one list.
func refusedPayloads(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "pkg", "dbconn", "agent_test.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "agentRefused" || len(vs.Values) != 1 {
			return true
		}
		lit, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			t.Fatal("agentRefused isn't a composite literal")
		}
		for _, e := range lit.Elts {
			b, ok := e.(*ast.BasicLit)
			if !ok {
				t.Fatalf("an agentRefused entry isn't a string literal: %T", e)
			}
			s, err := strconv.Unquote(b.Value)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return false
	})
	if len(out) < 100 {
		t.Fatalf("read %d refused payloads, want the whole table", len(out))
	}
	return out
}

// serverState is what a payload that reached the server could change: the
// globals, the user locks the payloads name, a sequence, and the tables.
type serverState struct {
	globals map[string]string
	locks   map[string]bool
	seq     string
	tables  map[string]string
}

func readState(ctx context.Context, t *testing.T, admin *sql.DB, db string, locks []string, mariadb bool) serverState {
	t.Helper()
	st := serverState{globals: map[string]string{}, locks: map[string]bool{}, tables: map[string]string{}}
	rows, err := admin.QueryContext(ctx, "SHOW GLOBAL VARIABLES")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k, v sql.NullString
		rows.Scan(&k, &v)
		st.globals[k.String] = v.String
	}
	rows.Close()
	for _, l := range locks {
		var holder sql.NullInt64
		admin.QueryRowContext(ctx, "SELECT IS_USED_LOCK(?)", l).Scan(&holder)
		st.locks[l] = holder.Valid
	}
	if mariadb {
		var next sql.NullString
		admin.QueryRowContext(ctx, "SELECT next_not_cached_value FROM "+db+".seq").Scan(&next)
		st.seq = next.String
	}
	for _, tbl := range []string{"customers", "orders", "t", "big", "wp_usermeta"} {
		var n int64
		var sum sql.NullString
		var name string
		admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+db+"."+tbl).Scan(&n)
		admin.QueryRowContext(ctx, "CHECKSUM TABLE "+db+"."+tbl).Scan(&name, &sum)
		st.tables[tbl] = fmt.Sprintf("%d rows, checksum %s", n, sum.String)
	}
	return st
}

// TestPayloadsReachNothing: every refused payload, sent through the
// query tool as root with --allow-write-login, the worst case, is refused by
// the statement rules, and leaves the server's globals, locks, sequences and
// tables as they were. A payload that got through would really run, so each
// is harmless first: an outfile names '.', which the server refuses, and
// changed globals are put back.
func TestPayloadsReachNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
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
	defer admin.Close()
	var version string
	admin.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version)
	mariadb := strings.Contains(strings.ToLower(version), "mariadb")
	const db = "prodmask_fixture_payloads"
	setup := []string{
		"DROP DATABASE IF EXISTS " + db,
		"CREATE DATABASE " + db,
		"CREATE TABLE " + db + ".customers (id INT PRIMARY KEY, name VARCHAR(40), first_name VARCHAR(40), FULLTEXT ft (name))",
		"CREATE TABLE " + db + ".orders (id INT PRIMARY KEY, customer_id INT, total DECIMAL(10,2), a VARCHAR(20))",
		"CREATE TABLE " + db + ".t (id INT PRIMARY KEY, a VARCHAR(20), b INT, d DATE, created_at DATETIME, v VARCHAR(10))",
		"CREATE TABLE " + db + ".big (i INT PRIMARY KEY)",
		"CREATE TABLE " + db + ".wp_usermeta (umeta_id INT PRIMARY KEY, user_id INT, meta_key VARCHAR(255), meta_value LONGTEXT)",
		"INSERT INTO " + db + ".customers VALUES (1, 'Ada', 'Ada'), (2, 'Bo', 'Bo')",
		"INSERT INTO " + db + ".orders VALUES (1, 1, 12.50, 'x')",
		"INSERT INTO " + db + ".t VALUES (1, 'a', 1, '2026-01-01', '2026-01-01 10:00:00', 'v')",
		"INSERT INTO " + db + ".big VALUES (1), (2), (3)",
		"INSERT INTO " + db + ".wp_usermeta VALUES (1, 1, 'billing_first_name', 'Ada')",
		"CREATE VIEW " + db + ".v AS SELECT id FROM " + db + ".t",
		"CREATE FUNCTION " + db + ".discount(x INT) RETURNS INT DETERMINISTIC NO SQL RETURN x - 1",
	}
	if mariadb {
		setup = append(setup, "CREATE SEQUENCE "+db+".seq")
	}
	// The table's statements name a database other, which the agent's
	// scope lists, as pkg/dbconn's test scope does.
	setup = append(setup, "DROP DATABASE IF EXISTS other", "CREATE DATABASE other", "CREATE TABLE other.t (a VARCHAR(10))",
		"INSERT INTO other.t VALUES ('a')")
	for _, q := range setup {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	defer admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+db)
	defer admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS other")

	shop := regexp.MustCompile(`\bshop\b`)
	payloads := refusedPayloads(t)
	var locks []string
	for _, m := range regexp.MustCompile(`(?i)LOCK\('([^']*)'`).FindAllStringSubmatch(strings.Join(payloads, "\n"), -1) {
		locks = append(locks, m[1])
	}

	// Globals that change by themselves are left out of the comparison.
	before := readState(ctx, t, admin, db, locks, mariadb)
	time.Sleep(time.Second)
	again := readState(ctx, t, admin, db, locks, mariadb)
	moving := map[string]bool{}
	for k, v := range before.globals {
		if again.globals[k] != v {
			moving[k] = true
		}
	}
	defer func() {
		after := readState(context.Background(), t, admin, db, locks, mariadb)
		for k, v := range before.globals {
			if !moving[k] && after.globals[k] != v {
				admin.ExecContext(context.Background(), fmt.Sprintf("SET GLOBAL %s = '%s'", k, strings.ReplaceAll(v, "'", "''")))
			}
		}
	}()

	dbCfg := cfg.Clone()
	dbCfg.DBName = db
	c := startClient(t, Options{Config: dbCfg, AllowWrite: true})
	refusedWords := "prodmask runs one read-only statement at a time, and refused this one"
	for _, p := range payloads {
		q := shop.ReplaceAllString(p, db)
		text, isErr := c.tool("query", map[string]any{"sql": q})
		if !isErr || !strings.HasPrefix(text, refusedWords) {
			t.Errorf("%q wasn't refused by the statement rules: %.200s", q, text)
		}
	}

	after := readState(ctx, t, admin, db, locks, mariadb)
	for k, v := range before.globals {
		if !moving[k] && after.globals[k] != v {
			t.Errorf("the global %s changed", k)
		}
	}
	for l, held := range after.locks {
		if held {
			t.Errorf("the user lock %q is held", l)
		}
	}
	if after.seq != before.seq {
		t.Errorf("the sequence moved: %q, was %q", after.seq, before.seq)
	}
	for tbl, s := range before.tables {
		if after.tables[tbl] != s {
			t.Errorf("table %s changed: %s, was %s", tbl, after.tables[tbl], s)
		}
	}
	t.Logf("%d payloads refused; %d globals compared, %d left out as moving; %d lock names", len(payloads),
		len(before.globals)-len(moving), len(moving), len(locks))
}
