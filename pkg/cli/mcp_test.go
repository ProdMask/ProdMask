package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
)

// runMCPWith runs the mcp command's Run with a hand-built Env carrying
// standard input.
func runMCPWith(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	var out, errOut bytes.Buffer
	env := &Env{App: New("1.2.3"), Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader(stdin)}
	code = mcpCommand().Run(context.Background(), env, args)
	return code, out.String(), errOut.String()
}

// nothingListening returns an address nothing listens on.
func nothingListening(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestMCPUsage(t *testing.T) {
	code, _, stderr := runMCPWith(t, "", "-h")
	if code != ExitOK || !strings.Contains(stderr, "Usage: prodmask mcp [flags]") ||
		!strings.Contains(stderr, "and 3 if it would refuse (3 is the scan's \"found something\" status;") ||
		!strings.Contains(stderr, "-allow-write-login") || !strings.Contains(stderr, "-copy") {
		t.Errorf("mcp -h: %d\n%s", code, stderr)
	}
	for _, args := range [][]string{
		{"--timeout", "500ms", "--dsn", "u@tcp(127.0.0.1:1)/db"},
		{"--max-rows", "0", "--dsn", "u@tcp(127.0.0.1:1)/db"},
		{"--max-rows", "1001", "--dsn", "u@tcp(127.0.0.1:1)/db"},
		{"--dsn", "u@tcp(127.0.0.1:1)/db", "--project", "."},
		{"--dsn", "u@tcp(127.0.0.1:1)/"},
		{"--dsn", "u@tcp(127.0.0.1:1)/mysql"},
		{"--dsn", "u@tcp(127.0.0.1:1)/Performance_Schema"},
		{"--dsn", "u:secret-pw@tcp(127.0.0.1:1)/db", "extra"},
		{},
	} {
		code, _, stderr := runMCPWith(t, "", args...)
		if code != ExitUsage || strings.Contains(stderr, "secret-pw") {
			t.Errorf("%q: status %d, %s", args, code, stderr)
		}
	}
	if _, _, stderr := runMCPWith(t, "", "--dsn", "u@tcp(127.0.0.1:1)/sys"); !strings.Contains(stderr, "the server's own sys schema") {
		t.Errorf("a DSN naming the sys schema: %s", stderr)
	}
}

// TestMCPHandshakeNoDatabase serves with nothing listening: initialize is
// answered at once, about says the server can't be reached, and the end of
// standard input ends the command with status 0.
func TestMCPHandshakeNoDatabase(t *testing.T) {
	addr := nothingListening(t)
	stdin := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"about"}}` + "\n"
	code, stdout, stderr := runMCPWith(t, stdin, "--dsn", "u:pw@tcp("+addr+")/shop")
	if code != ExitOK {
		t.Fatalf("status %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("standard output: %q", stdout)
	}
	var init map[string]any
	if json.Unmarshal([]byte(lines[0]), &init) != nil || init["result"] == nil {
		t.Errorf("initialize: %s", lines[0])
	}
	if !strings.Contains(lines[1], "couldn't reach the database server") || strings.Contains(lines[1], addr) {
		t.Errorf("about: %s", lines[1])
	}
	if !strings.Contains(stderr, "prodmask mcp: prodmask 1.2.3, reading MCP messages") || strings.Contains(stderr, addr) ||
		strings.Contains(stderr, "pw@") {
		t.Errorf("standard error: %s", stderr)
	}
}

// TestMCPCheck runs --check as a login that can only read (0), one that
// can insert (3), and against a closed port (1).
func TestMCPCheck(t *testing.T) {
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
	b := make([]byte, 12)
	rand.Read(b)
	password := "Pm1-" + hex.EncodeToString(b)
	const db = "prodmask_fixture_mcpcheck"
	ctx := context.Background()
	stmts := []string{"DROP DATABASE IF EXISTS " + db, "CREATE DATABASE " + db, "CREATE TABLE " + db + ".t (id INT PRIMARY KEY)"}
	for _, user := range []string{"pm_check_reader", "pm_check_writer"} {
		account := "'" + user + "'@'%'"
		stmts = append(stmts, "DROP USER IF EXISTS "+account, "CREATE USER "+account+" IDENTIFIED BY '"+password+"'")
		defer admin.ExecContext(ctx, "DROP USER IF EXISTS "+account)
	}
	stmts = append(stmts, "GRANT SELECT ON "+db+".* TO 'pm_check_reader'@'%'", "GRANT SELECT, INSERT ON "+db+".* TO 'pm_check_writer'@'%'")
	for _, q := range stmts {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			q, _, _ = strings.Cut(q, " IDENTIFIED")
			t.Fatalf("%s: %v", q, err)
		}
	}
	defer admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+db)
	dsn := func(user string) string {
		c := cfg.Clone()
		c.User, c.Passwd, c.DBName = user, password, db
		return c.FormatDSN()
	}

	code, stdout, stderr := runMCPWith(t, "", "--check", "--dsn", dsn("pm_check_reader"))
	if code != ExitOK || !strings.Contains(stdout, "Login:        can only read") || !strings.Contains(stdout, "would serve") {
		t.Errorf("--check as a reader: %d\n%s%s", code, stdout, stderr)
	}
	code, stdout, stderr = runMCPWith(t, "", "--check", "--dsn", dsn("pm_check_writer"))
	if code != ExitFindings || !strings.Contains(stdout, "change data: INSERT") || !strings.Contains(stdout, "--allow-write-login") {
		t.Errorf("--check as a writer: %d\n%s%s", code, stdout, stderr)
	}
	for _, out := range []string{stdout, stderr} {
		if strings.Contains(out, password) || strings.Contains(out, cfg.Addr) {
			t.Errorf("--check's output holds the password or the address: %s", out)
		}
	}
	code, _, stderr = runMCPWith(t, "", "--check", "--dsn", "u:pw@tcp("+nothingListening(t)+")/"+db)
	if code != ExitError || !strings.Contains(stderr, "couldn't reach the database server") {
		t.Errorf("--check on a closed port: %d, %s", code, stderr)
	}
}

// TestMCPWordingNeverReassures checks mcp -h and docs/coding-agents.md for
// words prodmask never uses about the data it shows; internal/mcp checks
// what the agent reads.
func TestMCPWordingNeverReassures(t *testing.T) {
	banned := []string{"anonymised", "anonymized", "anonymise", "anonymize", "pii-free", "compliant", "compliance", "safe", "guarantee"}
	_, _, usage := runMCPWith(t, "", "-h")
	texts := []string{usage}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "coding-agents.md"))
	if err != nil {
		t.Fatalf("read the docs: %v", err)
	}
	texts = append(texts, string(doc))
	for _, text := range texts {
		lower := strings.ToLower(text)
		for _, w := range banned {
			if strings.Contains(lower, w) {
				t.Errorf("%q in:\n%.400s", w, text)
			}
		}
	}
}

// TestMCPServes runs the command's Run against a server as an agent's
// client starts it: initialize, tools/list, about and a query, then the end
// of standard input, which ends the command with status 0.
func TestMCPServes(t *testing.T) {
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
	b := make([]byte, 12)
	rand.Read(b)
	password := "Pm1-" + hex.EncodeToString(b)
	const db = "prodmask_fixture_mcpserves"
	const account = "'pm_serves_reader'@'%'"
	ctx := context.Background()
	for _, q := range []string{
		"DROP DATABASE IF EXISTS " + db, "CREATE DATABASE " + db,
		"CREATE TABLE " + db + ".customers (id INT PRIMARY KEY, first_name VARCHAR(40))",
		"INSERT INTO " + db + ".customers VALUES (1, 'Zelphine'), (2, 'Quillon')",
		"DROP USER IF EXISTS " + account, "CREATE USER " + account + " IDENTIFIED BY '" + password + "'",
		"GRANT SELECT, SHOW VIEW ON " + db + ".* TO " + account,
	} {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			q, _, _ = strings.Cut(q, " IDENTIFIED")
			t.Fatalf("%s: %v", q, err)
		}
	}
	defer admin.ExecContext(ctx, "DROP USER IF EXISTS "+account)
	defer admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+db)
	c := cfg.Clone()
	c.User, c.Passwd, c.DBName = "pm_serves_reader", password, db

	stdin := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"about"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT first_name FROM customers ORDER BY id"}}}`,
	}, "\n") + "\n"
	code, stdout, stderr := runMCPWith(t, stdin, "--dsn", c.FormatDSN())
	if code != ExitOK {
		t.Fatalf("status %d: %s", code, stderr)
	}
	answers := map[float64]string{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("an answer isn't JSON: %q", line)
		}
		id, _ := m["id"].(float64)
		answers[id] = line
	}
	if len(answers) != 4 || !strings.Contains(answers[2], `"query"`) || !strings.Contains(answers[3], `\"serving\": true`) {
		t.Fatalf("answers: %v", answers)
	}
	if q := answers[4]; !strings.Contains(q, "person_name") || strings.Contains(q, "Zelphine") || strings.Contains(q, "Quillon") {
		t.Errorf("the query's answer: %s", q)
	}
	for _, want := range []string{"reading MCP messages", "connected in", "about: answered", "query: 2 rows"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("standard error lacks %q:\n%s", want, stderr)
		}
	}
	for _, leak := range []string{password, cfg.Addr, "pm_serves_reader", "Zelphine"} {
		if strings.Contains(stdout+stderr, leak) {
			t.Errorf("the output holds %q", leak)
		}
	}
	if strings.Contains(stderr, "SELECT") {
		t.Errorf("standard error holds the statement:\n%s", stderr)
	}
}
