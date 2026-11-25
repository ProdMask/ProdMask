package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
)

const mcpDB = "prodmask_fixture_mcp"

// client drives a Server through its Wire over pipes, as an agent would.
type client struct {
	t      *testing.T
	server *Server
	in     *io.PipeWriter
	out    *bufio.Reader
	served chan error
	stderr *syncBuffer
	nextID int
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startClient(t *testing.T, opts Options) *client {
	t.Helper()
	stderr := &syncBuffer{}
	opts.Log = stderr
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.MaxRows == 0 {
		opts.MaxRows = 100
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := NewServer(opts)
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	c := &client{t: t, server: s, in: inW, out: bufio.NewReader(outR), served: make(chan error, 1), stderr: stderr}
	go func() {
		c.served <- s.Wire().Serve(ctx, inR, outW)
		outW.Close()
	}()
	t.Cleanup(func() {
		inW.Close()
		select {
		case <-c.served:
		case <-time.After(30 * time.Second):
			t.Error("the server didn't end after its input did")
		}
		cancel()
		s.Close()
	})
	return c
}

// send writes a request and returns its id.
func (c *client) send(method string, params any) int {
	c.t.Helper()
	c.nextID++
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.nextID, "method": method, "params": params})
	if _, err := c.in.Write(append(msg, '\n')); err != nil {
		c.t.Fatal(err)
	}
	return c.nextID
}

// read reads one answer.
func (c *client) read() map[string]any {
	c.t.Helper()
	line, err := c.out.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("reading an answer: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		c.t.Fatalf("an answer isn't JSON: %q", line)
	}
	return m
}

// tool calls a tool and returns its text and whether it's an error.
func (c *client) tool(name string, args map[string]any) (string, bool) {
	c.t.Helper()
	id := c.send("tools/call", map[string]any{"name": name, "arguments": args})
	m := c.read()
	if m["id"] != float64(id) {
		c.t.Fatalf("an answer to %v, want %d: %v", m["id"], id, m)
	}
	return toolText(c.t, m)
}

func toolText(t *testing.T, m map[string]any) (string, bool) {
	t.Helper()
	res, _ := m["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("a tool's answer: %v", m)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	return text, res["isError"] == true
}

// mcpFixture recreates prodmask_fixture_mcp, with a canary in a row, and
// accounts that can only read and that can also insert. It returns the
// admin connection, the server's config, and the accounts' password.
func mcpFixture(ctx context.Context, t *testing.T, canary string) (*sql.DB, *mysql.Config, string) {
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
	b := make([]byte, 12)
	rand.Read(b)
	password := "Pm1-" + hex.EncodeToString(b)
	stmts := []string{
		"DROP DATABASE IF EXISTS " + mcpDB,
		"CREATE DATABASE " + mcpDB,
		"CREATE TABLE " + mcpDB + ".customers (id INT PRIMARY KEY, first_name VARCHAR(40), email VARCHAR(80), note VARCHAR(80))",
		"INSERT INTO " + mcpDB + ".customers VALUES (1, 'Ada', 'ada@example.com', '" + canary + "'), (2, 'Bo', NULL, 'plain')",
		"CREATE TABLE " + mcpDB + ".big (i INT PRIMARY KEY)",
		"INSERT INTO " + mcpDB + ".big SELECT id FROM " + mcpDB + ".customers",
	}
	for _, user := range []string{"pm_mcp_reader", "pm_mcp_writer"} {
		account := "'" + user + "'@'%'"
		stmts = append(stmts, "DROP USER IF EXISTS "+account, "CREATE USER "+account+" IDENTIFIED BY '"+password+"'")
		t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP USER IF EXISTS "+account) })
	}
	stmts = append(stmts,
		"GRANT SELECT, SHOW VIEW ON "+mcpDB+".* TO 'pm_mcp_reader'@'%'",
		"GRANT SELECT, INSERT ON "+mcpDB+".* TO 'pm_mcp_writer'@'%'")
	for _, q := range stmts {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			q, _, _ = strings.Cut(q, " IDENTIFIED")
			t.Fatalf("%s: %v", q, err)
		}
	}
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+mcpDB) })
	cfg = cfg.Clone()
	cfg.DBName = mcpDB
	return admin, cfg, password
}

func as(cfg *mysql.Config, user, password string) *mysql.Config {
	cfg = cfg.Clone()
	cfg.User, cfg.Passwd = user, password
	return cfg
}

// TestServeTools calls the four tools as a login that can only read.
func TestServeTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	canary := "canary-" + hex.EncodeToString([]byte(t.Name()))[:12]
	_, cfg, password := mcpFixture(ctx, t, canary)
	c := startClient(t, Options{Config: as(cfg, "pm_mcp_reader", password)})

	c.send("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}})
	if res, _ := c.read()["result"].(map[string]any); res["instructions"] == nil {
		t.Fatalf("initialize: %v", res)
	}
	c.send("tools/list", nil)
	tools, _ := c.read()["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("tools: %v", tools)
	}
	for _, x := range tools {
		tool := x.(map[string]any)
		ann := tool["annotations"].(map[string]any)
		if ann["readOnlyHint"] != true || ann["destructiveHint"] != false || (ann["openWorldHint"] == true) != (tool["name"] == "query") {
			t.Errorf("%s's annotations: %v", tool["name"], ann)
		}
		if tool["name"] == "query" && !strings.Contains(tool["description"].(string), dataNotInstructions) {
			t.Errorf("query's description lacks the line that values are data")
		}
	}

	about, isErr := c.tool("about", nil)
	var a map[string]any
	if isErr || json.Unmarshal([]byte(about), &a) != nil || a["serving"] != true || a["database"] != mcpDB {
		t.Fatalf("about: %s", about)
	}
	for _, leak := range []string{cfg.Addr, "pm_mcp_reader", "127.0.0.1"} {
		if strings.Contains(about, leak) {
			t.Errorf("about holds the server's address or the user: %s", about)
		}
	}

	list, isErr := c.tool("list_tables", nil)
	if isErr || !strings.Contains(list, `"name": "customers"`) || !strings.Contains(list, `"personal_data_columns": 3`) {
		t.Errorf("list_tables: %s", list)
	}

	desc, isErr := c.tool("describe_table", map[string]any{"table": "customers"})
	if isErr || !strings.Contains(desc, `"name": "email"`) || !strings.Contains(desc, "(by name)") {
		t.Errorf("describe_table: %s", desc)
	}
	if text, isErr := c.tool("describe_table", map[string]any{"table": "CUSTOMERS"}); !isErr {
		t.Errorf("describe_table matched a name in another case: %s", text)
	}

	// The canary is in the SQL and in the data; it isn't personal data, so
	// the answer shows it, and standard error mustn't.
	res, isErr := c.tool("query", map[string]any{"sql": "SELECT id, first_name, email, note FROM customers WHERE note = '" + canary + "'"})
	if isErr || !strings.Contains(res, `"more_rows": false`) || strings.Contains(res, "ada@example.com") ||
		strings.Contains(res, `"Ada"`) || !strings.Contains(res, "[email ") || !strings.Contains(res, "[person_name ") {
		t.Errorf("query: %s", res)
	}
	if text, isErr := c.tool("query", map[string]any{"sql": "SELECT SLEEP(1)"}); !isErr || !strings.Contains(text, "refused") {
		t.Errorf("a refused statement: %s", text)
	}
	if text, isErr := c.tool("query", map[string]any{"sql": "SELECT * FROM nothing_here"}); !isErr || !strings.HasPrefix(text, "MySQL error 1146") {
		t.Errorf("a server error: %s", text)
	}

	log := c.stderr.String()
	for _, want := range []string{"connected in", ", serving; copy status: This database has no prodmask copy marker", "; --copy off",
		"about: answered", "list_tables: 2 tables", "query: 1 rows", "query: refused by the statement rules", "query: MySQL error 1146"} {
		if !strings.Contains(log, want) {
			t.Errorf("standard error lacks %q:\n%s", want, log)
		}
	}
	for _, leak := range []string{canary, "SELECT", "nothing_here", "pm_mcp_reader", cfg.Addr} {
		if strings.Contains(log, leak) {
			t.Errorf("standard error holds %q:\n%s", leak, log)
		}
	}
}

// TestServeRefusedLogin serves a login that can insert: about answers, the
// other tools refuse without naming the flag, and once the admin revokes
// INSERT the next call is served with no restart.
func TestServeRefusedLogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, cfg, password := mcpFixture(ctx, t, "x")
	c := startClient(t, Options{Config: as(cfg, "pm_mcp_writer", password)})
	about, isErr := c.tool("about", nil)
	if isErr || !strings.Contains(about, `"serving": false`) || !strings.Contains(about, "(INSERT)") {
		t.Fatalf("about under a refusal: %s", about)
	}
	for _, tool := range []string{"list_tables", "query"} {
		text, isErr := c.tool(tool, map[string]any{"sql": "SELECT 1"})
		if !isErr || !strings.Contains(text, "won't serve this login") || strings.Contains(text, "allow-write") {
			t.Errorf("%s under a refusal: %s", tool, text)
		}
	}
	if _, err := admin.ExecContext(ctx, "REVOKE INSERT ON "+mcpDB+".* FROM 'pm_mcp_writer'@'%'"); err != nil {
		t.Fatal(err)
	}
	if text, isErr := c.tool("query", map[string]any{"sql": "SELECT COUNT(*) FROM customers"}); isErr {
		t.Fatalf("the call after the revoke: %s", text)
	}
	// With the flag, a login that can write is served.
	if _, err := admin.ExecContext(ctx, "GRANT INSERT ON "+mcpDB+".* TO 'pm_mcp_writer'@'%'"); err != nil {
		t.Fatal(err)
	}
	w := startClient(t, Options{Config: as(cfg, "pm_mcp_writer", password), AllowWrite: true})
	if text, isErr := w.tool("query", map[string]any{"sql": "SELECT COUNT(*) FROM customers"}); isErr {
		t.Fatalf("a login that can write, with --allow-write-login: %s", text)
	}
}

// TestServeSystemSchema: a connection whose database is one of the server's
// own schemas is refused before the login check, whatever the name's case;
// the copy marker isn't read, and Check says so.
func TestServeSystemSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, cfg, password := mcpFixture(ctx, t, "x")
	schema := as(cfg, "pm_mcp_reader", password)
	schema.DBName = "INFORMATION_SCHEMA"
	c := startClient(t, Options{Config: schema})
	about, isErr := c.tool("about", nil)
	if isErr || !strings.Contains(about, `"serving": false`) || !strings.Contains(strings.ToLower(about), "own information_schema schema") ||
		!strings.Contains(about, "The copy marker wasn't read") {
		t.Fatalf("about on information_schema: %s", about)
	}
	for _, tool := range []string{"list_tables", "query"} {
		text, isErr := c.tool(tool, map[string]any{"sql": "SELECT 1"})
		if !isErr || !strings.Contains(strings.ToLower(text), "own information_schema schema") {
			t.Errorf("%s on information_schema: %s", tool, text)
		}
	}
	lines, serves, err := Check(ctx, Options{Config: schema, Timeout: 5 * time.Second, MaxRows: 100})
	all := strings.Join(lines, "\n")
	if err != nil || serves || !strings.Contains(all, "Copy status:  The copy marker wasn't read") || !strings.Contains(all, "--copy:       off") {
		t.Errorf("Check on information_schema: %v, %v\n%s", err, serves, all)
	}
}

// TestServeSchemaReread: the schema is read once per connection of the
// agent's; when the next query's connection is a new one, it's read again,
// and a table made since is listed.
func TestServeSchemaReread(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, cfg, password := mcpFixture(ctx, t, "x")
	c := startClient(t, Options{Config: as(cfg, "pm_mcp_reader", password)})
	count := map[string]any{"sql": "SELECT COUNT(*) FROM customers"}
	if text, isErr := c.tool("query", count); isErr {
		t.Fatalf("the first query: %s", text)
	}
	if _, err := admin.ExecContext(ctx, "CREATE TABLE "+mcpDB+".added (id INT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if text, isErr := c.tool("query", count); isErr {
		t.Fatalf("the query on the same connection: %s", text)
	}
	if text, _ := c.tool("list_tables", nil); strings.Contains(text, `"added"`) {
		t.Fatalf("the schema was read again on the same connection: %s", text)
	}
	c.server.mu.Lock()
	c.server.conn.agent.DB.SetMaxIdleConns(0)
	c.server.mu.Unlock()
	if text, isErr := c.tool("query", count); isErr {
		t.Fatalf("the query on a new connection: %s", text)
	}
	if text, _ := c.tool("list_tables", nil); !strings.Contains(text, `"added"`) {
		t.Errorf("a table made before the new connection isn't listed: %s", text)
	}
	if log := c.stderr.String(); !strings.Contains(log, "new connection, serving; copy status: ") {
		t.Errorf("standard error has no line for the new connection:\n%s", log)
	}
}

// TestServeJudgeCancelled: a table's judgement cut short by a cancelled
// call isn't kept, nor one whose sample failed; a whole one is.
func TestServeJudgeCancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, cfg, password := mcpFixture(ctx, t, "x")
	s := NewServer(Options{Config: as(cfg, "pm_mcp_reader", password), Timeout: 5 * time.Second, MaxRows: 100})
	s.Start(ctx)
	defer s.Close()
	conn, failure := s.connection(ctx)
	if conn == nil {
		t.Fatalf("no connection: %s", failure)
	}
	if conn.schema == nil {
		t.Fatalf("no schema: %s", conn.refusal)
	}
	table := conn.schema.Table("customers")
	cut, stop := context.WithCancel(ctx)
	stop()
	conn.judge(cut, table)
	if _, kept := conn.verdicts["customers"]; kept {
		t.Error("a judgement cut short was kept")
	}
	conn.judge(ctx, table)
	if _, kept := conn.verdicts["customers"]; !kept {
		t.Error("a whole judgement wasn't kept")
	}
	// A table dropped since the schema was read can't be sampled.
	if _, err := admin.ExecContext(ctx, "DROP TABLE "+mcpDB+".big"); err != nil {
		t.Fatal(err)
	}
	if v := conn.judge(ctx, conn.schema.Table("big")); v.SampleErr == nil {
		t.Fatal("a dropped table's sample didn't fail")
	}
	if _, kept := conn.verdicts["big"]; kept {
		t.Error("a judgement whose sample failed was kept")
	}
}

// TestServeDatabaseListReread: the list of databases is read for each
// statement, so a database made after the connection began is known, and an
// alias named like it is refused.
func TestServeDatabaseListReread(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, cfg, password := mcpFixture(ctx, t, "x")
	const later = "prodmask_fixture_later"
	admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+later)
	c := startClient(t, Options{Config: as(cfg, "pm_mcp_reader", password)})
	q := map[string]any{"sql": "SELECT " + later + ".first_name FROM customers " + later}
	if text, isErr := c.tool("query", q); isErr {
		t.Fatalf("before the database is made: %s", text)
	}
	for _, s := range []string{"CREATE DATABASE " + later, "GRANT SELECT ON " + later + ".* TO 'pm_mcp_reader'@'%'"} {
		if _, err := admin.ExecContext(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+later) })
	if text, isErr := c.tool("query", q); !isErr || !strings.Contains(text, "another database's name") {
		t.Errorf("after the database is made: %s", text)
	}
}

// TestServeFoldCase: the session's database named in capitals is the
// session's where the server folds names' case, and another database's
// name where it doesn't.
func TestServeFoldCase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, cfg, password := mcpFixture(ctx, t, "x")
	var lowerCase int
	if err := admin.QueryRowContext(ctx, "SELECT @@lower_case_table_names").Scan(&lowerCase); err != nil {
		t.Fatal(err)
	}
	c := startClient(t, Options{Config: as(cfg, "pm_mcp_reader", password)})
	text, isErr := c.tool("query", map[string]any{"sql": "SELECT COUNT(*) FROM " + strings.ToUpper(mcpDB) + ".customers"})
	switch {
	case lowerCase != 0 && isErr:
		t.Errorf("lower_case_table_names %d: the database's name in capitals is refused: %s", lowerCase, text)
	case lowerCase == 0 && (!isErr || !strings.Contains(text, "another database")):
		t.Errorf("lower_case_table_names 0: the database's name in capitals: %s", text)
	}
}

// TestServeConnectionRetry starts on a closed port: the first call fails
// with fixed words and about says so; once the port forwards to the server,
// the next call is served.
func TestServeConnectionRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, cfg, password := mcpFixture(ctx, t, "x")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().String()
	l.Close()
	closed := as(cfg, "pm_mcp_reader", password)
	closed.Addr = port
	c := startClient(t, Options{Config: closed})
	if text, isErr := c.tool("list_tables", nil); !isErr || text != "prodmask couldn't reach the database server" {
		t.Fatalf("a call with the port closed: %q", text)
	}
	if about, _ := c.tool("about", nil); !strings.Contains(about, "couldn't reach the database server") || strings.Contains(about, port) {
		t.Fatalf("about with the port closed: %s", about)
	}
	l, err = net.Listen("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go forward(l, cfg.Addr)
	if text, isErr := c.tool("list_tables", nil); isErr {
		t.Fatalf("the call once the port forwards: %s", text)
	}
}

// forward passes each connection on the listener to the server.
func forward(l net.Listener, to string) {
	for {
		in, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer in.Close()
			out, err := net.Dial("tcp", to)
			if err != nil {
				return
			}
			defer out.Close()
			go io.Copy(out, in)
			io.Copy(in, out)
		}()
	}
}

// TestServeOneAtATime sends three queries at once: they run one at a time.
func TestServeOneAtATime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, cfg, password := mcpFixture(ctx, t, "x")
	c := startClient(t, Options{Config: as(cfg, "pm_mcp_reader", password)})
	if _, isErr := c.tool("list_tables", nil); isErr {
		t.Fatal("not served")
	}
	conn, _ := c.server.connection(ctx)
	var now, most atomic.Int32
	conn.runner.hook = func(stage string, _ *sql.Conn) {
		if stage == "before" {
			n := now.Add(1)
			for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
			}
			time.Sleep(50 * time.Millisecond)
		} else {
			now.Add(-1)
		}
	}
	for range 3 {
		c.send("tools/call", map[string]any{"name": "query", "arguments": map[string]any{"sql": "SELECT COUNT(*) FROM big"}})
	}
	for range 3 {
		if text, isErr := toolText(t, c.read()); isErr {
			t.Errorf("a parallel call: %s", text)
		}
	}
	if most.Load() != 1 {
		t.Errorf("%d statements ran at once", most.Load())
	}
}

// TestServeDriverSilent kills the agent's connection from the admin's side.
// The driver logs a broken connection through its config's logger, which
// here writes to a buffer: prodmask mcp's sessions replace it and log
// nothing, and a plain pool with the same config shows the kill does log.
func TestServeDriverSilent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, cfg, password := mcpFixture(ctx, t, "x")
	captured := &syncBuffer{}
	reader := as(cfg, "pm_mcp_reader", password)
	reader.Logger = log.New(captured, "", 0)
	kill := func(id int64) {
		if _, err := admin.ExecContext(ctx, fmt.Sprintf("KILL %d", id)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	c := startClient(t, Options{Config: reader})
	if _, isErr := c.tool("query", map[string]any{"sql": "SELECT 1"}); isErr {
		t.Fatal("not served")
	}
	conn, _ := c.server.connection(ctx)
	kill(conn.runner.lastID)
	c.tool("query", map[string]any{"sql": "SELECT 1"})
	c.tool("query", map[string]any{"sql": "SELECT 1"})
	if got := captured.String(); got != "" {
		t.Fatalf("the driver logged for prodmask mcp's sessions: %q", got)
	}

	connector, err := mysql.NewConnector(reader)
	if err != nil {
		t.Fatal(err)
	}
	plain := sql.OpenDB(connector)
	defer plain.Close()
	plain.SetMaxOpenConns(1)
	var id int64
	if err := plain.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id); err != nil {
		t.Fatal(err)
	}
	kill(id)
	plain.ExecContext(ctx, "SELECT 1")
	if captured.String() == "" {
		t.Error("the driver didn't log for a plain pool either, so the test shows nothing")
	}
}
