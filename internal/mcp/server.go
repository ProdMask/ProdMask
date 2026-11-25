package mcp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/login"
	"github.com/ProdMask/ProdMask/internal/redact"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/introspect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// Options are prodmask mcp's settings, from its flags.
type Options struct {
	Config     *mysql.Config // the DSN's, naming the database
	Timeout    time.Duration // the server's limit on each statement
	MaxRows    int           // the ceiling on rows a call returns
	Copy       bool          // --copy: show a checked prodmask copy as stored
	AllowWrite bool          // --allow-write-login
	Version    string
	Log        io.Writer // standard error: never a statement, a value, a host, a user or a DSN
}

// sessionLabel names the server in connection errors instead of its
// address.
const sessionLabel = "the database"

// connectWait is how long a tool call waits for a connection attempt.
const connectWait = 10 * time.Second

// Server is prodmask mcp: its connection to the database, and its tools.
type Server struct {
	opts Options
	ctx  context.Context // the server's lifetime, for connection attempts

	logMu sync.Mutex

	mu      sync.Mutex
	conn    *connection   // the connection, once one is made
	attempt chan struct{} // open while an attempt runs
	failure string        // the last attempt's failure, in fixed words

	// key is the token key: 32 random bytes made at start, never written
	// anywhere, so equal values get equal tokens within a run and nothing
	// links runs.
	key []byte
}

// connection is one connection's sessions and what was read through them.
// Its fields change only while the runner's turn is held, or before it's
// published.
type connection struct {
	agent, tools *dbconn.Session
	runner       *Runner
	database     string

	login  *model.Login
	marker login.Marker
	// foldCase marks a server that folds names' case.
	foldCase bool
	// markerRead marks a marker read: not when the connection was refused
	// before the login check.
	markerRead bool
	// refusal says why the connection isn't served, or is empty.
	refusal string
	// loginRefusal marks a refusal the login check made, which each call
	// reads again.
	loginRefusal bool
	// copyShown marks a checked --copy: values are shown as stored.
	copyShown bool

	schema    *model.Schema
	presets   *preset.Result
	functions []string
	databases []string
	// verdicts are the tables' judgements, read the first time a result
	// column ties to a table.
	verdicts map[string]scan.TableVerdict
}

// NewServer returns the server; Start connects it.
func NewServer(opts Options) *Server {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("prodmask mcp: no random bytes for the token key")
	}
	return &Server{opts: opts, key: key}
}

// redactor shows the connection's results.
func (s *Server) redactor(c *connection) *redact.Redactor {
	return redact.New(redact.Source{Schema: c.schema, Presets: c.presets, Judge: c.judge}, c.copyShown, s.key)
}

// judge reads a table's judgement on the tools' session, once per
// connection: the scan's own sample and key/value reads.
func (c *connection) judge(ctx context.Context, t *model.Table) scan.TableVerdict {
	if v, ok := c.verdicts[t.Name]; ok {
		return v
	}
	if c.verdicts == nil {
		c.verdicts = map[string]scan.TableVerdict{}
	}
	v := scan.JudgeTable(ctx, c.tools, c.presets, t, scan.Options{Samples: true})
	if kept(ctx, v) {
		c.verdicts[t.Name] = v
	}
	return v
}

// kept reports whether a table's judgement is kept for later calls. One a
// cancelled call cut short isn't, nor one whose sample failed, which the
// next call tries again; until then the table is judged by its columns'
// names. A sample that ran into the time limit is kept: trying again would
// only wait for the limit again, in every call that reads the table.
func kept(ctx context.Context, v scan.TableVerdict) bool {
	return ctx.Err() == nil && (v.SampleErr == nil || dbconn.IsTimeout(v.SampleErr))
}

// Start begins connecting in the background, so the protocol's handshake
// never waits for the database.
func (s *Server) Start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = ctx
	s.startLocked()
}

// Wire returns the protocol's side of the server.
func (s *Server) Wire() *Wire {
	return &Wire{Name: "prodmask", Version: s.opts.Version, Instructions: instructions, Tools: toolDefs(), Call: s.call}
}

func (s *Server) startLocked() chan struct{} {
	if s.attempt != nil {
		return s.attempt
	}
	done := make(chan struct{})
	s.attempt = done
	go func() {
		start := time.Now()
		c, failure := s.connect(s.ctx)
		s.mu.Lock()
		s.conn, s.failure, s.attempt = c, failure, nil
		s.mu.Unlock()
		close(done)
		took := time.Since(start).Round(10 * time.Millisecond)
		switch {
		case c == nil:
			s.logf("couldn't connect after %s: %s", took, failure)
		default:
			s.logf("connected in %s, %s", took, s.connectionWords(c))
		}
	}()
	return done
}

// connection returns the connection, waiting for an attempt, or starting
// one when the last failed, or the failure's words.
func (s *Server) connection(ctx context.Context) (*connection, string) {
	s.mu.Lock()
	if s.conn != nil {
		c := s.conn
		s.mu.Unlock()
		return c, ""
	}
	done := s.startLocked()
	s.mu.Unlock()
	t := time.NewTimer(connectWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		return nil, "prodmask is still connecting to the database; try again in a moment"
	case <-ctx.Done():
		return nil, "the call was cancelled"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn, s.failure
}

// connect opens the agent's session and the tools' session, then reads the
// login check and the copy marker, and, if the connection is served, the
// schema, the presets, the stored functions and the database list.
func (s *Server) connect(ctx context.Context) (*connection, string) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cfg := s.opts.Config
	agent, err := dbconn.OpenWith(ctx, cfg, dbconn.SessionOptions{Timeout: s.opts.Timeout, Label: sessionLabel,
		SelectLimit: s.opts.MaxRows + 1, ServerBigSelects: true, ColumnsWithAlias: true, TraditionalExplain: true})
	if err != nil {
		return nil, connectWords(err)
	}
	tools, err := dbconn.OpenWith(ctx, cfg, dbconn.SessionOptions{Timeout: s.opts.Timeout, Label: sessionLabel})
	if err != nil {
		agent.Close()
		return nil, connectWords(err)
	}
	c := &connection{agent: agent, tools: tools}
	// The database's name as the server gives it: the statement rules
	// take only that spelling for it, or any case where the server folds
	// names' case.
	var lowerCase int
	if err := tools.DB.QueryRowContext(ctx, "SELECT DATABASE(), @@lower_case_table_names").Scan(&c.database, &lowerCase); err != nil {
		c.close()
		return nil, "prodmask couldn't read which database the login is in (" + dbconn.ErrorText(err) + ")"
	}
	c.foldCase = lowerCase != 0
	if SystemSchema(c.database) {
		c.refusal = "prodmask mcp won't serve the server's own " + c.database + " schema: point it at the app's database"
		return c, ""
	}
	first := true
	c.runner, err = NewRunner(agent, tools, s.opts.MaxRows, c.scope, func(ctx context.Context) error {
		// On a new connection of the agent's, the schema is read again:
		// its tables may have changed since.
		again := !first
		if again {
			c.schema, c.verdicts = nil, nil
		}
		first = false
		s.check(ctx, c)
		if again {
			s.logf("new connection, %s", s.connectionWords(c))
		}
		if c.refusal != "" {
			return refusalError(c.refusal)
		}
		return nil
	})
	if err != nil {
		c.refusal = err.Error()
		return c, ""
	}
	s.check(ctx, c)
	return c, ""
}

// connectionWords say a connection's outcome on standard error: served or
// refused, the copy status, and whether --copy is on.
func (s *Server) connectionWords(c *connection) string {
	outcome := "serving"
	if c.refusal != "" {
		outcome = "refusing: " + c.refusal
	}
	return outcome + "; copy status: " + c.copyStatus() + "; --copy " + onOff(s.opts.Copy)
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// refusalError is a refusal's own words, which the agent reads as they are.
type refusalError string

func (e refusalError) Error() string { return string(e) }

// connectWords says why a connection failed, in fixed words: a dial error
// names the host, and a server's refusal the user, so neither is shown.
func connectWords(err error) string {
	var op *net.OpError
	if errors.As(err, &op) {
		return "prodmask couldn't reach the database server"
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return fmt.Sprintf("the database server refused the connection (MySQL error %d)", my.Number)
	}
	return "prodmask couldn't connect to the database (" + dbconn.ErrorText(err) + ")"
}

// check reads the login check and the copy marker, decides whether the
// connection is served, and reads the schema the first time it is.
func (s *Server) check(ctx context.Context, c *connection) {
	c.login = login.Read(ctx, c.tools.DB, c.database)
	c.marker, c.markerRead = login.ReadMarker(ctx, c.tools.DB, c.database), true
	c.copyShown = s.opts.Copy && c.marker.Holds
	c.refusal, c.loginRefusal = "", false
	switch {
	case s.opts.Copy && !c.marker.Holds:
		c.refusal = copyRefusal(c.marker)
	case !login.Serves(c.login, s.opts.AllowWrite, c.copyShown):
		c.refusal, c.loginRefusal = login.Refusal(c.login, c.database), true
	}
	if c.refusal != "" || c.schema != nil {
		return
	}
	schema, err := introspect.Load(ctx, c.tools.DB, c.database)
	if err != nil {
		c.refusal = "prodmask couldn't read the database's tables (" + dbconn.ErrorText(err) + "); try again"
		return
	}
	c.schema = schema
	c.presets = preset.Detect(ctx, c.tools.DB, schema, "auto", s.opts.Timeout)
	c.functions = readNames(ctx, c.tools, "SELECT ROUTINE_NAME FROM information_schema.ROUTINES "+
		"WHERE ROUTINE_SCHEMA = ? AND ROUTINE_TYPE = 'FUNCTION'", c.database)
	c.databases = readNames(ctx, c.tools, schemataQuery)
}

// SystemSchema reports the server's own schemas, which prodmask mcp never
// serves as the session's database: a name alone there reaches other
// sessions' statements or the accounts.
func SystemSchema(name string) bool {
	switch strings.ToLower(name) {
	case "mysql", "information_schema", "performance_schema", "sys":
		return true
	}
	return false
}

// copyStatus says what the copy marker says, or that it wasn't read.
func (c *connection) copyStatus() string {
	if !c.markerRead {
		return "The copy marker wasn't read: prodmask mcp refused this connection first."
	}
	return c.marker.Words()
}

// copyRefusal says why --copy won't serve a database whose marker doesn't
// hold as Pro checks it.
func copyRefusal(m login.Marker) string {
	return "prodmask mcp won't serve this database as a prodmask copy: " + m.Words() +
		" Ask the person who set this up to point it at a complete prodmask Pro copy."
}

// readNames reads one column of names; nil when the read fails, which the
// statement rules take as a list they can't use.
func readNames(ctx context.Context, sess *dbconn.Session, query string, args ...any) []string {
	rows, err := sess.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			return nil
		}
		out = append(out, name)
	}
	if rows.Err() != nil {
		return nil
	}
	return out
}

// schemataQuery reads the databases the login can see.
const schemataQuery = "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA"

// scope is what the agent's statements may name on this connection.
func (c *connection) scope() dbconn.AgentScope {
	sc := dbconn.AgentScope{Flavor: c.agent.Flavor(), Database: c.database, FoldCase: c.foldCase, Functions: c.functions,
		Databases: c.databases}
	if c.schema != nil {
		for _, t := range c.schema.Tables {
			sc.Tables = append(sc.Tables, t.Name)
		}
	}
	return sc
}

// call runs a tool and logs one line for it: the tool, the outcome and the
// time.
func (s *Server) call(ctx context.Context, name string, args map[string]json.RawMessage) (ToolResult, error) {
	start := time.Now()
	var (
		res     ToolResult
		outcome string
	)
	switch name {
	case "about":
		res, outcome = s.about(ctx)
	case "list_tables":
		res, outcome = s.served(ctx, s.listTables)
	case "describe_table":
		var table string
		if json.Unmarshal(args["table"], &table) != nil || table == "" {
			return ToolResult{}, InvalidParamsError{"describe_table needs table, a table's name"}
		}
		res, outcome = s.served(ctx, func(ctx context.Context, c *connection) (ToolResult, string) {
			return s.describeTable(c, table)
		})
	case "query":
		var statement string
		if json.Unmarshal(args["sql"], &statement) != nil || statement == "" {
			return ToolResult{}, InvalidParamsError{"query needs sql, one statement"}
		}
		maxRows := 0
		if raw, ok := args["max_rows"]; ok && string(raw) != "null" {
			if json.Unmarshal(raw, &maxRows) != nil || maxRows < 1 {
				return ToolResult{}, InvalidParamsError{"max_rows is a whole number from 1"}
			}
		}
		res, outcome = s.served(ctx, func(ctx context.Context, c *connection) (ToolResult, string) {
			return s.query(ctx, c, statement, maxRows)
		})
	default:
		return ToolResult{}, InvalidParamsError{"no tool of that name"}
	}
	s.logf("%s: %s (%s)", name, outcome, time.Since(start).Round(time.Millisecond))
	return res, nil
}

// served runs a tool on a connection that is served: it waits for the
// connection and the turn, and reads a refused login again first, so a
// login fixed by the person is served with no restart.
func (s *Server) served(ctx context.Context, tool func(context.Context, *connection) (ToolResult, string)) (ToolResult, string) {
	c, failure := s.connection(ctx)
	if c == nil {
		return ToolResult{Text: failure, IsError: true}, "no connection"
	}
	if c.runner == nil {
		return ToolResult{Text: c.refusal, IsError: true}, "refused the server"
	}
	done, err := c.runner.Turn(ctx)
	if err != nil {
		return ToolResult{Text: err.Error(), IsError: true}, "busy"
	}
	defer done()
	if c.refusal != "" {
		s.check(ctx, c)
		if c.refusal != "" {
			return ToolResult{Text: c.refusal, IsError: true}, "refused"
		}
	}
	return tool(ctx, c)
}

func (s *Server) logf(format string, args ...any) {
	if s.opts.Log == nil {
		return
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	fmt.Fprintf(s.opts.Log, "prodmask mcp: "+format+"\n", args...)
}

// jsonText renders a tool's answer.
func jsonText(v any) ToolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ToolResult{Text: "prodmask couldn't write the answer", IsError: true}
	}
	return ToolResult{Text: string(b)}
}

// close closes the connection's sessions.
func (c *connection) close() {
	c.agent.Close()
	c.tools.Close()
}

// Close closes the server's connection, once the protocol has ended.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.close()
		s.conn = nil
	}
}
