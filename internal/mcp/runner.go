// Package mcp is prodmask mcp: a Model Context Protocol server, over
// standard input and output, that lets a coding agent read a MySQL or
// MariaDB database through prodmask's read-only checks.
package mcp

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
)

// The runner's limits.
const (
	readCap  = 64 << 20 // bytes read per call
	valueCap = 1 << 20  // a value over this is withheld unread
	// grace is how long past the server's own limit the client waits before
	// it closes the connection on a statement.
	grace = 5 * time.Second
)

// The runner's answers, in the words the agent reads.
var (
	ErrBusy           = errors.New("busy: another statement is running")
	ErrStillRunning   = errors.New("busy: the previous statement is still running on the server")
	ErrSettings       = errors.New("prodmask couldn't confirm the connection's read-only settings, so it closed the connection; try again")
	ErrSessionNotKept = errors.New("the connection doesn't keep its session: connect to the server directly")
	ErrTimeLimit      = errors.New("the statement ran past the time limit, and prodmask closed its connection")
)

// Column is a result column: its label as the driver gives it with
// ColumnsWithAlias (the table's alias, a dot, the label) and its type's name.
type Column struct {
	Name string
	Type string
}

// Value is a result value as the server sent it. One over the value cap is
// withheld: only its size is kept.
type Value struct {
	Bytes    []byte
	Null     bool
	Withheld int
}

// Warning is a row of SHOW WARNINGS. Its message can quote a value, so it's
// never shown as it is.
type Warning struct {
	Level   string
	Code    int
	Message string
}

// Result is what a statement returned, read under the caps.
type Result struct {
	Columns  []Column
	Rows     [][]Value
	MoreRows bool
	Warnings []Warning
	// Notes are fixed words about the read: where it stopped, and what
	// wasn't read.
	Notes []string
}

// Runner runs the agent's statements one at a time on the agent's session,
// with the checks around each.
type Runner struct {
	agent, tools *dbconn.Session
	timeout      time.Duration
	grace        time.Duration
	ceiling      int
	scope        func() dbconn.AgentScope
	// newConnection runs when a call's connection isn't the last call's,
	// before its statement: it reads the login check and the copy marker
	// again, and an error refuses the call.
	newConnection func(context.Context) error

	turn chan struct{}
	// The rest is read and written holding the turn.
	lastID   int64 // the last call's CONNECTION_ID()
	cutShort int64 // the connection of a statement the client cut short
	broken   bool  // a release answered from another connection

	// hook is the tests' seam: it's called on the pinned connection before
	// the statement and after its rows and warnings are read.
	hook func(stage string, conn *sql.Conn)
}

// NewRunner checks that the agent's session can be served: the server marks
// it read-only and stops a statement at its time limit. ceiling is
// --max-rows, which the session's sql_select_limit is one above.
func NewRunner(agent, tools *dbconn.Session, ceiling int, scope func() dbconn.AgentScope,
	newConnection func(context.Context) error) (*Runner, error) {
	switch {
	case readOnlyVariable(agent.Settings) == "":
		return nil, refusalError("prodmask mcp won't serve this server: it can't mark a session read-only")
	case !agent.ServerTimeout:
		return nil, refusalError("prodmask mcp won't serve this server: it has no statement time limit")
	}
	return &Runner{agent: agent, tools: tools, timeout: agent.Timeout, grace: grace, ceiling: ceiling,
		scope: scope, newConnection: newConnection, turn: make(chan struct{}, 1)}, nil
}

func readOnlyVariable(settings map[string]string) string {
	for _, name := range []string{"transaction_read_only", "tx_read_only"} {
		if settings[name] == "1" {
			return name
		}
	}
	return ""
}

// Turn waits for the turn to run, up to the time limit plus the grace, and
// returns the function that gives it back. Every tool call takes it, so
// calls run one at a time.
func (r *Runner) Turn(ctx context.Context) (func(), error) {
	t := time.NewTimer(r.timeout + r.grace)
	defer t.Stop()
	select {
	case r.turn <- struct{}{}:
		return func() { <-r.turn }, nil
	case <-t.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Query checks the agent's statement, runs it on a pinned connection read
// back as prodmask set it, reads at most maxRows rows (the ceiling when 0 or
// above it) and the warnings, and frees the connection's locks.
func (r *Runner) Query(ctx context.Context, statement string, maxRows int) (*Result, error) {
	done, err := r.Turn(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return r.queryHeld(ctx, statement, maxRows)
}

// queryHeld is Query for a caller that holds the turn.
func (r *Runner) queryHeld(ctx context.Context, statement string, maxRows int) (*Result, error) {
	if err := dbconn.CheckAgentStatement(statement, r.scope()); err != nil {
		return nil, err
	}
	if maxRows <= 0 || maxRows > r.ceiling {
		maxRows = r.ceiling
	}
	if r.broken {
		return nil, ErrSessionNotKept
	}
	if r.cutShort != 0 {
		if err := r.waitGone(ctx, r.cutShort); err != nil {
			return nil, err
		}
		r.cutShort = 0
	}

	conn, err := r.agent.DB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	id, err := r.readBack(ctx, conn)
	if err != nil {
		discard(conn)
		return nil, err
	}
	if id != r.lastID {
		if r.newConnection != nil {
			if err := r.newConnection(ctx); err != nil {
				return nil, err
			}
		}
		r.lastID = id
	}

	res, cut, err := r.run(ctx, conn, statement, maxRows)
	if cut {
		// The connection is gone, and the server may still be running the
		// statement: the next call waits for it.
		r.cutShort = id
		discard(conn)
		return res, err
	}
	if err == nil {
		res.Warnings, err = readWarnings(ctx, conn)
		if err != nil {
			res.Notes = append(res.Notes, "warnings weren't read")
			err = nil
		}
	}
	if r.hook != nil {
		r.hook("after", conn)
	}
	if relErr := r.release(ctx, conn, id); relErr != nil {
		return nil, relErr
	}
	return res, err
}

// settingName guards the names read back, which are written into the SELECT.
var settingName = regexp.MustCompile(`^[a-z_]+$`)

// readBack reads the connection's id and every setting the session sets on
// connect, in one SELECT, and fails unless each is as set.
func (r *Runner) readBack(ctx context.Context, conn *sql.Conn) (int64, error) {
	names := make([]string, 0, len(r.agent.Settings))
	for name := range r.agent.Settings {
		if !settingName.MatchString(name) {
			return 0, ErrSettings
		}
		names = append(names, name)
	}
	sort.Strings(names)
	query := "SELECT CONNECTION_ID()"
	for _, name := range names {
		query += ", @@SESSION." + name
	}
	var id int64
	got := make([]sql.NullString, len(names))
	dest := []any{&id}
	for i := range got {
		dest = append(dest, &got[i])
	}
	if err := conn.QueryRowContext(ctx, query).Scan(dest...); err != nil {
		return 0, ErrSettings
	}
	for i, name := range names {
		if !got[i].Valid || !sameSetting(got[i].String, r.agent.Settings[name]) {
			return 0, ErrSettings
		}
	}
	return id, nil
}

// sameSetting compares a variable as read with its value as set: by number
// where both are numbers (MariaDB reads max_statement_time 10 back as
// 10.000000), and ON and OFF as 1 and 0.
func sameSetting(got, set string) bool {
	number := func(s string) (float64, bool) {
		switch strings.ToUpper(s) {
		case "ON":
			return 1, true
		case "OFF":
			return 0, true
		}
		f, err := strconv.ParseFloat(s, 64)
		return f, err == nil
	}
	g, ok1 := number(got)
	s, ok2 := number(set)
	if ok1 && ok2 {
		return g == s
	}
	return strings.EqualFold(got, set)
}

// waitGone waits up to the time limit for a connection cut short to leave
// the server's process list, which a login sees its own threads in.
func (r *Runner) waitGone(ctx context.Context, id int64) error {
	deadline := time.Now().Add(r.timeout)
	for {
		var n int
		err := r.tools.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID = ?", id).Scan(&n)
		if err == nil && n == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return ErrStillRunning
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// run sends the statement, with no arguments so it's never prepared, and
// reads its rows. cut reports that the connection was closed under the
// statement: by the client's deadline, a cancellation or a cap.
func (r *Runner) run(ctx context.Context, conn *sql.Conn, statement string, maxRows int) (res *Result, cut bool, err error) {
	stmtCtx, cancel := context.WithTimeout(ctx, r.timeout+r.grace)
	defer cancel()
	if r.hook != nil {
		r.hook("before", conn)
	}
	rows, err := conn.QueryContext(stmtCtx, statement)
	if err != nil {
		if stmtCtx.Err() != nil {
			return &Result{Notes: []string{"warnings weren't read"}}, true, cutError(ctx)
		}
		return nil, false, err
	}
	res, cut, err = read(rows, maxRows, r.ceiling+1, cancel)
	if !cut && stmtCtx.Err() != nil {
		cut, err = true, cutError(ctx)
	}
	if cut {
		res.Notes = append(res.Notes, "warnings weren't read")
	}
	return res, cut, err
}

// cutError is the error for a statement the client cut short: the caller's
// cancellation, or the deadline.
func cutError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrTimeLimit
}

// read reads rows: it keeps maxRows, reads on to the server's bound (the
// session's sql_select_limit) and stops the statement past it or past the
// read cap, by cancelling it, which closes the connection.
func read(rows *sql.Rows, maxRows, bound int, cancel func()) (*Result, bool, error) {
	defer rows.Close()
	types, err := rows.ColumnTypes()
	if err != nil {
		return &Result{}, false, err
	}
	res := &Result{Columns: make([]Column, len(types))}
	for i, t := range types {
		res.Columns[i] = Column{Name: t.Name(), Type: t.DatabaseTypeName()}
	}
	raw := make([]sql.RawBytes, len(types))
	dest := make([]any, len(types))
	for i := range raw {
		dest[i] = &raw[i]
	}
	total, count := 0, 0
	for rows.Next() {
		count++
		if count > bound {
			// The server didn't bound the statement: its own LIMIT, or a SHOW.
			res.MoreRows = true
			cancel()
			return res, true, nil
		}
		if err := rows.Scan(dest...); err != nil {
			return res, false, err
		}
		size := 0
		for _, v := range raw {
			size += len(v)
		}
		if total += size; total > readCap {
			res.MoreRows = true
			res.Notes = append(res.Notes, "the read stopped at 64 MiB")
			cancel()
			return res, true, nil
		}
		if count > maxRows {
			res.MoreRows = true
			continue
		}
		row := make([]Value, len(raw))
		for i, v := range raw {
			switch {
			case v == nil:
				row[i].Null = true
			case len(v) > valueCap:
				row[i].Withheld = len(v)
			default:
				row[i].Bytes = bytes.Clone(v)
			}
		}
		res.Rows = append(res.Rows, row)
	}
	return res, false, rows.Err()
}

// readWarnings reads the statement's warnings, the runner's own statement
// on the pinned connection, before anything else runs there.
func readWarnings(ctx context.Context, conn *sql.Conn) ([]Warning, error) {
	rows, err := conn.QueryContext(ctx, "SHOW WARNINGS LIMIT 20")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Warning
	for rows.Next() {
		var w Warning
		if err := rows.Scan(&w.Level, &w.Code, &w.Message); err != nil {
			return out, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// release frees every user lock the statement left, and checks the
// connection is the one read back. Without RELEASE_ALL_LOCKS, or on any
// error, the connection is closed, which frees them too. A release
// answered from another connection means something between prodmask and
// the server doesn't keep the session: every later call refuses.
func (r *Runner) release(ctx context.Context, conn *sql.Conn, id int64) error {
	var freed sql.NullInt64
	var after int64
	err := conn.QueryRowContext(ctx, "SELECT RELEASE_ALL_LOCKS(), CONNECTION_ID()").Scan(&freed, &after)
	switch {
	case err != nil:
		discard(conn)
	case after != id:
		r.broken = true
		discard(conn)
		return ErrSessionNotKept
	}
	return nil
}

// discard closes the pinned connection instead of returning it to the pool.
func discard(conn *sql.Conn) {
	conn.Raw(func(any) error { return driver.ErrBadConn })
}
