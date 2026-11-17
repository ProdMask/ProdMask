package dbconn

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/refusals"
)

// fakeDriver hands out fakeConns and logs every statement that reaches one.
type fakeDriver struct {
	mu        sync.Mutex
	log       []string
	connects  int
	failFirst bool // the first Connect fails with driver.ErrBadConn
}

func (d *fakeDriver) note(s string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.log = append(d.log, s)
}

func (d *fakeDriver) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.log)
}

func (d *fakeDriver) Connect(context.Context) (driver.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.connects++
	if d.failFirst && d.connects == 1 {
		return nil, driver.ErrBadConn
	}
	return &fakeConn{f: d}, nil
}

func (d *fakeDriver) Driver() driver.Driver { return nil }

// fakeConn mirrors the MySQL driver's connection: every interface
// checkedConn passes on to, the deprecated Execer and Queryer as well, and
// driver.ErrSkip from QueryContext and ExecContext for a statement with
// arguments, as the driver answers without interpolation. A statement
// holding "fail" gets a server error, and one holding "badconn" a lost
// connection.
type fakeConn struct{ f *fakeDriver }

var errFake = &mysql.MySQLError{Number: 1193, Message: "Unknown system variable"}

func (c *fakeConn) answer(kind, q string, args int) error {
	switch {
	case args > 0:
		return driver.ErrSkip
	case strings.Contains(q, "badconn"):
		return driver.ErrBadConn
	}
	c.f.note(kind + " " + q)
	if strings.Contains(q, "fail") {
		return errFake
	}
	return nil
}

func (c *fakeConn) Prepare(q string) (driver.Stmt, error) {
	c.f.note("prepare " + q)
	return fakeStmt{c.f}, nil
}

func (c *fakeConn) PrepareContext(_ context.Context, q string) (driver.Stmt, error) {
	return c.Prepare(q)
}

func (c *fakeConn) Begin() (driver.Tx, error) {
	c.f.note("begin")
	return fakeTx{}, nil
}

func (c *fakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return c.Begin() }

func (c *fakeConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.answer("query", q, len(args)); err != nil {
		return nil, err
	}
	return &fakeRows{}, nil
}

func (c *fakeConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.answer("exec", q, len(args)); err != nil {
		return nil, err
	}
	return driver.RowsAffected(0), nil
}

func (c *fakeConn) Exec(q string, _ []driver.Value) (driver.Result, error) {
	c.f.note("unchecked exec " + q)
	return driver.RowsAffected(0), nil
}

func (c *fakeConn) Query(q string, _ []driver.Value) (driver.Rows, error) {
	c.f.note("unchecked query " + q)
	return &fakeRows{}, nil
}

func (c *fakeConn) Ping(context.Context) error {
	c.f.note("ping")
	return nil
}

func (c *fakeConn) ResetSession(context.Context) error       { return nil }
func (c *fakeConn) IsValid() bool                            { return true }
func (c *fakeConn) CheckNamedValue(*driver.NamedValue) error { return nil }
func (c *fakeConn) Close() error                             { return nil }

type fakeStmt struct{ f *fakeDriver }

func (s fakeStmt) Close() error  { return nil }
func (s fakeStmt) NumInput() int { return -1 }

func (s fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	s.f.note("stmt exec")
	return driver.RowsAffected(0), nil
}

func (s fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	s.f.note("stmt query")
	return &fakeRows{}, nil
}

type fakeRows struct{}

func (*fakeRows) Columns() []string         { return []string{"x"} }
func (*fakeRows) Close() error              { return nil }
func (*fakeRows) Next([]driver.Value) error { return io.EOF }

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

// expectRefused checks that run fails with ErrStatementRefused, counted
// once.
func expectRefused(t *testing.T, name string, run func() error) {
	t.Helper()
	before := refusals.Count()
	if err := run(); !errors.Is(err, ErrStatementRefused) {
		t.Errorf("%s: %v, want a refusal", name, err)
	}
	if n := refusals.Count() - before; n != 1 {
		t.Errorf("%s: %d refusals counted, want 1", name, n)
	}
}

// TestCheckedConnRefuses checks that a write is refused, counted once and
// never reaches the driver, through every path database/sql has to a
// Session's connection: the pool, a pinned connection, a prepared
// statement, a transaction, and Conn.Raw through each driver interface.
func TestCheckedConnRefuses(t *testing.T) {
	ctx := context.Background()
	d := &fakeDriver{}
	db := sql.OpenDB(checkedConnector{d})
	defer db.Close()
	const write = "UPDATE t SET a = 1"

	expectRefused(t, "Exec", func() error { _, err := db.ExecContext(ctx, write); return err })
	expectRefused(t, "Exec with an argument", func() error { _, err := db.ExecContext(ctx, "UPDATE t SET a = ?", 1); return err })
	expectRefused(t, "Query", func() error {
		rows, err := db.QueryContext(ctx, write)
		if err == nil {
			rows.Close()
		}
		return err
	})
	expectRefused(t, "Query with an argument", func() error {
		rows, err := db.QueryContext(ctx, "DELETE FROM t WHERE id = ?", 1)
		if err == nil {
			rows.Close()
		}
		return err
	})
	expectRefused(t, "Prepare", func() error { _, err := db.PrepareContext(ctx, write); return err })
	expectRefused(t, "Begin", func() error { _, err := db.Begin(); return err })
	expectRefused(t, "a read-only BeginTx", func() error { _, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true}); return err })

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expectRefused(t, "a pinned connection's Exec", func() error { _, err := conn.ExecContext(ctx, write); return err })
	expectRefused(t, "a pinned connection's Prepare", func() error { _, err := conn.PrepareContext(ctx, write); return err })
	err = conn.Raw(func(dc any) error {
		if _, ok := dc.(driver.Execer); ok {
			t.Error("the connection has the unchecked Execer")
		}
		if _, ok := dc.(driver.Queryer); ok {
			t.Error("the connection has the unchecked Queryer")
		}
		expectRefused(t, "Raw Prepare", func() error { _, err := dc.(driver.Conn).Prepare(write); return err })
		expectRefused(t, "Raw Begin", func() error { _, err := dc.(driver.Conn).Begin(); return err })
		expectRefused(t, "Raw PrepareContext", func() error {
			_, err := dc.(driver.ConnPrepareContext).PrepareContext(ctx, write)
			return err
		})
		expectRefused(t, "Raw ExecContext", func() error { _, err := dc.(driver.ExecerContext).ExecContext(ctx, write, nil); return err })
		expectRefused(t, "Raw QueryContext", func() error { _, err := dc.(driver.QueryerContext).QueryContext(ctx, write, nil); return err })
		expectRefused(t, "Raw BeginTx", func() error {
			_, err := dc.(driver.ConnBeginTx).BeginTx(ctx, driver.TxOptions{ReadOnly: true})
			return err
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if log := d.seen(); len(log) > 0 {
		t.Errorf("refused statements reached the driver: %q", log)
	}
	if _, err := db.Driver().Open("root@tcp(127.0.0.1:3306)/"); err == nil {
		t.Error("the pool's driver opened a connection of its own")
	}
}

// TestCheckedConnPassesOn checks that reads, session SETs and pings reach
// the driver unchanged, with nothing counted, and that the driver's errors
// come back as they were: ErrSkip by identity, so database/sql falls back to
// Prepare for a statement with arguments, a server error and a lost
// connection.
func TestCheckedConnPassesOn(t *testing.T) {
	ctx := context.Background()
	d := &fakeDriver{}
	db := sql.OpenDB(checkedConnector{d})
	defer db.Close()
	before := refusals.Count()

	for _, q := range []string{"SELECT 1", "SELECT ?"} {
		var args []any
		if strings.Contains(q, "?") {
			args = append(args, 1)
		}
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		rows.Close()
	}
	if _, err := db.ExecContext(ctx, "SET SESSION sql_mode = ''"); err != nil {
		t.Fatal(err)
	}
	stmt, err := db.PrepareContext(ctx, "SET @x = ?")
	if err != nil {
		t.Fatal(err)
	}
	stmt.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"query SELECT 1", "prepare SELECT ?", "stmt query", "exec SET SESSION sql_mode = ''", "prepare SET @x = ?", "ping"}
	if got := d.seen(); !slices.Equal(got, want) {
		t.Errorf("the driver saw %q, want %q", got, want)
	}
	if n := refusals.Count() - before; n != 0 {
		t.Errorf("%d refusals counted, want none", n)
	}

	var my *mysql.MySQLError
	if _, err := db.ExecContext(ctx, "SET @fail = 1"); !errors.As(err, &my) || my.Number != errFake.Number {
		t.Errorf("a server error came back as %v", err)
	}
	c := &checkedConn{c: &fakeConn{f: d}}
	arg := []driver.NamedValue{{Ordinal: 1, Value: int64(1)}}
	if _, err := c.QueryContext(ctx, "SELECT ?", arg); err != driver.ErrSkip {
		t.Errorf("QueryContext with an argument: %v, want driver.ErrSkip itself", err)
	}
	if _, err := c.ExecContext(ctx, "SET @x = ?", arg); err != driver.ErrSkip {
		t.Errorf("ExecContext with an argument: %v, want driver.ErrSkip itself", err)
	}
	if _, err := c.ExecContext(ctx, "SET @badconn = 1", nil); err != driver.ErrBadConn {
		t.Errorf("a lost connection came back as %v", err)
	}
}

// TestCheckedConnReconnects checks that the connection database/sql opens
// after the driver loses one comes through the checked connector too.
func TestCheckedConnReconnects(t *testing.T) {
	ctx := context.Background()
	d := &fakeDriver{failFirst: true}
	db := sql.OpenDB(checkedConnector{d})
	defer db.Close()
	if _, err := db.ExecContext(ctx, "SET SESSION sql_mode = ''"); err != nil {
		t.Fatal(err)
	}
	if d.connects != 2 {
		t.Fatalf("%d connects, want 2", d.connects)
	}
	expectRefused(t, "after a reconnect", func() error { _, err := db.ExecContext(ctx, "UPDATE t SET a = 1"); return err })
}

// bareConn is a driver connection with none of the interfaces checkedConn
// passes on to.
type bareConn struct{ closed *bool }

func (c bareConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("bare") }
func (c bareConn) Close() error                        { *c.closed = true; return nil }
func (c bareConn) Begin() (driver.Tx, error)           { return nil, errors.New("bare") }

type bareConnector struct{ closed *bool }

func (k bareConnector) Connect(context.Context) (driver.Conn, error) { return bareConn{k.closed}, nil }
func (k bareConnector) Driver() driver.Driver                        { return nil }

// TestCheckedConnectorRefusesBareConn checks that a connection checkedConn
// can't pass on to is closed and refused, not used unchecked.
func TestCheckedConnectorRefusesBareConn(t *testing.T) {
	closed := false
	c, err := checkedConnector{bareConnector{&closed}}.Connect(context.Background())
	if err == nil || c != nil {
		t.Errorf("Connect: %v, %v; want an error", c, err)
	}
	if !closed {
		t.Error("the driver's connection was left open")
	}
}

// TestCheckedConfig checks the settings a Session's pool forces, whatever
// the DSN said, without changing the caller's config.
func TestCheckedConfig(t *testing.T) {
	cfg := mysql.NewConfig()
	cfg.MultiStatements, cfg.InterpolateParams, cfg.AllowAllFiles = true, true, true
	if err := cfg.Apply(mysql.Charset("latin1", "latin1_swedish_ci")); err != nil {
		t.Fatal(err)
	}
	got, err := checkedConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got.MultiStatements || got.InterpolateParams || got.AllowAllFiles {
		t.Errorf("an option stayed on: multiStatements %v, interpolateParams %v, allowAllFiles %v",
			got.MultiStatements, got.InterpolateParams, got.AllowAllFiles)
	}
	if cs := dsnCharset(got); cs != "utf8mb4" || got.Collation != "utf8mb4_general_ci" {
		t.Errorf("charset %q, collation %q, want utf8mb4 and utf8mb4_general_ci", cs, got.Collation)
	}
	if !cfg.MultiStatements || dsnCharset(cfg) != "latin1" {
		t.Error("the caller's config changed")
	}
}

// TestDropDSNSettings checks that a DSN's session variables are taken out
// of the config, and the warning for what a Session drops: plain names
// only, sorted, the charset and collation when they aren't utf8mb4's, the
// rest counted, and never a value, even one URL-encoded into a key.
func TestDropDSNSettings(t *testing.T) {
	const canary = "zq7" + "dsncanary"
	cfg := mysql.NewConfig()
	cfg.Params = map[string]string{
		"time_zone":                       "'+00:00'",
		"sql_mode":                        "'" + canary + "'",
		"sql_mode%3D%27" + canary + "%27": "1",
		"x y":                             "1",
	}
	if err := cfg.Apply(mysql.Charset("latin1", "latin1_swedish_ci")); err != nil {
		t.Fatal(err)
	}
	got := dropDSNSettings(cfg)
	if want := "the DSN's session variables aren't used: charset, collation, sql_mode, time_zone and 2 more"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if strings.Contains(got, canary) {
		t.Errorf("the warning holds a value: %q", got)
	}
	if cfg.Params != nil {
		t.Errorf("the session variables stayed: %d", len(cfg.Params))
	}

	for _, c := range []struct {
		params map[string]string
		utf8   bool
		want   string
	}{
		{map[string]string{"a-b": "1"}, false, "the DSN's session variables aren't used: 1 whose names aren't plain words"},
		{nil, false, ""},
		{nil, true, ""},
	} {
		cfg := mysql.NewConfig()
		cfg.Params = c.params
		if c.utf8 {
			if err := cfg.Apply(mysql.Charset("utf8mb4", "utf8mb4_general_ci")); err != nil {
				t.Fatal(err)
			}
		}
		if got := dropDSNSettings(cfg); got != c.want || cfg.Params != nil {
			t.Errorf("%v (utf8mb4 set: %v): got %q, want %q, %d left", c.params, c.utf8, got, c.want, len(cfg.Params))
		}
	}
}

// TestErrorTextNamesARefusal checks that a warning shows a refusal in the
// rules' own words, which ask for a report, not as a failed query.
func TestErrorTextNamesARefusal(t *testing.T) {
	const want = "prodmask stopped a statement it was about to send, because it isn't a read: this is a fault in prodmask, please report it"
	err := fmt.Errorf("sample orders: %w", refuseStatement("INTO, which writes"))
	if got := ErrorText(err); got != want {
		t.Errorf("ErrorText = %q", got)
	}
}

// TestNoReadOnlyWarning pins the warning for a server that can't mark a
// session read-only, which no test server shows.
func TestNoReadOnlyWarning(t *testing.T) {
	const want = "the server cannot mark the session read-only; every statement prodmask sends is still checked to be a read"
	if noReadOnlyWarning != want {
		t.Errorf("got %q", noReadOnlyWarning)
	}
}
