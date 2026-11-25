package mcp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
)

const runnerDB = "prodmask_fixture_runner"

// runnerFixture recreates prodmask_fixture_runner: a table a function
// writes to, a function that writes, one that takes a user lock, a
// 1,000-row table, a 30-row one, a view of their cross join, and a table
// holding a 2 MiB value. It returns the admin connection and a runner over
// root's sessions, as with --allow-write-login, the worst case.
func runnerFixture(ctx context.Context, t *testing.T, timeout time.Duration) (*sql.DB, *Runner) {
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
	var values []string
	for i := 1; i <= 1000; i++ {
		values = append(values, fmt.Sprintf("(%d, %d)", i, 1000-i))
	}
	for _, q := range []string{
		"DROP DATABASE IF EXISTS " + runnerDB,
		"CREATE DATABASE " + runnerDB,
		"CREATE TABLE " + runnerDB + ".w_t (id INT)",
		"CREATE FUNCTION " + runnerDB + ".w() RETURNS INT DETERMINISTIC MODIFIES SQL DATA BEGIN INSERT INTO " + runnerDB + ".w_t VALUES (1); RETURN 1; END",
		"CREATE FUNCTION " + runnerDB + ".lk() RETURNS INT DETERMINISTIC NO SQL SQL SECURITY INVOKER RETURN GET_LOCK('pm_runner_lock', 0)",
		"CREATE TABLE " + runnerDB + ".big (i INT PRIMARY KEY, v INT)",
		"INSERT INTO " + runnerDB + ".big VALUES " + strings.Join(values, ", "),
		"CREATE TABLE " + runnerDB + ".small (i INT PRIMARY KEY)",
		"INSERT INTO " + runnerDB + ".small SELECT i FROM " + runnerDB + ".big WHERE i <= 30",
		"CREATE VIEW " + runnerDB + ".bigv AS SELECT a.i * 1000000 + b.i * 1000 + c.i AS v FROM " + runnerDB + ".big a, " +
			runnerDB + ".big b, " + runnerDB + ".small c",
		"CREATE TABLE " + runnerDB + ".wide (id INT PRIMARY KEY, v LONGTEXT)",
		"INSERT INTO " + runnerDB + ".wide VALUES (1, REPEAT('x', 2097152))",
	} {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q[:min(len(q), 80)], err)
		}
	}
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+runnerDB) })

	cfg = cfg.Clone()
	cfg.DBName = runnerDB
	open := func(opts dbconn.SessionOptions) *dbconn.Session {
		opts.Timeout, opts.Label = timeout, "the test server"
		s, err := dbconn.OpenWith(ctx, cfg, opts)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	agent := open(dbconn.SessionOptions{SelectLimit: 101, ServerBigSelects: true, ColumnsWithAlias: true})
	tools := open(dbconn.SessionOptions{})
	r, err := NewRunner(agent, tools, 100, func() dbconn.AgentScope {
		return dbconn.AgentScope{Flavor: agent.Flavor(), Database: runnerDB,
			Tables: []string{"w_t", "big", "small", "bigv", "wide"}, Functions: []string{"w", "lk"}}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A statement the client cut short and the server still runs is
	// stopped before the database goes.
	t.Cleanup(func() {
		if r.cutShort != 0 {
			admin.ExecContext(context.Background(), fmt.Sprintf("KILL %d", r.cutShort))
		}
	})
	return admin, r
}

func serverError(err error) int {
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return int(my.Number)
	}
	return 0
}

// TestRunnerReadOnlySession runs a stored function that writes: the
// statement rules allow its call, so the read-only session alone stops it.
func TestRunnerReadOnlySession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, r := runnerFixture(ctx, t, 5*time.Second)
	if _, err := r.Query(ctx, "SELECT "+runnerDB+".w()", 0); serverError(err) != 1792 {
		t.Fatalf("a function that writes: %v, want error 1792", err)
	}
	var n int
	if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+runnerDB+".w_t").Scan(&n); err != nil || n != 0 {
		t.Fatalf("the table holds %d rows (%v)", n, err)
	}
}

// TestRunnerLocks calls a function that takes a user lock: the release after
// the statement frees it.
func TestRunnerLocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, r := runnerFixture(ctx, t, 5*time.Second)
	res, err := r.Query(ctx, "SELECT "+runnerDB+".lk()", 0)
	if err != nil || len(res.Rows) != 1 || string(res.Rows[0][0].Bytes) != "1" {
		t.Fatalf("a function that takes a lock: %v, %+v", err, res)
	}
	var holder sql.NullInt64
	if err := admin.QueryRowContext(ctx, "SELECT IS_USED_LOCK('pm_runner_lock')").Scan(&holder); err != nil || holder.Valid {
		t.Fatalf("the lock is still held by connection %v (%v)", holder, err)
	}
}

// TestRunnerRowCap reads a 1,000-row table with a ceiling of 100: the read
// stops there with more rows, and the server sent at most 101.
func TestRunnerRowCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, r := runnerFixture(ctx, t, 5*time.Second)
	const statement = "SELECT * FROM big"
	var before, after int
	if r.agent.Flavor() == "mariadb" {
		rowsSent := func(conn *sql.Conn) int {
			var name string
			var n int
			if err := conn.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Rows_sent'").Scan(&name, &n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		r.hook = func(stage string, conn *sql.Conn) {
			if stage == "before" {
				before = rowsSent(conn)
			} else {
				after = rowsSent(conn)
			}
		}
	}
	res, err := r.Query(ctx, statement, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.cutShort != 0 {
		t.Fatal("the server sent more than the ceiling plus one: the read went past it, and prodmask cut the statement short")
	}
	if len(res.Rows) != 100 || !res.MoreRows {
		t.Errorf("a 1,000-row table: %d rows, more %v", len(res.Rows), res.MoreRows)
	}
	var sent int
	if r.agent.Flavor() == "mariadb" {
		// The first SHOW STATUS's own row counts too, and the warnings'.
		sent = after - before - 1 - len(res.Warnings)
	} else if err := admin.QueryRowContext(ctx, "SELECT h.ROWS_SENT FROM performance_schema.events_statements_history h "+
		"JOIN performance_schema.threads t ON t.THREAD_ID = h.THREAD_ID WHERE t.PROCESSLIST_ID = ? AND h.SQL_TEXT = ?",
		r.lastID, statement).Scan(&sent); err != nil {
		t.Fatalf("the agent's statement isn't in performance_schema's history: %v", err)
	}
	if sent > 101 || sent < 100 {
		t.Errorf("the server sent %d rows, want at most the ceiling plus one, 101", sent)
	}
}

// TestRunnerTimeLimit runs a cross join past the time limit: the server stops
// it, and the next call runs on a connection read back as read-only.
func TestRunnerTimeLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, r := runnerFixture(ctx, t, time.Second)
	start := time.Now()
	_, err := r.Query(ctx, "SELECT SUM(a.i) FROM big a, big b, big c WHERE a.i + b.i + c.i > 0", 0)
	if n := serverError(err); n != 3024 && n != 1969 {
		t.Fatalf("a statement past the limit: %v, want the server's time limit error", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the statement stopped after %s", took)
	}
	variable := readOnlyVariable(r.agent.Settings)
	res, err := r.Query(ctx, "SELECT @@SESSION."+variable, 0)
	if err != nil || len(res.Rows) != 1 || string(res.Rows[0][0].Bytes) != "1" {
		t.Fatalf("the next call: %v, %+v", err, res)
	}
}

// TestRunnerTableStatement sorts a large view with MySQL's TABLE: the call
// still stops at the limit, by the server or, at the limit plus the grace,
// by the client.
func TestRunnerTableStatement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, r := runnerFixture(ctx, t, time.Second)
	if r.agent.Flavor() != "mysql" {
		t.Skip("TABLE is MySQL's")
	}
	start := time.Now()
	_, err := r.Query(ctx, "TABLE bigv ORDER BY v", 0)
	took := time.Since(start)
	if n := serverError(err); n != 3024 && !errors.Is(err, ErrTimeLimit) {
		t.Fatalf("TABLE past the limit: %v", err)
	}
	if took > time.Second+grace+2*time.Second {
		t.Errorf("TABLE stopped after %s", took)
	}
	t.Logf("TABLE bigv ORDER BY v stopped after %s: %v", took.Round(10*time.Millisecond), err)
}

// TestRunnerWait cuts a slow statement short from the client: the server
// still runs it, the admin sees it in PROCESSLIST when the next call
// arrives, and that call waits until it's gone, or answers busy.
func TestRunnerWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, r := runnerFixture(ctx, t, 3*time.Second)
	callCtx, cancelCall := context.WithCancel(ctx)
	time.AfterFunc(300*time.Millisecond, cancelCall)
	_, err := r.Query(callCtx, "SELECT SUM(a.i) FROM big a, big b, big c WHERE a.i + b.i + c.i > 0", 0)
	if !errors.Is(err, context.Canceled) || r.cutShort == 0 {
		t.Fatalf("a call cancelled mid-statement: %v, cut short %d", err, r.cutShort)
	}
	id := r.cutShort
	var n int
	if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID = ?", id).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the admin doesn't see the statement cut short in PROCESSLIST: %d (%v)", n, err)
	}
	start := time.Now()
	res, err := r.Query(ctx, "SELECT 1", 0)
	took := time.Since(start)
	switch {
	case errors.Is(err, ErrStillRunning):
		t.Logf("the next call answered busy after %s", took.Round(10*time.Millisecond))
	case err != nil:
		t.Fatalf("the next call: %v", err)
	case len(res.Rows) != 1:
		t.Fatalf("the next call: %+v", res)
	default:
		if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID = ?", id).Scan(&n); err != nil || n != 0 {
			t.Fatalf("the next call ran while the statement cut short still ran: %d (%v)", n, err)
		}
		if took < 500*time.Millisecond {
			t.Errorf("the next call took %s: it didn't wait", took)
		}
		t.Logf("the next call waited %s", took.Round(10*time.Millisecond))
	}
}

// TestRunnerWithheld reads a 2 MiB value: it's withheld, its size kept.
func TestRunnerWithheld(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, r := runnerFixture(ctx, t, 5*time.Second)
	res, err := r.Query(ctx, "SELECT v FROM wide", 0)
	if err != nil || len(res.Rows) != 1 || res.Rows[0][0].Withheld != 2097152 || res.Rows[0][0].Bytes != nil {
		t.Fatalf("a 2 MiB value: %v, %+v", err, res)
	}
}
