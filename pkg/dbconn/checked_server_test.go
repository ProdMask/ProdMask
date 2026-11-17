package dbconn

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/refusals"
)

func execAll(ctx context.Context, t *testing.T, db *sql.DB, statements ...string) {
	t.Helper()
	for _, q := range statements {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// readOnlyValue reads the session's read-only variable under whichever
// name the server has.
func readOnlyValue(ctx context.Context, t *testing.T, sess *Session) string {
	t.Helper()
	var v string
	for _, name := range []string{"transaction_read_only", "tx_read_only"} {
		if sess.DB.QueryRowContext(ctx, "SELECT @@SESSION."+name).Scan(&v) == nil {
			return v
		}
	}
	t.Fatal("the server has no read-only variable")
	return ""
}

// sessionDatabase recreates one test database and opens a Session on it as
// the test server's user, who can write.
func sessionDatabase(ctx context.Context, t *testing.T, db string, setup ...string) (*sql.DB, *mysql.Config, *Session) {
	t.Helper()
	admin, cfg := snapshotServer(t)
	execAll(ctx, t, admin, append([]string{"DROP DATABASE IF EXISTS " + db, "CREATE DATABASE " + db}, setup...)...)
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+db) })
	cfg = cfg.Clone()
	cfg.DBName = db
	sess, err := Open(ctx, cfg, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return admin, cfg, sess
}

// TestSessionRefusesWrites sends statements only the read-only rules stop,
// through every path to a Session opened as a user who can write. Each is
// refused and counted, and the server shows that none ran.
func TestSessionRefusesWrites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const db = "prodmask_fixture_refusals"
	admin, _, sess := sessionDatabase(ctx, t, db, "CREATE TABLE "+db+".t (id INT PRIMARY KEY)")
	// A payload that got through would run as the server's own user, so each
	// does no harm if it does: an outfile names a path that exists, which
	// the server refuses to overwrite, and the globals are put back.
	var maxConnections int
	var initConnect string
	if err := admin.QueryRowContext(ctx, "SELECT @@GLOBAL.max_connections, @@GLOBAL.init_connect").Scan(&maxConnections, &initConnect); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.ExecContext(context.Background(), "SET GLOBAL max_connections = ?", maxConnections)
		admin.ExecContext(context.Background(), "SET GLOBAL init_connect = ?", initConnect)
	})
	payloads := []string{
		"SET SESSION transaction_read_only = 0",
		"DO GET_LOCK('prodmask_refusals', 0)",
		fmt.Sprintf("SET GLOBAL max_connections = %d", maxConnections+1),
		"SELECT 1 INTO OUTFILE '.'",
		"SELECT 1 --\x7f'\n INTO OUTFILE '.' #'",
		"SELECT * FROM t --\x7f'\n FOR UPDATE #'",
		"SET @x = 1 --\x7f'\n, transaction_read_only = 0 #'",
		"SET @x = 1 --\x7f'\n, autocommit = 0 #'",
		"SET @x = 1 --\x7f'\n, GLOBAL init_connect = 0x44454C455445 #'",
	}
	if sess.Flavor() == "mariadb" {
		execAll(ctx, t, admin, "CREATE SEQUENCE "+db+".seq")
		payloads = append(payloads, "SELECT NEXTVAL(seq)")
	}
	type path struct {
		name string
		run  func(string) error
	}
	send := func(paths ...path) {
		t.Helper()
		for _, p := range paths {
			for _, q := range payloads {
				expectRefused(t, fmt.Sprintf("%s %q", p.name, q), func() error { return p.run(q) })
			}
		}
	}
	send(
		path{"Exec", func(q string) error { _, err := sess.DB.ExecContext(ctx, q); return err }},
		path{"Query", func(q string) error {
			rows, err := sess.DB.QueryContext(ctx, q)
			if err == nil {
				rows.Close()
			}
			return err
		}},
		path{"Prepare", func(q string) error {
			stmt, err := sess.DB.PrepareContext(ctx, q)
			if err == nil {
				stmt.Close()
			}
			return err
		}},
	)
	// The pool holds one connection: pinning it comes after the pool's own
	// paths, and it's given back before the checks below.
	conn, err := sess.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	send(
		path{"a pinned connection", func(q string) error { _, err := conn.ExecContext(ctx, q); return err }},
		path{"Raw", func(q string) error {
			return conn.Raw(func(dc any) error {
				rows, err := dc.(driver.QueryerContext).QueryContext(ctx, q, nil)
				if err == nil {
					rows.Close()
				}
				return err
			})
		}},
	)
	conn.Close()

	if v := readOnlyValue(ctx, t, sess); v != "1" && !strings.EqualFold(v, "on") {
		t.Errorf("the session's read-only variable reads %s", v)
	}
	var lock sql.NullInt64
	if err := admin.QueryRowContext(ctx, "SELECT IS_USED_LOCK('prodmask_refusals')").Scan(&lock); err != nil || lock.Valid {
		t.Errorf("the lock is held: %v %v", lock, err)
	}
	var now int
	if err := admin.QueryRowContext(ctx, "SELECT @@GLOBAL.max_connections").Scan(&now); err != nil || now != maxConnections {
		t.Errorf("max_connections is %d, was %d: %v", now, maxConnections, err)
	}
}

// TestSessionDropsDSNSettings opens a Session through a config whose DSN
// carries session variables, one of them adding an assignment through its
// value and one holding a canary in its name, and a latin1 charset. None of
// them reaches the server, the Session warns naming the plain ones and
// never a value, and its own settings hold.
func TestSessionDropsDSNSettings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, cfg := snapshotServer(t)
	const canary = "zq7" + "dsncanary"
	cfg = cfg.Clone()
	cfg.DBName = "mysql"
	cfg.Params = map[string]string{
		"wait_timeout":                    "123",
		"sql_mode":                        "'',autocommit=0",
		"TRANSACTION_READ_ONLY":           "0",
		"sql_mode%3D%27" + canary + "%27": "1",
	}
	if err := cfg.Apply(mysql.Charset("latin1", "latin1_swedish_ci")); err != nil {
		t.Fatal(err)
	}
	sess, err := Open(ctx, cfg, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	want := "the DSN's session variables aren't used: TRANSACTION_READ_ONLY, charset, collation, sql_mode, wait_timeout and 1 more"
	if !slices.Contains(sess.Warnings, want) {
		t.Errorf("warnings %q, want %q", sess.Warnings, want)
	}
	for _, w := range sess.Warnings {
		if strings.Contains(w, canary) {
			t.Errorf("a warning holds a value: %q", w)
		}
	}
	for _, c := range []struct{ name, want string }{
		{"autocommit", "1"},
		{"character_set_client", "utf8mb4"},
		{"sql_big_selects", "1"},
	} {
		var got string
		if err := sess.DB.QueryRowContext(ctx, "SELECT @@SESSION."+c.name).Scan(&got); err != nil || got != c.want {
			t.Errorf("%s is %q, want %q: %v", c.name, got, c.want, err)
		}
	}
	var wait int
	if err := sess.DB.QueryRowContext(ctx, "SELECT @@SESSION.wait_timeout").Scan(&wait); err != nil || wait == 123 {
		t.Errorf("wait_timeout is %d: %v", wait, err)
	}
	if v := readOnlyValue(ctx, t, sess); v != "1" && !strings.EqualFold(v, "on") {
		t.Errorf("the session's read-only variable reads %s", v)
	}
}

// TestSessionAllowsBigSelects lowers the global max_join_size, as a host
// can, which makes new connections start with sql_big_selects off and
// refuse reads that may examine more rows. The connection database/sql opens
// after a Session loses its own turns it back on. The global is low only
// while that connection opens and answers: every connection opened
// meanwhile, by any test, keeps the low limit.
func TestSessionAllowsBigSelects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, cfg := snapshotServer(t)
	cfg = cfg.Clone()
	cfg.DBName = "mysql"
	sess, err := Open(ctx, cfg, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	// A bad connection is closed, not put back, so the next statement opens
	// a new one.
	conn, err := sess.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn.Raw(func(any) error { return driver.ErrBadConn })
	conn.Close()

	var old uint64
	if err := admin.QueryRowContext(ctx, "SELECT @@GLOBAL.max_join_size").Scan(&old); err != nil {
		t.Fatal(err)
	}
	restore := func() { admin.ExecContext(context.Background(), "SET GLOBAL max_join_size = ?", old) }
	t.Cleanup(restore)
	execAll(ctx, t, admin, "SET GLOBAL max_join_size = 1000")
	var big string
	err = sess.DB.QueryRowContext(ctx, "SELECT @@SESSION.sql_big_selects").Scan(&big)
	restore()
	if err != nil || big != "1" {
		t.Errorf("sql_big_selects is %q, want 1: %v", big, err)
	}
	var now uint64
	if err := admin.QueryRowContext(ctx, "SELECT @@GLOBAL.max_join_size").Scan(&now); err != nil || now != old {
		t.Errorf("max_join_size is %d, was %d: %v", now, old, err)
	}
}

// TestServerReadsDELAsComment pins what the read-only rules mirror: after
// --, the server reads a DEL as the start of a comment. It sends its
// statement on the admin connection, so it tests the server, not the rules.
func TestServerReadsDELAsComment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, _ := snapshotServer(t)
	rows, err := admin.QueryContext(ctx, "SELECT 1 --\x7f'\n, 2 #'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if cols, err := rows.Columns(); err != nil || len(cols) != 2 {
		t.Errorf("columns %q: %v; the server didn't read the DEL as a comment", cols, err)
	}
}

// TestReadOnlySessionStopsWhatTheRulesCantSee pins the first guard on its
// own: a stored function that writes, called from a SELECT the rules allow,
// gets error 1792 from the read-only session and writes nothing, and on
// MariaDB so does a view that calls NEXTVAL. The rules refuse nothing here,
// so it holds without them.
func TestReadOnlySessionStopsWhatTheRulesCantSee(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const db = "prodmask_fixture_readonly"
	admin, _, sess := sessionDatabase(ctx, t, db,
		"CREATE TABLE "+db+".t (id INT)",
		"CREATE FUNCTION "+db+".w() RETURNS INT DETERMINISTIC MODIFIES SQL DATA BEGIN INSERT INTO "+db+".t VALUES (1); RETURN 1; END")
	reads := []string{"SELECT w()"}
	if sess.Flavor() == "mariadb" {
		execAll(ctx, t, admin, "CREATE SEQUENCE "+db+".seq", "CREATE VIEW "+db+".v AS SELECT NEXTVAL("+db+".seq) AS n")
		reads = append(reads, "SELECT n FROM v")
	}
	before := refusals.Count()
	for _, q := range reads {
		var n int
		err := sess.DB.QueryRowContext(ctx, q).Scan(&n)
		var my *mysql.MySQLError
		if !errors.As(err, &my) || my.Number != 1792 {
			t.Errorf("%s: %v, want error 1792 from the read-only session", q, err)
		}
	}
	if n := refusals.Count() - before; n != 0 {
		t.Errorf("the rules refused %d of these reads", n)
	}
	var rows int
	if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+db+".t").Scan(&rows); err != nil || rows != 0 {
		t.Errorf("the function wrote %d rows: %v", rows, err)
	}
}
