package dbconn

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestConnectionLost(t *testing.T) {
	lost := []error{
		driver.ErrBadConn, sql.ErrConnDone, mysql.ErrInvalidConn, context.Canceled,
		fmt.Errorf("read rows: %w", context.DeadlineExceeded),
		&mysql.MySQLError{Number: 1927}, &mysql.MySQLError{Number: 1053}, &mysql.MySQLError{Number: 1213},
	}
	for _, err := range lost {
		if !connectionLost(err) {
			t.Errorf("%v: not counted as a lost connection", err)
		}
	}
	kept := []error{
		&mysql.MySQLError{Number: 1146}, // no such table
		&mysql.MySQLError{Number: 1792}, // write in a read-only transaction
		&mysql.MySQLError{Number: 1317}, // KILL QUERY: the statement stops, the transaction stays
		&mysql.MySQLError{Number: 1205}, // lock wait timeout
	}
	for _, err := range kept {
		if connectionLost(err) {
			t.Errorf("%v: counted as a lost connection", err)
		}
	}
}

// snapshotServer connects as a user that can create databases, or skips the
// test. It needs PRODMASK_TEST_DSN, like the scan's integration tests.
func snapshotServer(t *testing.T) (*sql.DB, *mysql.Config) {
	t.Helper()
	dsn := os.Getenv("PRODMASK_TEST_DSN")
	if dsn == "" {
		t.Skip("PRODMASK_TEST_DSN is not set")
	}
	cfg, err := mysql.ParseDSN(dsn)
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
	return admin, cfg
}

// snapshotDatabase recreates prodmask_fixture_snapshot with one table and
// one row, written in a zone five and a half hours east of UTC.
func snapshotDatabase(ctx context.Context, t *testing.T, admin *sql.DB) {
	t.Helper()
	conn, err := admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, q := range []string{
		"DROP DATABASE IF EXISTS prodmask_fixture_snapshot",
		"CREATE DATABASE prodmask_fixture_snapshot",
		"CREATE TABLE prodmask_fixture_snapshot.t (id INT PRIMARY KEY, at TIMESTAMP NULL)",
		"SET time_zone = '+05:30'",
		"INSERT INTO prodmask_fixture_snapshot.t VALUES (1, '2026-01-01 05:30:00')",
	} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func openTestSnapshot(ctx context.Context, t *testing.T, cfg *mysql.Config) *Snapshot {
	t.Helper()
	cfg = cfg.Clone()
	cfg.DBName = "prodmask_fixture_snapshot"
	s, err := OpenSnapshot(ctx, cfg, SnapshotOptions{LockWait: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSnapshotSeesOneMoment(t *testing.T) {
	admin, cfg := snapshotServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	snapshotDatabase(ctx, t, admin)
	s := openTestSnapshot(ctx, t, cfg)

	if _, err := admin.ExecContext(ctx, "INSERT INTO prodmask_fixture_snapshot.t VALUES (2, NULL)"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.QueryRowContext(ctx, "SELECT COUNT(*) FROM t").Scan(&n); err != nil || n != 1 {
		t.Errorf("the snapshot sees %d rows (%v), want 1: the row added after it started", n, err)
	}
	if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM prodmask_fixture_snapshot.t").Scan(&n); err != nil || n != 2 {
		t.Errorf("outside the snapshot: %d rows (%v), want 2", n, err)
	}

	var at, zone, level string
	var lockWait, waitTimeout int
	if err := s.QueryRowContext(ctx, "SELECT CAST(at AS CHAR), @@SESSION.time_zone, @@SESSION.lock_wait_timeout, @@SESSION.wait_timeout FROM t WHERE id = 1").
		Scan(&at, &zone, &lockWait, &waitTimeout); err != nil {
		t.Fatal(err)
	}
	if at != "2026-01-01 00:00:00" || zone != "+00:00" || lockWait != 3 {
		t.Errorf("got at %q, time_zone %q, lock_wait_timeout %d; want the TIMESTAMP in UTC, +00:00 and 3", at, zone, lockWait)
	}
	// 2147483 is the most Windows servers allow, 31536000 the most elsewhere.
	if waitTimeout != 2147483 && waitTimeout != 31536000 {
		t.Errorf("wait_timeout %d, want the server's maximum", waitTimeout)
	}
	for _, name := range []string{"transaction_isolation", "tx_isolation"} {
		if s.QueryRowContext(ctx, "SELECT @@SESSION."+name).Scan(&level) == nil {
			break
		}
	}
	if level != "REPEATABLE-READ" {
		t.Errorf("isolation %q", level)
	}

	// A write never reaches the server through the snapshot's methods.
	if _, err := s.ExecContext(ctx, "INSERT INTO t VALUES (3, NULL)"); !errors.Is(err, ErrStatementRefused) {
		t.Errorf("write through ExecContext: %v; want ErrStatementRefused", err)
	}
	if _, err := s.QueryContext(ctx, "SELECT * FROM t FOR UPDATE"); !errors.Is(err, ErrStatementRefused) {
		t.Errorf("locking read: %v; want ErrStatementRefused", err)
	}
	if err := s.QueryRowContext(ctx, "SELECT 1 INTO @x").Scan(&n); !errors.Is(err, ErrStatementRefused) {
		t.Errorf("SELECT INTO: %v; want ErrStatementRefused", err)
	}
	if err := s.Check(ctx); err != nil {
		t.Errorf("after the refused statements: %v", err)
	}

	// The transaction is read-only too. A write sent past the rules fails
	// alone: the snapshot stays.
	_, err := s.conn.ExecContext(ctx, "INSERT INTO t VALUES (3, NULL)")
	var my *mysql.MySQLError
	if !errors.As(err, &my) || my.Number != 1792 {
		t.Errorf("write on the snapshot's connection: %v; want error 1792 (read-only transaction)", err)
	}
	if err := s.Check(ctx); err != nil {
		t.Errorf("after the failed write: %v", err)
	}
}

// TestSnapshotCheckSeesAnEndedTransaction ends the transaction behind the
// rules' back, as a statement they don't foresee could, and expects Check
// to notice.
func TestSnapshotCheckSeesAnEndedTransaction(t *testing.T) {
	admin, cfg := snapshotServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	snapshotDatabase(ctx, t, admin)
	s := openTestSnapshot(ctx, t, cfg)
	if err := s.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(ctx); !errors.Is(err, ErrSnapshotLost) {
		t.Fatalf("Check after COMMIT: %v, want ErrSnapshotLost", err)
	}
	var n int
	if err := s.QueryRowContext(ctx, "SELECT COUNT(*) FROM t").Scan(&n); !errors.Is(err, ErrSnapshotLost) {
		t.Errorf("a read after the loss: %v", err)
	}
}

func TestSnapshotNeverReconnects(t *testing.T) {
	admin, cfg := snapshotServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	snapshotDatabase(ctx, t, admin)
	s := openTestSnapshot(ctx, t, cfg)
	if err := s.Check(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := admin.ExecContext(ctx, fmt.Sprintf("KILL %d", s.ID)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.QueryRowContext(ctx, "SELECT COUNT(*) FROM t").Scan(&n); err == nil {
		t.Fatal("a query after KILL succeeded")
	}
	if err := s.Err(); !errors.Is(err, ErrSnapshotLost) {
		t.Fatalf("Err() = %v, want ErrSnapshotLost", err)
	}
	// Every later call fails without trying a new connection.
	if _, err := s.QueryContext(ctx, "SELECT 1"); !errors.Is(err, ErrSnapshotLost) {
		t.Errorf("QueryContext after the loss: %v", err)
	}
	if _, err := s.PrepareContext(ctx, "SELECT 1"); !errors.Is(err, ErrSnapshotLost) {
		t.Errorf("PrepareContext after the loss: %v", err)
	}
	if err := s.Check(ctx); !errors.Is(err, ErrSnapshotLost) {
		t.Errorf("Check after the loss: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
