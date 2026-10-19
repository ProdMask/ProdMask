package dbconn

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// ErrSnapshotLost is returned by every call on a Snapshot after its
// connection or its transaction was lost: the snapshot went with it.
var ErrSnapshotLost = errors.New("lost the connection that held the snapshot")

// ErrNotRepeatableRead is returned by OpenSnapshot when the session won't
// take REPEATABLE READ, the only level that holds a consistent snapshot.
var ErrNotRepeatableRead = errors.New("the session did not take REPEATABLE READ, so it can't hold a snapshot")

// Snapshot is one pinned connection that sees a database as it was at one
// moment: a REPEATABLE READ transaction started READ ONLY, WITH CONSISTENT
// SNAPSHOT. Every statement runs on that connection, so InnoDB tables read
// minutes apart still agree with each other.
//
// The connection is never replaced. A database/sql pool moves its work to a
// new connection when one breaks, which would quietly read the rest from a
// later moment; a pinned connection fails instead. Once the connection is
// lost, every later call returns ErrSnapshotLost, and the reader has to
// start again with a new snapshot.
//
// The session reads TIMESTAMP values in UTC (time_zone '+00:00'), whatever
// the server's zone, and starts with SET NAMES utf8mb4. Statement time
// limits are off, since reading a whole table takes as long as it takes;
// waits for metadata locks are bounded. The connection may idle for as long
// as the server allows (wait_timeout at its maximum).
//
// Only statements that keep the snapshot run: ExecContext takes SETs of
// session variables, and the query methods take reads (SELECT, SHOW,
// DESCRIBE, EXPLAIN, VALUES, TABLE, and WITH ... SELECT). INTO, locking
// reads and executable comments are refused anywhere. A refused statement
// returns ErrStatementRefused without running, and the snapshot stays. The
// rules don't vet functions, so callers must not call ones that write.
type Snapshot struct {
	Server   model.ServerInfo
	Database string
	// ID is the connection's CONNECTION_ID(), which another session can
	// look for in the process list or end with KILL.
	ID int64
	// Started is when the snapshot was taken, by the local clock.
	Started time.Time

	db   *sql.DB
	conn *sql.Conn

	mu   sync.Mutex
	lost error
}

// SnapshotOptions tunes the snapshot's session. Zero values pick the
// defaults.
type SnapshotOptions struct {
	// LockWait bounds how long a statement waits for a metadata lock
	// (lock_wait_timeout). Default 10 seconds.
	LockWait time.Duration
	// NetWrite is how long the server waits for the client to take more
	// rows before it gives up (net_write_timeout). A reader that writes
	// each batch somewhere slow needs it long. Default 10 minutes.
	NetWrite time.Duration
}

// OpenSnapshot connects to the database in cfg and starts the snapshot.
func OpenSnapshot(ctx context.Context, cfg *mysql.Config, opts SnapshotOptions) (*Snapshot, error) {
	cfg = cfg.Clone()
	cfg.MultiStatements = false
	cfg.AllowAllFiles = false
	cfg.ParseTime = false
	cfg.InterpolateParams = false
	if cfg.ConnectionAttributes == "" {
		cfg.ConnectionAttributes = "program_name:prodmask"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 10 * time.Minute
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if opts.LockWait <= 0 {
		opts.LockWait = 10 * time.Second
	}
	if opts.NetWrite <= 0 {
		opts.NetWrite = 10 * time.Minute
	}

	db, err := openPool(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to %s: %w", Describe(cfg), err)
	}
	s := &Snapshot{Database: cfg.DBName, db: db, conn: conn}
	if err := s.start(ctx, cfg, opts); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Snapshot) start(ctx context.Context, cfg *mysql.Config, opts SnapshotOptions) error {
	var version, comment string
	if err := s.conn.QueryRowContext(ctx, "SELECT VERSION(), @@version_comment, CONNECTION_ID()").Scan(&version, &comment, &s.ID); err != nil {
		return fmt.Errorf("read server version: %w", err)
	}
	flavor := "mysql"
	if strings.Contains(strings.ToLower(version+" "+comment), "mariadb") {
		flavor = "mariadb"
	}
	s.Server = model.ServerInfo{Flavor: flavor, Version: version, Address: Address(cfg), User: cfg.User}

	stmts := []string{
		"SET NAMES utf8mb4",
		"SET SESSION time_zone = '+00:00'",
		fmt.Sprintf("SET SESSION lock_wait_timeout = %d", max(1, int(opts.LockWait.Seconds()))),
		fmt.Sprintf("SET SESSION net_write_timeout = %d", max(1, int(opts.NetWrite.Seconds()))),
		// The most Linux allows; the server lowers it to its own maximum
		// (2147483 on Windows), with a warning.
		"SET SESSION wait_timeout = 31536000",
	}
	switch {
	case flavor == "mariadb" && hasVariable(ctx, s.conn, "max_statement_time"):
		stmts = append(stmts, "SET SESSION max_statement_time = 0")
	case flavor == "mysql" && hasVariable(ctx, s.conn, "max_execution_time"):
		stmts = append(stmts, "SET SESSION max_execution_time = 0")
	}
	stmts = append(stmts,
		"SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
		"START TRANSACTION READ ONLY, WITH CONSISTENT SNAPSHOT")
	for _, q := range stmts {
		if _, err := s.conn.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("start the snapshot: %w", err)
		}
	}
	s.Started = time.Now()

	// A consistent snapshot needs REPEATABLE READ; under any other level the
	// server ignores WITH CONSISTENT SNAPSHOT.
	level := ""
	for _, name := range []string{"transaction_isolation", "tx_isolation"} {
		if err := s.conn.QueryRowContext(ctx, "SELECT @@SESSION."+name).Scan(&level); err == nil {
			break
		}
	}
	if !strings.EqualFold(level, "REPEATABLE-READ") {
		return ErrNotRepeatableRead
	}
	return nil
}

// ExecContext runs a SET of session variables in the snapshot's session.
// Anything else returns ErrStatementRefused without running.
func (s *Snapshot) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if err := s.Err(); err != nil {
		return nil, err
	}
	if err := checkStatement(query, true); err != nil {
		return nil, err
	}
	r, err := s.conn.ExecContext(ctx, query, args...)
	return r, s.note(err)
}

// QueryContext runs a read in the snapshot. A connection lost while the
// rows are read shows up in rows.Err(), and then in every later call.
func (s *Snapshot) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if err := s.Err(); err != nil {
		return nil, err
	}
	if err := checkStatement(query, false); err != nil {
		return nil, err
	}
	rows, err := s.conn.QueryContext(ctx, query, args...)
	return rows, s.note(err)
}

// QueryRowContext runs a read that returns at most one row. Its error
// shows up in Scan.
func (s *Snapshot) QueryRowContext(ctx context.Context, query string, args ...any) *Row {
	if err := s.Err(); err != nil {
		return &Row{s: s, err: err}
	}
	if err := checkStatement(query, false); err != nil {
		return &Row{s: s, err: err}
	}
	return &Row{s: s, row: s.conn.QueryRowContext(ctx, query, args...)}
}

// PrepareContext prepares a read on the snapshot's connection. Queries
// through it use the binary protocol, which returns FLOAT and DOUBLE values
// exactly; the text protocol rounds them to a few digits.
func (s *Snapshot) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	if err := s.Err(); err != nil {
		return nil, err
	}
	if err := checkStatement(query, false); err != nil {
		return nil, err
	}
	stmt, err := s.conn.PrepareContext(ctx, query)
	return stmt, s.note(err)
}

// Row is the result of QueryRowContext.
type Row struct {
	s   *Snapshot
	row *sql.Row
	err error
}

// Scan copies the row's columns into dest, or returns sql.ErrNoRows.
func (r *Row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	return r.s.note(r.row.Scan(dest...))
}

// Check confirms the snapshot still holds, so nothing was read from a later
// moment: the same connection answers, and its transaction is still open.
// SET TRANSACTION fails with error 1568 inside an open transaction; any
// other outcome means the transaction, and the snapshot, ended.
func (s *Snapshot) Check(ctx context.Context) error {
	var id int64
	if err := s.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id); err != nil {
		return err
	}
	if id != s.ID {
		return s.lose()
	}
	_, err := s.conn.ExecContext(ctx, "SET TRANSACTION READ ONLY")
	var my *mysql.MySQLError
	if errors.As(err, &my) && my.Number == errTransactionInProgress {
		return nil
	}
	return s.lose()
}

func (s *Snapshot) lose() error {
	s.mu.Lock()
	s.lost = ErrSnapshotLost
	s.mu.Unlock()
	return ErrSnapshotLost
}

// Err returns ErrSnapshotLost once a call found the connection lost, and
// nil before.
func (s *Snapshot) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lost
}

// note records a lost connection and passes err through.
func (s *Snapshot) note(err error) error {
	if err != nil && connectionLost(err) {
		s.lose()
	}
	return err
}

// Close ends the snapshot and its connection.
func (s *Snapshot) Close() error {
	if s.conn != nil {
		if s.Err() == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.conn.ExecContext(ctx, "ROLLBACK")
			cancel()
		}
		s.conn.Close()
	}
	return s.db.Close()
}

// Server error numbers after which the connection, or the transaction that
// holds the snapshot, is gone.
const (
	errServerShutdown     = 1053 // ER_SERVER_SHUTDOWN
	errLockDeadlock       = 1213 // ER_LOCK_DEADLOCK: the transaction was rolled back
	errConnectionKilled   = 1927 // ER_CONNECTION_KILLED (MariaDB)
	errClientIdleTimedOut = 4031 // ER_CLIENT_INTERACTION_TIMEOUT (MySQL)

	errTransactionInProgress = 1568 // ER_CANT_CHANGE_TX_CHARACTERISTICS
)

// connectionLost reports whether err means the snapshot's connection or its
// transaction is gone, rather than one statement failing.
func connectionLost(err error) bool {
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		switch my.Number {
		case errServerShutdown, errLockDeadlock, errConnectionKilled, errClientIdleTimedOut:
			return true
		}
		return false
	}
	var ne net.Error
	return errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, mysql.ErrInvalidConn) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		// The driver closes the connection when a context ends mid-statement.
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &ne)
}
