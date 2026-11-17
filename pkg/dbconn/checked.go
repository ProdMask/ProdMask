package dbconn

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/refusals"
)

// openCheckedPool opens one of a Session's pools. Every statement a
// connection from it sends, through any database/sql path, passes the
// read-only rules first, and a refused one never leaves the process. The
// connection is utf8mb4, in which the server reads a statement's bytes as
// the rules do. It sends one statement at a time and binds its values: with
// interpolation, bound arguments, which include key names that can hold
// personal data, would be written into the statement text, which server
// error messages may quote.
func openCheckedPool(cfg *mysql.Config) (*sql.DB, error) {
	cfg, err := checkedConfig(cfg)
	if err != nil {
		return nil, err
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	return onePool(checkedConnector{connector}), nil
}

// checkedConfig is cfg as a Session's pool connects with it: one statement
// at a time, values bound, no local files, and utf8mb4 whatever the DSN
// said.
func checkedConfig(cfg *mysql.Config) (*mysql.Config, error) {
	cfg = cfg.Clone()
	cfg.MultiStatements = false
	cfg.InterpolateParams = false
	cfg.AllowAllFiles = false
	if err := cfg.Apply(mysql.Charset("utf8mb4", "utf8mb4_general_ci")); err != nil {
		return nil, err
	}
	return cfg, nil
}

// checkedConnector hands out the driver's connections wrapped in
// checkedConn, including the new one database/sql opens after a timeout
// kills the old.
type checkedConnector struct{ c driver.Connector }

func (k checkedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	c, err := k.c.Connect(ctx)
	if err != nil {
		return nil, err
	}
	dc, ok := c.(driverConn)
	if !ok {
		c.Close()
		return nil, errors.New("the database driver's connection can't be checked")
	}
	return &checkedConn{c: dc}, nil
}

// Driver returns a driver that opens nothing: a connection it opened from a
// caller's DSN would have none of the Session's settings or checks.
func (checkedConnector) Driver() driver.Driver { return refusingDriver{} }

type refusingDriver struct{}

func (refusingDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("a scan session's driver opens no connection of its own")
}

// driverConn is what checkedConn passes on to. The MySQL driver's
// connection has all of it.
type driverConn interface {
	driver.Conn
	driver.ConnPrepareContext
	driver.QueryerContext
	driver.ExecerContext
	driver.ConnBeginTx
	driver.Pinger
	driver.SessionResetter
	driver.Validator
	driver.NamedValueChecker
}

// checkedConn is one of a Session's connections. Reads go out through the
// query methods, session SETs through Exec, and either through Prepare.
// Anything else, and every transaction, is refused before it's sent, and
// counted. It holds the driver's connection in a field rather than
// embedding it, so no unchecked method is promoted, and nothing unwraps it.
// It has no deprecated Execer or Queryer, so database/sql always calls the
// checked methods. The driver's errors come back as they were, ErrSkip
// included, which database/sql compares by identity.
type checkedConn struct{ c driverConn }

var (
	_ driver.Conn               = (*checkedConn)(nil)
	_ driver.ConnPrepareContext = (*checkedConn)(nil)
	_ driver.QueryerContext     = (*checkedConn)(nil)
	_ driver.ExecerContext      = (*checkedConn)(nil)
	_ driver.ConnBeginTx        = (*checkedConn)(nil)
	_ driver.Pinger             = (*checkedConn)(nil)
	_ driver.SessionResetter    = (*checkedConn)(nil)
	_ driver.Validator          = (*checkedConn)(nil)
	_ driver.NamedValueChecker  = (*checkedConn)(nil)
)

// refused counts a refusal, with its fixed words, which never quote the
// statement.
func refused(err error) error {
	refusals.Add(err.Error())
	return err
}

func (c *checkedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := checkStatement(query, false); err != nil {
		return nil, refused(err)
	}
	return c.c.QueryContext(ctx, query, args)
}

func (c *checkedConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := checkStatement(query, true); err != nil {
		return nil, refused(err)
	}
	return c.c.ExecContext(ctx, query, args)
}

func (c *checkedConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if err := checkEither(query); err != nil {
		return nil, refused(err)
	}
	return c.c.PrepareContext(ctx, query)
}

func (c *checkedConn) Prepare(query string) (driver.Stmt, error) {
	if err := checkEither(query); err != nil {
		return nil, refused(err)
	}
	return c.c.Prepare(query)
}

// BeginTx and Begin refuse every transaction: nothing opens one on a
// Session, and one could hold row locks and a snapshot across statements.
func (c *checkedConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return nil, refuseTransaction()
}

func (c *checkedConn) Begin() (driver.Tx, error) { return nil, refuseTransaction() }

func refuseTransaction() error {
	return refused(refuseStatement("a transaction, which a scan session never opens"))
}

func (c *checkedConn) Ping(ctx context.Context) error              { return c.c.Ping(ctx) }
func (c *checkedConn) ResetSession(ctx context.Context) error      { return c.c.ResetSession(ctx) }
func (c *checkedConn) IsValid() bool                               { return c.c.IsValid() }
func (c *checkedConn) CheckNamedValue(nv *driver.NamedValue) error { return c.c.CheckNamedValue(nv) }
func (c *checkedConn) Close() error                                { return c.c.Close() }

// checkEither allows a read or a session SET, since a prepared statement
// can later run either way.
func checkEither(query string) error {
	err := checkStatement(query, false)
	if err != nil && checkStatement(query, true) == nil {
		return nil
	}
	return err
}

// dropDSNSettings takes a DSN's own session variables out of cfg. They
// never reach the server: the driver writes each value into its SET as
// written, so a value could add an assignment no check sees. It returns the
// warning for them, and for a charset or collation other than the ones the
// pool sets. The warning names only names of letters, digits and
// underscores, and counts any other, since a key can hold a value
// URL-encoded into it. It never holds a value.
func dropDSNSettings(cfg *mysql.Config) string {
	var names []string
	others := 0
	for k := range cfg.Params {
		if plainName(k) {
			names = append(names, k)
		} else {
			others++
		}
	}
	cfg.Params = nil
	if cs := dsnCharset(cfg); cs != "" && !strings.EqualFold(cs, "utf8mb4") {
		names = append(names, "charset")
	}
	if cfg.Collation != "" && !strings.EqualFold(cfg.Collation, "utf8mb4_general_ci") {
		names = append(names, "collation")
	}
	sort.Strings(names)
	const lead = "the DSN's session variables aren't used: "
	switch {
	case others == 0 && len(names) == 0:
		return ""
	case others == 0:
		return lead + strings.Join(names, ", ")
	case len(names) == 0:
		return fmt.Sprintf("%s%d whose names aren't plain words", lead, others)
	}
	return fmt.Sprintf("%s%s and %d more", lead, strings.Join(names, ", "), others)
}

// dsnCharset returns the charset a DSN set, which the driver keeps to
// itself but writes back into FormatDSN's text.
func dsnCharset(cfg *mysql.Config) string {
	c := cfg.Clone()
	c.Params = nil
	dsn := c.FormatDSN()
	i := strings.LastIndexByte(dsn, '?')
	if i < 0 {
		return ""
	}
	q, err := url.ParseQuery(dsn[i+1:])
	if err != nil {
		return ""
	}
	return q.Get("charset")
}

func plainName(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return s != ""
}

// onePool makes the pool of one connection every session uses.
func onePool(c driver.Connector) *sql.DB {
	db := sql.OpenDB(c)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return db
}
