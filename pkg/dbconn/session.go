package dbconn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// Session is a pool of exactly one connection to the scanned database. Every
// connection in it is read-only, gives up waiting for metadata locks after a
// few seconds, and has a server-side statement timeout. Statements run one at
// a time, and autocommit is on, so no lock or snapshot outlives a statement.
// When a timeout kills the connection, database/sql opens a new one with the
// same settings.
type Session struct {
	DB       *sql.DB
	Server   model.ServerInfo
	Database string
	Timeout  time.Duration
	// ServerTimeout reports whether the server enforces Timeout itself
	// (max_statement_time or max_execution_time). Without it, a statement
	// the client gives up on keeps running on the server.
	ServerTimeout bool
	Warnings      []string
	// Settings are the session variables every connection sets on connect,
	// by name, as sent: what a caller may read back.
	Settings map[string]string
}

// Flavor is "mariadb" or "mysql".
func (s *Session) Flavor() string { return s.Server.Flavor }

// Close closes the pool.
func (s *Session) Close() error { return s.DB.Close() }

// Open connects, checks the server and the user's privileges, and prepares
// the read-only session.
func Open(ctx context.Context, cfg *mysql.Config, timeout time.Duration) (*Session, error) {
	return OpenAs(ctx, cfg, timeout, "")
}

// OpenAs is Open for a target named by label instead of its address, as
// DescribeAs renders it: its errors and Server.Address show the label, never
// cfg's address, and the driver logs nothing. An empty label is Open.
func OpenAs(ctx context.Context, cfg *mysql.Config, timeout time.Duration, label string) (*Session, error) {
	return OpenWith(ctx, cfg, SessionOptions{Timeout: timeout, Label: label})
}

// SessionOptions are a Session's settings. The zero value of each field
// beyond Timeout and Label is Open's.
type SessionOptions struct {
	Timeout time.Duration
	// Label names the target in errors instead of its address, as OpenAs.
	Label string
	// SelectLimit, above zero, sets sql_select_limit on every connection:
	// the server sends at most that many rows of a statement without its
	// own LIMIT.
	SelectLimit int
	// ServerBigSelects leaves sql_big_selects at the server's value, so a
	// DBA's max_join_size keeps refusing the largest joins.
	ServerBigSelects bool
	// ColumnsWithAlias labels each result column with its table's alias:
	// c.email for SELECT c.email … FROM customers c.
	ColumnsWithAlias bool
	// TraditionalExplain sets explain_format to TRADITIONAL where MySQL has
	// it (8.0.32 on): a server-wide TREE or JSON would make a plain EXPLAIN
	// print values from the rows it read.
	TraditionalExplain bool
}

// OpenWith is Open with options.
func OpenWith(ctx context.Context, cfg *mysql.Config, opts SessionOptions) (*Session, error) {
	timeout, label := opts.Timeout, opts.Label
	cfg = cfg.Clone()
	quiet(cfg, label)
	cfg.ColumnsWithAlias = opts.ColumnsWithAlias
	// The session's settings are the probe's alone.
	note := dropDSNSettings(cfg)
	// The scanner never needs this, whatever the DSN says. openCheckedPool
	// sets the options the checks depend on.
	cfg.ParseTime = false
	if cfg.ConnectionAttributes == "" {
		cfg.ConnectionAttributes = "program_name:prodmask"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = timeout + 30*time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}

	s := &Session{Database: cfg.DBName, Timeout: timeout}
	if note != "" {
		s.warn(note)
	}
	params, err := s.probe(ctx, cfg, label)
	if err != nil {
		return nil, err
	}
	if opts.SelectLimit > 0 {
		params["sql_select_limit"] = strconv.Itoa(opts.SelectLimit)
	}
	if opts.ServerBigSelects {
		delete(params, "sql_big_selects")
	}
	if opts.TraditionalExplain && s.Server.Flavor == "mysql" {
		has, err := hasExplainFormat(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("read explain_format: %w", err)
		}
		if has {
			params["explain_format"] = "TRADITIONAL"
		}
	}
	s.Settings = params

	cfg.Params = params
	db, err := openCheckedPool(cfg)
	if err != nil {
		return nil, err
	}
	if err := s.verifyReadOnly(ctx, db, params); err != nil {
		db.Close()
		return nil, err
	}
	s.DB = db
	return s, nil
}

// hasExplainFormat reports whether the server has explain_format, as MySQL
// has from 8.0.32. It's read, not judged by the version, which a fork may
// spell its own way. Error 1193, an unknown variable, means it hasn't; any
// other error fails the session.
func hasExplainFormat(ctx context.Context, cfg *mysql.Config) (bool, error) {
	db, err := openCheckedPool(cfg)
	if err != nil {
		return false, err
	}
	defer db.Close()
	var v sql.NullString
	err = db.QueryRowContext(ctx, "SELECT @@SESSION.explain_format").Scan(&v)
	var my *mysql.MySQLError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &my) && my.Number == 1193:
		return false, nil
	}
	return false, err
}

// openPool opens a Snapshot's pool, whose statements the Snapshot's methods
// check: its own transaction statements are fixed text the rules would
// refuse.
func openPool(cfg *mysql.Config) (*sql.DB, error) {
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	return onePool(connector), nil
}

// probe opens a throwaway connection to learn the server flavour, which
// session variables exist, and what the user may do. It returns the session
// variables every scan connection should set on connect.
func (s *Session) probe(ctx context.Context, cfg *mysql.Config, label string) (map[string]string, error) {
	db, err := openCheckedPool(cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, connectError(cfg, label, err)
	}
	defer conn.Close()

	var version, comment string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION(), @@version_comment").Scan(&version, &comment); err != nil {
		return nil, fmt.Errorf("read server version: %w", err)
	}
	flavor := "mysql"
	if strings.Contains(strings.ToLower(version+" "+comment), "mariadb") {
		flavor = "mariadb"
	}
	_, address := target(cfg, label)
	s.Server = model.ServerInfo{Flavor: flavor, Version: version, Address: address, User: cfg.User}

	// sql_big_selects: a host with a low max_join_size refuses bigger reads
	// otherwise, and a DSN's own setting for it is dropped.
	params := map[string]string{"autocommit": "1", "lock_wait_timeout": "5", "sql_big_selects": "1"}
	switch {
	case hasVariable(ctx, conn, "transaction_read_only"):
		params["transaction_read_only"] = "1"
	case hasVariable(ctx, conn, "tx_read_only"):
		params["tx_read_only"] = "1"
	default:
		s.warn(noReadOnlyWarning)
	}
	switch {
	case flavor == "mariadb" && hasVariable(ctx, conn, "max_statement_time"):
		params["max_statement_time"] = strconv.FormatFloat(s.Timeout.Seconds(), 'f', -1, 64)
		s.ServerTimeout = true
	case flavor == "mysql" && hasVariable(ctx, conn, "max_execution_time"):
		params["max_execution_time"] = strconv.FormatInt(s.Timeout.Milliseconds(), 10)
		s.ServerTimeout = true
	default:
		s.warn("the server has no statement timeout setting; slow queries are only stopped by the client-side timeout")
	}

	if privs := s.writePrivileges(ctx, conn); len(privs) > 0 {
		s.warn(fmt.Sprintf("the scan user can change `%s` (%s). prodmask only reads, but a SELECT-only user is safer: "+
			"GRANT SELECT, SHOW VIEW ON `%s`.* TO 'prodmask'@'%%';", s.Database, strings.Join(privs, ", "), s.Database))
	}
	return params, nil
}

// noReadOnlyWarning is the warning for a server with neither
// transaction_read_only nor tx_read_only.
const noReadOnlyWarning = "the server cannot mark the session read-only; every statement prodmask sends is still checked to be a read"

func hasVariable(ctx context.Context, conn *sql.Conn, name string) bool {
	var v sql.NullString
	return conn.QueryRowContext(ctx, "SELECT @@SESSION."+name).Scan(&v) == nil
}

// verifyReadOnly checks that the session variables took effect.
func (s *Session) verifyReadOnly(ctx context.Context, db *sql.DB, params map[string]string) error {
	for _, name := range []string{"transaction_read_only", "tx_read_only"} {
		if _, ok := params[name]; !ok {
			continue
		}
		var v string
		if err := db.QueryRowContext(ctx, "SELECT @@SESSION."+name).Scan(&v); err != nil {
			return fmt.Errorf("check read-only session: %w", err)
		}
		if v != "1" && !strings.EqualFold(v, "on") {
			return errors.New("could not make the database session read-only; refusing to scan")
		}
	}
	return nil
}

func (s *Session) writePrivileges(ctx context.Context, conn *sql.Conn) []string {
	rows, err := conn.QueryContext(ctx, "SHOW GRANTS")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var grants []string
	for rows.Next() {
		var g string
		if rows.Scan(&g) == nil {
			grants = append(grants, g)
		}
	}
	return WritePrivileges(grants, s.Database)
}

func (s *Session) warn(msg string) { s.Warnings = append(s.Warnings, msg) }

var writePrivs = map[string]bool{
	"ALL": true, "ALL PRIVILEGES": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"DROP": true, "ALTER": true, "CREATE": true, "INDEX": true, "TRIGGER": true, "EVENT": true,
	"CREATE ROUTINE": true, "ALTER ROUTINE": true, "CREATE VIEW": true, "DELETE HISTORY": true,
}

// WritePrivileges reads SHOW GRANTS output and returns the privileges that
// would let the user change the given database.
func WritePrivileges(grants []string, database string) []string {
	out := []string{}
	for _, p := range ParseGrants(grants).On(database) {
		if writePrivs[p] {
			out = append(out, p)
		}
	}
	return out
}

func splitPrivileges(s string) []string {
	// Drop column lists such as UPDATE (a, b).
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '(':
			depth++
		case r == ')':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	var out []string
	for _, p := range strings.Split(b.String(), ",") {
		if p = strings.Join(strings.Fields(p), " "); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// grantCovers reports whether a grant target such as *.*, `shop`.* or
// `shop`.`orders` applies to the database.
func grantCovers(target, database string) bool {
	upper := strings.ToUpper(target)
	for _, kw := range []string{"TABLE ", "PROCEDURE ", "FUNCTION ", "PACKAGE BODY ", "PACKAGE "} {
		if strings.HasPrefix(upper, kw) {
			target = strings.TrimSpace(target[len(kw):])
			break
		}
	}
	var db string
	if strings.HasPrefix(target, "`") {
		end := 1
		for end < len(target) {
			if target[end] == '`' {
				if end+1 < len(target) && target[end+1] == '`' {
					end += 2
					continue
				}
				break
			}
			end++
		}
		db = strings.ReplaceAll(target[1:min(end, len(target))], "``", "`")
	} else {
		db, _, _ = strings.Cut(target, ".")
	}
	if db == "*" {
		return true
	}
	return grantPattern(db).MatchString(database)
}

// grantPattern turns a database name from a grant into a regexp: % matches
// any run of characters, _ matches one, and a backslash escapes either.
func grantPattern(name string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)^")
	r := []rune(name)
	for i := 0; i < len(r); i++ {
		switch {
		case r[i] == '\\' && i+1 < len(r):
			i++
			b.WriteString(regexp.QuoteMeta(string(r[i])))
		case r[i] == '%':
			b.WriteString(".*")
		case r[i] == '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r[i])))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}
