package dbconn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
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
}

// Flavor is "mariadb" or "mysql".
func (s *Session) Flavor() string { return s.Server.Flavor }

// Close closes the pool.
func (s *Session) Close() error { return s.DB.Close() }

// Open connects, checks the server and the user's privileges, and prepares
// the read-only session.
func Open(ctx context.Context, cfg *mysql.Config, timeout time.Duration) (*Session, error) {
	cfg = cfg.Clone()
	// The scanner never needs these, whatever the DSN says.
	cfg.MultiStatements = false
	cfg.AllowAllFiles = false
	cfg.ParseTime = false
	// Bound arguments include key names that can hold personal data; with
	// interpolation they would be written into the statement text, which
	// server error messages may quote.
	cfg.InterpolateParams = false
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
	params, err := s.probe(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	for k, v := range params {
		cfg.Params[k] = v
	}
	db, err := openPool(cfg)
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

func openPool(cfg *mysql.Config) (*sql.DB, error) {
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return db, nil
}

// probe opens a throwaway connection to learn the server flavour, which
// session variables exist, and what the user may do. It returns the session
// variables every scan connection should set on connect.
func (s *Session) probe(ctx context.Context, cfg *mysql.Config) (map[string]string, error) {
	db, err := openPool(cfg)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", Describe(cfg), err)
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
	s.Server = model.ServerInfo{Flavor: flavor, Version: version, Address: Address(cfg), User: cfg.User}

	params := map[string]string{"autocommit": "1", "lock_wait_timeout": "5"}
	switch {
	case hasVariable(ctx, conn, "transaction_read_only"):
		params["transaction_read_only"] = "1"
	case hasVariable(ctx, conn, "tx_read_only"):
		params["tx_read_only"] = "1"
	default:
		s.warn("the server cannot mark the session read-only; prodmask still only runs SELECT and SHOW statements")
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
	found := map[string]bool{}
	for _, g := range grants {
		up := strings.ToUpper(g)
		if !strings.HasPrefix(up, "GRANT ") {
			continue
		}
		on := strings.Index(up, " ON ")
		if on < 0 {
			continue // role grant
		}
		to := strings.Index(up[on:], " TO ")
		if to < 0 {
			continue
		}
		if !grantCovers(strings.TrimSpace(g[on+4:on+to]), database) {
			continue
		}
		for _, p := range splitPrivileges(up[len("GRANT "):on]) {
			if writePrivs[p] {
				found[p] = true
			}
		}
	}
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
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
