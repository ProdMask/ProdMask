// Package dbconn opens read-only, time-limited connections to MySQL and
// MariaDB servers.
package dbconn

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// ErrBadDSN is returned for a DSN that doesn't parse. The driver's own
// errors quote parts of the DSN, which can be the password, so ParseDSN
// returns this instead.
var ErrBadDSN = errors.New("the DSN doesn't parse: expected user:password@tcp(host:port)/database or mysql://user:password@host:port/database")

// ParseDSN reads a connection string in either of these forms:
//
//	mysql://user:pass@host:3306/dbname?tls=true
//	user:pass@tcp(host:3306)/dbname?tls=true
//
// The URL form also accepts ?socket=/path/to/mysqld.sock. When the DSN has no
// password, password (usually from PRODMASK_PASSWORD) is used instead. Its
// errors never quote the DSN.
func ParseDSN(dsn, password string) (*mysql.Config, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, errors.New("no DSN given: pass --dsn or set PRODMASK_DSN")
	}
	var (
		cfg *mysql.Config
		err error
	)
	if strings.Contains(dsn, "://") {
		cfg, err = parseURL(dsn)
	} else if cfg, err = mysql.ParseDSN(dsn); err != nil {
		err = ErrBadDSN
	}
	if err != nil {
		return nil, err
	}
	if cfg.Passwd == "" && password != "" {
		cfg.Passwd = password
	}
	if cfg.DBName == "" {
		return nil, errors.New("the DSN must name a database, e.g. mysql://user@host:3306/shop")
	}
	return cfg, nil
}

func parseURL(raw string) (*mysql.Config, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse quotes the whole URL in its error, password included.
		return nil, fmt.Errorf("%w: check the host and port, and percent-encode special characters in the password", ErrBadDSN)
	}
	if u.Scheme != "mysql" && u.Scheme != "mariadb" {
		return nil, fmt.Errorf("unsupported DSN scheme %q (use mysql://)", u.Scheme)
	}
	q := u.Query()
	socket := q.Get("socket")
	q.Del("socket")

	cfg := mysql.NewConfig()
	if len(q) > 0 {
		// Let the driver interpret its own parameters (tls, charset, ...).
		if cfg, err = mysql.ParseDSN("/?" + q.Encode()); err != nil {
			return nil, fmt.Errorf("%w: check the parameters after ?", ErrBadDSN)
		}
		// Parsing filled in a default address; the TLS settings are rebuilt
		// for the real host when the connector is created.
		cfg.TLS = nil
	}
	if u.User != nil {
		cfg.User = u.User.Username()
		cfg.Passwd, _ = u.User.Password()
	}
	if socket != "" {
		cfg.Net, cfg.Addr = "unix", socket
	} else {
		host, port := u.Hostname(), u.Port()
		if host == "" {
			host = "127.0.0.1"
		}
		if port == "" {
			port = "3306"
		}
		cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(host, port)
	}
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	return cfg, nil
}

// Address renders where the server is, without credentials.
func Address(cfg *mysql.Config) string {
	if cfg.Net == "unix" {
		return "unix(" + cfg.Addr + ")"
	}
	return cfg.Addr
}

// Describe renders the connection target without the password, e.g.
// shop_ro@db.internal:3306/shop.
func Describe(cfg *mysql.Config) string {
	s := Address(cfg) + "/" + cfg.DBName
	if cfg.User != "" {
		s = cfg.User + "@" + s
	}
	return s
}
