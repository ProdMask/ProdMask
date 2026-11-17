// Package projectdb reads the database settings from a PHP application's own
// configuration, without running it: WordPress's wp-config.php, Laravel's .env
// or Magento's app/etc/env.php. It reads plain values only. Anything it can't
// be sure the application reads the same way, it refuses in fixed words that
// name the file and the key, never a value, a line or a path.
package projectdb

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// The configuration files Read knows, by their names in the project folder.
const (
	WordPress = "wp-config.php"
	Laravel   = ".env"
	Magento   = "app/etc/env.php"
)

// maxFile is the most Read reads of a configuration: far more than one holds.
const maxFile = 1 << 20

// Project is the database a project folder's configuration names.
type Project struct {
	// File is the configuration's fixed name: WordPress, Laravel or Magento.
	File string
	// Config is the connection, built from the file's fields.
	Config *mysql.Config
	// Socket reports that Config connects through a unix socket. Its path
	// comes from the file and is never printed: Label names it instead.
	Socket bool
	// Localhost reports a host of localhost with no socket. PHP would reach
	// it through its default socket, whose path Go can't know, so Config
	// uses TCP to localhost instead.
	Localhost bool
	// ConfigCache reports Laravel's bootstrap/cache/config.php beside .env:
	// the application reads that, not .env.
	ConfigCache bool
	// DropIn reports WordPress's wp-content/db.php beside wp-config.php: a
	// plugin's database layer, which WordPress loads in place of its own and
	// which can connect elsewhere, as the SQLite one does.
	DropIn bool
}

// Label names the project's socket without its path, as "the unix socket
// from wp-config.php".
func (p *Project) Label() string { return "the unix socket from " + p.File }

// Port is the TCP port Config connects to, or 0 for a socket.
func (p *Project) Port() int {
	if p.Socket {
		return 0
	}
	_, port, err := net.SplitHostPort(p.Config.Addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}

// settings are the connection's parts as a configuration gives them.
type settings struct {
	user, password, database string
	// host is a name or an address, "localhost", or empty for localhost.
	host string
	// port is 0 for MySQL's default, 3306.
	port int
	// socket is a unix socket's path; when set, host and port aren't used.
	socket string
}

// Read reads the database settings of the application in dir. It looks in
// dir only, never above it, for wp-config.php, app/etc/env.php, and a .env
// beside an artisan file, and refuses a folder with none or more than one.
// Every error it returns is an *Error.
func Read(dir string) (*Project, error) {
	file, err := find(dir)
	if err != nil {
		return nil, err
	}
	data, err := readFile(filepath.Join(dir, filepath.FromSlash(file)), file)
	if err != nil {
		return nil, err
	}
	s, err := readers[file](data)
	if err != nil {
		var refusal *Error
		if !errors.As(err, &refusal) {
			return nil, refuse(file, fallbackText(file))
		}
		return nil, refusal
	}
	p := &Project{File: file}
	p.Config, p.Socket, p.Localhost = s.config()
	switch file {
	case Laravel:
		p.ConfigCache = present(filepath.Join(dir, "bootstrap", "cache", "config.php"))
	case WordPress:
		p.DropIn = present(filepath.Join(dir, "wp-content", "db.php"))
	}
	return p, nil
}

// readers reads each configuration's database settings from its bytes.
var readers = map[string]func([]byte) (*settings, error){
	WordPress: readWordPress,
	Laravel:   readLaravel,
	Magento:   readMagento,
}

// find names the one configuration in dir, in the order WordPress, Magento,
// Laravel.
func find(dir string) (string, error) {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return "", errNoFolder()
	}
	found := configs(func(name string) bool { return present(filepath.Join(dir, name)) })
	switch len(found) {
	case 0:
		return "", errNone()
	case 1:
		return found[0], nil
	}
	return "", errSeveral(found)
}

// configs names the configurations a folder holds, in the order WordPress,
// Magento, Laravel, from has, which reports whether a name in the folder
// exists. A .env counts only beside an artisan file.
func configs(has func(name string) bool) []string {
	var found []string
	for _, file := range []string{WordPress, Magento} {
		if has(filepath.FromSlash(file)) {
			found = append(found, file)
		}
	}
	if has(Laravel) && has("artisan") {
		found = append(found, Laravel)
	}
	return found
}

// present reports whether path names anything, a broken symlink or a folder
// included, so that one of those in a configuration's place is refused as
// unreadable rather than missed.
func present(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// readFile reads a configuration, following symlinks, and returns its bytes
// with a UTF-8 BOM dropped and CRLF line ends made LF. Values keep their
// bytes, so invalid UTF-8 is fine; a NUL byte or more than maxFile isn't.
func readFile(path, file string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errUnreadable(file)
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, errUnreadable(file)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	switch {
	case err != nil:
		return nil, errUnreadable(file)
	case len(data) > maxFile:
		return nil, errTooBig(file)
	case bytes.IndexByte(data, 0) >= 0:
		return nil, errNUL(file)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")), nil
}

// absolute reports whether a socket's path is absolute: from the root, as a
// config on a server names it, or absolute on the system running the scan.
// A relative path would resolve from the app's folder for PHP and from the
// user's for prodmask, so readers refuse one.
func absolute(path string) bool {
	return strings.HasPrefix(path, "/") || filepath.IsAbs(path)
}

// config builds the connection: through the socket when there is one, else
// TCP to the host, with localhost standing for an empty host.
func (s *settings) config() (cfg *mysql.Config, socket, localhost bool) {
	cfg = mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.DBName = s.user, s.password, s.database
	if s.socket != "" {
		cfg.Net, cfg.Addr = "unix", s.socket
		return cfg, true, false
	}
	host := s.host
	if host == "" || strings.EqualFold(host, "localhost") {
		host, localhost = "localhost", true
	}
	port := s.port
	if port == 0 {
		port = 3306
	}
	cfg.Net, cfg.Addr = "tcp", net.JoinHostPort(host, strconv.Itoa(port))
	return cfg, false, localhost
}
