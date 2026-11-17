package cli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
)

// projectCanaries are values a project's config holds besides the database
// settings: no output may show any of them.
var projectCanaries = []string{
	"Qz8" + "authKeyCanary", "Qz8" + "saltCanary", "Qz8" + "appKeyCanary", "Qz8" + "mailCanary",
	"Qz8" + "cryptCanary", "Qz8" + "frontCanary", "Qz8" + "awsCanary",
}

// projectTarget is where a fixture's config points: the test database's user,
// password and name, and a host, port or socket.
type projectTarget struct {
	user, password, database string
	host                     string // empty with a socket
	port                     int
	socket                   string
}

// phpQuote writes s as a PHP single-quoted string.
func phpQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// writeProject writes app's config into dir, aimed at target, with a canary
// in every other value. It returns the config's fixed name.
func writeProject(t *testing.T, dir, app string, target projectTarget) string {
	t.Helper()
	write := func(name, text string) {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := projectCanaries
	switch app {
	case "wordpress":
		host := target.host + ":" + strconv.Itoa(target.port)
		if target.socket != "" {
			host = "localhost:" + target.socket
		}
		write("wp-config.php", "<?php\n"+
			"// ** Database settings ** //\n"+
			"define( 'DB_NAME', "+phpQuote(target.database)+" );\n"+
			"define( 'DB_USER', "+phpQuote(target.user)+" );\n"+
			"define( 'DB_PASSWORD', "+phpQuote(target.password)+" );\n"+
			"define( 'DB_HOST', "+phpQuote(host)+" );\n"+
			"define( 'DB_CHARSET', 'utf8mb4' );\n"+
			"define( 'AUTH_KEY', '"+c[0]+"' );\n"+
			"define( 'SECURE_AUTH_SALT', '"+c[1]+"' );\n"+
			"define( 'WP_DEBUG', getenv('"+c[3]+"') );\n"+
			"$table_prefix = 'wp_';\n"+
			"if ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n"+
			"require_once ABSPATH . 'wp-settings.php';\n")
		return "wp-config.php"
	case "laravel":
		db := "DB_HOST=" + target.host + "\nDB_PORT=" + strconv.Itoa(target.port) + "\n"
		if target.socket != "" {
			db = "DB_SOCKET='" + target.socket + "'\n"
		}
		write("artisan", "#!/usr/bin/env php\n")
		write(".env", "APP_NAME=Shop\nAPP_KEY=base64:"+c[2]+"\n\n"+
			"DB_CONNECTION=mysql\n"+db+
			"DB_DATABASE="+target.database+"\nDB_USERNAME="+target.user+"\nDB_PASSWORD='"+target.password+"'\n\n"+
			"MAIL_PASSWORD="+c[3]+"\nAWS_SECRET_ACCESS_KEY="+c[6]+"\n")
		return ".env"
	case "magento":
		host := target.host + ":" + strconv.Itoa(target.port)
		if target.socket != "" {
			host = target.socket
		}
		write("app/etc/env.php", "<?php\nreturn [\n"+
			"    'backend' => ['frontName' => '"+c[5]+"'],\n"+
			"    'crypt' => ['key' => '"+c[4]+"'],\n"+
			"    'db' => [\n        'table_prefix' => '',\n        'connection' => [\n            'default' => [\n"+
			"                'host' => "+phpQuote(host)+",\n"+
			"                'dbname' => "+phpQuote(target.database)+",\n"+
			"                'username' => "+phpQuote(target.user)+",\n"+
			"                'password' => "+phpQuote(target.password)+",\n"+
			"                'model' => 'mysql4',\n                'engine' => 'innodb',\n"+
			"                'initStatements' => 'SET NAMES utf8;',\n                'active' => '1',\n"+
			"                'driver_options' => [1014 => false]\n            ]\n        ]\n    ],\n"+
			"    'MAGE_MODE' => 'production',\n];\n")
		return "app/etc/env.php"
	}
	t.Fatalf("no app %s", app)
	return ""
}

// unshown checks that out holds none of the canaries, the secret folder's
// name, its path, or the password, and returns out with the password masked
// for printing.
func unshown(t *testing.T, name, out, dir, password string, also ...string) {
	t.Helper()
	shown := out
	if password != "" {
		shown = strings.ReplaceAll(out, password, "<password>")
		if strings.Contains(out, password) {
			t.Errorf("%s shows the password:\n%s", name, shown)
		}
	}
	for _, s := range append(append([]string{projectSecret, dir}, projectCanaries...), also...) {
		if s != "" && strings.Contains(out, s) {
			t.Errorf("%s shows %q:\n%s", name, s, shown)
		}
	}
}

// closedPort returns a port on 127.0.0.1 that nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// TestScanProjectClosed checks --project end to end with nothing to connect
// to, which needs no database: the lines it prints, in their order, the exit
// status 1, and the socket hint for localhost. No output shows the folder or
// anything else from the file.
func TestScanProjectClosed(t *testing.T) {
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	port := closedPort(t)
	target := projectTarget{user: "shop_ro", password: "pw-" + "Qz8" + "closedPassword", database: "shop", host: "127.0.0.1", port: port}
	for _, app := range []string{"wordpress", "laravel", "magento"} {
		dir := filepath.Join(t.TempDir(), projectSecret)
		file := writeProject(t, dir, app, target)
		code, stdout, stderr := run(New("1.2.3"), "scan", "--project", dir)
		want := "Reading the database settings from " + file + " in the folder given to --project.\n" +
			"Connecting to shop_ro@127.0.0.1:" + strconv.Itoa(port) + "/shop (read-only)...\n"
		if code != ExitError || stdout != "" || !strings.HasPrefix(stderr, want) || !strings.Contains(stderr, "prodmask: connect to ") {
			t.Errorf("%s at a closed port: status %d\n%s", app, code, strings.ReplaceAll(stderr, target.password, "<password>"))
		}
		if strings.Contains(stderr, "socket") {
			t.Errorf("%s: a TCP host got the socket hint", app)
		}
		unshown(t, app+" at a closed port", stdout+stderr, dir, target.password)

		// The same at localhost: PHP would use its socket, so the scan says
		// it uses TCP instead, and its failure adds the socket hint.
		local := target
		local.host = "localhost"
		dir = filepath.Join(t.TempDir(), projectSecret)
		file = writeProject(t, dir, app, local)
		code, _, stderr = run(New("1.2.3"), "scan", "--project", dir)
		want = "Reading the database settings from " + file + " in the folder given to --project.\n" +
			file + " names localhost, which PHP reaches through a socket; connecting over TCP to localhost:" + strconv.Itoa(port) + " instead.\n" +
			"Connecting to shop_ro@localhost:" + strconv.Itoa(port) + "/shop (read-only)...\n"
		hint := "prodmask: the app may reach localhost through a socket; pass --dsn with ?socket=/path instead\n"
		if code != ExitError || !strings.HasPrefix(stderr, want) || !strings.HasSuffix(stderr, hint) {
			t.Errorf("%s at localhost: status %d\n%s", app, code, strings.ReplaceAll(stderr, target.password, "<password>"))
		}
		unshown(t, app+" at localhost", stderr, dir, target.password)
	}

	// Everything stderr can say before connecting, in its order: the notes,
	// Laravel's config cache, the file read, and localhost over TCP.
	t.Setenv("PRODMASK_DSN", "mysql://ro:"+"Qz8envSecret"+"@db.example.test/shop")
	t.Setenv("PRODMASK_PASSWORD", "Qz8"+"envPassword")
	local := target
	local.host = "localhost"
	dir := filepath.Join(t.TempDir(), projectSecret)
	writeProject(t, dir, "laravel", local)
	if err := os.MkdirAll(filepath.Join(dir, "bootstrap", "cache"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bootstrap", "cache", "config.php"), []byte("<?php return ['Qz8"+"cachedCanary'];"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(New("1.2.3"), "scan", "--project", dir)
	want := "$PRODMASK_DSN isn't used with --project.\n" +
		"$PRODMASK_PASSWORD isn't used with --project.\n" +
		"Laravel's config cache is on, so the app reads bootstrap/cache/config.php, not .env; check the database below, or pass --dsn\n" +
		"Reading the database settings from .env in the folder given to --project.\n" +
		".env names localhost, which PHP reaches through a socket; connecting over TCP to localhost:" + strconv.Itoa(port) + " instead.\n" +
		"Connecting to shop_ro@localhost:" + strconv.Itoa(port) + "/shop (read-only)...\n"
	if code != ExitError || stdout != "" || !strings.HasPrefix(stderr, want) ||
		!strings.HasSuffix(stderr, "prodmask: the app may reach localhost through a socket; pass --dsn with ?socket=/path instead\n") {
		t.Errorf("every line before connecting: status %d\n%s", code, strings.ReplaceAll(stderr, target.password, "<password>"))
	}
	unshown(t, "every line before connecting", stdout+stderr, dir, target.password, "Qz8envSecret", "Qz8envPassword", "Qz8cachedCanary")

	// WordPress's database drop-in, warned of before the file is read.
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	dir = filepath.Join(t.TempDir(), projectSecret)
	writeProject(t, dir, "wordpress", target)
	if err := os.MkdirAll(filepath.Join(dir, "wp-content"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wp-content", "db.php"), []byte("<?php // Qz8"+"dropInCanary"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run(New("1.2.3"), "scan", "--project", dir)
	want = "WordPress loads wp-content/db.php, which can replace its database connection; check the database below, or pass --dsn\n" +
		"Reading the database settings from wp-config.php in the folder given to --project.\n" +
		"Connecting to shop_ro@127.0.0.1:" + strconv.Itoa(port) + "/shop (read-only)...\n"
	if code != ExitError || stdout != "" || !strings.HasPrefix(stderr, want) {
		t.Errorf("a database drop-in: status %d\n%s", code, strings.ReplaceAll(stderr, target.password, "<password>"))
	}
	unshown(t, "a database drop-in", stdout+stderr, dir, target.password, "Qz8"+"dropInCanary")
}

// socketProxy listens on a unix socket at path and forwards each connection
// to addr over TCP, until stopped.
func socketProxy(t *testing.T, path, addr string) (stop func()) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("this system can't listen on a unix socket here, so the socket cases don't run: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				s, err := net.Dial("tcp", addr)
				if err != nil {
					return
				}
				defer s.Close()
				done := make(chan struct{}, 2)
				go func() { io.Copy(s, c); done <- struct{}{} }()
				go func() { io.Copy(c, s); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return func() {
		l.Close()
		os.Remove(path)
	}
}

// TestScanProject scans the test database through --project, for each app's
// config: over TCP, and through a unix socket inside the project folder,
// whose path never shows. No output or report shows a canary, the folder or
// the password; the user, host and database may show where Describe shows
// them. It needs PRODMASK_TEST_DSN; testdb.DSN skips or fails it without one.
func TestScanProject(t *testing.T) {
	dsn := testdb.DSN(t)
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	admin, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("PRODMASK_TEST_DSN doesn't parse")
	}
	if admin.Net != "tcp" {
		t.Skip("PRODMASK_TEST_DSN isn't a TCP address")
	}
	host, portText, err := net.SplitHostPort(admin.Addr)
	if err != nil {
		t.Fatal("PRODMASK_TEST_DSN's address has no port")
	}
	port, _ := strconv.Atoi(portText)
	if strings.ContainsAny(admin.Passwd, `'"\$#`+" ") {
		t.Skip("PRODMASK_TEST_DSN's password needs quoting these fixtures don't do")
	}

	const database = "prodmask_cli_fixture_project"
	email := "qz8" + "sampledcanary@example.com"
	adminCfg := admin.Clone()
	adminCfg.DBName = ""
	connector, err := mysql.NewConnector(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	drop := "DROP DATABASE IF EXISTS `" + database + "`"
	for _, s := range []string{
		drop,
		"CREATE DATABASE `" + database + "` CHARACTER SET utf8mb4",
		"CREATE TABLE `" + database + "`.customers (id int PRIMARY KEY, email varchar(100))",
		"INSERT INTO `" + database + "`.customers VALUES (1, '" + email + "')",
	} {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatalf("build the database: %v", err)
		}
	}
	defer db.ExecContext(context.Background(), drop)

	target := projectTarget{user: admin.User, password: admin.Passwd, database: database, host: host, port: port}
	// scanned scans dir's project and checks that no output shows dir, the
	// password, a canary, or any of also.
	scanned := func(name, dir string, wantLabel bool, also ...string) {
		t.Helper()
		report := filepath.Join(t.TempDir(), "report.json")
		code, stdout, stderr := run(New("1.2.3"), "scan", "--project", dir, "--format", "json", "--out", report)
		raw, _ := os.ReadFile(report)
		if code != ExitOK || len(raw) == 0 {
			t.Errorf("%s: status %d\n%s", name, code, strings.ReplaceAll(stderr, target.password, "<password>"))
		}
		if wantLabel != strings.Contains(stderr+string(raw), "the unix socket from ") {
			t.Errorf("%s: the socket's label shown %v, want %v", name, !wantLabel, wantLabel)
		}
		unshown(t, name, stdout+stderr+string(raw), dir, target.password, append(also, email)...)
	}
	for _, app := range []string{"wordpress", "laravel", "magento"} {
		dir := filepath.Join(t.TempDir(), projectSecret)
		writeProject(t, dir, app, target)
		scanned(app+" over TCP", dir, false)
	}

	// A refused login at localhost adds the socket hint. The login is a user
	// of the test's own with an ordinary password, since an install's root at
	// localhost can fall back to another authentication plugin, as MariaDB's
	// on Windows does, rather than refuse with 1045.
	const user = "prodmask_proj_login"
	for _, host := range []string{"%", "localhost", "127.0.0.1", "::1"} {
		account := "'" + user + "'@'" + host + "'"
		if _, err := db.ExecContext(ctx, "CREATE USER IF NOT EXISTS "+account+" IDENTIFIED BY 'pw-Qz8rightPassword'"); err != nil {
			t.Fatalf("create the login's user: %v", err)
		}
		defer db.ExecContext(context.Background(), "DROP USER IF EXISTS "+account)
	}
	wrong := target
	wrong.host, wrong.user, wrong.password = "localhost", user, "pw-"+"Qz8"+"wrongPassword"
	dir := filepath.Join(t.TempDir(), projectSecret)
	writeProject(t, dir, "wordpress", wrong)
	code, _, stderr := run(New("1.2.3"), "scan", "--project", dir)
	if code != ExitError || !strings.Contains(stderr, "1045") ||
		!strings.HasSuffix(stderr, "prodmask: the app may reach localhost through a socket; pass --dsn with ?socket=/path instead\n") {
		t.Errorf("a refused login at localhost: status %d\n%s", code, strings.ReplaceAll(stderr, target.password, "<password>"))
	}
	unshown(t, "a refused login at localhost", stderr, dir, target.password, wrong.password)

	// Through a unix socket inside the project folder. Its path is short, as
	// a socket's must be.
	short, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(short)
	for _, app := range []string{"wordpress", "laravel", "magento"} {
		if app == "wordpress" && runtime.GOOS == "windows" {
			t.Log("WordPress's DB_HOST can't name a Windows path, since parse_db_host splits it at the first :/, so its socket case runs on Linux")
			continue
		}
		dir := filepath.Join(short, "Qz8"+app[:2])
		// Forward slashes, as a config names a socket, and as Windows takes them.
		socket := filepath.ToSlash(filepath.Join(dir, "m.sock"))
		if len(socket) > 100 {
			t.Skipf("the socket's path would be %d bytes, over what a unix socket takes", len(socket))
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		stop := socketProxy(t, socket, admin.Addr)
		sock := target
		sock.host, sock.port, sock.socket = "", 0, socket
		file := writeProject(t, dir, app, sock)
		// The socket's path in its config's form, with forward slashes, and
		// the folder's name, so that neither shows on Windows either.
		scanned(app+" through a socket", dir, true, socket, filepath.Base(dir))

		// With the proxy closed, the error names the label and the dial's
		// cause, a "connect: " system error, and not the path.
		stop()
		code, stdout, stderr := run(New("1.2.3"), "scan", "--project", dir)
		want := "prodmask: connect to " + database + " as " + target.user + " through the unix socket from " + file + ": connect: "
		if code != ExitError || !strings.Contains(stderr, want) {
			t.Errorf("%s through a closed socket: status %d\n%s", app, code, strings.ReplaceAll(stderr, target.password, "<password>"))
		}
		unshown(t, app+" through a closed socket", stdout+stderr, dir, target.password, socket, fmt.Sprintf("Qz8%s", app[:2]))
	}
}
