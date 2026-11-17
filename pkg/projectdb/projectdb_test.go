package projectdb

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// secretDir makes a folder whose name reads like a secret, for checking that
// no refusal names it.
func secretDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pw-"+"Qz8"+"projectCanary")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func write(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// refusalText checks that err is an *Error whose text is in Messages and
// names neither dir nor its path, and returns the text.
func refusalText(t *testing.T, dir string, err error) string {
	t.Helper()
	var refusal *Error
	if !errors.As(err, &refusal) {
		t.Fatalf("not a refusal: %#v", err)
	}
	text := refusal.Error()
	if !slices.Contains(Messages(), text) {
		t.Errorf("not in Messages: %q", text)
	}
	if strings.Contains(text, filepath.Base(dir)) || strings.Contains(text, dir) {
		t.Errorf("names the folder: %q", text)
	}
	return text
}

// stubReaders makes every reader return fixed settings, so Read's own steps
// can be checked apart from the readers.
func stubReaders(t *testing.T) {
	t.Helper()
	saved := readers
	readers = map[string]func([]byte) (*settings, error){}
	for _, file := range []string{WordPress, Laravel, Magento} {
		readers[file] = func([]byte) (*settings, error) {
			return &settings{user: "u", password: "p", database: "d", host: "db.example.test", port: 3307}, nil
		}
	}
	t.Cleanup(func() { readers = saved })
}

// TestFind checks which configuration Read picks: one in the folder itself,
// never above it, with .env counted only beside artisan, and a refusal for
// none, for more than one, or for a folder that isn't one.
func TestFind(t *testing.T) {
	stubReaders(t)
	none := "the folder given to --project has no wp-config.php, app/etc/env.php or Laravel .env " +
		"(WordPress can keep wp-config.php one folder up; pass that folder)"
	cases := []struct {
		name  string
		files []string
		want  string // the file read, or the refusal's text
	}{
		{"nothing", nil, none},
		{"wp-config.php", []string{WordPress}, WordPress},
		{"app/etc/env.php", []string{Magento}, Magento},
		{".env beside artisan", []string{Laravel, "artisan"}, Laravel},
		{".env alone", []string{Laravel}, none},
		{"artisan alone", []string{"artisan"}, none},
		{"WordPress and Magento", []string{WordPress, Magento},
			"the folder given to --project has wp-config.php and app/etc/env.php; pass --dsn instead"},
		{"WordPress and Laravel", []string{WordPress, Laravel, "artisan"},
			"the folder given to --project has wp-config.php and .env; pass --dsn instead"},
		{"Magento and Laravel", []string{Magento, Laravel, "artisan"},
			"the folder given to --project has app/etc/env.php and .env; pass --dsn instead"},
		{"all three", []string{WordPress, Magento, Laravel, "artisan"},
			"the folder given to --project has wp-config.php, app/etc/env.php and .env; pass --dsn instead"},
		{"WordPress and a stray .env", []string{WordPress, Laravel}, WordPress},
	}
	for _, c := range cases {
		dir := secretDir(t)
		for _, f := range c.files {
			write(t, dir, f, []byte("x"))
		}
		p, err := Read(dir)
		switch {
		case err != nil:
			if got := refusalText(t, dir, err); got != c.want {
				t.Errorf("%s: %q, want %q", c.name, got, c.want)
			}
		case p.File != c.want:
			t.Errorf("%s: read %s, want %q", c.name, p.File, c.want)
		}
	}

	// A config one folder up is never read.
	parent := secretDir(t)
	write(t, parent, WordPress, []byte("x"))
	child := filepath.Join(parent, "public")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(child); err == nil || refusalText(t, child, err) != none {
		t.Errorf("a config one folder up: %v", err)
	}

	// A folder that isn't one.
	file := filepath.Join(secretDir(t), "pw-Qz8notAFolder")
	write(t, filepath.Dir(file), filepath.Base(file), []byte("x"))
	for _, dir := range []string{file, filepath.Join(filepath.Dir(file), "pw-Qz8missing")} {
		if _, err := Read(dir); err == nil || refusalText(t, dir, err) != "can't read the folder given to --project" {
			t.Errorf("%s: %v", filepath.Base(dir), err)
		}
	}
}

// TestReadLimits checks what Read takes from any file: a BOM and CRLF line
// ends normalised, invalid UTF-8 kept as bytes; and what it refuses: over
// 1 MiB, a NUL byte, a folder in the file's place and a broken symlink.
func TestReadLimits(t *testing.T) {
	var got []byte
	saved := readers
	readers = map[string]func([]byte) (*settings, error){
		WordPress: func(b []byte) (*settings, error) {
			got = append([]byte(nil), b...)
			return &settings{user: "u", database: "d", host: "db"}, nil
		},
	}
	t.Cleanup(func() { readers = saved })

	for _, c := range []struct {
		name     string
		data, in []byte
	}{
		{"a BOM", []byte("\xef\xbb\xbf<?php\n"), []byte("<?php\n")},
		{"CRLF line ends", []byte("<?php\r\ndefine();\r\n"), []byte("<?php\ndefine();\n")},
		{"a lone CR", []byte("a\rb\n"), []byte("a\rb\n")},
		{"invalid UTF-8", []byte("<?php // \xe9t\xe9\n'\xff'"), []byte("<?php // \xe9t\xe9\n'\xff'")},
		{"exactly 1 MiB", []byte(strings.Repeat("x", 1<<20)), []byte(strings.Repeat("x", 1<<20))},
	} {
		dir := secretDir(t)
		write(t, dir, WordPress, c.data)
		got = nil
		if _, err := Read(dir); err != nil {
			t.Errorf("%s: %v", c.name, err)
		} else if string(got) != string(c.in) {
			t.Errorf("%s: the reader got %q", c.name, got)
		}
	}

	refusals := []struct {
		name  string
		build func(dir string)
		want  string
	}{
		{"over 1 MiB", func(dir string) { write(t, dir, WordPress, []byte(strings.Repeat("x", 1<<20+1))) },
			"wp-config.php is over 1 MiB, which is more than a config holds; pass --dsn instead"},
		{"a NUL byte", func(dir string) { write(t, dir, WordPress, []byte("<?php\x00")) },
			"wp-config.php holds a NUL byte, so it isn't a config prodmask reads; pass --dsn instead"},
		{"a folder in its place", func(dir string) {
			if err := os.Mkdir(filepath.Join(dir, WordPress), 0o700); err != nil {
				t.Fatal(err)
			}
		}, "can't read wp-config.php in the folder given to --project"},
	}
	for _, c := range refusals {
		dir := secretDir(t)
		c.build(dir)
		if _, err := Read(dir); err == nil {
			t.Errorf("%s: no refusal", c.name)
		} else if got := refusalText(t, dir, err); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}

}

// TestReadSymlinks checks that a symlinked configuration is followed, as
// deploy tools link shared ones, and that a broken link is unreadable.
func TestReadSymlinks(t *testing.T) {
	var got []byte
	saved := readers
	readers = map[string]func([]byte) (*settings, error){
		WordPress: func(b []byte) (*settings, error) {
			got = append([]byte(nil), b...)
			return &settings{user: "u", database: "d", host: "db"}, nil
		},
	}
	t.Cleanup(func() { readers = saved })
	dir := secretDir(t)
	target := filepath.Join(secretDir(t), "shared-wp-config.php")
	write(t, filepath.Dir(target), filepath.Base(target), []byte("<?php\n"))
	if err := os.Symlink(target, filepath.Join(dir, WordPress)); err != nil {
		t.Skip("this system won't make a symlink without a privilege, so the symlink cases run elsewhere, such as on Linux in CI")
	}
	if _, err := Read(dir); err != nil || string(got) != "<?php\n" {
		t.Errorf("a symlinked config: %v, read %q", err, got)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil || refusalText(t, dir, err) != "can't read wp-config.php in the folder given to --project" {
		t.Errorf("a broken symlink: %v", err)
	}
}

// TestConfigCache checks that Laravel's bootstrap/cache/config.php beside .env
// sets ConfigCache, from a stat only.
func TestConfigCache(t *testing.T) {
	stubReaders(t)
	for _, cached := range []bool{false, true} {
		dir := secretDir(t)
		write(t, dir, Laravel, []byte("DB_CONNECTION=mysql\n"))
		write(t, dir, "artisan", []byte("x"))
		if cached {
			// A folder in the cache file's place proves it's never read.
			if err := os.MkdirAll(filepath.Join(dir, "bootstrap", "cache", "config.php"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		p, err := Read(dir)
		if err != nil || p.ConfigCache != cached {
			t.Errorf("cache %v: %+v, %v", cached, p, err)
		}
	}
}

// TestDropIn checks that WordPress's wp-content/db.php sets DropIn, from a
// stat only, and only beside wp-config.php.
func TestDropIn(t *testing.T) {
	stubReaders(t)
	for _, c := range []struct {
		file         string
		dropIn, want bool
	}{
		{WordPress, false, false},
		{WordPress, true, true},
		{Magento, true, false},
	} {
		dir := secretDir(t)
		write(t, dir, c.file, []byte("<?php\n"))
		if c.dropIn {
			// A folder in the drop-in's place proves it's never read.
			if err := os.MkdirAll(filepath.Join(dir, "wp-content", "db.php"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		p, err := Read(dir)
		if err != nil || p.DropIn != c.want {
			t.Errorf("%s, drop-in %v: %+v, %v", c.file, c.dropIn, p, err)
		}
	}
}

// TestConfig checks how settings become a connection: a socket over its path,
// localhost for an empty host, TCP to anything else, and 3306 by default.
func TestConfig(t *testing.T) {
	for _, c := range []struct {
		s                        settings
		net, addr                string
		socket, localhost        bool
		user, password, database string
	}{
		{settings{socket: "/run/mysqld.sock", host: "db", port: 3307}, "unix", "/run/mysqld.sock", true, false, "", "", ""},
		{settings{}, "tcp", "localhost:3306", false, true, "", "", ""},
		{settings{host: "LocalHost", port: 3307}, "tcp", "localhost:3307", false, true, "", "", ""},
		{settings{host: "127.0.0.1"}, "tcp", "127.0.0.1:3306", false, false, "", "", ""},
		{settings{host: "::1", port: 3307}, "tcp", "[::1]:3307", false, false, "", "", ""},
		{settings{host: "db.example.test", user: "u", password: "p", database: "shop"}, "tcp", "db.example.test:3306", false, false, "u", "p", "shop"},
	} {
		cfg, socket, localhost := c.s.config()
		if cfg.Net != c.net || cfg.Addr != c.addr || socket != c.socket || localhost != c.localhost ||
			cfg.User != c.user || cfg.Passwd != c.password || cfg.DBName != c.database || cfg.TLS != nil || cfg.TLSConfig != "" {
			t.Errorf("%+v: %s %s, socket %v, localhost %v", c.s, cfg.Net, cfg.Addr, socket, localhost)
		}
	}
	p := &Project{File: WordPress, Socket: true}
	if p.Label() != "the unix socket from wp-config.php" || p.Port() != 0 {
		t.Errorf("label %q, port %d", p.Label(), p.Port())
	}
}

// TestHint checks the no-DSN hint: one configuration in the folder, found
// through stat alone, and only at the fixed names.
func TestHint(t *testing.T) {
	allowed := map[string]bool{WordPress: true, Magento: true, Laravel: true, "artisan": true}
	for _, c := range []struct {
		files []string
		want  string
	}{
		{nil, ""},
		{[]string{WordPress}, "this folder has wp-config.php: pass --project . to read it"},
		{[]string{Magento}, "this folder has app/etc/env.php: pass --project . to read it"},
		{[]string{Laravel, "artisan"}, "this folder has .env: pass --project . to read it"},
		{[]string{Laravel}, ""},
		{[]string{WordPress, Magento}, ""},
		{[]string{WordPress, Laravel}, "this folder has wp-config.php: pass --project . to read it"},
	} {
		stat := func(name string) (fs.FileInfo, error) {
			name = filepath.ToSlash(name)
			if !allowed[name] {
				t.Errorf("the hint looked at %q", name)
			}
			if slices.Contains(c.files, name) {
				return nil, nil
			}
			return nil, fs.ErrNotExist
		}
		if got := Hint(stat); got != c.want {
			t.Errorf("%v: %q, want %q", c.files, got, c.want)
		}
	}
}

// TestMessages checks the closed set: every constructor's text is in it, and
// a text that isn't falls back to fixed words.
func TestMessages(t *testing.T) {
	set := map[string]bool{}
	for _, m := range Messages() {
		set[m] = true
	}
	for _, e := range []*Error{
		errNoFolder(), errNone(), errUnreadable(Magento), errTooBig(Laravel), errNUL(WordPress), errTLS(Laravel),
		errSeveral([]string{WordPress, Laravel}), errUnquoted("DB_PASSWORD"),
		keyError(WordPress, "DB_HOST", reasonForm), fileError(Magento, "it doesn't return an array of plain values"),
		{textClientFlags}, {textDriverOptions},
	} {
		if !set[e.Error()] {
			t.Errorf("not in Messages: %q", e.Error())
		}
	}
	if got := keyError(WordPress, "DB_HOST", "is "+"pw-Qz8canary").Error(); got != "can't read the database from wp-config.php; pass --dsn instead" {
		t.Errorf("an unknown reason: %q", got)
	}
	if got := keyError(WordPress, "Qz8canary", reasonMissing).Error(); strings.Contains(got, "Qz8canary") {
		t.Errorf("an unknown key: %q", got)
	}
}
