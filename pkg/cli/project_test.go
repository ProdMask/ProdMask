package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// projectSecret is a folder name that reads like a secret typed in the wrong
// place, which no output may repeat.
const projectSecret = "pw-" + "Qz8" + "projectSecret"

// TestScanProjectUsage checks --project's bad usage: with --dsn, even empty,
// empty itself, a folder that isn't there, and one with no config. Each exits
// 2 in fixed words that never name the folder, and $PRODMASK_DSN and
// $PRODMASK_PASSWORD are noted as unused before anything is read; an empty
// --project never falls back on them.
func TestScanProjectUsage(t *testing.T) {
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	empty := filepath.Join(t.TempDir(), projectSecret)
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	none := "prodmask scan: the folder given to --project has no wp-config.php, app/etc/env.php or Laravel .env " +
		"(WordPress can keep wp-config.php one folder up; pass that folder)\n"
	emptyProject := "prodmask scan: --project is empty: give the app's folder\n"
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--dsn", "mysql://ro@db.example.test/shop", "--project", empty}, "prodmask scan: give --dsn or --project, not both\n"},
		{[]string{"--project", empty, "--dsn", "mysql://ro@db.example.test/shop"}, "prodmask scan: give --dsn or --project, not both\n"},
		{[]string{"--dsn", "mysql://ro@db.example.test/shop", "--project="}, "prodmask scan: give --dsn or --project, not both\n"},
		{[]string{"--dsn=", "--project", empty}, "prodmask scan: give --dsn or --project, not both\n"},
		{[]string{"--project", ""}, emptyProject},
		{[]string{"--project="}, emptyProject},
		{[]string{"--project", filepath.Join(empty, "missing")}, "prodmask scan: can't read the folder given to --project\n"},
		{[]string{"--project", empty}, none},
		{[]string{"--project=" + empty}, none},
	} {
		code, stdout, stderr := run(New("1.2.3"), append([]string{"scan"}, c.args...)...)
		if code != ExitUsage || stdout != "" || stderr != c.want {
			t.Errorf("scan %s: status %d\n%q, want\n%q", strings.Join(c.args, " "), code, stderr, c.want)
		}
		if strings.Contains(stdout+stderr, projectSecret) {
			t.Errorf("scan %s: the folder is named", strings.Join(c.args, " "))
		}
	}

	t.Setenv("PRODMASK_DSN", "mysql://ro:"+"Qz8envSecret"+"@db.example.test/shop")
	t.Setenv("PRODMASK_PASSWORD", "Qz8"+"envPassword")
	code, stdout, stderr := run(New("1.2.3"), "scan", "--project", empty)
	want := "$PRODMASK_DSN isn't used with --project.\n$PRODMASK_PASSWORD isn't used with --project.\n" + none
	if code != ExitUsage || stdout != "" || stderr != want {
		t.Errorf("scan --project with the variables set: status %d\n%q, want\n%q", code, stderr, want)
	}
	code, stdout, stderr = run(New("1.2.3"), "scan", "--project", "")
	if code != ExitUsage || stdout != "" || stderr != emptyProject {
		t.Errorf("scan --project \"\" with the variables set: status %d\n%q", code, stderr)
	}
}

// TestScanNoDSNHint checks that a scan with no DSN, in a folder holding one
// config, adds the hint that names only the config's fixed name.
func TestScanNoDSNHint(t *testing.T) {
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	noDSN := "prodmask scan: no DSN given: pass --dsn or set PRODMASK_DSN\n"
	for _, c := range []struct {
		files []string
		hint  string
	}{
		{nil, ""},
		{[]string{"wp-config.php"}, "prodmask scan: this folder has wp-config.php: pass --project . to read it\n"},
		{[]string{"app/etc/env.php"}, "prodmask scan: this folder has app/etc/env.php: pass --project . to read it\n"},
		{[]string{".env", "artisan"}, "prodmask scan: this folder has .env: pass --project . to read it\n"},
		{[]string{".env"}, ""},
	} {
		dir := filepath.Join(t.TempDir(), projectSecret)
		for _, f := range c.files {
			path := filepath.Join(dir, filepath.FromSlash(f))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("Qz8"+"fileCanary"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		code, stdout, stderr := run(New("1.2.3"), "scan")
		if code != ExitUsage || stdout != "" || stderr != noDSN+c.hint {
			t.Errorf("%v: status %d\n%q", c.files, code, stderr)
		}
	}
}

// TestScanProjectCleansNames checks that the database and user names read
// from a project's .env, which can hold characters that steer a terminal,
// reach the Connecting line and the connect error with each of those as ?.
// Nothing listens on the port, so the scan stops at the connect error.
func TestScanProjectCleansNames(t *testing.T) {
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	dir := filepath.Join(t.TempDir(), projectSecret)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A screen clear and a bell in the database's name, and a right-to-left
	// override in the user's. A semicolon, as a title change has, is refused
	// before this: PDO reads it as a separator.
	env := fmt.Sprintf("DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=%d\nDB_DATABASE=shop\x1b[2J\x07\n"+
		"DB_USERNAME=app\xe2\x80\xaeuser\nDB_PASSWORD=%s\n", port, "Qz8"+"envPassword")
	for name, body := range map[string]string{"artisan": "x", ".env": env} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, stdout, stderr := run(New("1.2.3"), "scan", "--project", dir)
	if code != ExitError || stdout != "" {
		t.Fatalf("status %d\n%q\n%q", code, stdout, stderr)
	}
	if strings.ContainsAny(stderr, "\x1b\x07\u202e") {
		t.Errorf("a character that steers a terminal reached stderr:\n%q", stderr)
	}
	target := fmt.Sprintf("app?user@127.0.0.1:%d/shop?[2J?", port)
	for _, want := range []string{"\nConnecting to " + target + " (read-only)...\n", "\nprodmask: connect to " + target + ": "} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr is missing %q:\n%q", want, stderr)
		}
	}
}

// TestLeakCheckRefusesProject checks that leak-check, which takes only an
// explicit --dsn, doesn't know --project.
func TestLeakCheckRefusesProject(t *testing.T) {
	for _, verb := range []string{"hash", "compare"} {
		code, stdout, stderr := run(New("1.2.3"), "leak-check", verb, "--project", ".")
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "is no flag it knows") {
			t.Errorf("leak-check %s --project: status %d\n%s", verb, code, stderr)
		}
	}
}
