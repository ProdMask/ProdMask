package cli

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
)

// The free build's help text, exactly as prodmask 0.1.0 printed it.
const wantUsage = `prodmask finds what a plain copy of a MySQL or MariaDB database would carry
into staging: personal data, secrets, and settings that would email or charge
real customers. It only reads, and it never prints the data it samples.

Usage:
  prodmask scan [flags]    scan a database (read-only)
  prodmask version         print the version

Run "prodmask scan -h" for the scan flags.
`

func run(a *App, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = a.Run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestFreeBuild(t *testing.T) {
	cases := []struct {
		args           []string
		code           int
		stdout, stderr string
	}{
		{nil, ExitUsage, "", wantUsage},
		{[]string{"help"}, ExitOK, wantUsage, ""},
		{[]string{"-h"}, ExitOK, wantUsage, ""},
		{[]string{"--help", "scan"}, ExitOK, wantUsage, ""},
		{[]string{"version"}, ExitOK, "prodmask 1.2.3\n", ""},
		{[]string{"--version"}, ExitOK, "prodmask 1.2.3\n", ""},
		{[]string{"version", "extra"}, ExitOK, "prodmask 1.2.3\n", ""},
		{[]string{"bogus"}, ExitUsage, "", "prodmask: unknown command \"bogus\"\n\n" + wantUsage},
		{[]string{"--bogus"}, ExitUsage, "", "prodmask: unknown command \"--bogus\"\n\n" + wantUsage},
	}
	for _, c := range cases {
		code, stdout, stderr := run(New("1.2.3"), c.args...)
		if code != c.code || stdout != c.stdout || stderr != c.stderr {
			t.Errorf("prodmask %q: got status %d\nstdout: %q\nstderr: %q", c.args, code, stdout, stderr)
		}
	}
}

func TestScanUsageErrors(t *testing.T) {
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	cases := []struct {
		args   []string
		stderr string
	}{
		{[]string{"--format", "xml"}, "prodmask scan: unknown --format \"xml\" (want text, markdown or json)\n"},
		{[]string{"--preset", "foo"}, "prodmask scan: unknown --preset \"foo\"\n"},
		{[]string{"--fail-on", "extreme"}, "prodmask scan: --fail-on: unknown severity \"extreme\" (want none, low, medium, high or critical)\n"},
		{[]string{"--sample-rows", "0"}, "prodmask scan: --sample-rows and --meta-sample-rows must be at least 1 (or use --no-samples)\n"},
		{[]string{"--timeout", "100ms"}, "prodmask scan: --timeout must be at least 1s\n"},
		{[]string{"extra"}, "prodmask scan: unexpected argument \"extra\"\n"},
		{nil, "prodmask scan: no DSN given: pass --dsn or set PRODMASK_DSN\n"},
		{[]string{"--dsn", "ftp://x"}, "prodmask scan: unsupported DSN scheme \"ftp\" (use mysql://)\n"},
	}
	for _, c := range cases {
		code, stdout, stderr := run(New("1.2.3"), append([]string{"scan"}, c.args...)...)
		if code != ExitUsage || stdout != "" || stderr != c.stderr {
			t.Errorf("prodmask scan %q: got status %d\nstdout: %q\nstderr: %q", c.args, code, stdout, stderr)
		}
	}

	code, stdout, stderr := run(New("1.2.3"), "scan", "-h")
	if code != ExitOK || stdout != "" || !strings.HasPrefix(stderr, "Usage: prodmask scan [flags]\n") ||
		!strings.Contains(stderr, "\n  -fail-on string\n") {
		t.Errorf("prodmask scan -h: got status %d\nstdout: %q\nstderr: %q", code, stdout, stderr)
	}
	code, _, stderr = run(New("1.2.3"), "scan", "--bogus")
	if code != ExitUsage || !strings.HasPrefix(stderr, "flag provided but not defined: -bogus\nUsage: prodmask scan [flags]\n") {
		t.Errorf("prodmask scan --bogus: got status %d\nstderr: %q", code, stderr)
	}
}

// Another build adds its own commands next to the free ones.
func TestRegister(t *testing.T) {
	var gotArgs []string
	var gotEnv *Env
	a := &App{Version: "2.0.0", Edition: "Pro", About: "About.\n", Footer: "Footer.\n"}
	a.Register(FreeCommands()...)
	a.Register(&Command{
		Name: "copy", Aliases: []string{"cp"}, Args: "[flags]", Summary: "make a copy",
		Run: func(_ context.Context, env *Env, args []string) int {
			gotArgs, gotEnv = args, env
			return 7
		},
	})

	wantPro := "About.\n\nUsage:\n" +
		"  prodmask copy [flags]    make a copy\n" +
		"  prodmask scan [flags]    scan a database (read-only)\n" +
		"  prodmask version         print the version\n" +
		"\nFooter.\n"
	if got := a.Usage(); got != wantPro {
		t.Errorf("usage:\n%s\nwant:\n%s", got, wantPro)
	}
	if code, stdout, _ := run(a, "version"); code != ExitOK || stdout != "prodmask Pro 2.0.0\n" {
		t.Errorf("version: got status %d, %q", code, stdout)
	}
	if code, _, _ := run(a, "cp", "--x", "y"); code != 7 || strings.Join(gotArgs, " ") != "--x y" || gotEnv.App != a {
		t.Errorf("copy: got status %d, args %q", code, gotArgs)
	}

	// New copies of the free commands, so builds don't share them.
	if FreeCommands()[0] == FreeCommands()[0] {
		t.Error("FreeCommands returned the same command twice")
	}
	var names []string
	for _, c := range a.Commands() {
		names = append(names, c.Name)
	}
	if strings.Join(names, " ") != "copy scan version" {
		t.Errorf("Commands: got %q", names)
	}

	// Each mistake on an app of its own, so one case can't pass because an
	// earlier one registered by mistake.
	noop := func(context.Context, *Env, []string) int { return ExitOK }
	for name, c := range map[string]*Command{
		"taken name":     {Name: "scan", Run: noop},
		"taken alias":    {Name: "plan", Aliases: []string{"--version"}, Run: noop},
		"own name":       {Name: "plan", Aliases: []string{"plan"}, Run: noop},
		"repeated alias": {Name: "plan", Aliases: []string{"p", "p"}, Run: noop},
		"empty alias":    {Name: "plan", Aliases: []string{""}, Run: noop},
		"reserved word":  {Name: "help", Run: noop},
		"reserved alias": {Name: "plan", Aliases: []string{"-h"}, Run: noop},
		"no name":        {Run: noop},
		"no Run":         {Name: "plan"},
		"nil":            nil,
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: Register did not panic", name)
				}
			}()
			New("1.2.3").Register(c)
		}()
	}
	// A well-formed command registers on the same kind of app.
	New("1.2.3").Register(&Command{Name: "plan", Aliases: []string{"p"}, Run: noop})
}

// Exit statuses are part of the command line's contract with scripts.
func TestExitStatuses(t *testing.T) {
	if got := []int{ExitOK, ExitError, ExitUsage, ExitFindings, ExitLicence}; !slices.Equal(got, []int{0, 1, 2, 3, 4}) {
		t.Errorf("got %v", got)
	}
}

func TestBuildVersion(t *testing.T) {
	if got := BuildVersion("1.4.0"); got != "1.4.0" {
		t.Errorf("stamped: got %q", got)
	}
	// Test binaries carry no module version.
	if got := BuildVersion(""); got != "dev" {
		t.Errorf("unstamped: got %q", got)
	}
}
