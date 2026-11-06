package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/leak"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/report"
)

// keyEnv is where the key can come from besides --key-file. No flag takes the
// key itself, so it can't reach a process list or a shell's history.
const keyEnv = "PRODMASK_LEAK_KEY"

const leakCheckUsage = `Usage: prodmask leak-check key|hash|compare [flags]

Answers one question: how many real production values are on this staging
database? It reports counts per column, never a value or a row, and a zero
isn't proof that none are there: only a sample is looked for, and only kinds
unlikely to match by chance, so real names and addresses aren't.

  prodmask leak-check key --out leak.key
      Makes a key. It goes to a file, never to the screen.

  prodmask leak-check hash --dsn PRODUCTION --key-file leak.key --out hashes.json
      Scans production, samples the columns the scan flags, and writes keyed
      hashes. Treat that file as personal data.

  prodmask leak-check compare --dsn STAGING --key-file leak.key --hashes hashes.json
      Reads those columns whole on staging and counts the sampled values it
      finds. It belongs on staging: never point it at production.

The key can come from $PRODMASK_LEAK_KEY instead of --key-file. Run
"prodmask leak-check hash -h" or "compare -h" for their flags. See
https://github.com/ProdMask/ProdMask/blob/main/docs/leak-check.md
`

func leakCheckCommand() *Command {
	return &Command{
		Name:    "leak-check",
		Args:    "key|hash|compare [flags]",
		Summary: "count real production values on a staging database",
		Run:     runLeakCheck,
	}
}

func runLeakCheck(ctx context.Context, env *Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, leakCheckUsage)
		return ExitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(env.Stderr, leakCheckUsage)
		return ExitOK
	case "key":
		return runLeakKey(env, args[1:])
	case "hash":
		return runLeakHash(ctx, env, args[1:])
	case "compare":
		return runLeakCompare(ctx, env, args[1:])
	}
	fmt.Fprintf(env.Stderr, "prodmask leak-check: argument 1 is none of key, hash or compare; it isn't shown, in case it is a secret\n")
	return ExitUsage
}

// listFlag is a flag that can be given many times.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error {
	*l = append(*l, s)
	return nil
}

func runLeakKey(env *Env, args []string) int {
	fs := flag.NewFlagSet("key", flag.ContinueOnError)
	out := fs.String("out", "", "the new file to write the key to; it won't overwrite a file")
	usage := `Usage: prodmask leak-check key --out FILE

Makes a key: 32 random bytes, in hex. It goes to the file, owner-only where the
system has that, and never to the screen. Keep it apart from the hash file.
`
	if ok, code := parseQuiet(env, "leak-check key", fs, usage, args); !ok {
		return code
	}
	if *out == "" {
		fmt.Fprintln(env.Stderr, "prodmask leak-check key: --out is required")
		return ExitUsage
	}
	if err := leak.WriteNewKey(*out); err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintln(env.Stderr, "prodmask leak-check key: the file given to --out already exists, and a key file is never overwritten")
			return ExitUsage
		}
		fmt.Fprintln(env.Stderr, "prodmask: can't write the file given to --out")
		return ExitError
	}
	fmt.Fprintln(env.Stderr, "Key written. Keep it apart from the hash file.")
	return ExitOK
}

// loadLeakKey reads the key from --key-file or the environment. Its errors
// never quote what it read.
func loadLeakKey(env *Env, verb, file string) (leak.Key, bool) {
	var (
		k   leak.Key
		err error
	)
	switch {
	case file != "":
		var open bool
		k, open, err = leak.ReadKeyFile(file)
		if err == nil && open && runtime.GOOS != "windows" {
			fmt.Fprintln(env.Stderr, "prodmask: warning: other users can read the file given to --key-file")
		}
	case os.Getenv(keyEnv) != "":
		k, err = leak.ParseKey([]byte(os.Getenv(keyEnv)))
	default:
		err = errors.New("no key: pass --key-file or set $" + keyEnv)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "prodmask leak-check %s: %v\n", verb, err)
		return leak.Key{}, false
	}
	return k, true
}

// openLeakSession connects to the one database a step names. Both steps need
// --dsn given outright, and ignore $PRODMASK_DSN: a wrong source gives a
// comforting zero, and a wrong target reads whole columns on production.
func openLeakSession(ctx context.Context, env *Env, verb, dsn string, timeout time.Duration) (*dbconn.Session, int) {
	stderr := env.Stderr
	if dsn == "" {
		fmt.Fprintf(stderr, "prodmask leak-check %s: --dsn is required; it never comes from $PRODMASK_DSN\n", verb)
		return nil, ExitUsage
	}
	cfg, err := dbconn.ParseDSN(dsn, os.Getenv("PRODMASK_PASSWORD"))
	if err != nil {
		// Fixed words: a parse error can quote part of what was typed.
		fmt.Fprintf(stderr, "prodmask leak-check %s: the value of --dsn doesn't parse: it takes mysql://user@host:port/database or user@tcp(host:port)/database\n", verb)
		return nil, ExitUsage
	}
	fmt.Fprintf(stderr, "Connecting to %s (read-only)...\n", dbconn.Describe(cfg))
	sess, err := dbconn.Open(ctx, cfg, timeout)
	if err != nil {
		fmt.Fprintf(stderr, "prodmask: %v\n", err)
		return nil, ExitError
	}
	return sess, ExitOK
}

func runLeakHash(ctx context.Context, env *Env, args []string) int {
	stdout, stderr := env.Stdout, env.Stderr
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "production's connection string, as scan takes it (required; never from $PRODMASK_DSN)\n(the password may come from $PRODMASK_PASSWORD)")
	keyFile := fs.String("key-file", "", "the file holding the key (default $"+keyEnv+")")
	out := fs.String("out", "", "the file to write the hashes to (required). Treat it as personal data")
	force := fs.Bool("force", false, "overwrite the file given to --out")
	var allow listFlag
	fs.Var(&allow, "allow-email", "keep staff addresses out of the sample: a domain with its subdomains, or an address.\nAn address is never written to the file. Can be given many times")
	presetName := fs.String("preset", "auto", "platform presets: auto, none, "+strings.Join(preset.Names, ", "))
	timeout := fs.Duration("timeout", 10*time.Second, "server-side time limit for each statement")
	usage := `Usage: prodmask leak-check hash --dsn PRODUCTION --out FILE [flags]

Scans production as prodmask scan does, then samples the columns it flags: up to
3,000 rows of a table, spread over its primary key, and for a key/value table
30,000 rows of keys and the flagged keys' values. All of it is read-only and
one statement at a time, and nothing it reads is kept but keyed hashes.

Treat the file as personal data until you delete it. Whoever holds the key and
the file can test a guess against it.

Exit status: 0 done, 1 error or nothing to hash, 2 bad usage.
`
	if ok, code := parseQuiet(env, "leak-check hash", fs, usage, args); !ok {
		return code
	}
	if *out == "" {
		fmt.Fprintln(stderr, "prodmask leak-check hash: --out is required")
		return ExitUsage
	}
	if *presetName != "auto" && *presetName != "none" && !slices.Contains(preset.Names, *presetName) {
		fmt.Fprintln(stderr, "prodmask leak-check hash: the value of --preset isn't valid")
		return ExitUsage
	}
	if *timeout < time.Second {
		fmt.Fprintln(stderr, "prodmask leak-check hash: --timeout must be at least 1s")
		return ExitUsage
	}
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintln(stderr, "prodmask leak-check hash: the file given to --out already exists; use --force to overwrite it")
			return ExitUsage
		}
	}
	allowed, err := leak.NewAllowlist(allow)
	if err != nil {
		fmt.Fprintf(stderr, "prodmask leak-check hash: %v\n", err)
		return ExitUsage
	}
	key, ok := loadLeakKey(env, "hash", *keyFile)
	if !ok {
		return ExitUsage
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	sess, code := openLeakSession(ctx, env, "hash", *dsn, *timeout)
	if sess == nil {
		return code
	}
	defer sess.Close()

	opts := leak.HashOptions{Allow: allowed, Preset: *presetName, Version: env.App.Version}
	interactive := isTerminal(os.Stderr)
	if interactive {
		opts.ScanProgress = func(done, total int, table string) {
			if table == "" {
				fmt.Fprint(stderr, "\r\x1b[K")
				return
			}
			fmt.Fprintf(stderr, "\r\x1b[KScanning %d/%d %s", done+1, total, table)
		}
		opts.Progress = func(done, total int, table string) {
			if table == "" {
				fmt.Fprint(stderr, "\r\x1b[K")
				return
			}
			fmt.Fprintf(stderr, "\r\x1b[KSampling %d/%d %s", done+1, total, table)
		}
	}
	f, warnings, err := leak.Hash(ctx, sess, key, opts)
	if interactive && err != nil {
		fmt.Fprintln(stderr)
	}
	for _, wn := range warnings {
		fmt.Fprintf(stderr, "prodmask: warning: %s\n", wn)
	}
	if err != nil {
		fmt.Fprintf(stderr, "prodmask: %v\n", err)
		return ExitError
	}
	if err := writeFile(*out, f.Write); err != nil {
		fmt.Fprintln(stderr, "prodmask: can't write the file given to --out")
		return ExitError
	}
	var total int64
	for _, c := range f.Columns {
		total += int64(c.Values)
	}
	fmt.Fprintf(stdout, "Hash file written: %s values sampled from %d columns of %s.\n", report.Count(total), len(f.Columns), f.Database)
	for _, c := range f.Columns {
		fmt.Fprintf(stdout, "  %s  %s  %s\n", model.LeakLocation(c.Table, c.Column, c.MetaKey), c.Kind.Label(), report.Count(int64(c.Values)))
	}
	for _, l := range f.LeftOut {
		if l.NotRead {
			fmt.Fprintf(stdout, "  %s  %s: compare will count it as not read\n", l.Location, l.Why)
		}
	}
	fmt.Fprintln(stdout, "Treat the file as personal data: keep it as you keep production data, and delete it after the check.")
	return ExitOK
}

func runLeakCompare(ctx context.Context, env *Env, args []string) int {
	stdout, stderr := env.Stdout, env.Stderr
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "staging's connection string, as scan takes it (required; never from $PRODMASK_DSN)\n(the password may come from $PRODMASK_PASSWORD)")
	keyFile := fs.String("key-file", "", "the file holding the key (default $"+keyEnv+")")
	hashes := fs.String("hashes", "", "the file prodmask leak-check hash wrote (required)")
	var allow, except listFlag
	fs.Var(&allow, "allow-email", "skip staff addresses: a domain with its subdomains, or an address.\nAn address is never written to the report. Can be given many times")
	failOn := fs.String("fail-on", "none", "exit with status 3 if a sampled value at or above this severity turns up, and\nwith status 1 if a column at or above it couldn't be checked in full:\nnone, low, medium, high or critical. high means any kind this check counts,\ncritical means secrets only")
	fs.Var(&except, "fail-except", "a column, key or table, as the report prints it, that can't fail --fail-on.\nIt's still read and reported. Can be given many times")
	format := fs.String("format", "text", "report format: text or json")
	reportOut := fs.String("out", "", "write the report to this file instead of standard output")
	force := fs.Bool("force", false, "overwrite the file given to --out")
	maxTime := fs.Duration("max-time", time.Hour, "the limit on the whole read; what it stops is reported, and fails --fail-on (0 for none)")
	timeout := fs.Duration("timeout", time.Minute, "server-side time limit for each statement. Tables with a single integer\nprimary key are read in short chunks; any other table is one statement")
	noColor := fs.Bool("no-color", false, "plain text report without colours (also: $NO_COLOR)")
	usage := `Usage: prodmask leak-check compare --dsn STAGING --hashes FILE [flags]

Reads on staging, whole, the columns the hash file names, and counts the sampled
values it finds. The report holds names and counts, never a value or a row. A
zero isn't proof that none are there. It reads whole columns, so it belongs on
staging: never point it at production.

Exit status: 0 done, 1 error, nothing read, or with --fail-on a column that
couldn't be checked in full, 2 bad usage, 3 a sampled value at or above --fail-on
turned up.
`
	if ok, code := parseQuiet(env, "leak-check compare", fs, usage, args); !ok {
		return code
	}
	usageErr := func(s string) int {
		fmt.Fprintf(stderr, "prodmask leak-check compare: %s\n", s)
		return ExitUsage
	}
	if *hashes == "" {
		return usageErr("--hashes is required")
	}
	if *format != "text" && *format != "json" {
		return usageErr("the value of --format isn't valid: it's text or json")
	}
	threshold, err := model.ParseSeverity(*failOn)
	if err != nil {
		return usageErr("the value of --fail-on isn't valid: it's none, low, medium, high or critical")
	}
	if *timeout < time.Second {
		return usageErr("--timeout must be at least 1s")
	}
	if *maxTime < 0 {
		return usageErr("--max-time can't be negative")
	}
	if *reportOut != "" && !*force {
		if _, err := os.Stat(*reportOut); err == nil {
			return usageErr("the file given to --out already exists; use --force to overwrite it")
		}
	}
	allowed, err := leak.NewAllowlist(allow)
	if err != nil {
		return usageErr(err.Error())
	}
	key, ok := loadLeakKey(env, "compare", *keyFile)
	if !ok {
		return ExitUsage
	}
	file, err := leak.ReadFile(*hashes)
	if err != nil {
		return usageErr(err.Error())
	}
	if err := file.CheckKey(key); err != nil {
		return usageErr(err.Error())
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	sess, code := openLeakSession(ctx, env, "compare", *dsn, *timeout)
	if sess == nil {
		return code
	}
	defer sess.Close()

	opts := leak.CompareOptions{Allow: allowed, FailExcept: except, MaxTime: *maxTime, Version: env.App.Version,
		Starting: func(tables int, rows int64) {
			fmt.Fprintf(stderr, "Reading whole columns on %s: about %s rows in %d tables.\n",
				sess.Database, report.Count(rows), tables)
		},
	}
	interactive := isTerminal(os.Stderr)
	if interactive {
		opts.Progress = func(done, total int, table string, rows int64) {
			if table == "" {
				fmt.Fprint(stderr, "\r\x1b[K")
				return
			}
			fmt.Fprintf(stderr, "\r\x1b[KReading %d/%d %s: %s rows", done+1, total, table, report.Count(rows))
		}
	}
	res, err := leak.Compare(ctx, sess, file, key, opts)
	if err != nil {
		if interactive {
			fmt.Fprintln(stderr)
		}
		fmt.Fprintf(stderr, "prodmask: %v\n", err)
		return ExitError
	}

	render := func(w io.Writer, color bool) error {
		if *format == "json" {
			return report.LeakJSON(w, res)
		}
		return report.LeakText(w, res, color)
	}
	if *reportOut != "" {
		err = writeFile(*reportOut, func(w io.Writer) error { return render(w, false) })
	} else {
		color := !*noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" &&
			isTerminal(os.Stdout) && enableANSI(os.Stdout)
		err = render(stdout, color)
	}
	if err != nil {
		fmt.Fprintln(stderr, "prodmask: can't write the report")
		return ExitError
	}
	if *reportOut != "" {
		fmt.Fprintln(stderr, "Report written.")
	}
	return leakStatus(stderr, res, threshold, *failOn)
}

// leakStatus prints the last word on stderr, so a CI log carries it even when
// the report goes to a file, and works out the exit status. A gate fails closed
// whenever it couldn't look.
func leakStatus(stderr io.Writer, res *model.LeakResult, threshold model.Severity, failOn string) int {
	s := res.Summary
	found, sampled := s.Found+s.FoundInPart, s.Sampled+s.SampledInPart
	unread, total := s.Columns-s.ColumnsRead, s.Columns
	for _, l := range res.LeftOut {
		if l.NotRead {
			unread++
			total++
		}
	}
	note := ""
	if unread > 0 {
		note = fmt.Sprintf(" %d of %d columns weren't read in whole.", unread, total)
	}
	switch {
	case res.NothingRead():
		fmt.Fprintln(stderr, "prodmask: nothing was read on staging, so nothing is known about it.")
	case found > 0:
		fmt.Fprintf(stderr, "prodmask: %s of %s sampled production values found on staging.%s\n", report.Count(found), report.Count(sampled), note)
	default:
		fmt.Fprintf(stderr, "prodmask: 0 of %s sampled production values found. That isn't proof that none are there: see the report.%s\n", report.Count(sampled), note)
	}
	if threshold != model.SeverityNone {
		hits, unchecked := leak.Gate(res, threshold)
		if hits > 0 {
			return ExitFindings
		}
		if unchecked > 0 {
			fmt.Fprintf(stderr, "prodmask: %d columns at or above --fail-on %s couldn't be checked in full, so the gate fails: see the report.\n", unchecked, failOn)
			return ExitError
		}
	}
	if res.NothingRead() {
		return ExitError
	}
	return ExitOK
}
