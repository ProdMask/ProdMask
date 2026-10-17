// Command prodmask finds what a plain copy of a MySQL or MariaDB database
// would carry into staging: personal data, secrets, and settings that would
// let staging email or charge real customers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/config"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// version is set at build time with -ldflags "-X main.version=...". Builds
// without it, from go install or go build, report the module version Go
// recorded, or "dev".
var version string

func currentVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "dev"
}

// Exit statuses.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitFindings = 3
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usageText = `prodmask finds what a plain copy of a MySQL or MariaDB database would carry
into staging: personal data, secrets, and settings that would email or charge
real customers. It only reads, and it never prints the data it samples.

Usage:
  prodmask scan [flags]    scan a database (read-only)
  prodmask version         print the version

Run "prodmask scan -h" for the scan flags.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return scanCmd(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintf(stdout, "prodmask %s\n", currentVersion())
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return exitOK
	}
	fmt.Fprintf(stderr, "prodmask: unknown command %q\n\n%s", args[0], usageText)
	return exitUsage
}

func scanCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("dsn", "", "connection string, mysql://user@host:3306/db or user@tcp(host:3306)/db\n(default $PRODMASK_DSN; the password may come from $PRODMASK_PASSWORD)")
	sampleRows := fs.Int("sample-rows", scan.DefaultSampleRows, "rows to sample per table")
	metaRows := fs.Int("meta-sample-rows", scan.DefaultMetaSampleRows, "rows to sample per key/value table such as wp_postmeta")
	noSamples := fs.Bool("no-samples", false, "judge column names only and read no rows")
	format := fs.String("format", "text", "report format: text, markdown or json")
	out := fs.String("out", "", "write the report to this file instead of standard output")
	configOut := fs.String("config-out", "", "also write a starter masking config (YAML) to this file")
	force := fs.Bool("force", false, "overwrite the files given to --out and --config-out")
	presetName := fs.String("preset", "auto", "platform presets: auto, none, "+strings.Join(preset.Names, ", "))
	timeout := fs.Duration("timeout", 10*time.Second, "server-side time limit for each statement")
	failOn := fs.String("fail-on", "none", "exit with status 3 if anything at or above this severity is found:\nnone, low, medium, high or critical")
	verbose := fs.Bool("verbose", false, "also show low-confidence matches, inferred relationships and full evidence")
	noColor := fs.Bool("no-color", false, "plain text report without colours (also: $NO_COLOR)")
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: prodmask scan [flags]

Scans one database without changing anything: a read-only session, a few
hundred rows per table, and a time limit on every statement. Reports list
names, counts and categories, never the sampled values.

Exit status: 0 done, 1 error, 2 bad usage, 3 found something at or above
--fail-on.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "prodmask scan: "+format+"\n", a...)
		return exitUsage
	}
	if fs.NArg() > 0 {
		return usageErr("unexpected argument %q", fs.Arg(0))
	}
	if !slices.Contains([]string{"text", "markdown", "md", "json"}, *format) {
		return usageErr("unknown --format %q (want text, markdown or json)", *format)
	}
	if *presetName != "auto" && *presetName != "none" && !slices.Contains(preset.Names, *presetName) {
		return usageErr("unknown --preset %q", *presetName)
	}
	threshold, err := model.ParseSeverity(*failOn)
	if err != nil {
		return usageErr("--fail-on: %v", err)
	}
	if !*noSamples && (*sampleRows < 1 || *metaRows < 1) {
		return usageErr("--sample-rows and --meta-sample-rows must be at least 1 (or use --no-samples)")
	}
	if *timeout < time.Second {
		return usageErr("--timeout must be at least 1s")
	}
	for _, p := range []string{*out, *configOut} {
		if p == "" || *force {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return usageErr("%s already exists; use --force to overwrite it", p)
		}
	}

	conn := *dsn
	if conn == "" {
		conn = os.Getenv("PRODMASK_DSN")
	}
	cfg, err := dbconn.ParseDSN(conn, os.Getenv("PRODMASK_PASSWORD"))
	if err != nil {
		return usageErr("%v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	interactive := isTerminal(os.Stderr)
	fmt.Fprintf(stderr, "Connecting to %s (read-only)...\n", dbconn.Describe(cfg))
	sess, err := dbconn.Open(ctx, cfg, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "prodmask: %v\n", err)
		return exitError
	}
	defer sess.Close()

	opts := scan.Options{
		SampleRows: *sampleRows, MetaSampleRows: *metaRows, Samples: !*noSamples,
		Preset: *presetName, Version: currentVersion(),
	}
	if interactive {
		opts.Progress = func(done, total int, table string) {
			if table == "" {
				fmt.Fprint(stderr, "\r\x1b[K")
				return
			}
			fmt.Fprintf(stderr, "\r\x1b[KScanning %d/%d %s", done+1, total, table)
		}
	}
	res, err := scan.Run(ctx, sess, opts)
	if err != nil {
		if interactive {
			fmt.Fprintln(stderr)
		}
		fmt.Fprintf(stderr, "prodmask: %v\n", err)
		return exitError
	}

	if *configOut != "" {
		if err := writeFile(*configOut, func(w io.Writer) error { return config.Write(w, res) }); err != nil {
			fmt.Fprintf(stderr, "prodmask: write config: %v\n", err)
			return exitError
		}
	}

	render := func(w io.Writer, color bool) error {
		switch *format {
		case "json":
			return report.JSON(w, res)
		case "markdown", "md":
			return report.Markdown(w, res)
		}
		return report.Text(w, res, report.TextOptions{Color: color, Verbose: *verbose, ConfigPath: *configOut})
	}
	if *out != "" {
		err = writeFile(*out, func(w io.Writer) error { return render(w, false) })
	} else {
		color := !*noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" &&
			isTerminal(os.Stdout) && enableANSI(os.Stdout)
		err = render(stdout, color)
	}
	if err != nil {
		fmt.Fprintf(stderr, "prodmask: write report: %v\n", err)
		return exitError
	}
	if *out != "" {
		fmt.Fprintf(stderr, "Report written to %s\n", *out)
	}

	if threshold != model.SeverityNone && res.Summary.Highest >= threshold {
		fmt.Fprintf(stderr, "prodmask: found %s-severity items (--fail-on %s)\n", res.Summary.Highest, threshold)
		return exitFindings
	}
	return exitOK
}

// writeFile writes through a temporary file in the same folder, so a failed
// scan never leaves half a file behind.
func writeFile(path string, fill func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".prodmask-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := fill(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
