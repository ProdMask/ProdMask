package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/config"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/projectdb"
	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

func scanCommand() *Command {
	return &Command{
		Name:    "scan",
		Args:    "[flags]",
		Summary: "scan a database (read-only)",
		Run:     runScan,
	}
}

func runScan(ctx context.Context, env *Env, args []string) int {
	stdout, stderr := env.Stdout, env.Stderr
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "connection string, mysql://user@host:3306/db or user@tcp(host:3306)/db\n(default $PRODMASK_DSN; the password may come from $PRODMASK_PASSWORD)")
	project := fs.String("project", "", "read the database settings from the app's config in this folder instead:\nwp-config.php, Laravel's .env or Magento's app/etc/env.php")
	sampleRows := fs.Int("sample-rows", scan.DefaultSampleRows, "rows to sample per table")
	metaRows := fs.Int("meta-sample-rows", scan.DefaultMetaSampleRows, "rows to sample from a key/value table such as wp_postmeta\nthat is too big to read whole")
	noSamples := fs.Bool("no-samples", false, "judge column names only and sample no rows; the platform checks\nstill read settings rows, unless --preset none")
	format := fs.String("format", "text", "report format: text, markdown or json")
	out := fs.String("out", "", "write the report to this file instead of standard output")
	configOut := fs.String("config-out", "", "also write a starter masking config (YAML) to this file")
	force := fs.Bool("force", false, "overwrite the files given to --out and --config-out")
	presetName := fs.String("preset", "auto", "platform presets: auto, none, "+strings.Join(preset.Names, ", "))
	dump := fs.String("dump", "", "scan this SQL dump file (plain or gzip) instead of a database: a path, read twice;\nit judges what the file holds, so run it on a masked dump")
	database := fs.String("database", "", "with --dump: the database to scan, when the file holds several")
	timeout := fs.Duration("timeout", 10*time.Second, "server-side time limit for each statement")
	failOn := fs.String("fail-on", "none", "exit with status 3 if anything at or above this severity is found:\nnone, low, medium, high or critical")
	verbose := fs.Bool("verbose", false, "also show low-confidence matches and inferred relationships, and the evidence,\nkinds of data and side-effect sentences the report otherwise shortens")
	noColor := fs.Bool("no-color", false, "plain text report without colours (also: $NO_COLOR); the report fits\nthe terminal's width, at most 100 columns, or $COLUMNS when set")
	usage := `Usage: prodmask scan [flags]

Scans one database without changing anything: a read-only session, a few
hundred rows per table, and a time limit on every statement. Reports list
names, counts and categories, never the sampled values.

Exit status: 0 done, 1 error, 2 bad usage, 3 found something at or above
--fail-on.

With --dump FILE it scans a SQL dump file in place of a database, to check
what a masker left behind. It reads the file twice, without a server: the
structure from its CREATE TABLE statements, and up to --sample-rows rows of
each table, the ones a scan of a database reads. It judges the names and values
that are in the file. It doesn't check side effects (those read live settings
and queues through a server), the bodies of triggers, routines, events and
views, or IDENTIFIED BY passwords. A statement it can't read is listed in the
report and fails --fail-on with status 1, after the report. --dsn, --project,
--timeout, --meta-sample-rows and --config-out don't go with --dump.
`
	if ok, code := parseQuiet(env, "scan", fs, usage, args); !ok {
		return code
	}
	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "prodmask scan: "+format+"\n", a...)
		return ExitUsage
	}
	if !slices.Contains([]string{"text", "markdown", "md", "json"}, *format) {
		return usageErr("the value of --format isn't valid: it's text, markdown or json")
	}
	if *presetName != "auto" && *presetName != "none" && !slices.Contains(preset.Names, *presetName) {
		return usageErr("the value of --preset isn't valid: it's auto, none, %s", strings.Join(preset.Names, ", "))
	}
	threshold, err := model.ParseSeverity(*failOn)
	if err != nil {
		return usageErr("the value of --fail-on isn't valid: it's none, low, medium, high or critical")
	}
	// A flag given empty, as by a script's unset variable, still counts as
	// given.
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if given["database"] && !given["dump"] {
		return usageErr("--database goes with --dump")
	}
	if given["dump"] {
		for _, f := range []string{"dsn", "project", "timeout", "meta-sample-rows", "config-out"} {
			if given[f] {
				return usageErr("--%s doesn't go with --dump", f)
			}
		}
		switch *dump {
		case "":
			return usageErr("--dump is empty: give the dump file's path")
		case "-":
			return usageErr("--dump needs a file's path, not standard input: it reads the file twice")
		}
	}
	if !*noSamples && given["dump"] && *sampleRows < 1 {
		return usageErr("--sample-rows must be at least 1 (or use --no-samples)")
	}
	if !*noSamples && (*sampleRows < 1 || *metaRows < 1) {
		return usageErr("--sample-rows and --meta-sample-rows must be at least 1 (or use --no-samples)")
	}
	if *timeout < time.Second {
		return usageErr("--timeout must be at least 1s")
	}
	for _, f := range []struct{ name, path string }{{"--out", *out}, {"--config-out", *configOut}} {
		if f.path == "" || *force {
			continue
		}
		if _, err := os.Stat(f.path); err == nil {
			return usageErr("the file given to %s already exists; use --force to overwrite it", f.name)
		}
	}

	if given["dump"] {
		return runScanDump(ctx, env, dumpScan{
			path: *dump, database: *database, format: *format, out: *out, verbose: *verbose, noColor: *noColor,
			threshold: threshold, failOn: *failOn,
			opts: scan.Options{SampleRows: *sampleRows, Samples: !*noSamples, Preset: *presetName, Version: env.App.Version},
		})
	}
	var (
		cfg  *mysql.Config
		proj *projectdb.Project
	)
	if given["project"] {
		switch {
		case given["dsn"]:
			return usageErr("give --dsn or --project, not both")
		case *project == "":
			return usageErr("--project is empty: give the app's folder")
		}
		proj, err = readProject(stderr, *project)
		if err != nil {
			return usageErr("%v", err)
		}
		cfg = proj.Config
	} else {
		conn := *dsn
		if conn == "" {
			conn = os.Getenv("PRODMASK_DSN")
		}
		cfg, err = dbconn.ParseDSN(conn, os.Getenv("PRODMASK_PASSWORD"))
		if err != nil {
			code := usageErr("%v", err)
			if strings.TrimSpace(conn) == "" {
				if hint := projectdb.Hint(os.Stat); hint != "" {
					fmt.Fprintln(stderr, "prodmask scan: "+hint)
				}
			}
			return code
		}
	}
	// A socket read from a project's config is named by a label, never by its
	// path, which can hold a user's or the project's name; showErr keeps the
	// path out of any error printed later too. With --project, the database
	// and user names come from a file the user may not have written, so
	// showErr cleans errors as the reports clean names from the database.
	label, showErr := "", func(err error) string { return err.Error() }
	if proj != nil {
		if proj.Socket {
			label = proj.Label()
		}
		showErr = func(err error) string {
			s := err.Error()
			if label != "" {
				s = strings.ReplaceAll(s, cfg.Addr, label)
			}
			return report.Clean(s)
		}
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	interactive := isTerminal(os.Stderr)
	fmt.Fprintf(stderr, "Connecting to %s (read-only)...\n", report.Clean(dbconn.DescribeAs(cfg, label)))
	sess, err := dbconn.OpenAs(ctx, cfg, *timeout, label)
	if err != nil {
		fmt.Fprintf(stderr, "prodmask: %s\n", showErr(err))
		if proj != nil && proj.Localhost {
			fmt.Fprintln(stderr, "prodmask: the app may reach localhost through a socket; pass --dsn with ?socket=/path instead")
		}
		return ExitError
	}
	defer sess.Close()

	opts := scan.Options{
		SampleRows: *sampleRows, MetaSampleRows: *metaRows, Samples: !*noSamples,
		Preset: *presetName, Version: env.App.Version,
	}
	if interactive {
		opts.Progress = func(done, total int, table string) {
			fmt.Fprint(stderr, progressLine("Scanning", done, total, table))
		}
	}
	res, err := scan.Run(ctx, sess, opts)
	if err != nil {
		if interactive {
			fmt.Fprintln(stderr)
		}
		fmt.Fprintf(stderr, "prodmask: %s\n", showErr(err))
		return ExitError
	}
	// The reports name the build's edition; the starter config keeps the
	// version alone.
	res.Edition = env.App.Edition

	if *configOut != "" {
		if err := writeFile(*configOut, func(w io.Writer) error { return config.Write(w, res) }); err != nil {
			fmt.Fprintln(stderr, "prodmask: can't write the file given to --config-out")
			return ExitError
		}
	}

	render := func(w io.Writer, color bool) error {
		switch *format {
		case "json":
			return report.JSON(w, res)
		case "markdown", "md":
			return report.Markdown(w, res)
		}
		return report.Text(w, res, report.TextOptions{Color: color, Verbose: *verbose, ConfigWritten: *configOut != "",
			Width: textWidth(env, *out)})
	}
	if *out != "" {
		err = writeFile(*out, func(w io.Writer) error { return render(w, false) })
	} else {
		color := !*noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" &&
			isTerminal(os.Stdout) && enableANSI(os.Stdout)
		err = render(stdout, color)
	}
	if err != nil {
		fmt.Fprintln(stderr, "prodmask: can't write the report")
		return ExitError
	}
	if *out != "" {
		fmt.Fprintln(stderr, "Report written.")
	}

	if threshold != model.SeverityNone && res.Summary.Highest >= threshold {
		fmt.Fprintf(stderr, "prodmask: found %s-severity items (--fail-on %s)\n", res.Summary.Highest, threshold)
		return ExitFindings
	}
	return ExitOK
}

// readProject reads the database settings of the app in dir, for --project,
// and says on stderr, in fixed words, what it read and what it ignored. Its
// error is a fixed refusal that names neither dir nor anything from the file.
func readProject(stderr io.Writer, dir string) (*projectdb.Project, error) {
	for _, v := range []string{"PRODMASK_DSN", "PRODMASK_PASSWORD"} {
		if os.Getenv(v) != "" {
			fmt.Fprintf(stderr, "$%s isn't used with --project.\n", v)
		}
	}
	p, err := projectdb.Read(dir)
	if err != nil {
		return nil, err
	}
	if p.ConfigCache {
		fmt.Fprintln(stderr, "Laravel's config cache is on, so the app reads bootstrap/cache/config.php, not .env; "+
			"check the database below, or pass --dsn")
	}
	if p.DropIn {
		fmt.Fprintln(stderr, "WordPress loads wp-content/db.php, which can replace its database connection; "+
			"check the database below, or pass --dsn")
	}
	fmt.Fprintf(stderr, "Reading the database settings from %s in the folder given to --project.\n", p.File)
	if p.Localhost {
		fmt.Fprintf(stderr, "%s names localhost, which PHP reaches through a socket; connecting over TCP to localhost:%d instead.\n",
			p.File, p.Port())
	}
	return p, nil
}

// writeFile writes through a temporary file in the same folder, so a failed
// scan never leaves half a file behind. Its errors quote the path, which may be
// a secret typed in the wrong place, so they aren't for printing.
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
