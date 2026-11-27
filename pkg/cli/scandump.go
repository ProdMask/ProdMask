package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/scan"
	"github.com/ProdMask/ProdMask/pkg/sqldump"
)

// dumpScan is what scan --dump needs of the flags.
type dumpScan struct {
	path, database string
	opts           scan.Options
	format         string
	out            string
	verbose        bool
	noColor        bool
	threshold      model.Severity
	failOn         string
}

// dumpProgress is the progress line of a read of a dump: the pass of passes,
// the bytes read of the file's size, and the table, or a clear line when the
// pass ends.
func dumpProgress(pass, passes int, done, total int64, table string) string {
	if table == "" {
		return "\r\x1b[K"
	}
	if total < 0 {
		// Standard input, whose size isn't known.
		return fmt.Sprintf("\r\x1b[KReading pass %d of %d: %s: %s", pass, passes, megabytes(done), report.Clean(table))
	}
	return fmt.Sprintf("\r\x1b[KReading pass %d of %d: %s of %s: %s", pass, passes, megabytes(done), megabytes(total), report.Clean(table))
}

func megabytes(n int64) string { return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20)) }

// runScanDump is scan --dump. Every error it prints is a fixed text, or a name
// the reader parsed as one, cleaned; none holds the file's path.
func runScanDump(ctx context.Context, env *Env, d dumpScan) int {
	stdout, stderr := env.Stdout, env.Stderr
	if v := os.Getenv("PRODMASK_DSN"); v != "" {
		fmt.Fprintln(stderr, "$PRODMASK_DSN isn't used with --dump.")
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	rc, info, err := sqldump.Open(d.path, false)
	if err != nil {
		fmt.Fprintf(stderr, "prodmask: %s\n", report.Clean(err.Error()))
		return ExitError
	}
	rc.Close()
	cur := info
	open := func() (io.ReadCloser, error) {
		rc, in, err := sqldump.Open(d.path, false)
		if err == nil {
			cur = in
		}
		return rc, err
	}
	interactive := isTerminal(os.Stderr)
	opts := scan.DumpOptions{
		Options: d.opts, Database: d.database, File: filepath.Base(d.path), Compression: info.Compression,
		Size: info.Size, ModTime: info.ModTime,
		Stat: func() (int64, time.Time, error) {
			st, err := os.Stat(d.path)
			if err != nil {
				return 0, time.Time{}, sqldump.ErrOpen
			}
			return st.Size(), st.ModTime(), nil
		},
		BytesRead: func() int64 { return cur.BytesRead() },
	}
	passes := 2
	if !d.opts.Samples {
		passes = 1 // names only: the second pass doesn't run
	}
	if interactive {
		opts.ReadProgress = func(pass int, done, total int64, table string) {
			fmt.Fprint(stderr, dumpProgress(pass, passes, done, total, table))
		}
	}
	res, err := scan.RunDump(ctx, open, opts)
	if interactive {
		fmt.Fprint(stderr, dumpProgress(0, passes, 0, 0, ""))
	}
	cut := false
	if err != nil {
		if res == nil || !errors.Is(err, sqldump.ErrRead) {
			fmt.Fprintf(stderr, "prodmask: %s\n", report.Clean(err.Error()))
			var de *scan.DatabaseError
			if errors.As(err, &de) {
				return ExitUsage
			}
			return ExitError
		}
		cut = true
	}
	res.Edition = env.App.Edition

	render := func(w io.Writer, color bool) error {
		switch d.format {
		case "json":
			return report.JSON(w, res)
		case "markdown", "md":
			return report.Markdown(w, res)
		}
		return report.Text(w, res, report.TextOptions{Color: color, Verbose: d.verbose, Width: textWidth(env, d.out)})
	}
	if d.out != "" {
		err = writeFile(d.out, func(w io.Writer) error { return render(w, false) })
	} else {
		color := !d.noColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" &&
			isTerminal(os.Stdout) && enableANSI(os.Stdout)
		err = render(stdout, color)
	}
	if err != nil {
		fmt.Fprintln(stderr, "prodmask: can't write the report")
		return ExitError
	}
	if d.out != "" {
		fmt.Fprintln(stderr, "Report written.")
	}

	if cut {
		fmt.Fprintln(stderr, "prodmask: the dump could not be read to its end, so the report covers only what was read, by names alone. The check fails.")
		return ExitError
	}
	if d.threshold != model.SeverityNone && res.Summary.Highest >= d.threshold {
		fmt.Fprintf(stderr, "prodmask: found %s-severity items (--fail-on %s)\n", res.Summary.Highest, d.threshold)
		return ExitFindings
	}
	if n := unreadCounted(res.Dump, res.Database); d.threshold != model.SeverityNone && n > 0 {
		what := report.Count(int64(n)) + " statements of the dump weren't"
		if n == 1 {
			what = "1 statement of the dump wasn't"
		}
		fmt.Fprintf(stderr, "prodmask: %s read, so the check at --fail-on %s is incomplete and the gate fails: see the report.\n", what, d.failOn)
		return ExitError
	}
	return ExitOK
}

// unreadCounted is how many unread statements count against the gate: those
// of the database checked, and those whose database can't be told. The report
// lists the first 100; the rest are counted as if they were of the database.
func unreadCounted(d *model.DumpInfo, database string) int {
	n := d.Unread - len(d.UnreadList)
	for _, u := range d.UnreadList {
		if u.Database == "" || u.Database == database {
			n++
		}
	}
	return max(n, 0)
}
