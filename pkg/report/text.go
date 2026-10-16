package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// TextOptions control the terminal report.
type TextOptions struct {
	Color      bool   // use ANSI colours
	Verbose    bool   // also list low-confidence matches, relationships and full evidence
	ConfigPath string // where a starter config was written, if anywhere
}

type style struct{ on bool }

func (s style) wrap(code, text string) string {
	if !s.on {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s style) bold(t string) string { return s.wrap("1", t) }
func (s style) dim(t string) string  { return s.wrap("2", t) }

func (s style) severity(sev model.Severity, text string) string {
	switch sev {
	case model.SeverityCritical:
		return s.wrap("1;91", text)
	case model.SeverityHigh:
		return s.wrap("31", text)
	case model.SeverityMedium:
		return s.wrap("33", text)
	case model.SeverityLow:
		return s.wrap("36", text)
	}
	return text
}

func sevLabel(sev model.Severity) string { return fmt.Sprintf("%-8s", strings.ToUpper(sev.String())) }

func pad(s string, n int) string {
	if l := utf8.RuneCountInString(s); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// shortField names a finding inside its table; for key/value tables the
// key stands for the value column.
func shortField(f model.Finding) string {
	s := f.Column
	if f.MetaKey != "" {
		s = "[" + f.MetaKey + "]"
	}
	if f.Path != "" {
		s += " → " + f.Path
	}
	return s
}

// Text writes the terminal report.
func Text(w io.Writer, res *model.Result, opts TextOptions) error {
	b := bufio.NewWriter(w)
	st := style{opts.Color}
	pf := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }

	pf("%s %s\n", st.bold("prodmask scan"), st.dim("· "+res.Database+" · "+serverLine(res)))
	if len(res.Platforms) > 0 {
		var ps []string
		for _, p := range res.Platforms {
			ps = append(ps, platformLine(p))
		}
		pf("Platforms: %s\n", strings.Join(ps, " · "))
	}
	s := res.Summary
	scanned := fmt.Sprintf("Scanned %d tables", s.Tables-s.Views)
	if s.Views > 0 {
		scanned += fmt.Sprintf(" (%d views skipped)", s.Views)
	}
	if res.Options.Samples {
		scanned += fmt.Sprintf(" · %s rows sampled", thousands(s.RowsSampled))
	} else {
		scanned += " · names only, no rows read"
	}
	pf("%s · %s\n\n", scanned, seconds(s.DurationMillis))

	pf("%s\n", st.bold(Headline))
	groups := groupBySeverity(res.Findings)
	if len(groups) == 0 {
		pf("  Nothing found. Check the warnings below: a scan user that cannot read the tables finds nothing too.\n")
	}
	for _, g := range groups {
		pf("  %s %4d  %s\n", st.severity(g.Severity, sevLabel(g.Severity)), g.Count, strings.Join(g.Categories, ", "))
	}
	pf("\n")

	if len(res.SideEffects) > 0 {
		pf("%s\n", st.bold("What staging could do to real people"))
		for _, se := range res.SideEffects {
			pf("  %s  %s\n", st.severity(se.Severity, sevLabel(se.Severity)), se.Summary)
			where := se.Table
			if se.Item != "" {
				where += " · " + se.Item
			}
			pf("            %s\n", st.dim(where+" · fix: "+se.Fix))
		}
		pf("\n")
	}

	order, by := tableFindings(res, opts.Verbose)
	if len(order) > 0 {
		pf("%s\n", st.bold("Findings by table"))
		summaries := map[string]model.TableSummary{}
		for _, t := range res.Tables {
			summaries[t.Name] = t
		}
		for _, table := range order {
			ts := summaries[table]
			info := fmt.Sprintf("~%s rows", thousands(ts.RowsEstimate))
			if ts.Kind == "key/value" {
				info = fmt.Sprintf("key/value: %s → %s · %s", ts.KeyColumn, ts.ValueColumn, info)
			}
			pf("  %s %s\n", st.bold(table), st.dim("· "+info))
			fs := by[table]
			width := 0
			for _, f := range fs {
				if l := utf8.RuneCountInString(shortField(f)); l > width {
					width = l
				}
			}
			width = min(width, 48)
			for _, f := range fs {
				conf := f.Confidence.String()
				line := fmt.Sprintf("    %s  %s  %s  %s",
					st.severity(f.Severity, sevLabel(f.Severity)),
					pad(cut(shortField(f), 48), width),
					pad(cut(f.Category.Label(), 28), 28),
					pad(conf, 6))
				ev := evidence(f)
				if !opts.Verbose {
					ev = cut(ev, 70)
				}
				pf("%s  %s\n", line, st.dim(ev))
			}
		}
		pf("\n")
	}

	if tt := truncateTables(res); len(tt) > 0 {
		pf("%s\n", st.bold("Tables to empty in the copy"))
		width := 0
		for _, t := range tt {
			width = max(width, utf8.RuneCountInString(t.Name))
		}
		for _, t := range tt {
			pf("  %s  %s\n", pad(t.Name, width), st.dim(t.ActionReason))
		}
		pf("\n")
	}

	declared, confirmed, likely, weak, unverified := relStats(res.Relationships)
	inferred := confirmed + likely + weak + unverified
	pf("%s %d declared, %d inferred", st.bold("Relationships:"), declared, inferred)
	if inferred > 0 {
		pf(" (%d confirmed, %d likely, %d weak, %d not checked)", confirmed, likely, weak, unverified)
	}
	pf("\n")
	if opts.Verbose {
		for _, r := range res.Relationships {
			if r.Status == model.RelDeclared {
				continue
			}
			pf("  %-10s %s  %s\n", r.Status, relString(r), st.dim(relEvidence(r)))
		}
	}

	if n := lowCount(res); n > 0 && !opts.Verbose {
		pf("%s\n", st.dim(fmt.Sprintf("%d low-confidence matches are not shown; add --verbose or see --format json.", n)))
	}

	if len(res.Warnings) > 0 {
		pf("\n%s\n", st.bold("Warnings"))
		for _, wn := range res.Warnings {
			pf("  ! %s\n", wn)
		}
	}

	pf("\n")
	if opts.ConfigPath != "" {
		pf("Starter masking config written to %s. Review it before use.\n", opts.ConfigPath)
	} else {
		pf("%s\n", st.dim("Add --config-out prodmask.yml to write a starter masking config from these findings."))
	}
	return b.Flush()
}
