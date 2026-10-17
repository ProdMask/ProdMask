package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

func code(s string) string {
	if s == "" {
		return ""
	}
	return "`" + strings.ReplaceAll(s, "`", "'") + "`"
}

func title(sev model.Severity) string {
	s := sev.String()
	return strings.ToUpper(s[:1]) + s[1:]
}

// Markdown writes the report as Markdown, for tickets, pull requests and
// audit folders.
func Markdown(w io.Writer, res *model.Result) error {
	b := bufio.NewWriter(w)
	pf := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	s := res.Summary

	pf("# prodmask scan: %s\n\n", code(res.Database))
	pf("- **Server:** %s, user %s\n", serverLine(res), code(res.Server.User))
	if len(res.Platforms) > 0 {
		var ps []string
		for _, p := range res.Platforms {
			ps = append(ps, platformLine(p))
		}
		pf("- **Platforms:** %s\n", strings.Join(ps, "; "))
	}
	sampling := "names only, no rows read"
	if res.Options.Samples {
		sampling = fmt.Sprintf("%s rows sampled (up to %d per table, %d per key/value table)",
			thousands(s.RowsSampled), res.Options.SampleRows, res.Options.MetaSampleRows)
	}
	pf("- **Scanned:** %d tables, %s, on %s, in %s\n", s.Tables-s.Views, sampling,
		res.GeneratedAt.Format("2006-01-02 15:04 MST"), seconds(s.DurationMillis))
	pf("- **Tool:** prodmask %s. The report lists names, counts and categories only; it contains no sampled values.\n\n", res.Version)

	pf("## %s\n\n", Headline)
	groups := groupBySeverity(res.Findings)
	if len(groups) == 0 {
		pf("Nothing found.\n\n")
	} else {
		pf("| Severity | Findings | Kinds of data |\n|---|---:|---|\n")
		for _, g := range groups {
			pf("| %s | %d | %s |\n", title(g.Severity), g.Count, cell(strings.Join(g.Categories, ", ")))
		}
		pf("\n")
	}

	if len(res.SideEffects) > 0 {
		pf("## What staging could do to real people\n\n")
		pf("| Severity | What | Where | Fix in the copy |\n|---|---|---|---|\n")
		for _, se := range res.SideEffects {
			where := code(se.Table)
			if se.Item != "" {
				where += " " + code(se.Item)
			}
			pf("| %s | %s | %s | %s |\n", title(se.Severity), cell(se.Summary), where, cell(se.Fix))
		}
		pf("\n")
	}

	order, by := tableFindings(res, false)
	if len(order) > 0 {
		pf("## Findings\n\n")
		pf("| Severity | Where | Data | Confidence | Evidence | Suggested mask |\n|---|---|---|---|---|---|\n")
		for _, table := range order {
			for _, f := range by[table] {
				pf("| %s | %s | %s | %s | %s | %s |\n", title(f.Severity), code(f.Table+"."+fieldName(f)),
					cell(f.Category.Label()), f.Confidence, cell(evidence(f)), code(f.Mask))
			}
		}
		pf("\n")
		if n := lowCount(res); n > 0 {
			pf("%d low-confidence matches are left out here; the JSON report lists them.\n\n", n)
		}
	}

	if tt := truncateTables(res); len(tt) > 0 {
		pf("## Tables to empty in the copy\n\n| Table | Why |\n|---|---|\n")
		for _, t := range tt {
			pf("| %s | %s |\n", code(t.Name), cell(t.ActionReason))
		}
		pf("\n")
	}

	declared, confirmed, likely, weak, unverified := relStats(res.Relationships)
	pf("## Relationships\n\n")
	pf("%d declared foreign keys; %d inferred: %d confirmed, %d likely, %d weak, %d not checked.\n\n",
		declared, confirmed+likely+weak+unverified, confirmed, likely, weak, unverified)
	if confirmed+likely+weak+unverified > 0 {
		pf("| Status | Link | Evidence |\n|---|---|---|\n")
		for _, r := range res.Relationships {
			if r.Status != model.RelDeclared {
				pf("| %s | %s | %s |\n", r.Status, code(relString(r)), cell(relEvidence(r)))
			}
		}
		pf("\n")
	}

	if len(res.Warnings) > 0 {
		pf("## Warnings\n\n")
		for _, wn := range res.Warnings {
			pf("- %s\n", wn)
		}
		pf("\n")
	}
	pf("---\n\n%s\n", proLine)
	return b.Flush()
}
