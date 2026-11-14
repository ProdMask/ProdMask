// Package report renders scan results as text for terminals, Markdown for
// tickets and pull requests, and JSON for tools. Reports only ever contain
// names, counts and categories: never sampled values.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
)

// Headline is the question every report answers first.
const Headline = "What a plain copy of this database would carry into staging"

// proLine ends the free build's text and Markdown reports: one line about
// the paid product, with a plain link and no tracking. A build with an
// edition prints none.
const proLine = "prodmask Pro makes copies of this database with the real shape and fake customers: https://prodmask.com"

// toolName is how a report names the build that wrote it: "prodmask 1.2.3",
// or with an edition "prodmask Pro 1.2.3", whose version drops its semver
// build metadata (a Pro build's "+pro") for display only: the JSON report
// and the starter config keep it.
func toolName(edition, version string) string {
	if edition == "" {
		return "prodmask " + version
	}
	shown, _, _ := strings.Cut(version, "+")
	return "prodmask " + edition + " " + shown
}

// JSON writes the full result as indented JSON, with each polymorphic type
// value as detect.ShowType shows it.
func JSON(w io.Writer, res *model.Result) error {
	shown := *res
	if res.Relationships != nil {
		shown.Relationships = make([]model.Relationship, len(res.Relationships))
		for i, r := range res.Relationships {
			r.TypeValue = detect.ShowType(r.TypeValue)
			shown.Relationships[i] = r
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(&shown)
}

// severityGroup is one line of the summary: how many findings of a
// severity, and in which categories.
type severityGroup struct {
	Severity   model.Severity
	Count      int
	Categories []string // "email address (5)"
}

func groupBySeverity(fs []model.Finding) []severityGroup {
	counts := map[model.Severity]map[model.Category]int{}
	for _, f := range fs {
		if f.Confidence == model.ConfidenceLow {
			continue
		}
		if counts[f.Severity] == nil {
			counts[f.Severity] = map[model.Category]int{}
		}
		counts[f.Severity][f.Category]++
	}
	var out []severityGroup
	for sev := model.SeverityCritical; sev >= model.SeverityLow; sev-- {
		cats := counts[sev]
		if len(cats) == 0 {
			continue
		}
		g := severityGroup{Severity: sev}
		type kv struct {
			c model.Category
			n int
		}
		var list []kv
		for c, n := range cats {
			list = append(list, kv{c, n})
			g.Count += n
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].n != list[j].n {
				return list[i].n > list[j].n
			}
			return list[i].c < list[j].c
		})
		for _, x := range list {
			g.Categories = append(g.Categories, fmt.Sprintf("%s (%d)", x.c.Label(), x.n))
		}
		out = append(out, g)
	}
	return out
}

// tableFindings groups the confident findings by table, in the order of the
// worst finding of each table.
func tableFindings(res *model.Result, includeLow bool) ([]string, map[string][]model.Finding) {
	by := map[string][]model.Finding{}
	var order []string
	for _, f := range res.Findings {
		if f.Confidence == model.ConfidenceLow && !includeLow {
			continue
		}
		if _, ok := by[f.Table]; !ok {
			order = append(order, f.Table)
		}
		by[f.Table] = append(by[f.Table], f)
	}
	worst := func(t string) model.Severity {
		w := model.SeverityNone
		for _, f := range by[t] {
			if f.Severity > w {
				w = f.Severity
			}
		}
		return w
	}
	sort.SliceStable(order, func(i, j int) bool {
		wi, wj := worst(order[i]), worst(order[j])
		if wi != wj {
			return wi > wj
		}
		return order[i] < order[j]
	})
	return order, by
}

func lowCount(res *model.Result) int {
	n := 0
	for _, f := range res.Findings {
		if f.Confidence == model.ConfidenceLow {
			n++
		}
	}
	return n
}

// fieldName is how a finding is named inside its table.
func fieldName(f model.Finding) string {
	s := f.Column
	if f.MetaKey != "" {
		s += "[" + f.MetaKey + "]"
	}
	if f.Path != "" {
		s += " → " + f.Path
	}
	if f.Where != "" {
		s += " where " + f.Where
	}
	return s
}

func evidence(f model.Finding) string {
	var parts []string
	if f.Keys > 0 {
		parts = append(parts, f.KeyCount())
	}
	parts = append(parts, f.Reasons...)
	if f.Note != "" {
		parts = append(parts, f.Note)
	}
	return strings.Join(parts, "; ")
}

func relStats(rels []model.Relationship) (declared, confirmed, likely, weak, unverified int) {
	for _, r := range rels {
		switch r.Status {
		case model.RelDeclared:
			declared++
		case model.RelConfirmed:
			confirmed++
		case model.RelLikely:
			likely++
		case model.RelWeak:
			weak++
		default:
			unverified++
		}
	}
	return
}

// namesOnly is how a report says what a scan with --no-samples read: no
// sampled rows, but the platform checks still read settings rows, unless no
// platform was checked.
func namesOnly(res *model.Result) string {
	if len(res.Platforms) > 0 {
		return "names only, no rows sampled; the platform checks read settings rows"
	}
	return "names only, nothing read but the schema"
}

func relString(r model.Relationship) string {
	s := fmt.Sprintf("%s.%s → %s.%s", r.ChildTable, strings.Join(r.ChildColumns, ","), r.ParentTable, strings.Join(r.ParentColumns, ","))
	if r.TypeValue != "" {
		s += fmt.Sprintf(" (where %s = %s)", r.TypeColumn, detect.ShowType(r.TypeValue))
	}
	return s
}

func relEvidence(r model.Relationship) string {
	var parts []string
	parts = append(parts, r.Source)
	if r.Checked > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d sampled values found", r.Found, r.Checked))
	}
	if r.Note != "" {
		parts = append(parts, r.Note)
	}
	return strings.Join(parts, "; ")
}

func platformLine(p model.Platform) string {
	s := p.Label
	if p.Version != "" {
		s += " " + p.Version
	}
	var details []string
	if p.Prefix != "" {
		details = append(details, "prefix "+p.Prefix)
	}
	details = append(details, p.Details...)
	if len(details) > 0 {
		s += " (" + strings.Join(details, ", ") + ")"
	}
	return s
}

func serverLine(res *model.Result) string {
	flavor := "MySQL"
	if res.Server.Flavor == "mariadb" {
		flavor = "MariaDB"
	}
	v := res.Server.Version
	if i := strings.Index(v, "-MariaDB"); i > 0 {
		v = v[:i]
	}
	return fmt.Sprintf("%s %s at %s", flavor, v, res.Server.Address)
}

// thousands formats 12345 as 12,345.
func thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func seconds(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%d ms", ms)
	}
	return fmt.Sprintf("%.1f s", float64(ms)/1000)
}

func truncateTables(res *model.Result) []model.TableSummary {
	var out []model.TableSummary
	for _, t := range res.Tables {
		if t.Action != "" {
			out = append(out, t)
		}
	}
	return out
}

// cacheTables lists the tables with a possible action: guesses, such as
// emptying a table that looks like a cache, for the user to confirm.
func cacheTables(res *model.Result) []model.TableSummary {
	var out []model.TableSummary
	for _, t := range res.Tables {
		if t.PossibleAction != "" {
			out = append(out, t)
		}
	}
	return out
}
