package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// TextOptions control the terminal report.
type TextOptions struct {
	Color         bool // use ANSI colours
	Verbose       bool // also list low-confidence matches and relationships, and in full the evidence, kinds of data and side-effect sentences
	ConfigWritten bool // a starter config was written. Its path isn't printed: it may be a secret typed in the wrong place
	// Width is the width to lay the report out at. The report clamps it to
	// 60..100 columns; 0 or less means 100.
	Width int
}

type style struct{ on bool }

// styled is text the report has put in its own colour codes, which the
// report's writer leaves as it is. It cleans every other string it's given.
type styled string

func (s style) wrap(code, text string) styled {
	text = Clean(text)
	if !s.on {
		return styled(text)
	}
	return styled("\x1b[" + code + "m" + text + "\x1b[0m")
}

func (s style) bold(t string) styled { return s.wrap("1", t) }
func (s style) dim(t string) styled  { return s.wrap("2", t) }

func (s style) severity(sev model.Severity, text string) styled {
	if code := sevCode(sev); code != "" {
		return s.wrap(code, text)
	}
	return styled(Clean(text))
}

// sevCode is the colour a severity is printed in, or "" for none.
func sevCode(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical:
		return "1;91"
	case model.SeverityHigh:
		return "31"
	case model.SeverityMedium:
		return "33"
	case model.SeverityLow:
		return "36"
	}
	return ""
}

// line renders parts on one line without breaking it: each part cleaned,
// and printed in its code.
func (s style) line(parts ...part) styled {
	var b strings.Builder
	for _, p := range parts {
		if p.code == "" {
			b.WriteString(Clean(p.text))
		} else {
			b.WriteString(string(s.wrap(p.code, p.text)))
		}
	}
	return styled(b.String())
}

// Clean replaces each character in s that can steer a terminal, and each byte
// that isn't UTF-8, with ?. Table, column and key names come from the
// database, and one written to a terminal as stored could move the cursor,
// hide a line or reorder one. The reports clean what they write, and a
// command that writes a name to the terminal itself cleans it with this.
func Clean(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, steers) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || steers(r) {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// steers reports a control character, a format character such as a bidi
// override, or a line or paragraph separator.
func steers(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// printer returns the terminal reports' writer, which cleans every string
// argument, since those hold names from the database. The format is the
// report's own, and so is styled text, which isn't a string.
func printer(b *bufio.Writer) func(format string, a ...any) {
	return func(format string, a ...any) {
		for i, x := range a {
			if s, ok := x.(string); ok {
				a[i] = Clean(s)
			}
		}
		fmt.Fprintf(b, format, a...)
	}
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
// key stands for the value column, while a finding about the key names
// themselves keeps its column.
func shortField(f model.Finding) string {
	s := f.Column
	switch {
	case f.KeyName:
		s += "[" + f.MetaKey + "]"
	case f.MetaKey != "":
		s = "[" + f.MetaKey + "]"
	}
	if f.Path != "" {
		s += " → " + f.Path
	}
	if f.Where != "" {
		s += " where " + f.Where
	}
	return s
}

// countOf renders "1 finding" or "157 findings".
func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// sideEffectLabel is what a side effect's row leads with: its label, or,
// for one with none, such as one from a check written later, its kind.
func sideEffectLabel(se model.SideEffect) string {
	if se.Label != "" {
		return se.Label
	}
	return strings.ReplaceAll(se.Kind, "_", " ")
}

// sideEffectText is what a side effect's row says: its lead, the start of
// its summary; with --verbose, or when the lead is missing or doesn't begin
// the summary, the whole summary, so nothing is ever dropped.
func sideEffectText(se model.SideEffect, verbose bool) string {
	if verbose || se.Lead == "" || !strings.HasPrefix(se.Summary, se.Lead) {
		return se.Summary
	}
	return se.Lead
}

// textReport lays a result out at one width.
type textReport struct {
	b    *bufio.Writer
	st   style
	w    int
	opts TextOptions
	res  *model.Result
}

func (r *textReport) out(lines ...styled) {
	for _, l := range lines {
		r.b.WriteString(string(l))
		r.b.WriteByte('\n')
	}
}

func (r *textReport) blank() { r.b.WriteByte('\n') }

// heading prints a section's heading in bold with its total after it.
func (r *textReport) heading(title, total string) {
	r.out(r.st.fill(r.w, 0, 2, part{title, "1"}, part{" · " + total, "2"})...)
}

// beside prints text after before, which takes the first line's first
// columns, and wraps it onto lines that start at column indent.
func (r *textReport) beside(before styled, first, indent int, text ...part) {
	ls := r.st.fill(r.w, first, indent, text...)
	ls[0] = before + ls[0]
	r.out(ls...)
}

// under prints text on lines of its own, all starting at column col.
func (r *textReport) under(col int, text ...part) {
	r.beside(styled(strings.Repeat(" ", col)), col, col, text...)
}

// labelled prints a row of a list: lead, leadWidth columns wide, then a
// name padded to nameWidth, then text beside it, wrapped under its own first
// character. When that would leave the text under stackBelow columns, the
// name ends the first line and the text goes under it, indented 4. It
// returns the column the text starts at, for lines that go under it.
func (r *textReport) labelled(lead styled, leadWidth int, name string, nameWidth int, text ...part) int {
	col := leadWidth + nameWidth + 2
	if r.w-col >= stackBelow {
		r.beside(lead+styled(pad(Clean(name), nameWidth))+"  ", col, col, text...)
		return col
	}
	r.beside(lead, leadWidth, leadWidth+2, plain(name))
	r.under(4, text...)
	return 4
}

// Text writes the terminal report: the details first, the summaries last,
// so they're on screen when the command ends.
func Text(w io.Writer, res *model.Result, opts TextOptions) error {
	r := &textReport{b: bufio.NewWriter(w), st: style{opts.Color}, w: layoutWidth(opts.Width), opts: opts, res: res}
	r.header()
	r.findings()
	r.tableLists()
	r.relationships()
	r.fixes()
	r.warnings()
	r.summary()
	r.sideEffects()
	r.closing()
	return r.b.Flush()
}

func (r *textReport) header() {
	res := r.res
	title := "prodmask scan"
	if res.Edition != "" {
		title = toolName(res.Edition, res.Version) + " scan"
	}
	source := "· " + res.Database + " · " + serverLine(res)
	if res.Dump != nil {
		source = "· " + res.Database + " · " + dumpSource(res)
		if res.Database == "" {
			source = "· " + dumpSource(res) // a dump that names no database
		}
	}
	r.out(r.st.fill(r.w, 0, 2, part{title, "1"}, plain(" "), part{source, "2"})...)
	if len(res.Platforms) > 0 {
		var ps []string
		for _, p := range res.Platforms {
			ps = append(ps, platformLine(p))
		}
		r.out(r.st.fill(r.w, 0, 2, plain("Platforms: "+strings.Join(ps, " · ")))...)
	}
	if res.Dump != nil {
		// A dump's header ends with what was read, in place of the scanned line.
		r.out(r.st.fill(r.w, 0, 2, plain(dumpRead(res)))...)
		r.blank()
		return
	}
	s := res.Summary
	scanned := fmt.Sprintf("Scanned %d tables", s.Tables-s.Views)
	if s.Views > 0 {
		scanned += fmt.Sprintf(" (%d views skipped)", s.Views)
	}
	if res.Options.Samples {
		scanned += fmt.Sprintf(" · %s rows sampled", thousands(s.RowsSampled))
	} else {
		scanned += " · " + namesOnly(res)
	}
	r.out(r.st.fill(r.w, 0, 2, plain(scanned+" · "+seconds(s.DurationMillis)))...)
	r.blank()
}

// findingRows lays out one table's findings: inline when severity, field,
// category and confidence fit the width, and always with --verbose; else
// stacked on two lines. It reports whether any row left its evidence out.
func (r *textReport) findingRows(fs []model.Finding) (rows []styled, lost bool) {
	fieldW, catW, confW := 0, 0, 0
	for _, f := range fs {
		fieldW = max(fieldW, utf8.RuneCountInString(Clean(shortField(f))))
		catW = max(catW, utf8.RuneCountInString(f.Category.Label()))
		confW = max(confW, utf8.RuneCountInString(f.Confidence.String()))
	}
	fieldW = min(fieldW, 48)
	inline := 4 + 8 + 2 + fieldW + 2 + catW + 2 + confW
	for _, f := range fs {
		sev := part{sevLabel(f.Severity), sevCode(f.Severity)}
		field := Clean(shortField(f))
		ev := Clean(evidence(f))
		if r.opts.Verbose || inline <= r.w {
			parts := []part{plain("    "), sev, plain("  " + pad(cut(field, 48), fieldW) + "  " + pad(f.Category.Label(), catW) + "  ")}
			switch room := r.w - inline - 2; {
			case ev == "":
				parts = append(parts, plain(f.Confidence.String()))
			case r.opts.Verbose:
				// A named exception: the whole evidence, on one line, to copy and search.
				parts = append(parts, plain(pad(f.Confidence.String(), confW)+"  "), part{ev, "2"})
			case room >= evidenceMin:
				parts = append(parts, plain(pad(f.Confidence.String(), confW)+"  "), part{cut(ev, room), "2"})
			default:
				parts = append(parts, plain(f.Confidence.String()))
				lost = true
			}
			rows = append(rows, r.st.line(parts...))
			continue
		}
		rows = append(rows, r.st.line(plain("    "), sev, plain("  "+cut(field, min(48, r.w-14)))))
		second := []part{plain(strings.Repeat(" ", 14) + f.Category.Label() + " · " + f.Confidence.String())}
		if ev != "" {
			if room := r.w - 14 - utf8.RuneCountInString(f.Category.Label()+" · "+f.Confidence.String()) - 3; room >= evidenceMin {
				second = append(second, plain(" · "), part{cut(ev, room), "2"})
			} else {
				lost = true
			}
		}
		rows = append(rows, r.st.line(second...))
	}
	return rows, lost
}

func (r *textReport) findings() {
	order, by := tableFindings(r.res, r.opts.Verbose)
	if len(order) == 0 {
		return
	}
	summaries := map[string]model.TableSummary{}
	for _, t := range r.res.Tables {
		summaries[t.Name] = t
	}
	var body []styled
	lost, total := false, 0
	for _, table := range order {
		ts := summaries[table]
		info := fmt.Sprintf("~%s rows", thousands(ts.RowsEstimate))
		if ts.Kind == "key/value" {
			if ts.Keys > 0 {
				info = thousands(int64(ts.Keys)) + " keys · " + info
			}
			info = fmt.Sprintf("key/value: %s → %s · %s", ts.KeyColumn, ts.ValueColumn, info)
		}
		ls := r.st.fill(r.w, 2, 4, part{table, "1"}, plain(" "), part{"· " + info, "2"})
		ls[0] = "  " + ls[0]
		body = append(body, ls...)
		rows, l := r.findingRows(by[table])
		body = append(body, rows...)
		lost = lost || l
		total += len(by[table])
	}
	r.heading("Findings by table", countOf(total, "finding", "findings")+" in "+countOf(len(order), "table", "tables"))
	if lost {
		r.out(r.st.fill(r.w, 0, 2, part{"Evidence that didn't fit is left out; add --verbose.", "2"})...)
	}
	r.out(body...)
	r.blank()
}

func (r *textReport) tableLists() {
	lists := []struct {
		title  string
		tables []model.TableSummary
		reason func(model.TableSummary) string
	}{
		{"Tables to empty in the copy", truncateTables(r.res), func(t model.TableSummary) string { return t.ActionReason }},
		{"Tables that look like caches (the starter config suggests emptying them, commented out)", cacheTables(r.res),
			func(t model.TableSummary) string { return t.PossibleActionReason }},
	}
	for _, l := range lists {
		if len(l.tables) == 0 {
			continue
		}
		r.heading(l.title, countOf(len(l.tables), "table", "tables"))
		width := 0
		for _, t := range l.tables {
			width = max(width, utf8.RuneCountInString(Clean(t.Name)))
		}
		for _, t := range l.tables {
			r.labelled("  ", 2, t.Name, width, part{l.reason(t), "2"})
		}
		r.blank()
	}
}

func (r *textReport) relationships() {
	declared, confirmed, likely, weak, unverified := relStats(r.res.Relationships)
	inferred := confirmed + likely + weak + unverified
	text := fmt.Sprintf(" %d declared, %d inferred", declared, inferred)
	if inferred > 0 {
		text += fmt.Sprintf(" (%d confirmed, %d likely, %d weak, %d not checked)", confirmed, likely, weak, unverified)
	}
	r.out(r.st.fill(r.w, 0, 2, part{"Relationships:", "1"}, plain(text))...)
	if r.opts.Verbose {
		for _, rel := range r.res.Relationships {
			if rel.Status == model.RelDeclared {
				continue
			}
			// A named exception: one line each, to copy and search.
			r.out(r.st.line(plain(fmt.Sprintf("  %-10s %s  ", rel.Status, Clean(relString(rel)))), part{relEvidence(rel), "2"}))
		}
	}
	if n := lowCount(r.res); n > 0 && !r.opts.Verbose {
		r.out(r.st.fill(r.w, 0, 2, part{fmt.Sprintf("%d low-confidence matches are not shown; add --verbose or see --format json.", n), "2"})...)
	}
	r.blank()
}

// sideEffectLabelWidth is the width of the side effects' label column.
func (r *textReport) sideEffectLabelWidth() int {
	width := 0
	for _, se := range r.res.SideEffects {
		width = max(width, utf8.RuneCountInString(Clean(sideEffectLabel(se))))
	}
	return width
}

// fixes prints how to stop each side effect: its label, the fix, and where.
// A dump's report has none: its side effects weren't checked.
func (r *textReport) fixes() {
	if len(r.res.SideEffects) == 0 || r.res.Dump != nil {
		return
	}
	r.heading("How to stop each one", fmt.Sprint(len(r.res.SideEffects)))
	width := r.sideEffectLabelWidth()
	for _, se := range r.res.SideEffects {
		where := se.Table
		if se.Item != "" {
			where += " · " + se.Item
		}
		col := r.labelled("  ", 2, sideEffectLabel(se), width, plain(se.Fix))
		r.under(col, part{where, "2"})
	}
	r.blank()
}

// warnings prints the warnings; a dump's add its unread statements, the
// first 100 and a count of the rest, and its total counts every one.
func (r *textReport) warnings() {
	warnings, total := r.res.Warnings, len(r.res.Warnings)
	if r.res.Dump != nil {
		warnings = append(warnings[:len(warnings):len(warnings)], dumpUnread(r.res)...)
		total += r.res.Dump.Unread
	}
	if len(warnings) == 0 {
		return
	}
	r.heading("Warnings", fmt.Sprint(total))
	for _, wn := range warnings {
		r.beside("  ! ", 4, 4, plain(wn))
	}
	r.blank()
}

// summary prints the headline with each severity's count and kinds of data.
func (r *textReport) summary() {
	groups := groupBySeverity(r.res.Findings)
	total := 0
	for _, g := range groups {
		total += g.Count
	}
	r.heading(Headline, countOf(total, "finding", "findings"))
	if len(groups) == 0 {
		nothing := "Nothing found. Check the warnings above: a scan user that cannot read the tables finds nothing too."
		if r.res.Dump != nil {
			nothing = "Nothing found. Check the warnings above: statements that weren't read can hide findings."
		}
		r.beside("  ", 2, 4, plain(nothing))
	}
	// The counts' column is 4 digits wide, or as wide as the largest count,
	// so the kinds of data line up and every row stays within the width.
	digits := 4
	for _, g := range groups {
		digits = max(digits, len(fmt.Sprint(g.Count)))
	}
	col := 2 + 8 + 1 + digits + 2
	for _, g := range groups {
		lead := r.st.line(plain("  "), part{sevLabel(g.Severity), sevCode(g.Severity)}, plain(fmt.Sprintf(" %*d  ", digits, g.Count)))
		if r.opts.Verbose {
			r.beside(lead, col, col, plain(strings.Join(g.Categories, " · ")))
			continue
		}
		r.out(lead + styled(Clean(fitKinds(g.Categories, r.w-col))))
	}
	r.blank()
}

// fitKinds joins kinds of data with " · ", as many as fit in room with
// "N more" after them, and at least one, cut with … if even one doesn't.
func fitKinds(kinds []string, room int) string {
	for n := len(kinds); n >= 1; n-- {
		s := strings.Join(kinds[:n], " · ")
		if n < len(kinds) {
			s += fmt.Sprintf(" · %d more", len(kinds)-n)
		}
		if utf8.RuneCountInString(s) <= room {
			return s
		}
	}
	more := ""
	if len(kinds) > 1 {
		more = fmt.Sprintf(" · %d more", len(kinds)-1)
	}
	return cut(kinds[0], room-utf8.RuneCountInString(more)) + more
}

// sideEffects prints what staging could do: each side effect's severity,
// label and lead. A dump's section has no total, and says the checks didn't
// run.
func (r *textReport) sideEffects() {
	if r.res.Dump != nil {
		r.out(r.st.fill(r.w, 0, 2, part{"What staging could do to real people", "1"})...)
		r.beside("  ", 2, 4, plain(dumpSideEffects))
		r.blank()
		return
	}
	if len(r.res.SideEffects) == 0 {
		return
	}
	r.heading("What staging could do to real people", fmt.Sprint(len(r.res.SideEffects)))
	width := r.sideEffectLabelWidth()
	for _, se := range r.res.SideEffects {
		sev := r.st.line(plain("  "), part{sevLabel(se.Severity), sevCode(se.Severity)}, plain("  "))
		r.labelled(sev, 2+8+2, sideEffectLabel(se), width, plain(sideEffectText(se, r.opts.Verbose)))
	}
	r.blank()
}

// closing prints the lines that end the report. A dump's are its own: what
// wasn't judged, which rows were, what a finding is, and its Pro line; no
// starter config is written from a dump.
func (r *textReport) closing() {
	if r.res.Dump != nil {
		for _, l := range dumpClosing(r.res) {
			r.out(r.st.fill(r.w, 0, 2, part{l, "2"})...)
		}
		if p := dumpPro(r.res); p != "" {
			r.out(r.st.fill(r.w, 0, 2, part{p, "2"})...)
		}
		return
	}
	if r.opts.ConfigWritten {
		r.out(r.st.fill(r.w, 0, 2, plain("Starter masking config written to the file given to --config-out. Review it before use."))...)
	} else {
		r.out(r.st.fill(r.w, 0, 2, part{"Add --config-out prodmask.yml to write a starter masking config from these findings.", "2"})...)
	}
	if r.res.Edition == "" {
		r.out(r.st.fill(r.w, 0, 2, part{proLine, "2"})...)
	}
}
