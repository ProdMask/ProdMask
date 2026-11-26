package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// labelRules give the fake shop's side effects their labels and leads as
// the checks that find them set them: the fixture is v0.14.0's JSON, which
// has neither. A rule matches a side effect's kind and a word of its
// summary; the lead is the summary up to the marker, where the rest starts,
// or the whole summary when the rule has none. TestLabelRulesMatchTheChecks
// holds them to what the checks set on every fixture pkg/scan scans.
var labelRules = []struct{ kind, contains, label, marker string }{
	{"payments", "subscription renewal", "charge customers", "; staging would"},
	{"payments", "", "take live payments", ""},
	{"email", "Memberships", "email members", "; staging would"},
	{"email", "store staff", "email store staff", "; staging would"},
	{"email", "plugin setting", "email staff", ""},
	{"email", "Contact Form 7", "email form recipients", ""},
	{"email", "order emails are queued", "email customers", ""},
	{"email", "", "send email", ""},
	{"webhooks", "", "post to webhooks", ""},
	{"backups", "", "upload backups", "; staging would"},
	{"connection", "are active", "act as the live site", ""},
	{"connection", "", "act as the live site", "; connected services"},
	{"scheduled_jobs", "scheduled actions", "run scheduled actions", " (most common:"},
	{"scheduled_jobs", "WP-Cron", "run cron events", " (most common:"},
	{"scheduled_jobs", "cron jobs", "run cron jobs", " (most common:"},
	{"queued_jobs", "", "run queued jobs", " (queues:"},
}

// The layout's limits, written here rather than read from the code, so a
// test catches one that moves.
const (
	wantStack    = 30 // a column of text beside a label keeps at least this many columns, or stacks
	wantEvidence = 16 // a finding row shows its evidence only with at least this many columns left
	wantField    = 48 // a finding's field takes at most this many runes of its row
	wantProLine  = "prodmask Pro copies this database with the real shape and fake customers: https://prodmask.com"
)

// labelFor sets a side effect's label and lead by the first of labelRules
// that matches it, and returns that rule's index.
func labelFor(se *model.SideEffect) (int, error) {
	for i, r := range labelRules {
		if se.Kind != r.kind || !strings.Contains(se.Summary, r.contains) {
			continue
		}
		se.Label, se.Lead = r.label, se.Summary
		if r.marker != "" {
			lead, _, ok := strings.Cut(se.Summary, r.marker)
			if !ok {
				return i, fmt.Errorf("%q has no %q", se.Summary, r.marker)
			}
			se.Lead = lead
		}
		return i, nil
	}
	return -1, fmt.Errorf("no rule labels %s: %q", se.Kind, se.Summary)
}

// fakeShop is the fake shop's result with each side effect's label and lead.
func fakeShop(t *testing.T) *model.Result {
	t.Helper()
	res := loadFakeShop(t)
	for i := range res.SideEffects {
		if _, err := labelFor(&res.SideEffects[i]); err != nil {
			t.Fatal(err)
		}
	}
	return res
}

// TestLabelRulesMatchTheChecks reads the side effects pkg/scan's goldens
// hold, which its fixtures' scans write with the labels and leads the
// checks set, and holds labelRules to them: each rule gives a side effect
// the check's own label and lead, and each rule matches one.
func TestLabelRulesMatchTheChecks(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "scan", "testdata", "*.sideeffects"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no side-effect goldens in ../scan/testdata: %v", err)
	}
	used := make([]bool, len(labelRules))
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			if line == "" {
				continue // a fixture without side effects
			}
			// platform, kind, table, item, severity, count, summary, fix, label, lead
			f := strings.Split(line, "\t")
			if len(f) != 10 {
				t.Fatalf("%s: %d fields, want 10: %q", name, len(f), line)
			}
			se := model.SideEffect{Kind: f[1], Summary: f[6]}
			i, err := labelFor(&se)
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			used[i] = true
			if se.Label != f[8] || se.Lead != f[9] {
				t.Errorf("%s: the rules give %q and the lead %q; the check sets %q and %q", name, se.Label, se.Lead, f[8], f[9])
			}
		}
	}
	for i, u := range used {
		if !u {
			t.Errorf("no fixture's side effect uses the rule %+v", labelRules[i])
		}
	}
}

// withExtras adds what the fake shop lacks: a table to empty more, a table
// that looks like a cache with a reason too long for one line, and
// warnings, one too long for one line.
func withExtras(res *model.Result) *model.Result {
	res.Tables = append(res.Tables,
		model.TableSummary{Name: "wp_fixture_rate_limits", Action: "truncate", ActionReason: "rate limits, which the plugin rebuilds"},
		model.TableSummary{Name: "wp_fixture_page_cache", PossibleAction: "truncate", PossibleActionReason: "its name says it's " +
			"a cache, and its rows are whole rendered pages that the plugin writes again on the next visit to each of them"})
	res.Warnings = append(res.Warnings, "skipped wp_big: no index on option_name",
		"could not count the Contact Form 7 forms of wp_posts: the server ended the statement at the time limit, "+
			"so the report may miss forms that send mail to the addresses in their settings")
	return res
}

// testServer is a scanned server for results built in a test.
var testServer = model.ServerInfo{Flavor: "mariadb", Version: "11.8.9-MariaDB", Address: "db.example:3306", User: "scan"}

func textOf(t *testing.T, res *model.Result, opts TextOptions) string {
	t.Helper()
	var b bytes.Buffer
	if err := Text(&b, res, opts); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func reportLines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

func indexOf(lines []string, prefix string) int {
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

// plural renders "1 table" or "3 tables".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// wantLabel is the label a side effect's row should show, worked out here
// rather than by the code under test: its label, or its kind with spaces.
func wantLabel(se model.SideEffect) string {
	if se.Label != "" {
		return se.Label
	}
	return strings.ReplaceAll(se.Kind, "_", " ")
}

// wantText is what a side effect's row should say: its lead, or its whole
// summary with --verbose or when the lead isn't the summary's start.
func wantText(se model.SideEffect, verbose bool) string {
	if verbose || se.Lead == "" || !strings.HasPrefix(se.Summary, se.Lead) {
		return se.Summary
	}
	return se.Lead
}

// labelWidth is the side effects' label column's width.
func labelWidth(res *model.Result) int {
	width := 0
	for _, se := range res.SideEffects {
		width = max(width, runeLen(wantLabel(se)))
	}
	return width
}

// fitted is a severity row's kinds of data as the layout gives them: all of
// them when they fit; else as many as fit, then how many more; else the
// first, cut with …, then how many more.
func fitted(kinds []string, room int) string {
	if all := strings.Join(kinds, " · "); runeLen(all) <= room {
		return all
	}
	for n := len(kinds) - 1; n >= 1; n-- {
		if s := strings.Join(kinds[:n], " · ") + fmt.Sprintf(" · %d more", len(kinds)-n); runeLen(s) <= room {
			return s
		}
	}
	more := ""
	if len(kinds) > 1 {
		more = fmt.Sprintf(" · %d more", len(kinds)-1)
	}
	return string([]rune(kinds[0])[:room-runeLen(more)-1]) + "…" + more
}

// walker reads a plain text report line by line and stops at the first
// line that isn't where the layout puts it.
type walker struct {
	t     *testing.T
	w     int
	lines []string
	i     int
	ok    bool
}

func (k *walker) fail(format string, a ...any) {
	k.t.Helper()
	if k.ok {
		k.t.Errorf("width %d, line %d: "+format, append([]any{k.w, k.i + 1}, a...)...)
	}
	k.ok = false
}

// text reads a wrapped text: the line starts with prefix, the text goes on
// in the lines that start with exactly indent spaces, and it must be want,
// every word whole and the lines joined at single spaces.
func (k *walker) text(prefix string, indent int, want, what string) {
	k.t.Helper()
	if !k.ok {
		return
	}
	if k.i >= len(k.lines) || !strings.HasPrefix(k.lines[k.i], prefix) {
		k.fail("%s: want a line starting %q", what, prefix)
		return
	}
	got := k.lines[k.i][len(prefix):]
	pad := strings.Repeat(" ", indent)
	for k.i++; got != want && strings.HasPrefix(want, got+" ") && k.i < len(k.lines) &&
		strings.HasPrefix(k.lines[k.i], pad) && len(k.lines[k.i]) > indent && k.lines[k.i][indent] != ' '; k.i++ {
		got += " " + k.lines[k.i][indent:]
	}
	if got != want {
		k.fail("%s: got %q, want %q", what, got, want)
	}
}

func (k *walker) blank(after string) {
	k.t.Helper()
	if !k.ok {
		return
	}
	if k.i < len(k.lines) && k.lines[k.i] == "" {
		k.i++
		return
	}
	k.fail("no blank line after %s", after)
}

// cutTo is s cut to n runes, its last one …, when it's longer.
func cutTo(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// padTo is s with spaces after it up to n runes.
func padTo(s string, n int) string { return s + strings.Repeat(" ", max(0, n-runeLen(s))) }

// rows reads a table's finding rows: inline when severity, field, category
// and confidence fit, or with --verbose, the field cut to wantField runes
// and the columns padded; else stacked, the field cut to wantField or the
// width less 14, and the second line at column 14. The evidence is shown
// when, and only when, it has wantEvidence columns. It reports whether a row
// left its evidence out.
func (k *walker) rows(fs []model.Finding, verbose bool) (lost bool) {
	k.t.Helper()
	fieldW, catW, confW := 0, 0, 0
	for _, f := range fs {
		fieldW = max(fieldW, runeLen(Clean(shortField(f))))
		catW = max(catW, runeLen(f.Category.Label()))
		confW = max(confW, runeLen(f.Confidence.String()))
	}
	fieldW = min(fieldW, wantField)
	inline := 4 + 8 + 2 + fieldW + 2 + catW + 2 + confW
	for _, f := range fs {
		if !k.ok {
			return lost
		}
		head := "    " + sevLabel(f.Severity) + "  "
		if k.i >= len(k.lines) || !strings.HasPrefix(k.lines[k.i], head) {
			k.fail("want %s's row, starting %q", f.Column, head)
			return lost
		}
		field := Clean(shortField(f))
		ev := evidence(f) != ""
		if verbose || inline <= k.w {
			cols := head + padTo(cutTo(field, wantField), fieldW) + "  " + padTo(f.Category.Label(), catW) + "  " + f.Confidence.String()
			if !strings.HasPrefix(k.lines[k.i], cols) {
				k.fail("%q isn't %s's row; want it to start %q", k.lines[k.i], f.Column, cols)
				return lost
			}
			shows := ev && (verbose || k.w-inline-2 >= wantEvidence)
			if got := runeLen(k.lines[k.i]) > inline; got != shows {
				k.fail("%q shows its evidence %v; want %v", k.lines[k.i], got, shows)
			}
			lost = lost || ev && !shows
			k.i++
			continue
		}
		if want := head + cutTo(field, min(wantField, k.w-14)); k.lines[k.i] != want {
			k.fail("%q isn't %s's first line; want %q", k.lines[k.i], f.Column, want)
			return lost
		}
		k.i++
		second := strings.Repeat(" ", 14) + f.Category.Label() + " · " + f.Confidence.String()
		if k.i >= len(k.lines) || !strings.HasPrefix(k.lines[k.i], second) {
			k.fail("want %s's second line, starting %q", f.Column, second)
			return lost
		}
		shows := ev && k.w-runeLen(second)-3 >= wantEvidence
		if got := len(k.lines[k.i]) > len(second); got != shows {
			k.fail("%q shows its evidence %v; want %v", k.lines[k.i], got, shows)
		}
		lost = lost || ev && !shows
		k.i++
	}
	return lost
}

// walkReport reads a plain text report from its first line to its last, as
// the layout lays each kind of line out, in the report's order: every
// wrapped text whole with its continuation lines at their column, the
// finding rows and the severity rows as rows and fitted say, and nothing
// after the closing lines.
func walkReport(t *testing.T, w int, text string, res *model.Result, verbose bool) {
	t.Helper()
	k := &walker{t: t, w: w, lines: reportLines(text), ok: true}

	k.text("", 2, "prodmask scan · "+res.Database+" · "+serverLine(res), "the title")
	if len(res.Platforms) > 0 {
		var ps []string
		for _, p := range res.Platforms {
			ps = append(ps, platformLine(p))
		}
		k.text("", 2, "Platforms: "+strings.Join(ps, " · "), "the platforms")
	}
	s := res.Summary
	scanned := fmt.Sprintf("Scanned %d tables", s.Tables-s.Views)
	if s.Views > 0 {
		scanned += fmt.Sprintf(" (%d views skipped)", s.Views)
	}
	if res.Options.Samples {
		scanned += " · " + thousands(s.RowsSampled) + " rows sampled"
	} else {
		scanned += " · " + namesOnly(res)
	}
	k.text("", 2, scanned+" · "+seconds(s.DurationMillis), "the scanned line")
	k.blank("the header")

	if order, by := tableFindings(res, verbose); len(order) > 0 {
		total := 0
		for _, table := range order {
			total += len(by[table])
		}
		k.text("", 2, "Findings by table · "+plural(total, "finding")+" in "+plural(len(order), "table"), "Findings by table")
		note := k.ok && k.i < len(k.lines) && k.lines[k.i] == evidenceNote
		if note {
			k.i++
		}
		tables := map[string]model.TableSummary{}
		for _, ts := range res.Tables {
			tables[ts.Name] = ts
		}
		lost := false
		for _, table := range order {
			ts := tables[table]
			info := "~" + thousands(ts.RowsEstimate) + " rows"
			if ts.Kind == "key/value" {
				if ts.Keys > 0 {
					info = thousands(int64(ts.Keys)) + " keys · " + info
				}
				info = "key/value: " + ts.KeyColumn + " → " + ts.ValueColumn + " · " + info
			}
			k.text("  ", 4, table+" · "+info, "table "+table)
			lost = k.rows(by[table], verbose) || lost
		}
		if k.ok && note != lost {
			k.fail("the note on evidence left out shows %v, but a row left its evidence out %v", note, lost)
		}
		k.blank("Findings by table")
	}

	for _, l := range []struct {
		title  string
		tables []model.TableSummary
		reason func(model.TableSummary) string
	}{
		{"Tables to empty in the copy", truncateTables(res), func(ts model.TableSummary) string { return ts.ActionReason }},
		{"Tables that look like caches (the starter config suggests emptying them, commented out)", cacheTables(res),
			func(ts model.TableSummary) string { return ts.PossibleActionReason }},
	} {
		if len(l.tables) == 0 {
			continue
		}
		k.text("", 2, l.title+" · "+plural(len(l.tables), "table"), l.title)
		width := 0
		for _, ts := range l.tables {
			width = max(width, runeLen(ts.Name))
		}
		col := 2 + width + 2
		for _, ts := range l.tables {
			if w-col >= wantStack {
				k.text("  "+ts.Name+strings.Repeat(" ", width-runeLen(ts.Name))+"  ", col, l.reason(ts), ts.Name+"'s reason")
			} else {
				k.text("  ", 4, ts.Name, ts.Name)
				k.text("    ", 4, l.reason(ts), ts.Name+"'s reason")
			}
		}
		k.blank(l.title)
	}

	declared, confirmed, likely, weak, unverified := relStats(res.Relationships)
	rel := fmt.Sprintf("Relationships: %d declared, %d inferred", declared, confirmed+likely+weak+unverified)
	if confirmed+likely+weak+unverified > 0 {
		rel += fmt.Sprintf(" (%d confirmed, %d likely, %d weak, %d not checked)", confirmed, likely, weak, unverified)
	}
	k.text("", 2, rel, "Relationships")
	if verbose {
		for _, r := range res.Relationships {
			if r.Status == model.RelDeclared || !k.ok {
				continue
			}
			if k.i >= len(k.lines) || !strings.HasPrefix(k.lines[k.i], fmt.Sprintf("  %-10s ", r.Status)) {
				k.fail("want a %s relationship", r.Status)
				break
			}
			k.i++
		}
	} else if n := lowCount(res); n > 0 {
		k.text("", 2, fmt.Sprintf("%d low-confidence matches are not shown; add --verbose or see --format json.", n), "the low-confidence line")
	}
	k.blank("Relationships")

	width := labelWidth(res)
	if len(res.SideEffects) > 0 {
		k.text("", 2, "How to stop each one · "+fmt.Sprint(len(res.SideEffects)), "the fixes' heading")
		col := 2 + width + 2
		for _, se := range res.SideEffects {
			label := wantLabel(se)
			where := se.Table
			if se.Item != "" {
				where += " · " + se.Item
			}
			if w-col >= wantStack {
				k.text("  "+label+strings.Repeat(" ", width-runeLen(label))+"  ", col, se.Fix, label+"'s fix")
				k.text(strings.Repeat(" ", col), col, where, label+"'s place")
			} else {
				k.text("  ", 4, label, label)
				k.text("    ", 4, se.Fix, label+"'s fix")
				k.text("    ", 4, where, label+"'s place")
			}
		}
		k.blank("the fixes")
	}

	if len(res.Warnings) > 0 {
		k.text("", 2, "Warnings · "+fmt.Sprint(len(res.Warnings)), "the warnings' heading")
		for _, wn := range res.Warnings {
			k.text("  ! ", 4, wn, "a warning")
		}
		k.blank("the warnings")
	}

	groups := groupBySeverity(res.Findings)
	total, digits := 0, 4
	for _, g := range groups {
		total += g.Count
		digits = max(digits, len(fmt.Sprint(g.Count)))
	}
	k.text("", 2, Headline+" · "+plural(total, "finding"), "the headline")
	if len(groups) == 0 {
		k.text("  ", 4, "Nothing found. Check the warnings above: a scan user that cannot read the tables finds nothing too.", "nothing found")
	}
	for _, g := range groups {
		prefix := "  " + sevLabel(g.Severity) + fmt.Sprintf(" %*d  ", digits, g.Count)
		kinds := strings.Join(g.Categories, " · ")
		if !verbose {
			kinds = fitted(g.Categories, w-len(prefix))
		}
		k.text(prefix, len(prefix), kinds, g.Severity.String()+"'s row")
	}
	k.blank("the summary")

	if len(res.SideEffects) > 0 {
		k.text("", 2, "What staging could do to real people · "+fmt.Sprint(len(res.SideEffects)), "the side effects' heading")
		col := 2 + 8 + 2 + width + 2
		for _, se := range res.SideEffects {
			label := wantLabel(se)
			sev := "  " + sevLabel(se.Severity) + "  "
			if w-col >= wantStack {
				k.text(sev+label+strings.Repeat(" ", width-runeLen(label))+"  ", col, wantText(se, verbose), label)
			} else {
				k.text(sev, 2+8+2+2, label, label)
				k.text("    ", 4, wantText(se, verbose), label+"'s text")
			}
		}
		k.blank("the side effects")
	}

	k.text("", 2, "Add --config-out prodmask.yml to write a starter masking config from these findings.", "the config line")
	if res.Edition == "" {
		k.text("", 2, wantProLine, "the Pro line")
	}
	if k.ok && k.i != len(k.lines) {
		k.fail("%d lines after the closing lines", len(k.lines)-k.i)
	}
}

// The text report of the fake shop at 60, 80 and 100 columns, plain,
// coloured and with --verbose, so a reviewer sees the layout.
func TestTextGoldens(t *testing.T) {
	res := fakeShop(t)
	for _, w := range []int{60, 80, 100} {
		for _, v := range []struct {
			suffix string
			opts   TextOptions
		}{
			{"", TextOptions{Width: w}},
			{".color", TextOptions{Width: w, Color: true}},
			{".verbose", TextOptions{Width: w, Verbose: true}},
		} {
			compareFile(t, fmt.Sprintf("fakeshop.%d%s.txt", w, v.suffix), textOf(t, res, v.opts))
		}
	}
}

// vocabulary is every word the fake shop's report prints whole: the words
// of its verbose report, which leaves nothing out, and of its default one.
func vocabulary(t *testing.T, res *model.Result) map[string]bool {
	words := map[string]bool{}
	for _, opts := range []TextOptions{{Width: 100, Verbose: true}, {Width: 100}} {
		for _, w := range strings.Fields(textOf(t, res, opts)) {
			words[w] = true
		}
	}
	return words
}

func isNumber(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsDigit(r) && r != ',' }) < 0
}

// TestTextAtEveryWidth checks the fake shop's report, with what it lacks
// added, at every width from 60 to 100: no line wider than the width but a
// line holding one word too long for its room; no line ending with a space;
// no word split or changed, a word cut with … being the start of one the
// report prints whole; colour on and off giving the same text; and every
// line where the layout puts it (walkReport).
func TestTextAtEveryWidth(t *testing.T) {
	res := withExtras(fakeShop(t))
	vocab := vocabulary(t, res)
	for w := 60; w <= 100; w++ {
		text := textOf(t, res, TextOptions{Width: w})
		if coloured := textOf(t, res, TextOptions{Width: w, Color: true}); ownColours.ReplaceAllString(coloured, "") != text {
			t.Errorf("width %d: colour changes the text", w)
		}
		for i, l := range reportLines(text) {
			if n := runeLen(l); n > w && strings.Contains(strings.TrimLeft(l, " "), " ") {
				t.Errorf("width %d: line %d is %d wide: %q", w, i+1, n, l)
			}
			if strings.HasSuffix(l, " ") {
				t.Errorf("width %d: line %d ends with a space: %q", w, i+1, l)
			}
		}
	words:
		for _, word := range strings.Fields(text) {
			if vocab[word] || isNumber(word) {
				continue
			}
			if start, ok := strings.CutSuffix(word, "…"); ok {
				for v := range vocab {
					if strings.HasPrefix(v, start) {
						continue words
					}
				}
			}
			t.Errorf("width %d: %q isn't a word the report prints whole", w, word)
		}
		walkReport(t, w, text, res, false)
	}
}

// Each side effect's row shows its label and its lead; with --verbose, its
// whole summary. No row holds its fix.
func TestSideEffectRows(t *testing.T) {
	res := fakeShop(t)
	for _, w := range []int{60, 80, 100} {
		walkReport(t, w, textOf(t, res, TextOptions{Width: w}), res, false)
		walkReport(t, w, textOf(t, res, TextOptions{Width: w, Verbose: true}), res, true)
	}
	if strings.Contains(textOf(t, res, TextOptions{}), "· fix:") {
		t.Error("a side effect's row still holds its fix")
	}
}

// The fixes section has one block a side effect, in the summary's order:
// its label, its fix, and its place under the fix.
func TestFixesSection(t *testing.T) {
	res := fakeShop(t)
	for _, w := range []int{60, 80, 100} {
		lines := reportLines(textOf(t, res, TextOptions{Width: w}))
		i := indexOf(lines, "How to stop each one · ")
		if i < 0 {
			t.Fatalf("width %d: no fixes section", w)
		}
		width := labelWidth(res)
		k := &walker{t: t, w: w, lines: lines, i: i + 1, ok: true}
		for _, se := range res.SideEffects {
			label := wantLabel(se)
			where := se.Table
			if se.Item != "" {
				where += " · " + se.Item
			}
			k.text("  "+label+strings.Repeat(" ", width-runeLen(label))+"  ", 2+width+2, se.Fix, label+"'s fix")
			k.text(strings.Repeat(" ", 2+width+2), 2+width+2, where, label+"'s place")
		}
	}
}

// A side effect a check sets no label for shows its kind; one whose lead
// doesn't begin its summary shows the whole summary.
func TestSideEffectFallbacks(t *testing.T) {
	res := &model.Result{Database: "shop", Server: testServer, SideEffects: []model.SideEffect{
		{Kind: "scheduled_jobs", Severity: model.SeverityLow, Summary: "3 jobs would run", Lead: "3 jobs", Table: "t", Fix: "stop them"},
		{Kind: "email", Label: "send email", Severity: model.SeverityLow, Summary: "Mail goes out", Lead: "Other words", Table: "t", Fix: "stop it"},
	}}
	out := textOf(t, res, TextOptions{})
	for _, want := range []string{"  LOW       scheduled jobs  3 jobs\n", "  LOW       send email      Mail goes out\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	walkReport(t, 100, out, res, false)
}

// A long label, a long fix and a long table name, at 60 columns: the
// rows stack.
func TestStackingAt60(t *testing.T) {
	res := &model.Result{Database: "shop", Server: testServer,
		SideEffects: []model.SideEffect{{Kind: "a_kind_a_later_check_names_at_length", Severity: model.SeverityHigh, Table: "wp_options",
			Item: "some_option", Summary: "Something staging would do to real people",
			Fix: strings.TrimSpace(strings.Repeat("Turn it off in the copy. ", 5))}},
		Tables: []model.TableSummary{{Name: "wp_a_table_with_a_long_name_a_plugin_made_up_for_itself", Action: "truncate",
			ActionReason: "sessions a copy needn't keep"}}}
	text := textOf(t, res, TextOptions{Width: 60})
	walkReport(t, 60, text, res, false)
	lines := reportLines(text)
	if i := indexOf(lines, "Tables to empty in the copy"); i < 0 || lines[i+1] != "  "+res.Tables[0].Name {
		t.Errorf("the table's name didn't stack:\n%s", text)
	}
	if i := indexOf(lines, "How to stop each one"); i < 0 || lines[i+1] != "  a kind a later check names at length" {
		t.Errorf("the fix's label didn't stack:\n%s", text)
	}
}

// A severity with more findings than 4 digits hold widens the counts'
// column for every row, so the rows stay within the width and line up.
func TestManyFindings(t *testing.T) {
	res := &model.Result{Database: "shop", Server: testServer}
	for i := range 12345 {
		res.Findings = append(res.Findings, model.Finding{Table: "big", Column: fmt.Sprintf("c%05d", i),
			Category: model.Category(fmt.Sprintf("made_up_kind_%02d", i%12)), Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh})
	}
	res.Findings = append(res.Findings, model.Finding{Table: "small", Column: "email", Category: model.CatEmail,
		Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh})
	for w := 60; w <= 100; w++ {
		text := textOf(t, res, TextOptions{Width: w})
		walkReport(t, w, text, res, false)
		for i, l := range reportLines(text) {
			if runeLen(l) > w {
				t.Errorf("width %d: line %d is %d wide: %q", w, i+1, runeLen(l), l)
			}
		}
	}
	for _, w := range []int{60, 100} {
		walkReport(t, w, textOf(t, res, TextOptions{Width: w, Verbose: true}), res, true)
	}
	// "HIGH" and "MEDIUM" pad to 8, then a space and the 5-digit column.
	if out := textOf(t, res, TextOptions{}); !strings.Contains(out, "\n  HIGH         1  email address (1)\n") ||
		!strings.Contains(out, "\n  MEDIUM   12345  made_up_kind_00 (1029) · ") {
		t.Errorf("the counts don't line up in a 5-digit column:\n%s", out[strings.Index(out, Headline):])
	}
}

// At 100 columns the summaries and closing lines fit a 30-row screen with
// the prompt under them.
func TestSummariesFitTheScreen(t *testing.T) {
	lines := reportLines(textOf(t, fakeShop(t), TextOptions{Width: 100}))
	if n := len(lines) - indexOf(lines, Headline); n > 29 {
		t.Errorf("the summaries and closing lines take %d lines at 100 columns; 29 fit a 30-row screen with the prompt", n)
	}
}

func TestTextWidthClamp(t *testing.T) {
	res := fakeShop(t)
	for in, as := range map[int]int{30: 60, 150: 100, 0: 100} {
		if textOf(t, res, TextOptions{Width: in}) != textOf(t, res, TextOptions{Width: as}) {
			t.Errorf("a width of %d isn't laid out as %d", in, as)
		}
	}
}

const evidenceNote = "Evidence that didn't fit is left out; add --verbose."

// The note shows under "Findings by table" when a row left its evidence
// out, and only then.
func TestEvidenceNote(t *testing.T) {
	res := fakeShop(t)
	lines := reportLines(textOf(t, res, TextOptions{Width: 100}))
	if i := indexOf(lines, "Findings by table"); i < 0 || lines[i+1] != evidenceNote {
		t.Errorf("rows lose their evidence at 100, but the note isn't under the heading")
	}
	if strings.Contains(textOf(t, res, TextOptions{Width: 100, Verbose: true}), evidenceNote) {
		t.Error("--verbose keeps every row's evidence, yet the note shows")
	}
	small := &model.Result{Database: "shop", Server: testServer, Findings: []model.Finding{{Table: "users", Column: "email",
		Category: model.CatEmail, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Reasons: []string{"named like an email"}}}}
	if strings.Contains(textOf(t, small, TextOptions{Width: 100}), evidenceNote) {
		t.Error("no row lost its evidence, yet the note shows")
	}
}

// The sections come in their order: the details, then the summaries.
func TestTextOrder(t *testing.T) {
	out := textOf(t, withExtras(fakeShop(t)), TextOptions{Width: 100})
	last := -1
	for _, s := range []string{"\nFindings by table · ", "\nTables to empty in the copy · ", "\nTables that look like caches ",
		"\nRelationships: ", "\nHow to stop each one · ", "\nWarnings · ", "\n" + Headline + " · ",
		"\nWhat staging could do to real people · ", "\nAdd --config-out", "\n" + wantProLine} {
		i := strings.Index(out, s)
		switch {
		case i < 0:
			t.Errorf("no %q", s)
		case i < last:
			t.Errorf("%q comes before the section above it", s)
		}
		last = max(last, i)
	}
}

// With no findings the summary points at the warnings, which are above it.
func TestNothingFound(t *testing.T) {
	res := &model.Result{Database: "shop", Server: testServer, Warnings: []string{"could not read wp_users"}}
	out := textOf(t, res, TextOptions{})
	found, warnings := strings.Index(out, "\n  Nothing found. Check the warnings above:"), strings.Index(out, "\nWarnings · 1\n")
	if found < 0 || warnings < 0 || warnings > found {
		t.Errorf("want the warnings, then 'Nothing found. Check the warnings above':\n%s", out)
	}
	for _, w := range []int{60, 100} {
		walkReport(t, w, textOf(t, res, TextOptions{Width: w}), res, false)
	}
}

// Each severity row is one line: as many kinds of data as fit, joined with
// " · ", then how many more; at least one, cut with … when even one doesn't
// fit. --verbose lists every kind, wrapped under the first.
func TestSeverityRows(t *testing.T) {
	res := fakeShop(t)
	for w := 60; w <= 100; w += 5 {
		walkReport(t, w, textOf(t, res, TextOptions{Width: w}), res, false)
		walkReport(t, w, textOf(t, res, TextOptions{Width: w, Verbose: true}), res, true)
	}
	long := &model.Result{Database: "shop", Server: testServer}
	for i, c := range []string{"free text with personal data in it, such as notes and messages", "kind b", "kind c"} {
		for range 3 - i {
			long.Findings = append(long.Findings, model.Finding{Table: "t", Column: c, Category: model.Category(c),
				Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh})
		}
	}
	// The first kind alone is too long for 60 columns: walkReport holds the
	// row to its first 33 runes, …, then how many more.
	text := textOf(t, long, TextOptions{Width: 60})
	walkReport(t, 60, text, long, false)
	if !strings.Contains(text, "\n  MEDIUM      6  free text with personal data in i… · 2 more\n") {
		t.Errorf("the first kind wasn't cut to fit:\n%s", text)
	}
}

// Every heading has its total. The fake shop has 157 findings in 18 tables,
// 3 tables to empty and 12 side effects; withExtras adds a table to empty, a
// cache and two warnings. With --verbose, Findings by table counts the rows
// it lists, low-confidence ones among them; the summary still counts 157.
func TestHeadingTotals(t *testing.T) {
	res := withExtras(fakeShop(t))
	out := textOf(t, res, TextOptions{Width: 100})
	for _, want := range []string{
		"\n" + Headline + " · 157 findings\n",
		"\nWhat staging could do to real people · 12\n",
		"\nHow to stop each one · 12\n",
		"\nFindings by table · 157 findings in 18 tables\n",
		"\nTables to empty in the copy · 4 tables\n",
		"\nTables that look like caches (the starter config suggests emptying them, commented out) · 1 table\n",
		"\nWarnings · 2\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	verbose := textOf(t, res, TextOptions{Width: 100, Verbose: true})
	for _, want := range []string{"\nFindings by table · 162 findings in 20 tables\n", "\n" + Headline + " · 157 findings\n"} {
		if !strings.Contains(verbose, want) {
			t.Errorf("--verbose: missing %q", want)
		}
	}
}
