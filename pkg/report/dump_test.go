package report

import (
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// The words a report on a dump has in place of a live scan's, written here
// rather than read from the code, so a test catches one that changes.
const (
	wantDumpSideEffects = "not checked in a dump file: these checks read live settings and queues through a server"
	wantDumpProLine     = "prodmask Pro makes masked copies and checks every value of them: https://prodmask.com"
	wantDumpShape       = "A finding is a shape: a masked value can look the same. leak-check compare --dump counts the real production values a dump holds."
)

// dumpShop is the fake shop as a scan of its dump reports it: the dump's
// facts in place of the server's, no side effects, which a dump can't show,
// two warnings, one too long for a line, and more unread statements than the
// report lists, one of them too long for a line too.
func dumpShop(t *testing.T) *model.Result {
	t.Helper()
	res := withExtras(loadFakeShop(t))
	res.SideEffects = nil
	res.Server = model.ServerInfo{Flavor: "mariadb", Version: "11.8.2-MariaDB"}
	res.Dump = &model.DumpInfo{File: "shop-masked.sql.gz", Compression: "gzip", Statements: 1204, Rows: 48310, Unread: 102,
		Bodies: model.DumpBodies{Triggers: 2, Views: 1},
		Judged: "Judged up to 300 rows of each table, the ones scan reads on a database, and every key of its key/value tables."}
	res.Dump.UnreadList = append(res.Dump.UnreadList, model.DumpUnread{Line: 12, Kind: "ALTER TABLE", Database: "shop",
		Table:  "wp_a_table_with_a_long_name_a_plugin_made_up_for_itself",
		Reason: "the ALTER TABLE changes the structure in a way the reader doesn't follow"})
	for i := range 99 {
		res.Dump.UnreadList = append(res.Dump.UnreadList, model.DumpUnread{Line: 1000 + i, Kind: "INSERT", Database: "shop",
			Table: "wp_users", Reason: "an expression the reader doesn't evaluate"})
	}
	return res
}

// A report on a dump keeps the layout's rules at every width from 60 to 100,
// as TestTextAtEveryWidth checks the fake shop's: no line wider than the
// width but one holding a word too long for its room, none ending with a
// space, colour on and off giving the same text, and every line where the
// layout puts it (walkReport), the dump's own lines among them. The warnings'
// total counts every unread statement, listed or not.
func TestDumpTextAtEveryWidth(t *testing.T) {
	res := dumpShop(t)
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
		walkReport(t, w, text, res, false)
	}
	for _, w := range []int{60, 100} {
		walkReport(t, w, textOf(t, res, TextOptions{Width: w, Verbose: true}), res, true)
	}
	if out := textOf(t, res, TextOptions{}); !strings.Contains(out, "\nWarnings · 104\n") {
		t.Errorf("the warnings' total isn't the 2 warnings and the 102 unread statements:\n%s", out)
	}
	// Side effects on a dump's result, which no check sets today, still give
	// no fixes and no list: the section says they weren't checked.
	effects := dumpShop(t)
	effects.SideEffects = fakeShop(t).SideEffects
	for _, w := range []int{60, 100} {
		walkReport(t, w, textOf(t, effects, TextOptions{Width: w}), effects, false)
	}
	// Nothing found, in a dump that names no database and no server.
	empty := &model.Result{Dump: &model.DumpInfo{File: "masked.sql", Judged: "Judged names only; no values were read."}}
	for _, w := range []int{60, 100} {
		walkReport(t, w, textOf(t, empty, TextOptions{Width: w}), empty, false)
	}
}

// The lines a report on a dump adds: the bodies left out, in the singular
// for one; the unread statements past the list; the read line, which says
// what ran and gives the time as other lines do.
func TestDumpLines(t *testing.T) {
	for _, c := range []struct {
		b    model.DumpBodies
		want string
	}{
		{model.DumpBodies{}, ""},
		{model.DumpBodies{Views: 1}, "The body of 1 view isn't judged."},
		{model.DumpBodies{Triggers: 2, Views: 1}, "The bodies of 2 triggers and 1 view aren't judged."},
		{model.DumpBodies{Triggers: 1, Routines: 3, Events: 1, Views: 2}, "The bodies of 1 trigger, 3 routines, 1 event and 2 views aren't judged."},
	} {
		if got := dumpBodies(&model.Result{Dump: &model.DumpInfo{Bodies: c.b}}); got != c.want {
			t.Errorf("%+v: %q, want %q", c.b, got, c.want)
		}
	}

	res := &model.Result{Dump: &model.DumpInfo{Unread: 101, UnreadList: make([]model.DumpUnread, 100)}}
	if l := dumpUnread(res); l[len(l)-1] != "and 1 more statement wasn't read" {
		t.Errorf("one more: %q", l[len(l)-1])
	}
	res.Dump.Unread = 102
	if l := dumpUnread(res); l[len(l)-1] != "and 2 more statements weren't read" {
		t.Errorf("two more: %q", l[len(l)-1])
	}

	res = &model.Result{Dump: &model.DumpInfo{Statements: 3, Rows: 2}, Summary: model.Summary{Tables: 1, DurationMillis: 6400}}
	if got := dumpRead(res); !strings.Contains(got, "in 6.4 s (one pass)") {
		t.Errorf("names only: %q", got)
	}
	res.Options.Samples = true
	if got := dumpRead(res); !strings.Contains(got, "in 6.4 s (two passes)") {
		t.Errorf("with samples: %q", got)
	}
}

// A dump that never names its database has its name shown as "an unnamed
// database": in the scan's Markdown title, and in the leak check's line on
// the hash file. A named one shows as before.
func TestUnnamedDatabase(t *testing.T) {
	var b strings.Builder
	if err := Markdown(&b, &model.Result{Dump: &model.DumpInfo{File: "masked.sql"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "# prodmask scan: an unnamed database\n") {
		t.Errorf("Markdown title:\n%s", b.String())
	}
	b.Reset()
	if err := Markdown(&b, &model.Result{Database: "shop", Dump: &model.DumpInfo{File: "masked.sql"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "# prodmask scan: `shop`\n") {
		t.Errorf("Markdown title:\n%s", b.String())
	}

	res := leakFixture()
	res.Hashes.Database, res.Limits = "", LeakLimitsDump(3000)
	res.Dump = &model.DumpInfo{File: "masked.sql", Judged: LeakDumpJudged(0, 3000)}
	b.Reset()
	if err := LeakText(&b, res, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "\nCompared with values sampled from an unnamed database on 2026-11-05 · ") {
		t.Errorf("leak text:\n%s", b.String())
	}
}

// A leak check of a dump speaks of the dump: its limit lines and its hint
// when nothing was read name no staging database, database name or user's
// rights. A check of a database keeps its lines. The closing line about
// Pro's staging copies is the same on every report.
func TestLeakDumpWording(t *testing.T) {
	live, dump := LeakLimits(3000), LeakLimitsDump(3000)
	if len(dump) != len(live) || !strings.Contains(dump[1], "prodmask scan --dump samples for them.") ||
		!strings.Contains(dump[2], "so copies of them in the dump aren't found.") {
		t.Errorf("dump limits:\n%s", strings.Join(dump, "\n"))
	}
	if !strings.Contains(live[1], "prodmask scan on staging samples for them.") || !strings.Contains(live[2], "so copies of them on staging aren't found.") {
		t.Errorf("live limits:\n%s", strings.Join(live, "\n"))
	}

	res := leakFixture()
	res.Database, res.Server, res.Limits = "", model.ServerInfo{}, dump
	res.Dump = &model.DumpInfo{File: "masked.sql", Judged: LeakDumpJudged(0, 3000)}
	res.Columns = []model.LeakColumn{
		spreadColumn(model.LeakColumn{Table: "users", Column: "email", Kind: model.LeakEmail, Sampled: 3000, State: model.LeakNotOnStaging}),
	}
	res.Summary = model.LeakSummary{Columns: 1, NothingRead: true}
	var b strings.Builder
	if err := LeakText(&b, res, false); err != nil {
		t.Fatal(err)
	}
	out, _, _ := strings.Cut(b.String(), leakProLine)
	if !strings.Contains(out, "None of the 1 columns in the hash file could be read from the dump.") {
		t.Errorf("no dump hint:\n%s", out)
	}
	for _, w := range []string{"staging", "database name", "user's rights"} {
		if strings.Contains(out, w) {
			t.Errorf("%q in:\n%s", w, out)
		}
	}
}
