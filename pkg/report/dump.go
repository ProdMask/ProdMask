package report

import (
	"fmt"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// The words a report on a dump file adds. A report on a database has none of
// them.
const (
	// dumpSideEffects stands in place of the side-effects section's items.
	dumpSideEffects = "not checked in a dump file: these checks read live settings and queues through a server"
	// dumpShape says what a finding in a dump is.
	dumpShape = "A finding is a shape: a masked value can look the same. leak-check compare --dump counts the real production values a dump holds."
	// dumpProLine ends the free build's report on a dump.
	dumpProLine = "prodmask Pro makes masked copies and checks every value of them: https://prodmask.com"
)

// dumpServer names the server the dump came from, "MariaDB 11.8.2", or says
// nothing when the file has no header.
func dumpServer(res *model.Result) string {
	if res.Server.Version == "" && res.Server.Flavor == "" {
		return ""
	}
	flavor := "MySQL"
	if res.Server.Flavor == "mariadb" {
		flavor = "MariaDB"
	}
	v, _, _ := strings.Cut(res.Server.Version, "-MariaDB")
	return strings.TrimSpace(flavor + " " + v)
}

// dumpSource is "dump file NAME (MariaDB 11.8.2)", which stands in for the
// server in a report's header.
func dumpSource(res *model.Result) string {
	s := "dump file " + res.Dump.File
	if v := dumpServer(res); v != "" {
		s += " (" + v + ")"
	}
	return s
}

// counted is a count with its noun, in the singular for 1.
func counted(n int64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return thousands(n) + " " + noun + "s"
}

// dumpRead is the line that says what was read.
func dumpRead(res *model.Result) string {
	d, s := res.Dump, res.Summary
	passes := "two passes"
	if !res.Options.Samples {
		passes = "one pass"
	}
	line := fmt.Sprintf("Read %s and %s of %s in %s (%s); ",
		counted(int64(d.Statements), "statement"), counted(d.Rows, "row"), counted(int64(s.Tables-s.Views), "table"),
		seconds(s.DurationMillis), passes)
	switch d.Unread {
	case 0:
		return line + "every statement was read."
	case 1:
		return line + "1 statement wasn't read, see Warnings."
	}
	return line + fmt.Sprintf("%s statements weren't read, see Warnings.", thousands(int64(d.Unread)))
}

// dumpUnread lists the statements that weren't read, the first 100, then a
// count of the rest.
func dumpUnread(res *model.Result) []string {
	var out []string
	for _, u := range res.Dump.UnreadList {
		out = append(out, dumpUnreadLine(u))
	}
	switch more := res.Dump.Unread - len(res.Dump.UnreadList); {
	case more == 1:
		out = append(out, "and 1 more statement wasn't read")
	case more > 1:
		out = append(out, fmt.Sprintf("and %s more statements weren't read", thousands(int64(more))))
	}
	return out
}

func dumpUnreadLine(u model.DumpUnread) string {
	if u.ToEnd {
		return fmt.Sprintf("lines %s to the end of the file weren't read: %s", thousands(int64(u.Line)), u.Reason)
	}
	what := u.Kind + " statement"
	switch {
	case u.Kind == "OTHER":
		what = "statement"
	case u.Table != "" && (u.Kind == "INSERT" || u.Kind == "INSERT IGNORE" || u.Kind == "REPLACE"):
		what = u.Kind + " into " + u.Table
	case u.Table != "":
		what = u.Kind + " of " + u.Table
	case strings.Contains(u.Kind, " "), u.Kind == "INSERT", u.Kind == "REPLACE":
		what = u.Kind
	}
	article := "a"
	if strings.ContainsRune("AEIOU", rune(what[0])) && what != "USE statement" {
		article = "an"
	}
	return fmt.Sprintf("line %s: %s %s wasn't read: %s", thousands(int64(u.Line)), article, what, u.Reason)
}

// dumpBodies says that the bodies of triggers, routines, events and views
// exist and weren't judged, when the file holds any: "The bodies of 2
// triggers and 1 view aren't judged."
func dumpBodies(res *model.Result) string {
	b := res.Dump.Bodies
	var parts []string
	n := 0
	for _, c := range []struct {
		n    int
		noun string
	}{{b.Triggers, "trigger"}, {b.Routines, "routine"}, {b.Events, "event"}, {b.Views, "view"}} {
		if c.n > 0 {
			parts = append(parts, counted(int64(c.n), c.noun))
			n += c.n
		}
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
	default:
		parts = []string{strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]}
	}
	if n == 1 {
		return "The body of " + parts[0] + " isn't judged."
	}
	return "The bodies of " + parts[0] + " aren't judged."
}

// dumpClosing is the facts that close a report on a dump, before the Pro
// line: what was left out, which rows were judged, and what a finding is.
func dumpClosing(res *model.Result) []string {
	var out []string
	if b := dumpBodies(res); b != "" {
		out = append(out, b)
	}
	return append(out, res.Dump.Judged, dumpShape)
}

// dumpPro is the Pro line, in the free build alone.
func dumpPro(res *model.Result) string {
	if res.Edition != "" {
		return ""
	}
	return dumpProLine
}

// dumpSourceMarkdown is the file's line in a Markdown report: its name, the
// server it came from, how it was compressed and the tool that wrote it.
func dumpSourceMarkdown(res *model.Result) string {
	d := res.Dump
	s := code(d.File)
	if v := dumpServer(res); v != "" {
		s += " (" + v + ")"
	}
	if d.Compression != "" {
		s += ", " + d.Compression
	}
	if d.Producer != "" {
		s += ", written by " + code(d.Producer)
	}
	return s
}
