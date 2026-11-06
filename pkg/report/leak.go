package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// LeakHeadline is the question a leak check's report answers first. It says
// "sampled" and "found" so that a zero under it can't read as "none".
const LeakHeadline = "Sampled production values found on this staging database"

// leakProLine ends the text report: one line about the paid product, with a
// link of its own and no tracking, the same for everyone.
const leakProLine = "prodmask Pro, in development, will make staging copies with fake customers and check the result row by row: https://prodmask.com/leak-check"

const leakDocs = "https://github.com/ProdMask/ProdMask/blob/main/docs/leak-check.md"

// LeakLimits is the "How to read this" list. Every report carries it, JSON
// included, with n, the sample's size, in the odds.
func LeakLimits(n int) []string {
	catch := func(real float64) int { return int(math.Round((1 - math.Pow(1-float64(n)/100000, real)) * 100)) }
	return []string{
		fmt.Sprintf("A zero is not proof. Only a sample of values is looked for: %s sampled values out of 100,000 have about a %d%% chance of catching 50 real rows, and about %d%% of catching 5.",
			thousands(int64(n)), catch(50), catch(5)),
		"Only email addresses, phone numbers, IBANs, national and tax IDs, payment tokens, password hashes and secrets are counted. " +
			"Real names, street addresses, cities and dates aren't looked for, because they match by chance, so they can still be there. " +
			"Card numbers aren't hashed: prodmask scan on staging samples for them.",
		"Only columns flagged on production are read. A value a script changed even slightly doesn't match: a real name before a swapped domain, " +
			"a common home-made mask, reads as a zero. Values no longer on production, such as deleted customers, can't be sampled, " +
			"so copies of them on staging aren't found.",
		"Treat the hash file as personal data. Keep it as you keep production data, and delete it when you're done: " + leakDocs,
	}
}

// LeakLine is the report's line about a column, from its numbers.
func LeakLine(c model.LeakColumn) string {
	n := thousands(int64(c.Sampled))
	if c.Found > 0 {
		h := thousands(int64(c.Found))
		rows := "on " + rowsWord(c.Rows)
		if c.ChanceMatches > 0 && float64(c.Found) <= 2*c.ChanceMatches {
			line := fmt.Sprintf("%s of %s · %s · all of these could be chance, if a masking tool makes up realistic numbers; if no tool made them, they're real", h, n, rows)
			if c.State == model.LeakStopped {
				line += " · read in part"
			}
			return line
		}
		line := fmt.Sprintf("%s of %s (%s) · %s", h, n, percent(c.Found, c.Sampled), rows)
		switch {
		case c.Exact && c.State == model.LeakRead:
			line += " · every value of this kind on production was sampled"
		case c.EstimateInAll > 0:
			line += " · roughly " + thousands(c.EstimateInAll) + " values in all"
		default:
			line += " · at least " + h
		}
		if c.ChanceMatches > 0 {
			line += fmt.Sprintf(" · up to about %s of these could be chance, if a masking tool makes up realistic numbers", thousands(int64(math.Round(c.ChanceMatches))))
		}
		if c.State == model.LeakStopped {
			line += " · read in part"
		}
		return line
	}
	switch {
	case c.State != model.LeakRead:
		return notReadWords(c)
	case c.Values == 0 && c.ValuesSkipped > 0:
		return "0 of " + n + ": every value of this kind here was skipped by --allow-email"
	case c.Exact:
		return "0 of " + n + ": every value of this kind on production was sampled"
	case c.Values == 0:
		return "0 of " + n + ": no values of this kind in what was read"
	case c.ShownAt95 == 0:
		return "0 of " + n + ", from part of the table only: a copy of other rows reads as zero"
	case c.CatchIfAllReal > 0:
		return fmt.Sprintf("0 of %s: even if all %s values here were real, this would catch it about %d%% of the time",
			n, thousands(c.Values), int(math.Round(c.CatchIfAllReal*100)))
	}
	return fmt.Sprintf("0 of %s: about %s real values would show 95%% of the time; fewer may not", n, thousands(int64(math.Round(c.ShownAt95))))
}

// Count formats a count as reports do: 12,345.
func Count(n int64) string { return thousands(n) }

func rowsWord(n int64) string {
	if n == 1 {
		return "1 row"
	}
	return thousands(n) + " rows"
}

func percent(h, n int) string {
	if n <= 0 {
		return "0%"
	}
	p := float64(h) / float64(n) * 100
	if p < 1 {
		return "under 1%"
	}
	return fmt.Sprintf("%d%%", int(math.Round(p)))
}

// LeakJSON writes a leak check's result as indented JSON.
func LeakJSON(w io.Writer, res *model.LeakResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(res)
}

// LeakText writes a leak check's terminal report. It says clearly what it
// can't know, since the worst it could do is read as "staging is fine".
func LeakText(w io.Writer, res *model.LeakResult, colors bool) error {
	b := bufio.NewWriter(w)
	st := style{colors}
	pf := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	s := res.Summary

	pf("%s %s\n", st.bold("prodmask leak-check"), st.dim("· "+res.Database+" · "+leakServerLine(res)))
	pf("Compared with values sampled from %s on %s · %d of %d columns read · %s rows · %s\n\n",
		res.Hashes.Database, res.Hashes.CreatedAt.Format("2006-01-02"), s.ColumnsRead, s.Columns, thousands(s.RowsRead), seconds(s.DurationMillis))

	if res.NothingRead() {
		pf("%s\n", st.bold("Nothing was read on this staging database, so nothing is known about it."))
		pf("  None of the %d columns in the hash file could be read. Check the database name, the user's rights and the list below.\n\n", s.Columns)
	} else {
		pf("%s\n", st.bold(LeakHeadline))
		switch {
		case s.ColumnsRead == 0:
			pf("  No column was read in whole.\n")
		case s.Found > 0:
			pf("  %s of %s sampled values found, in %d of the %d columns read.\n", thousands(s.Found), thousands(s.Sampled), s.ColumnsWithHit, s.ColumnsRead)
		default:
			pf("  0 of %s sampled values found, in the %d columns read.\n", thousands(s.Sampled), s.ColumnsRead)
		}
		if s.FoundInPart > 0 {
			pf("  And %s more in columns read only in part.\n", thousands(s.FoundInPart))
		}
		if s.Found == 0 && s.FoundInPart == 0 {
			pf("  That isn't proof that none are there. This looked for a sample of values, and only some kinds of data.\n")
		}
		pf("\n")

		hits, zeros := splitColumns(res.Columns)
		if len(hits) > 0 {
			width := locationWidth(hits, zeros)
			for _, c := range hits {
				pf("  %s %s  %s  %s%s\n", st.severity(c.Severity, sevLabel(c.Severity)), pad(c.Location(), width),
					pad(c.Kind.Label(), 22), c.Line, exceptMark(c.Excepted))
			}
			pf("\n")
		}
		if len(zeros) > 0 {
			pf("%s\n", st.bold("Nothing found in these, which isn't proof that none are there"))
			width := locationWidth(zeros, nil)
			for _, c := range zeros {
				pf("  %s  %s  %s%s\n", pad(c.Location(), width), pad(c.Kind.Label(), 22), c.Line, exceptMark(c.Excepted))
			}
			pf("\n")
		}
	}

	if lines := notReadLines(res); len(lines) > 0 {
		pf("%s\n", st.bold("Not read, so nothing is known about these"))
		width := 0
		for _, l := range lines {
			width = max(width, utf8.RuneCountInString(l[0]))
		}
		for _, l := range lines {
			pf("  %s  %s\n", pad(l[0], width), l[1])
		}
		pf("\n")
	}

	if line := leftOutLine(res.LeftOut); line != "" {
		pf("%s\n\n", line)
	}
	if line := allowedLine(res.Allowed); line != "" {
		pf("%s\n\n", line)
	}
	if len(res.Warnings) > 0 {
		pf("%s\n", st.bold("Warnings"))
		for _, wn := range res.Warnings {
			pf("  ! %s\n", wn)
		}
		pf("\n")
	}
	pf("%s\n", st.bold("How to read this"))
	for _, l := range res.Limits {
		pf("  - %s\n", l)
	}
	pf("\n%s\n", st.dim(leakProLine))
	return b.Flush()
}

func leakServerLine(res *model.LeakResult) string {
	return serverLine(&model.Result{Server: res.Server})
}

func exceptMark(excepted bool) string {
	if excepted {
		return " (excepted from --fail-on)"
	}
	return ""
}

// splitColumns picks the columns with hits, the worst and biggest first, and
// the columns read with none. Other columns are for the list of what wasn't
// read, a stopped one with hits being in both.
func splitColumns(cols []model.LeakColumn) (hits, zeros []model.LeakColumn) {
	for _, c := range cols {
		switch {
		case c.Found > 0:
			hits = append(hits, c)
		case c.State == model.LeakRead:
			zeros = append(zeros, c)
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Severity != hits[j].Severity {
			return hits[i].Severity > hits[j].Severity
		}
		return hits[i].Found > hits[j].Found
	})
	return hits, zeros
}

func locationWidth(a, b []model.LeakColumn) int {
	width := 0
	for _, list := range [][]model.LeakColumn{a, b} {
		for _, c := range list {
			width = max(width, utf8.RuneCountInString(c.Location()))
		}
	}
	return width
}

// notReadLines lists what wasn't read: location, then why.
func notReadLines(res *model.LeakResult) [][2]string {
	var out [][2]string
	seen := map[string]bool{}
	add := func(loc, why string, excepted bool) {
		if !seen[loc] {
			seen[loc] = true
			out = append(out, [2]string{loc, why + exceptMark(excepted)})
		}
	}
	for _, c := range res.Columns {
		if c.State != model.LeakRead {
			add(c.Location(), notReadWords(c), c.Excepted)
		}
	}
	for _, l := range res.LeftOut {
		if l.NotRead {
			add(l.Location, l.Why+" on production", l.Excepted)
		}
	}
	return out
}

// notReadWords says why a column wasn't read in whole.
func notReadWords(c model.LeakColumn) string {
	switch c.State {
	case model.LeakNotRead:
		return "not read: --max-time came first"
	case model.LeakNotOnStaging:
		return "not on staging"
	case model.LeakUnreadable:
		return "can't be read on staging: a view, or now binary"
	}
	return stoppedLine(c)
}

func stoppedLine(c model.LeakColumn) string {
	of := thousands(c.RowsRead) + " rows"
	if c.RowsEstimate > 0 {
		of = thousands(c.RowsRead) + " of ~" + thousands(c.RowsEstimate) + " rows"
	}
	switch c.StoppedBy {
	case "--max-time":
		return "stopped by --max-time after " + of
	case "timed out":
		return "stopped after " + of + " (timed out); a longer --timeout may read more"
	}
	return "stopped after " + of + " (" + c.StoppedBy + ")"
}

// leftOutLine sums up what was left out on production by why, in one line. The
// JSON report lists each.
func leftOutLine(list []model.LeakLeftOut) string {
	counts := map[string]int{}
	var order []string
	for _, l := range list {
		if l.NotRead {
			continue
		}
		if counts[l.Why] == 0 {
			order = append(order, l.Why)
		}
		counts[l.Why]++
	}
	if len(order) == 0 {
		return ""
	}
	sort.Strings(order)
	parts := make([]string, len(order))
	for i, why := range order {
		parts[i] = fmt.Sprintf("%d, %s", counts[why], why)
	}
	return "Left out on production (--format json lists them): " + strings.Join(parts, "; ") + "."
}

func allowedLine(a model.LeakAllowed) string {
	if len(a.Domains) == 0 && a.Addresses == 0 {
		return ""
	}
	var who []string
	if len(a.Domains) > 0 {
		who = append(who, strings.Join(a.Domains, ", "))
	}
	switch a.Addresses {
	case 0:
	case 1:
		who = append(who, "1 address")
	default:
		who = append(who, fmt.Sprintf("%d addresses", a.Addresses))
	}
	return fmt.Sprintf("Allowed by --allow-email: %s. %s values skipped.", strings.Join(who, " and "), thousands(a.ValuesSkipped))
}
