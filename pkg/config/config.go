// Package config writes the starter prodmask.yml that a scan proposes: what
// to mask in each column and meta key, which tables to empty, which inferred
// relationships to follow, and what to neutralise.
package config

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// Strategies lists the masking strategies a config may use.
var Strategies = []string{
	"keep", "null", "empty", "hash", "delete", "redact",
	"fake_email", "fake_phone", "fake_name", "fake_first_name", "fake_last_name", "fake_username",
	"fake_street", "fake_postcode", "fake_city", "fake_company", "fake_iban", "fake_ip",
	"fake_user_agent", "fake_date", "test_card", "staging_password",
}

type rule struct {
	mask    string
	comment string
	low     bool // only low-confidence evidence: written commented out
}

type field struct {
	rule  *rule
	name  *rule // rewrites the part of a key's name that holds data
	paths map[string]*rule
	rows  []rowRule
}

// rowRule replaces a field's mask for the rows that match where.
type rowRule struct {
	where string
	rule  *rule
}

type tableConf struct {
	action, reason string
	columns        map[string]*field
	keyCol, valCol string
	keys           map[string]*field
}

// better reports whether finding a should decide the mask over b.
func better(a, b model.Finding) bool {
	if (a.Confidence == model.ConfidenceLow) != (b.Confidence == model.ConfidenceLow) {
		return b.Confidence == model.ConfidenceLow
	}
	if a.Severity != b.Severity {
		return a.Severity > b.Severity
	}
	return a.Confidence > b.Confidence
}

// Header lines that say how to read the config.
var header = []string{
	"It is a starting point, not a guarantee: review every rule, and rescan after schema changes.",
	"Lines starting with \"# \" inside a table are weak matches; uncomment the ones that are real.",
	"In keys and in path segments alike, * stands for one or more characters that vary, such as a user ID.",
	"A path segment that is exactly * stands for the keys at that level that aren't plain names (hashes, labels",
	"with spaces, data); plain-named keys beside them keep their own rules. Stored keys never contain *.",
	"An exact key wins over a pattern, more fixed characters win over fewer, and on a tie the first one here wins.",
	"In paths, [] stands for each item of a list or numeric key of a map (such as a timestamp), and {} (always",
	"last) for the keys of a map whose keys are data, such as email or IP addresses.",
	"name: rewrites the part of a key's name that holds personal data; mask: masks its value.",
}

// Write renders the starter config for a scan result.
func Write(w io.Writer, res *model.Result) error {
	tables := map[string]*tableConf{}
	get := func(name string) *tableConf {
		t := tables[name]
		if t == nil {
			t = &tableConf{columns: map[string]*field{}, keys: map[string]*field{}}
			tables[name] = t
		}
		return t
	}
	for _, ts := range res.Tables {
		if ts.Action != "" {
			t := get(ts.Name)
			t.action, t.reason = ts.Action, ts.ActionReason
		}
	}

	// Pick one finding per column, key, path, row condition and key name:
	// the most severe of the confident ones.
	best := map[string]model.Finding{}
	others := map[string][]string{}
	rowMasks := map[string][]model.RowMask{}
	var keys []string
	for _, f := range res.Findings {
		if f.MetaKey == "(key hidden)" {
			continue
		}
		k := f.Table + "\x00" + f.Column + "\x00" + f.MetaKey + "\x00" + f.Path + "\x00" + f.Where + "\x00" + fmt.Sprint(f.KeyName)
		for _, rm := range f.RowMasks {
			if !slices.Contains(rowMasks[k], rm) {
				rowMasks[k] = append(rowMasks[k], rm)
			}
		}
		old, ok := best[k]
		switch {
		case !ok:
			best[k] = f
			keys = append(keys, k)
		case better(f, old):
			best[k] = f
			others[k] = append(others[k], old.Category.Label())
		default:
			others[k] = append(others[k], f.Category.Label())
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		f := best[k]
		r := &rule{mask: f.Mask, low: f.Confidence == model.ConfidenceLow}
		r.comment = f.Category.Label() + ", " + f.Confidence.String() + " confidence"
		if f.KeyName {
			r.comment = f.Category.Label() + " in the key name, " + f.Confidence.String() + " confidence"
		}
		if extra := others[k]; len(extra) > 0 {
			r.comment += "; also " + strings.Join(extra, ", ")
		}
		if f.Keys > 0 {
			r.comment += "; " + f.KeyCount()
		}
		if f.Note != "" {
			r.comment += "; " + f.Note
		}
		t := get(f.Table)
		var fd *field
		switch {
		case f.KeyName:
			fd = t.keys[f.MetaKey]
			if fd == nil {
				fd = &field{paths: map[string]*rule{}}
				t.keys[f.MetaKey] = fd
			}
			fd.name = r
			continue
		case f.MetaKey != "":
			t.valCol = f.Column
			fd = t.keys[f.MetaKey]
			if fd == nil {
				fd = &field{paths: map[string]*rule{}}
				t.keys[f.MetaKey] = fd
			}
		default:
			fd = t.columns[f.Column]
			if fd == nil {
				fd = &field{paths: map[string]*rule{}}
				t.columns[f.Column] = fd
			}
		}
		if f.Where != "" {
			// A finding about some rows only: it never sets the field's own mask.
			fd.rows = append(fd.rows, rowRule{where: f.Where, rule: r})
			continue
		}
		if f.Path != "" {
			fd.paths[f.Path] = r
			continue
		}
		fd.rule = r
		for _, rm := range rowMasks[k] {
			fd.rows = append(fd.rows, rowRule{where: rm.Where, rule: &rule{mask: rm.Mask, comment: rm.Note, low: r.low}})
		}
	}
	for _, t := range tables {
		for _, fd := range t.keys {
			// Renaming rows the copy deletes is pointless.
			if fd.rule != nil && fd.rule.mask == "delete" {
				fd.name = nil
			}
		}
		for _, fd := range t.columns {
			sortRows(fd.rows)
		}
		for _, fd := range t.keys {
			sortRows(fd.rows)
		}
	}
	for _, ts := range res.Tables {
		if t := tables[ts.Name]; t != nil && ts.KeyColumn != "" {
			t.keyCol, t.valCol = ts.KeyColumn, ts.ValueColumn
		}
	}

	b := bufio.NewWriter(w)
	pf := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	pf("# prodmask starter config\n")
	pf("# Written by prodmask %s on %s from a scan of %s (%s %s).\n", res.Version,
		res.GeneratedAt.Format("2006-01-02"), res.Database, res.Server.Flavor, res.Server.Version)
	for _, line := range header {
		pf("# %s\n", line)
	}
	pf("# Masking strategies: %s\n", strings.Join(Strategies, ", "))
	pf("version: 1\n")
	pf("database: %s\n", scalar(res.Database))
	if len(res.Platforms) > 0 {
		var ps []string
		for _, p := range res.Platforms {
			ps = append(ps, scalar(p.Name))
		}
		pf("platforms: [%s]\n", strings.Join(ps, ", "))
	}

	names := make([]string, 0, len(tables))
	for n := range tables {
		names = append(names, n)
	}
	sort.Strings(names)
	pf("\ntables:\n")
	if len(names) == 0 {
		pf("  {}\n")
	}
	for _, n := range names {
		t := tables[n]
		pf("  %s:\n", scalar(n))
		if t.action != "" {
			pf("    action: %s%s\n", t.action, comment(t.reason))
			if len(t.columns) == 0 && len(t.keys) == 0 {
				continue
			}
		}
		if len(t.columns) > 0 {
			pf("    columns:\n")
			writeFields(b, "      ", t.columns)
		}
		if len(t.keys) > 0 {
			pf("    key_column: %s\n", scalar(t.keyCol))
			pf("    value_column: %s\n", scalar(t.valCol))
			pf("    keys:\n")
			writeFields(b, "      ", t.keys)
		}
	}

	var rels []model.Relationship
	for _, r := range res.Relationships {
		if r.Status != model.RelDeclared {
			rels = append(rels, r)
		}
	}
	if len(rels) > 0 {
		pf("\n# Links the schema does not declare. A copy follows them to keep subsets consistent.\n")
		pf("relationships:\n")
		for _, r := range rels {
			prefix := "  "
			if r.Status == model.RelWeak {
				prefix = "  # "
			}
			pf("%s- from: %s\n", prefix, scalar(r.ChildTable+"."+strings.Join(r.ChildColumns, ",")))
			pf("%s  to: %s\n", prefix, scalar(r.ParentTable+"."+strings.Join(r.ParentColumns, ",")))
			if r.TypeValue != "" {
				pf("%s  where: %s\n", prefix, scalar(r.TypeColumn+" = "+r.TypeValue))
			}
			ev := r.Source
			if r.Checked > 0 {
				ev += fmt.Sprintf(", %d of %d sampled values found", r.Found, r.Checked)
			}
			pf("%s  status: %s%s\n", prefix, r.Status, comment(ev))
		}
	}

	if len(res.SideEffects) > 0 {
		pf("\n# What staging could do to real people. Apply these fixes to every copy.\n")
		pf("neutralise:\n")
		for _, se := range res.SideEffects {
			pf("  - kind: %s\n", scalar(se.Kind))
			where := se.Table
			if se.Item != "" {
				where += "[" + se.Item + "]"
			}
			pf("    where: %s\n", scalar(where))
			pf("    why: %s\n", scalar(se.Summary))
			pf("    fix: %s\n", scalar(se.Fix))
		}
	}
	return b.Flush()
}

func sortRows(rows []rowRule) {
	slices.SortFunc(rows, func(a, b rowRule) int {
		return cmp.Or(strings.Compare(a.where, b.where), strings.Compare(a.rule.mask, b.rule.mask),
			strings.Compare(a.rule.comment, b.rule.comment))
	})
}

func writeFields(b *bufio.Writer, indent string, fields map[string]*field) {
	names := make([]string, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fd := fields[n]
		if len(fd.paths) == 0 && len(fd.rows) == 0 && fd.name == nil {
			if fd.rule != nil {
				writeRule(b, indent, n, fd.rule)
			}
			continue
		}
		weakRows := !slices.ContainsFunc(fd.rows, func(rr rowRule) bool { return !rr.rule.low })
		name := indent
		if len(fd.paths) == 0 && (fd.rule == nil || fd.rule.low) && (fd.name == nil || fd.name.low) && weakRows {
			name += "# " // nothing confident inside, so no live key either
		}
		fmt.Fprintf(b, "%s%s:\n", name, scalar(n))
		if fd.name != nil {
			writeRule(b, indent+"  ", "name", fd.name)
		}
		if fd.rule != nil {
			writeRule(b, indent+"  ", "mask", fd.rule)
		}
		if len(fd.paths) > 0 {
			fmt.Fprintf(b, "%s  paths:\n", indent)
			paths := make([]string, 0, len(fd.paths))
			for p := range fd.paths {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			for _, p := range paths {
				writeRule(b, indent+"    ", p, fd.paths[p])
			}
		}
		if len(fd.rows) > 0 {
			header := indent + "  "
			if weakRows {
				header += "# " // all weak: don't leave an empty rows: key behind
			}
			note := "for the rows that match, these replace the mask above"
			if fd.rule == nil {
				note = "for the rows that match; the other rows keep their values"
			}
			fmt.Fprintf(b, "%srows:  # %s\n", header, note)
			for _, rr := range fd.rows {
				prefix := indent + "    "
				if rr.rule.low {
					prefix += "# "
				}
				fmt.Fprintf(b, "%s- where: %s\n", prefix, scalar(rr.where))
				fmt.Fprintf(b, "%s  mask: %s%s\n", prefix, scalar(rr.rule.mask), comment(rr.rule.comment))
			}
		}
	}
}

func writeRule(b *bufio.Writer, indent, key string, r *rule) {
	prefix := indent
	if r.low {
		prefix = indent + "# "
	}
	fmt.Fprintf(b, "%s%s: %s%s\n", prefix, scalar(key), scalar(r.mask), comment(r.comment))
}

func comment(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	return "  # " + s
}

var plain = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*$`)

var yamlWords = map[string]bool{"true": true, "false": true, "yes": true, "no": true, "on": true,
	"off": true, "y": true, "n": true, "null": true, "~": true}

// scalar renders a YAML scalar, quoting it unless it is a plain identifier.
func scalar(s string) string {
	if plain.MatchString(s) && !yamlWords[strings.ToLower(s)] && !looksNumeric(s) {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

var numeric = regexp.MustCompile(`^[-+]?(?:\d[\d_]*)?(?:\.\d+)?(?:[eE][-+]?\d+)?$|^0x[0-9a-fA-F]+$|^0o[0-7]+$`)

func looksNumeric(s string) bool { return numeric.MatchString(s) }
