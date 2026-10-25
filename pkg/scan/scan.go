// Package scan runs a read-only scan of one database. It reads the schema,
// samples rows, judges every column and meta key, works out how tables link
// up, and lists what a plain copy would let staging do to real people.
package scan

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/infer"
	"github.com/ProdMask/ProdMask/pkg/introspect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// Options control a scan.
type Options struct {
	SampleRows     int  // rows per table
	MetaSampleRows int  // rows per key/value table too big to read whole
	KeySampleRows  int  // rows per key of a key/value table
	Samples        bool // false judges names only and reads no rows
	// SampleKeysOnly reads every key/value table by sampling, as for tables
	// too large to list their keys: a window of rows plus probes for the
	// keys presets know.
	SampleKeysOnly bool
	Preset         string
	MaxValueLen    int
	Version        string
	Progress       func(done, total int, table string)
}

// Defaults for Options.
const (
	DefaultSampleRows     = 300
	DefaultMetaSampleRows = 3000
	DefaultKeySampleRows  = 20
	DefaultMaxValueLen    = 4096
)

// Run scans the database behind the session.
func Run(ctx context.Context, sess *dbconn.Session, opts Options) (*model.Result, error) {
	start := time.Now()
	if opts.MaxValueLen <= 0 {
		opts.MaxValueLen = DefaultMaxValueLen
	}
	if opts.KeySampleRows <= 0 {
		opts.KeySampleRows = DefaultKeySampleRows
	}
	res := &model.Result{
		Tool: "prodmask", Version: opts.Version, GeneratedAt: start.UTC().Truncate(time.Second),
		Server: sess.Server, Database: sess.Database,
		Options: model.ScanOptions{
			SampleRows: opts.SampleRows, MetaSampleRows: opts.MetaSampleRows, KeySampleRows: opts.KeySampleRows,
			Samples: opts.Samples, Preset: opts.Preset, TimeoutSeconds: sess.Timeout.Seconds(),
		},
		Warnings: append([]string(nil), sess.Warnings...),
	}

	schema, err := introspect.Load(ctx, sess.DB, sess.Database)
	if err != nil {
		return nil, err
	}
	if len(schema.Tables) == 0 {
		res.Warnings = append(res.Warnings, "the database has no tables, or the user cannot see them")
	}

	// Server-side timeouts stop slow statements; this is the backstop.
	queryTimeout := sess.Timeout + 15*time.Second
	pr := &preset.Result{}
	if opts.Preset != "none" {
		pr = preset.Detect(ctx, sess.DB, schema, opts.Preset, queryTimeout)
	}
	res.Platforms = pr.Platforms
	res.SideEffects = pr.SideEffects
	res.Warnings = append(res.Warnings, pr.Warnings...)

	sampler := &sample.Sampler{DB: sess.DB, MaxValueLen: opts.MaxValueLen, Timeout: queryTimeout, Hex: hexColumn(pr)}
	ids := infer.NewIDValues()

	metas := map[string]*preset.MetaTable{}
	for _, t := range schema.Tables {
		if !t.IsData() {
			continue
		}
		if m := pr.Meta[t.Name]; m != nil {
			metas[t.Name] = m
		} else if m := genericMeta(t, pr); m != nil {
			metas[t.Name] = m
		}
	}
	// Key/value tables first, the main site's before the others, so they
	// draw on the scan's budgets first.
	order := planOrder(schema.Tables, metas)
	b := newBudget()

	for i, t := range order {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if opts.Progress != nil {
			opts.Progress(i, len(order), t.Name)
		}
		ts := model.TableSummary{Name: t.Name, Kind: "table", RowsEstimate: t.RowsEstimate}
		if a, ok := pr.Actions[t.Name]; ok {
			ts.Action, ts.ActionReason = a.Action, a.Reason
		}
		if !t.IsData() {
			ts.Kind = strings.ToLower(t.Type)
			if t.IsView() {
				ts.Kind = "view"
			}
			res.Tables = append(res.Tables, ts)
			continue
		}
		meta := metas[t.Name]
		if meta != nil {
			ts.Kind = "key/value"
			ts.KeyColumn, ts.ValueColumn = meta.Key, meta.Value
		}

		var (
			s  *sample.Sample
			kv *kvRead
		)
		var keyNames *model.Finding
		if opts.Samples {
			if meta != nil {
				kv = readKV(ctx, sess, sampler, t, meta, opts, b)
			}
			s, err = sampler.Table(ctx, t, windowRows(opts, kv))
			if err != nil {
				ts.Error = dbconn.ErrorText(err)
				res.Warnings = append(res.Warnings, fmt.Sprintf("could not sample %s: %s", t.Name, ts.Error))
			}
			if kv != nil && kv.mode == modeSample && !kv.demoted {
				kv.sampleKV(ctx, sampler, sess, t, meta, s, opts, b)
			}
			if s != nil {
				ts.RowsSampled = len(s.Rows)
				ids.Collect(t, s)
			}
			if kv != nil {
				ts.RowsSampled += kv.rows
				if kv.demoted {
					// Keyed by data, such as people's names: judged as a
					// plain table, whose key column may hold the names.
					// Failed statements are still reported.
					res.Warnings = append(res.Warnings, kv.failures()...)
					keyNames = demotedKeyFinding(t, meta, kv)
					meta, kv = nil, nil
					ts.Kind, ts.KeyColumn, ts.ValueColumn = "table", "", ""
				} else {
					res.Warnings = append(res.Warnings, kv.warnings...)
				}
			}
			if ts.Action == "" && cacheTable(t) && holdsText(s, kv) {
				ts.PossibleAction = "truncate"
				ts.PossibleActionReason = "looks like a cache: applications rebuild their caches, so emptying the copy's " +
					"is usually safe; check that this one is rebuilt"
			}
		}

		var findings []model.Finding
		if kv != nil {
			var hidden int
			findings, hidden = analyzeKV(t, s, meta, kv)
			ts.Keys = len(kv.keys)
			if n, named := skippedSummary(t, meta, kv); n > 0 {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%d keys of %s were not sampled (limits: %d keys and %d MB per table, "+
					"%d keys and %d MB per scan); %d of them match names and are listed at low confidence in the JSON report",
					n, t.Name, tableKeys, tableBytes>>20, scanKeys, scanBytes>>20, named))
			}
			switch {
			case hidden == 1:
				ts.HiddenKeys = hidden
				res.Warnings = append(res.Warnings, fmt.Sprintf("1 key of %s holds findings but isn't shown, since its name "+
					"may hold personal data; the starter config has no rule for it", t.Name))
			case hidden > 1:
				ts.HiddenKeys = hidden
				res.Warnings = append(res.Warnings, fmt.Sprintf("%d keys of %s hold findings but aren't shown, since their names "+
					"may hold personal data; the starter config has no rules for them", hidden, t.Name))
			}
		}
		findings = append(findings, analyzeColumns(t, s, pr, meta)...)
		if keyNames != nil && !slices.ContainsFunc(findings, func(f model.Finding) bool {
			return f.Column == keyNames.Column && f.Confidence > model.ConfidenceLow
		}) {
			findings = append(findings, *keyNames)
		}
		if opts.Samples {
			fs, warns := rowSubjects(ctx, sampler, t, pr)
			findings = append(findings, fs...)
			res.Warnings = append(res.Warnings, warns...)
		}
		hashUnique(t, findings)
		for _, f := range findings {
			if f.Confidence > model.ConfidenceLow {
				ts.Findings++
				if f.Severity > ts.Highest {
					ts.Highest = f.Severity
				}
			}
		}
		res.Findings = append(res.Findings, findings...)
		res.Tables = append(res.Tables, ts)
	}
	if opts.Progress != nil {
		opts.Progress(len(order), len(order), "")
	}
	sort.SliceStable(res.Tables, func(i, j int) bool { return res.Tables[i].Name < res.Tables[j].Name })

	inf := &infer.Inferrer{Schema: schema, IDs: ids, Prefixes: pr.Prefixes, Known: pr.Relationships}
	rels, warns := infer.Verify(ctx, sess.DB, ids, schema, inf.Relationships(), queryTimeout)
	res.Relationships = rels
	res.Warnings = append(res.Warnings, warns...)
	weakenDeviceReferences(res, schema)

	detect.SortFindings(res.Findings)
	sortRelationships(res.Relationships)
	summarize(res, time.Since(start))
	return res, nil
}

// hexColumn picks the columns the sampler reads as hex: short binary
// columns named like IP addresses, decoded in memory. A preset's column is
// judged as the preset says.
func hexColumn(pr *preset.Result) func(t *model.Table, c *model.Column) bool {
	return func(t *model.Table, c *model.Column) bool {
		return pr.ColumnHint(t.Name, c.Name) == nil && detect.BinaryIPColumn(t.Name, c.Name)
	}
}

// windowRows is how many rows a table's sample reads. Lookups read each
// key's oldest rows; the window adds the middle and newest ones for keys on
// many rows, such as a nickname every user has. A whole read needs no
// window for its values, nor does a table keyed by data.
func windowRows(opts Options, kv *kvRead) int {
	if kv != nil && kv.mode != modeWhole && !kv.demoted {
		return opts.MetaSampleRows
	}
	return opts.SampleRows
}

var cacheWords = wordSet("cache caches")

// cacheTable reports whether a table's name says it is a cache.
func cacheTable(t *model.Table) bool {
	return anyWord(detect.Tokens(t.Name), cacheWords)
}

// holdsText reports whether a table's sample, or its key/value reads, hold
// at least one filled text value.
func holdsText(s *sample.Sample, kv *kvRead) bool {
	if s != nil {
		for i, c := range s.Columns {
			if !sample.IsText(c) {
				continue
			}
			for _, r := range s.Rows {
				if r[i].Valid && strings.TrimSpace(r[i].String) != "" {
					return true
				}
			}
		}
	}
	if kv != nil {
		for _, rows := range kv.values {
			for _, r := range rows {
				if !r.Null && strings.TrimSpace(r.Value) != "" {
					return true
				}
			}
		}
	}
	return false
}

// weakenDeviceReferences lowers a device ID found on a column that a
// declared or confirmed relationship joins to a parent's primary key named
// id or uuid: such a column most likely references a devices table, as
// user_id does users. The tables' counts are redone.
func weakenDeviceReferences(res *model.Result, schema *model.Schema) {
	parents := map[string]string{}
	for _, r := range res.Relationships {
		if (r.Status != model.RelDeclared && r.Status != model.RelConfirmed) || len(r.ChildColumns) != 1 ||
			len(r.ParentColumns) != 1 {
			continue
		}
		if p := strings.ToLower(r.ParentColumns[0]); p != "id" && p != "uuid" {
			continue
		}
		if pt := schema.Table(r.ParentTable); pt == nil || pt.SinglePK() == nil ||
			!strings.EqualFold(pt.SinglePK().Name, r.ParentColumns[0]) {
			continue
		}
		parents[r.ChildTable+"\x00"+r.ChildColumns[0]] = r.ParentTable + "." + r.ParentColumns[0]
	}
	changed := map[string]bool{}
	for i := range res.Findings {
		f := &res.Findings[i]
		parent, ok := parents[f.Table+"\x00"+f.Column]
		if !ok || f.Category != model.CatDeviceID || f.Confidence == model.ConfidenceLow || f.MetaKey != "" {
			continue
		}
		f.Confidence, f.Severity = model.ConfidenceLow, model.SeverityLow
		note := "a relationship joins this column to " + parent + ": it's likely a reference; if " + parent +
			" holds the device IDs themselves, mask both the same way"
		if f.Note != "" {
			note = f.Note + "; " + note
		}
		f.Note = note
		changed[f.Table] = true
	}
	for i := range res.Tables {
		ts := &res.Tables[i]
		if !changed[ts.Name] {
			continue
		}
		ts.Findings, ts.Highest = 0, model.SeverityNone
		for _, f := range res.Findings {
			if f.Table == ts.Name && f.Confidence > model.ConfidenceLow {
				ts.Findings++
				ts.Highest = max(ts.Highest, f.Severity)
			}
		}
	}
}

func analyzeColumns(t *model.Table, s *sample.Sample, pr *preset.Result, meta *preset.MetaTable) []model.Finding {
	words := detect.Tokens(t.Name)
	pk := t.SinglePK()
	var out []model.Finding
	for _, c := range t.Columns {
		if c.AutoIncrement() || (c == pk && sample.IsInteger(c)) {
			continue
		}
		if meta != nil && (strings.EqualFold(c.Name, meta.Key) || strings.EqualFold(c.Name, meta.Value)) {
			continue
		}
		sub := detect.Subject{
			Table: t.Name, Column: c.Name, Name: c.Name, DataType: c.DataType, Context: words,
			Hint: pr.ColumnHint(t.Name, c.Name),
		}
		var p *detect.Profile
		if s != nil {
			if i := s.Index(c.Name); i >= 0 {
				sub.Sampled = true
				p = detect.NewProfileNamed(c.Name).WithContext(words)
				if s.Hex[i] {
					if !addBinaryIPs(p, s, i) {
						sub.Sampled, p = false, nil // nothing decoded: judged as if unread, as before
					}
				} else {
					for _, row := range s.Rows {
						if row[i].Valid {
							p.Add(row[i].String)
						}
					}
				}
			}
		}
		out = append(out, detect.Analyze(sub, p)...)
	}
	return out
}

// undecoded stands for a binary value that is no address the scanner
// knows; it matches no format.
const undecoded = "(binary)"

// addBinaryIPs adds the decoded values of a binary IP column, read as hex,
// to a profile. The addresses exist only in memory. It reports whether any
// value decoded to an address.
func addBinaryIPs(p *detect.Profile, s *sample.Sample, i int) bool {
	decoded := false
	for _, row := range s.Rows {
		if !row[i].Valid {
			continue
		}
		switch ip, empty, ok := detect.BinaryIP(row[i].String); {
		case empty:
			p.Add("")
		case ok:
			p.Add(ip)
			decoded = true
		default:
			p.Add(undecoded)
		}
	}
	return decoded
}

// rowSubjectRows is how many rows a row subject reads.
const rowSubjectRows = 50

// rowSubjects judges the columns whose data depends on the row, such as
// the titles of WordPress privacy requests. Each runs only when an index
// leads with the column its condition filters on, so no subject needs a
// full scan.
func rowSubjects(ctx context.Context, sm *sample.Sampler, t *model.Table, pr *preset.Result) ([]model.Finding, []string) {
	var (
		out   []model.Finding
		warns []string
	)
	words := detect.Tokens(t.Name)
	for _, rs := range pr.RowSubjects {
		if rs.Table != t.Name {
			continue
		}
		c := t.Column(rs.Column)
		if c == nil {
			continue
		}
		if !t.KeyIndex(rs.IndexColumn).Found {
			warns = append(warns, fmt.Sprintf("skipped the rows where %s in %s: no index on %s", rs.Where, t.Name, rs.IndexColumn))
			continue
		}
		vals, err := sm.Where(ctx, t, c, rs.Where, rowSubjectRows)
		if err != nil {
			warns = append(warns, fmt.Sprintf("could not read the rows where %s in %s (%s)", rs.Where, t.Name, dbconn.ErrorText(err)))
			continue
		}
		if len(vals) == 0 {
			continue
		}
		p := detect.NewProfileNamed(c.Name).WithContext(words)
		for _, v := range vals {
			p.Add(v)
		}
		sub := detect.Subject{Table: t.Name, Column: c.Name, Name: c.Name, DataType: c.DataType, Context: words,
			Hint: rs.Hint, Sampled: true, Where: rs.Where}
		out = append(out, detect.Analyze(sub, p)...)
	}
	return out, warns
}

// Column pairs that make a table a key/value store even without a preset.
var metaPairs = [][2]string{
	{"meta_key", "meta_value"}, {"option_name", "option_value"}, {"setting_key", "setting_value"},
	{"config_key", "config_value"}, {"key", "value"}, {"name", "value"}, {"path", "value"}, {"param", "value"},
}

// vagueKeys are key columns that say little on their own: their table's
// name must have a settings word, and their tables get no key-shape guard.
var vagueKeys = map[string]bool{"name": true, "path": true, "param": true}

var settingsWords = map[string]bool{"meta": true, "metadata": true, "option": true, "options": true,
	"setting": true, "settings": true, "config": true, "configuration": true, "preference": true,
	"preferences": true, "property": true, "properties": true, "attribute": true, "attributes": true}

// entryWords end the X of an X_name key column that names settings or form
// fields, as setting_name and field_name do.
var entryWords = wordSet("config setting settings option options param params parameter parameters property properties " +
	"attribute attributes field fields var vars variable variables meta pref prefs preference preferences")

// labelTableWords mark a translation table's name.
var labelTableWords = wordSet("language languages lang langs translation translations locale locales localization " +
	"localisation phrase phrases lexicon")

func wordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

func anyWord(ws []string, set map[string]bool) bool {
	for _, w := range ws {
		if set[w] {
			return true
		}
	}
	return false
}

// genericMeta recognises a key/value table without a preset: one of the
// usual column pairs; any X_key with an X_value beside it (Ultimate
// Member's um_key and um_value); or an X_name with a text X_value, when X
// names settings or fields. An X keyed by people (member_key, user_name), or
// an X_key or X_name that names data itself (customer_name, license_key),
// keeps its columns. Sessions aren't settings, and a pair a preset already
// describes column by column isn't one either. Binary values are never
// read, so a pair with one isn't a key/value table.
func genericMeta(t *model.Table, pr *preset.Result) *preset.MetaTable {
	tw := detect.Tokens(t.Name)
	settings := anyWord(tw, settingsWords)
	lowerName := strings.ToLower(t.Name)
	labels := !settings && (anyWord(tw, labelTableWords) || strings.Contains(lowerName, "i18n") ||
		strings.Contains(lowerName, "l10n"))
	textKey := func(c *model.Column) bool { return c != nil && (c.DataType == "varchar" || c.DataType == "char") }
	hinted := func(k, v *model.Column) bool {
		return pr != nil && (pr.ColumnHint(t.Name, k.Name) != nil || pr.ColumnHint(t.Name, v.Name) != nil)
	}
	for _, pair := range metaPairs {
		k, v := t.Column(pair[0]), t.Column(pair[1])
		if v == nil || !sample.Sampleable(v) || !textKey(k) || (vagueKeys[pair[0]] && !settings) {
			continue
		}
		return &preset.MetaTable{Key: k.Name, Value: v.Name, Labels: labels, Guard: !vagueKeys[pair[0]]}
	}
	for _, k := range t.Columns {
		lower := strings.ToLower(k.Name)
		var base string
		switch {
		case strings.HasSuffix(lower, "_key"):
			base = k.Name[:len(k.Name)-len("_key")]
		case strings.HasSuffix(lower, "_name"):
			base = k.Name[:len(k.Name)-len("_name")]
		default:
			continue
		}
		v := t.Column(base + "_value")
		if !textKey(k) || v == nil || !sample.Sampleable(v) || strings.EqualFold(base, "session") || hinted(k, v) {
			continue
		}
		bw := detect.Tokens(base)
		if len(bw) == 0 || detect.PeopleWord(bw[len(bw)-1]) {
			continue
		}
		if m := detect.MatchName(detect.NameWords(k.Name), tw, detect.TypeString); m != nil && m.Category != model.CatFreeText {
			continue
		}
		if strings.HasSuffix(lower, "_name") && (!sample.IsText(v) || !(entryWords[bw[len(bw)-1]] || settings)) {
			continue
		}
		return &preset.MetaTable{Key: k.Name, Value: v.Name, Labels: labels, Guard: true}
	}
	return nil
}

func sortRelationships(rels []model.Relationship) {
	rank := map[string]int{model.RelDeclared: 0, model.RelConfirmed: 1, model.RelLikely: 2, model.RelUnverified: 3, model.RelWeak: 4}
	sort.SliceStable(rels, func(i, j int) bool {
		a, b := rels[i], rels[j]
		if rank[a.Status] != rank[b.Status] {
			return rank[a.Status] < rank[b.Status]
		}
		if a.ChildTable != b.ChildTable {
			return a.ChildTable < b.ChildTable
		}
		return strings.Join(a.ChildColumns, ",") < strings.Join(b.ChildColumns, ",")
	})
}

func summarize(res *model.Result, took time.Duration) {
	s := model.Summary{BySeverity: map[string]int{}, ByCategory: map[string]int{}, DurationMillis: took.Milliseconds()}
	tables := map[string]bool{}
	for _, f := range res.Findings {
		if f.Confidence == model.ConfidenceLow {
			continue
		}
		s.Findings++
		s.BySeverity[f.Severity.String()]++
		s.ByCategory[string(f.Category)]++
		tables[f.Table] = true
		if f.Severity > s.Highest {
			s.Highest = f.Severity
		}
	}
	for _, se := range res.SideEffects {
		if se.Severity > s.Highest {
			s.Highest = se.Severity
		}
	}
	for _, t := range res.Tables {
		s.Tables++
		switch {
		case t.Kind == "view":
			s.Views++
		case t.RowsSampled > 0:
			s.TablesSampled++
			s.RowsSampled += int64(t.RowsSampled)
		}
	}
	for _, r := range res.Relationships {
		s.Relationships++
		if r.Status == model.RelConfirmed {
			s.InferredConfirmed++
		}
	}
	s.TablesWithFindings = len(tables)
	s.SideEffects = len(res.SideEffects)
	res.Summary = s
}
