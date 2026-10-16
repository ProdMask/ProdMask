// Package scan runs a read-only scan of one database. It reads the schema,
// samples rows, judges every column and meta key, works out how tables link
// up, and lists what a plain copy would let staging do to real people.
package scan

import (
	"context"
	"fmt"
	"regexp"
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
	MetaSampleRows int  // rows per key/value table
	Samples        bool // false judges names only and reads no rows
	Preset         string
	MaxValueLen    int
	Version        string
	Progress       func(done, total int, table string)
}

// Defaults for Options.
const (
	DefaultSampleRows     = 300
	DefaultMetaSampleRows = 3000
	DefaultMaxValueLen    = 4096
	maxMetaKeys           = 2000
	probeRows             = 50
)

// Run scans the database behind the session.
func Run(ctx context.Context, sess *dbconn.Session, opts Options) (*model.Result, error) {
	start := time.Now()
	if opts.MaxValueLen <= 0 {
		opts.MaxValueLen = DefaultMaxValueLen
	}
	res := &model.Result{
		Tool: "prodmask", Version: opts.Version, GeneratedAt: start.UTC().Truncate(time.Second),
		Server: sess.Server, Database: sess.Database,
		Options: model.ScanOptions{
			SampleRows: opts.SampleRows, MetaSampleRows: opts.MetaSampleRows, Samples: opts.Samples,
			Preset: opts.Preset, TimeoutSeconds: sess.Timeout.Seconds(),
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

	sampler := &sample.Sampler{DB: sess.DB, MaxValueLen: opts.MaxValueLen, Timeout: queryTimeout}
	ids := infer.NewIDValues()

	for i, t := range schema.Tables {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if opts.Progress != nil {
			opts.Progress(i, len(schema.Tables), t.Name)
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
		meta := pr.Meta[t.Name]
		if meta == nil {
			meta = genericMeta(t)
		}
		if meta != nil {
			ts.Kind = "key/value"
			ts.KeyColumn, ts.ValueColumn = meta.Key, meta.Value
		}

		var s *sample.Sample
		if opts.Samples {
			limit := opts.SampleRows
			if meta != nil {
				limit = opts.MetaSampleRows
			}
			s, err = sampler.Table(ctx, t, limit)
			if err != nil {
				ts.Error = err.Error()
				res.Warnings = append(res.Warnings, fmt.Sprintf("could not sample %s: %v", t.Name, err))
			}
			if s != nil {
				ts.RowsSampled = len(s.Rows)
				ids.Collect(t, s)
			}
		}

		var findings []model.Finding
		if meta != nil {
			var warns []string
			findings, warns = analyzeMeta(ctx, t, s, meta, sampler)
			res.Warnings = append(res.Warnings, warns...)
		}
		findings = append(findings, analyzeColumns(t, s, pr, meta)...)
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
		opts.Progress(len(schema.Tables), len(schema.Tables), "")
	}

	inf := &infer.Inferrer{Schema: schema, IDs: ids, Prefixes: pr.Prefixes, Known: pr.Relationships}
	rels, warns := infer.Verify(ctx, sess.DB, ids, schema, inf.Relationships(), queryTimeout)
	res.Relationships = rels
	res.Warnings = append(res.Warnings, warns...)

	detect.SortFindings(res.Findings)
	sortRelationships(res.Relationships)
	summarize(res, time.Since(start))
	return res, nil
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
				p = detect.NewProfile()
				for _, row := range s.Rows {
					if row[i].Valid {
						p.Add(row[i].String)
					}
				}
			}
		}
		out = append(out, detect.Analyze(sub, p)...)
	}
	return out
}

// Meta keys are shown in reports, so they must look like labels: keys
// made of other characters could be data themselves.
var reMetaKey = regexp.MustCompile(`^[A-Za-z0-9_.:/ -]{1,64}$`)

// analyzeMeta judges each key of a key/value table as if it were a column.
func analyzeMeta(ctx context.Context, t *model.Table, s *sample.Sample, meta *preset.MetaTable, sm *sample.Sampler) ([]model.Finding, []string) {
	var warnings []string
	groups := map[string]*detect.Profile{}
	if s != nil {
		ki, vi := s.Index(meta.Key), s.Index(meta.Value)
		if ki >= 0 && vi >= 0 {
			for _, row := range s.Rows {
				if !row[ki].Valid {
					continue
				}
				p := groups[row[ki].String]
				if p == nil {
					if len(groups) >= maxMetaKeys {
						continue
					}
					p = detect.NewProfile()
					groups[row[ki].String] = p
				}
				if row[vi].Valid {
					p.Add(row[vi].String)
				}
			}
		}
		// Look known keys up directly when the sample missed them, if the
		// key column is indexed or the table is small.
		keyCol, valueCol := t.Column(meta.Key), t.Column(meta.Value)
		if keyCol != nil && valueCol != nil && (t.HasIndexOn(meta.Key) || t.RowsEstimate < 200000) {
			seen := map[string]bool{}
			for _, k := range meta.Probe {
				if groups[k] != nil || seen[k] {
					continue
				}
				seen[k] = true
				vals, err := sm.KeyValues(ctx, t, keyCol, valueCol, k, probeRows)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("could not read key %s of %s: %v", k, t.Name, err))
					continue
				}
				if len(vals) == 0 {
					continue
				}
				p := detect.NewProfile()
				for _, v := range vals {
					p.Add(v)
				}
				groups[k] = p
			}
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	words := detect.Tokens(t.Name)
	var out []model.Finding
	for _, k := range keys {
		label := k
		if meta.Label != nil {
			label = meta.Label(k)
		}
		shown := label
		if !reMetaKey.MatchString(shown) {
			shown = "(key hidden)"
		}
		sub := detect.Subject{
			Table: t.Name, Column: meta.Value, MetaKey: shown, Name: label, Context: words,
			Hint: meta.Hint(k), Sampled: true,
		}
		out = append(out, detect.Analyze(sub, groups[k])...)
	}
	return out, warnings
}

// Column pairs that make a table a key/value store even without a preset.
var metaPairs = [][2]string{
	{"meta_key", "meta_value"}, {"option_name", "option_value"}, {"setting_key", "setting_value"},
	{"config_key", "config_value"}, {"key", "value"}, {"name", "value"}, {"path", "value"},
}

var settingsWords = map[string]bool{"meta": true, "metadata": true, "option": true, "options": true,
	"setting": true, "settings": true, "config": true, "configuration": true, "preference": true,
	"preferences": true, "property": true, "properties": true, "attribute": true, "attributes": true}

func genericMeta(t *model.Table) *preset.MetaTable {
	words := detect.Tokens(t.Name)
	for _, pair := range metaPairs {
		k, v := t.Column(pair[0]), t.Column(pair[1])
		if k == nil || v == nil || !(k.DataType == "varchar" || k.DataType == "char") {
			continue
		}
		if pair[0] == "name" || pair[0] == "path" {
			ok := false
			for _, w := range words {
				ok = ok || settingsWords[w]
			}
			if !ok {
				continue
			}
		}
		return &preset.MetaTable{Key: k.Name, Value: v.Name}
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
