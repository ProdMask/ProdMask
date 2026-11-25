package scan

import (
	"context"
	"fmt"
	"slices"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// keyLimits are the limits on a key/value table's reads that the skipped-keys
// warning quotes.
type keyLimits struct {
	TableKeys  int
	TableBytes int64
	ScanKeys   int
	ScanBytes  int64
}

// scanLimits are the limits a scan reads key/value tables under.
var scanLimits = keyLimits{TableKeys: tableKeys, TableBytes: tableBytes, ScanKeys: scanKeys, ScanBytes: scanBytes}

// rowRead is what one row subject read: the values of its column where its
// condition holds.
type rowRead struct {
	Subject preset.RowSubject
	Column  *model.Column
	Values  []string
}

// judgeTable judges one data table from what was read of it: its sample s, its
// key/value reads kv (nil for a plain table), and the rows its row subjects
// read, with the warnings that reading left. It takes no session or sampler,
// so the values may come from anywhere. ts holds the summary so far (name,
// kind, estimate, action and any read error); the table's findings and its
// finished summary row are appended to res, and its warnings too.
func judgeTable(res *model.Result, t *model.Table, ts model.TableSummary, meta *preset.MetaTable, s *sample.Sample,
	kv *kvRead, rows []rowRead, rowWarns []string, pr *preset.Result, lim keyLimits) {
	var keyNames *model.Finding
	if s != nil {
		ts.RowsSampled = len(s.Rows)
	}
	if kv != nil {
		ts.RowsSampled += kv.rows
		ts.ReadFailed = len(kv.failures()) > 0
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

	var findings []model.Finding
	if kv != nil {
		var hidden int
		findings, hidden = analyzeKV(t, s, meta, kv)
		ts.Keys = len(kv.keys)
		if n, named := skippedSummary(t, meta, kv); n > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%d keys of %s were not sampled (limits: %d keys and %d MB per table, "+
				"%d keys and %d MB per scan); %d of them match names and are listed at low confidence in the JSON report",
				n, t.Name, lim.TableKeys, lim.TableBytes>>20, lim.ScanKeys, lim.ScanBytes>>20, named))
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
	findings = append(findings, judgeRowSubjects(t, rows)...)
	res.Warnings = append(res.Warnings, rowWarns...)
	hashUnique(t, findings)
	fitFakes(t, findings)
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

// rowSubjectRows is how many rows a row subject reads.
const rowSubjectRows = 50

// readRowSubjects reads the columns whose data depends on the row, such as
// the titles of WordPress privacy requests. Each runs only when an index
// leads with the column its condition filters on, so no subject needs a
// full scan. It returns what was read and the warnings for what wasn't.
func readRowSubjects(ctx context.Context, sm *sample.Sampler, t *model.Table, pr *preset.Result) ([]rowRead, []string) {
	var (
		out   []rowRead
		warns []string
	)
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
		out = append(out, rowRead{Subject: rs, Column: c, Values: vals})
	}
	return out, warns
}

// judgeRowSubjects judges what the row subjects read.
func judgeRowSubjects(t *model.Table, rows []rowRead) []model.Finding {
	var out []model.Finding
	words := detect.Tokens(t.Name)
	for _, r := range rows {
		c := r.Column
		p := detect.NewProfileNamed(c.Name).WithContext(words)
		for _, v := range r.Values {
			p.Add(v)
		}
		sub := detect.Subject{Table: t.Name, Column: c.Name, Name: c.Name, DataType: c.DataType, Context: words,
			Hint: r.Subject.Hint, Sampled: true, Where: r.Subject.Where}
		out = append(out, detect.Analyze(sub, p)...)
	}
	return out
}
