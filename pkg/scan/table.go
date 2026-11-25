package scan

import (
	"context"
	"time"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// tableReads is what a scan reads of one data table: its sample, its
// key/value reads, the rows its row subjects read and the warnings they
// left, and the sample's error, which the caller words.
type tableReads struct {
	s         *sample.Sample
	kv        *kvRead
	rows      []rowRead
	rowWarns  []string
	sampleErr error
}

// readTable reads one data table as Run does: a key/value table's keys when
// it has a meta, the sample, a key/value table's sampled keys, and the row
// subjects. b is the scan's key/value budget.
func readTable(ctx context.Context, sess *dbconn.Session, sampler *sample.Sampler, t *model.Table, meta *preset.MetaTable,
	pr *preset.Result, opts Options, b *budget) tableReads {
	var r tableReads
	if meta != nil {
		r.kv = readKV(ctx, sess, sampler, t, meta, opts, b)
	}
	r.s, r.sampleErr = sampler.Table(ctx, t, windowRows(opts, r.kv))
	if r.kv != nil && r.kv.mode == modeSample && !r.kv.demoted {
		r.kv.sampleKV(ctx, sampler, sess, t, meta, r.s, opts, b)
	}
	r.rows, r.rowWarns = readRowSubjects(ctx, sampler, t, pr)
	return r
}

// KeyValueTable returns how a scan reads the table as key/value: its
// preset's meta, or the scan's own rule for a pair such as meta_key and
// meta_value; nil for a plain table. A table a scan finds keyed by data is
// then judged as a plain one, which JudgeTable's summary says.
func KeyValueTable(t *model.Table, pr *preset.Result) *preset.MetaTable {
	if pr != nil {
		if m := pr.Meta[t.Name]; m != nil {
			return m
		}
	} else {
		pr = &preset.Result{}
	}
	return genericMeta(t, pr)
}

// TableVerdict is one table's judgement as a scan makes it.
type TableVerdict struct {
	Findings []model.Finding
	Summary  model.TableSummary
	// SampleErr is the sample's error. The findings are then by name, the
	// presets' hints and any key/value reads.
	SampleErr error
}

// JudgeTable reads and judges one table with Run's per-table step, on its own, as
// prodmask mcp asks of a table a result column comes from. A key/value
// table is read by sampling (SampleKeysOnly), with a key budget of its own.
// A view, or another table that isn't data, is judged by its columns' names
// and the presets' hints alone: sampling a view runs its query.
func JudgeTable(ctx context.Context, sess *dbconn.Session, pr *preset.Result, t *model.Table, opts Options) TableVerdict {
	if opts.MaxValueLen <= 0 {
		opts.MaxValueLen = DefaultMaxValueLen
	}
	if opts.KeySampleRows <= 0 {
		opts.KeySampleRows = DefaultKeySampleRows
	}
	if opts.SampleRows <= 0 {
		opts.SampleRows = DefaultSampleRows
	}
	if opts.MetaSampleRows <= 0 {
		opts.MetaSampleRows = DefaultMetaSampleRows
	}
	opts.SampleKeysOnly = true
	if pr == nil {
		pr = &preset.Result{}
	}
	ts := model.TableSummary{Name: t.Name, Kind: "table", RowsEstimate: t.RowsEstimate}
	if !t.IsData() {
		return TableVerdict{Findings: analyzeColumns(t, nil, pr, nil), Summary: ts}
	}
	meta := KeyValueTable(t, pr)
	if meta != nil {
		ts.Kind = "key/value"
		ts.KeyColumn, ts.ValueColumn = meta.Key, meta.Value
	}
	var r tableReads
	if opts.Samples {
		sampler := &sample.Sampler{DB: sess.DB, MaxValueLen: opts.MaxValueLen, Timeout: sess.Timeout + 15*time.Second,
			Hex: hexColumn(pr)}
		r = readTable(ctx, sess, sampler, t, meta, pr, opts, newBudget())
		if r.sampleErr != nil {
			ts.Error = dbconn.ErrorText(r.sampleErr)
		}
	}
	res := &model.Result{}
	judgeTable(res, t, ts, meta, r.s, r.kv, r.rows, r.rowWarns, pr, scanLimits)
	return TableVerdict{Findings: res.Findings, Summary: res.Tables[0], SampleErr: r.sampleErr}
}
