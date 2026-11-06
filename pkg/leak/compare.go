package leak

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/introspect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// chunkRows is how many rows one statement of a whole read asks for.
const chunkRows = 5000

// CompareOptions control Compare.
type CompareOptions struct {
	Allow      *Allowlist
	FailExcept []string
	// MaxTime is the limit on the whole read; 0 means none.
	MaxTime time.Duration
	Version string
	// Starting says what's about to be read, once it's known.
	Starting func(tables int, rowsEstimate int64)
	// Progress reports the table being read and the rows read so far.
	Progress func(done, total int, table string, rows int64)
}

// target is one column or key on staging, with its kinds.
type target struct {
	file     FileColumn // the first of its file columns, for the names
	wants    wants
	subjects map[model.LeakKind]*subject
	skipped  int64 // values the allowlist kept out
	values   int64 // values read that count
}

// subject is one kind of value in one column or key.
type subject struct {
	col     *model.LeakColumn
	prefix  []byte
	found   map[[hashLen]byte]bool
	lastHit int64 // the row of the last hit, so each row counts once
}

// tableRead is what to read in one staging table.
type tableRead struct {
	name    string // as the file has it
	table   *model.Table
	plain   []*target
	keyed   []*target
	keyCol  *model.Column
	valCol  *model.Column
	columns []*model.LeakColumn
}

// Compare reads on staging the columns a hash file names, whole, and counts
// the sampled values it finds. It reads through sess, a read-only session, and
// never runs detection to choose columns. Only names and counts leave it.
func Compare(ctx context.Context, sess *dbconn.Session, f *File, key Key, opts CompareOptions) (*model.LeakResult, error) {
	start := time.Now()
	if err := f.CheckKey(key); err != nil {
		return nil, err
	}
	schema, err := introspect.Load(ctx, sess.DB, sess.Database)
	if err != nil {
		return nil, err
	}
	res := &model.LeakResult{
		Tool: "prodmask", Version: opts.Version, GeneratedAt: start.UTC().Truncate(time.Second),
		Server: sess.Server, Database: sess.Database,
		Hashes: model.LeakHashesInfo{Database: f.Database, CreatedAt: f.CreatedAt, ToolVersion: f.ToolVersion, SampleRows: f.SampleRows},
		Limits: report.LeakLimits(f.SampleRows), Warnings: slices.Clone(sess.Warnings),
	}
	for _, w := range f.Warnings {
		res.Warnings = append(res.Warnings, "on production: "+w)
	}
	res.Columns = make([]model.LeakColumn, len(f.Columns))
	reads := groupColumns(schema, f, key, res.Columns)

	domains := slices.Clone(f.AllowDomains)
	addresses := f.AllowedAddresses
	if opts.Allow != nil {
		for _, d := range opts.Allow.Domains {
			if !slices.Contains(domains, d) {
				domains = append(domains, d)
			}
		}
		addresses += opts.Allow.Addresses()
	}
	allow := &Allowlist{Domains: domains}
	if opts.Allow != nil {
		allow.addresses = opts.Allow.addresses
	}
	ex := newExtractor(allow)
	hs := key.hasher(f.Salt)

	sm := &sample.Sampler{DB: sess.DB, MaxValueLen: 0, Timeout: sess.Timeout + 15*time.Second}
	readCtx := ctx
	if opts.MaxTime > 0 {
		var cancel context.CancelFunc
		readCtx, cancel = context.WithTimeout(ctx, opts.MaxTime)
		defer cancel()
	}

	// The smallest first, so a time limit costs the fewest columns.
	var ready []*tableRead
	var rowsAhead int64
	for _, r := range reads {
		if r.table != nil && (len(r.plain) > 0 || len(r.keyed) > 0) {
			ready = append(ready, r)
			rowsAhead += r.table.RowsEstimate
		}
	}
	sort.SliceStable(ready, func(i, j int) bool { return ready[i].table.RowsEstimate < ready[j].table.RowsEstimate })
	if opts.Starting != nil {
		opts.Starting(len(ready), rowsAhead)
	}
	for i, r := range ready {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if readCtx.Err() != nil {
			setState(r.columns, model.LeakNotRead, "--max-time", 0)
			continue
		}
		var prog func(int64)
		if opts.Progress != nil {
			opts.Progress(i, len(ready), r.table.Name, 0)
			prog = func(rows int64) { opts.Progress(i, len(ready), r.table.Name, rows) }
		}
		read, err := readTable(readCtx, sm, r, ex, hs, prog)
		switch {
		case err == nil:
			setState(r.columns, model.LeakRead, "", read)
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case readCtx.Err() != nil:
			setState(r.columns, model.LeakStopped, "--max-time", read)
		default:
			setState(r.columns, model.LeakStopped, dbconn.ErrorText(err), read)
		}
		for _, t := range append(slices.Clone(r.plain), r.keyed...) {
			for _, s := range t.subjects {
				s.col.Found = countFound(s)
			}
			if s := t.subjects[model.LeakEmail]; s != nil {
				s.col.ValuesSkipped = t.skipped
			}
			if w := allowWarning(model.LeakLocation(t.file.Table, t.file.Column, t.file.MetaKey), t.skipped, t.values); w != "" {
				res.Warnings = append(res.Warnings, w)
			}
		}
	}
	if opts.Progress != nil {
		opts.Progress(len(ready), len(ready), "", 0)
	}

	res.LeftOut = slices.Clone(f.LeftOut)
	for i := range res.Columns {
		c := &res.Columns[i]
		fillOdds(c)
		c.Line = report.LeakLine(*c)
	}
	applyExcept(res, opts.FailExcept)
	res.Allowed = model.LeakAllowed{Domains: domains, Addresses: addresses, ValuesSkipped: f.ValuesSkipped + ex.skipped}
	summarize(res, time.Since(start))
	return res, nil
}

// groupColumns sets out the file's columns as what to read in each table, and
// fills in each column's state where staging's schema already settles it.
func groupColumns(schema *model.Schema, f *File, key Key, out []model.LeakColumn) []*tableRead {
	hs := key.hasher(f.Salt)
	reads := map[string]*tableRead{}
	var order []*tableRead
	targets := map[string]*target{}
	for i, fc := range f.Columns {
		c := &out[i]
		*c = model.LeakColumn{
			Table: fc.Table, Column: fc.Column, MetaKey: fc.MetaKey, Kind: fc.Kind, Severity: fc.Kind.Severity(),
			State: model.LeakRead, Sample: fc.Sample, Exact: fc.Exact, Sampled: fc.Values, EstimatedValues: fc.EstimatedValues,
		}
		r := reads[fc.Table]
		if r == nil {
			r = &tableRead{name: fc.Table, table: findTable(schema, fc.Table)}
			reads[fc.Table] = r
			order = append(order, r)
		}
		r.columns = append(r.columns, c)
		if r.table != nil {
			c.RowsEstimate = r.table.RowsEstimate
		}
		if state := columnState(r.table, fc); state != "" {
			c.State = state
			continue
		}
		loc := model.LeakLocation(fc.Table, fc.Column, fc.MetaKey)
		t := targets[loc]
		if t == nil {
			t = &target{file: fc, subjects: map[model.LeakKind]*subject{}}
			targets[loc] = t
			if fc.MetaKey == "" {
				r.plain = append(r.plain, t)
			} else {
				r.keyed = append(r.keyed, t)
				r.keyCol, r.valCol = r.table.Column(fc.KeyColumn), r.table.Column(fc.Column)
			}
		}
		if fc.Whole {
			if fc.Kind == model.LeakPhone {
				t.wants.loosePhone = true
			} else {
				t.wants.whole = append(t.wants.whole, fc.Kind)
			}
		}
		s := &subject{col: c, prefix: hs.prefix(fc.Table, fc.Column, fc.MetaKey, fc.Kind), found: make(map[[hashLen]byte]bool, fc.Values)}
		for b := fc.Hashes; len(b) > 0; b = b[hashLen:] {
			s.found[[hashLen]byte(b[:hashLen])] = false
		}
		t.subjects[fc.Kind] = s
	}
	return order
}

// findTable finds a table on staging, whose name's letter case may differ from
// production's on another system.
func findTable(schema *model.Schema, name string) *model.Table {
	if t := schema.Table(name); t != nil {
		return t
	}
	for _, t := range schema.Tables {
		if strings.EqualFold(t.Name, name) {
			return t
		}
	}
	return nil
}

// columnState is a column's state where the schema already settles it, or "".
func columnState(t *model.Table, fc FileColumn) string {
	if t == nil {
		return model.LeakNotOnStaging
	}
	if !t.IsData() {
		return model.LeakUnreadable
	}
	c := t.Column(fc.Column)
	if c == nil {
		return model.LeakNotOnStaging
	}
	if !sample.Sampleable(c) {
		return model.LeakUnreadable
	}
	if fc.MetaKey != "" {
		k := t.Column(fc.KeyColumn)
		if k == nil {
			return model.LeakNotOnStaging
		}
		if !sample.IsText(k) {
			return model.LeakUnreadable
		}
	}
	return ""
}

func setState(cols []*model.LeakColumn, state, by string, read int64) {
	for _, c := range cols {
		if c.State == model.LeakRead {
			c.State, c.StoppedBy, c.RowsRead = state, by, read
		}
	}
}

// readTable reads one table whole and looks every value it finds up. Nothing
// it reads outlives the row.
func readTable(ctx context.Context, sm *sample.Sampler, r *tableRead, ex *extractor, hs *hasher, progress func(int64)) (int64, error) {
	exprs := make([]string, 0, len(r.plain)+2)
	for _, t := range r.plain {
		exprs = append(exprs, sample.ValueExpr(r.table.Column(t.file.Column), t.file.MaxChars))
	}
	var args []any
	var match *keyMatcher
	keyAt := len(exprs)
	if len(r.keyed) > 0 {
		keys := make([]string, len(r.keyed))
		for i, t := range r.keyed {
			keys[i] = t.file.MetaKey
		}
		keyExpr, valueExpr, a := keyedExprs(r.keyCol, r.valCol, r.keyed[0].file.MaxChars, keys)
		exprs = append(exprs, keyExpr, valueExpr)
		args = a
		match = newKeyMatcher(keys)
	}
	var rowNo int64
	read, err := sm.Whole(ctx, r.table, exprs, args, chunkRows, func(row []sql.RawBytes) error {
		rowNo++
		if progress != nil && rowNo%chunkRows == 0 {
			progress(rowNo)
		}
		for i, t := range r.plain {
			if row[i] != nil {
				look(t, string(row[i]), rowNo, ex, hs)
			}
		}
		if match != nil && row[keyAt] != nil && row[keyAt+1] != nil {
			if i := match.match(string(row[keyAt])); i >= 0 {
				look(r.keyed[i], string(row[keyAt+1]), rowNo, ex, hs)
			}
		}
		return nil
	})
	return read, err
}

// look reads one value and counts what it holds.
func look(t *target, v string, rowNo int64, ex *extractor, hs *hasher) {
	before := ex.skipped
	defer func() { t.skipped += ex.skipped - before }()
	ex.values(v, &t.wants, func(k model.LeakKind, norm string) {
		t.values++
		s := t.subjects[k]
		if s == nil {
			return
		}
		s.col.Values++
		sum := hs.of(s.prefix, norm)
		if _, ok := s.found[sum]; ok {
			s.found[sum] = true
			if s.lastHit != rowNo {
				s.lastHit = rowNo
				s.col.Rows++
			}
		}
	})
}

// countFound counts the sampled values that turned up.
func countFound(s *subject) int {
	n := 0
	for _, hit := range s.found {
		if hit {
			n++
		}
	}
	return n
}

// applyExcept marks what --fail-except covers, and warns of a value that
// covers nothing, by its position: a value may be a secret typed in the wrong
// place.
func applyExcept(res *model.LeakResult, except []string) {
	for i, e := range except {
		used := false
		for j := range res.Columns {
			if model.LeakExcept(e, res.Columns[j].Location()) {
				res.Columns[j].Excepted = true
				used = true
			}
		}
		for j := range res.LeftOut {
			if model.LeakExcept(e, res.LeftOut[j].Location) {
				res.LeftOut[j].Excepted = true
				used = true
			}
		}
		if !used {
			res.Warnings = append(res.Warnings, fmt.Sprintf("--fail-except value %d matches no column in the hash file", i+1))
		}
	}
}

func summarize(res *model.LeakResult, took time.Duration) {
	s := model.LeakSummary{Columns: len(res.Columns), DurationMillis: took.Milliseconds()}
	tables := map[string]int64{}
	for _, c := range res.Columns {
		if c.State == model.LeakRead || c.State == model.LeakStopped {
			tables[c.Table] = c.RowsRead
		}
		if c.Found > 0 && c.Severity > s.Highest {
			s.Highest = c.Severity
		}
		switch c.State {
		case model.LeakRead:
			s.ColumnsRead++
			s.Sampled += int64(c.Sampled)
			s.Found += int64(c.Found)
			if c.Found > 0 {
				s.ColumnsWithHit++
			}
		case model.LeakStopped:
			s.SampledInPart += int64(c.Sampled)
			s.FoundInPart += int64(c.Found)
		}
	}
	for _, n := range tables {
		s.RowsRead += n
	}
	s.NothingRead = s.ColumnsRead == 0 && s.RowsRead == 0
	res.Summary = s
}

// Gate says how a check stands against --fail-on: how many columns at or above
// the threshold, not excepted, hold a sampled value, and how many couldn't be
// checked in full. A hit counts in a stopped column too. A gate fails closed
// whenever it couldn't look, which includes a column renamed on staging, since
// hashes are bound to their location. A column left out on production for a
// reason a rerun might cure counts at any threshold, as it has no kind.
func Gate(res *model.LeakResult, threshold model.Severity) (hits, unchecked int) {
	for _, c := range res.Columns {
		if c.Excepted || c.Severity < threshold {
			continue
		}
		switch {
		case c.Found > 0:
			hits++
		case c.State != model.LeakRead, c.Sample == model.SampleCut:
			unchecked++
		}
	}
	for _, l := range res.LeftOut {
		if l.NotRead && !l.Excepted {
			unchecked++
		}
	}
	return hits, unchecked
}
