package leak

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/introspect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// DefaultSampleRows is how many rows a check samples per table, and values per
// key of a key/value table. It has no flag: a bigger sample is what would move
// the free check towards the exact one in Pro, and a smaller one says too
// little. 3,000 values out of 100,000 catch 50 real rows about 78% of the time;
// 300 would catch them 14% of the time.
const DefaultSampleRows = 3000

const (
	kvRowsPerPoint = 10       // rows of keys read at each point of a key/value table
	thinKey        = 300      // a key with fewer values gets one indexed lookup
	kvValueBatch   = 500      // values read by primary key in one statement
	lookupBytes    = 32 << 20 // bytes of values a table's lookups may read
	settingsChars  = 65536    // characters read of a value of a key/value table with a unique key column, as scan reads
	allowedShare   = 0.2      // above this share of a column's values, an allowlist gets a warning
	allowedAtLeast = 20       // and with at least this many values
)

// HashOptions control Hash.
type HashOptions struct {
	Allow      *Allowlist
	Preset     string
	Version    string
	SampleRows int // 0 means DefaultSampleRows; only tests set it
	// ScanProgress and Progress report the scan and then the sampling.
	ScanProgress func(done, total int, table string)
	Progress     func(done, total int, table string)
	// Pick picks a number below n, where a sample needs a random spot; nil
	// picks at random. Only tests set it.
	Pick func(n uint64) uint64
}

// source is one flagged column or key on production.
type source struct {
	table, column, metaKey, keyColumn string

	wants    wants
	maxChars int
	kinds    map[model.LeakKind]*kindSample
	// counted says a finding says the column may hold a counted kind, or text
	// that could. Otherwise, a column with no values says nothing is wrong.
	counted bool
	cards   bool

	sample        string
	exact         bool
	rowsRead      int64           // rows read at the points, of any key
	keyRows       int64           // of those, rows of this key
	picked        int64           // of those, rows whose values were read
	seen          map[string]bool // primary keys read, so a lookup adds none twice
	rowsValued    int             // rows whose values were read, so a key's sample can be judged thin
	addressesSkip int64           // values the allowlist kept out
	values        int64           // values read that count
}

type kindSample struct {
	prefix     []byte
	hashes     map[[hashLen]byte]struct{}
	fromPoints int // distinct values once the points were read
}

func (s *source) location() string { return model.LeakLocation(s.table, s.column, s.metaKey) }

// plan is what to sample in one table.
type plan struct {
	table          *model.Table
	plain          []*source
	keyed          []*source
	keyCol, valCol *model.Column
	valueChars     int
}

// Hash runs a scan of production, samples the columns it flags, and returns
// the hash file, with warnings to show. It reads through sess, a read-only
// session, and what it reads stays in memory.
func Hash(ctx context.Context, sess *dbconn.Session, key Key, opts HashOptions) (*File, []string, error) {
	if opts.SampleRows <= 0 {
		opts.SampleRows = DefaultSampleRows
	}
	res, err := scan.Run(ctx, sess, scan.Options{
		SampleRows: scan.DefaultSampleRows, MetaSampleRows: scan.DefaultMetaSampleRows, Samples: true,
		Preset: opts.Preset, Version: opts.Version, Progress: opts.ScanProgress,
	})
	if err != nil {
		return nil, nil, err
	}
	schema, err := introspect.Load(ctx, sess.DB, sess.Database)
	if err != nil {
		return nil, nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	f := &File{
		Format: fileFormat, Version: fileVersion, Notice: fileNotice, ToolVersion: opts.Version,
		CreatedAt: time.Now().UTC().Truncate(time.Second), Database: sess.Database,
		Salt: salt, KeyCheck: key.keyCheck(salt), SampleRows: opts.SampleRows,
	}
	if opts.Allow != nil {
		f.AllowDomains = slices.Clone(opts.Allow.Domains)
		f.AllowedAddresses = opts.Allow.Addresses()
	}
	plans, leftOut := planSample(res, schema)
	f.LeftOut = leftOut
	r := &hashRun{
		sampler: &sample.Sampler{DB: sess.DB, MaxValueLen: scan.DefaultMaxValueLen, Timeout: sess.Timeout + 15*time.Second},
		ex:      newExtractor(opts.Allow), hs: key.hasher(salt), n: opts.SampleRows, pick: opts.Pick,
		file: f,
	}
	for i, p := range plans {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if opts.Progress != nil {
			opts.Progress(i, len(plans), p.table.Name)
		}
		if err := r.sampleTable(ctx, p); err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			r.warnings = append(r.warnings, fmt.Sprintf("could not sample all of %s (%s)", p.table.Name, dbconn.ErrorText(err)))
		}
		r.finishTable(p)
	}
	if opts.Progress != nil {
		opts.Progress(len(plans), len(plans), "")
	}
	sort.Slice(f.LeftOut, func(i, j int) bool { return f.LeftOut[i].Location < f.LeftOut[j].Location })
	sort.SliceStable(f.Columns, func(i, j int) bool {
		a, b := f.Columns[i], f.Columns[j]
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.MetaKey < b.MetaKey
	})
	f.ValuesSkipped = r.ex.skipped
	// The file carries the sample's own warnings to the report. The scan's stay
	// here: they're about the scan, side effects included, and a read of a
	// table that failed is in LeftOut anyway.
	f.Warnings = r.warnings
	warnings := append(slices.Clone(res.Warnings), r.warnings...)
	if len(f.Columns) == 0 {
		// An empty file would only produce a comforting zero.
		if slices.ContainsFunc(f.LeftOut, func(l model.LeakLeftOut) bool { return l.NotRead }) {
			return nil, warnings, ErrNothingSampled
		}
		return nil, warnings, ErrNothingToHash
	}
	return f, warnings, nil
}

// wholeKind returns the kind a finding on a column says a whole value may be.
// A finding on a JSON path keeps the blob's column, so it says nothing about a
// whole value: an identical settings blob holding only test keys would read as
// a live secret. A secret needs a high severity for the same reason: below it
// the scan saw only test keys.
func wholeKind(f model.Finding) (model.LeakKind, bool) {
	switch f.Category {
	case model.CatNationalID:
		return model.LeakNationalID, true
	case model.CatPaymentToken:
		return model.LeakPaymentToken, true
	case model.CatPasswordHash:
		return model.LeakPasswordHash, true
	case model.CatSecret:
		return model.LeakSecret, f.Severity >= model.SeverityHigh
	}
	return "", false
}

// countedCategory says a finding's column may hold a counted kind, or text
// that could.
func countedCategory(c model.Category) bool {
	switch c {
	case model.CatEmail, model.CatPhone, model.CatBankAccount, model.CatNationalID, model.CatPaymentToken,
		model.CatPasswordHash, model.CatSecret, model.CatFreeText, model.CatSessionData:
		return true
	}
	return false
}

// planSample turns a scan's findings into what to sample in each table, and
// what is left out and why.
func planSample(res *model.Result, schema *model.Schema) ([]*plan, []model.LeakLeftOut) {
	summaries := map[string]model.TableSummary{}
	for _, ts := range res.Tables {
		summaries[ts.Name] = ts
	}
	var leftOut []model.LeakLeftOut
	seenOut := map[string]bool{}
	left := func(loc, why string, notRead bool) {
		if !seenOut[loc+"\x00"+why] {
			seenOut[loc+"\x00"+why] = true
			leftOut = append(leftOut, model.LeakLeftOut{Location: loc, Why: why, NotRead: notRead})
		}
	}
	for _, ts := range res.Tables {
		if ts.Error != "" || ts.ReadFailed {
			left(ts.Name, "the scan could not read all of this table", true)
		}
	}
	plans := map[string]*plan{}
	sources := map[string]*source{}
	for _, f := range res.Findings {
		if f.Confidence == model.ConfidenceLow {
			continue
		}
		loc := model.LeakLocation(f.Table, f.Column, f.MetaKey)
		switch {
		case f.KeyName:
			left(loc, "a finding about key names, which aren't read", false)
			continue
		case f.Where != "":
			left(loc, "a finding about some rows only", false)
			continue
		case f.MetaKey == detect.HiddenKey:
			left(loc, "a key whose name can't be shown", false)
			continue
		}
		t := schema.Table(f.Table)
		c := (*model.Column)(nil)
		if t != nil {
			c = t.Column(f.Column)
		}
		if c == nil {
			left(loc, "could not be sampled", true)
			continue
		}
		if !sample.Sampleable(c) {
			left(loc, "a binary column, which isn't read", false)
			continue
		}
		var kc *model.Column
		if f.MetaKey != "" {
			kc = t.Column(summaries[f.Table].KeyColumn)
			if kc == nil || !sample.IsText(kc) {
				left(loc, "a key/value table whose keys are stored as numbers", false)
				continue
			}
		}
		p := plans[f.Table]
		if p == nil {
			p = &plan{table: t, valueChars: scan.DefaultMaxValueLen}
			plans[f.Table] = p
		}
		s := sources[loc]
		if s == nil {
			s = &source{table: f.Table, column: f.Column, metaKey: f.MetaKey, maxChars: scan.DefaultMaxValueLen,
				kinds: map[model.LeakKind]*kindSample{}, seen: map[string]bool{}}
			sources[loc] = s
			if f.MetaKey == "" {
				p.plain = append(p.plain, s)
			} else {
				s.keyColumn = kc.Name
				p.keyed = append(p.keyed, s)
				p.keyCol, p.valCol = kc, c
				if t.KeyIndex(kc.Name).Unique {
					s.maxChars, p.valueChars = settingsChars, settingsChars
				}
			}
		}
		s.counted = s.counted || countedCategory(f.Category)
		s.cards = s.cards || f.Category == model.CatCardNumber
		if f.Path == "" {
			if f.Category == model.CatPhone {
				s.wants.loosePhone = true
			}
			if k, ok := wholeKind(f); ok && !slices.Contains(s.wants.whole, k) {
				s.wants.whole = append(s.wants.whole, k)
			}
		}
	}
	out := make([]*plan, 0, len(plans))
	for _, p := range plans {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].table.Name < out[j].table.Name })
	return out, leftOut
}

// hashRun is the state of one run of Hash.
type hashRun struct {
	sampler  *sample.Sampler
	ex       *extractor
	hs       *hasher
	n        int
	pick     func(n uint64) uint64
	file     *File
	warnings []string
}

// add reads one value of a source.
func (r *hashRun) add(s *source, v string) {
	before := r.ex.skipped
	r.ex.values(v, &s.wants, func(k model.LeakKind, norm string) {
		ks := s.kinds[k]
		if ks == nil {
			ks = &kindSample{prefix: r.hs.prefix(s.table, s.column, s.metaKey, k), hashes: map[[hashLen]byte]struct{}{}}
			s.kinds[k] = ks
		}
		ks.hashes[r.hs.of(ks.prefix, norm)] = struct{}{}
		s.values++
	})
	s.addressesSkip += r.ex.skipped - before
}

// sampleTable reads a table's sample. It returns the error that cut it short,
// if any: the sample so far stays, marked so.
func (r *hashRun) sampleTable(ctx context.Context, p *plan) error {
	exprs := make([]string, 0, len(p.plain)+1)
	for _, s := range p.plain {
		c := p.table.Column(s.column)
		exprs = append(exprs, sample.ValueExpr(c, s.maxChars))
	}
	var err error
	switch {
	case len(p.keyed) == 0:
		err = r.samplePlain(ctx, p, exprs)
	case sample.IntegerPK(p.table) != nil:
		err = r.sampleKeyed(ctx, p, exprs)
	default:
		err = r.sampleKeyedInline(ctx, p, exprs)
	}
	if err != nil {
		for _, s := range append(slices.Clone(p.plain), p.keyed...) {
			s.sample, s.exact = model.SampleCut, false
		}
	}
	return err
}

// samplePlain samples a table with no flagged keys: one row per point.
func (r *hashRun) samplePlain(ctx context.Context, p *plan, exprs []string) error {
	res, err := r.sampler.Spread(ctx, p.table, exprs, nil, r.n, 1, r.pick)
	for _, row := range res.Rows {
		for i, s := range p.plain {
			if row.Values[i].Valid {
				r.add(s, row.Values[i].String)
			}
		}
	}
	for _, s := range p.plain {
		s.sample = res.Method
		s.exact = res.Method == model.SampleAllRows
		s.rowsRead, s.keyRows, s.picked = int64(len(res.Rows)), int64(len(res.Rows)), int64(len(res.Rows))
		s.notePoints()
	}
	return err
}

// sampleKeyed samples a table with flagged keys and an integer primary key.
// The points read primary keys and keys only, 10 rows each; the values of the
// flagged rows come after, by primary key, at most one per key per point, so a
// key on every row reads like a plain column.
func (r *hashRun) sampleKeyed(ctx context.Context, p *plan, plainExprs []string) error {
	exprs := append([]string{sample.QuoteIdent(p.keyCol.Name)}, plainExprs...)
	res, err := r.sampler.Spread(ctx, p.table, exprs, nil, r.n, kvRowsPerPoint, r.pick)
	match := newKeyMatcher(metaKeys(p.keyed))
	type pick struct {
		s  *source
		pk string
	}
	var picks []pick
	picked := map[string]bool{}
	lastPoint := -1
	for _, row := range res.Rows {
		if row.Point != lastPoint {
			lastPoint = row.Point
			for i, s := range p.plain {
				if v := row.Values[i+1]; v.Valid {
					r.add(s, v.String)
				}
				s.picked++
			}
		}
		if !row.Values[0].Valid {
			continue
		}
		i := match.match(row.Values[0].String)
		if i < 0 {
			continue
		}
		s := p.keyed[i]
		s.keyRows++
		// A table read whole has one row per point, so this keeps them all.
		if id := s.location() + "\x00" + strconv.Itoa(row.Point); !picked[id] {
			picked[id] = true
			picks = append(picks, pick{s, row.PK})
			s.picked++
		}
	}
	for _, s := range p.plain {
		s.sample, s.exact = res.Method, res.Method == model.SampleAllRows
		s.rowsRead, s.keyRows = s.picked, s.picked
		s.notePoints()
	}
	// A table read whole can hold more rows of a key than the sample. An even
	// pick of them will do, and the count is no longer exact.
	byKey := map[*source][]string{}
	for _, pk := range picks {
		byKey[pk.s] = append(byKey[pk.s], pk.pk)
	}
	var ids []string
	owner := map[string]*source{}
	for _, s := range p.keyed {
		s.sample, s.exact = res.Method, res.Method == model.SampleAllRows
		s.rowsRead = int64(len(res.Rows))
		list := byKey[s]
		if len(list) > r.n {
			s.exact = false
			thinned := make([]string, r.n)
			for i := range thinned {
				thinned[i] = list[i*len(list)/r.n]
			}
			list = thinned
			s.picked = int64(r.n)
			s.sample = model.SampleSpread
		}
		for _, id := range list {
			ids = append(ids, id)
			owner[id] = s
		}
	}
	verr := r.valuesByPK(ctx, p, ids, owner)
	for _, s := range p.keyed {
		s.notePoints()
	}
	if err == nil {
		err = verr
	}
	if err != nil {
		return err
	}
	return r.lookThinKeys(ctx, p, match)
}

// valuesByPK reads the values of flagged rows by primary key, whose values are
// numbers parsed here, never text from the database.
func (r *hashRun) valuesByPK(ctx context.Context, p *plan, ids []string, owner map[string]*source) error {
	pk := sample.IntegerPK(p.table)
	for start := 0; start < len(ids); start += kvValueBatch {
		part := ids[start:min(start+kvValueBatch, len(ids))]
		rows, err := r.sampler.ValuesByPK(ctx, p.table, pk, p.valCol, p.valueChars, part)
		for _, row := range rows {
			s := owner[row.PK]
			if s == nil || !row.Valid {
				continue
			}
			s.seen[row.PK] = true
			s.rowsValued++
			r.add(s, row.Value)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// lookThinKeys gives a key left with few values one indexed lookup, so a rare
// key still has a sample. A lookup that reaches the key's end has read all its
// values. One that doesn't has read its oldest, which is no spread sample. With
// no index on the key column, a lookup would be a full scan of production, so
// there's none: the key keeps what the points found, and finishTable lists one
// they missed as not read.
func (r *hashRun) lookThinKeys(ctx context.Context, p *plan, match *keyMatcher) error {
	if !p.table.KeyIndex(p.keyCol.Name).Found {
		return nil
	}
	var lookups []sample.Lookup
	var owners []*source
	for _, s := range p.keyed {
		if s.exact || s.rowsValued >= min(thinKey, r.n) {
			continue
		}
		l, ok := lookupOf(s.metaKey)
		if !ok {
			continue
		}
		lookups = append(lookups, l)
		owners = append(owners, s)
	}
	if len(lookups) == 0 {
		return nil
	}
	got, err := r.sampler.KeyValuesBatch(ctx, p.table, p.keyCol, p.valCol, lookups, p.valueChars, lookupBytes)
	for i, s := range owners {
		rows := got.Rows[i]
		for _, kv := range rows {
			if kv.Null {
				continue
			}
			// A pattern's lookup can find a key a more exact rule owns. That
			// key has a sample of its own, unless it's thin: then these rows
			// are its oldest too, so it's no spread sample.
			to := s
			if j := match.match(kv.Key); j >= 0 {
				to = p.keyed[j]
			}
			if to != s {
				if to.exact || to.rowsValued >= min(thinKey, r.n) {
					continue
				}
				to.sample = model.SampleFirstRows
			}
			if kv.PK != "" {
				if to.seen[kv.PK] {
					continue
				}
				to.seen[kv.PK] = true
			}
			to.rowsValued++
			r.add(to, kv.Value)
		}
		switch {
		case !got.Complete[i]:
			s.sample, s.exact = model.SampleCut, false
		case len(rows) < thinKey:
			s.sample, s.exact = model.SampleAllRows, true
		default:
			s.sample, s.exact = model.SampleFirstRows, false
		}
	}
	if err != nil && ctx.Err() == nil {
		// The keys it finished, and the others' spread samples, still stand.
		r.warnings = append(r.warnings, fmt.Sprintf("could not look up all the rare keys of %s (%s)", p.table.Name, dbconn.ErrorText(err)))
		return nil
	}
	return err
}

// sampleKeyedInline samples a table with flagged keys and no integer primary
// key: its first rows, with the values of the flagged ones in the same read.
func (r *hashRun) sampleKeyedInline(ctx context.Context, p *plan, plainExprs []string) error {
	keyExpr, valueExpr, args := keyedExprs(p.keyCol, p.valCol, p.valueChars, metaKeys(p.keyed))
	exprs := append([]string{keyExpr, valueExpr}, plainExprs...)
	res, err := r.sampler.Spread(ctx, p.table, exprs, args, r.n, kvRowsPerPoint, r.pick)
	match := newKeyMatcher(metaKeys(p.keyed))
	for _, row := range res.Rows {
		for i, s := range p.plain {
			if v := row.Values[i+2]; v.Valid {
				r.add(s, v.String)
			}
			s.picked++
		}
		if !row.Values[0].Valid {
			continue
		}
		if i := match.match(row.Values[0].String); i >= 0 {
			s := p.keyed[i]
			s.keyRows++
			s.picked++
			if row.Values[1].Valid {
				s.rowsValued++
				r.add(s, row.Values[1].String)
			}
		}
	}
	for _, s := range append(slices.Clone(p.plain), p.keyed...) {
		s.sample = res.Method
		s.exact = res.Method == model.SampleAllRows
		s.rowsRead = int64(len(res.Rows))
		if slices.Contains(p.plain, s) {
			s.keyRows = s.picked
		}
		s.notePoints()
	}
	if err != nil {
		return err
	}
	return r.lookThinKeys(ctx, p, match)
}

// notePoints records how many distinct values the points gave, the only part
// of a sample that says anything about the whole column.
func (s *source) notePoints() {
	for _, ks := range s.kinds {
		ks.fromPoints = len(ks.hashes)
	}
}

// finishTable adds a table's sampled sources to the file, and what yielded
// nothing to what's left out.
func (r *hashRun) finishTable(p *plan) {
	f := r.file
	all := append(slices.Clone(p.plain), p.keyed...)
	if slices.ContainsFunc(all, func(s *source) bool { return s.sample == model.SampleThin }) {
		r.warnings = append(r.warnings, fmt.Sprintf("the primary key of %s has large gaps or tight clusters, so its sample is thin and the report gives no odds for it", p.table.Name))
	}
	for _, s := range all {
		if w := allowWarning(s.location(), s.addressesSkip, s.values); w != "" {
			r.warnings = append(r.warnings, w)
		}
		if len(s.kinds) == 0 {
			why := "only kinds this check doesn't count"
			notRead := false
			switch {
			case s.sample == model.SampleCut:
				why, notRead = "could not be sampled", true
			case s.cards:
				why = "card numbers aren't hashed: prodmask scan on staging samples for them"
			case s.counted && s.metaKey != "" && s.keyRows == 0 && s.rowsValued == 0 && !s.exact:
				// A rare key the points missed, with no lookup to reach it.
				why, notRead = "a rare key the sample couldn't reach", true
			case s.counted:
				why = "no value of a counted kind in the sample"
			}
			f.LeftOut = append(f.LeftOut, model.LeakLeftOut{Location: s.location(), Why: why, NotRead: notRead})
			continue
		}
		for _, kind := range sortedKinds(s.kinds) {
			ks := s.kinds[kind]
			hashes := make([][hashLen]byte, 0, len(ks.hashes))
			for h := range ks.hashes {
				hashes = append(hashes, h)
			}
			slices.SortFunc(hashes, func(a, b [hashLen]byte) int { return bytes.Compare(a[:], b[:]) })
			distinct := len(hashes)
			exact := s.exact
			// More distinct values than the sample, as free text can give: the
			// smallest hashes are an unbiased pick that depends only on the key.
			if len(hashes) > r.n {
				hashes = hashes[:r.n]
				exact = false
			}
			raw := make([]byte, 0, len(hashes)*hashLen)
			for _, h := range hashes {
				raw = append(raw, h[:]...)
			}
			c := FileColumn{
				Table: s.table, Column: s.column, KeyColumn: s.keyColumn, MetaKey: s.metaKey, Kind: kind,
				Whole: isWhole(kind, &s.wants), MaxChars: s.maxChars, Sample: s.sample, Exact: exact,
				RowsEstimate: p.table.RowsEstimate, RowsRead: s.picked, Values: len(hashes), Hashes: raw,
				EstimatedValues: estimateValues(p.table.RowsEstimate, s, ks.fromPoints, distinct, exact),
			}
			f.Columns = append(f.Columns, c)
		}
	}
}

// allowWarning warns when an allowlist took a large share of a column's values:
// gmail.com among its domains would empty the check.
func allowWarning(location string, skipped, values int64) string {
	if skipped >= allowedAtLeast && float64(skipped) > allowedShare*float64(skipped+values) {
		return fmt.Sprintf("--allow-email kept out more than a fifth of the values in %s: is a public mail service among its domains?", location)
	}
	return ""
}

func isWhole(k model.LeakKind, w *wants) bool {
	return (k == model.LeakPhone && w.loosePhone) || slices.Contains(w.whole, k)
}

func sortedKinds(m map[model.LeakKind]*kindSample) []model.LeakKind {
	out := make([]model.LeakKind, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// estimateValues estimates how many distinct values of a kind production's
// column holds: the table's rows, times the share of rows the key is on, times
// the distinct values per row picked at the points. A table's row count is an
// estimate that can be 0 or far off, so the result is never below the distinct
// values found. A sample that read every value knows the answer.
func estimateValues(rowsEstimate int64, s *source, fromPoints, distinct int, exact bool) int64 {
	if exact || s.rowsRead == 0 || s.picked == 0 {
		return int64(distinct)
	}
	est := float64(rowsEstimate) * float64(s.keyRows) / float64(s.rowsRead) * float64(fromPoints) / float64(s.picked)
	return max(int64(est), int64(distinct))
}

// The errors of a production with nothing to compare.
var (
	ErrNothingToHash  = errors.New("no flagged column holds a value this check counts, so there is nothing to compare")
	ErrNothingSampled = errors.New("some flagged columns couldn't be sampled, and no other holds a value this check counts, so there is nothing to compare")
)
