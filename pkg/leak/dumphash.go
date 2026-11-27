package leak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
	"github.com/ProdMask/ProdMask/pkg/scan"
	"github.com/ProdMask/ProdMask/pkg/sqldump"
)

// The errors of a dump no sample of which can be trusted. They name nothing.
var (
	ErrDumpUnreadNoTable = errors.New("a statement of the dump wasn't read and its table can't be told, so no sample of the dump can be trusted")
	ErrDumpSQLMode       = errors.New("the dump's SQL mode became unknown part-way, so the rest of it wasn't read and no sample of the dump can be trusted")
)

// dumpTableBytes is the bytes of values a table's sample may hash.
const dumpTableBytes = 64 << 20

// HashDumpOptions control HashDump.
type HashDumpOptions struct {
	Allow      *Allowlist
	Preset     string
	Version    string
	SampleRows int // 0 means DefaultSampleRows; only tests set it
	// Database picks the database of a dump that holds several.
	Database string
	// File is the dump's base name, and Compression is "gzip" or "".
	File, Compression string
	// Size and ModTime are the file's before the first pass, and Stat reads
	// them again after the last: any difference stops the run.
	Size    int64
	ModTime time.Time
	Stat    func() (int64, time.Time, error)
	// BytesRead gives the compressed bytes read of the pass in progress.
	BytesRead func() int64
	// Progress is told about once for every megabyte read: the pass (1 to 3),
	// the bytes read, Size, and the table last read.
	Progress func(pass int, done, total int64, table string)

	tableBytes     int64 // tests shrink it
	panicAfterRead bool  // tests make the code after the read fail
}

// unreadError says whether an unread statement makes every sample of the dump
// untrustworthy. A client command, a chunk that changes the session, and a
// USE, a SET or a CREATE or ALTER DATABASE that a version comment leaves
// unread also leave the rest of the file unread, but name no table, which says
// what holds.
func unreadError(u sqldump.Unread) error {
	switch {
	case u.ToEnd && u.Reason != sqldump.ReasonClient && u.Reason != sqldump.ReasonSeveral && u.Reason != sqldump.ReasonVersion:
		return ErrDumpSQLMode
	case u.Table == "":
		return ErrDumpUnreadNoTable
	}
	return nil
}

// HashDump makes production's hash file from a dump of production, in three
// passes of the file. The first two are scan.RunDump's, so the same columns are
// flagged; the third keeps the sample, as Hash's sampling does on a server: all
// the rows of a table of 3,000 rows or fewer, else every k-th one in file order,
// and, for each flagged key of a key/value table, up to 3,000 of its values
// spread the same way. open gives the file's SQL and is called once for each
// pass. A statement of a sampled table that wasn't read leaves that table's
// columns out as not read; one whose table can't be told, an SQL mode that
// became unknown, or a file that changed between the passes is an error.
func HashDump(ctx context.Context, open func() (io.ReadCloser, error), key Key, opts HashDumpOptions) (outFile *File, outWarns []string, outErr error) {
	var d *dumpHash
	defer func() {
		// A fault after the read becomes a fixed error that holds the line only.
		if p := recover(); p != nil {
			line := int64(0)
			if d != nil {
				line = d.line
			}
			outFile, outWarns, outErr = nil, nil, &sqldump.PanicError{Line: int(line)}
		}
	}()
	if opts.SampleRows <= 0 {
		opts.SampleRows = DefaultSampleRows
	}
	if opts.tableBytes <= 0 {
		opts.tableBytes = dumpTableBytes
	}
	counts := map[string]map[string]int64{}
	var schema *model.Schema
	var db string
	res, err := scan.RunDump(ctx, open, scan.DumpOptions{
		Options: scan.Options{
			SampleRows: scan.DefaultSampleRows, MetaSampleRows: scan.DefaultMetaSampleRows, Samples: true,
			Preset: opts.Preset, Version: opts.Version,
		},
		Database: opts.Database, File: opts.File, Compression: opts.Compression,
		Size: opts.Size, ModTime: opts.ModTime, Stat: opts.Stat, BytesRead: opts.BytesRead,
		ReadProgress: opts.Progress,
		KeyCounts:    func(table string, c map[string]int64) { counts[table] = c },
		Schema:       func(s *model.Schema, d string) { schema, db = s, d },
		StopOnUnread: unreadError,
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, err
	}
	plans, leftOut := planSample(res, schema)

	f, salt, err := newHashFile(key, opts.Version, res.Database, opts.SampleRows, opts.Allow)
	if err != nil {
		return nil, nil, err
	}
	f.LeftOut = leftOut
	r := &hashRun{ex: newExtractor(opts.Allow), hs: key.hasher(salt), n: opts.SampleRows, file: f}
	d = &dumpHash{r: r, db: db, tables: map[string]*hashTable{}, limit: opts.tableBytes}
	maxChars := 0
	for _, p := range plans {
		d.tables[p.table.Name] = newHashTable(p, counts[p.table.Name], r.n)
		for _, s := range append(slices.Clone(p.plain), p.keyed...) {
			maxChars = max(maxChars, s.maxChars)
		}
	}

	if err := d.read(ctx, open, opts, maxChars); err != nil {
		return nil, nil, err
	}
	if opts.panicAfterRead {
		panic("test panic")
	}
	if d.fatal != nil {
		return nil, nil, d.fatal
	}
	for _, p := range plans {
		if d.tables[p.table.Name].seen != p.table.RowsEstimate {
			return nil, nil, scan.ErrDumpChanged
		}
	}
	if opts.Stat != nil {
		size, mod, err := opts.Stat()
		if err != nil {
			return nil, nil, err
		}
		if size != opts.Size || !mod.Equal(opts.ModTime) {
			return nil, nil, scan.ErrDumpChanged
		}
	}

	for _, p := range plans {
		d.tables[p.table.Name].finish(r, p, d.limit)
	}
	// An unread table is listed by its columns, in place of the scan's line
	// for the whole table.
	left := f.LeftOut[:0]
	for _, l := range f.LeftOut {
		if ht := d.tables[l.Location]; ht != nil && ht.unread && l.NotRead {
			continue
		}
		left = append(left, l)
	}
	f.LeftOut = left
	for _, p := range plans {
		if ht := d.tables[p.table.Name]; ht.unread {
			for _, s := range append(slices.Clone(p.plain), p.keyed...) {
				f.LeftOut = append(f.LeftOut, model.LeakLeftOut{Location: s.location(), Why: stoppedTableUnread, NotRead: true})
			}
		}
	}
	return r.seal(res)
}

// hashTable is what pass 3 keeps of one planned table.
type hashTable struct {
	p      *plan
	k      int64 // every k-th row's plain values are hashed
	keyK   []int64
	match  *keyMatcher
	seen   int64 // rows read
	bytes  int64
	over   bool // the table's bytes ran out
	unread bool

	bound   *model.Table
	plainAt []int
	plainCh []int
	keyAt   int
	valAt   int
	valCh   []int
}

// every is how many rows apart a spread sample takes them: 1 for a table or key
// of n rows or fewer, which is read whole.
func every(rows int64, n int) int64 {
	if rows <= int64(n) {
		return 1
	}
	return (rows + int64(n) - 1) / int64(n)
}

func newHashTable(p *plan, counts map[string]int64, n int) *hashTable {
	ht := &hashTable{p: p, k: every(p.table.RowsEstimate, n), keyAt: -1, valAt: -1}
	if len(p.keyed) == 0 {
		return ht
	}
	ht.match = newKeyMatcher(metaKeys(p.keyed))
	// A key's rows are those pass 2 counted of the keys it matches. A table it
	// gave no counts for is taken to be all of one key's, so its keys are spread.
	total := make([]int64, len(p.keyed))
	for key, c := range counts {
		if i := ht.match.match(key); i >= 0 {
			total[i] += c
		}
	}
	for i := range total {
		if counts == nil {
			total[i] = p.table.RowsEstimate
		}
		ht.keyK = append(ht.keyK, every(total[i], n))
	}
	return ht
}

// bind finds the sampled columns in the structure a row was written under: a
// column that structure lacks is left alone.
func (ht *hashTable) bind(t *model.Table) {
	ht.bound = t
	ht.plainAt, ht.plainCh, ht.valCh = ht.plainAt[:0], ht.plainCh[:0], ht.valCh[:0]
	for _, s := range ht.p.plain {
		at, ch := columnAt(t, s.column), 0
		if at >= 0 && !sample.Sampleable(t.Columns[at]) {
			at = -1
		}
		if at >= 0 {
			ch = cutOf(t.Columns[at], s.maxChars)
		}
		ht.plainAt, ht.plainCh = append(ht.plainAt, at), append(ht.plainCh, ch)
	}
	ht.keyAt, ht.valAt = -1, -1
	if len(ht.p.keyed) == 0 {
		return
	}
	ka, va := columnAt(t, ht.p.keyCol.Name), columnAt(t, ht.p.valCol.Name)
	if ka < 0 || va < 0 || !sample.IsText(t.Columns[ka]) || !sample.Sampleable(t.Columns[va]) {
		return
	}
	ht.keyAt, ht.valAt = ka, va
	for _, s := range ht.p.keyed {
		ht.valCh = append(ht.valCh, cutOf(t.Columns[va], s.maxChars))
	}
}

// dumpHash is the visitor of pass 3.
type dumpHash struct {
	sqldump.BaseVisitor
	r      *hashRun
	db     string
	tables map[string]*hashTable
	limit  int64
	fatal  error
	cur    string
	line   int64 // the last row's line, for a fault outside the reader
}

func (d *dumpHash) Unread(u sqldump.Unread) {
	if err := unreadError(u); err != nil {
		if d.fatal == nil {
			d.fatal = err
		}
		return
	}
	if u.Database != d.db {
		return
	}
	if ht := d.tables[u.Table]; ht != nil {
		ht.unread = true
	}
}

func (d *dumpHash) Row(row *sqldump.Row) {
	d.cur, d.line = row.Table, row.Line
	if row.DB != d.db {
		return
	}
	ht := d.tables[row.Table]
	if ht == nil {
		return
	}
	ht.seen++
	if ht.bound != row.Structure {
		ht.bind(row.Structure)
	}
	r := d.r
	// pick reads a value for a source, if the table's bytes allow.
	if !ht.over && len(ht.p.plain) > 0 && (ht.seen-1)%ht.k == 0 {
		for i, s := range ht.p.plain {
			s.picked++
			if at := ht.plainAt[i]; at >= 0 {
				if v, ok := valueText(row.Values[at], ht.plainCh[i]); ok {
					r.add(s, v)
					ht.bytes += int64(len(v))
				}
			}
		}
	}
	if ht.match == nil || ht.keyAt < 0 {
		ht.checkBytes(d.limit)
		return
	}
	k, ok := valueText(row.Values[ht.keyAt], 0)
	if !ok {
		ht.checkBytes(d.limit)
		return
	}
	if i := ht.match.match(k); i >= 0 {
		s := ht.p.keyed[i]
		s.keyRows++
		if !ht.over && (s.keyRows-1)%ht.keyK[i] == 0 {
			s.picked++
			if v, ok := valueText(row.Values[ht.valAt], ht.valCh[i]); ok {
				s.rowsValued++
				r.add(s, v)
				ht.bytes += int64(len(v))
			}
		}
	}
	ht.checkBytes(d.limit)
}

func (ht *hashTable) checkBytes(limit int64) {
	if ht.bytes > limit {
		ht.over = true
	}
}

// finish records how each source of a table was sampled, as the sampling of a
// server does, and has finishTable hash it. A table with an unread statement is
// left to the caller.
func (ht *hashTable) finish(r *hashRun, p *plan, limit int64) {
	if ht.unread {
		return
	}
	method := func(k int64) (string, bool) {
		switch {
		case ht.over:
			return model.SampleFirstRows, false
		case k == 1:
			return model.SampleAllRows, true
		}
		return model.SampleSpread, false
	}
	for _, s := range p.plain {
		s.sample, s.exact = method(ht.k)
		s.rowsRead, s.keyRows = s.picked, s.picked
		s.notePoints()
	}
	for i, s := range p.keyed {
		s.sample, s.exact = method(ht.keyK[i])
		s.rowsRead = ht.seen
		s.notePoints()
	}
	if ht.over {
		r.warnings = append(r.warnings, fmt.Sprintf("the sample of %s stopped at %d MiB of values, so it holds the table's first rows only", p.table.Name, limit>>20))
	}
	r.finishTable(p)
}

// read runs pass 3.
func (d *dumpHash) read(ctx context.Context, open func() (io.ReadCloser, error), opts HashDumpOptions, maxChars int) error {
	rc, err := open()
	if err != nil {
		return err
	}
	defer rc.Close()
	var src io.Reader = rc
	if opts.Progress != nil {
		src = &progressReader{r: rc, fn: func(n int64) {
			if opts.BytesRead != nil {
				n = opts.BytesRead()
			}
			opts.Progress(3, n, opts.Size, d.cur)
		}}
	}
	_, err = sqldump.Read(ctx, src, d, sqldump.Options{MaxChars: maxChars})
	return err
}

// progressReader reports the bytes read, about once for every megabyte.
type progressReader struct {
	r    io.Reader
	n    int64
	next int64
	fn   func(n int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if p.n >= p.next {
		p.next = p.n + 1<<20
		p.fn(p.n)
	}
	return n, err
}
