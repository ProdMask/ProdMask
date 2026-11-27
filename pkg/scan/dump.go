package scan

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/infer"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
	"github.com/ProdMask/ProdMask/pkg/sqldump"
)

// ErrDumpChanged is returned when the file is not the same in the second pass
// as it was in the first.
var ErrDumpChanged = errors.New("the file changed while it was read")

// ErrNotDump is returned when the file holds no SQL statement the reader
// recognises, such as an image or another binary format.
var ErrNotDump = errors.New("the file given to --dump holds no SQL statement the reader recognises, so it isn't a dump")

// DumpOptions control a scan of a dump file. Options.Progress is not used:
// the dump's progress, ReadProgress, counts bytes.
type DumpOptions struct {
	Options
	// Database picks the database to scan when the file holds several.
	Database string
	// File is the file's base name, and Compression is "gzip" or "".
	File        string
	Compression string
	// Size and ModTime are the file's, taken before the first pass. When Stat
	// is set, it is called before the first pass and after the second, and any
	// difference stops the scan.
	Size    int64
	ModTime time.Time
	Stat    func() (size int64, modTime time.Time, err error)
	// ReadProgress, when set, is told about once for every megabyte read: the
	// pass (1 or 2), the bytes read, Size, and the table last read. The bytes
	// are those BytesRead gives when it is set (the compressed bytes of the
	// file), else the bytes of SQL read.
	ReadProgress func(pass int, done, total int64, table string)
	BytesRead    func() int64
	// KeyCounts, when set, is called as each key/value table is judged with
	// the number of rows of each key the scan kept, for hash --dump.
	KeyCounts func(table string, counts map[string]int64)
	// Schema, when set, is called once with the schema the first pass built,
	// between the passes, and the database it is of as the file names it (""
	// when its statements name none). Each table's RowsEstimate is the dump's
	// exact row count, for hash --dump.
	Schema func(schema *model.Schema, db string)
	// StopOnUnread, when set, is called in the first pass for each statement
	// that wasn't read. An error it returns ends the scan with that error: at
	// once when the file has shown a structure or a row, else once the file is
	// known to be a dump, since a file that isn't one is better told so.
	StopOnUnread func(u sqldump.Unread) error

	limits dumpLimits // zero fields take their defaults; tests shrink them
}

// dumpLimits are the bounds of a dump scan. Every one is a constant in code;
// tests shrink them.
type dumpLimits struct {
	wholeRows      int   // rows a key/value table may have to be read whole
	wholeBytes     int64 // and bytes of row data
	maxKeys        int   // keys kept of a table read outside that
	keyBytes       int64 // bytes of key names kept
	valueBytes     int64 // bytes of keys and values kept
	wholeTableRows int   // rows kept of each table the platform checks read whole
	sampleBytes    int64 // held bytes of one table's plain sample, before it is thinned
	sampleFloor    int   // rows a thinned sample keeps, at the least
	openBytes      int64 // held bytes of the collectors of all the tables open at once
	repanic        bool  // a panic outside the reader is raised again, for tests
	// tap, set only by tests, sees what each table collected: every window by
	// its limit, and the key/value read, before the table is judged.
	tap func(table string, wins map[int]*sample.Sample, kv *kvRead)
	// finishTime, set only by tests, is told how long it took to finish each
	// table in the second pass: to read out what it collected and judge it.
	finishTime func(time.Duration)
}

func (o DumpOptions) lim() *dumpLimits {
	l := o.limits
	if l.wholeRows == 0 {
		l.wholeRows = wholeRows
	}
	if l.wholeBytes == 0 {
		l.wholeBytes = wholeBytes
	}
	if l.maxKeys == 0 {
		l.maxKeys = maxListedKeys
	}
	if l.keyBytes == 0 {
		l.keyBytes = 32 << 20
	}
	if l.valueBytes == 0 {
		l.valueBytes = tableBytes
	}
	if l.wholeTableRows == 0 {
		l.wholeTableRows = 100000
	}
	if l.sampleBytes == 0 {
		l.sampleBytes = 64 << 20
	}
	if l.sampleFloor == 0 {
		l.sampleFloor = 30
	}
	if l.openBytes == 0 {
		l.openBytes = 256 << 20
	}
	return &l
}

// keyLimits are the limits a dump's skipped-keys warning quotes: per table
// only, since a dump scan has no limit for the whole scan.
func (l *dumpLimits) keyLimits() keyLimits {
	return keyLimits{TableKeys: l.maxKeys, TableBytes: l.valueBytes}
}

type tkey struct{ db, table string }

// p1Table is what the first pass learns of one table.
type p1Table struct {
	rows, bytes int64
	lastLine    int64
	unread      int
	keysUnknown bool
	ranges      map[string]*intRange // integer columns tracked, by lower-case name
	plan        *rowPlan
}

// rowPlan says what the first pass keeps of each row of a table, for the
// structure in force.
type rowPlan struct {
	st       *model.Table
	track    []*intRange
	trackIdx []int
	optName  int // the columns of a settings table, or -1
	optVal   int
	whole    *keptRows
	wholeIdx []int
}

// keptRows holds the rows of a table the platform checks read whole.
type keptRows struct {
	cols   []string
	rows   [][]string
	capped bool
}

// pass1 reads structure, facts and settings.
type pass1 struct {
	sqldump.BaseVisitor
	d        *dumpRun
	hdr      sqldump.Header
	tables   map[tkey]*p1Table
	structs  map[tkey]*model.Table
	dbs      []string
	sigs     []uint64
	warnings []string
	settings map[tkey]map[string][2]string // lower-case key → stored key, value
	whole    map[tkey]*keptRows
	setKeys  map[string]bool
	seen     bool // a structure or a row was read
	fatal    error
	cancel   context.CancelFunc
}

func newPass1(d *dumpRun) *pass1 {
	p := &pass1{d: d, tables: map[tkey]*p1Table{}, structs: map[tkey]*model.Table{},
		settings: map[tkey]map[string][2]string{}, whole: map[tkey]*keptRows{}, setKeys: map[string]bool{}}
	for _, k := range preset.SettingsKeys() {
		p.setKeys[strings.ToLower(k)] = true
	}
	return p
}

func (p *pass1) Header(h sqldump.Header)   { p.hdr = h }
func (p *pass1) Database(name string)      { p.dbs = append(p.dbs, name) }
func (p *pass1) Warning(w sqldump.Warning) { p.warnings = append(p.warnings, w.Text) }

func (p *pass1) table(k tkey) *p1Table {
	t := p.tables[k]
	if t == nil {
		t = &p1Table{ranges: map[string]*intRange{}}
		p.tables[k] = t
	}
	return t
}

func (p *pass1) Unread(u sqldump.Unread) {
	if f := p.d.opts.StopOnUnread; f != nil && p.fatal == nil {
		if p.fatal = f(u); p.fatal != nil && p.seen {
			p.cancel()
		}
	}
	if u.Table != "" {
		p.table(tkey{u.Database, u.Table}).unread++
	}
}

func (p *pass1) Structure(db string, t *model.Table) {
	k := tkey{db, t.Name}
	p.seen = true
	p.structs[k] = t
	p.sigs = append(p.sigs, structSig(db, t))
}

// structSig is a fingerprint of a structure, for the check that the second
// pass reads the same file.
func structSig(db string, t *model.Table) uint64 {
	h := fnv.New64a()
	w := func(s string) { io.WriteString(h, s); h.Write([]byte{0}) }
	w(db)
	w(t.Name)
	w(t.Type)
	for _, c := range t.Columns {
		w(c.Name)
		w(c.ColumnType)
		w(c.Extra)
	}
	for _, c := range t.PrimaryKey {
		w(c)
	}
	return h.Sum64()
}

func colIndex(st *model.Table, name string) int {
	for i, c := range st.Columns {
		if strings.EqualFold(c.Name, name) {
			return i
		}
	}
	return -1
}

// planFor works out what to keep of the rows of one structure of a table.
func (p *pass1) planFor(k tkey, t *p1Table, st *model.Table) *rowPlan {
	pl := &rowPlan{st: st, optName: -1, optVal: -1}
	track := func(i int) {
		name := strings.ToLower(st.Columns[i].Name)
		r := t.ranges[name]
		if r == nil {
			r = &intRange{}
			t.ranges[name] = r
		}
		pl.track, pl.trackIdx = append(pl.track, r), append(pl.trackIdx, i)
	}
	switch pk := st.SinglePK(); {
	case pk != nil && sample.IsInteger(pk):
		track(colIndex(st, pk.Name))
	case len(st.PrimaryKey) == 0:
		// A key declared after the rows still has its range.
		for i, c := range st.Columns {
			if sample.IsInteger(c) {
				track(i)
			}
		}
	}
	lower := strings.ToLower(k.table)
	if strings.HasSuffix(lower, "options") {
		pl.optName, pl.optVal = colIndex(st, "option_name"), colIndex(st, "option_value")
		if pl.optName < 0 || pl.optVal < 0 {
			pl.optName, pl.optVal = -1, -1
		}
	}
	for base, cols := range preset.WholeTables() {
		if !strings.HasSuffix(lower, base) {
			continue
		}
		idx := make([]int, len(cols))
		for i, c := range cols {
			if idx[i] = colIndex(st, c); idx[i] < 0 {
				idx = nil
				break
			}
		}
		if idx == nil {
			continue
		}
		w := p.whole[k]
		if w == nil {
			w = &keptRows{cols: cols}
			p.whole[k] = w
		}
		pl.whole, pl.wholeIdx = w, idx
	}
	return pl
}

func (p *pass1) Row(r *sqldump.Row) {
	p.seen = true
	k := tkey{r.DB, r.Table}
	t := p.table(k)
	t.rows++
	t.lastLine = r.Line
	p.d.line, p.d.cur = r.Line, r.Table
	var n int64
	for i := range r.Values {
		n += int64(len(r.Values[i].Bytes))
	}
	t.bytes += n
	t.keysUnknown = t.keysUnknown || r.KeysUnknown
	if t.plan == nil || t.plan.st != r.Structure {
		t.plan = p.planFor(k, t, r.Structure)
	}
	pl := t.plan
	for i, rg := range pl.track {
		rg.add(&r.Values[pl.trackIdx[i]])
	}
	if pl.optName >= 0 {
		name := &r.Values[pl.optName]
		if name.Kind == sqldump.ValString || name.Kind == sqldump.ValNumber {
			lk := strings.ToLower(string(name.Bytes))
			m := p.settings[k]
			if _, seen := m[lk]; p.setKeys[lk] && !seen {
				if m == nil {
					m = map[string][2]string{}
					p.settings[k] = m
				}
				v, _ := cellText(r.Structure.Columns[pl.optVal], &r.Values[pl.optVal], 65535, false)
				m[lk] = [2]string{string(name.Bytes), v}
			}
		}
	}
	if w := pl.whole; w != nil {
		if len(w.rows) >= p.d.lim.wholeTableRows {
			w.capped = true
			return
		}
		row := make([]string, len(pl.wholeIdx))
		for i, j := range pl.wholeIdx {
			row[i], _ = cellText(r.Structure.Columns[j], &r.Values[j], 0, false)
		}
		w.rows = append(w.rows, row)
	}
}

// dumpRun holds what one scan of a dump needs between its steps.
type dumpRun struct {
	opts    DumpOptions
	lim     *dumpLimits
	line    int64 // the last row's line, for a fault outside the reader
	cur     string
	pr      *preset.Result
	schema  *model.Schema
	metas   map[string]*preset.MetaTable
	hexFn   func(*model.Table, *model.Column) bool
	results map[string]*model.Result // each judged table's findings, summary and warnings
	warns   []string                 // warnings of the second pass that belong to no one table
}

// progReader reports the bytes read, about once for every megabyte.
type progReader struct {
	r    io.Reader
	n    int64
	next int64
	fn   func(n int64)
}

func (p *progReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if p.n >= p.next {
		p.next = p.n + 1<<20
		p.fn(p.n)
	}
	return n, err
}

// read runs one pass over the file.
func (d *dumpRun) read(ctx context.Context, open func() (io.ReadCloser, error), pass int, v sqldump.Visitor) (sqldump.Stats, error) {
	rc, err := open()
	if err != nil {
		return sqldump.Stats{}, err
	}
	defer rc.Close()
	var src io.Reader = rc
	if d.opts.ReadProgress != nil {
		src = &progReader{r: rc, fn: func(n int64) {
			if d.opts.BytesRead != nil {
				n = d.opts.BytesRead()
			}
			d.opts.ReadProgress(pass, n, d.opts.Size, d.cur)
		}}
	}
	return sqldump.Read(ctx, src, v, sqldump.Options{})
}

func (d *dumpRun) stat() (int64, time.Time, error) {
	if d.opts.Stat != nil {
		return d.opts.Stat()
	}
	return d.opts.Size, d.opts.ModTime, nil
}

// RunDump scans a dump file in two passes and judges it with the code the
// scan of a database uses. open gives the file's SQL, decompressed, and is
// called once for each pass. The first pass reads structure, row counts, key
// ranges and the settings the platform checks read; the second reads the rows
// the live scan's reads would have returned. With opts.Samples false it stops
// after the first and judges names only.
//
// When the file ends early (sqldump.ErrRead) in the first pass, RunDump
// returns the result for what was read, judged by names only, with the error.
// Every other error comes with no result.
func RunDump(ctx context.Context, open func() (io.ReadCloser, error), opts DumpOptions) (res *model.Result, err error) {
	d := &dumpRun{opts: opts, lim: opts.lim(), results: map[string]*model.Result{}}
	defer func() {
		if p := recover(); p != nil {
			if d.lim.repanic {
				panic(p)
			}
			res, err = nil, &sqldump.PanicError{Line: int(d.line)}
		}
	}()
	start := time.Now()
	// What the live command line sets from its flags' defaults, which a dump
	// scan takes no flag for, or a caller may leave out.
	if opts.SampleRows <= 0 {
		opts.SampleRows = DefaultSampleRows
	}
	if opts.MetaSampleRows <= 0 {
		opts.MetaSampleRows = DefaultMetaSampleRows
	}
	if opts.MaxValueLen <= 0 {
		opts.MaxValueLen = DefaultMaxValueLen
	}
	if opts.KeySampleRows <= 0 {
		opts.KeySampleRows = DefaultKeySampleRows
	}
	d.opts.Options = opts.Options

	size0, mod0, err := d.stat()
	if err != nil {
		return nil, err
	}
	p1 := newPass1(d)
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	p1.cancel = cancel
	stats, rerr := d.read(readCtx, open, 1, p1)
	if p1.fatal != nil && p1.seen {
		return nil, p1.fatal
	}
	partial := false
	if rerr != nil {
		if !errors.Is(rerr, sqldump.ErrRead) {
			return nil, rerr
		}
		partial = true
	}
	recognised := false
	for k, n := range stats.ByKind {
		recognised = recognised || (k != sqldump.KindOther && n > 0)
	}
	if !recognised {
		return nil, ErrNotDump
	}
	if p1.fatal != nil {
		return nil, p1.fatal
	}
	db, err := chooseDatabase(p1, opts.Database)
	if err != nil {
		return nil, err
	}
	samples := opts.Samples && !partial

	res = &model.Result{
		Tool: "prodmask", Version: opts.Version, GeneratedAt: start.UTC().Truncate(time.Second),
		Database: databaseName(p1, db),
		Options: model.ScanOptions{
			// What ran: a file cut in its first pass is judged by names only.
			SampleRows: opts.SampleRows, MetaSampleRows: opts.MetaSampleRows, KeySampleRows: opts.KeySampleRows,
			Samples: samples, Preset: opts.Preset,
		},
		Warnings: append([]string(nil), p1.warnings...),
	}
	if p1.hdr.ServerVersion != "" || p1.hdr.MariaDB {
		res.Server = model.ServerInfo{Flavor: "mysql", Version: p1.hdr.ServerVersion}
		if p1.hdr.MariaDB {
			res.Server.Flavor = "mariadb"
		}
	}
	for k, w := range p1.whole {
		if w.capped && k.db == db {
			res.Warnings = append(res.Warnings, fmt.Sprintf("only the first %d rows of %s were kept for the platform checks", d.lim.wholeTableRows, k.table))
		}
	}
	sort.Strings(res.Warnings[len(p1.warnings):])

	d.schema = buildSchema(p1, db, res.Database)
	if opts.Schema != nil {
		opts.Schema(d.schema, db)
	}
	if len(d.schema.Tables) == 0 {
		res.Warnings = append(res.Warnings, "the dump holds no tables of this database")
	}
	d.pr = &preset.Result{}
	if opts.Preset != "none" {
		d.pr = preset.DetectOffline(d.schema, opts.Preset, p1.offline(db))
	}
	res.Platforms = d.pr.Platforms
	res.SideEffects = d.pr.SideEffects
	res.Warnings = append(res.Warnings, d.pr.Warnings...)

	d.metas = map[string]*preset.MetaTable{}
	for _, t := range d.schema.Tables {
		if !t.IsData() {
			continue
		}
		if m := d.pr.Meta[t.Name]; m != nil {
			d.metas[t.Name] = m
		} else if m := genericMeta(t, d.pr); m != nil {
			d.metas[t.Name] = m
		}
	}
	d.hexFn = hexColumn(d.pr)
	order := planOrder(d.schema.Tables, d.metas)

	if samples {
		if err := d.second(ctx, open, p1, db, size0, mod0); err != nil {
			return nil, err
		}
		res.Warnings = append(res.Warnings, d.warns...)
	} else {
		for _, t := range order {
			if t.IsData() {
				d.judge(t, p1.tables[tkey{db, t.Name}], nil, nil, nil, nil)
			}
		}
	}

	for _, t := range order {
		if r := d.results[t.Name]; r != nil {
			res.Findings = append(res.Findings, r.Findings...)
			res.Tables = append(res.Tables, r.Tables...)
			res.Warnings = append(res.Warnings, r.Warnings...)
			continue
		}
		res.Tables = append(res.Tables, d.summary(t, p1.tables[tkey{db, t.Name}]))
	}
	sort.SliceStable(res.Tables, func(i, j int) bool { return res.Tables[i].Name < res.Tables[j].Name })

	res.Relationships = dumpRelationships(d.schema, d.pr)
	weakenDeviceReferences(res, d.schema)
	noteUnverifiedDeviceReferences(res, d.schema)
	detect.SortFindings(res.Findings)
	sortRelationships(res.Relationships)
	res.Dump = dumpInfo(opts, stats, p1, samples)
	if stats.Rows == 0 {
		res.Warnings = append(res.Warnings, "the dump holds no rows, so no values were judged")
	}
	summarize(res, time.Since(start))
	if partial {
		return res, rerr
	}
	return res, nil
}

// chooseDatabase picks the database to scan: the one asked for, or the only
// one the file has tables of.
func chooseDatabase(p *pass1, want string) (string, error) {
	names := p.databases()
	// The reader gives a database one spelling, the file's first, whatever
	// the letter case; --database matches it in any case.
	match := ""
	for _, n := range names {
		if n != "" && strings.EqualFold(n, want) {
			match = n
		}
	}
	switch {
	case want != "":
		if len(names) == 1 && names[0] == "" {
			// A dump of one database, written with no USE: --database names the unnamed database, and the report names it only as the file does.
			return "", nil
		}
		if len(names) > 0 && match == "" {
			// What --database holds may be a DSN or a key: never repeat it.
			return "", &DatabaseError{fmt.Sprintf("the dump holds no tables of the database given to --database, only of %s", firstTen(names, "%q"))}
		}
		return match, nil
	case len(names) > 1:
		return "", &DatabaseError{fmt.Sprintf("the dump holds tables of several databases (%s); name one with --database", firstTen(names, "%q"))}
	case len(names) == 1:
		return names[0], nil
	}
	return "", nil
}

// databases lists the databases the file has tables of, in order.
func (p *pass1) databases() []string {
	seen := map[string]bool{}
	var names []string
	for k := range p.structs {
		if !seen[k.db] {
			seen[k.db] = true
			names = append(names, k.db)
		}
	}
	sort.Strings(names)
	return names
}

// firstTen joins the first ten names, each written with format, and counts
// the rest.
func firstTen(names []string, format string) string {
	var q []string
	for i, n := range names {
		if i == 10 {
			q = append(q, fmt.Sprintf("and %d more", len(names)-10))
			break
		}
		q = append(q, fmt.Sprintf(format, n))
	}
	return strings.Join(q, ", ")
}

// databaseName is the database the report names, always a name the file
// gives, never what --database holds: the one the tables were created in, in
// the file's spelling when --database matched it, the first one a USE, CREATE
// DATABASE or ALTER DATABASE names, or the header's.
func databaseName(p *pass1, chosen string) string {
	switch {
	case chosen != "":
		return chosen
	case len(p.dbs) > 0:
		return p.dbs[0]
	}
	return p.hdr.Database
}

// buildSchema is the schema the first pass read, tables in name order, with
// the dump's exact counts where a database has estimates.
func buildSchema(p *pass1, db, name string) *model.Schema {
	s := &model.Schema{Database: db}
	if db == "" {
		s.Database = name // a key that names no database refers to this one
	}
	for k, t := range p.structs {
		if k.db != db {
			continue
		}
		c := *t
		if t1 := p.tables[k]; t1 != nil {
			c.RowsEstimate, c.DataBytes = t1.rows, t1.bytes
		}
		if db == "" && name != "" {
			c.ForeignKeys = slices.Clone(c.ForeignKeys)
			for i := range c.ForeignKeys {
				if c.ForeignKeys[i].RefSchema == "" {
					c.ForeignKeys[i].RefSchema = name
				}
			}
		}
		s.Tables = append(s.Tables, &c)
	}
	sort.Slice(s.Tables, func(i, j int) bool { return s.Tables[i].Name < s.Tables[j].Name })
	return s
}

// offline answers the platform checks' reads from what the first pass kept.
func (p *pass1) offline(db string) preset.Offline {
	return preset.Offline{
		Options: func(table, _, _ string, keys []string) map[string]string {
			out := map[string]string{}
			m := p.settings[tkey{db, table}]
			for _, k := range keys {
				if e, ok := m[strings.ToLower(k)]; ok {
					out[e[0]] = e[1]
				}
			}
			return out
		},
		Rows: func(table string, columns []string) [][]string {
			w := p.whole[tkey{db, table}]
			if w == nil {
				return nil
			}
			idx := make([]int, len(columns))
			for i, c := range columns {
				idx[i] = -1
				for j, wc := range w.cols {
					if strings.EqualFold(wc, c) {
						idx[i] = j
					}
				}
				if idx[i] < 0 {
					return nil
				}
			}
			out := make([][]string, len(w.rows))
			for n, r := range w.rows {
				row := make([]string, len(idx))
				for i, j := range idx {
					row[i] = r[j]
				}
				out[n] = row
			}
			return out
		},
	}
}

// summary is a table's summary row before it is judged.
func (d *dumpRun) summary(t *model.Table, t1 *p1Table) model.TableSummary {
	ts := model.TableSummary{Name: t.Name, Kind: "table", RowsEstimate: t.RowsEstimate}
	if a, ok := d.pr.Actions[t.Name]; ok {
		ts.Action, ts.ActionReason = a.Action, a.Reason
	}
	if !t.IsData() {
		ts.Kind = strings.ToLower(t.Type)
		if t.IsView() {
			ts.Kind = "view"
		}
		return ts
	}
	if meta := d.metas[t.Name]; meta != nil {
		ts.Kind = "key/value"
		ts.KeyColumn, ts.ValueColumn = meta.Key, meta.Value
	}
	if t1 != nil && t1.unread > 0 {
		if t1.unread == 1 {
			ts.Error = "1 statement of this table wasn't read"
		} else {
			ts.Error = fmt.Sprintf("%d statements of this table weren't read", t1.unread)
		}
	}
	return ts
}

// judge judges one data table from what was read of it, and keeps the result
// until the tables are put in order.
func (d *dumpRun) judge(t *model.Table, t1 *p1Table, s *sample.Sample, kv *kvRead, rows []rowRead, rowWarns []string) {
	r := &model.Result{}
	judgeTable(r, t, d.summary(t, t1), d.metas[t.Name], s, kv, rows, rowWarns, d.pr, d.lim.keyLimits())
	d.results[t.Name] = r
}

// dumpRelationships lists the declared foreign keys and the links presets
// know. Nothing is looked up in a file, so a preset's link stays unverified;
// guesses from names and polymorphic columns are left out.
func dumpRelationships(schema *model.Schema, pr *preset.Result) []model.Relationship {
	inf := &infer.Inferrer{Schema: schema, IDs: infer.NewIDValues(), Prefixes: pr.Prefixes, Known: pr.Relationships}
	var out []model.Relationship
	for _, r := range inf.Relationships() {
		switch {
		case r.Source == "declared":
		case strings.HasPrefix(r.Source, "preset:"):
			r.Status, r.Note = model.RelUnverified, "not checked in a dump file"
		default:
			continue
		}
		out = append(out, r)
	}
	return out
}

// noteUnverifiedDeviceReferences adds a note to a device ID found on a column
// that only a preset's unchecked link joins to a parent's key named id or
// uuid. The finding keeps its confidence, which is the safe side.
func noteUnverifiedDeviceReferences(res *model.Result, schema *model.Schema) {
	parents := map[string]string{}
	for _, r := range res.Relationships {
		if r.Status != model.RelUnverified || len(r.ChildColumns) != 1 || len(r.ParentColumns) != 1 {
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
	for i := range res.Findings {
		f := &res.Findings[i]
		parent, ok := parents[f.Table+"\x00"+f.Column]
		if !ok || f.Category != model.CatDeviceID || f.Confidence == model.ConfidenceLow || f.MetaKey != "" {
			continue
		}
		note := "a platform link joins this column to " + parent + " (not checked in a dump file); a scan of the database " +
			"could find it to be a reference"
		if f.Note != "" {
			note = f.Note + "; " + note
		}
		f.Note = note
	}
}

// dumpInfo is the result's facts about the file.
func dumpInfo(opts DumpOptions, st sqldump.Stats, p *pass1, samples bool) *model.DumpInfo {
	info := &model.DumpInfo{
		File: opts.File, Compression: opts.Compression, Bytes: st.Bytes, Producer: p.hdr.Producer,
		Statements: st.Statements(), ByKind: map[string]int{}, Rows: st.Rows, Defaults: st.DefaultsNoLiteral,
		Unread: st.Unread, SampleRows: opts.SampleRows,
	}
	for k, n := range st.ByKind {
		info.ByKind[string(k)] = n
	}
	for _, u := range st.UnreadList {
		info.UnreadList = append(info.UnreadList, model.DumpUnread{Line: u.Line, Kind: string(u.Kind), Reason: string(u.Reason),
			Database: u.Database, Table: u.Table, ToEnd: u.ToEnd})
	}
	if dbs := p.databases(); len(dbs) > 1 {
		info.Databases = dbs
	}
	info.NotChecked = []string{"side_effects"}
	info.Bodies, info.Users = model.DumpBodiesOf(info.ByKind, st.Views), st.Users
	info.Judged = "Judged names only; no values were read."
	if samples {
		info.Judged = fmt.Sprintf("Judged up to %s rows of each table, the ones scan reads on a database, and every key of its key/value tables.",
			thousands(opts.SampleRows))
	}
	return info
}

// thousands writes n with a comma between its thousands.
func thousands(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// second runs the second pass: the rows the live scan's reads would return,
// judged table by table as their last row statements pass.
func (d *dumpRun) second(ctx context.Context, open func() (io.ReadCloser, error), p1 *pass1, db string,
	size0 int64, mod0 time.Time) error {
	p2 := &pass2{d: d, p1: p1, tables: map[tkey]*dumpTable{}, counts: map[tkey]int64{}}
	for _, t := range d.schema.Tables {
		if t.IsData() {
			dt := d.newTable(t, p1.tables[tkey{db, t.Name}])
			p2.tables[tkey{db, t.Name}] = dt
			p2.byLine = append(p2.byLine, dt)
		}
	}
	sort.SliceStable(p2.byLine, func(i, j int) bool { return p2.byLine[i].lastLine < p2.byLine[j].lastLine })
	if _, err := d.read(ctx, open, 2, p2); err != nil {
		return err
	}
	if p2.changed || p2.sig != len(p1.sigs) {
		return ErrDumpChanged
	}
	for k, t := range p1.tables {
		if p2.counts[k] != t.rows {
			return ErrDumpChanged
		}
	}
	for k, n := range p2.counts {
		if p1.tables[k] == nil || p1.tables[k].rows != n {
			return ErrDumpChanged
		}
	}
	if d.opts.Stat != nil {
		size, mod, err := d.opts.Stat()
		if err != nil {
			return err
		}
		if size != size0 || !mod.Equal(mod0) {
			return ErrDumpChanged
		}
	}
	for _, dt := range p2.byLine {
		p2.finish(dt)
	}
	p2.openWarning()
	return nil
}

// pass2 reads the rows to judge.
type pass2 struct {
	sqldump.BaseVisitor
	d       *dumpRun
	p1      *pass1
	tables  map[tkey]*dumpTable
	byLine  []*dumpTable // in the order their last row statements come
	next    int
	counts  map[tkey]int64
	sig     int
	changed bool

	open []*dumpTable // the tables with rows collected and not yet judged
	held int64        // what their collectors hold, counted as dumpTable.total
	// nextCheck is what the open collectors may hold before thinOpen looks again,
	// after it found every open sample already down to its floor.
	nextCheck int64
	limited   []*dumpTable // tables limited because of what all the open ones held
}

func (p *pass2) Structure(db string, t *model.Table) {
	if p.sig >= len(p.p1.sigs) || p.p1.sigs[p.sig] != structSig(db, t) {
		p.changed = true
	}
	p.sig++
}

func (p *pass2) Row(r *sqldump.Row) {
	k := tkey{r.DB, r.Table}
	p.counts[k]++
	p.d.line, p.d.cur = r.Line, r.Table
	// A statement that starts after a table's last row statement ends is
	// proof that the table has no more rows.
	for p.next < len(p.byLine) && p.byLine[p.next].lastLine < r.Line {
		p.finish(p.byLine[p.next])
		p.next++
	}
	if dt := p.tables[k]; dt != nil && !dt.judged {
		if dt.rows == 0 {
			p.open = append(p.open, dt)
		}
		dt.add(r)
		t := dt.held + dt.kvHeld()
		p.held += t - dt.total
		dt.total = t
		if p.held > p.d.lim.openBytes && p.held > p.nextCheck {
			p.thinOpen()
		}
	}
}

// thinOpen thins the samples of the open tables, the largest first, until
// what they hold is within the limit or each is down to its floor. Rows of
// tables whose statements come interleaved are all held at once, so this is
// what keeps a file of such tables within the memory bound.
func (p *pass2) thinOpen() {
	live := p.open[:0]
	for _, dt := range p.open {
		if !dt.judged {
			live = append(live, dt)
		}
	}
	clear(p.open[len(live):])
	p.open = live
	p.nextCheck = 0
	for p.held > p.d.lim.openBytes {
		var big *dumpTable
		for _, dt := range p.open {
			if !dt.floored && dt.held > 0 && (big == nil || dt.held > big.held) {
				big = dt
			}
		}
		if big == nil {
			p.nextCheck = p.held + p.d.lim.openBytes/16
			return
		}
		dropped := big.thin()
		if !big.thinnedOpen {
			big.thinnedOpen = true
			p.limited = append(p.limited, big)
		}
		if !dropped {
			big.floored = true
			continue
		}
		t := big.held + big.kvHeld()
		p.held += t - big.total
		big.total = t
	}
}

// openWarning is the one warning for the tables whose samples thinOpen cut
// short, naming at most ten of them.
func (p *pass2) openWarning() {
	var names []string
	for _, dt := range p.limited {
		if dt.lost {
			names = append(names, dt.t.Name)
		}
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	p.d.warns = append(p.d.warns, fmt.Sprintf("the samples of %s were thinned to stay within the scan's memory, because the "+
		"statements of several tables came interleaved; fewer rows of them were judged", firstTen(names, "%s")))
}

// finish judges a table and frees what was collected of it.
func (p *pass2) finish(dt *dumpTable) {
	if dt.judged {
		return
	}
	if f := p.d.lim.finishTime; f != nil {
		start := time.Now()
		defer func() { f(time.Since(start)) }()
	}
	dt.judged = true
	p.held -= dt.total
	dt.total = 0
	s, kv, rows, warns := dt.result()
	p.d.judge(dt.t, dt.p1, s, kv, rows, warns)
	dt.free()
}

// dumpTable collects one table's rows in the second pass.
type dumpTable struct {
	d        *dumpRun
	t        *model.Table
	p1       *p1Table
	lastLine int64
	judged   bool
	rows     int64

	cols   []*model.Column // the columns sampled, as sampler.Table reads them
	hex    []bool
	colIdx []int // each one's index in t.Columns
	pkI    int   // the single integer key's index in t.Columns, or -1
	wins   map[int]*window
	kvc    *kvCollect // nil for a plain table, or a key/value table with no usable columns
	meta   *preset.MetaTable
	subs   []*subjectCollect
	warns  []string // row subjects' warnings, and the one for a thinned sample

	held        int64 // bytes the windows hold, as rowSize counts them
	total       int64 // what the windows and the key/value collector held, as pass2 last counted it
	floored     bool  // the windows are down to their floor
	enforced    bool  // the windows held more than the table's limit
	thinnedOpen bool  // limited because of what all the open tables held
	lost        bool  // and so the sample holds fewer rows than the live read would

	maps    map[*model.Table][]int
	lastSt  *model.Table
	lastMap []int
	row     *sqldump.Row
	cached  []sql.NullString
	build   func() []sql.NullString
}

var nullValue = sqldump.Value{Kind: sqldump.ValNull}

func (d *dumpTable) val(j int) *sqldump.Value {
	if i := d.lastMap[j]; i >= 0 {
		return &d.row.Values[i]
	}
	return &nullValue
}

func (d *dumpTable) buildRow() []sql.NullString {
	if d.cached == nil {
		out := make([]sql.NullString, len(d.cols))
		for i, j := range d.colIdx {
			s, ok := cellText(d.cols[i], d.val(j), d.d.opts.MaxValueLen, d.hex[i])
			out[i] = sql.NullString{String: s, Valid: ok}
		}
		d.cached = out
	}
	return d.cached
}

// newTable plans the collectors of a table from the first pass's facts.
func (d *dumpRun) newTable(t *model.Table, t1 *p1Table) *dumpTable {
	dt := &dumpTable{d: d, t: t, p1: t1, pkI: -1, meta: d.metas[t.Name], maps: map[*model.Table][]int{}, wins: map[int]*window{}}
	dt.build = dt.buildRow
	if t1 == nil {
		t1 = &p1Table{}
		dt.p1 = nil
	}
	dt.lastLine = t1.lastLine
	for i, c := range t.Columns {
		switch {
		case sample.Sampleable(c):
			dt.cols, dt.hex, dt.colIdx = append(dt.cols, c), append(dt.hex, false), append(dt.colIdx, i)
		case sample.ShortBinary(c) && d.hexFn != nil && d.hexFn(t, c):
			dt.cols, dt.hex, dt.colIdx = append(dt.cols, c), append(dt.hex, true), append(dt.colIdx, i)
		}
	}
	// The key the live sampler orders by, when the first pass has its range
	// and the keys are all the file's or counted.
	var rng *intRange
	if pk := t.SinglePK(); pk != nil && sample.IsInteger(pk) {
		dt.pkI = colIndex(t, pk.Name)
		switch r := t1.ranges[strings.ToLower(pk.Name)]; {
		case t1.rows == 0:
			rng = &intRange{}
		case r != nil && !r.bad && !t1.keysUnknown:
			rng = r
		}
		if rng == nil {
			dt.pkI = -1
		}
	}
	opts := d.opts
	limits := []int{opts.SampleRows}
	if dt.meta != nil {
		limits = append(limits, opts.MetaSampleRows)
	}
	for _, n := range limits {
		w := newWindow(n, rng, t1.rows)
		if len(dt.cols) == 0 {
			w.method = methodNone
		}
		w.hold(&dt.held)
		dt.wins[n] = w
	}
	if dt.meta != nil {
		if keyCol, valCol := kvColumns(t, dt.meta); keyCol != nil {
			c := &kvCollect{keyI: colIndex(t, keyCol.Name), valI: colIndex(t, valCol.Name), pkI: -1, keyCol: keyCol, valCol: valCol,
				whole: t1.rows <= int64(d.lim.wholeRows) && t1.bytes <= d.lim.wholeBytes, valueLen: opts.MaxValueLen,
				perKey: keyRows(t, dt.meta, opts.Options), keys: map[string]*kvKey{}, protected: map[string]bool{}}
			if dt.meta.Settings || t.KeyIndex(dt.meta.Key).Unique {
				c.valueLen = settingsValueLen
			}
			if pk := t.SinglePK(); pk != nil && sample.IsInteger(pk) {
				c.pkI = colIndex(t, pk.Name)
			}
			for k := range dt.meta.Keys {
				c.protected[k] = true
			}
			for _, k := range dt.meta.Probe {
				c.protected[k] = true
			}
			dt.kvc = c
		}
	}
	d.rowSubjects(dt)
	return dt
}

// rowSubjects plans the collectors of the table's row subjects, by the live
// rule: no index on the column the rows are found by, no read.
func (d *dumpRun) rowSubjects(dt *dumpTable) {
	t := dt.t
	for _, rs := range d.pr.RowSubjects {
		if rs.Table != t.Name {
			continue
		}
		c := t.Column(rs.Column)
		if c == nil {
			continue
		}
		if !t.KeyIndex(rs.IndexColumn).Found {
			dt.warns = append(dt.warns, fmt.Sprintf("skipped the rows where %s in %s: no index on %s", rs.Where, t.Name, rs.IndexColumn))
			continue
		}
		cond, ok := parseCond(rs.Where)
		var condC *model.Column
		if ok {
			condC = t.Column(cond.col)
		}
		if condC == nil {
			dt.warns = append(dt.warns, fmt.Sprintf("could not read the rows where %s in %s (the condition isn't one a dump file can be checked for)", rs.Where, t.Name))
			continue
		}
		dt.subs = append(dt.subs, &subjectCollect{rs: rs, col: c, condC: condC, cond: cond,
			colI: colIndex(t, c.Name), condI: colIndex(t, condC.Name), rows: &rowHeap{cap: rowSubjectRows}})
	}
}

// mapFor maps the table's final columns to the columns of the structure in
// force when a row was written: an ALTER may have moved a column since.
func (d *dumpTable) mapFor(st *model.Table) []int {
	if st == d.lastSt {
		return d.lastMap
	}
	m, ok := d.maps[st]
	if !ok {
		m = make([]int, len(d.t.Columns))
		for j, c := range d.t.Columns {
			m[j] = colIndex(st, c.Name)
		}
		d.maps[st] = m
	}
	d.lastSt, d.lastMap = st, m
	return m
}

func (d *dumpTable) add(r *sqldump.Row) {
	d.row = r
	d.mapFor(r.Structure)
	d.rows++
	d.cached = nil
	var key ikey
	have := false
	if d.pkI >= 0 {
		key, have = parseKey(d.val(d.pkI))
	}
	for _, w := range d.wins {
		w.offer(key, have, r.Ordinal, d.build)
	}
	if d.held > d.d.lim.sampleBytes && !d.floored {
		d.enforce()
	}
	if d.kvc != nil {
		d.kvc.add(d, r.Ordinal, d.d.lim)
	}
	for _, s := range d.subs {
		cv, ok := cellText(s.condC, d.val(s.condI), 0, false)
		if !ok || !s.matches(cv) {
			continue
		}
		k := ikeyInt(r.Ordinal)
		if have {
			k = key
		}
		v, vok := cellText(s.col, d.val(s.colI), d.d.opts.MaxValueLen, false)
		s.rows.offer(k, r.Ordinal, func() []sql.NullString { return []sql.NullString{{String: v, Valid: vok}} })
	}
}

// kvHeld is the bytes the key/value collector holds.
func (d *dumpTable) kvHeld() int64 {
	if d.kvc == nil {
		return 0
	}
	return d.kvc.held()
}

// thin halves every window of the table, to the floor, and reports whether it
// dropped a row.
func (d *dumpTable) thin() bool {
	dropped := false
	for _, w := range d.wins {
		dropped = w.thin(d.d.lim.sampleFloor) || dropped
	}
	return dropped
}

// enforce thins the table's sample until its windows hold no more than the
// limit, or are down to their floor, and take no more rows than that.
func (d *dumpTable) enforce() {
	d.enforced = true
	for d.held > d.d.lim.sampleBytes {
		if !d.thin() {
			d.floored = true
			return
		}
	}
}

// result is what the live scan would have read of the table.
func (d *dumpTable) result() (s *sample.Sample, kv *kvRead, rows []rowRead, warns []string) {
	opts := d.d.opts
	var held map[int64]bool
	if d.meta != nil {
		if d.kvc == nil {
			kv = newKVRead()
			kv.mode = modeSample
		} else {
			var counts map[string]int64
			kv, held, counts = d.kvc.finish(d.t, d.meta, opts.Options, d.d.lim)
			if opts.KeyCounts != nil {
				opts.KeyCounts(d.t.Name, counts)
			}
		}
	}
	limit := windowRows(opts.Options, kv)
	w := d.wins[limit]
	s = &sample.Sample{Columns: d.cols, Hex: d.hex, Method: w.method}
	if len(d.cols) > 0 {
		var ords []int64
		s.Rows, ords = w.result()
		if (d.enforced || d.thinnedOpen) && int64(len(s.Rows)) < min(int64(limit), d.rows) {
			d.lost = true
		}
		if kv != nil && len(held) > 0 {
			kv.heldRows = make([]bool, len(ords))
			for i, o := range ords {
				kv.heldRows[i] = held[o]
			}
		}
	}
	if tap := d.d.lim.tap; tap != nil {
		wins := map[int]*sample.Sample{}
		for n, w := range d.wins {
			ws := &sample.Sample{Columns: d.cols, Hex: d.hex, Method: w.method}
			ws.Rows, _ = w.result()
			wins[n] = ws
		}
		tap(d.t.Name, wins, kv)
	}
	warns = append(warns, d.warns...)
	if d.enforced && d.lost {
		warns = append(warns, fmt.Sprintf("%s has very wide rows, so its sample was thinned to stay within the scan's memory; "+
			"fewer rows of it were judged", d.t.Name))
	}
	for _, sc := range d.subs {
		var vals []string
		for _, r := range sc.rows.sorted() {
			if r.vals[0].Valid {
				vals = append(vals, r.vals[0].String)
			}
		}
		if len(vals) > 0 {
			rows = append(rows, rowRead{Subject: sc.rs, Column: sc.col, Values: vals})
		}
	}
	return s, kv, rows, warns
}

func (d *dumpTable) free() {
	d.wins, d.kvc, d.subs, d.maps, d.row, d.cached = nil, nil, nil, nil, nil, nil
}

// DatabaseError is returned when the database to scan can't be chosen: the
// file holds tables of several and none was named, or none of the one named.
// It is a mistake in the command, not in the file.
type DatabaseError struct{ msg string }

func (e *DatabaseError) Error() string { return e.msg }
