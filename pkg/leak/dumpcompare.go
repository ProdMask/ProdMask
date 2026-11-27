package leak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/sample"
	"github.com/ProdMask/ProdMask/pkg/sqldump"
)

// ErrSecondDatabase stops a read of a dump that holds a table the hash file
// names in two databases, when no database was chosen. It names nothing.
var ErrSecondDatabase = errors.New("the dump holds a table the hash file names in more than one database: pass --database to choose one")

// ErrUnnamedDatabase stops a read with a chosen database, of a dump that holds
// a table the hash file names both in a database the file never names and in
// a named one. It names nothing.
var ErrUnnamedDatabase = errors.New("the dump holds a table the hash file names in a database it doesn't name and in a named one: give a dump of one database, or one that names each of its databases")

// ErrNotADump is the error of a file with no statement the reader recognises,
// such as an image: no report is made of it.
var ErrNotADump = errors.New("the file given to --dump holds no SQL statement the reader recognises, so it isn't a dump")

// What stops a column of a dump: the words the report prints in brackets.
const (
	stoppedTableUnread = "a statement of this table in the dump wasn't read"
	stoppedAnyUnread   = "a statement in the dump wasn't read, and its table can't be told"
)

// maxDumpWarnings is how many of the reader's warnings a report keeps.
const maxDumpWarnings = 20

// CompareDumpOptions control CompareDump.
type CompareDumpOptions struct {
	Allow      *Allowlist
	FailExcept []string
	// MaxTime is the limit on the whole read; 0 means none.
	MaxTime time.Duration
	Version string
	// Database limits the read to one database of the dump. Without it, the
	// first database that holds a table of the hash file is read. In a dump
	// that never names its database, it names the unnamed one, as for
	// scan.RunDump.
	Database string
	// File is the dump's base name, and Compression is "gzip" or "", for the
	// report.
	File        string
	Compression string
	// ReadProgress, when set, is told about once for every megabyte read:
	// the bytes read so far, as BytesRead counts them when it is set, the
	// file's Size, and the table the last row went into.
	ReadProgress func(done, total int64, table string)
	Size         int64
	BytesRead    func() int64

	panicAfterRead bool // tests make the code after the read fail
}

// dumpTable is what to read in one table of a dump: the tableRead of the
// hash file's table, and what the dump has shown of it so far.
type dumpTable struct {
	r      *tableRead
	final  *model.Table // the structure as the dump leaves it
	rows   int64
	unread bool // a statement of the table wasn't read

	// The binding is the targets' places in one structure.
	bound   *model.Table
	plainAt []int
	plainCh []int // the cut of each plain target, in characters; 0 for none
	keyed   []*target
	match   *keyMatcher
	keyAt   int
	valAt   int
	valCh   int
}

// dumpRead is the visitor of CompareDump.
type dumpRead struct {
	sqldump.BaseVisitor
	line   int64 // the last row's line, for a fault outside the reader
	opts   CompareDumpOptions
	ex     *extractor
	hs     *hasher
	exact  map[string]*dumpTable
	folded map[string]*dumpTable
	tables []*dumpTable

	db     string
	dbSet  bool
	others bool // a named database other than the one chosen holds a table of the hash file
	err    error
	stop   context.CancelFunc

	hdr      sqldump.Header
	warnings []string
	skipped  int // warnings beyond the cap
	stopAll  bool
	cur      string // the table the last row went into, for the progress line
}

// CompareDump reads a dump once and counts, in every column and key the hash
// file names, the sampled values it finds: Compare, with the dump playing
// staging. It needs no server, and only names and counts leave it. With an
// error it returns the result too when the read had begun, so a caller can
// report what was read.
func CompareDump(ctx context.Context, r io.Reader, f *File, key Key, opts CompareDumpOptions) (out *model.LeakResult, outErr error) {
	var d *dumpRead
	defer func() {
		// A fault after the read becomes a fixed error that holds the line only.
		if p := recover(); p != nil {
			line := int64(0)
			if d != nil {
				line = d.line
			}
			out, outErr = nil, &sqldump.PanicError{Line: int(line)}
		}
	}()
	start := time.Now()
	if err := f.CheckKey(key); err != nil {
		return nil, err
	}
	allow, domains, addresses := mergeAllow(f, opts.Allow)
	d = &dumpRead{opts: opts, ex: newExtractor(allow), hs: key.hasher(f.Salt),
		exact: map[string]*dumpTable{}, folded: map[string]*dumpTable{}}
	res := &model.LeakResult{
		Tool: "prodmask", Version: opts.Version, GeneratedAt: start.UTC().Truncate(time.Second),
		Hashes: model.LeakHashesInfo{Database: f.Database, CreatedAt: f.CreatedAt, ToolVersion: f.ToolVersion, SampleRows: f.SampleRows},
		Limits: report.LeakLimitsDump(f.SampleRows),
	}
	for _, w := range f.Warnings {
		res.Warnings = append(res.Warnings, "on production: "+w)
	}
	res.Columns = make([]model.LeakColumn, len(f.Columns))
	colTable := d.plan(f, res.Columns)

	// One chunk size for the whole read: no value is cut before its own
	// column's cut, which looks at characters again.
	maxChars := 0
	for _, fc := range f.Columns {
		maxChars = max(maxChars, fc.MaxChars)
	}
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.stop = cancel
	if opts.MaxTime > 0 {
		var stopTimer context.CancelFunc
		readCtx, stopTimer = context.WithTimeout(readCtx, opts.MaxTime)
		defer stopTimer()
	}
	if opts.ReadProgress != nil {
		r = &progressReader{r: r, fn: func(n int64) {
			if opts.BytesRead != nil {
				n = opts.BytesRead()
			}
			opts.ReadProgress(n, opts.Size, d.cur)
		}}
	}
	stats, rerr := sqldump.Read(readCtx, r, d, sqldump.Options{MaxChars: maxChars})
	if opts.panicAfterRead {
		panic("test panic")
	}
	if d.err != nil {
		return nil, d.err
	}
	if rerr == nil || errors.Is(rerr, sqldump.ErrRead) {
		recognised := false
		for k, n := range stats.ByKind {
			recognised = recognised || (k != sqldump.KindOther && n > 0)
		}
		if !recognised {
			return nil, ErrNotADump
		}
	}
	timedOut := false
	if rerr != nil {
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case errors.Is(rerr, context.DeadlineExceeded) && opts.MaxTime > 0:
			timedOut, rerr = true, nil
		}
	}

	var by string
	switch {
	case rerr != nil:
		by = rerr.Error()
	case timedOut:
		by = "--max-time"
	}
	for i, fc := range f.Columns {
		c, dt := &res.Columns[i], colTable[i]
		t := dt.final
		state := columnState(t, fc)
		if state == model.LeakNotOnStaging && t != nil && columnsGuessed(t) {
			state = model.LeakUnreadable
		}
		if state != "" {
			c.State = state
			continue
		}
		why := by
		switch {
		case why != "":
		case dt.unread:
			why = stoppedTableUnread
		case d.stopAll:
			why = stoppedAnyUnread
		}
		c.RowsRead = dt.rows
		if why != "" {
			c.State, c.StoppedBy = model.LeakStopped, why
		} else {
			c.RowsEstimate = dt.rows
		}
	}
	for _, dt := range d.tables {
		for _, t := range append(slices.Clone(dt.r.plain), dt.r.keyed...) {
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
	res.Warnings = append(res.Warnings, d.warnings...)
	if d.skipped > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d more warnings about the dump aren't listed", d.skipped))
	}

	res.LeftOut = slices.Clone(f.LeftOut)
	read := map[string]bool{}
	for i := range res.Columns {
		c := &res.Columns[i]
		if c.State == model.LeakRead {
			read[c.Location()] = true
		}
		fillOdds(c)
		c.Line = report.LeakLineDump(*c)
	}
	applyExcept(res, opts.FailExcept)
	res.Allowed = model.LeakAllowed{Domains: domains, Addresses: addresses, ValuesSkipped: f.ValuesSkipped + d.ex.skipped}
	summarize(res, time.Since(start))

	res.Server = model.ServerInfo{Version: d.hdr.ServerVersion}
	res.Server.Flavor = "mysql"
	if d.hdr.MariaDB {
		res.Server.Flavor = "mariadb"
	}
	if res.Database == "" {
		res.Database = d.db
	}
	if res.Database == "" {
		res.Database = d.hdr.Database
	}
	res.Dump = d.info(stats, f.SampleRows, len(read))
	return res, rerr
}

// plan sets the hash file's columns out as what to read in each table, and
// says which table each column is in. No structure is known yet, so every
// column has its targets, and a row reads only the ones its structure keeps.
func (d *dumpRead) plan(f *File, out []model.LeakColumn) []*dumpTable {
	targets := map[string]*target{}
	colTable := make([]*dumpTable, len(f.Columns))
	for i, fc := range f.Columns {
		c := &out[i]
		*c = model.LeakColumn{
			Table: fc.Table, Column: fc.Column, MetaKey: fc.MetaKey, Kind: fc.Kind, Severity: fc.Kind.Severity(),
			State: model.LeakRead, Sample: fc.Sample, Exact: fc.Exact, Sampled: fc.Values, EstimatedValues: fc.EstimatedValues,
		}
		dt := d.exact[fc.Table]
		if dt == nil {
			dt = &dumpTable{r: &tableRead{name: fc.Table}}
			d.exact[fc.Table] = dt
			if _, ok := d.folded[strings.ToLower(fc.Table)]; !ok {
				d.folded[strings.ToLower(fc.Table)] = dt
			}
			d.tables = append(d.tables, dt)
		}
		dt.r.columns = append(dt.r.columns, c)
		addTarget(dt.r, targets, d.hs, fc, c)
		colTable[i] = dt
	}
	return colTable
}

// find finds the hash file's table that a dump's table is: by name, then
// ignoring letter case, as a staging database's tables are found.
func (d *dumpRead) find(name string) *dumpTable {
	if dt := d.exact[name]; dt != nil {
		return dt
	}
	return d.folded[strings.ToLower(name)]
}

// accept says whether a statement of a database is read. Without a chosen
// database the first one to hold a table of the hash file is; a second one
// stops the read. With one, its tables are read; in a dump that never names
// its database, the unnamed one is the file's one database, which the choice
// names, as scan --dump takes it, and a named database holding a table of the
// hash file beside it stops the read.
func (d *dumpRead) accept(db string) bool {
	switch {
	case d.err != nil:
		return false
	case d.opts.Database != "":
		// The report names the file's spelling, never what --database holds.
		unnamed := d.dbSet && d.db == ""
		switch {
		case db == "" && d.dbSet && !unnamed:
			return false // the database chosen came by its name
		case db == "" && d.others, db != "" && unnamed:
			d.err = ErrUnnamedDatabase
			d.stop()
			return false
		case db != "" && !strings.EqualFold(db, d.opts.Database):
			d.others = true
			return false
		}
		if !d.dbSet {
			d.db, d.dbSet = db, true
		}
		return true
	case !d.dbSet:
		d.db, d.dbSet = db, true
		return true
	case db == d.db:
		return true
	}
	d.err = ErrSecondDatabase
	d.stop()
	return false
}

func (d *dumpRead) Header(h sqldump.Header) { d.hdr = h }

func (d *dumpRead) Warning(w sqldump.Warning) {
	if len(d.warnings) >= maxDumpWarnings {
		d.skipped++
		return
	}
	d.warnings = append(d.warnings, report.Clean(w.Text))
}

func (d *dumpRead) Structure(db string, t *model.Table) {
	if dt := d.find(t.Name); dt != nil && d.accept(db) {
		dt.final = t
	}
}

// Unread stops what an unread statement could have held: the columns of its
// table, or, when its table can't be told, every column. A table the hash file
// doesn't name, or one in another database than the one read, costs nothing.
func (d *dumpRead) Unread(u sqldump.Unread) {
	if u.Table == "" {
		d.stopAll = true
		return
	}
	if dt := d.find(u.Table); dt != nil && d.accept(u.Database) {
		dt.unread = true
	}
}

func (d *dumpRead) Row(row *sqldump.Row) {
	d.line, d.cur = row.Line, row.Table
	dt := d.find(row.Table)
	if dt == nil || !d.accept(row.DB) {
		return
	}
	if dt.final == nil {
		dt.final = row.Structure
	}
	dt.rows++
	if dt.bound != row.Structure {
		dt.bind(row.Structure)
	}
	for i, t := range dt.r.plain {
		if at := dt.plainAt[i]; at >= 0 {
			if v, ok := valueText(row.Values[at], dt.plainCh[i]); ok {
				look(t, v, dt.rows, d.ex, d.hs)
			}
		}
	}
	if dt.match != nil {
		k, ok := valueText(row.Values[dt.keyAt], 0)
		if !ok {
			return
		}
		if i := dt.match.match(k); i >= 0 {
			if v, ok := valueText(row.Values[dt.valAt], dt.valCh); ok {
				look(dt.keyed[i], v, dt.rows, d.ex, d.hs)
			}
		}
	}
}

// bind finds the targets' columns in a structure, as the select list of a
// live read does: a target whose column the structure can't give is left
// alone, and its state says why.
func (dt *dumpTable) bind(t *model.Table) {
	dt.bound = t
	dt.plainAt, dt.plainCh = dt.plainAt[:0], dt.plainCh[:0]
	for _, tg := range dt.r.plain {
		at, ch := -1, 0
		if columnState(t, tg.file) == "" {
			at = columnAt(t, tg.file.Column)
			ch = cutOf(t.Columns[at], tg.file.MaxChars)
		}
		dt.plainAt, dt.plainCh = append(dt.plainAt, at), append(dt.plainCh, ch)
	}
	dt.keyed, dt.match, dt.keyAt, dt.valAt, dt.valCh = nil, nil, -1, -1, 0
	var keys []string
	for _, tg := range dt.r.keyed {
		if columnState(t, tg.file) != "" {
			continue
		}
		if dt.keyed == nil {
			dt.valCh = cutOf(t.Column(tg.file.Column), tg.file.MaxChars)
		}
		dt.keyed = append(dt.keyed, tg)
		keys = append(keys, tg.file.MetaKey)
		dt.keyAt, dt.valAt = columnAt(t, tg.file.KeyColumn), columnAt(t, tg.file.Column)
	}
	if len(keys) > 0 {
		dt.match = newKeyMatcher(keys)
	}
}

// columnAt is a column's place in a table, or -1.
func columnAt(t *model.Table, name string) int {
	for i, c := range t.Columns {
		if strings.EqualFold(c.Name, name) {
			return i
		}
	}
	return -1
}

// cutOf is how many characters of a column's values are read: text is cut
// where the hash file cut it, as LEFT cuts it on a server.
func cutOf(c *model.Column, n int) int {
	if c != nil && sample.IsText(c) && n > 0 {
		return n
	}
	return 0
}

// valueText is a value as the text a server's read gives, cut to n characters
// when n is above 0. NULLs, and bytes the column holds raw, aren't looked at.
func valueText(v sqldump.Value, n int) (string, bool) {
	if v.Kind != sqldump.ValString && v.Kind != sqldump.ValNumber {
		return "", false
	}
	if n > 0 {
		for i := range v.Bytes {
			if n == 0 {
				return string(v.Bytes[:i]), true
			}
			if v.Bytes[i]&0xC0 != 0x80 {
				n--
			}
		}
	}
	return string(v.Bytes), true
}

// columnsGuessed reports whether a structure is the one the reader made for a
// table the dump never creates and whose INSERTs name no columns: every column
// is called column_1 onwards.
func columnsGuessed(t *model.Table) bool {
	if len(t.Columns) == 0 {
		return false
	}
	for i, c := range t.Columns {
		if c.Name != "column_"+strconv.Itoa(i+1) {
			return false
		}
	}
	return true
}

// info is the check's facts about the dump, for its JSON report.
func (d *dumpRead) info(st sqldump.Stats, sampleRows, columns int) *model.DumpInfo {
	n := sampleRows
	if n <= 0 {
		n = DefaultSampleRows
	}
	info := &model.DumpInfo{
		File: d.opts.File, Compression: d.opts.Compression, Bytes: st.Bytes, Producer: d.hdr.Producer,
		Statements: st.Statements(), ByKind: map[string]int{}, Rows: st.Rows, Defaults: st.DefaultsNoLiteral,
		Unread: st.Unread, SampleRows: n, Judged: report.LeakDumpJudged(columns, n),
	}
	for k, c := range st.ByKind {
		info.ByKind[string(k)] = c
	}
	info.Bodies, info.Users = model.DumpBodiesOf(info.ByKind, st.Views), st.Users
	for _, u := range st.UnreadList {
		info.UnreadList = append(info.UnreadList, model.DumpUnread{Line: u.Line, Kind: string(u.Kind), Reason: string(u.Reason),
			Database: u.Database, Table: u.Table, ToEnd: u.ToEnd})
	}
	return info
}
