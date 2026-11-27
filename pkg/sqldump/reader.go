package sqldump

import (
	"context"
	"fmt"
	"io"
)

// countReader counts the bytes that pass through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type tableKey struct{ db, table string }

// reader holds the state of one read: the lexer, the SQL mode, the client
// character set, the user variables the file saves them in, the current
// database, and what has been counted.
type reader struct {
	ctx  context.Context
	lx   *lexer
	cr   *countReader
	v    Visitor
	opts Options

	stats Stats

	mode sqlMode
	vars map[string]string
	cs   clientCharset
	db   string

	// known holds the tables that have a parsed structure or fully read rows.
	// Only those may be named in an unread entry.
	known map[tableKey]struct{}

	// tables holds the structure of each table read, with its column
	// defaults. hasRows holds the tables that have rows in the file: the row
	// reader adds a table with markRows when it reads the table's first row.
	// dbDefs holds the default character set and collation a CREATE or
	// ALTER DATABASE gave each database.
	tables  map[tableKey]*tableInfo
	hasRows map[tableKey]struct{}
	dbDefs  map[string]charColl

	// folded maps a database and a table's name in lower case to the name a
	// structure was last put under: a server with lower_case_table_names
	// takes names that differ only by case for one. triggers holds the
	// tables a CREATE TRIGGER names, by name in lower case.
	folded   map[tableKey]string
	triggers map[tableKey]struct{}

	// views holds the views the file creates, by database and name in lower
	// case.
	views map[tableKey]struct{}

	// shown holds the databases handed to the visitor. dbSpell maps a
	// database name in lower case to the spelling the file first gave it.
	shown   map[string]bool
	dbSpell map[string]string

	// rows holds what the row reader keeps for each table with rows. aiShift
	// is set once the file changes auto_increment_increment or
	// auto_increment_offset. rd holds the row reader's buffers.
	rows    map[tableKey]*rowState
	aiShift bool
	rd      rowBufs

	users  int
	warned map[string]bool

	hdr     Header
	hdrSent bool

	// fl is the server the header names, read apart from the header's
	// display facts: a version too odd to show still says MariaDB.
	fl    flavour
	flSet bool

	stop bool

	num  []byte // the text of the last number read
	conv []byte // a hex literal converted from latin1
}

func newReader(ctx context.Context, src io.Reader, v Visitor, opts Options) *reader {
	cr := &countReader{r: src}
	r := &reader{
		ctx:   ctx,
		cr:    cr,
		v:     v,
		opts:  opts,
		mode:  sqlMode{known: true},
		vars:  map[string]string{},
		cs:    clientCharset{name: "utf8mb4", info: charsets["utf8mb4"]},
		known: map[tableKey]struct{}{},

		tables:  map[tableKey]*tableInfo{},
		hasRows: map[tableKey]struct{}{},
		rows:    map[tableKey]*rowState{},
		dbDefs:  map[string]charColl{},
		warned:  map[string]bool{},

		folded:   map[tableKey]string{},
		triggers: map[tableKey]struct{}{},
		shown:    map[string]bool{},
		views:    map[tableKey]struct{}{},
		dbSpell:  map[string]string{},
	}
	r.stats.ByKind = map[Kind]int{}
	r.lx = newLexer(ctx, cr, opts.MaxChars)
	r.lx.onComment = r.onComment
	return r
}

// markKnown records that a table has a parsed structure or fully read rows.
func (r *reader) markKnown(db, table string) {
	r.known[tableKey{db, table}] = struct{}{}
}

func (r *reader) isKnown(db, table string) bool {
	_, ok := r.known[tableKey{db, table}]
	return ok
}

func (r *reader) warnOnce(key, text string) {
	if r.warned[key] {
		return
	}
	r.warned[key] = true
	r.v.Warning(Warning{Text: text})
}

func (r *reader) snapshot() Stats {
	s := r.stats
	s.Bytes = r.cr.n
	s.Views, s.Users = len(r.views), r.users
	return s
}

func (r *reader) run() error {
	for !r.stop {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		st := r.begin()
		first := st.next()
		// An empty statement isn't counted, unless a client command or a
		// broken version comment is all it holds.
		if !st.client && !st.lx.vFault {
			if first.kind == tokEOF {
				break
			}
			if first.kind == tokEnd {
				continue
			}
		}
		st.line = first.line
		if st.lx.vOpen == 0 {
			st.line = st.lx.vLine // it starts with a version comment
		}
		class, why := r.dispatch(st, first)
		r.finish(st, class, why)
	}
	if r.stop {
		// The rest of the file is one unread entry; still read it through, so
		// that the byte count and a damaged archive are seen.
		if _, err := io.Copy(io.Discard, ctxReader{r.ctx, r.lx.br}); err != nil && r.lx.err == nil {
			r.lx.err = err
		}
	}
	r.end()
	if err := r.lx.err; err != nil {
		if r.ctx.Err() != nil {
			return r.ctx.Err()
		}
		return ErrRead
	}
	return nil
}

// end sends what is left to send once the file is done.
func (r *reader) end() {
	r.sendHeader()
	if r.users > 0 {
		noun := "users"
		if r.users == 1 {
			noun = "user"
		}
		r.v.Warning(Warning{Text: fmt.Sprintf(warnUsersFormat, r.users, noun)})
	}
	if !r.mode.literal && r.stats.Statements() > 0 {
		r.v.Warning(Warning{Text: WarnNoSQLMode})
	}
}

// finish counts a statement and reports it when it is unread. It reads the
// statement to its end first, so that whatever path classified it, a second
// statement before the delimiter, a client command or a version comment a
// server may skip can't be missed. A client command and a second statement
// that is a SET, a USE or a DELIMITER leave the rest of the file unread, and
// so do a USE, a SET and a CREATE or ALTER DATABASE that such a comment
// leaves unread (versioned). None of them names a table, since what the rest
// held can't be told.
func (r *reader) finish(st *stmt, class Class, why Reason) {
	st.skipRest()
	vUnread, vToEnd := r.versioned(st)
	switch {
	case st.client:
		class, why = ClassUnread, ReasonClient
		st.toEnd = true
	case st.several && !st.toEnd:
		class, why = ClassUnread, ReasonSeveral
	case vUnread && !st.toEnd:
		class, why = ClassUnread, ReasonVersion
	case st.err == ReasonString:
		class, why = ClassUnread, ReasonString
	case st.eof:
		class, why = ClassUnread, ReasonEOF
	case st.err == ReasonIdentLength && (class == ClassRead || class == ClassStructure):
		class, why = ClassUnread, ReasonIdentLength
	}
	if class == ClassUnread && (st.state || vToEnd) {
		st.toEnd = true
	}
	if st.toEnd {
		r.stop = true
	}
	if !vUnread {
		for _, f := range st.later {
			f()
		}
	}
	r.stats.ByKind[st.kind]++
	switch class {
	case ClassRead:
		r.stats.Read++
	case ClassKnown:
		r.stats.Known++
	case ClassStructure:
		r.stats.Structure++
	default:
		r.stats.Unread++
		u := Unread{Line: st.line, Kind: st.kind, Reason: why, ToEnd: st.toEnd}
		if st.table != "" && !st.several && !st.client && !vUnread && r.isKnown(st.tableDB, st.table) {
			u.Database, u.Table = st.tableDB, st.table
		}
		if len(r.stats.UnreadList) < maxUnreadListed {
			r.stats.UnreadList = append(r.stats.UnreadList, u)
		}
		r.v.Unread(u)
	}
	if st.kind != KindSet || st.line > maxHeaderComment {
		r.sendHeader()
	}
	r.syncLexer()
}

// versioned says what the statement's uncertain version comments, which a
// supported server may skip, do to it. Such a comment stands where skipping
// it changes nothing that loads:
//   - as the whole statement, only for a SET (whose assignments then become
//     unknown) or an ANALYZE TABLE of a histogram;
//   - in CREATE TABLE, and CREATE or ALTER DATABASE, as a form MySQL writes in
//     a version comment, in its place (the parsers call lexer.approve);
//   - in a SET, after SET, holding only string and number literals.
//
// Anywhere else, or broken (see blockComment), it makes the statement unread,
// and finish then applies nothing the statement would change (stmt.apply). A
// USE, a CREATE or ALTER DATABASE, or a SET leave the rest of the file
// unread too: a server that skipped the comment may be in another database,
// SQL mode or character set than the reader.
func (r *reader) versioned(st *stmt) (unread, toEnd bool) {
	lx := st.lx
	if lx.vOpen < 0 {
		return false, false
	}
	whole := !lx.vFault && lx.vOpen == 0 && lx.vOutside == 0
	switch st.kind {
	case KindUse:
		return true, true
	case KindCreateDatabase, KindAlterDatabase:
		ok := !whole && !lx.vFault && lx.approved()
		return !ok, !ok
	case KindCreateTable:
		return lx.vFault || !lx.approved(), false
	case KindSet:
		ok := whole || !lx.vFault && !lx.vNonLit && lx.vOpen >= st.objTok
		return !ok, !ok
	case KindAnalyzeTable:
		return !whole, false
	}
	return true, false
}

// syncLexer gives the lexer the SQL mode and character set that hold now.
func (r *reader) syncLexer() {
	lx := r.lx
	lx.noBackslash, lx.ansiQuotes = r.mode.flags()
	lx.mb = mbNone
	lx.cs = csKeep
	if !r.cs.unknown {
		lx.mb = r.cs.info.mb
		if r.cs.info.decoded {
			lx.cs = r.cs.info.kind
		}
	}
}

// ctxReader stops reading once its context is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
