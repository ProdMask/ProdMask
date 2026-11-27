package sqldump

import "strings"

// seenBits records words a skipped statement held, outside its strings.
type seenBits uint8

const (
	seenIdentified seenBits = 1 << iota
	seenHistogram
	seenDuplicate
	seenString // a string literal, or DATA, which can hold column values
)

// stmt is the statement being read. Parsers pull tokens from it, one at a
// time, and never hold more than one token of lookahead.
type stmt struct {
	r  *reader
	lx *lexer

	kind    Kind
	line    int
	table   string // set by a parser that has read the table's name
	tableDB string
	toEnd   bool

	peeked bool
	pk     token
	depth  int
	ended  bool // the delimiter or the end of the file was read
	eof    bool // the end of the file was read, not the delimiter
	err    Reason
	seen   seenBits
	prevOn bool

	mod   string // unique, fulltext or spatial, before CREATE INDEX
	known bool   // a structure statement that changed nothing

	// Under a delimiter other than ;, the client sends everything up to the
	// delimiter as one query, and the server runs each of its statements.
	// semi is set by a semicolon and cleared by the next token, which sets
	// several, and state when it is SET, USE or DELIMITER; body is set in a
	// stored program, whose reader follows its own semicolons. client is set
	// when a command of the client's own ended the statement.
	semi    bool
	several bool
	state   bool
	body    bool
	client  bool

	// objTok is the count of tokens through SET, after which an uncertain
	// version comment of literals may stand. targets holds what a SET
	// assigned.
	objTok  int
	targets []string

	// later holds what the statement changes in what the reader holds: the
	// structures, the databases and the counts. finish applies it unless the
	// version rule leaves the statement unread, since a server that skips the
	// comment changes none of it. orReplace is set by CREATE OR REPLACE.
	later     []func()
	orReplace bool

	// fxWatch is set while a SET's value is read; fx is then set by a := or
	// a function call in it, either of which may set a user variable.
	// fxPrev says what the last token was: ':', '.', or 'f' for a name a (
	// would make a call.
	fxWatch bool
	fx      bool
	fxPrev  byte
}

// apply defers f, a change to what the reader holds, to finish.
func (st *stmt) apply(f func()) {
	st.later = append(st.later, f)
}

// switchTo switches to the database a USE names, once finished.
func (st *stmt) switchTo(name string) {
	st.apply(func() { st.r.setDatabase(st.r.dbName(name)) })
}

// nameDatabase hands on the name CREATE or ALTER DATABASE gives, for the
// report to show, once finished. The current database stays: only USE
// switches it.
func (st *stmt) nameDatabase(name string) {
	st.apply(func() { st.r.showDatabase(st.r.dbName(name)) })
}

func (r *reader) begin() *stmt {
	st := &stmt{r: r, lx: r.lx, kind: KindOther}
	st.line = r.lx.line
	r.lx.startStatement()
	return st
}

// changesSession reports SET, USE and DELIMITER, which change the session
// for what follows them.
func changesSession(t token) bool {
	return t.is("set") || t.is("use") || t.is("delimiter")
}

func (st *stmt) pull() token {
	if st.ended {
		if st.eof {
			return token{kind: tokEOF, line: st.lx.line}
		}
		return token{kind: tokEnd, line: st.lx.line}
	}
	t := st.lx.next()
	switch t.kind {
	case tokEnd:
		st.ended = true
		return t
	case tokEOF:
		st.ended, st.eof = true, true
		return t
	case tokClient:
		st.ended, st.client = true, true
		return token{kind: tokEnd, line: t.line}
	case tokErr:
		if st.err == "" {
			st.err = t.err
		}
	case tokSym:
		switch t.sym {
		case '(':
			st.depth++
		case ')':
			st.depth--
		case ';':
			st.semi = st.semi || !st.body
			return t
		}
	}
	if st.semi {
		st.semi, st.several = false, true
		st.state = st.state || changesSession(t)
	}
	if st.fxWatch {
		st.watchEffects(t)
	}
	return t
}

// watchEffects notes a := or a function call in a SET's value: anything but
// CONCAT and REPLACE, which the reader evaluates and which set nothing.
func (st *stmt) watchEffects(t token) {
	if t.isSym('=') && st.fxPrev == ':' || t.isSym('(') && st.fxPrev == 'f' {
		st.fx = true
	}
	switch {
	case t.isSym(':'):
		st.fxPrev = ':'
	case t.isSym('.'):
		st.fxPrev = '.'
	case t.kind == tokWord && (t.is("concat") || t.is("replace")) && st.fxPrev != '.':
		st.fxPrev = 0
	case t.kind == tokWord || t.kind == tokIdent:
		st.fxPrev = 'f'
	default:
		st.fxPrev = 0
	}
}

// next consumes the next token of the statement.
func (st *stmt) next() token {
	if st.peeked {
		st.peeked = false
		return st.pk
	}
	return st.pull()
}

// peek looks at the next token without consuming it.
func (st *stmt) peek() token {
	if !st.peeked {
		st.pk = st.pull()
		st.peeked = true
	}
	return st.pk
}

// skipRest consumes the statement to its end, token by token, keeping
// nothing of its strings.
func (st *stmt) skipRest() {
	if st.ended && !st.peeked {
		return
	}
	st.lx.discard = true
	for !st.ended || st.peeked {
		t := st.next()
		if t.kind == tokWord {
			st.note(t)
		} else if t.kind == tokString {
			st.seen |= seenString
		}
	}
	st.lx.discard = false
}

// note records the words a skipped statement is judged by.
func (st *stmt) note(t token) {
	switch len(t.text) {
	case 2:
		st.prevOn = t.is("on")
		return
	case 9:
		if t.is("histogram") {
			st.seen |= seenHistogram
		} else if t.is("duplicate") && st.prevOn {
			st.seen |= seenDuplicate
		}
	case 10:
		if t.is("identified") {
			st.seen |= seenIdentified
		}
	case 4:
		if t.is("data") {
			st.seen |= seenString
		}
	}
	st.prevOn = false
}

// skipToComma consumes tokens up to and including a comma at the statement's
// top level, or up to the end of the statement.
func (st *stmt) skipToComma() {
	st.lx.discard = true
	for !st.ended || st.peeked {
		t := st.next()
		if t.isSym(',') && st.depth == 0 {
			break
		}
	}
	st.lx.discard = false
}

// name reads an identifier: a word or a quoted identifier.
func (st *stmt) name() (string, bool) {
	t := st.peek()
	if t.kind != tokWord && t.kind != tokIdent && t.kind != tokNum {
		return "", false
	}
	st.next()
	return string(t.text), true
}

// qname reads a name that may be qualified with a database.
func (st *stmt) qname() (db, name string, ok bool) {
	n, ok := st.name()
	if !ok {
		return "", "", false
	}
	if p := st.peek(); p.isSym('.') {
		st.next()
		n2, ok2 := st.name()
		if !ok2 {
			return "", "", false
		}
		return n, n2, true
	}
	return "", n, true
}

// setTable records the table a statement names; an unqualified name is in
// the current database.
func (st *stmt) setTable(db, name string) {
	st.table, st.tableDB = name, st.r.qualify(db)
}

// ifExists consumes IF EXISTS or IF NOT EXISTS.
func (st *stmt) ifExists() {
	if !st.peek().is("if") {
		return
	}
	st.next()
	if st.peek().is("not") {
		st.next()
	}
	if st.peek().is("exists") {
		st.next()
	}
}

// skipDefiner consumes what follows DEFINER = in a CREATE statement.
func (st *stmt) skipDefiner() {
	if st.peek().isSym('=') {
		st.next()
	}
	u := st.next()
	if u.kind == tokVar {
		return // user@host, with the host read as a variable name
	}
	if u.is("current_user") && st.peek().isSym('(') {
		st.next()
		if st.peek().isSym(')') {
			st.next()
		}
		return
	}
	if p := st.peek(); p.kind == tokVar {
		st.next()
	} else if p.isSym('@') {
		st.next()
		st.next()
	}
}

// dispatch reads the statement that began with the token first, and says
// what became of it.
func (r *reader) dispatch(st *stmt, first token) (Class, Reason) {
	if r.opts.test.panicAtLine != 0 && st.line == r.opts.test.panicAtLine {
		panic("test panic")
	}
	if first.kind != tokWord || len(first.text) > 12 {
		return r.other(st)
	}
	switch strings.ToLower(string(first.text)) {
	case "insert":
		return r.doInsert(st, false)
	case "replace":
		return r.doInsert(st, true)
	case "create":
		return r.doCreate(st)
	case "alter":
		return r.doAlter(st)
	case "drop":
		return r.doDrop(st)
	case "truncate":
		st.kind = KindTruncate
		r.truncate(st)
		return r.noRows(st)
	case "use":
		st.kind = KindUse
		if n, ok := st.name(); ok {
			semi := false
			for st.peek().isSym(';') {
				st.next()
				semi = true
			}
			// A word after the name, with no ; between, makes a statement
			// the server rejects: nothing switches. After a ; it is a
			// second statement, which finish makes unread, and the server
			// has switched before it.
			if p := st.peek(); p.kind != tokEnd && p.kind != tokEOF && !semi {
				return r.unread(st, ReasonKind)
			}
			st.switchTo(n)
		}
		return r.noRows(st)
	case "set":
		st.kind = KindSet
		st.objTok = st.lx.ntok
		return r.doSet(st)
	case "delimiter":
		// Not at a line's start, so no command to the reader. The clients
		// still run a statement whose text starts with DELIMITER as their
		// own: the next word becomes the delimiter, and the rest up to the
		// old one is dropped. How the rest of the file splits can't be told,
		// as after a command of the client's own. An executable comment
		// before it is text the clients send to the server.
		if !st.lx.exec {
			st.client = true
		}
		return r.other(st)
	case "lock":
		return r.afterWord(st, KindLockTables, "table", "tables")
	case "unlock":
		return r.afterWord(st, KindUnlockTables, "table", "tables")
	case "start":
		return r.afterWord(st, KindTransaction, "transaction")
	case "begin":
		// BEGIN NOT ATOMIC opens a compound statement that holds rows.
		if p := st.peek(); p.kind != tokEnd && p.kind != tokEOF && !p.is("work") {
			return r.other(st)
		}
		st.kind = KindTransaction
		return r.noRows(st)
	case "commit", "rollback":
		st.kind = KindTransaction
		return r.noRows(st)
	case "flush":
		st.kind = KindFlush
		return r.noRows(st)
	case "change":
		return r.afterWord(st, KindChangeSource, "master", "replication")
	case "grant", "revoke":
		st.kind = KindGrant
		return r.doUser(st)
	case "update":
		st.kind = KindUpdate
		for p := st.peek(); p.is("low_priority") || p.is("ignore"); p = st.peek() {
			st.next()
		}
		r.tableOf(st)
		return r.unread(st, ReasonKind)
	case "delete":
		st.kind = KindDelete
		for p := st.peek(); p.is("low_priority") || p.is("quick") || p.is("ignore"); p = st.peek() {
			st.next()
		}
		if st.peek().is("from") {
			st.next()
			r.tableOf(st)
		}
		return r.unread(st, ReasonKind)
	case "load":
		if p := st.peek(); p.is("data") || p.is("xml") {
			st.kind = KindLoadData
		}
		return r.unread(st, ReasonKind)
	case "call":
		st.kind = KindCall
		return r.unread(st, ReasonKind)
	case "source":
		st.kind = KindSource
		return r.unread(st, ReasonKind)
	case "analyze":
		st.skipRest()
		if st.seen&seenHistogram != 0 && st.seen&seenString == 0 {
			st.kind = KindAnalyzeTable
			return ClassKnown, ""
		}
		return ClassUnread, ReasonKind
	case "select", "do":
		if st.peek().is("setval") {
			st.kind = KindSetval
			return r.noRows(st)
		}
	}
	return r.other(st)
}

// noRows skips a statement that holds no rows.
func (r *reader) noRows(st *stmt) (Class, Reason) {
	st.skipRest()
	return ClassKnown, ""
}

// unread skips a statement the reader doesn't read.
func (r *reader) unread(st *stmt, why Reason) (Class, Reason) {
	st.skipRest()
	return ClassUnread, why
}

func (r *reader) other(st *stmt) (Class, Reason) {
	st.kind = KindOther
	return r.unread(st, ReasonKind)
}

// afterWord classifies a statement by the word after its first, one of words.
func (r *reader) afterWord(st *stmt, kind Kind, words ...string) (Class, Reason) {
	t := st.peek()
	for _, w := range words {
		if t.is(w) {
			st.kind = kind
			return r.noRows(st)
		}
	}
	return r.other(st)
}

// tableOf reads a table's name, for naming it in an unread entry.
func (r *reader) tableOf(st *stmt) {
	if db, n, ok := st.qname(); ok {
		st.setTable(db, n)
	}
}

// setDatabase makes name the current database, as USE does.
func (r *reader) setDatabase(name string) {
	r.db = name
	r.showDatabase(name)
}

// dbName returns the spelling the file first gave a database's name, in any
// letter case: a server that folds case takes them for one database, and on
// one that doesn't, taking them for one judges more.
func (r *reader) dbName(name string) string {
	if name == "" {
		return ""
	}
	k := strings.ToLower(name)
	if n, ok := r.dbSpell[k]; ok {
		return n
	}
	r.dbSpell[k] = name
	return name
}

// qualify returns the database of a table a statement names as db.name, or
// the current one for a name with none.
func (r *reader) qualify(db string) string {
	if db == "" {
		return r.db
	}
	return r.dbName(db)
}

// showDatabase hands a database's name to the visitor the first time the file
// names it.
func (r *reader) showDatabase(name string) {
	if r.shown[name] {
		return
	}
	r.shown[name] = true
	r.v.Database(name)
}

func (r *reader) doDrop(st *stmt) (Class, Reason) {
	st.kind = KindDrop
	if st.peek().is("temporary") {
		// A temporary table shadows a table of its name on the server in
		// ways the reader doesn't follow.
		return r.unread(st, ReasonKind)
	}
	t := st.peek()
	for _, w := range []string{"table", "view", "database", "schema", "trigger", "procedure", "function", "event", "sequence"} {
		if t.is(w) {
			if w == "table" || w == "view" {
				st.next()
				r.dropTables(st, w == "view")
			}
			return r.noRows(st)
		}
	}
	return r.other(st)
}

func (r *reader) doInsert(st *stmt, replace bool) (Class, Reason) {
	st.kind = KindInsert
	if replace {
		st.kind = KindReplace
	}
	for {
		p := st.peek()
		switch {
		case p.is("low_priority") || p.is("delayed") || (p.is("high_priority") && !replace):
			st.next()
			continue
		case p.is("ignore") && !replace:
			st.kind = KindInsertIgnore
			st.next()
			continue
		}
		break
	}
	if st.peek().is("into") {
		st.next()
	}
	if !r.cs.usable() {
		return r.unread(st, ReasonCharset)
	}
	why := r.readRows(st)
	if st.table != "" && r.hasTrigger(st.tableDB, st.table) {
		// The table's triggers run with its rows, and may set any user
		// variable.
		clear(r.vars)
	}
	if why != "" {
		st.skipRest()
		return ClassUnread, why
	}
	return ClassRead, ""
}

func (r *reader) doAlter(st *stmt) (Class, Reason) {
	st.kind = KindOther
	for p := st.peek(); p.is("online") || p.is("ignore"); p = st.peek() {
		st.next()
	}
	switch p := st.peek(); {
	case p.is("table"):
		st.next()
		st.kind = KindAlterTable
		if !r.cs.usable() {
			return r.unread(st, ReasonCharset)
		}
		if why := r.readStructure(st); why != "" {
			st.skipRest()
			return ClassUnread, why
		}
		return ClassStructure, ""
	case p.is("database") || p.is("schema"):
		st.next()
		st.kind = KindAlterDatabase
		if n, ok := st.name(); ok {
			st.nameDatabase(n)
			r.dbOptions(st, n)
		} else {
			r.dbOptions(st, r.db)
		}
		return r.noRows(st)
	case p.is("user"):
		st.next()
		st.kind = KindUser
		return r.doUser(st)
	}
	return r.other(st)
}

// doCreate classifies a CREATE statement by the object it creates.
func (r *reader) doCreate(st *stmt) (Class, Reason) {
	st.kind = KindOther
	for {
		p := st.peek()
		switch {
		case p.is("or"):
			st.next()
			if st.peek().is("replace") {
				st.next()
				st.orReplace = true
			}
		case p.is("unique") || p.is("fulltext") || p.is("spatial"):
			st.mod = strings.ToLower(string(p.text))
			st.next()
		case p.is("temporary"):
			// As DROP TEMPORARY: a temporary table or sequence shadows one of
			// its name in ways the reader doesn't follow.
			st.next()
			if p := st.peek(); p.is("table") || p.is("sequence") {
				st.kind = KindCreateTable
				if p.is("sequence") {
					st.kind = KindCreateSequence
				}
			}
			return r.unread(st, ReasonKind)
		case p.is("online") || p.is("offline") || p.is("aggregate"):
			st.next()
		case p.is("definer"):
			st.next()
			st.skipDefiner()
		case p.is("algorithm"):
			st.next()
			if st.peek().isSym('=') {
				st.next()
			}
			st.next()
		case p.is("sql"):
			st.next()
			if st.peek().is("security") {
				st.next()
				st.next()
			}
		default:
			return r.createObject(st, p)
		}
	}
}

func (r *reader) createObject(st *stmt, p token) (Class, Reason) {
	switch {
	case p.is("table"):
		st.next()
		st.kind = KindCreateTable
		return r.structure(st)
	case p.is("index"):
		st.next()
		st.kind = KindCreateIndex
		return r.structure(st)
	case p.is("view"):
		st.kind = KindCreateView
		if r.cs.usable() {
			st.next()
			if why := r.readView(st); why != "" {
				return r.unread(st, why)
			}
		}
	case p.is("trigger"):
		st.kind = KindCreateTrigger
		return r.program(st)
	case p.is("procedure"):
		st.kind = KindCreateProcedure
		return r.program(st)
	case p.is("function"):
		st.kind = KindCreateFunction
		return r.program(st)
	case p.is("event"):
		st.kind = KindCreateEvent
		return r.program(st)
	case p.is("sequence"):
		st.kind = KindCreateSequence
		if r.cs.usable() {
			st.next()
			r.readSequence(st)
		}
	case p.is("database") || p.is("schema"):
		st.next()
		st.kind = KindCreateDatabase
		st.ifExists()
		if n, ok := st.name(); ok {
			st.nameDatabase(n)
			r.dbOptions(st, n)
		}
	case p.is("user"):
		st.next()
		st.kind = KindUser
		return r.doUser(st)
	default:
		return r.other(st)
	}
	return r.noRows(st)
}

func (r *reader) structure(st *stmt) (Class, Reason) {
	if !r.cs.usable() {
		return r.unread(st, ReasonCharset)
	}
	if why := r.readStructure(st); why != "" {
		st.skipRest()
		return ClassUnread, why
	}
	if st.known {
		return ClassKnown, ""
	}
	return ClassStructure, ""
}

// doUser skips CREATE USER, ALTER USER and GRANT, counting those that can
// hold a password.
func (r *reader) doUser(st *stmt) (Class, Reason) {
	st.skipRest()
	if st.kind == KindUser || st.seen&seenIdentified != 0 {
		st.apply(func() { r.users++ })
	}
	return ClassKnown, ""
}
