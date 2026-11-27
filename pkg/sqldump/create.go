package sqldump

import (
	"strconv"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// tk is a token with its text copied, so that it stays valid while the lexer
// reads on.
type tk struct {
	kind tokKind
	s    string // the text as written
	lw   string // lower case, for words only
	sym  byte
	unc  int // the uncertain version comment it came from, or 0
}

func (t tk) is(kw string) bool  { return t.kind == tokWord && t.lw == kw }
func (t tk) isSym(c byte) bool  { return t.kind == tokSym && t.sym == c }
func (t tk) isName() bool       { return t.kind == tokWord || t.kind == tokIdent || t.kind == tokNum }
func (t tk) isEnd() bool        { return t.kind == tokEnd || t.kind == tokEOF || t.kind == tokErr }
func (t tk) isNumber() bool     { return t.kind == tokNum }
func (t tk) isQuoted() bool     { return t.kind == tokString }
func (t tk) isListEnd() bool    { return t.isSym(',') || t.isSym(')') }
func (t tk) isGroupStart() bool { return t.isSym('(') }

// sp parses the tokens of one statement. It counts the parentheses itself,
// and ends an element at a comma or a closing parenthesis at depth base.
type sp struct {
	st    *stmt
	depth int
	base  int
	pk    tk
	have  bool
	bad   bool
}

func newSP(st *stmt) *sp { return &sp{st: st} }

func (p *sp) conv(t token) tk {
	x := tk{kind: t.kind, sym: t.sym, unc: t.unc}
	switch t.kind {
	case tokWord:
		x.s = string(t.text)
		x.lw = strings.ToLower(x.s)
	case tokIdent, tokNum, tokString, tokHex, tokBit, tokVar:
		x.s = string(t.text)
	case tokErr:
		p.bad = true
	}
	return x
}

func (p *sp) peek() tk {
	if !p.have {
		p.pk = p.conv(p.st.peek())
		p.have = true
	}
	return p.pk
}

func (p *sp) next() tk {
	var t tk
	if p.have {
		t = p.pk
		p.have = false
		p.st.next()
	} else {
		t = p.conv(p.st.next())
	}
	if t.kind == tokSym {
		switch t.sym {
		case '(':
			p.depth++
		case ')':
			p.depth--
		}
	}
	return t
}

// str reads a string literal, with the strings that follow it joined.
func (p *sp) str() string {
	p.have = false
	p.st.next()
	b, _ := p.st.joinStrings()
	return string(b)
}

func (p *sp) atEnd() bool { return p.peek().isEnd() }

// elemEnd reports the end of an element of a list: a comma or a closing
// parenthesis at the list's depth, or the end of the statement.
func (p *sp) elemEnd() bool {
	t := p.peek()
	return t.isEnd() || (t.isListEnd() && p.depth == p.base)
}

// skipGroup consumes what follows a parenthesis already read, through its
// closing one.
func (p *sp) skipGroup() {
	target := p.depth - 1
	p.st.lx.discard = true
	for p.depth > target && !p.atEnd() {
		p.next()
	}
	p.st.lx.discard = false
}

// skipElem consumes the rest of an element.
func (p *sp) skipElem() {
	p.st.lx.discard = true
	for !p.elemEnd() {
		if p.next().isGroupStart() {
			p.skipGroup()
			p.st.lx.discard = true
		}
	}
	p.st.lx.discard = false
}

func (p *sp) eq() {
	if p.peek().isSym('=') {
		p.next()
	}
}

func (p *sp) name() (string, bool) {
	t := p.peek()
	if !t.isName() {
		return "", false
	}
	p.next()
	return t.s, true
}

func (p *sp) qname() (db, name string, ok bool) {
	n, ok := p.name()
	if !ok {
		return "", "", false
	}
	if p.peek().isSym('.') {
		p.next()
		n2, ok2 := p.name()
		if !ok2 {
			return "", "", false
		}
		return n, n2, true
	}
	return "", n, true
}

// colDef is a column as the statement declares it.
type colDef struct {
	col       model.Column
	dt        string
	class     typeClass
	args      []string
	length    int64
	members   []string
	unsigned  bool
	zerofill  bool
	cs, coll  string
	binary    bool
	def       colDefault
	onUpdate  string
	gen       string
	invisible bool
	autoInc   bool
	pk, uniq  bool
	first     bool
	after     string
}

// keyDef is an index as the statement declares it.
type keyDef struct {
	kind  string // primary, unique, key, fulltext, spatial
	name  string
	using string
	cols  []string
	subs  []int
}

// fkDef is a foreign key as the statement declares it.
type fkDef struct {
	name     string
	cols     []string
	refDB    string
	refTable string
	refCols  []string
}

// tableOpts are the options after a CREATE TABLE's column list.
type tableOpts struct {
	engine    string
	cs, coll  string
	comment   string
	versioned bool
	sequence  bool
	autoInc   uint64
}

var engineNames = map[string]string{
	"innodb": "InnoDB", "myisam": "MyISAM", "memory": "MEMORY", "heap": "MEMORY",
	"aria": "Aria", "csv": "CSV", "archive": "ARCHIVE", "blackhole": "BLACKHOLE",
	"federated": "FEDERATED", "mrg_myisam": "MRG_MyISAM", "sequence": "SEQUENCE",
	"ndbcluster": "ndbcluster", "rocksdb": "ROCKSDB",
}

func engineName(s string) string {
	if n, ok := engineNames[strings.ToLower(s)]; ok {
		return n
	}
	return s
}

// failure gives the reason a statement can't be read, or "" when the lexer
// already has a fault that finish turns into the reason.
func (p *sp) failure(st *stmt, why Reason) Reason {
	if p.bad || st.err != "" || st.eof {
		st.skipRest()
		return ""
	}
	return why
}

// readStructure reads CREATE TABLE, ALTER TABLE and CREATE INDEX.
func (r *reader) readStructure(st *stmt) Reason {
	switch st.kind {
	case KindCreateTable:
		return r.createTable(st)
	case KindCreateIndex:
		return r.createIndex(st)
	}
	return r.alterTable(st)
}

func (r *reader) createTable(st *stmt) Reason {
	p := newSP(st)
	st.ifExists()
	db, name, ok := p.qname()
	if !ok {
		return p.failure(st, ReasonKind)
	}
	st.setTable(db, name)
	if t := p.peek(); !t.isGroupStart() {
		return p.failure(st, ReasonKind) // LIKE, SELECT and the like
	}
	p.next()
	p.base = 1
	if p.peek().is("like") {
		return ReasonKind
	}
	var cols []*colDef
	var keys []*keyDef
	var fks []*fkDef
	for {
		if why := p.element(&cols, &keys, &fks); why != "" {
			return p.failure(st, why)
		}
		p.skipElem()
		t := p.peek()
		if t.isSym(',') {
			p.next()
			continue
		}
		if t.isSym(')') {
			p.next()
			break
		}
		return p.failure(st, ReasonKind)
	}
	p.base = 0
	var opts tableOpts
	if why := p.tableOptions(&opts); why != "" {
		if why == ReasonInsertForm {
			// The servers fill the table from what follows: the entry names
			// no table.
			st.table, st.tableDB = "", ""
		}
		return p.failure(st, why)
	}
	st.skipRest()
	if p.bad || st.err != "" || st.eof {
		return ""
	}

	f := r.fl
	ti := &tableInfo{t: &model.Table{Name: name, Type: "BASE TABLE", Engine: "InnoDB", Comment: opts.comment}}
	if opts.engine != "" {
		ti.t.Engine = engineName(opts.engine)
	}
	ti.autoStart = opts.autoInc
	if opts.versioned {
		ti.t.Type = "SYSTEM VERSIONED"
	}
	if opts.sequence {
		ti.t.Type = "SEQUENCE" // MariaDB's SHOW CREATE TABLE of a sequence
	}
	cc := f.complete(opts.cs, opts.coll)
	if cc.cs == "" {
		cc = r.dbCharColl(st.tableDB, f)
	}
	ti.cs, ti.coll = cc.cs, cc.coll
	for _, cd := range cols {
		ti.addColumn(cd, f)
	}
	for _, cd := range cols {
		switch {
		case cd.pk:
			ti.addKey(&keyDef{kind: "primary", cols: []string{cd.col.Name}, subs: []int{0}})
		case cd.uniq:
			ti.addKey(&keyDef{kind: "unique", cols: []string{cd.col.Name}, subs: []int{0}})
		}
	}
	for _, kd := range keys {
		ti.addKey(kd)
	}
	for _, fd := range fks {
		ti.addForeignKey(fd, st.tableDB)
	}
	ti.settle()

	// A table the file created, with no DROP since, keeps its structure
	// unless OR REPLACE: servers keep the first table for IF NOT EXISTS and
	// refuse a plain CREATE. The statement is known when the columns and
	// their types are the same. After rows, and over the structure made for
	// rows with none, the columns' names decide.
	old, variant := r.existing(st.tableDB, name)
	switch {
	case old != nil && !old.dropped && !old.implicit && (!st.orReplace || variant):
		if sameDefinition(old.t.Columns, ti.t.Columns) {
			st.known = true
			return ""
		}
		return ReasonRecreate
	case old != nil && r.rowsOf(st.tableDB, old.t.Name):
		if sameColumns(old.t.Columns, ti.t.Columns) {
			st.known = true
			return ""
		}
		return ReasonRecreate
	}
	db = st.tableDB
	st.apply(func() { r.put(db, ti) })
	return ""
}

// element reads one element of a CREATE TABLE's list: a column or a key.
func (p *sp) element(cols *[]*colDef, keys *[]*keyDef, fks *[]*fkDef) Reason {
	t := p.peek()
	if kd := p.readKey(t, ""); kd != nil {
		*keys = append(*keys, kd)
		return ""
	}
	if t.kind == tokWord {
		switch t.lw {
		case "constraint":
			p.next()
			cname := ""
			if n := p.peek(); n.isName() && !n.is("primary") && !n.is("unique") && !n.is("foreign") && !n.is("check") {
				cname = n.s
				p.next()
			}
			switch k := p.peek(); {
			case k.is("primary"), k.is("unique"):
				*keys = append(*keys, p.readKey(k, cname))
			case k.is("foreign"):
				p.next()
				if fd := p.parseFK(cname); fd != nil {
					*fks = append(*fks, fd)
				}
			case k.is("check"):
				p.next()
				p.check()
			}
			return ""
		case "foreign":
			p.next()
			if fd := p.parseFK(""); fd != nil {
				*fks = append(*fks, fd)
			}
			return ""
		case "check":
			p.next()
			p.check()
			return ""
		case "period":
			return ""
		}
	}
	if !t.isName() {
		return ReasonKind
	}
	p.next()
	cd := p.parseColumn(t.s)
	if cd == nil {
		return ReasonKind
	}
	*cols = append(*cols, cd)
	return ""
}

// readKey reads an index from its first word w, the next token: PRIMARY
// [KEY], UNIQUE, FULLTEXT or SPATIAL [KEY|INDEX], or KEY or INDEX. For any
// other token it reads nothing and gives nil.
func (p *sp) readKey(w tk, name string) *keyDef {
	switch w.lw {
	case "primary":
		p.next()
		if p.peek().is("key") {
			p.next()
		}
		return p.parseKey("primary", name)
	case "unique", "fulltext", "spatial":
		p.next()
		if k := p.peek(); k.is("key") || k.is("index") {
			p.next()
		}
		return p.parseKey(w.lw, name)
	case "key", "index":
		p.next()
		return p.parseKey("key", name)
	}
	return nil
}

// parseKey reads an index after its leading words: the name, the type, the
// parts and the options.
func (p *sp) parseKey(kind, name string) *keyDef {
	kd := &keyDef{kind: kind, name: name}
	if p.peek().is("if") {
		p.next()
		p.next()
		p.next()
	}
	if kind != "primary" {
		if t := p.peek(); t.isName() && !t.is("using") {
			kd.name = t.s
			p.next()
		}
	}
	if p.peek().is("using") {
		p.next()
		kd.using = p.next().lw
	}
	kd.cols, kd.subs = p.keyParts()
	for !p.elemEnd() {
		t := p.next()
		switch {
		case t.is("using"):
			kd.using = p.next().lw
		case t.is("invisible") && kd.cols != nil:
			p.st.lx.approve(t.unc, 1) // MySQL writes /*!80000 INVISIBLE */ after the parts
		case t.isGroupStart():
			p.skipGroup()
		}
	}
	return kd
}

// check reads a CHECK constraint's expression, after CHECK, and the NOT
// ENFORCED that MySQL writes after it in a version comment.
func (p *sp) check() {
	if !p.peek().isGroupStart() {
		return
	}
	p.next()
	p.skipGroup()
	if t := p.peek(); t.is("not") && t.unc != 0 {
		p.next()
		if e := p.peek(); e.is("enforced") && e.unc == t.unc {
			p.next()
			p.st.lx.approve(t.unc, 2)
		}
	}
}

// listedOption reads a table or database option that MySQL writes in a
// version comment, from its first word t: [DEFAULT] ENCRYPTION [=] 'text',
// or, for a table, AUTOEXTEND_SIZE [=] a number or a size such as 4M. The
// comment is accepted when the option is all it holds.
func (p *sp) listedOption(t tk, table bool) {
	id, n := t.unc, 1
	from := func(x tk) bool { return x.unc == id }
	if t.is("default") {
		if e := p.peek(); !e.is("encryption") || !from(e) {
			return
		}
		t = p.next()
		n++
	}
	var value func(tk) bool
	switch {
	case t.is("encryption"):
		value = tk.isQuoted
	case table && t.is("autoextend_size"):
		value = func(v tk) bool { return v.isNumber() || isSize(v) }
	default:
		return
	}
	if e := p.peek(); e.isSym('=') && from(e) {
		p.next()
		n++
	}
	if v := p.peek(); value(v) && from(v) {
		p.next()
		p.st.lx.approve(id, n+1)
	}
}

// isSize reports a size written as digits and K, M or G, as AUTOEXTEND_SIZE
// takes it.
func isSize(t tk) bool {
	n := len(t.lw)
	if t.kind != tokWord || n < 2 || !allDigits([]byte(t.lw[:n-1])) {
		return false
	}
	switch t.lw[n-1] {
	case 'k', 'm', 'g':
		return true
	}
	return false
}

// keyParts reads a parenthesised list of key parts: column names with their
// prefix lengths, and an expression as an empty name.
func (p *sp) keyParts() (cols []string, subs []int) {
	if !p.peek().isGroupStart() {
		return nil, nil
	}
	p.next()
	target := p.depth - 1
	expect := true
	for p.depth > target && !p.atEnd() {
		t := p.peek()
		switch {
		case t.isSym(')'):
			p.next()
		case t.isSym(','):
			p.next()
			expect = true
		case expect && t.isGroupStart():
			p.next()
			p.skipGroup()
			cols, subs = append(cols, ""), append(subs, 0)
			expect = false
		case expect && t.isName():
			p.next()
			cols, subs = append(cols, t.s), append(subs, 0)
			expect = false
		case !expect && t.isGroupStart():
			p.next()
			if n := p.peek(); n.isNumber() {
				subs[len(subs)-1], _ = strconv.Atoi(n.s)
			}
			p.skipGroup()
		default:
			p.next()
		}
	}
	return cols, subs
}

// parseFK reads a foreign key after FOREIGN KEY.
func (p *sp) parseFK(name string) *fkDef {
	if p.peek().is("key") {
		p.next()
	}
	fd := &fkDef{name: name}
	if t := p.peek(); t.isName() && !t.is("references") {
		p.next() // the name of the index
	}
	fd.cols, _ = p.keyParts()
	if p.peek().is("references") {
		p.next()
		if db, n, ok := p.qname(); ok {
			fd.refDB, fd.refTable = p.st.r.dbName(db), n
		}
		fd.refCols, _ = p.keyParts()
	}
	p.skipElem()
	if fd.refTable == "" {
		return nil
	}
	return fd
}

// tableOptions reads what follows a CREATE TABLE's column list, to the end of
// the statement, and takes no option from the PARTITION clause. It gives
// ReasonInsertForm when what follows fills the table: a word fillsTable
// reports, or an AS among the table's options.
func (p *sp) tableOptions(o *tableOpts) Reason {
	partition := false // in the PARTITION clause, whose options are a partition's
	for !p.atEnd() {
		t := p.next()
		if p.fillsTable(t) {
			return ReasonInsertForm
		}
		if t.unc != 0 {
			p.listedOption(t, true)
			continue
		}
		if t.kind != tokWord || p.depth != 0 || partition {
			continue
		}
		switch t.lw {
		case "engine":
			p.eq()
			o.engine = p.next().s
		case "auto_increment":
			p.eq()
			if n := p.peek(); n.isNumber() {
				p.next()
				o.autoInc, _ = strconv.ParseUint(n.s, 10, 64)
			}
		case "charset":
			p.eq()
			o.cs = p.next().s
		case "character":
			if p.peek().is("set") {
				p.next()
			}
			p.eq()
			o.cs = p.next().s
		case "collate":
			p.eq()
			o.coll = p.next().s
		case "comment":
			p.eq()
			if p.peek().isQuoted() {
				o.comment = p.str()
			}
		case "with":
			if p.peek().is("system") {
				p.next()
				if p.peek().is("versioning") {
					p.next()
					o.versioned = true
				}
			}
		case "sequence":
			if p.peek().isSym('=') {
				p.next()
				o.sequence = true
			}
		case "partition":
			partition = true
		case "as":
			return ReasonInsertForm
		}
	}
	return ""
}

// fillsTable reports a word, anywhere after CREATE TABLE's list, PARTITION
// clause and parentheses included, that starts a query or rows for the table
// to take: SELECT, TABLE, WITH but MariaDB's WITH SYSTEM VERSIONING, VALUES
// but a partition's VALUES LESS THAN and VALUES IN, IGNORE and REPLACE.
func (p *sp) fillsTable(t tk) bool {
	switch t.lw {
	case "select", "table", "ignore", "replace":
		return true
	case "with":
		return !p.peek().is("system")
	case "values":
		n := p.peek()
		return !n.is("less") && !n.is("in")
	}
	return false
}

// parseColumn reads a column's type and attributes, after its name.
func (p *sp) parseColumn(name string) *colDef {
	cd := &colDef{}
	cd.col = model.Column{Name: name, Nullable: true}
	if !p.parseType(cd) {
		return nil
	}
	for !p.elemEnd() {
		t := p.next()
		if t.isGroupStart() {
			p.skipGroup()
			continue
		}
		if t.kind != tokWord {
			continue
		}
		switch t.lw {
		case "unsigned":
			cd.unsigned = true
		case "zerofill":
			cd.zerofill, cd.unsigned = true, true
		case "not":
			if p.peek().is("null") {
				p.next()
				cd.col.Nullable = false
			}
		case "null":
			cd.col.Nullable = true
		case "default":
			cd.def = p.parseDefault()
		case "auto_increment":
			cd.autoInc = true
		case "unique":
			if p.peek().is("key") {
				p.next()
			}
			cd.uniq = true
		case "primary":
			if p.peek().is("key") {
				p.next()
			}
			cd.pk = true
		case "key":
			cd.pk = true
		case "comment":
			if p.peek().isQuoted() {
				cd.col.Comment = p.str()
			}
		case "collate":
			cd.coll = p.next().s
		case "character":
			if p.peek().is("set") {
				p.next()
			}
			p.eq()
			cd.cs = p.next().s
		case "charset":
			p.eq()
			cd.cs = p.next().s
		case "ascii":
			cd.cs = "latin1"
		case "unicode":
			cd.cs = "ucs2"
		case "binary":
			cd.binary = true
		case "on":
			if p.peek().is("update") {
				p.next()
				cd.onUpdate = p.parseOnUpdate()
			}
		case "generated", "as":
			if t.lw == "generated" && p.peek().is("always") {
				p.next()
				if p.peek().is("as") {
					p.next()
				}
			}
			p.parseGenerated(cd)
		case "invisible":
			cd.invisible = true
			p.st.lx.approve(t.unc, 1) // MySQL writes /*!80023 INVISIBLE */ here
		case "srid":
			// MySQL writes /*!80003 SRID n */ after a spatial column's type.
			if n := p.peek(); n.isNumber() {
				p.next()
				if spatialTypes[cd.dt] && n.unc == t.unc {
					p.st.lx.approve(t.unc, 2)
				}
			}
		case "first":
			cd.first = true
		case "after":
			cd.after, _ = p.name()
		}
	}
	return cd
}

// parseGenerated reads what follows GENERATED ALWAYS AS: an expression and
// VIRTUAL, STORED or PERSISTENT, or ROW START or ROW END.
func (p *sp) parseGenerated(cd *colDef) {
	if p.peek().is("row") {
		p.next()
		p.next()
		cd.gen = "STORED GENERATED"
		return
	}
	if p.peek().isGroupStart() {
		p.next()
		p.skipGroup()
	}
	cd.gen = "VIRTUAL GENERATED"
	if t := p.peek(); t.is("stored") || t.is("persistent") {
		p.next()
		cd.gen = "STORED GENERATED"
	} else if t.is("virtual") {
		p.next()
	}
}

// parseOnUpdate reads the expression after ON UPDATE as a server writes it
// in information_schema.
func (p *sp) parseOnUpdate() string {
	t := p.next()
	var args string
	paren := false
	if p.peek().isGroupStart() {
		paren = true
		p.next()
		var b strings.Builder
		target := p.depth - 1
		for p.depth > target && !p.atEnd() {
			if x := p.next(); x.kind != tokSym {
				b.WriteString(x.s)
			}
		}
		args = b.String()
	}
	switch t.lw {
	case "now", "localtime", "localtimestamp", "current_timestamp":
		return "CURRENT_TIMESTAMP\x00" + args
	}
	if paren {
		return t.s + "(" + args + ")"
	}
	return t.s
}

// parseDefault reads what follows DEFAULT.
func (p *sp) parseDefault() colDefault {
	d := colDefault{set: true}
	t := p.peek()
	switch {
	case t.isQuoted():
		d.kind, d.text = ValString, p.str()
	case t.isNumber():
		p.next()
		d.kind, d.text = ValNumber, t.s
	case t.isSym('-') || t.isSym('+'):
		p.next()
		if n := p.peek(); n.isNumber() {
			p.next()
			d.kind, d.text = ValNumber, n.s
			if t.sym == '-' {
				d.text = "-" + n.s
			}
		} else {
			d.expr = true
		}
	case t.kind == tokHex:
		p.next()
		d.kind, d.text = ValHex, t.s
	case t.kind == tokBit:
		p.next()
		d.kind, d.text = ValBit, t.s
	case t.is("null"):
		p.next()
		d.kind = ValNull
	case t.is("true"):
		p.next()
		d.kind, d.text = ValNumber, "1"
	case t.is("false"):
		p.next()
		d.kind, d.text = ValNumber, "0"
	case t.kind == tokWord && len(t.s) > 1 && t.s[0] == '_':
		p.next()
		if n := p.peek(); n.isQuoted() {
			d.kind, d.text = ValString, p.str()
		} else {
			d.expr = true
		}
	case t.isGroupStart():
		p.next()
		p.skipGroup()
		d.expr = true
	case t.kind == tokWord:
		p.next()
		if p.peek().isGroupStart() {
			p.next()
			p.skipGroup()
		}
		d.expr = true
	default:
		d.expr = true
	}
	return d
}

// parseType reads a column's data type, its arguments and its modifiers.
func (p *sp) parseType(cd *colDef) bool {
	t := p.next()
	if t.kind != tokWord {
		return false
	}
	dt := t.lw
	switch dt {
	case "double":
		if p.peek().is("precision") {
			p.next()
		}
	case "character", "char", "nchar", "national":
		if dt == "national" {
			dt = p.next().lw
			cd.cs = "utf8"
		} else if dt == "nchar" {
			cd.cs = "utf8"
		}
		if dt == "character" || dt == "nchar" {
			dt = "char"
		}
		if dt == "char" {
			if n := p.peek(); n.is("varying") || n.is("varchar") {
				p.next()
				dt = "varchar"
			}
		}
	case "nvarchar":
		cd.cs = "utf8"
	case "long":
		dt = "mediumtext"
		switch n := p.peek(); {
		case n.is("varbinary"):
			p.next()
			dt = "mediumblob"
		case n.is("varchar"):
			p.next()
		}
	case "bool", "boolean":
		dt = "tinyint"
		cd.args = []string{"1"}
	}
	if a, ok := typeAlias[dt]; ok {
		dt = a
	}
	cd.dt = dt
	cd.class = classOf(dt)
	if p.peek().isGroupStart() {
		p.next()
		target := p.depth - 1
		for p.depth > target && !p.atEnd() {
			x := p.next()
			switch {
			case x.kind == tokNum:
				cd.args = append(cd.args, x.s)
			case x.kind == tokString:
				cd.members = append(cd.members, x.s)
			}
		}
	}
	if dt == "char" && p.peek().is("byte") {
		p.next()
		dt = "binary"
		cd.dt, cd.class = dt, classBinary
	}
	switch cd.class {
	case classChar, classBinary:
		cd.length = 1
		if len(cd.args) > 0 {
			cd.length, _ = strconv.ParseInt(cd.args[0], 10, 64)
		} else if dt == "char" || dt == "binary" {
			cd.args = []string{"1"}
		}
	case classText, classBlob:
		if len(cd.args) > 0 {
			n, _ := strconv.ParseInt(cd.args[0], 10, 64)
			base := strings.TrimSuffix(strings.TrimSuffix(dt, "text"), "blob")
			kind := dt[len(base):]
			switch {
			case n <= 255:
				dt = "tiny" + kind
			case n <= 65535:
				dt = kind
			case n <= 16777215:
				dt = "medium" + kind
			default:
				dt = "long" + kind
			}
			cd.dt = dt
			cd.args = nil
		}
	case classOther:
		if dt == "decimal" {
			switch len(cd.args) {
			case 0:
				cd.args = []string{"10", "0"}
			case 1:
				cd.args = append(cd.args, "0")
			}
		}
	}
	return true
}

// addColumn resolves a column's declaration against the table's defaults and
// appends it.
func (ti *tableInfo) addColumn(cd *colDef, f flavour) {
	cd.resolve(ti, f)
	ti.t.Columns = append(ti.t.Columns, &cd.col)
	ti.defaults = append(ti.defaults, cd.def)
}

// resolve fills the column's type, lengths, character set and Extra.
func (cd *colDef) resolve(ti *tableInfo, f flavour) {
	c := &cd.col
	c.DataType = cd.dt
	var b strings.Builder
	b.WriteString(cd.dt)
	if cd.class == classEnum {
		b.WriteByte('(')
		for i, m := range cd.members {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(quoteMember(m))
		}
		b.WriteByte(')')
	} else if len(cd.args) > 0 {
		b.WriteString("(" + strings.Join(cd.args, ",") + ")")
	}
	if cd.unsigned {
		b.WriteString(" unsigned")
	}
	if cd.zerofill {
		b.WriteString(" zerofill")
	}
	c.ColumnType = b.String()

	c.MaxLength, c.OctetLength, c.Charset, c.Collation = 0, 0, "", ""
	switch cd.class {
	case classChar, classEnum:
		if cd.class == classChar {
			c.MaxLength = cd.length
		} else {
			c.MaxLength = memberLength(cd.dt, cd.members)
		}
	case classBinary:
		c.MaxLength, c.OctetLength = cd.length, cd.length
	case classText, classBlob:
		c.MaxLength, c.OctetLength = fixedLength[cd.dt], fixedLength[cd.dt]
	}
	if hasCharset(cd.class) {
		var cc charColl
		switch {
		case cd.cs != "" || cd.coll != "":
			cc = f.complete(cd.cs, cd.coll)
			if cd.binary && cd.coll == "" {
				cc.coll = cc.cs + "_bin"
			}
		case cd.binary:
			cc = charColl{ti.cs, ti.cs + "_bin"}
		default:
			cc = charColl{ti.cs, ti.coll}
		}
		c.Charset, c.Collation = cc.cs, cc.coll
		if cd.class != classText {
			c.OctetLength = c.MaxLength * bytesPerChar(cc.cs)
		}
	}

	var extra []string
	if cd.autoInc {
		extra = append(extra, "auto_increment")
	}
	if cd.def.set && cd.def.expr && !f.mariadb && f.major != 5 {
		extra = append(extra, "DEFAULT_GENERATED")
	}
	if cd.onUpdate != "" {
		extra = append(extra, "on update "+cd.onUpdateText(f))
	}
	if cd.gen != "" {
		extra = append(extra, cd.gen)
	}
	if cd.invisible {
		extra = append(extra, "INVISIBLE")
	}
	c.Extra = strings.Join(extra, " ")
}

// onUpdateText spells the ON UPDATE expression as the server does:
// CURRENT_TIMESTAMP(6) for MySQL, current_timestamp(6) for MariaDB.
func (cd *colDef) onUpdateText(f flavour) string {
	s := cd.onUpdate
	i := strings.IndexByte(s, 0)
	if i < 0 {
		return s
	}
	args := s[i+1:]
	if f.mariadb {
		return "current_timestamp(" + args + ")"
	}
	if args == "" {
		return "CURRENT_TIMESTAMP"
	}
	return "CURRENT_TIMESTAMP(" + args + ")"
}

// addKey appends an index, naming it as the server does when the statement
// doesn't.
func (ti *tableInfo) addKey(kd *keyDef) {
	if len(kd.cols) == 0 {
		return
	}
	ix := model.Index{Unique: kd.kind == "primary" || kd.kind == "unique", Type: "BTREE"}
	switch kd.kind {
	case "fulltext":
		ix.Type = "FULLTEXT"
	case "spatial":
		ix.Type = "SPATIAL"
	default:
		if isMemoryEngine(ti.t.Engine) && kd.using != "btree" {
			ix.Type = "HASH"
		}
	}
	for i, name := range kd.cols {
		sub := kd.subs[i]
		if kd.kind == "spatial" {
			sub = spatialSubPart
		}
		if j := ti.column(name); j >= 0 {
			c := ti.t.Columns[j]
			name = c.Name
			if sub > 0 && (classOf(c.DataType) == classChar || classOf(c.DataType) == classBinary) && int64(sub) >= c.MaxLength {
				sub = 0
			}
		}
		ix.Columns = append(ix.Columns, name)
		ix.SubParts = append(ix.SubParts, sub)
	}
	if kd.kind == "primary" {
		ix.Name = "PRIMARY"
		for i, x := range ti.t.Indexes {
			if x.Name == "PRIMARY" {
				ti.t.Indexes = append(ti.t.Indexes[:i], ti.t.Indexes[i+1:]...)
				break
			}
		}
	} else {
		ix.Name = ti.indexName(kd.name, ix.Columns[0])
	}
	ti.t.Indexes = append(ti.t.Indexes, ix)
}

// spatialSubPart is the SUB_PART both servers give a spatial index's parts.
const spatialSubPart = 32

func isMemoryEngine(e string) bool { return e == "MEMORY" || e == "ndbcluster" }

// indexName gives an unnamed index the name of its first column, with _2,
// _3 and so on when that is taken.
func (ti *tableInfo) indexName(name, first string) string {
	if name != "" {
		return name
	}
	if first == "" {
		first = "functional_index"
	}
	taken := func(n string) bool {
		for _, x := range ti.t.Indexes {
			if strings.EqualFold(x.Name, n) {
				return true
			}
		}
		return false
	}
	n := first
	for i := 2; taken(n); i++ {
		n = first + "_" + strconv.Itoa(i)
	}
	return n
}

// addForeignKey appends a foreign key. An unqualified reference is to the
// current database.
func (ti *tableInfo) addForeignKey(fd *fkDef, db string) {
	fk := model.ForeignKey{Name: fd.name, RefSchema: fd.refDB, RefTable: fd.refTable}
	if fk.RefSchema == "" {
		fk.RefSchema = db
	}
	if fk.Name == "" {
		fk.Name = ti.t.Name + "_ibfk_" + strconv.Itoa(len(ti.t.ForeignKeys)+1)
	}
	for _, n := range fd.cols {
		if j := ti.column(n); j >= 0 {
			n = ti.t.Columns[j].Name
		}
		fk.Columns = append(fk.Columns, n)
	}
	fk.RefColumns = append(fk.RefColumns, fd.refCols...)
	ti.t.ForeignKeys = append(ti.t.ForeignKeys, fk)
}

// dbCharColl is the default character set and collation of a database: the
// one a CREATE or ALTER DATABASE gave, or utf8mb4 with the flavour's default
// collation.
func (r *reader) dbCharColl(db string, f flavour) charColl {
	if cc, ok := r.dbDefs[db]; ok {
		return cc
	}
	return f.fallback()
}

// createIndex reads CREATE [UNIQUE|FULLTEXT|SPATIAL] INDEX name ON t (...).
func (r *reader) createIndex(st *stmt) Reason {
	p := newSP(st)
	st.ifExists()
	name, _ := p.name()
	using := ""
	for !p.atEnd() && !p.peek().is("on") {
		if p.next().is("using") {
			using = p.next().lw
		}
	}
	if !p.peek().is("on") {
		return p.failure(st, ReasonKind)
	}
	p.next()
	db, tbl, ok := p.qname()
	if !ok {
		return p.failure(st, ReasonKind)
	}
	st.setTable(db, tbl)
	kind := "key"
	if st.mod != "" {
		kind = st.mod
	}
	kd := p.parseKey(kind, name)
	if kd.using == "" {
		kd.using = using
	}
	st.skipRest()
	if p.bad || st.err != "" || st.eof {
		return ""
	}
	old := r.tables[tableKey{st.tableDB, tbl}]
	if old == nil || len(kd.cols) == 0 {
		return ReasonAlter
	}
	ti := old.clone()
	ti.addKey(kd)
	ti.settle()
	db = st.tableDB
	st.apply(func() { r.put(db, ti) })
	return ""
}

// alterOp is one action of an ALTER TABLE the reader follows.
type alterOp struct {
	key *keyDef
	fk  *fkDef
	col *colDef
}

func (r *reader) alterTable(st *stmt) Reason {
	p := newSP(st)
	db, tbl, ok := p.qname()
	if !ok {
		return p.failure(st, ReasonKind)
	}
	st.setTable(db, tbl)
	var ops []alterOp
	var autoN uint64
	autoSet := false
	for {
		t := p.next()
		switch {
		case t.is("add"):
			op, ok := p.alterAdd()
			if !ok {
				return p.failure(st, ReasonAlter)
			}
			ops = append(ops, op)
		case t.is("modify"):
			if p.peek().is("column") {
				p.next()
			}
			n, ok := p.name()
			if !ok {
				return p.failure(st, ReasonAlter)
			}
			cd := p.parseColumn(n)
			if cd == nil {
				return p.failure(st, ReasonAlter)
			}
			ops = append(ops, alterOp{col: cd})
		case t.is("auto_increment"):
			p.eq()
			if n := p.peek(); n.isNumber() {
				var err error
				if autoN, err = strconv.ParseUint(n.s, 10, 64); err == nil {
					autoSet = true
				}
			}
		case t.is("disable") || t.is("enable"):
			if !p.peek().is("keys") {
				return p.failure(st, ReasonAlter)
			}
			p.next()
		default:
			return p.failure(st, ReasonAlter)
		}
		p.skipElem()
		if p.peek().isSym(',') {
			p.next()
			continue
		}
		break
	}
	st.skipRest()
	if p.bad || st.err != "" || st.eof {
		return ""
	}
	key := tableKey{st.tableDB, tbl}
	old := r.tables[key]
	if len(ops) > 0 && old == nil {
		return ReasonAlter
	}
	var ti *tableInfo
	if len(ops) > 0 {
		f := r.fl
		ti = old.clone()
		for _, op := range ops {
			switch {
			case op.key != nil:
				ti.addKey(op.key)
			case op.fk != nil:
				ti.addForeignKey(op.fk, st.tableDB)
			case op.col != nil:
				if !ti.modify(op.col, f) {
					return ReasonAlter
				}
			}
		}
		ti.settle()
	}
	db = st.tableDB
	st.apply(func() {
		if autoSet && old != nil {
			old.autoStart = autoN
			if ti != nil {
				ti.autoStart = autoN
			}
			if rs := r.rows[key]; rs != nil && rs.next < autoN {
				rs.next = autoN
			}
		}
		if ti != nil {
			r.put(db, ti)
		}
	})
	return ""
}

// alterAdd reads ADD [CONSTRAINT name] followed by a key.
func (p *sp) alterAdd() (alterOp, bool) {
	cname := ""
	if p.peek().is("constraint") {
		p.next()
		if n := p.peek(); n.isName() && !n.is("primary") && !n.is("unique") && !n.is("foreign") {
			cname = n.s
			p.next()
		}
	}
	t := p.peek()
	if kd := p.readKey(t, cname); kd != nil {
		return alterOp{key: kd}, true
	}
	if t.is("foreign") {
		p.next()
		if fd := p.parseFK(cname); fd != nil {
			return alterOp{fk: fd}, true
		}
	}
	return alterOp{}, false
}

// modify replaces a column by its new definition, in place or at the place
// FIRST or AFTER names. It reports false when there is no such column.
func (ti *tableInfo) modify(cd *colDef, f flavour) bool {
	i := ti.column(cd.col.Name)
	if i < 0 {
		return false
	}
	cd.col.Name = ti.t.Columns[i].Name
	cd.resolve(ti, f)
	ti.t.Columns[i] = &cd.col
	ti.defaults[i] = cd.def
	to := i
	switch {
	case cd.first:
		to = 0
	case cd.after != "":
		j := ti.column(cd.after)
		if j < 0 {
			return false
		}
		if j < i {
			to = j + 1
		} else {
			to = j
		}
	}
	if to != i {
		c, d := ti.t.Columns[i], ti.defaults[i]
		ti.t.Columns = append(ti.t.Columns[:i], ti.t.Columns[i+1:]...)
		ti.defaults = append(ti.defaults[:i], ti.defaults[i+1:]...)
		ti.t.Columns = append(ti.t.Columns[:to], append([]*model.Column{c}, ti.t.Columns[to:]...)...)
		ti.defaults = append(ti.defaults[:to], append([]colDefault{d}, ti.defaults[to:]...)...)
	}
	return true
}
