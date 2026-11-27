package sqldump

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// maxRowColumns is the most columns a table has, and so the most values a row
// of a table with no structure may hold.
const maxRowColumns = 4096

// rowState is what the row reader keeps for a table with rows.
type rowState struct {
	// ord is how many rows of the table were handed on.
	ord int64
	// next is the key the server would give the next row that leaves its
	// auto-increment key to it; spent is set once the counter has passed
	// the largest key there is.
	next  uint64
	spent bool
	// unknown is set when the table's keys can't be counted; it stays set.
	unknown bool
	warned  bool
}

// rawVal is a value of a row as it was read, with its bytes in the arena.
type rawVal struct {
	kind   ValueKind
	off, n int
	cut    bool
	src    csKind
}

// loc says where the bytes of a decoded value are: 0 none, 1 the arena, 2 out.
type loc struct {
	buf    uint8
	off, n int
}

// rowBufs holds the buffers the row reader reuses.
type rowBufs struct {
	raw        []rawVal
	arena, out []byte
	at         []int
	locs       []loc
	vals       []Value
	row        Row
}

// rowCtx is what one INSERT or REPLACE statement knows about its table.
type rowCtx struct {
	st        *stmt
	db, table string
	ti        *tableInfo
	rs        *rowState
	names     []string // the column list, as written
	listed    bool
	colMap    []int // the column of each listed name
	ai        int   // the auto-increment column, or -1
	pk        []int // the primary key's columns but the auto-increment one
	zeroGen   bool  // a 0 in the auto-increment column asks for the next key
}

// readRows is called for INSERT and REPLACE, with the lexer just past the
// modifiers and INTO, at the table's name. It reads
//
//	[db.]t [PARTITION (...)] [(columns)] VALUES|VALUE (row), (row) ... [AS alias [(columns)]]
//
// hands each row to the visitor, and consumes the statement to its end. It
// returns "" when the rows were read, or the reason they were not.
func (r *reader) readRows(st *stmt) Reason {
	why := r.readRowsBody(st)
	if why != "" && st.err == ReasonIdentLength {
		st.skipRest()
		return "" // finish gives the statement its reason
	}
	return why
}

func (r *reader) readRowsBody(st *stmt) Reason {
	r.tableOf(st)
	if st.table == "" {
		return ReasonInsertForm
	}
	if ti := r.table(st.tableDB, st.table); ti != nil && ti.t.Type == "VIEW" {
		// The rows go into a table behind the view, which the entry can't
		// name.
		st.table, st.tableDB = "", ""
		return ReasonInsertForm
	}
	rc := &rowCtx{st: st, db: st.tableDB, table: st.table, ai: -1}
	if st.peek().is("partition") {
		st.next()
		if !st.peek().isSym('(') {
			return ReasonInsertForm
		}
		st.skipGroup()
	}
	if st.peek().isSym('(') {
		st.next()
		rc.listed = true
		if why := r.columnList(st, rc); why != "" {
			return why
		}
	}
	if t := st.next(); !t.is("values") && !t.is("value") {
		return ReasonInsertForm
	}
	rc.zeroGen = !r.mode.noAutoOnZero()
	if ti := r.table(rc.db, rc.table); ti != nil {
		if why := r.bind(rc, ti); why != "" {
			return why
		}
	}
	st.lx.hexWide = true
	defer func() { st.lx.hexWide = false }()
	for {
		if !st.next().isSym('(') {
			return ReasonInsertForm
		}
		if why := r.rawRow(st, rc.want()); why != "" {
			return why
		}
		if why := r.emit(rc); why != "" {
			return why
		}
		if !st.peek().isSym(',') {
			break
		}
		st.next()
	}
	st.apply(func() { r.markKnown(rc.db, rc.table) })
	st.skipRest()
	if st.seen&seenDuplicate != 0 {
		return ReasonInsertForm
	}
	return ""
}

// skipGroup consumes a parenthesis, which is the next token, and everything
// through its closing one.
func (st *stmt) skipGroup() {
	st.next()
	target := st.depth - 1
	st.lx.discard = true
	for st.depth > target && (!st.ended || st.peeked) {
		st.next()
	}
	st.lx.discard = false
}

// columnList reads the names of an INSERT's column list, past its opening
// parenthesis, through its closing one.
func (r *reader) columnList(st *stmt, rc *rowCtx) Reason {
	if p := st.peek(); p.is("select") || p.is("with") || p.is("table") || p.is("values") || p.isSym('(') {
		return ReasonInsertForm // INSERT INTO t (SELECT ...)
	}
	for !st.peek().isSym(')') {
		n, ok := st.name()
		if !ok {
			return ReasonInsertForm
		}
		if st.peek().isSym('.') { // t.column
			st.next()
			if n, ok = st.name(); !ok {
				return ReasonInsertForm
			}
		}
		rc.names = append(rc.names, n)
		if len(rc.names) > maxRowColumns {
			return ReasonColumns
		}
		if st.peek().isSym(',') {
			st.next()
		} else if !st.peek().isSym(')') {
			return ReasonInsertForm
		}
	}
	st.next()
	return ""
}

// bind matches the statement's column list with a structure and finds the
// columns that carry keys.
func (r *reader) bind(rc *rowCtx, ti *tableInfo) Reason {
	rc.ti = ti
	rc.rs = r.rows[tableKey{rc.db, rc.table}]
	rc.ai = -1
	for i, c := range ti.t.Columns {
		if c.AutoIncrement() {
			rc.ai = i
			break
		}
	}
	rc.pk = rc.pk[:0]
	for _, n := range ti.t.PrimaryKey {
		if j := ti.column(n); j >= 0 && j != rc.ai {
			rc.pk = append(rc.pk, j)
		}
	}
	if rc.listed {
		rc.colMap = rc.colMap[:0]
		seen := make([]bool, len(ti.t.Columns))
		for _, n := range rc.names {
			j := ti.column(n)
			if j < 0 || seen[j] {
				return ReasonColumns
			}
			seen[j] = true
			rc.colMap = append(rc.colMap, j)
		}
	}
	return ""
}

// want is how many values a row may hold, at most.
func (rc *rowCtx) want() int {
	switch {
	case rc.listed:
		return len(rc.names)
	case rc.ti != nil:
		return len(rc.ti.t.Columns)
	}
	return maxRowColumns
}

// count says whether a row of n values fits the statement's columns. An empty
// row is every column's default.
func (rc *rowCtx) count(n int) bool {
	switch {
	case rc.listed:
		return n == len(rc.names)
	case rc.ti != nil:
		return n == len(rc.ti.t.Columns) || n == 0
	}
	return n > 0
}

// rawRow reads the values of a row, past its opening parenthesis, through its
// closing one. Their bytes are copied into the arena, since each literal
// overwrites the one before.
func (r *reader) rawRow(st *stmt, want int) Reason {
	b := &r.rd
	b.raw, b.arena = b.raw[:0], b.arena[:0]
	if st.peek().isSym(')') {
		st.next()
		return ""
	}
	for {
		if len(b.raw) >= want {
			return ReasonColumns
		}
		v, why := st.readValue()
		if why != "" {
			return why
		}
		off := len(b.arena)
		b.arena = append(b.arena, v.Bytes...)
		b.raw = append(b.raw, rawVal{kind: v.Kind, off: off, n: len(v.Bytes), cut: v.Cut, src: v.src})
		if st.next().isSym(')') {
			return ""
		}
	}
}

// emit aligns the row just read to the table's columns, counts its key, and
// hands it to the visitor.
func (r *reader) emit(rc *rowCtx) Reason {
	b := &r.rd
	if rc.st.lx.vOpen >= 0 {
		// An uncertain version comment makes an INSERT unread: no row of it is
		// handed on from there, as a server that skips it may load others.
		return ReasonVersion
	}
	if !rc.count(len(b.raw)) {
		return ReasonColumns
	}
	if rc.ti == nil {
		if why := r.implicit(rc, len(b.raw)); why != "" {
			return why
		}
	}
	ti := rc.ti
	cols := ti.t.Columns
	n := len(cols)
	b.at = resize(b.at, n)
	for i := range b.at {
		b.at[i] = -1
	}
	for k := range b.raw {
		j := k
		if rc.listed {
			j = rc.colMap[k]
		}
		b.at[j] = k
	}
	b.vals, b.locs = resize(b.vals, n), resize(b.locs, n)
	b.out = b.out[:0]

	var noLiteral int64
	aiDefault := false
	for i, c := range cols {
		var rv rawVal
		explicitDefault := false
		have := false
		if k := b.at[i]; k >= 0 {
			rv = b.raw[k]
			have = true
			if rv.kind == ValDefault {
				have, explicitDefault = false, true
			}
		}
		if !have {
			d := ti.defaultOf(i)
			literal := d.set && !d.expr
			if !literal || d.kind == ValNull {
				b.vals[i], b.locs[i] = Value{Kind: ValNull}, loc{}
				switch {
				case i == rc.ai:
					aiDefault = aiDefault || explicitDefault && !literal
				case explicitDefault && !literal, d.expr, generated(c):
					// The server fills it, from an expression the reader
					// doesn't judge when there is one.
					noLiteral++
				}
				continue
			}
			off := len(b.arena)
			b.arena = append(b.arena, d.text...)
			rv = rawVal{kind: d.kind, off: off, n: len(d.text)}
		}
		v, l, why := r.decode(c, rv)
		if why != "" {
			return why
		}
		b.vals[i], b.locs[i] = v, l
	}

	key := tableKey{rc.db, rc.table}
	rs := rc.rs
	if rs == nil {
		rs = &rowState{next: max(ti.autoStart, 1)}
		r.rows[key] = rs
		rc.rs = rs
		r.markRows(rc.db, rc.table)
	}
	rs.ord++
	counted, counter := r.keys(rc, rs)
	if counted {
		off := len(b.out)
		b.out = strconv.AppendUint(b.out, counter, 10)
		b.vals[rc.ai], b.locs[rc.ai] = Value{Kind: ValNumber}, loc{buf: 2, off: off, n: len(b.out) - off}
	} else if aiDefault {
		noLiteral++
	}

	for i := range b.vals {
		switch l := b.locs[i]; l.buf {
		case 1:
			b.vals[i].Bytes = b.arena[l.off : l.off+l.n]
		case 2:
			b.vals[i].Bytes = b.out[l.off : l.off+l.n]
		}
	}
	r.stats.Rows++
	r.stats.DefaultsNoLiteral += noLiteral
	b.row = Row{
		DB:          rc.db,
		Table:       rc.table,
		Kind:        rc.st.kind,
		Line:        int64(rc.st.line),
		Ordinal:     rs.ord,
		Structure:   ti.t,
		Values:      b.vals,
		KeyCounted:  counted,
		KeysUnknown: rs.unknown,
	}
	r.v.Row(&b.row)
	return ""
}

func resize[T any](s []T, n int) []T {
	if cap(s) < n {
		return make([]T, n)
	}
	return s[:n]
}

// keys decides, for the row in the buffers, whether its auto-increment key
// is one the reader counts, and which, and keeps the table's counter and its
// verdict on its keys.
func (r *reader) keys(rc *rowCtx, rs *rowState) (counted bool, key uint64) {
	b := &r.rd
	if rc.ai < 0 && len(rc.pk) == 0 {
		return false, 0
	}
	if rc.ai >= 0 && r.aiShift {
		r.unknownKeys(rc, rs)
	}
	leaves := false
	if rc.ai >= 0 {
		k := b.at[rc.ai]
		leaves = k < 0
		if !leaves {
			rv := b.raw[k]
			switch rv.kind {
			case ValNull, ValDefault:
				leaves = true
			default:
				n, neg, ok := r.keyNumber(rv)
				switch {
				case !ok:
					r.unknownKeys(rc, rs)
				case !neg && n == 0 && rc.zeroGen:
					leaves = true
				case !neg && !rs.spent && n >= rs.next:
					rs.next = n + 1
					rs.spent = n == math.MaxUint64
				}
			}
		}
		if leaves && rc.st.kind != KindInsert {
			r.unknownKeys(rc, rs)
		}
	}
	for _, j := range rc.pk {
		k := b.at[j]
		if k >= 0 && b.raw[k].kind != ValNull && b.raw[k].kind != ValDefault {
			continue
		}
		if d := rc.ti.defaultOf(j); !d.set || d.expr || d.kind == ValNull {
			r.unknownKeys(rc, rs)
		}
	}
	if !leaves || rs.unknown {
		return false, 0
	}
	if rs.spent {
		r.unknownKeys(rc, rs)
		return false, 0
	}
	key = rs.next
	rs.next++
	rs.spent = key == math.MaxUint64
	return true, key
}

// unknownKeys makes the table's keys unknown, with one warning.
func (r *reader) unknownKeys(rc *rowCtx, rs *rowState) {
	rs.unknown = true
	if !rs.warned {
		rs.warned = true
		r.v.Warning(Warning{Text: fmt.Sprintf(warnKeysFormat, rc.table)})
	}
}

// keyNumber reads an explicit key as an integer: a number, a string of digits
// or bytes of hex. neg is set for a negative one, which moves no counter.
func (r *reader) keyNumber(rv rawVal) (n uint64, neg, ok bool) {
	data := r.rd.arena[rv.off : rv.off+rv.n]
	switch rv.kind {
	case ValHex, ValBinary:
		if len(data) > 8 {
			return 0, false, false
		}
		for _, c := range data {
			n = n<<8 | uint64(c)
		}
		return n, false, true
	case ValNumber, ValString:
		if len(data) > 0 && (data[0] == '-' || data[0] == '+') {
			neg = data[0] == '-'
			data = data[1:]
		}
		if len(data) == 0 {
			return 0, false, false
		}
		for _, c := range data {
			if c < '0' || c > '9' {
				return 0, false, false
			}
			d := uint64(c - '0')
			if n > (math.MaxUint64-d)/10 {
				return 0, false, false
			}
			n = n*10 + d
		}
		return n, neg, true
	}
	return 0, false, false
}

// implicit gives a table the file never created a structure, from the
// INSERT's column list or else column_1 onwards, every column longtext, and
// hands it on with a warning.
func (r *reader) implicit(rc *rowCtx, n int) Reason {
	names := rc.names
	if !rc.listed {
		names = make([]string, n)
		for i := range names {
			names[i] = "column_" + strconv.Itoa(i+1)
		}
	}
	seen := make(map[string]bool, len(names))
	for _, nm := range names {
		l := strings.ToLower(nm)
		if seen[l] {
			return ReasonColumns
		}
		seen[l] = true
	}
	coll := r.fl.defaultUTF8MB4()
	t := &model.Table{Name: rc.table, Type: "BASE TABLE", Engine: "InnoDB"}
	for _, nm := range names {
		t.Columns = append(t.Columns, &model.Column{
			Name: nm, DataType: "longtext", ColumnType: "longtext", Nullable: true,
			MaxLength: fixedLength["longtext"], OctetLength: fixedLength["longtext"],
			Charset: "utf8mb4", Collation: coll,
		})
	}
	ti := &tableInfo{t: t, defaults: make([]colDefault, len(names)), cs: "utf8mb4", coll: coll, implicit: true}
	ti.settle()
	r.v.Warning(Warning{Text: fmt.Sprintf(warnNoTableFormat, rc.table)})
	r.put(rc.db, ti)
	return r.bind(rc, ti)
}

// decode turns a value as read into the value for the column it goes into.
func (r *reader) decode(c *model.Column, rv rawVal) (Value, loc, Reason) {
	b := &r.rd
	if rv.kind == ValBit && c.DataType != "bit" {
		rv = r.bitBytes(rv)
	}
	v := Value{Kind: rv.kind, Cut: rv.cut}
	l := loc{buf: 1, off: rv.off, n: rv.n}
	enum := classOf(c.DataType) == classEnum
	switch rv.kind {
	case ValNull:
		return v, loc{}, ""
	case ValNumber:
		if enum {
			ev, el, why, _ := r.enumValue(c, b.arena[rv.off:rv.off+rv.n], false)
			return ev, el, why
		}
		return v, l, ""
	case ValBit, ValDefault:
		return v, l, ""
	}
	data := b.arena[rv.off : rv.off+rv.n]
	if enum {
		// A string, hex or bit literal that names no member and spells a
		// whole number is taken as one, as the servers take it.
		if ev, el, why, ok := r.enumValue(c, data, true); ok {
			return ev, el, why
		}
	}
	switch c.DataType {
	case "uuid", "inet6", "inet4":
		if rv.kind == ValString {
			return v, l, ""
		}
		off := len(b.out)
		if out, ok := appendTyped(b.out, c.DataType, data); ok {
			b.out = out
			return Value{Kind: ValString}, loc{buf: 2, off: off, n: len(out) - off}, ""
		}
		return r.capHex(v, l)
	}
	switch cls := classOf(c.DataType); {
	case cls == classChar || cls == classText || cls == classEnum || c.DataType == "json":
		return r.textValue(c, rv, data)
	case cls == classBinary || cls == classBlob:
		return r.binaryValue(rv, data)
	}
	return r.capHex(v, l)
}

// enumValue stores what the servers store for a number put into an ENUM or
// SET column: the member an ENUM index picks, the empty string for 0, or the
// members a SET mask's bits pick, joined by commas in definition order. A
// number it can't map the way the servers do, out of range or not a whole
// number, is ReasonExpression. A quoted text is taken as a number only when
// it names no member and is all digits, fewer than 6 for an ENUM and 22 for
// a SET; ok is false for any other, which reads as written.
func (r *reader) enumValue(c *model.Column, text []byte, quoted bool) (Value, loc, Reason, bool) {
	set := c.DataType == "set"
	digits := allDigits(text)
	members := enumMembers(c.ColumnType)
	if quoted {
		if !digits || len(text) >= 6 && !set || len(text) >= 22 {
			return Value{}, loc{}, "", false
		}
		for _, m := range members {
			if strings.EqualFold(m, string(text)) {
				return Value{}, loc{}, "", false
			}
		}
	}
	n, err := strconv.ParseUint(string(text), 10, 64)
	if !digits || err != nil {
		return Value{}, loc{}, ReasonExpression, true
	}
	b := &r.rd
	off := len(b.out)
	switch {
	case !set && n <= uint64(len(members)):
		if n > 0 {
			b.out = append(b.out, members[n-1]...)
		}
	case set && n>>uint(len(members)) == 0:
		sep := false
		for i, m := range members {
			if n&(1<<uint(i)) != 0 {
				if sep {
					b.out = append(b.out, ',')
				}
				b.out, sep = append(b.out, m...), true
			}
		}
	default:
		return Value{}, loc{}, ReasonExpression, true
	}
	return Value{Kind: ValString}, loc{buf: 2, off: off, n: len(b.out) - off}, "", true
}

// enumMembers reads an ENUM or SET column's members back from its type, as
// quoteMember wrote them.
func enumMembers(columnType string) []string {
	i := strings.IndexByte(columnType, '(')
	if i < 0 {
		return nil
	}
	var out []string
	s := columnType[i+1:]
	for len(s) > 0 && s[0] == '\'' {
		var m strings.Builder
		j := 1
		for ; j < len(s); j++ {
			if s[j] == '\'' {
				if j+1 < len(s) && s[j+1] == '\'' {
					m.WriteByte('\'')
					j++
					continue
				}
				break
			}
			m.WriteByte(s[j])
		}
		if j >= len(s) {
			break
		}
		out = append(out, m.String())
		s = strings.TrimPrefix(s[j+1:], ",")
	}
	return out
}

// generated reports a generated column, which the server fills from an
// expression.
func generated(c *model.Column) bool {
	return strings.Contains(c.Extra, "VIRTUAL GENERATED") || strings.Contains(c.Extra, "STORED GENERATED")
}

// bitBytes turns the digits of a bit-value literal into the bytes the server
// stores for it outside a BIT column, read on as a hex literal's: a binary
// string of its bits, left-padded with zeros to whole bytes. A literal the
// lexer cut keeps its digits from the left, a whole number of bytes.
func (r *reader) bitBytes(rv rawVal) rawVal {
	b := &r.rd
	digits := b.arena[rv.off : rv.off+rv.n]
	off := len(b.arena)
	n := 0
	if !rv.cut {
		n = (8 - len(digits)%8) % 8
	}
	var x byte
	for _, d := range digits {
		x = x<<1 | (d - '0')
		if n++; n == 8 {
			b.arena = append(b.arena, x)
			x, n = 0, 0
		}
	}
	return rawVal{kind: ValHex, off: off, n: len(b.arena) - off, cut: rv.cut}
}

// capHex cuts a hex literal that goes into a column that isn't text to the
// cap in bytes. The lexer reads hex at four times the cap, for text columns.
func (r *reader) capHex(v Value, l loc) (Value, loc, Reason) {
	if v.Kind == ValHex && l.n > r.lx.maxChars {
		l.n, v.Cut = r.lx.maxChars, true
	}
	return v, l, ""
}

// textValue decodes a value into a text column. A string was decoded when it
// was read; raw bytes are in the column's character set.
func (r *reader) textValue(c *model.Column, rv rawVal, data []byte) (Value, loc, Reason) {
	l := loc{buf: 1, off: rv.off, n: rv.n}
	if rv.kind == ValString {
		return Value{Kind: ValString, Cut: rv.cut}, l, ""
	}
	cs := csKeep
	if c.Charset != "" {
		info, _, ok := lookupCharset(c.Charset)
		if !ok || !info.decoded {
			return Value{}, loc{}, ReasonCharset
		}
		cs = info.kind
	}
	limit := r.lx.maxChars
	cut := rv.cut
	switch cs {
	case csBinary:
		if len(data) > limit {
			l.n, cut = limit, true
		}
		return Value{Kind: ValBinary, Cut: cut}, l, ""
	case csLatin1:
		if len(data) > limit {
			data, cut = data[:limit], true
		}
		b := &r.rd
		off := len(b.out)
		b.out = appendLatin1(b.out, data)
		return Value{Kind: ValString, Cut: cut}, loc{buf: 2, off: off, n: len(b.out) - off}, ""
	}
	if keep, was := capChars(data, limit); was {
		l.n, cut = keep, true
	}
	return Value{Kind: ValString, Cut: cut}, l, ""
}

// binaryValue keeps the raw bytes of a value that goes into a binary column.
// A string read under latin1 was turned into UTF-8; the column holds the
// bytes the client sent.
func (r *reader) binaryValue(rv rawVal, data []byte) (Value, loc, Reason) {
	b := &r.rd
	l := loc{buf: 1, off: rv.off, n: rv.n}
	cut := rv.cut
	if rv.kind == ValString && rv.src == csLatin1 {
		off := len(b.out)
		for len(data) > 0 {
			ch, size := utf8.DecodeRune(data)
			data = data[size:]
			b.out = append(b.out, latin1Byte(ch))
		}
		l = loc{buf: 2, off: off, n: len(b.out) - off}
	}
	if limit := r.lx.maxChars; l.n > limit {
		l.n, cut = limit, true
	}
	return Value{Kind: ValBinary, Cut: cut}, l, ""
}

// latin1Byte is the byte latin1 maps to a code point; latin1Rune's inverse.
func latin1Byte(ch rune) byte {
	if ch < 0x80 || (ch >= 0xA0 && ch <= 0xFF) {
		return byte(ch)
	}
	for i, h := range latin1High {
		if h == ch {
			return byte(0x80 + i)
		}
	}
	return '?'
}

// capChars returns how many bytes of b hold at most limit characters, and
// whether there were more.
func capChars(b []byte, limit int) (int, bool) {
	chars := 0
	for i, c := range b {
		if c&0xC0 != 0x80 {
			if chars >= limit {
				return i, true
			}
			chars++
		}
	}
	return len(b), false
}

// appendIPv6 writes 16 bytes as the server does: lower case, with the first
// longest run of zero groups, even one group long, written as ::.
func appendIPv6(out, b []byte) []byte {
	var g [8]uint16
	for i := range g {
		g[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	start, length := -1, 0
	for i := 0; i < 8; {
		if g[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && g[j] == 0 {
			j++
		}
		if j-i > length {
			start, length = i, j-i
		}
		i = j
	}
	for i := 0; i < 8; i++ {
		if i == start {
			out = append(out, ':', ':')
			i += length - 1
			continue
		}
		if i > 0 && i != start+length {
			out = append(out, ':')
		}
		out = strconv.AppendUint(out, uint64(g[i]), 16)
	}
	return out
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// appendTyped writes the text form of the raw bytes of a MariaDB uuid, inet6
// or inet4 value, as the server returns it.
func appendTyped(out []byte, dataType string, b []byte) ([]byte, bool) {
	const hexDigits = "0123456789abcdef"
	switch {
	case dataType == "uuid" && len(b) == 16:
		for i, c := range b {
			if i == 4 || i == 6 || i == 8 || i == 10 {
				out = append(out, '-')
			}
			out = append(out, hexDigits[c>>4], hexDigits[c&15])
		}
		return out, true
	case dataType == "inet6" && len(b) == 16:
		a := netip.AddrFrom16([16]byte(b))
		switch {
		case a.Is4In6():
			return a.AppendTo(out), true
		case isZero(b[:12]) && b[12]|b[13] != 0:
			// the server writes an IPv4-compatible address, ::a.b.c.d, in
			// dotted form once it's above ::ffff
			out = append(out, "::"...)
			return netip.AddrFrom4([4]byte(b[12:])).AppendTo(out), true
		}
		return appendIPv6(out, b), true
	case dataType == "inet4" && len(b) == 4:
		return netip.AddrFrom4([4]byte(b)).AppendTo(out), true
	}
	return out, false
}
