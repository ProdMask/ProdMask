package scan

import (
	"container/heap"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
	"github.com/ProdMask/ProdMask/pkg/sqldump"
)

// ikey is an integer key as a 128-bit signed number (hi * 2^64 + lo), so
// every value of a signed or unsigned 64-bit column compares exactly.
type ikey struct {
	hi int64
	lo uint64
}

func ikeyInt(v int64) ikey   { return ikey{hi: v >> 63, lo: uint64(v)} }
func ikeyUint(v uint64) ikey { return ikey{lo: v} }

func (a ikey) cmp(b ikey) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	}
	return 0
}

func (a ikey) big() *big.Int {
	b := big.NewInt(a.hi)
	b.Lsh(b, 64)
	return b.Add(b, new(big.Int).SetUint64(a.lo))
}

func ikeyBig(b *big.Int) ikey {
	lo := new(big.Int).And(b, new(big.Int).SetUint64(^uint64(0)))
	return ikey{hi: new(big.Int).Rsh(b, 64).Int64(), lo: lo.Uint64()}
}

// parseKey reads a value as an integer key: digits, possibly signed, or up to
// eight bytes of hex, which the server reads as a number too.
func parseKey(v *sqldump.Value) (ikey, bool) {
	switch v.Kind {
	case sqldump.ValNumber, sqldump.ValString:
		return parseDecimal(v.Bytes)
	case sqldump.ValHex:
		if u, ok := hexUint(v.Bytes); ok {
			return ikeyUint(u), true
		}
	}
	return ikey{}, false
}

func hexUint(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var u uint64
	for _, c := range b {
		u = u<<8 | uint64(c)
	}
	return u, true
}

func parseDecimal(b []byte) (ikey, bool) {
	b = trimSpaces(b)
	neg := false
	if len(b) > 0 && (b[0] == '-' || b[0] == '+') {
		neg = b[0] == '-'
		b = b[1:]
	}
	if len(b) == 0 {
		return ikey{}, false
	}
	var mag uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return ikey{}, false
		}
		d := uint64(c - '0')
		if mag > (^uint64(0)-d)/10 {
			return ikey{}, false
		}
		mag = mag*10 + d
	}
	if !neg {
		return ikeyUint(mag), true
	}
	if mag > 1<<63 {
		return ikey{}, false
	}
	return ikeyInt(-int64(mag)), true
}

func trimSpaces(b []byte) []byte {
	for len(b) > 0 && b[0] == ' ' {
		b = b[1:]
	}
	for len(b) > 0 && b[len(b)-1] == ' ' {
		b = b[:len(b)-1]
	}
	return b
}

// intRange is the smallest and largest value of one integer column, and
// whether the values came in ascending order.
type intRange struct {
	any, bad bool // bad: a value that isn't an integer
	min, max ikey
	n        int64 // values that aren't NULL
	last     ikey
	unsorted bool // a value came after a greater one
}

func (r *intRange) add(v *sqldump.Value) {
	if v.Kind == sqldump.ValNull {
		return
	}
	k, ok := parseKey(v)
	if !ok {
		r.bad = true
		return
	}
	if r.any && k.cmp(r.last) < 0 {
		r.unsorted = true
	}
	r.last = k
	r.n++
	if !r.any || k.cmp(r.min) < 0 {
		r.min = k
	}
	if !r.any || k.cmp(r.max) > 0 {
		r.max = k
	}
	r.any = true
}

// cutText returns the first n characters of b.
func cutText(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	i := 0
	for c := 0; c < n && i < len(b); c++ {
		_, w := utf8.DecodeRune(b[i:])
		i += w
	}
	return b[:i]
}

// cellText is the text the server would return for a value of a column: text
// cut to maxLen characters, a short binary column's bytes as upper-case hex,
// and a number given as hex in decimal. ok is false for NULL.
func cellText(c *model.Column, v *sqldump.Value, maxLen int, hexCol bool) (string, bool) {
	if v.Kind == sqldump.ValNull || v.Kind == sqldump.ValDefault {
		return "", false
	}
	if hexCol {
		return strings.ToUpper(hex.EncodeToString(v.Bytes)), true
	}
	b := v.Bytes
	if v.Kind == sqldump.ValHex && sample.IsInteger(c) {
		if u, ok := hexUint(b); ok {
			return strconv.FormatUint(u, 10), true
		}
	}
	if maxLen > 0 && sample.IsText(c) {
		b = cutText(b, maxLen)
	}
	return string(b), true
}

// Held bytes are the text of the values plus an allowance for what a value
// and a row cost beyond their text (the string and slice headers, the
// allocator's rounding, a heap's slot), so the count tracks the heap and not
// only the data. TestDumpHeldBytesTrackHeap checks it against the heap.
const (
	cellOverhead = 32  // a value
	rowOverhead  = 160 // a row
)

// textSize is the bytes n bytes of text are counted as: the allocator rounds
// a string up to its size class, by up to an eighth.
func textSize(n int) int64 { return int64(n + n>>3) }

// rowSize is the bytes a row of values is counted as holding.
func rowSize(vals []sql.NullString) int64 {
	n := int64(rowOverhead + cellOverhead*len(vals))
	for i := range vals {
		n += textSize(len(vals[i].String))
	}
	return n
}

// winRow is a row a window holds.
type winRow struct {
	key  ikey
	ord  int64
	vals []sql.NullString
	size int64
}

// rowHeap keeps the n smallest rows by (key, ordinal), or the n largest when
// desc is set. Its root is the worst row kept. held, when set, is told the
// bytes the heap takes and gives back.
type rowHeap struct {
	rows []winRow
	cap  int
	desc bool
	held *int64
}

func (h *rowHeap) hold(n int64) {
	if h.held != nil {
		*h.held += n
	}
}

func (h *rowHeap) Len() int { return len(h.rows) }
func (h *rowHeap) Less(i, j int) bool {
	return h.worse(h.rows[i].key, h.rows[i].ord, h.rows[j].key, h.rows[j].ord)
}
func (h *rowHeap) Swap(i, j int) { h.rows[i], h.rows[j] = h.rows[j], h.rows[i] }
func (h *rowHeap) Push(x any)    { h.rows = append(h.rows, x.(winRow)) }
func (h *rowHeap) Pop() any {
	n := len(h.rows) - 1
	x := h.rows[n]
	h.rows = h.rows[:n]
	return x
}

// worse reports whether (k1, o1) is a worse row to keep than (k2, o2).
func (h *rowHeap) worse(k1 ikey, o1 int64, k2 ikey, o2 int64) bool {
	c := k1.cmp(k2)
	if c == 0 {
		switch {
		case o1 < o2:
			c = -1
		case o1 > o2:
			c = 1
		}
	}
	if h.desc {
		return c < 0
	}
	return c > 0
}

// offer keeps the row when it is among the best n so far. build makes the
// row's values, and runs only for a row that is kept.
func (h *rowHeap) offer(key ikey, ord int64, build func() []sql.NullString) {
	if h.cap <= 0 {
		return
	}
	if len(h.rows) < h.cap {
		vals := build()
		r := winRow{key, ord, vals, rowSize(vals)}
		h.hold(r.size)
		heap.Push(h, r)
		return
	}
	if r := &h.rows[0]; h.worse(r.key, r.ord, key, ord) {
		vals := build()
		nr := winRow{key, ord, vals, rowSize(vals)}
		h.hold(nr.size - r.size)
		h.rows[0] = nr
		heap.Fix(h, 0)
	}
}

// evenly picks keep of n positions, spread over 0..n-1 with both ends in.
func evenly(n, keep int) []bool {
	pick := make([]bool, n)
	if keep <= 1 {
		pick[0] = true
		return pick
	}
	for i := range keep {
		pick[i*(n-1)/(keep-1)] = true
	}
	return pick
}

// thin drops about half of the rows, evenly over their order and never below
// floor rows, and lowers the heap's cap to what is left (or to the floor, if
// that is more), so it doesn't fill again. It reports whether it dropped any.
func (h *rowHeap) thin(floor int) bool {
	n := len(h.rows)
	keep := max(n/2, floor)
	dropped := keep < n
	if dropped {
		pick := evenly(n, keep)
		rows := h.sorted()
		h.rows = h.rows[:0]
		var freed int64
		for i, r := range rows {
			if pick[i] {
				h.rows = append(h.rows, r)
			} else {
				freed += r.size
			}
		}
		h.rows = slices.Clip(h.rows)
		heap.Init(h)
		h.hold(-freed)
	}
	h.cap = min(h.cap, max(len(h.rows), floor))
	return dropped
}

// sorted returns the kept rows, best first: ascending by key, or descending
// for a heap that keeps the largest.
func (h *rowHeap) sorted() []winRow {
	out := slices.Clone(h.rows)
	sort.Slice(out, func(i, j int) bool { return h.worse(out[j].key, out[j].ord, out[i].key, out[i].ord) })
	return out
}

// Sample methods, as the live sampler names them.
const (
	methodNone   = "none"
	methodEmpty  = "empty"
	methodFirst  = "first rows"
	methodAll    = "all rows by key"
	methodWindow = "oldest, middle and newest rows by key"
)

// window holds the rows sampler.Table would read from one table at one limit.
type window struct {
	limit  int
	method string
	first  []winRow // first rows, in file order
	small  *rowHeap // the k smallest keys, or the limit smallest
	mid    *rowHeap // the limit-2k smallest keys at or above midKey
	large  *rowHeap // the k largest keys
	midKey ikey
	// largeFrom is the ordinal after which a row can be among the largest keys.
	// When the keys came in ascending order, those are the last k rows, so a row
	// before them is never decoded; otherwise it is -1.
	largeFrom int64
	held      *int64
}

// newWindow plans a window from the table's first-pass facts. rng is the
// range of the single integer key, or nil when the table is read by its first
// rows (no such key, keys the file doesn't hold, or a key that isn't integer
// in every row).
func newWindow(limit int, rng *intRange, rows int64) *window {
	w := &window{limit: limit, largeFrom: -1}
	switch {
	case limit <= 0:
		w.method = methodNone
	case rng == nil:
		w.method = methodFirst
	case rows == 0 || !rng.any:
		w.method = methodEmpty
	default:
		span := new(big.Int).Sub(rng.max.big(), rng.min.big())
		if span.Cmp(big.NewInt(int64(limit)*2)) <= 0 {
			w.method = methodAll
			w.small = &rowHeap{cap: limit}
			break
		}
		k := max(limit/3, 1)
		w.method = methodWindow
		w.small = &rowHeap{cap: k}
		w.mid = &rowHeap{cap: limit - 2*k}
		w.large = &rowHeap{cap: k, desc: true}
		if !rng.unsorted && rng.n == rows {
			w.largeFrom = rows - int64(k)
		}
		mid := new(big.Int).Add(rng.min.big(), new(big.Int).Div(span, big.NewInt(2)))
		w.midKey = ikeyBig(mid)
	}
	return w
}

// hold makes the window count its rows in *held.
func (w *window) hold(held *int64) {
	w.held = held
	for _, h := range []*rowHeap{w.small, w.mid, w.large} {
		if h != nil {
			h.held = held
		}
	}
}

// thin halves the rows the window holds, evenly, keeping at least floor of
// them in all, and lets it take no more than that again. It reports whether
// it dropped any.
func (w *window) thin(floor int) bool {
	dropped := false
	if w.method == methodFirst {
		defer func() { w.limit = min(w.limit, max(len(w.first), floor)) }()
	}
	if n := len(w.first); n > floor {
		keep := max(n/2, floor)
		pick := evenly(n, keep)
		out := w.first[:0]
		var freed int64
		for i, r := range w.first {
			if pick[i] {
				out = append(out, r)
			} else {
				freed += r.size
			}
		}
		clear(w.first[len(out):])
		w.first = out
		if w.held != nil {
			*w.held -= freed
		}
		dropped = true
	}
	var hs []*rowHeap
	for _, h := range []*rowHeap{w.small, w.mid, w.large} {
		if h != nil {
			hs = append(hs, h)
		}
	}
	for _, h := range hs {
		dropped = h.thin(max((floor+len(hs)-1)/len(hs), 1)) || dropped
	}
	return dropped
}

// keyed reports whether the window picks rows by their key.
func (w *window) keyed() bool { return w.small != nil }

func (w *window) offer(key ikey, haveKey bool, ord int64, build func() []sql.NullString) {
	switch {
	case w.keyed():
		if !haveKey {
			return
		}
		w.small.offer(key, ord, build)
		if w.mid != nil {
			if key.cmp(w.midKey) >= 0 {
				w.mid.offer(key, ord, build)
			}
			if ord > w.largeFrom {
				w.large.offer(key, ord, build)
			}
		}
	case w.method == methodFirst:
		if len(w.first) < w.limit {
			vals := build()
			r := winRow{ord: ord, vals: vals, size: rowSize(vals)}
			if w.held != nil {
				*w.held += r.size
			}
			w.first = append(w.first, r)
		}
	}
}

// result returns the window's rows in the order the live reads give them,
// with the ordinal of each.
func (w *window) result() (rows [][]sql.NullString, ords []int64) {
	seen := map[int64]bool{}
	add := func(rs []winRow) {
		for _, r := range rs {
			if !seen[r.ord] {
				seen[r.ord] = true
				rows = append(rows, r.vals)
				ords = append(ords, r.ord)
			}
		}
	}
	add(w.first)
	if w.small != nil {
		add(w.small.sorted())
	}
	if w.mid != nil {
		add(w.mid.sorted())
		add(w.large.sorted())
	}
	return rows, ords
}

// rowCond is a row subject's condition: a column equal to one of some
// literals.
type rowCond struct {
	col  string
	vals []string
}

// parseCond reads the forms the presets write: col = 'lit' and col IN ('a',
// 'b'). It reports false for anything else.
func parseCond(where string) (rowCond, bool) {
	s := strings.TrimSpace(where)
	i := 0
	for i < len(s) && (s[i] == '_' || s[i] == '`' || s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z') {
		i++
	}
	c := rowCond{col: strings.Trim(s[:i], "`")}
	if c.col == "" {
		return c, false
	}
	rest := strings.TrimSpace(s[i:])
	var list bool
	switch {
	case strings.HasPrefix(rest, "="):
		rest = strings.TrimSpace(rest[1:])
	case len(rest) > 2 && strings.EqualFold(rest[:2], "in"):
		rest = strings.TrimSpace(rest[2:])
		if !strings.HasPrefix(rest, "(") || !strings.HasSuffix(rest, ")") {
			return c, false
		}
		rest = strings.TrimSpace(rest[1 : len(rest)-1])
		list = true
	default:
		return c, false
	}
	for {
		if !strings.HasPrefix(rest, "'") {
			return c, false
		}
		end := strings.IndexByte(rest[1:], '\'')
		if end < 0 {
			return c, false
		}
		lit := rest[1 : 1+end]
		if strings.ContainsAny(lit, `\`) {
			return c, false
		}
		c.vals = append(c.vals, lit)
		rest = strings.TrimSpace(rest[end+2:])
		if rest == "" {
			return c, true
		}
		if !list || !strings.HasPrefix(rest, ",") {
			return c, false
		}
		rest = strings.TrimSpace(rest[1:])
	}
}

// collEqual compares ASCII text as the column's collation does: ignoring case
// for _ci, and trailing spaces for the PAD SPACE collations.
func collEqual(c *model.Column, a, b string) bool {
	coll := strings.ToLower(c.Collation)
	if !strings.Contains(coll, "_0900_") && !strings.Contains(coll, "nopad") {
		a, b = strings.TrimRight(a, " "), strings.TrimRight(b, " ")
	}
	if !strings.HasSuffix(coll, "_ci") {
		return a == b
	}
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// subjectCollect keeps, for one row subject, the 50 matching rows with the
// smallest keys.
type subjectCollect struct {
	rs    preset.RowSubject
	col   *model.Column // the column read
	condC *model.Column // the column the condition tests
	cond  rowCond
	colI  int // indexes into the table's columns
	condI int
	rows  *rowHeap
}

func (s *subjectCollect) matches(v string) bool {
	for _, l := range s.cond.vals {
		if collEqual(s.condC, v, l) {
			return true
		}
	}
	return false
}

// nameHeap is a max-heap of key names.
type nameHeap []string

func (h nameHeap) Len() int           { return len(h) }
func (h nameHeap) Less(i, j int) bool { return h[i] > h[j] }
func (h nameHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *nameHeap) Push(x any)        { *h = append(*h, x.(string)) }
func (h *nameHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// kvRow is one row of a key/value table, with the position that orders it.
type kvRow struct {
	ord   int64
	pk    ikey // the integer primary key, else the ordinal
	key   string
	value string
	null  bool
}

func (a kvRow) before(b kvRow) bool {
	if c := a.pk.cmp(b.pk); c != 0 {
		return c < 0
	}
	return a.ord < b.ord
}

// kvKey is what a key/value table listed outside the envelope keeps of one
// key: its first rows by primary key, and how many rows it has.
type kvKey struct {
	rows []kvRow
	n    int64
}

// kvCollect reads a key/value table in pass 2, in one of two shapes. Within
// the whole-read envelope it holds every row. Outside it holds, per key, the
// first rows, for as many keys and bytes as the limits allow.
type kvCollect struct {
	whole                 bool
	keyI, valI, pkI       int // indexes into the table's columns; pkI is -1 without an integer single key
	keyCol, valCol        *model.Column
	valueLen, perKey      int
	rows                  []kvRow
	keys                  map[string]*kvKey
	names                 nameHeap
	nameBytes, valueBytes int64
	kept                  int  // keys in names
	evicted, evictedBytes bool // keys were dropped; some for the bytes of names
	protected             map[string]bool
	rowBytes              int64 // bytes of the rows held whole
}

// A key/value row, and a key, count for more than their text: the kvRow's
// fields, the strings' headers, the map slot and the name heap's entry.
const (
	kvRowOverhead = 112
	kvKeyOverhead = 160
)

// kvRowSize is the bytes a key/value row is counted as holding.
func kvRowSize(r kvRow) int64 { return textSize(len(r.key)) + textSize(len(r.value)) + kvRowOverhead }

// held is the bytes the collector counts itself as holding.
func (c *kvCollect) held() int64 { return c.rowBytes + c.valueBytes + c.nameBytes }

// accessor reads the pass-2 row being added.
type accessor interface {
	val(j int) *sqldump.Value
}

// keyText is the text of a key value, as bytes that live only as long as the
// value does.
func keyText(c *model.Column, v *sqldump.Value) []byte {
	switch {
	case v.Kind == sqldump.ValNull || v.Kind == sqldump.ValDefault:
		return nil
	case v.Kind == sqldump.ValHex && sample.IsInteger(c):
		s, _ := cellText(c, v, 0, false)
		return []byte(s)
	}
	return v.Bytes
}

func (c *kvCollect) add(a accessor, ord int64, lim *dumpLimits) {
	kb := keyText(c.keyCol, a.val(c.keyI))
	pk := ikeyInt(ord)
	if c.pkI >= 0 {
		if k, ok := parseKey(a.val(c.pkI)); ok {
			pk = k
		}
	}
	text := func() kvRow {
		vtext, ok := cellText(c.valCol, a.val(c.valI), c.valueLen, false)
		return kvRow{ord: ord, pk: pk, key: string(kb), value: vtext, null: !ok}
	}
	if c.whole {
		row := text()
		c.rowBytes += kvRowSize(row)
		c.rows = append(c.rows, row)
		return
	}
	ent := c.keys[string(kb)]
	if ent == nil {
		key := string(kb)
		ent = &kvKey{}
		c.keys[key] = ent
		if !c.protected[key] {
			heap.Push(&c.names, key)
			c.kept++
			c.nameBytes += textSize(len(key)) + kvKeyOverhead
			for c.kept > lim.maxKeys || c.nameBytes > lim.keyBytes {
				c.evictedBytes = c.evictedBytes || c.nameBytes > lim.keyBytes
				drop := heap.Pop(&c.names).(string)
				c.kept--
				c.nameBytes -= textSize(len(drop)) + kvKeyOverhead
				for _, r := range c.keys[drop].rows {
					c.valueBytes -= kvRowSize(r)
				}
				delete(c.keys, drop)
				c.evicted = true
			}
			if c.keys[key] == nil {
				return
			}
		}
	}
	ent.n++
	// Only a row that is one of the key's first by primary key is read out.
	worst := 0
	for i := range ent.rows {
		if ent.rows[worst].before(ent.rows[i]) {
			worst = i
		}
	}
	probe := kvRow{ord: ord, pk: pk}
	if len(ent.rows) >= c.perKey && !probe.before(ent.rows[worst]) {
		return
	}
	row := text()
	size := kvRowSize(row)
	if len(ent.rows) < c.perKey {
		if c.valueBytes+size > lim.valueBytes {
			return
		}
		ent.rows = append(ent.rows, row)
		c.valueBytes += size
		return
	}
	old := ent.rows[worst]
	if c.valueBytes-kvRowSize(old)+size > lim.valueBytes {
		return
	}
	c.valueBytes += size - kvRowSize(old)
	ent.rows[worst] = row
}

// finish turns what the collector holds into the kvRead the live code
// judges, and the ordinals of the rows it holds. counts has the rows of each
// key kept.
func (c *kvCollect) finish(t *model.Table, meta *preset.MetaTable, opts Options, lim *dumpLimits) (kv *kvRead, held map[int64]bool, counts map[string]int64) {
	kv = newKVRead()
	held = map[int64]bool{}
	counts = map[string]int64{}
	toKV := func(rs []kvRow) []sample.KV {
		out := make([]sample.KV, len(rs))
		for i, r := range rs {
			out[i] = sample.KV{Key: r.key, Value: r.value, Null: r.null}
			held[r.ord] = true
		}
		return out
	}
	if c.whole {
		kv.mode = modeWhole
		sort.SliceStable(c.rows, func(i, j int) bool { return c.rows[i].before(c.rows[j]) })
		type ring struct {
			head, tail []kvRow
			next       int
		}
		n := opts.KeySampleRows
		first := max(n/2, 1)
		by := map[string]*ring{}
		var order []string
		for _, r := range c.rows {
			g := by[r.key]
			if g == nil {
				g = &ring{}
				by[r.key] = g
				order = append(order, r.key)
			}
			counts[r.key]++
			if len(g.head) < first {
				g.head = append(g.head, r)
				continue
			}
			if len(g.tail) < n-first {
				g.tail = append(g.tail, r)
				continue
			}
			if n-first > 0 {
				g.tail[g.next] = r
				g.next = (g.next + 1) % (n - first)
			}
		}
		for _, k := range order {
			g := by[k]
			kv.addKey(k)
			kv.addRows(k, toKV(append(g.head, g.tail...)))
		}
		sort.Strings(kv.keys)
		kv.guard(meta)
		return kv, held, counts
	}

	kv.mode = modeList
	for k := range c.keys {
		kv.addKey(k)
	}
	sort.Strings(kv.keys)
	kv.truncated = c.evicted
	switch {
	case c.evictedBytes:
		kv.warn(fmt.Sprintf("%s has more key names than the scan holds (%d MB of names); the smallest by name were judged, "+
			"and the keys presets know were kept", t.Name, lim.keyBytes>>20))
	case c.evicted:
		kv.warn(fmt.Sprintf("%s has more than %d keys; the smallest %d by name were judged, and the keys presets know were kept",
			t.Name, lim.maxKeys, lim.maxKeys))
	}
	for k, e := range c.keys {
		counts[k] = e.n
	}
	// Before any value is judged, as the live listing does.
	if kv.guard(meta) {
		return kv, held, counts
	}
	kv.subjects = subjects(t, meta, kv.keys)
	for _, k := range kv.keys {
		if e := c.keys[k]; len(e.rows) > 0 {
			sort.Slice(e.rows, func(i, j int) bool { return e.rows[i].before(e.rows[j]) })
			kv.addRows(k, toKV(e.rows))
		}
	}
	// A key with rows the byte limit left out is judged by name.
	for _, s := range kv.subjects {
		read := false
		for _, k := range s.keys {
			read = read || kv.read[k]
		}
		s.skipped = !read
	}
	return kv, held, counts
}
