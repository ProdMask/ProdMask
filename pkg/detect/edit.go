package detect

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The editor's limits are wider than the walker's, which only reads
// samples: a copy edits whole values, page-builder data included.
const (
	maxEditSize    = 64 << 20 // bytes
	maxEditNodes   = 1_000_000
	maxEditDepth   = 512
	maxEditNesting = 8 // serialized data inside JSON inside serialized data ...
)

// The errors EditStructured returns. Their text is fixed and never holds
// any of the value.
var (
	// ErrNotStructured: the value isn't one complete JSON or PHP-serialized
	// value, such as one cut off or with bytes after it.
	ErrNotStructured = errors.New("not a complete JSON or PHP-serialized value")
	// ErrTooLarge: the value is over the editor's limits of size, nodes,
	// depth or nesting.
	ErrTooLarge = errors.New("structured value over the editor's limits")
	// ErrBadEdit: an edit can't be written, such as a key that would equal
	// another key of its map, or a number that isn't one.
	ErrBadEdit = errors.New("an edit can't be written into the structured value")
)

// LeafKind says what a Leaf is.
type LeafKind int

const (
	LeafString LeafKind = iota + 1
	LeafNumber
	LeafBool
	LeafNull
	LeafKey
	// LeafEnum is a PHP enum case (E:…), which can't be edited.
	LeafEnum
)

// Leaf is one scalar or one key of a structured value, as EditStructured
// hands it out.
type Leaf struct {
	// Path is the leaf's path as Walk gives it: keys that may be data are
	// "*", "[]" or "{}". For a key, it is the path of the object or array
	// that holds it. Path is valid only during the call.
	Path []string
	// Key is a key's own text, for LeafKey: a JSON or PHP string key
	// decoded, or a PHP integer key in decimal. Segment is what the key adds
	// to the paths below it: the key, a template of it, "*" or "[]".
	Key, Segment string
	// DataKey marks a key that is itself a value worth checking, such as an
	// email or IP address, which Walk reports as a value at path {}.
	DataKey bool
	// Value is a string decoded, JSON escapes resolved, and other leaves as
	// written: 12.50, true, 1 for PHP's b:1;, null or N. For a key, it is
	// the key.
	Value string
	Kind  LeafKind
}

// EditStructured calls fn for every leaf of a JSON or PHP-serialized value,
// keys included, in order, and returns the value with the edits fn asked
// for: fn returns a leaf's new value and true, or false to keep it. Strings
// holding JSON or PHP-serialized data are opened as Walk opens them, and fn
// gets their leaves instead.
//
// Bytes that aren't edited are kept exactly: with no edit, out is s. An
// edited JSON string is escaped as the bytes it replaces are, or else as
// the value's other strings are, and PHP's lengths are recomputed in
// bytes, in every string and C: payload that holds an edit. A JSON string
// holding an edited value has only the characters the edits touch written
// again. Enum cases can't be edited, PHP integer keys only to
// integers, numbers and booleans only to valid ones, and keys only to keys
// unique in their map. On an error, out is empty, so a caller that drops
// the error writes nothing of the value.
func EditStructured(s string, fn func(Leaf) (string, bool)) (out string, edited bool, err error) {
	if len(s) > maxEditSize {
		return "", false, ErrTooLarge
	}
	// A first pass reads the value without calling fn, so fn never sees
	// the leaves of a value that turns out not to be whole.
	ed := &editor{fn: fn, dry: true, first: true}
	if _, _, err := ed.document(s, nil, 0); err != nil {
		return "", false, err
	}
	ed.dry, ed.first = false, false
	out, edits, err := ed.document(s, nil, 0)
	if err != nil {
		return "", false, err
	}
	return out, len(edits) > 0, nil
}

type editor struct {
	fn    func(Leaf) (string, bool)
	nodes int
	// dry reads without calling fn; first marks the first pass, which
	// counts the nodes; shallow reads nested values as plain strings.
	dry, first, shallow bool
}

// call hands a leaf to fn, except in a dry read.
func (ed *editor) call(l Leaf) (string, bool) {
	if ed.dry {
		return "", false
	}
	return ed.fn(l)
}

// node counts one value or key against the limit, in the first pass.
func (ed *editor) node() error {
	if !ed.first {
		return nil
	}
	if ed.nodes++; ed.nodes > maxEditNodes {
		return ErrTooLarge
	}
	return nil
}

// edit replaces s[start:end] with repl.
type edit struct {
	start, end int
	repl       string
}

func apply(s string, edits []edit) string {
	var b strings.Builder
	n := len(s)
	for _, e := range edits {
		n += len(e.repl) - (e.end - e.start)
	}
	b.Grow(n)
	prev := 0
	for _, e := range edits {
		b.WriteString(s[prev:e.start])
		b.WriteString(e.repl)
		prev = e.end
	}
	b.WriteString(s[prev:])
	return b.String()
}

// document edits one JSON or PHP-serialized value, with white space around
// it, as the walker trims it. It returns the value edited and the edits, in
// order, as offsets of s.
func (ed *editor) document(s string, path []string, nesting int) (string, []edit, error) {
	if nesting > maxEditNesting {
		return s, nil, ErrTooLarge
	}
	body := strings.TrimSpace(s)
	if body == "" {
		return s, nil, ErrNotStructured
	}
	lead := strings.Index(s, body)
	var (
		edits []edit
		err   error
	)
	switch {
	case body[0] == '{' || body[0] == '[':
		p := &jsonEditor{ed: ed, s: body, nesting: nesting, style: jsonStyleOf(body)}
		if err = p.value(path, 0); err == nil {
			p.skipSpace()
			if p.i != len(body) {
				err = ErrNotStructured
			}
		}
		edits = p.edits
	case rePHPStart.MatchString(body):
		p := &phpEditor{ed: ed, s: body, nesting: nesting}
		if err = p.value(path, 0); err == nil && p.i != len(body) {
			err = ErrNotStructured
		}
		edits = p.edits
	default:
		err = ErrNotStructured
	}
	if err != nil {
		return s, nil, err
	}
	if len(edits) == 0 {
		return s, nil, nil
	}
	out := s[:lead] + apply(body, edits) + s[lead+len(body):]
	for i := range edits {
		edits[i].start += lead
		edits[i].end += lead
	}
	return out, edits, nil
}

// nested edits a string leaf that holds structured data, as the walker
// opens it, and returns it edited, with the edits as offsets of v. ok is
// false when the string isn't such data, and is then a leaf of its own.
func (ed *editor) nested(v string, path []string, nesting int) (out string, edits []edit, ok bool, err error) {
	if ed.shallow || !looksStructured(strings.TrimSpace(v)) {
		return v, nil, false, nil
	}
	if nesting+1 > maxEditNesting {
		// Too deep to open: over the limits if it is structured data, a
		// string of its own if it isn't.
		dry, first := ed.dry, ed.first
		ed.dry, ed.first, ed.shallow = true, false, true
		_, _, err := ed.document(v, path, maxEditNesting)
		ed.dry, ed.first, ed.shallow = dry, first, false
		if err == nil {
			return v, nil, false, ErrTooLarge
		}
		return v, nil, false, nil
	}
	if !ed.dry {
		// Read it dry first, as the first pass did, before fn sees it.
		ed.dry = true
		_, _, err := ed.document(v, path, nesting+1)
		ed.dry = false
		if err != nil {
			return v, nil, false, nil
		}
	}
	out, edits, err = ed.document(v, path, nesting+1)
	if err == ErrNotStructured {
		return v, nil, false, nil
	}
	return out, edits, err == nil, err
}

// uniqueKeys checks that every edited key differs from the other keys of
// its map. keys holds each key as compared, edited marks the edited ones.
func uniqueKeys(keys []string, edited []bool) error {
	seen := make(map[string]int, len(keys))
	for _, k := range keys {
		seen[k]++
	}
	for i, k := range keys {
		if edited[i] && seen[k] > 1 {
			return ErrBadEdit
		}
	}
	return nil
}

// jsonStyle is how a JSON text writes its strings, for edits to match.
type jsonStyle struct {
	slash   bool      // escapes / as \/
	unicode bool      // escapes non-ASCII characters as \u
	upper   bool      // writes \u escapes in capitals
	ascii   [2]uint64 // the ASCII characters a part being written over escapes as \u
}

func jsonStyleOf(s string) jsonStyle {
	var st jsonStyle
	for off := 0; ; {
		i := strings.Index(s[off:], `\/`)
		if i < 0 {
			break
		}
		i += off
		if escapedAt(s, i) {
			st.slash = true
			break
		}
		off = i + 2
	}
	rawHigh := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			rawHigh = true
			break
		}
	}
	for off := 0; ; {
		i := strings.Index(s[off:], `\u`)
		if i < 0 {
			break
		}
		i += off
		off = i + 2
		if !escapedAt(s, i) || i+6 > len(s) {
			continue
		}
		hex := s[i+2 : i+6]
		r, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			continue
		}
		if r >= 0x80 && !rawHigh {
			st.unicode = true
		}
		if strings.ContainsAny(hex, "ABCDEF") {
			st.upper = true
		}
	}
	return st
}

// escapedAt reports whether the backslash at s[i] starts an escape, which
// it does after an even number of backslashes.
func escapedAt(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 0
}

type jsonEditor struct {
	ed      *editor
	s       string
	i       int
	nesting int
	style   jsonStyle
	edits   []edit
}

func (p *jsonEditor) skipSpace() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\r', '\n':
			p.i++
		default:
			return
		}
	}
}

func (p *jsonEditor) value(path []string, depth int) error {
	if depth > maxEditDepth {
		return ErrTooLarge
	}
	if err := p.ed.node(); err != nil {
		return err
	}
	p.skipSpace()
	if p.i >= len(p.s) {
		return ErrNotStructured
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(path, depth)
	case c == '[':
		return p.array(path, depth)
	case c == '"':
		return p.stringLeaf(path)
	case c == 't' || c == 'f':
		return p.literal(path, LeafBool)
	case c == 'n':
		return p.literal(path, LeafNull)
	case c == '-' || c >= '0' && c <= '9':
		return p.number(path)
	}
	return ErrNotStructured
}

func (p *jsonEditor) object(path []string, depth int) error {
	p.i++
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return nil
	}
	var (
		keys    []string
		edited  []bool
		changed bool
	)
	for {
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return ErrNotStructured
		}
		if err := p.ed.node(); err != nil {
			return err
		}
		start := p.i
		k, err := p.readString()
		if err != nil {
			return err
		}
		seg := normKey(k)
		final := k
		if nk, ok := p.ed.call(Leaf{Path: path, Key: k, Segment: seg, DataKey: keyIsData(k), Value: k, Kind: LeafKey}); ok && nk != k {
			p.edits = append(p.edits, edit{start, p.i, p.encode(start, k, nk)})
			final = nk
			changed = true
		}
		keys = append(keys, final)
		edited = append(edited, final != k)
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return ErrNotStructured
		}
		p.i++
		if err := p.value(extend(path, seg), depth+1); err != nil {
			return err
		}
		p.skipSpace()
		if p.i >= len(p.s) {
			return ErrNotStructured
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] != '}' {
			return ErrNotStructured
		}
		p.i++
		break
	}
	if changed {
		return uniqueKeys(keys, edited)
	}
	return nil
}

func (p *jsonEditor) array(path []string, depth int) error {
	p.i++
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return nil
	}
	for {
		if err := p.value(extend(path, "[]"), depth+1); err != nil {
			return err
		}
		p.skipSpace()
		if p.i >= len(p.s) {
			return ErrNotStructured
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] != ']' {
			return ErrNotStructured
		}
		p.i++
		return nil
	}
}

func (p *jsonEditor) stringLeaf(path []string) error {
	start := p.i
	v, err := p.readString()
	if err != nil {
		return err
	}
	if _, edits, ok, err := p.ed.nested(v, path, p.nesting); err != nil {
		return err
	} else if ok {
		if len(edits) > 0 {
			p.edits = append(p.edits, edit{start, p.i, p.encodeEdits(start, v, edits)})
		}
		return nil
	}
	if nv, ok := p.ed.call(Leaf{Path: path, Value: v, Kind: LeafString}); ok && nv != v {
		p.edits = append(p.edits, edit{start, p.i, p.encode(start, v, nv)})
	}
	return nil
}

func (p *jsonEditor) literal(path []string, kind LeafKind) error {
	var word string
	for _, w := range []string{"true", "false", "null"} {
		if strings.HasPrefix(p.s[p.i:], w) {
			word = w
		}
	}
	if word == "" || (kind == LeafNull) != (word == "null") {
		return ErrNotStructured
	}
	start := p.i
	p.i += len(word)
	nv, ok := p.ed.call(Leaf{Path: path, Value: word, Kind: kind})
	if !ok || nv == word {
		return nil
	}
	if kind == LeafNull || nv != "true" && nv != "false" {
		return ErrBadEdit
	}
	p.edits = append(p.edits, edit{start, p.i, nv})
	return nil
}

func (p *jsonEditor) number(path []string) error {
	start := p.i
	n := jsonNumberLen(p.s[p.i:])
	if n == 0 {
		return ErrNotStructured
	}
	p.i += n
	v := p.s[start:p.i]
	nv, ok := p.ed.call(Leaf{Path: path, Value: v, Kind: LeafNumber})
	if !ok || nv == v {
		return nil
	}
	if nv == "" || jsonNumberLen(nv) != len(nv) {
		return ErrBadEdit
	}
	p.edits = append(p.edits, edit{start, p.i, nv})
	return nil
}

// jsonNumberLen returns the length of the JSON number s starts with, or 0.
func jsonNumberLen(s string) int {
	i := 0
	if i < len(s) && s[i] == '-' {
		i++
	}
	switch {
	case i < len(s) && s[i] == '0':
		i++
	case i < len(s) && s[i] >= '1' && s[i] <= '9':
		for i < len(s) && isDigitASCII(s[i]) {
			i++
		}
	default:
		return 0
	}
	if i < len(s) && s[i] == '.' {
		j := i + 1
		for j < len(s) && isDigitASCII(s[j]) {
			j++
		}
		if j == i+1 {
			return 0
		}
		i = j
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		j := i + 1
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		k := j
		for k < len(s) && isDigitASCII(s[k]) {
			k++
		}
		if k == j {
			return 0
		}
		i = k
	}
	return i
}

// jsonUnit reads the escape or byte at raw[i] in a JSON string's content:
// how many bytes it takes there and what it decodes to. A surrogate pair is
// one unit. Bytes that aren't UTF-8 decode as themselves.
func jsonUnit(raw string, i int) (n int, dec string, ok bool) {
	c := raw[i]
	if c != '\\' {
		if c < 0x20 {
			return 0, "", false
		}
		return 1, raw[i : i+1], true
	}
	if i+1 >= len(raw) {
		return 0, "", false
	}
	switch raw[i+1] {
	case '"', '\\', '/':
		return 2, raw[i+1 : i+2], true
	case 'b':
		return 2, "\b", true
	case 'f':
		return 2, "\f", true
	case 'n':
		return 2, "\n", true
	case 'r':
		return 2, "\r", true
	case 't':
		return 2, "\t", true
	case 'u':
		r, ok := hex4(raw, i+2)
		if !ok {
			return 0, "", false
		}
		if r >= 0xD800 && r < 0xDC00 && i+12 <= len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
			if lo, ok := hex4(raw, i+8); ok && lo >= 0xDC00 && lo < 0xE000 {
				return 12, string(rune(0x10000 + (r-0xD800)<<10 + (lo - 0xDC00))), true
			}
		}
		if r >= 0xD800 && r < 0xE000 {
			return 6, string(utf8.RuneError), true
		}
		return 6, string(rune(r)), true
	}
	return 0, "", false
}

func hex4(s string, i int) (rune, bool) {
	if i+4 > len(s) {
		return 0, false
	}
	v, err := strconv.ParseUint(s[i:i+4], 16, 32)
	return rune(v), err == nil && !strings.ContainsAny(s[i:i+4], "+-")
}

// readString reads the JSON string at p.i and returns it decoded.
func (p *jsonEditor) readString() (string, error) {
	start := p.i + 1
	end := start
	plain := true
	for {
		if end >= len(p.s) {
			return "", ErrNotStructured
		}
		c := p.s[end]
		if c == '"' {
			break
		}
		if c < 0x20 {
			return "", ErrNotStructured
		}
		if c == '\\' {
			plain = false
			if end+1 >= len(p.s) {
				return "", ErrNotStructured
			}
			end += 2
			continue
		}
		end++
	}
	p.i = end + 1
	raw := p.s[start:end]
	if plain {
		return raw, nil
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		n, dec, ok := jsonUnit(raw, i)
		if !ok {
			return "", ErrNotStructured
		}
		b.WriteString(dec)
		i += n
	}
	return b.String(), nil
}

// encode writes the string token at p.s[start:p.i], which decodes to old,
// with new as its value. Only the part that changed is written again, so
// the bytes around it stay as they were, and in the style of the bytes it
// replaces where they show one, else in the text's.
func (p *jsonEditor) encode(start int, old, new string) string {
	raw := p.s[start+1 : p.i-1]
	pre := 0
	for pre < len(old) && pre < len(new) && old[pre] == new[pre] {
		pre++
	}
	suf := 0
	for suf < len(old)-pre && suf < len(new)-pre && old[len(old)-1-suf] == new[len(new)-1-suf] {
		suf++
	}
	// Widen the changed part to whole units of the raw text.
	rawA, decA, rawB, decB := 0, 0, len(raw), len(old)
	for i, d := 0, 0; i < len(raw); {
		n, dec, _ := jsonUnit(raw, i)
		if d+len(dec) <= pre {
			rawA, decA = i+n, d+len(dec)
		}
		if d >= len(old)-suf && i < rawB {
			rawB, decB = i, d
			break
		}
		i += n
		d += len(dec)
	}
	var b strings.Builder
	b.Grow(len(raw) + len(new) - len(old) + 8)
	b.WriteByte('"')
	b.WriteString(raw[:rawA])
	p.style.within(raw[rawA:rawB]).write(&b, new[decA:len(new)-(len(old)-decB)])
	b.WriteString(raw[rawB:])
	b.WriteByte('"')
	return b.String()
}

// encodeEdits writes the string token at p.s[start:p.i], which decodes to
// old, with edits, as offsets of old, applied. Each edit is widened to the
// whole escapes and characters it touches, and edits whose widened parts
// meet are written together; every other unit stays as it was.
func (p *jsonEditor) encodeEdits(start int, old string, edits []edit) string {
	raw := p.s[start+1 : p.i-1]
	var b strings.Builder
	b.Grow(len(raw) + 16)
	b.WriteByte('"')
	ri, d := 0, 0 // a unit's start, in raw and in old
	for k := 0; k < len(edits); {
		// The units wholly before the edit stay.
		for ri < len(raw) {
			n, dec, _ := jsonUnit(raw, ri)
			if d+len(dec) > edits[k].start {
				break
			}
			b.WriteString(raw[ri : ri+n])
			ri, d = ri+n, d+len(dec)
		}
		ra, pos := ri, d
		var text strings.Builder
		for {
			// Take the units up to the edit's end, and the next edit too when it
			// starts inside them.
			for d < edits[k].end && ri < len(raw) {
				n, dec, _ := jsonUnit(raw, ri)
				ri, d = ri+n, d+len(dec)
			}
			text.WriteString(old[pos:edits[k].start])
			text.WriteString(edits[k].repl)
			pos = edits[k].end
			if k++; k == len(edits) || edits[k].start >= d {
				break
			}
		}
		text.WriteString(old[pos:d])
		p.style.within(raw[ra:ri]).write(&b, text.String())
	}
	b.WriteString(raw[ri:])
	b.WriteByte('"')
	return b.String()
}

// within is the style for writing over a part of a string's raw text: the
// part's own, where it shows one, so a text that mixes styles keeps each
// part's.
func (st jsonStyle) within(raw string) jsonStyle {
	high, upper, lower := false, false, false
	unicode, slash, rawSlash := false, false, false
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c >= 0x80:
			high = true
		case c == '/':
			rawSlash = true
		case c == '\\' && i+1 < len(raw):
			switch raw[i+1] {
			case '/':
				slash = true
			case 'u':
				if i+6 <= len(raw) {
					hex := raw[i+2 : i+6]
					switch r, err := strconv.ParseUint(hex, 16, 32); {
					case err != nil:
					case r >= 0x80:
						unicode = true
					case r >= 0x20:
						// A character of ASCII written as an escape, as WordPress
						// writes quotes and < > & in block attributes.
						st.ascii[r>>6] |= 1 << (r & 63)
					}
					upper = upper || strings.ContainsAny(hex, "ABCDEF")
					lower = lower || strings.ContainsAny(hex, "abcdef")
				}
			}
			i++ // the escaped character
		}
	}
	switch {
	case high:
		st.unicode = false
	case unicode:
		st.unicode = true
	}
	switch {
	case slash:
		st.slash = true
	case rawSlash:
		st.slash = false
	}
	if upper != lower {
		st.upper = upper
	}
	return st
}

// write escapes s as a JSON string's content in the style.
func (st jsonStyle) write(b *strings.Builder, s string) {
	const lower, upper = "0123456789abcdef", "0123456789ABCDEF"
	digits := lower
	if st.upper {
		digits = upper
	}
	u := func(r rune) {
		b.WriteString(`\u`)
		for shift := 12; shift >= 0; shift -= 4 {
			b.WriteByte(digits[r>>shift&0xF])
		}
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c < 0x80 && st.ascii[c>>6]&(1<<(c&63)) != 0:
			u(rune(c))
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '/' && st.slash:
			b.WriteString(`\/`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c < 0x20:
			u(rune(c))
		case c >= 0x80 && st.unicode:
			r, n := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && n == 1 {
				b.WriteByte(c) // not UTF-8: kept as it is
				break
			}
			if r > 0xFFFF {
				r -= 0x10000
				u(0xD800 + r>>10)
				u(0xDC00 + r&0x3FF)
			} else {
				u(r)
			}
			i += n
			continue
		default:
			b.WriteByte(c)
		}
		i++
	}
}

type phpEditor struct {
	ed      *editor
	s       string
	i       int
	nesting int
	edits   []edit
}

var (
	rePHPInt   = regexp.MustCompile(`^-?[0-9]+$`)
	rePHPFloat = regexp.MustCompile(`^(?:-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|-?INF|NAN)$`)
)

func (p *phpEditor) value(path []string, depth int) error {
	if depth > maxEditDepth {
		return ErrTooLarge
	}
	if err := p.ed.node(); err != nil {
		return err
	}
	if p.i >= len(p.s) {
		return ErrNotStructured
	}
	switch p.s[p.i] {
	case 'N':
		if !strings.HasPrefix(p.s[p.i:], "N;") {
			return ErrNotStructured
		}
		p.i += 2
		if nv, ok := p.ed.call(Leaf{Path: path, Value: "N", Kind: LeafNull}); ok && nv != "N" {
			return ErrBadEdit
		}
		return nil
	case 'b', 'i', 'd':
		return p.scalar(path)
	case 's':
		return p.stringLeaf(path)
	case 'E':
		start, n, err := p.lengthString()
		if err != nil {
			return err
		}
		if p.s[start+n+1] != ';' {
			return ErrNotStructured
		}
		v := p.s[start : start+n]
		if nv, ok := p.ed.call(Leaf{Path: path, Value: v, Kind: LeafEnum}); ok && nv != v {
			return ErrBadEdit
		}
		return nil
	case 'a':
		p.i++
		count, err := p.header(':', ':')
		if err != nil {
			return err
		}
		if !p.expect('{') {
			return ErrNotStructured
		}
		return p.members(path, depth, count, true)
	case 'O':
		if _, _, err := p.lengthString(); err != nil {
			return err
		}
		p.i-- // lengthString read the closing ";", which is ":" here
		if p.s[p.i] != ':' {
			return ErrNotStructured
		}
		p.i++
		count, err := p.number(':')
		if err != nil {
			return err
		}
		if !p.expect('{') {
			return ErrNotStructured
		}
		return p.members(path, depth, count, false)
	case 'C':
		return p.custom(path)
	case 'r', 'R':
		p.i++
		if _, err := p.header(':', ';'); err != nil {
			return err
		}
		return nil
	}
	return ErrNotStructured
}

func (p *phpEditor) expect(c byte) bool {
	if p.i < len(p.s) && p.s[p.i] == c {
		p.i++
		return true
	}
	return false
}

// header reads ":N" up to term after a type letter, and returns N.
func (p *phpEditor) header(colon, term byte) (int, error) {
	if p.i >= len(p.s) || p.s[p.i] != colon {
		return 0, ErrNotStructured
	}
	p.i++
	return p.number(term)
}

// number reads 1 to 10 digits up to term, skips term, and returns them.
func (p *phpEditor) number(term byte) (int, error) {
	end := strings.IndexByte(p.s[p.i:], term)
	if end <= 0 || end > 10 {
		return 0, ErrNotStructured
	}
	for j := p.i; j < p.i+end; j++ {
		if !isDigitASCII(p.s[j]) {
			return 0, ErrNotStructured
		}
	}
	n, err := strconv.Atoi(p.s[p.i : p.i+end])
	if err != nil {
		return 0, ErrNotStructured
	}
	p.i += end + 1
	return n, nil
}

// lengthString reads x:N:"<N bytes>"; and returns where the bytes start.
func (p *phpEditor) lengthString() (start, n int, err error) {
	p.i++
	if n, err = p.header(':', ':'); err != nil {
		return 0, 0, err
	}
	if p.i >= len(p.s) || p.s[p.i] != '"' || p.i+1+n+2 > len(p.s) || p.s[p.i+1+n] != '"' {
		return 0, 0, ErrNotStructured
	}
	start = p.i + 1
	if p.s[start+n+1] != ';' && p.s[start+n+1] != ':' {
		return 0, 0, ErrNotStructured
	}
	p.i = start + n + 2
	return start, n, nil
}

func (p *phpEditor) scalar(path []string) error {
	typ := p.s[p.i]
	tok := p.i
	if p.i+1 >= len(p.s) || p.s[p.i+1] != ':' {
		return ErrNotStructured
	}
	end := strings.IndexByte(p.s[p.i+2:], ';')
	if end < 0 {
		return ErrNotStructured
	}
	v := p.s[p.i+2 : p.i+2+end]
	p.i += 2 + end + 1
	kind, valid := LeafNumber, rePHPInt.MatchString
	switch typ {
	case 'b':
		kind, valid = LeafBool, func(s string) bool { return s == "0" || s == "1" }
	case 'd':
		valid = rePHPFloat.MatchString
	}
	if !valid(v) {
		return ErrNotStructured
	}
	nv, ok := p.ed.call(Leaf{Path: path, Value: v, Kind: kind})
	if !ok || nv == v {
		return nil
	}
	if !valid(nv) {
		return ErrBadEdit
	}
	p.edits = append(p.edits, edit{tok, p.i, string(typ) + ":" + nv + ";"})
	return nil
}

func (p *phpEditor) stringLeaf(path []string) error {
	tok := p.i
	start, n, err := p.lengthString()
	if err != nil {
		return err
	}
	if p.s[start+n+1] != ';' {
		return ErrNotStructured
	}
	v := p.s[start : start+n]
	if out, edits, ok, err := p.ed.nested(v, path, p.nesting); err != nil {
		return err
	} else if ok {
		if len(edits) > 0 {
			p.edits = append(p.edits, edit{tok, p.i, phpString(out)})
		}
		return nil
	}
	if nv, ok := p.ed.call(Leaf{Path: path, Value: v, Kind: LeafString}); ok && nv != v {
		p.edits = append(p.edits, edit{tok, p.i, phpString(nv)})
	}
	return nil
}

func phpString(s string) string { return "s:" + strconv.Itoa(len(s)) + `:"` + s + `";` }

// custom reads C:N:"Class":M:{<M bytes>}, whose payload is a string leaf.
func (p *phpEditor) custom(path []string) error {
	tok := p.i
	if _, _, err := p.lengthString(); err != nil {
		return err
	}
	p.i--
	if p.s[p.i] != ':' {
		return ErrNotStructured
	}
	head := p.s[tok:p.i] // C:N:"Class"
	p.i++
	size, err := p.number(':')
	if err != nil {
		return err
	}
	if p.i >= len(p.s) || p.s[p.i] != '{' || p.i+1+size+1 > len(p.s) || p.s[p.i+1+size] != '}' {
		return ErrNotStructured
	}
	start := p.i + 1
	p.i = start + size + 1
	v := p.s[start : start+size]
	nv, edits, ok, err := p.ed.nested(v, path, p.nesting)
	if err != nil {
		return err
	}
	edited := len(edits) > 0
	if !ok {
		var change bool
		nv, change = p.ed.call(Leaf{Path: path, Value: v, Kind: LeafString})
		edited = change && nv != v
	}
	if edited {
		p.edits = append(p.edits, edit{tok, p.i, head + ":" + strconv.Itoa(len(nv)) + ":{" + nv + "}"})
	}
	return nil
}

// members reads count key/value pairs and the closing brace of an array
// (or an object's properties, when array is false).
func (p *phpEditor) members(path []string, depth, count int, array bool) error {
	var (
		keys    []string
		edited  []bool
		changed bool
	)
	for k := 0; k < count; k++ {
		if p.i >= len(p.s) {
			return ErrNotStructured
		}
		if err := p.ed.node(); err != nil {
			return err
		}
		var seg string
		switch p.s[p.i] {
		case 'i':
			if p.i+1 >= len(p.s) || p.s[p.i+1] != ':' {
				return ErrNotStructured
			}
			end := strings.IndexByte(p.s[p.i+2:], ';')
			if end < 0 || !rePHPInt.MatchString(p.s[p.i+2:p.i+2+end]) {
				return ErrNotStructured
			}
			tok, key := p.i, p.s[p.i+2:p.i+2+end]
			p.i += 2 + end + 1
			seg = "[]"
			final := key
			if nk, ok := p.ed.call(Leaf{Path: path, Key: key, Segment: seg, Value: key, Kind: LeafKey}); ok && nk != key {
				// An integer key stays an integer.
				if n, err := strconv.ParseInt(nk, 10, 64); err != nil || strconv.FormatInt(n, 10) != nk {
					return ErrBadEdit
				}
				p.edits = append(p.edits, edit{tok, p.i, "i:" + nk + ";"})
				final = nk
				changed = true
			}
			keys = append(keys, "i:"+final)
			edited = append(edited, final != key)
		case 's':
			tok := p.i
			start, n, err := p.lengthString()
			if err != nil {
				return err
			}
			if p.s[start+n+1] != ';' {
				return ErrNotStructured
			}
			key := p.s[start : start+n]
			seg = normKey(key)
			final := key
			if nk, ok := p.ed.call(Leaf{Path: path, Key: key, Segment: seg, DataKey: keyIsData(key), Value: key, Kind: LeafKey}); ok && nk != key {
				p.edits = append(p.edits, edit{tok, p.i, phpString(nk)})
				final = nk
				changed = true
			}
			keys = append(keys, phpKeyOf(final, array))
			edited = append(edited, final != key)
		default:
			return ErrNotStructured
		}
		if err := p.value(extend(path, seg), depth+1); err != nil {
			return err
		}
	}
	if p.i >= len(p.s) || p.s[p.i] != '}' {
		return ErrNotStructured
	}
	p.i++
	if changed {
		return uniqueKeys(keys, edited)
	}
	return nil
}

// phpKeyOf is a string key as PHP compares it: in an array, a decimal
// integer written plainly is the integer key.
func phpKeyOf(k string, array bool) string {
	if n, err := strconv.ParseInt(k, 10, 64); array && err == nil && strconv.FormatInt(n, 10) == k {
		return "i:" + k
	}
	return "s:" + k
}
