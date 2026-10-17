package detect

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Limits that keep a hostile or huge value from costing much.
const (
	maxDepth     = 24
	maxNodes     = 5000
	maxNesting   = 4 // serialized data inside JSON inside serialized data ...
	maxPathParts = 8
)

// leafFunc receives every scalar inside a structured value with the path of
// keys leading to it.
type leafFunc func(path []string, value string)

var rePHPStart = regexp.MustCompile(`^(?:a:\d+:\{|O:\d+:"|C:\d+:"|s:\d+:"|i:-?\d+;|d:-?[0-9.eE+-]+;|b:[01];|N;$)`)

// looksStructured reports whether a value is JSON or PHP-serialized.
func looksStructured(s string) bool {
	if len(s) < 2 {
		return false
	}
	switch s[0] {
	case '{':
		return true
	case '[':
		t := strings.TrimLeft(s[1:], " \t\r\n")
		return t != "" && (t[0] == '{' || t[0] == '"' || t[0] == '[')
	}
	return (s[0] == 'a' || s[0] == 'O' || s[0] == 'C') && rePHPStart.MatchString(s)
}

// walkStructured feeds every leaf of a JSON or PHP-serialized value to fn.
// It returns false when the value is neither. Truncated input still yields
// the leaves before the cut.
func walkStructured(s string, fn leafFunc) bool {
	w := &walker{fn: fn}
	return w.walk(s, nil, 0)
}

type walker struct {
	fn    leafFunc
	nodes int
}

func (w *walker) walk(s string, path []string, nesting int) bool {
	if nesting > maxNesting {
		return false
	}
	switch {
	case len(s) >= 2 && (s[0] == '{' || s[0] == '['):
		jw := &jsonWalker{w: w, dec: json.NewDecoder(strings.NewReader(s)), nesting: nesting}
		jw.dec.UseNumber()
		err := jw.value(path, 0)
		return err == nil || jw.leaves > 0
	case rePHPStart.MatchString(s):
		p := &phpParser{w: w, s: s, nesting: nesting}
		p.value(path, 0)
		return p.leaves > 0 || p.complete
	}
	return false
}

// leaf hands a scalar to fn, unless it is itself structured data, which is
// walked in place (Laravel queues put serialized PHP inside JSON, WooCommerce
// serializes arrays twice).
func (w *walker) leaf(path []string, v string, nesting int) {
	w.nodes++
	t := strings.TrimSpace(v)
	if looksStructured(t) && w.walk(t, path, nesting+1) {
		return
	}
	w.fn(path, v)
}

var (
	reIdentKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$`)
	reHexKey   = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
)

// normKey makes a key safe and stable for a path. Keys that are not plain
// identifiers (numbers, hashes, emails, anything with spaces) may be data
// themselves, so they collapse to "*" or "[]" and are never shown. In
// identifiers, the parts that look like data are templated as in key names:
// a cached profile keyed by um_email_as_username_<email> shows as
// um_email_as_username_*.
func normKey(k string) string {
	if i := strings.LastIndexByte(k, 0); i >= 0 { // PHP private/protected properties
		k = k[i+1:]
	}
	k = strings.TrimSpace(k)
	switch {
	case k == "":
		return "*"
	case isDigits(k):
		return "[]"
	case reHexKey.MatchString(k):
		return "*"
	case !reIdentKey.MatchString(k):
		return "*"
	}
	if t := Template(k).Pattern; t != k {
		if countLetters(t) < 3 {
			return "*"
		}
		return t
	}
	return k
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' {
		s = s[1:]
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// keyIsData reports whether a raw key looks like a value worth checking,
// such as a map keyed by email address or by visitor IP (Limit Login
// Attempts keeps lockouts that way).
func keyIsData(k string) bool {
	k = strings.TrimSpace(k)
	return (strings.Contains(k, "@") && IsEmail(k)) || (strings.ContainsAny(k, ".:") && isIP(k) && !versionQuad(k))
}

// keysPath is the path segment for the keys of a map whose keys are data.
// It only ever ends a path; the values under those keys stay under "*".
const keysPath = "{}"

func extend(path []string, key string) []string {
	if len(path) >= maxPathParts {
		return path
	}
	return append(path, key)
}

// Walk feeds every leaf of a JSON or PHP-serialized value to fn, with its
// path as JoinPath would render it in parts. Keys that may be data are
// already reduced to "*", "[]" or "{}". It returns false when the value is
// neither. Callers must never print the values.
func Walk(s string, fn func(path []string, value string)) bool {
	return walkStructured(strings.TrimSpace(s), fn)
}

// Flatten returns the leaves of a JSON or PHP-serialized value by path,
// keeping the first value of each path. It is for reading settings, such as
// whether a payment gateway runs in live mode; callers must never print the
// values.
func Flatten(s string) map[string]string {
	out := map[string]string{}
	walkStructured(strings.TrimSpace(s), func(path []string, v string) {
		k := JoinPath(path)
		if _, ok := out[k]; !ok {
			out[k] = v
		}
	})
	return out
}

// JoinPath renders a path: billing.email, items[].name, cart.*.line_total,
// lockouts{} (the keys of a map keyed by data).
func JoinPath(path []string) string {
	var b strings.Builder
	for _, p := range path {
		if p == "[]" || p == keysPath {
			b.WriteString(p)
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(p)
	}
	return b.String()
}

type jsonWalker struct {
	w       *walker
	dec     *json.Decoder
	nesting int
	leaves  int
}

func (j *jsonWalker) value(path []string, depth int) error {
	if depth > maxDepth || j.w.nodes > maxNodes {
		return errLimit
	}
	tok, err := j.dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			for j.dec.More() {
				kt, err := j.dec.Token()
				if err != nil {
					return err
				}
				k, _ := kt.(string)
				if keyIsData(k) {
					j.leaves++
					j.w.fn(extend(path, keysPath), k)
				}
				if err := j.value(extend(path, normKey(k)), depth+1); err != nil {
					return err
				}
			}
			_, err = j.dec.Token()
			return err
		case '[':
			for j.dec.More() {
				if err := j.value(extend(path, "[]"), depth+1); err != nil {
					return err
				}
			}
			_, err = j.dec.Token()
			return err
		}
	case string:
		j.leaves++
		j.w.leaf(path, t, j.nesting)
	case json.Number:
		j.leaves++
		j.w.fn(path, t.String())
	case bool:
		j.leaves++
		j.w.fn(path, strconv.FormatBool(t))
	}
	return nil
}

type limitError struct{}

func (limitError) Error() string { return "structure too large or deep" }

var errLimit error = limitError{}

// phpParser reads PHP's serialize() format: N; b:1; i:5; d:0.5; s:3:"abc";
// a:2:{...} O:8:"stdClass":1:{...} C:3:"Foo":5:{...} E:7:"Foo:Bar"; r:1;
type phpParser struct {
	w        *walker
	s        string
	i        int
	nesting  int
	leaves   int
	complete bool
}

func (p *phpParser) value(path []string, depth int) bool {
	if depth > maxDepth || p.w.nodes > maxNodes || p.i >= len(p.s) {
		return false
	}
	p.w.nodes++
	ok := p.parse(path, depth)
	if ok && depth == 0 {
		p.complete = p.i == len(p.s)
	}
	return ok
}

func (p *phpParser) parse(path []string, depth int) bool {
	s := p.s
	switch s[p.i] {
	case 'N':
		if strings.HasPrefix(s[p.i:], "N;") {
			p.i += 2
			return true
		}
		return false
	case 'b', 'i', 'd':
		if p.i+1 >= len(s) || s[p.i+1] != ':' {
			return false
		}
		end := strings.IndexByte(s[p.i+2:], ';')
		if end < 0 {
			return false
		}
		v := s[p.i+2 : p.i+2+end]
		p.i += 2 + end + 1
		p.leaves++
		p.w.fn(path, v)
		return true
	case 's', 'E':
		n, ok := p.length()
		if !ok || p.i >= len(s) || s[p.i] != '"' {
			return false
		}
		start := p.i + 1
		if start+n > len(s) { // cut off by the sampler
			p.leaves++
			p.w.fn(path, s[start:])
			p.i = len(s)
			return false
		}
		v := s[start : start+n]
		if !strings.HasPrefix(s[start+n:], `";`) {
			return false
		}
		p.i = start + n + 2
		p.leaves++
		p.w.leaf(path, v, p.nesting)
		return true
	case 'a':
		count, ok := p.length()
		if !ok || !p.expect('{') {
			return false
		}
		for k := 0; k < count; k++ {
			key, ok := p.key(path)
			if !ok {
				return false
			}
			if !p.value(extend(path, key), depth+1) {
				return false
			}
		}
		return p.expect('}')
	case 'O':
		n, ok := p.length() // class name length
		if !ok || !p.expect('"') || p.i+n > len(s) {
			return false
		}
		p.i += n
		if !p.expect('"') || !p.expect(':') {
			return false
		}
		count, ok := p.number(':')
		if !ok || !p.expect('{') {
			return false
		}
		for k := 0; k < count; k++ {
			key, ok := p.key(path)
			if !ok {
				return false
			}
			if !p.value(extend(path, key), depth+1) {
				return false
			}
		}
		return p.expect('}')
	case 'C':
		n, ok := p.length()
		if !ok || !p.expect('"') || p.i+n > len(s) {
			return false
		}
		p.i += n
		if !p.expect('"') || !p.expect(':') {
			return false
		}
		size, ok := p.number(':')
		if !ok || !p.expect('{') {
			return false
		}
		if p.i+size > len(s) {
			p.leaves++
			p.w.fn(path, s[p.i:])
			p.i = len(s)
			return false
		}
		p.leaves++
		p.w.leaf(path, s[p.i:p.i+size], p.nesting)
		p.i += size
		return p.expect('}')
	case 'r', 'R':
		end := strings.IndexByte(s[p.i:], ';')
		if end < 0 {
			return false
		}
		p.i += end + 1
		return true
	}
	return false
}

// key reads an array key or property name and normalises it.
func (p *phpParser) key(path []string) (string, bool) {
	if p.i >= len(p.s) {
		return "", false
	}
	switch p.s[p.i] {
	case 'i':
		if p.i+1 >= len(p.s) || p.s[p.i+1] != ':' {
			return "", false
		}
		end := strings.IndexByte(p.s[p.i+2:], ';')
		if end < 0 {
			return "", false
		}
		p.i += 2 + end + 1
		return "[]", true
	case 's':
		n, ok := p.length()
		if !ok || p.i >= len(p.s) || p.s[p.i] != '"' || p.i+1+n+2 > len(p.s) {
			return "", false
		}
		k := p.s[p.i+1 : p.i+1+n]
		if p.s[p.i+1+n:p.i+1+n+2] != `";` {
			return "", false
		}
		p.i += 1 + n + 2
		if keyIsData(k) {
			p.leaves++
			p.w.fn(extend(path, keysPath), k)
		}
		return normKey(k), true
	}
	return "", false
}

// length reads the "x:N:" header and returns N, leaving p.i after the colon.
func (p *phpParser) length() (int, bool) {
	if p.i+1 >= len(p.s) || p.s[p.i+1] != ':' {
		return 0, false
	}
	p.i += 2
	return p.number(':')
}

// number reads digits up to the terminator and skips the terminator.
func (p *phpParser) number(term byte) (int, bool) {
	end := strings.IndexByte(p.s[p.i:], term)
	if end <= 0 || end > 10 {
		return 0, false
	}
	n, err := strconv.Atoi(p.s[p.i : p.i+end])
	if err != nil || n < 0 {
		return 0, false
	}
	p.i += end + 1
	return n, true
}

func (p *phpParser) expect(c byte) bool {
	if p.i < len(p.s) && p.s[p.i] == c {
		p.i++
		return true
	}
	return false
}
