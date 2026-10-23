package detect

import (
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Span is one match inside a value, by its byte offsets in the string
// given. A match found through an escape, such as JSON's \n or \u00e9, or
// the %40 of a URL, covers the whole escape. Callers must never print the
// text a span covers.
type Span struct {
	Start, End int
	Kind       string // one of the Span* kinds, or a caller's own
	// Detail says more: a secret's or a password hash's kind, "strict" or
	// "loose" for a phone number, "test" for a published test card number,
	// "reserved" for an email address at a domain reserved for examples, and
	// "placeholder" for a password in a URL that reads as an example.
	Detail string
	Mode   string // for secrets: live, test or "" when the format does not say
}

// The kinds of the built-in spans.
const (
	SpanSecret       = "secret"
	SpanURLPassword  = "url_password"
	SpanPasswordHash = "password_hash"
	SpanEmail        = "email"
	SpanIBAN         = "iban"
	SpanCard         = "card"
	SpanIP           = "ip"
	SpanPhone        = "phone"
	// SpanLoosePhone is the kind of the finder of loose phone numbers, whose
	// spans are of kind SpanPhone with Detail "loose".
	SpanLoosePhone = "loose_phone"
)

// SpanFinder finds the spans of one kind in a value.
type SpanFinder struct {
	Kind string
	// Find finds spans in a value.
	Find func(s string) []Span
	// FindView, when set, finds spans in the value's TextView, by offsets of
	// its Text. FindSpans prefers it, and builds the view once for every
	// finder that has one. A copy of a built-in finder that is given a Find
	// of its own must have its FindView set to nil, or wrapped too, as Keep
	// wraps both.
	FindView func(v *TextView) []Span
}

// Keep returns the finder with only the spans keep accepts, whichever of
// Find and FindView FindSpans calls. keep gets the text the finder read,
// the value or its view's Text, and the span by offsets of that text.
func (f SpanFinder) Keep(keep func(text string, sp Span) bool) SpanFinder {
	filter := func(text string, spans []Span) []Span {
		out := spans[:0:0]
		for _, sp := range spans {
			if keep(text, sp) {
				out = append(out, sp)
			}
		}
		return out
	}
	if find := f.Find; find != nil {
		f.Find = func(s string) []Span { return filter(s, find(s)) }
	}
	if view := f.FindView; view != nil {
		f.FindView = func(v *TextView) []Span { return filter(v.Text, view(v)) }
	}
	return f
}

func viewFinder(kind string, fn func(v *TextView) []Span) SpanFinder {
	return SpanFinder{Kind: kind, FindView: fn, Find: func(s string) []Span {
		v := NewTextView(s)
		return v.spans(fn(v))
	}}
}

// SpanFinders returns the built-in finders in priority order: secrets,
// passwords in URLs and password hashes; then email addresses, IBANs, card
// numbers, IP addresses and phone numbers whose layout says phone; and last
// loose phone numbers, so that a caller can filter them in their finder
// without their spans hiding others. They use the scan's own patterns and
// checks, but report every match, where the scan stops counting at 8 per
// pattern.
func SpanFinders() []SpanFinder {
	return []SpanFinder{
		viewFinder(SpanSecret, findSecretSpans),
		viewFinder(SpanURLPassword, findURLPasswordSpans),
		viewFinder(SpanPasswordHash, findHashSpans),
		viewFinder(SpanEmail, findEmailSpans),
		viewFinder(SpanIBAN, findIBANSpans),
		viewFinder(SpanCard, findCardSpans),
		viewFinder(SpanIP, findIPSpans),
		viewFinder(SpanPhone, findPhoneSpans),
		viewFinder(SpanLoosePhone, findLoosePhoneSpans),
	}
}

// FindSpans runs the finders on s and returns their spans sorted by Start,
// no two overlapping: where spans overlap, the earlier finder's wins, then
// the longer one. Spans outside s, or empty, are dropped.
//
// The result is final. A caller that keeps only some of a finder's spans,
// such as loose phone numbers that match a known number, must filter them
// inside that finder, with SpanFinder.Keep, so the spans it would drop never
// hide another finder's.
func FindSpans(s string, finders []SpanFinder) []Span {
	type ranked struct {
		Span
		finder int
	}
	var (
		all []ranked
		v   *TextView
	)
	for i, f := range finders {
		var spans []Span
		switch {
		case f.FindView != nil:
			if v == nil {
				v = NewTextView(s)
			}
			spans = v.spans(f.FindView(v))
		case f.Find != nil:
			spans = f.Find(s)
		}
		for _, sp := range spans {
			if sp.Start >= 0 && sp.End <= len(s) && sp.Start < sp.End {
				all = append(all, ranked{sp, i})
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.finder != b.finder {
			return a.finder < b.finder
		}
		if la, lb := a.End-a.Start, b.End-b.Start; la != lb {
			return la > lb
		}
		return a.Start < b.Start
	})
	// Each span covers a run of the elementary intervals between the
	// spans' ends; a bit per interval says whether a span took it.
	coords := make([]int, 0, 2*len(all))
	for _, r := range all {
		coords = append(coords, r.Start, r.End)
	}
	slices.Sort(coords)
	coords = slices.Compact(coords)
	var taken bitRange
	taken.words = make([]uint64, (len(coords)+63)/64)
	var out []Span
	for _, r := range all {
		a, _ := slices.BinarySearch(coords, r.Start)
		b, _ := slices.BinarySearch(coords, r.End)
		if !taken.any(a, b) {
			taken.set(a, b)
			out = append(out, r.Span)
		}
	}
	slices.SortFunc(out, func(x, y Span) int { return x.Start - y.Start })
	return out
}

// bitRange is a set of bits, read and written by ranges [a, b).
type bitRange struct{ words []uint64 }

// rangeMask returns the bits of word w that fall in [a, b).
func rangeMask(w, a, b int) uint64 {
	lo, hi := max(a-w*64, 0), min(b-w*64, 64)
	if lo >= hi {
		return 0
	}
	m := ^uint64(0) << lo
	if hi < 64 {
		m &= (uint64(1) << hi) - 1
	}
	return m
}

func (r *bitRange) any(a, b int) bool {
	for w := a / 64; w*64 < b; w++ {
		if r.words[w]&rangeMask(w, a, b) != 0 {
			return true
		}
	}
	return false
}

func (r *bitRange) set(a, b int) {
	for w := a / 64; w*64 < b; w++ {
		r.words[w] |= rangeMask(w, a, b)
	}
}

// spanAt looks for a span overlapping [start, end) in spans, which are
// sorted and apart. It returns where such a span would be inserted.
func spanAt(spans []Span, start, end int) (int, bool) {
	k := sort.Search(len(spans), func(i int) bool { return spans[i].End > start })
	return k, k < len(spans) && spans[k].Start < end
}

// TextView is a value with its escapes read as what they stand for, so
// finders see text as an application would: JSON's \" \\ \/ \b \f \n \r \t
// and \uXXXX, surrogate pairs included, and %40 as @. A backslash that
// starts no such escape is itself. Span maps a span of Text back to the
// value, widened to whole escapes.
type TextView struct {
	// Text is the value's text, as finders read it. Like the value, it
	// holds the data: never print it.
	Text string
	esc  []escape // sorted
}

// escape is one escape: where it is in Text and in the value, how long it
// is in each, and the sum of the lengths escapes add up to it.
type escape struct{ v, o, vn, on, shift int }

// NewTextView reads a value's escapes.
func NewTextView(s string) *TextView {
	if strings.IndexByte(s, '\\') < 0 && !strings.Contains(s, "%40") {
		return &TextView{Text: s}
	}
	v := &TextView{}
	var b strings.Builder
	b.Grow(len(s))
	shift := 0
	add := func(o, on int, dec string) {
		shift += on - len(dec)
		v.esc = append(v.esc, escape{v: b.Len(), o: o, vn: len(dec), on: on, shift: shift})
		b.WriteString(dec)
	}
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '\\':
			if n, dec, ok := jsonUnit(s, i); ok && n > 1 {
				add(i, n, dec)
				i += n
				continue
			}
		case c == '%' && strings.HasPrefix(s[i:], "%40"):
			add(i, 3, "@")
			i += 3
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	v.Text = b.String()
	return v
}

// orig maps an offset of Text to the value. An offset inside what an
// escape stands for maps to the escape's start, or, for an end, its end.
func (v *TextView) orig(i int, end bool) int {
	k := sort.Search(len(v.esc), func(j int) bool { return v.esc[j].v+v.esc[j].vn > i })
	if k < len(v.esc) && v.esc[k].v < i {
		e := v.esc[k]
		if end {
			return e.o + e.on
		}
		return e.o
	}
	if k > 0 {
		return i + v.esc[k-1].shift
	}
	return i
}

// Span maps a span of Text to the value.
func (v *TextView) Span(sp Span) Span {
	sp.Start, sp.End = v.orig(sp.Start, false), v.orig(sp.End, true)
	return sp
}

func (v *TextView) spans(spans []Span) []Span {
	if len(v.esc) == 0 {
		return spans
	}
	for i := range spans {
		spans[i] = v.Span(spans[i])
	}
	return spans
}

const urlPasswordKind = "password in a URL"

// urlPasswordPattern is the scan's pattern for user:password@ in URLs,
// which reports its password part as a span of its own kind.
var urlPasswordPattern = func() *secretPattern {
	for i := range secretPatterns {
		if secretPatterns[i].kind == urlPasswordKind {
			return &secretPatterns[i]
		}
	}
	panic("no pattern for passwords in URLs")
}()

// secretMatch is one secret found in the text of a value.
type secretMatch struct {
	start, end int
	pattern    int // its index in secretPatterns
	mode       string
}

// secretMatches finds every secret in text as FindSecrets would, without
// its cap of 8 matches per pattern, and resolves the patterns that unless
// skips span by span: overlapping matches are merged later. A fallback
// match is dropped when it overlaps a token already found, as in the scan.
func secretMatches(text string) []secretMatch {
	found := hints.scan(text)
	if found.empty() && len(text) < 50 && !strings.Contains(text, "://") && !bearerValue(text) && !basicValue(text) {
		return nil
	}
	var (
		out     []secretMatch
		taken   []Span // the matches so far, merged, once fallbacks start
		started bool
	)
	for i := range secretPatterns {
		p := &secretPatterns[i]
		if p.kind == urlPasswordKind || len(p.hints) > 0 && !found.meets(&patternHints[i]) || p.pre != nil && !p.pre(text) {
			continue
		}
		if p.fallback && !started {
			taken = mergeSecrets(out)
			started = true
		}
		for _, loc := range p.re.FindAllStringSubmatchIndex(text, -1) {
			if loc[0] > 0 && !p.before.ok(text[loc[0]-1]) || loc[1] < len(text) && !p.after.ok(text[loc[1]]) {
				continue
			}
			m := submatches(text, loc)
			if p.valid != nil && !p.valid(text, m) {
				continue
			}
			start, end := loc[2*p.group], loc[2*p.group+1]
			if start < 0 || start >= end {
				continue
			}
			if p.fallback {
				k, hit := spanAt(taken, start, end)
				if hit {
					continue
				}
				taken = slices.Insert(taken, k, Span{Start: start, End: end})
			}
			out = append(out, secretMatch{start, end, i, p.mode(m)})
		}
	}
	return out
}

// mergeSecrets merges overlapping matches into one span each, named after
// the earliest pattern among them, so a secret is cleared whole whichever
// patterns read it.
func mergeSecrets(ms []secretMatch) []Span {
	ms = slices.Clone(ms)
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].start < ms[j].start })
	var out []Span
	first := -1 // the pattern that names the last span
	for _, m := range ms {
		if n := len(out); n > 0 && m.start < out[n-1].End {
			out[n-1].End = max(out[n-1].End, m.end)
			if m.pattern < first {
				first = m.pattern
				out[n-1].Detail, out[n-1].Mode = secretPatterns[m.pattern].kind, m.mode
			}
			continue
		}
		first = m.pattern
		out = append(out, Span{Start: m.start, End: m.end, Kind: SpanSecret, Detail: secretPatterns[m.pattern].kind, Mode: m.mode})
	}
	return out
}

// findSecretSpans finds secrets in the scan's formats, and passwords in
// Basic Authorization headers.
func findSecretSpans(v *TextView) []Span {
	if len(v.Text) < 12 {
		return nil
	}
	return mergeSecrets(secretMatches(v.Text))
}

// findURLPasswordSpans finds the password of every user:password@ in a URL,
// placeholders, a password equal to its user and example hosts included,
// which the scan doesn't count but a copy should clear all the same.
func findURLPasswordSpans(v *TextView) []Span {
	p := urlPasswordPattern
	if len(v.Text) < 9 || !p.pre(v.Text) {
		return nil
	}
	var out []Span
	for _, loc := range p.re.FindAllStringSubmatchIndex(v.Text, -1) {
		detail := ""
		if !p.valid(v.Text, submatches(v.Text, loc)) {
			detail = "placeholder"
		}
		out = append(out, Span{Start: loc[4], End: loc[5], Kind: SpanURLPassword, Detail: detail, Mode: "live"})
	}
	return out
}

// hashFinders are the scan's password hash formats, found inside text.
var hashFinders = func() []hashFormat {
	out := make([]hashFormat, len(hashFormats))
	for i, f := range hashFormats {
		expr := strings.TrimSuffix(strings.TrimPrefix(f.re.String(), "^"), "$")
		out[i] = hashFormat{f.name, regexp.MustCompile(expr)}
	}
	return out
}()

// The bytes that can't come before or after a hash: its alphabet, and the
// padding of base64 tails.
var (
	setHashBefore = charSet("A-Za-z0-9./$")
	setHashAfter  = charSet("A-Za-z0-9./$+=")
)

func findHashSpans(v *TextView) []Span {
	s := v.Text
	if !strings.ContainsAny(s, "$:") {
		return nil
	}
	var out []Span
	for _, f := range hashFinders {
		for _, loc := range f.re.FindAllStringIndex(s, -1) {
			a, b := loc[0], loc[1]
			if b-a < 30 || b-a > 512 || a > 0 && setHashBefore[s[a-1]] || b < len(s) && setHashAfter[s[b]] {
				continue
			}
			out = append(out, Span{Start: a, End: b, Kind: SpanPasswordHash, Detail: f.name})
		}
	}
	return out
}

// localRune reports whether r may be part of an email address's local part:
// the scan's pattern takes ASCII letters, digits and ._%+-, and an address
// may have letters of any script too.
func localRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) || strings.ContainsRune("._%+-", r)
}

// findEmailSpans finds email addresses, written plainly or with the @
// percent-encoded as in URLs, except image names such as logo@2x.png. A
// local part with letters past ASCII, as in müller@, is taken whole.
func findEmailSpans(v *TextView) []Span {
	s := v.Text
	if strings.IndexByte(s, '@') < 0 {
		return nil
	}
	var out []Span
	for _, m := range reEmailIn.FindAllStringSubmatchIndex(s, -1) {
		if notTLD[strings.ToLower(s[m[2]:m[3]])] {
			continue
		}
		start := m[0]
		for start > 0 {
			r, n := utf8.DecodeLastRuneInString(s[:start])
			if !localRune(r) {
				break
			}
			start -= n
		}
		detail := ""
		if reservedEmail(s[m[0]:m[1]]) {
			detail = "reserved"
		}
		out = append(out, Span{Start: start, End: m[1], Kind: SpanEmail, Detail: detail})
	}
	return out
}

// ibanLengths holds the IBAN length of the countries whose length is
// fixed and well known. Other country codes take any length from 15 to 34.
var ibanLengths = map[string]int{
	"AD": 24, "AT": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "EE": 20,
	"ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IS": 26, "IT": 27,
	"LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25,
	"RO": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TR": 26,
}

func isLetterASCII(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
func isDigitASCII(c byte) bool  { return c >= '0' && c <= '9' }
func isAlnumASCII(c byte) bool  { return isLetterASCII(c) || isDigitASCII(c) }

// isWordByte reports whether c can be part of a word, as \b reads it.
func isWordByte(c byte) bool { return setWord[c] }

// findIBANSpans finds IBANs, in any letter case, written with or without
// spaces between groups, whose checksum is right.
func findIBANSpans(v *TextView) []Span {
	s := v.Text
	var out []Span
	for i := 0; i+15 <= len(s); i++ {
		if !isLetterASCII(s[i]) || !isLetterASCII(s[i+1]) || !isDigitASCII(s[i+2]) || !isDigitASCII(s[i+3]) ||
			i > 0 && isWordByte(s[i-1]) {
			continue
		}
		// The ends of runs of letters and digits, with single spaces
		// between them, up to 34 characters.
		var ends []int
		n, j := 0, i
		for j < len(s) && n < 34 {
			c := s[j]
			if isAlnumASCII(c) {
				n++
				j++
				continue
			}
			if c == ' ' && j+1 < len(s) && isAlnumASCII(s[j+1]) {
				ends = append(ends, j)
				j++
				continue
			}
			break
		}
		ends = append(ends, j)
		for k := len(ends) - 1; k >= 0; k-- {
			end := ends[k]
			if end < len(s) && isWordByte(s[end]) {
				continue
			}
			compact := strings.ToUpper(strings.ReplaceAll(s[i:end], " ", ""))
			if l, ok := ibanLengths[compact[:2]]; ok && len(compact) != l || !isIBAN(compact) {
				continue
			}
			out = append(out, Span{Start: i, End: end, Kind: SpanIBAN})
			i = end - 1
			break
		}
	}
	return out
}

// digitRuns calls fn for each run of digit groups in s: digits joined by
// separators of up to maxSep bytes from seps. Groups are byte ranges; sums
// holds, for each group, the digits of the groups before it.
func digitRuns(s, seps string, maxSep int, fn func(groups [][2]int, sums []int)) {
	var (
		groups [][2]int
		sums   []int
	)
	for i := 0; i < len(s); {
		if !isDigitASCII(s[i]) {
			i++
			continue
		}
		groups, sums = groups[:0], sums[:0]
		total := 0
		for {
			j := i
			for j < len(s) && isDigitASCII(s[j]) {
				j++
			}
			groups = append(groups, [2]int{i, j})
			sums = append(sums, total)
			total += j - i
			k := j
			for k < len(s) && k-j < maxSep && strings.IndexByte(seps, s[k]) >= 0 {
				k++
			}
			if k > j && k < len(s) && isDigitASCII(s[k]) {
				i = k
				continue
			}
			i = j
			break
		}
		sums = append(sums, total)
		fn(groups, sums)
	}
}

// pickRuns takes, from the left, the longest ranges of consecutive groups
// that hold min to max digits and that ok accepts. A range may start after
// group k, or end with it, only where split(k) allows; start says whether
// a range may start at group gi at all, before any range is tried there.
func pickRuns(groups [][2]int, sums []int, min, max int, split func(k int) bool, start func(gi int) bool,
	ok func(gi, gj int) bool) {
	for gi := 0; gi < len(groups); gi++ {
		if gi > 0 && !split(gi-1) || !start(gi) {
			continue
		}
		last := gi
		for gj := gi; gj < len(groups) && sums[gj+1]-sums[gi] <= max; gj++ {
			last = gj
		}
		for gj := last; gj >= gi; gj-- {
			if gj < len(groups)-1 && !split(gj) {
				continue
			}
			if d := sums[gj+1] - sums[gi]; d >= min && d <= max && ok(gi, gj) {
				gi = gj
				break
			}
		}
	}
}

func anywhere(int) bool { return true }

// findCardSpans finds payment card numbers: 13 to 19 digits, spaces or
// dashes allowed, with a valid checksum and a known network's prefix.
// Digits written next to a card number, such as its security code, don't
// hide it.
func findCardSpans(v *TextView) []Span {
	s := v.Text
	var out []Span
	digitRuns(s, " -", 1, func(groups [][2]int, sums []int) {
		// A known network's prefix, read from a group's first digits.
		network := func(gi int) bool {
			var d []byte
			for g := gi; g < len(groups) && len(d) < 4; g++ {
				d = append(d, s[groups[g][0]:groups[g][1]]...)
			}
			for len(d) < 4 {
				d = append(d, '0')
			}
			return cardPrefix(d)
		}
		pickRuns(groups, sums, 13, 19, anywhere, network, func(gi, gj int) bool {
			a, b := groups[gi][0], groups[gj][1]
			if a > 0 && isWordByte(s[a-1]) || b < len(s) && isWordByte(s[b]) {
				return false
			}
			ok, test := cardNumber(s[a:b])
			if !ok {
				return false
			}
			detail := ""
			if test {
				detail = "test"
			}
			out = append(out, Span{Start: a, End: b, Kind: SpanCard, Detail: detail})
			return true
		})
	})
	return out
}

// cardPrefix reports whether a number's first four digits are a known
// card network's, whatever its length.
func cardPrefix(d []byte) bool {
	p1, p2, p3, p4 := prefixNum(d, 1), prefixNum(d, 2), prefixNum(d, 3), prefixNum(d, 4)
	return p1 == 4 || p2 >= 51 && p2 <= 55 || p4 >= 2221 && p4 <= 2720 || p2 == 34 || p2 == 37 ||
		p4 == 6011 || p3 >= 644 && p3 <= 649 || p2 == 65 || p4 >= 3528 && p4 <= 3589 ||
		p3 >= 300 && p3 <= 305 || p2 == 36 || p2 == 38 || p2 == 39 || p2 == 62
}

// findIPSpans finds IPv4 and IPv6 addresses, except loopback and
// unspecified addresses and version numbers such as 1.8.5.4.
func findIPSpans(v *TextView) []Span {
	s := v.Text
	var out []Span
	for _, loc := range reIPv4In.FindAllStringIndex(s, -1) {
		a, b := loc[0], loc[1]
		if a >= 2 && s[a-1] == '.' && isDigitASCII(s[a-2]) || b+1 < len(s) && s[b] == '.' && isDigitASCII(s[b+1]) {
			continue
		}
		if ip, err := netip.ParseAddr(s[a:b]); err == nil && !ip.IsLoopback() && !ip.IsUnspecified() && !versionQuad(s[a:b]) {
			out = append(out, Span{Start: a, End: b, Kind: SpanIP})
		}
	}
	if strings.Count(s, ":") < 2 {
		return out
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) || i > 0 && (isWordByte(s[i-1]) || s[i-1] == ':' || s[i-1] == '.') {
			continue
		}
		j := i
		for j < len(s) && (isHexByte(s[j]) || s[j] == ':' || s[j] == '.') {
			j++
		}
		end := j
		for end > i && s[end-1] == '.' {
			end--
		}
		if (j == len(s) || !isWordByte(s[j])) && strings.Count(s[i:end], ":") >= 2 {
			if ip, err := netip.ParseAddr(s[i:end]); err == nil && ip.Is6() && !ip.IsLoopback() && !ip.IsUnspecified() {
				out = append(out, Span{Start: i, End: end, Kind: SpanIP})
			}
		}
		i = j
	}
	return out
}

func isHexByte(c byte) bool { return isDigitASCII(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// rePhoneAt is rePhoneIn anchored, for a window of phoneWindow bytes, which
// holds its longest match.
var rePhoneAt = regexp.MustCompile(`^(?:` + rePhoneIn.String() + `)`)

const phoneWindow = 48

// findPhoneSpans finds phone numbers whose layout says phone: a country
// code, or an area code in parentheses.
func findPhoneSpans(v *TextView) []Span {
	s := v.Text
	var out []Span
	// rePhoneIn's matches start with + or ( and are short, so it runs on a
	// window at each of those: over a whole large value it would be slow.
	for i := 0; i < len(s); i++ {
		if s[i] != '+' && s[i] != '(' {
			continue
		}
		loc := rePhoneAt.FindStringIndex(s[i:min(i+phoneWindow, len(s))])
		if loc == nil {
			continue
		}
		a, b := i, i+loc[1]
		if a > 0 && isDigitASCII(s[a-1]) || b < len(s) && isDigitASCII(s[b]) {
			continue
		}
		if ok, strict := phoneShape(s[a:b]); ok && strict && !isbn13(s[a:b]) {
			out = append(out, Span{Start: a, End: b, Kind: SpanPhone, Detail: "strict"})
		}
		i = b - 1
	}
	return out
}

// findLoosePhoneSpans finds runs of 7 to 15 digits with separators that may
// be phone numbers in a domestic layout, such as 07700 900123, which only a
// caller that knows the numbers to look for should act on. A run may start
// and end only at a space, since digits joined without one, as in
// 2024-01-02, are one token.
func findLoosePhoneSpans(v *TextView) []Span {
	s := v.Text
	var out []Span
	digitRuns(s, " .-/()", 2, func(groups [][2]int, sums []int) {
		split := func(k int) bool { return strings.IndexByte(s[groups[k][1]:groups[k+1][0]], ' ') >= 0 }
		pickRuns(groups, sums, 7, 15, split, anywhere, func(gi, gj int) bool {
			a, b := groups[gi][0], groups[gj][1]
			if a > 0 && (s[a-1] == '+' || s[a-1] == '(') {
				a--
			}
			if b < len(s) && s[b] == ')' {
				b++
			}
			if a > 0 && isWordByte(s[a-1]) || b < len(s) && isWordByte(s[b]) || !loosePhone(s[a:b]) {
				return false
			}
			out = append(out, Span{Start: a, End: b, Kind: SpanPhone, Detail: "loose"})
			return true
		})
	})
	return out
}

// loosePhone reports whether a run of digits and separators may be a phone
// number rather than a date, an IP address, a number with thousands
// separators, an ISBN or a card number.
func loosePhone(t string) bool {
	if ok, _ := phoneShape(t); !ok || isbn13(t) {
		return false
	}
	if ok, _ := cardNumber(t); ok {
		return false
	}
	first, _, _ := strings.Cut(t, " ")
	return !reDate.MatchString(first)
}

// isbn13 reports whether the digits of t are an ISBN-13.
func isbn13(t string) bool {
	var d []byte
	for i := 0; i < len(t); i++ {
		if isDigitASCII(t[i]) {
			d = append(d, t[i])
		}
	}
	if len(d) != 13 || d[0] != '9' || d[1] != '7' || (d[2] != '8' && d[2] != '9') {
		return false
	}
	sum := 0
	for i, c := range d {
		w := 1
		if i%2 == 1 {
			w = 3
		}
		sum += int(c-'0') * w
	}
	return sum%10 == 0
}
