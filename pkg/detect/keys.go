package detect

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// HiddenKey stands for a key name that can't be shown.
const HiddenKey = "(key hidden)"

// Known prefixes of key names whose rest is personal data whatever its
// shape. Ultimate Member stores each user's email address, with the @
// removed, in a user meta key name.
var dataPrefixes = []struct {
	prefix string
	cat    model.Category
}{
	{"um_email_as_username_", model.CatEmail},
}

// DataPrefixes lists the known prefixes of key names whose rest is data.
func DataPrefixes() []string {
	out := make([]string, len(dataPrefixes))
	for i, dp := range dataPrefixes {
		out[i] = dp.prefix
	}
	return out
}

// TypeString is the type class of text columns and meta keys, for MatchName.
const TypeString = tStr

// What the varying part of a key looked like, weakest first.
type keyKind int

const (
	kindNone   keyKind = iota
	kindNumber         // a run of 4 or more digits
	kindToken          // 16 or more letters and digits
	kindHash           // 8 or more hex digits
	kindUUID
	kindIP
	kindEmail
	kindPrefix // the rest of a key after a known data prefix
)

// KeyTemplate is a key name with the parts that look like data replaced by *.
type KeyTemplate struct {
	Pattern string // e.g. um_cache_userdata_* or _transient_feed_*
	// Short is Pattern with runs of 1 to 3 digits replaced too. Those
	// become * only when several keys share the result.
	Short   string
	Carries model.Category // email or IP address when the varying part is one
	kind    keyKind
}

var (
	reKeyUUID = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	// IPv4 addresses with dots, or with underscores or hyphens as in
	// ip_192_0_2_10. No \b: in key names an address often follows an
	// underscore, which \b counts as part of a word. Boundaries are
	// checked by hand.
	reKeyIPv4 = map[byte]*regexp.Regexp{'.': ipv4Pattern("."), '_': ipv4Pattern("_"), '-': ipv4Pattern("-")}
	reKeyIPv6 = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	reVersion = regexp.MustCompile(`(?i)(?:^|[^a-z])(?:v|ver|version)[_\-. ]*$`)
	reAlnum   = regexp.MustCompile(`[A-Za-z0-9]+`)
	reHexRun  = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	reHexIn   = regexp.MustCompile(`[0-9a-fA-F]{8,}`)
	reDigits  = regexp.MustCompile(`[0-9]+`)
)

func ipv4Pattern(sep string) *regexp.Regexp {
	const octet = `(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`
	return regexp.MustCompile(octet + `(?:` + regexp.QuoteMeta(sep) + octet + `){3}`)
}

// versionQuad reports whether every part of a dotted quad is one digit,
// as in 1.8.5.4: a version number, not the address of a visitor.
func versionQuad(ip string) bool {
	for _, part := range strings.Split(ip, ".") {
		if len(part) != 1 {
			return false
		}
	}
	return true
}

// Template replaces the parts of a key that look like data: email and IP
// addresses, UUIDs, runs of 4 or more digits, hex hashes of 8 or more
// characters, long tokens, and whatever follows a known data prefix.
func Template(key string) KeyTemplate {
	for _, dp := range dataPrefixes {
		if strings.HasPrefix(key, dp.prefix) && len(key) > len(dp.prefix) {
			p := dp.prefix + "*"
			return KeyTemplate{Pattern: p, Short: p, Carries: dp.cat, kind: kindPrefix}
		}
	}
	kind := kindNone
	carries := model.Category("")
	mark := func(k keyKind) {
		if k > kind {
			kind = k
		}
	}
	s := key
	s = replaceAll(s, reEmailIn, func(m string) bool {
		if notTLD[strings.ToLower(m[strings.LastIndexByte(m, '.')+1:])] {
			return false
		}
		mark(kindEmail)
		carries = model.CatEmail
		return true
	})
	s = replaceIPv4(s, func() {
		mark(kindIP)
		if carries == "" {
			carries = model.CatIPAddress
		}
	})
	s = replaceIPv6(s, func() {
		mark(kindIP)
		if carries == "" {
			carries = model.CatIPAddress
		}
	})
	s = replaceAll(s, reKeyUUID, func(string) bool { mark(kindUUID); return true })

	var pat, short strings.Builder
	last := 0
	for _, loc := range reAlnum.FindAllStringIndex(s, -1) {
		pat.WriteString(s[last:loc[0]])
		short.WriteString(s[last:loc[0]])
		last = loc[1]
		run := s[loc[0]:loc[1]]
		switch {
		case reHexRun.MatchString(run) && strings.ContainsAny(run, "0123456789") && strings.ContainsAny(run, "abcdefABCDEF"):
			mark(kindHash)
			pat.WriteString("*")
			short.WriteString("*")
		case len(run) >= 16 && countDigits(run) >= 2 && len(run)-countDigits(run) >= 2:
			mark(kindToken)
			pat.WriteString("*")
			short.WriteString("*")
		default:
			// A hash glued to a word: user3f9a2b7c.
			run = reHexIn.ReplaceAllStringFunc(run, func(h string) string {
				if strings.ContainsAny(h, "0123456789") && strings.ContainsAny(h, "abcdefABCDEF") {
					mark(kindHash)
					return "*"
				}
				return h
			})
			// Digit runs inside the word: user12345 has a 5-digit ID.
			at := 0
			for _, d := range reDigits.FindAllStringIndex(run, -1) {
				pat.WriteString(run[at:d[0]])
				short.WriteString(run[at:d[0]])
				at = d[1]
				if d[1]-d[0] >= 4 {
					mark(kindNumber)
					pat.WriteString("*")
				} else {
					pat.WriteString(run[d[0]:d[1]])
				}
				short.WriteString("*")
			}
			pat.WriteString(run[at:])
			short.WriteString(run[at:])
		}
	}
	pat.WriteString(s[last:])
	short.WriteString(s[last:])
	return KeyTemplate{Pattern: pat.String(), Short: short.String(), Carries: carries, kind: kind}
}

// replaceAll replaces the matches that keep says are data with *.
func replaceAll(s string, re *regexp.Regexp, keep func(m string) bool) string {
	return re.ReplaceAllStringFunc(s, func(m string) string {
		if keep(m) {
			return "*"
		}
		return m
	})
}

// replaceIPv4 replaces IPv4 addresses written with dots, underscores or
// hyphens, except version numbers such as v1.2.3.4 or 1.8.5.4 and runs of
// numbers that go on (1.2.3.4.5).
func replaceIPv4(s string, found func()) string {
	for _, sep := range []byte{'.', '_', '-'} {
		s = replaceIPv4Sep(s, sep, found)
	}
	return s
}

func replaceIPv4Sep(s string, sep byte, found func()) string {
	var b strings.Builder
	last := 0
	for _, loc := range reKeyIPv4[sep].FindAllStringIndex(s, -1) {
		ip := strings.ReplaceAll(s[loc[0]:loc[1]], string(sep), ".")
		before, after := s[:loc[0]], s[loc[1]:]
		if _, err := netip.ParseAddr(ip); err != nil || versionQuad(ip) || reVersion.MatchString(before) ||
			goesOn(before, after, sep) {
			continue
		}
		found()
		b.WriteString(s[last:loc[0]])
		b.WriteString("*")
		last = loc[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// goesOn reports whether the numbers around a quad go on, so it is part
// of a longer run rather than an address. A dot before a dotted quad
// counts too; an underscore or hyphen before one only with a digit
// before it, since ip_192_0_2_10 is the usual shape.
func goesOn(before, after string, sep byte) bool {
	const digits = "0123456789"
	if endsWith(before, digits) || startsWith(after, digits) ||
		(len(after) > 1 && after[0] == sep && startsWith(after[1:], digits)) {
		return true
	}
	if sep == '.' {
		return endsWith(before, ".")
	}
	return len(before) > 1 && before[len(before)-1] == sep && endsWith(before[:len(before)-1], digits)
}

// replaceIPv6 replaces IPv6 addresses that stand apart from the letters
// and digits around them, so App::cache::key keeps its :: separators.
func replaceIPv6(s string, found func()) string {
	const word = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:"
	var b strings.Builder
	last := 0
	for _, loc := range reKeyIPv6.FindAllStringIndex(s, -1) {
		m := s[loc[0]:loc[1]]
		groups := 0
		for _, g := range strings.Split(m, ":") {
			if g != "" {
				groups++
			}
		}
		if groups < 2 || endsWith(s[:loc[0]], word) || startsWith(s[loc[1]:], word) {
			continue
		}
		if _, err := netip.ParseAddr(m); err != nil {
			continue
		}
		found()
		b.WriteString(s[last:loc[0]])
		b.WriteString("*")
		last = loc[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

func endsWith(s, chars string) bool   { return s != "" && strings.IndexByte(chars, s[len(s)-1]) >= 0 }
func startsWith(s, chars string) bool { return s != "" && strings.IndexByte(chars, s[0]) >= 0 }

func countDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}

func countLetters(s string) int {
	n := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			n++
		}
	}
	return n
}

// Key names that reports may show: they must look like labels.
var reShownKey = regexp.MustCompile(`^[A-Za-z0-9_.:/ *-]{1,64}$`)

// ShowKey is how a stored key name may appear in reports, warnings and
// configs: with the parts that look like data replaced by *, or as
// HiddenKey when even that could carry data.
func ShowKey(key string) string {
	if strings.Contains(key, "*") {
		return HiddenKey // a stored * would read as a pattern
	}
	return ShowPattern(Template(key).Pattern)
}

// ShowPattern checks a key or pattern for display. A pattern needs three
// literal letters, so * or *_* never stands for a whole key.
func ShowPattern(p string) string {
	if !reShownKey.MatchString(p) || (strings.Contains(p, "*") && countLetters(p) < 3) {
		return HiddenKey
	}
	return p
}

// FamilyRule is what a preset knows about keys that share a prefix.
type FamilyRule struct {
	Prefix  string
	Carries model.Category // what the rest of the name holds, if personal
	Hint    *Hint
}

// KeyFamily is a set of keys whose names differ only in a part that looks
// like data, such as a user ID, a hash or an email address.
type KeyFamily struct {
	Pattern string
	Keys    []string // sorted
	Carries model.Category
	Hint    *Hint // from a preset rule
	known   bool  // the varying part is data by a preset rule or a known prefix
	matched int   // keys whose varying part looked like the carried category
}

// Known reports whether the family comes from a preset rule or a known
// data prefix rather than from the shape of its keys.
func (f *KeyFamily) Known() bool { return f.known }

// minShortFamily is how many keys must share a template before runs of
// 1 to 3 digits count as varying: _billing_address_1 and _2 stay apart.
const minShortFamily = 5

// GroupKeys splits keys into single keys and families. rules come from
// presets; exact reports keys a preset knows by name, which stay single.
func GroupKeys(keys []string, rules []FamilyRule, exact func(string) bool) (singles []string, families []KeyFamily) {
	rules = append([]FamilyRule(nil), rules...)
	sort.SliceStable(rules, func(i, j int) bool { return len(rules[i].Prefix) > len(rules[j].Prefix) })

	byPattern := map[string]*KeyFamily{}
	add := func(pattern, key string, carries model.Category, hint *Hint, known bool, matched bool) {
		f := byPattern[pattern]
		if f == nil {
			f = &KeyFamily{Pattern: pattern, Hint: hint, known: known}
			byPattern[pattern] = f
		}
		f.Keys = append(f.Keys, key)
		if carries != "" {
			if f.Carries == "" || (f.Carries == model.CatIPAddress && carries == model.CatEmail) {
				f.Carries = carries
			}
			if matched {
				f.matched++
			}
		}
	}
	short := map[string][]string{}
	for _, k := range keys {
		// A stored * would read as part of the pattern, so such keys
		// stay single (and hidden).
		if (exact != nil && exact(k)) || strings.Contains(k, "*") {
			singles = append(singles, k)
			continue
		}
		ruled := false
		for _, r := range rules {
			if strings.HasPrefix(k, r.Prefix) && len(k) > len(r.Prefix) {
				add(r.Prefix+"*", k, r.Carries, r.Hint, true, r.Carries != "")
				ruled = true
				break
			}
		}
		if ruled {
			continue
		}
		t := Template(k)
		switch {
		case t.kind != kindNone:
			add(t.Pattern, k, t.Carries, nil, t.kind == kindPrefix, t.Carries != "")
		case t.Short != k:
			short[t.Short] = append(short[t.Short], k)
		default:
			singles = append(singles, k)
		}
	}
	for p, ks := range short {
		if len(ks) >= minShortFamily && countLetters(p) >= 3 {
			for _, k := range ks {
				add(p, k, "", nil, false, false)
			}
			continue
		}
		singles = append(singles, ks...)
	}
	sort.Strings(singles)
	for _, f := range byPattern {
		sort.Strings(f.Keys)
		families = append(families, *f)
	}
	sort.Slice(families, func(i, j int) bool { return families[i].Pattern < families[j].Pattern })
	return singles, families
}

// KeyNameFinding reports that the names of a family's keys hold personal
// data, so a copy has to rewrite the key column as well as the values.
func KeyNameFinding(table, keyColumn, shown string, fam *KeyFamily, partial bool) model.Finding {
	cat := fam.Carries
	n := len(fam.Keys)
	f := model.Finding{
		Table: table, Column: keyColumn, MetaKey: shown, KeyName: true, Keys: n, KeysPartial: partial,
		Category: cat, Severity: cat.Info().Severity, Confidence: model.ConfidenceHigh,
		Sampled: n, Matched: fam.matched, Mask: cat.Info().Mask, Source: "key",
		Note: "the key names hold personal data; a copy must rewrite them too",
	}
	if fam.known {
		f.Reasons = []string{"known key family"}
		f.Matched = n
	} else {
		f.Reasons = []string{fmt.Sprintf("%d of %d key names hold %s in the part matched by *", fam.matched, n, withArticle(cat.Label()))}
	}
	return f
}

func withArticle(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case 'a', 'e', 'i', 'o', 'u', 'I':
		return "an " + s
	}
	return "a " + s
}

// Words that end a key naming a field (Your Name, Emergency contact), and
// short words that say nothing on their own.
var (
	labelWords    = words("name names email phone address line number message contact date time code notes")
	keyStopWords  = words("of for e x no me")
	keyKnownWords = func() map[string]bool {
		m := map[string]bool{}
		for _, set := range []map[string]bool{ruleWords, fieldWords, labelWords} {
			for w := range set {
				m[w] = true
			}
		}
		return m
	}()
)

// KnownWord reports whether a word is one the naming rules, field names or
// labels use, such as billing, phone or name, in any letter case. The
// words are fixed in the scan, so a value never makes one known.
func KnownWord(w string) bool { return keyKnownWords[strings.ToLower(w)] }

// KeyWords is how the key-shape guard of a key/value table found without a
// preset reads a stored key with a space in it.
type KeyWords struct {
	// Label says the key names a field: at most one of its words is
	// unknown, and it ends in a label word or has a lower-case word the
	// rules or field names use. Date of birth and shipping method are
	// labels; Jane Doe phone, John Street and Next of kin aren't.
	Label   bool
	Known   []string // its words the rules, field names and labels use, lower case, in order
	Unknown int      // its other words, numbers aside
}

// ReadKey reads a stored key for the key-shape guard.
func ReadKey(key string) KeyWords {
	var kw KeyWords
	ws := NameWords(key)
	for _, w := range ws {
		switch {
		case isDigits(w):
		case keyKnownWords[w]:
			kw.Known = append(kw.Known, w)
		default:
			kw.Unknown++
		}
	}
	// The last word decides, before a trailing number: Phone 2 is a label.
	last := len(ws) - 1
	for last >= 0 && isDigits(ws[last]) {
		last--
	}
	signal := last >= 0 && labelWords[ws[last]]
	// Rule words count only as written in lower case, so a surname such as
	// Street or Pan doesn't make a person's name a label; nor does a number,
	// as in Jane 2 or jane2.
	for _, raw := range strings.FieldsFunc(key, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if signal || raw != strings.ToLower(raw) || isDigits(raw) {
			continue
		}
		for _, w := range NameWords(raw) {
			if !isDigits(w) && (ruleWords[w] || fieldWords[w]) && !keyStopWords[w] {
				signal = true
			}
		}
	}
	kw.Label = kw.Unknown <= 1 && signal
	return kw
}

// FreeTextKey reports whether a key, as reports would show it, has a space
// and doesn't read as a label. In a key/value table found without a
// preset, such a key may be a person's name, so it isn't shown.
func FreeTextKey(key string) bool {
	return strings.Contains(Template(key).Pattern, " ") && !ReadKey(key).Label
}
