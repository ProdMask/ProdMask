package leak

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
)

// The floors below which a value isn't counted: under them it may be anyone's,
// and with the key and the file it could be guessed.
const (
	minPhoneDigits   = 8
	minPhoneDistinct = 4
	minIDLen         = 8
	minIDDistinct    = 4
	maxIDLen         = 64
	minTokenLen      = 12
	minHashLen       = 16
	minSecretLen     = 16
	minSecretDiff    = 8
	maxWholeLen      = 512

	// basicPasswordKind is the detail of a Basic credential with no key in it.
	basicPasswordKind = "password in a Basic Authorization header"
)

// ErrAllowValue is the error of an --allow-email value that is neither an
// address nor a domain with a dot. It doesn't quote the value.
var ErrAllowValue = errors.New("a value of --allow-email is neither an address nor a domain with a dot")

// Allowlist is what --allow-email keeps out of a check: domains with their
// subdomains, and exact addresses, in lower case. Addresses are real people's:
// they're never written to a file or a report, only counted.
type Allowlist struct {
	Domains   []string
	addresses map[string]bool
}

// NewAllowlist reads --allow-email's values.
func NewAllowlist(values []string) (*Allowlist, error) {
	a := &Allowlist{addresses: map[string]bool{}}
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		switch {
		case strings.Contains(v, "@") && detect.IsEmail(v):
			a.addresses[v] = true
		case !strings.Contains(v, "@") && strings.Contains(v, ".") && detect.IsEmail("x@"+v):
			a.Domains = append(a.Domains, v)
		default:
			return nil, ErrAllowValue
		}
	}
	return a, nil
}

// Addresses is how many exact addresses the list holds.
func (a *Allowlist) Addresses() int { return len(a.addresses) }

// has reports whether the list covers a lower-case address.
func (a *Allowlist) has(addr string) bool {
	if a == nil {
		return false
	}
	if a.addresses[addr] {
		return true
	}
	d := addr[strings.LastIndexByte(addr, '@')+1:]
	for _, dom := range a.Domains {
		if d == dom || strings.HasSuffix(d, "."+dom) {
			return true
		}
	}
	return false
}

// wants says what to look for in one column or key, beyond the kinds the span
// finders find in any flagged column.
type wants struct {
	// loosePhone adds the loose phone finder, for a column whose own finding
	// says phone. In text it would read order numbers as phones.
	loosePhone bool
	// whole lists the kinds a whole value may be: those no span finder finds
	// on its own, in a column flagged as that with no JSON path.
	whole []model.LeakKind
}

// extractor reads values the same way on both sides of a check, so what a
// value yields on production it yields on staging. It's for one goroutine.
//
// It runs every finder, card numbers and IP addresses included, and drops what
// doesn't count afterwards, not inside the finders. So what doesn't count still
// hides what overlaps it: the password in user:pw@host still hides the
// pw@host that would read as an email, and a key too short to count can't come
// back through that door, or as a whole value.
type extractor struct {
	allow       *Allowlist
	base, loose []detect.SpanFinder
	cards       []detect.SpanFinder
	skipped     int64 // addresses the allowlist kept out, in all
}

func newExtractor(allow *Allowlist) *extractor {
	e := &extractor{allow: allow}
	for _, f := range detect.SpanFinders() {
		if f.Kind != detect.SpanLoosePhone {
			e.base = append(e.base, f)
		}
		if f.Kind == detect.SpanCard {
			e.cards = append(e.cards, f)
		}
		e.loose = append(e.loose, f)
	}
	return e
}

// secretCounts reports whether a secret is worth a hash: long enough that a
// holder of the key and the file couldn't guess it, and no card number.
func (e *extractor) secretCounts(secret string) bool {
	return len(secret) >= minSecretLen && len(detect.FindSpans(secret, e.cards)) == 0
}

// basicSecret is the part of a Basic credential's text that is a secret, since
// the span covers the whole encoded credential, whose length says nothing: its
// password, or its user if it has none. A credential that holds a key is
// reported under the key's own kind, and doesn't come here.
func basicSecret(encoded string) string {
	d, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
	if err != nil {
		return ""
	}
	user, pw, _ := strings.Cut(string(d), ":")
	if pw == "" {
		return user
	}
	return pw
}

// placeholderWhole reports whether a whole value reads as a stand-in rather
// than a secret: a constant's name, or a template's words. A value with a digit
// never does: most random keys have one, and a false zero on a real key would
// be worse than a false match on a template.
func placeholderWhole(v string) bool {
	if strings.ContainsAny(v, "0123456789") {
		return false
	}
	if strings.Contains(v, "_") && strings.ToUpper(v) == v {
		return true
	}
	lower := strings.ToLower(v)
	if strings.Contains(lower, "xxxx") {
		return true
	}
	for _, word := range strings.FieldsFunc(lower, func(r rune) bool { return r < 'a' || r > 'z' }) {
		if placeholderWords[word] {
			return true
		}
	}
	return false
}

var placeholderWords = map[string]bool{"changeme": true, "change": true, "your": true, "example": true, "placeholder": true,
	"replace": true, "dummy": true, "sample": true, "todo": true, "insert": true}

// values finds what a value holds that counts, and hands each to emit, by kind
// and normalised. Callers must never print what emit gets.
func (e *extractor) values(v string, w *wants, emit func(model.LeakKind, string)) {
	if strings.TrimSpace(v) == "" {
		return
	}
	finders := e.base
	if w.loosePhone {
		finders = e.loose
	}
	spans := detect.FindSpans(v, finders)
	for _, sp := range spans {
		// Spans are offsets of the value, widened to whole escapes, so the
		// span alone decodes them exactly once.
		t := detect.NewTextView(v[sp.Start:sp.End]).Text
		switch sp.Kind {
		case detect.SpanEmail:
			addr := strings.ToLower(t)
			switch {
			case sp.Detail == "reserved":
			case e.allow.has(addr):
				e.skipped++
			default:
				emit(model.LeakEmail, addr)
			}
		case detect.SpanPhone:
			if d, ok := normPhone(t); ok {
				emit(model.LeakPhone, d)
			}
		case detect.SpanIBAN:
			emit(model.LeakIBAN, strings.ToUpper(strings.ReplaceAll(t, " ", "")))
		case detect.SpanSecret:
			secret := t
			if sp.Detail == basicPasswordKind {
				secret = basicSecret(t)
			}
			if sp.Detail != "placeholder" && sp.Mode != "test" && e.secretCounts(secret) {
				emit(model.LeakSecret, t)
			}
		case detect.SpanURLPassword:
			if sp.Detail != "placeholder" && e.secretCounts(t) {
				emit(model.LeakSecret, t)
			}
		case detect.SpanPasswordHash:
			emit(model.LeakPasswordHash, t)
		}
	}
	if len(spans) > 0 {
		return // a whole value only where no finder saw anything at all
	}
	for _, k := range w.whole {
		if n, ok := normWhole(k, v); ok {
			emit(k, n)
		}
	}
}

// normPhone keeps a phone number's digits, without a leading 00. It keeps all
// of them, not the last few: a copied value has the same digits anyway, and a
// shorter form is one a masking tool's made-up number lands on far more often.
// Numbers that sit in test data everywhere, such as 1234567890, don't count.
func normPhone(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	d := strings.TrimPrefix(b.String(), "00")
	if len(d) < minPhoneDigits || distinctBytes(d) < minPhoneDistinct || digitRun(d) {
		return "", false
	}
	return d, true
}

// digitRun reports whether digits only count up or only count down.
func digitRun(d string) bool {
	up, down := true, true
	for i := 1; i < len(d); i++ {
		a, b := int(d[i-1]-'0'), int(d[i]-'0')
		up = up && (a+1)%10 == b
		down = down && (b+1)%10 == a
	}
	return up || down
}

// normWhole reads a whole value as a kind no span finder finds on its own.
func normWhole(k model.LeakKind, v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) > maxWholeLen {
		return "", false
	}
	switch k {
	case model.LeakNationalID:
		id := strings.NewReplacer(" ", "", ".", "", "-", "", "/", "").Replace(strings.ToUpper(v))
		return id, len(id) >= minIDLen && len(id) <= maxIDLen && distinctBytes(id) >= minIDDistinct
	case model.LeakPaymentToken:
		return v, len(v) >= minTokenLen
	case model.LeakPasswordHash:
		return v, len(v) >= minHashLen
	case model.LeakSecret:
		return v, len(v) >= minSecretLen && distinctBytes(v) >= minSecretDiff && !placeholderWhole(v)
	}
	return "", false
}

func distinctBytes(s string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}
