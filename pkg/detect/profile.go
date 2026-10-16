package detect

import (
	"regexp"
	"sort"
	"strings"
)

var (
	reNumber = regexp.MustCompile(`^[-+]?\d+(?:[.,]\d+)?$`)
	reCode   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:(?:\\|::)[A-Za-z_][A-Za-z0-9_]*)+$`)
)

// maxPaths caps how many distinct JSON/PHP paths one column may track.
const maxPaths = 500

// Profile counts what the sampled values of one column, meta key or JSON
// path look like. It keeps counts only, never the values.
type Profile struct {
	Values   int // all values seen, including empty ones
	NonEmpty int

	Email, EmailReserved int
	Phone, PhoneStrict   int
	IP                   int
	IBAN                 int
	Card, CardTest       int
	Hash, HexDigest      int
	HashFormats          map[string]int
	UserAgent            int
	PaymentID            int
	Date                 int
	Secrets              map[string]*SecretCount

	// Prose: values with spaces that are longer than a few words.
	Text, TextEmail, TextPhone, TextIP, TextCard int

	// Values that cannot be names or addresses: plain numbers, and code
	// identifiers such as App\Jobs\SendInvoice.
	Numeric, CodeLike int

	Structured int
	Paths      map[string]*Profile
	pathKeys   map[string][]string
	walk       bool
}

// SecretCount counts values holding one kind of secret.
type SecretCount struct {
	Live, Test, Unknown int
}

// NewProfile returns an empty profile. Values that are JSON or PHP-serialized
// are opened up and counted per path.
func NewProfile() *Profile { return &Profile{walk: true} }

// Add counts one sampled value.
func (p *Profile) Add(v string) {
	p.Values++
	t := strings.TrimSpace(v)
	if t == "" {
		return
	}
	p.NonEmpty++
	if p.walk && looksStructured(t) {
		if walkStructured(t, p.addPath) {
			p.Structured++
			return
		}
	}
	p.addScalar(t)
}

func (p *Profile) addPath(path []string, v string) {
	key := JoinPath(path)
	if p.Paths == nil {
		p.Paths = map[string]*Profile{}
		p.pathKeys = map[string][]string{}
	}
	sub := p.Paths[key]
	if sub == nil {
		if len(p.Paths) >= maxPaths {
			return
		}
		sub = &Profile{}
		p.Paths[key] = sub
		p.pathKeys[key] = append([]string(nil), path...)
	}
	sub.Add(v)
}

// PathNames returns the tracked paths in a stable order.
func (p *Profile) PathNames() []string {
	names := make([]string, 0, len(p.Paths))
	for k := range p.Paths {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (p *Profile) addScalar(t string) {
	if reNumber.MatchString(t) {
		p.Numeric++
	}
	if reCode.MatchString(t) {
		p.CodeLike++
	}
	matched := false
	email := IsEmail(t)
	if email {
		matched = true
		p.Email++
		if reservedEmail(t) {
			p.EmailReserved++
		}
	}
	if ok, strict := phoneShape(t); ok {
		matched = true
		p.Phone++
		if strict {
			p.PhoneStrict++
		}
	}
	if isIP(t) {
		matched = true
		p.IP++
	}
	if isIBAN(t) {
		p.IBAN++
	}
	if ok, test := cardNumber(t); ok {
		p.Card++
		if test {
			p.CardTest++
		}
	}
	if f := passwordHash(t); f != "" {
		p.Hash++
		if p.HashFormats == nil {
			p.HashFormats = map[string]int{}
		}
		p.HashFormats[f]++
	} else if reHex.MatchString(t) {
		p.HexDigest++
	}
	if isUserAgent(t) {
		matched = true
		p.UserAgent++
	}
	if rePaymentID.MatchString(t) {
		p.PaymentID++
	}
	if reDate.MatchString(t) {
		p.Date++
	}
	for _, h := range FindSecrets(t) {
		if p.Secrets == nil {
			p.Secrets = map[string]*SecretCount{}
		}
		c := p.Secrets[h.Kind]
		if c == nil {
			c = &SecretCount{}
			p.Secrets[h.Kind] = c
		}
		switch h.Mode {
		case "live":
			c.Live++
		case "test":
			c.Test++
		default:
			c.Unknown++
		}
	}
	if !matched && len(t) >= 20 && strings.ContainsAny(t, " \n") {
		p.Text++
		if containsEmail(t) {
			p.TextEmail++
		}
		if containsPhone(t) {
			p.TextPhone++
		}
		if containsIP(t) {
			p.TextIP++
		}
		if containsCard(t) {
			p.TextCard++
		}
	}
}

// SecretTotals sums the secret counts over all kinds.
func (p *Profile) SecretTotals() (live, test, unknown int) {
	for _, c := range p.Secrets {
		live += c.Live
		test += c.Test
		unknown += c.Unknown
	}
	return
}

// SecretKinds lists the kinds of secrets seen, sorted.
func (p *Profile) SecretKinds() []string {
	kinds := make([]string, 0, len(p.Secrets))
	for k := range p.Secrets {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}
