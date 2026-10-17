package detect

import (
	"regexp"
	"sort"
	"strings"
)

var (
	reNumber = regexp.MustCompile(`^[-+]?\d+(?:[.,]\d+)?$`)
	reCode   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:(?:\\|::)[A-Za-z_][A-Za-z0-9_]*)+$`)

	// Field names and placeholders: billing_address_1, wc-admin-new-note,
	// {billing_email}, [your-email], %first_name%.
	reSnake       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+$`)
	reKebab       = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$`)
	rePlaceholder = regexp.MustCompile(`^(?:\{[^{}\s]{1,64}\}|\[[^\[\]\s]{1,64}\]|%[^%\s]{1,64}%)$`)
	// Advanced Custom Fields names each field field_<uniqid>, and keeps
	// that key beside every value as _<field name>.
	reACFKey = regexp.MustCompile(`^(?:field|group)_[0-9a-f]{13}$`)
)

// Words that make a two-part name such as first_name or user-login a field
// name rather than a person's handle such as john_smith.
var fieldWords = words("address name email mail phone billing shipping field first last user login city " +
	"postcode zip country state company street")

// On/off values, which no name, address or secret ever is.
var flagWords = words("yes no true false on off y n 0 1 enabled disabled checked unchecked null none")

// maxPaths caps how many distinct JSON/PHP paths one column may track. Past
// it, a path is still tracked when its last key matches a naming rule, up
// to maxNamedPaths more, and every other leaf is still checked for secrets.
const (
	maxPaths      = 2000
	maxNamedPaths = 500
)

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

	// Values that say a name match is wrong: on/off flags, field names
	// (billing_address_1, edit-address), placeholders and ACF field keys,
	// and the field's own name (as in translation tables and import
	// mappings).
	Flag, FieldName, Placeholder, Echo int
	// MaxDigits is the most digits any one value holds: an ID number or a
	// birth date has at least four.
	MaxDigits int

	Structured int
	Paths      map[string]*Profile
	pathKeys   map[string][]string
	walk       bool
	name       []string // tokens of the field's own name, for FieldName
	named      int      // paths admitted past maxPaths
}

// NewProfileNamed returns an empty profile for a field with the given
// name; values that only repeat the name, such as "First name" under
// first_name, count as field names.
func NewProfileNamed(name string) *Profile {
	p := NewProfile()
	p.name = Tokens(name)
	return p
}

// SecretCount counts values holding one kind of secret.
type SecretCount struct {
	Live, Test, Unknown int
}

// NewProfile returns an empty profile. Values that are JSON or PHP-serialized
// are opened up and counted per path.
func NewProfile() *Profile { return &Profile{walk: true} }

// Add counts one sampled value. An empty array or object, or one whose
// leaves are all empty, counts as an empty value: WordPress keeps
// recovery_keys as a:0:{} on nearly every site.
func (p *Profile) Add(v string) {
	p.Values++
	t := strings.TrimSpace(v)
	if t == "" || t == "[]" || t == "N;" {
		return
	}
	if p.walk && looksStructured(t) {
		filled := 0
		ok := walkStructured(t, func(path []string, leaf string) {
			if strings.TrimSpace(leaf) != "" {
				filled++
			}
			p.addPath(path, leaf)
		})
		if ok {
			if filled > 0 {
				p.NonEmpty++
				p.Structured++
			}
			return
		}
	}
	p.NonEmpty++
	p.addScalar(t)
}

func (p *Profile) addPath(path []string, v string) {
	if n := len(path); n > 0 && path[n-1] == keysPath && !IsEmail(strings.TrimSpace(v)) && p.versionKeyed(path[:n-1]) {
		return
	}
	key := JoinPath(path)
	if p.Paths == nil {
		p.Paths = map[string]*Profile{}
		p.pathKeys = map[string][]string{}
	}
	sub := p.Paths[key]
	if sub == nil {
		last := lastName(path)
		if len(p.Paths) >= maxPaths {
			// Big settings arrays: keep paths whose names say something,
			// and still look for secrets in the rest.
			if p.named >= maxNamedPaths || last < 0 ||
				MatchName(Tokens(path[last]), pathContext(path[:last]), tStr|tJSON) == nil {
				p.overflow(v)
				return
			}
			p.named++
		}
		sub = &Profile{}
		if last >= 0 {
			sub.name = Tokens(path[last])
		}
		p.Paths[key] = sub
		p.pathKeys[key] = append([]string(nil), path...)
	}
	sub.Add(v)
}

// versionWords mark maps keyed by version numbers, such as
// wpforms_versions_lite, whose keys (1.8.5.4) read as IPv4 addresses.
var versionWords = words("version versions ver")

// versionKeyed reports whether the field's name or the path to a map says
// the map is keyed by version.
func (p *Profile) versionKeyed(path []string) bool {
	if anyIn(p.name, versionWords) {
		return true
	}
	for _, k := range path {
		if anyIn(Tokens(k), versionWords) {
			return true
		}
	}
	return false
}

// overflow checks a leaf past the path cap for secrets only, counting them
// on the parent value.
func (p *Profile) overflow(v string) {
	for _, h := range FindSecrets(strings.TrimSpace(v)) {
		p.addSecret(h)
	}
}

// lastName returns the index of the last path segment that is a name, not
// "[]", "*" or "{}", or -1.
func lastName(path []string) int {
	for i := len(path) - 1; i >= 0; i-- {
		if k := path[i]; k != "[]" && k != "*" && k != keysPath {
			return i
		}
	}
	return -1
}

func pathContext(keys []string) []string {
	var ctx []string
	for _, k := range keys {
		ctx = append(ctx, Tokens(k)...)
	}
	return ctx
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
	if flagWords[strings.ToLower(t)] {
		p.Flag++
	}
	switch {
	case p.echo(t):
		p.Echo++
	case rePlaceholder.MatchString(t) || reACFKey.MatchString(t):
		p.Placeholder++
	case fieldName(t):
		p.FieldName++
	}
	p.MaxDigits = max(p.MaxDigits, countDigits(t))
	matched := false
	email, reserved := IsEmail(t), false
	if email {
		reserved = reservedEmail(t)
	} else if list := emailList(t); list != nil {
		// Recipient settings: "staff@shop.example, boss@shop.example".
		email, reserved = true, true
		for _, e := range list {
			reserved = reserved && reservedEmail(e)
		}
	}
	if email {
		matched = true
		p.Email++
		if reserved {
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
		if !localIP(t) {
			p.IP++
		}
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
		p.addSecret(h)
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

func (p *Profile) addSecret(h SecretHit) {
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

// fieldName reports whether a value looks like a field name rather than
// data: billing_address_1, wc-admin-note-id. Two-part names count only
// with a field word, so john_smith stays a name, and every part must be a
// word, so sk_live_… keys and UUIDs are not field names.
func fieldName(t string) bool {
	var parts []string
	switch {
	case reSnake.MatchString(t):
		parts = strings.Split(strings.ToLower(t), "_")
	case reKebab.MatchString(t):
		parts = strings.Split(t, "-")
	}
	for _, part := range parts {
		if !wordPart(part) {
			return false
		}
	}
	return len(parts) >= 3 || (len(parts) == 2 && (fieldWords[parts[0]] || fieldWords[parts[1]]))
}

// wordPart reports whether part of a field name is a word, a number of up
// to 3 digits or a short tag such as v2 or 2fa, rather than random
// characters.
func wordPart(s string) bool {
	digits := countDigits(s)
	switch {
	case digits == 0:
		return true
	case digits == len(s):
		return digits <= 3
	}
	return len(s) <= 4
}

// echo reports whether a value only repeats the field's own name, as in
// "First name" under first_name, or user_login under user_login.
func (p *Profile) echo(t string) bool {
	if len(p.name) == 0 || len(t) > 64 {
		return false
	}
	vt := Tokens(t)
	if len(vt) != len(p.name) {
		return false
	}
	for i := range vt {
		if vt[i] != p.name[i] {
			return false
		}
	}
	return true
}

// leafMaxDigits is the most digits any sampled value holds, looking inside
// JSON and serialized values too.
func (p *Profile) leafMaxDigits() int {
	n := p.MaxDigits
	for _, sub := range p.Paths {
		n = max(n, sub.MaxDigits)
	}
	return n
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
