package detect

import (
	"net/netip"
	"regexp"
	"strings"
)

var (
	reEmail = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)
	// Looser, for finding addresses inside text.
	reEmailIn = regexp.MustCompile(`[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})\b`)
	reIPv4In  = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b`)
	reCardIn  = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	rePhoneIn = regexp.MustCompile(`(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?|\(\d{2,5}\)[ .-]?)\d{2,4}(?:[ .-]?\d{2,4}){1,4}`)

	reDate = regexp.MustCompile(`^(?:\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?.*)?|\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})$`)
	reUA   = regexp.MustCompile(`^(?:Mozilla/\d|Opera/\d|curl/\d|Wget/\d|python-requests/|okhttp/|Dalvik/|WordPress/|` +
		`Go-http-client/|Java/\d|Apache-HttpClient/|facebookexternalhit/|Googlebot|bingbot|PostmanRuntime/)`)
	// Stripe and Braintree style object IDs: customers, payment methods,
	// cards, charges. Not secret, but they lead to a real payment profile.
	rePaymentID = regexp.MustCompile(`^(?:cus|pm|card|src|ba|pi|seti|sub|ch|py|acct)_[0-9A-Za-z]{8,}$`)
	reHex       = regexp.MustCompile(`^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$`)
)

// File extensions that follow an @ in image names like logo@2x.png.
var notTLD = words("png jpg jpeg gif svg webp avif bmp ico tif tiff css js mjs map json xml txt pdf zip gz mp4 webm mov woff woff2 ttf")

// IsEmail reports whether s is one email address.
func IsEmail(s string) bool {
	if len(s) > 254 || !reEmail.MatchString(s) {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	tld := s[strings.LastIndexByte(s, '.')+1:]
	return at > 0 && !notTLD[strings.ToLower(tld)]
}

// reservedEmail reports whether an address uses a domain reserved for
// examples and tests (RFC 2606, RFC 6761), as masking tools usually do.
func reservedEmail(s string) bool {
	d := strings.ToLower(s[strings.LastIndexByte(s, '@')+1:])
	switch d {
	case "example.com", "example.net", "example.org", "localhost":
		return true
	}
	for _, suffix := range []string{".example", ".test", ".invalid", ".localhost", ".example.com", ".example.net", ".example.org"} {
		if strings.HasSuffix(d, suffix) {
			return true
		}
	}
	return false
}

func containsEmail(s string) bool {
	for _, m := range reEmailIn.FindAllStringSubmatch(s, 8) {
		if !notTLD[strings.ToLower(m[1])] {
			return true
		}
	}
	return false
}

// phoneShape reports whether s looks like a phone number. strict means the
// formatting itself says "phone" (+30 210 ..., (555) 010-1234), which is
// needed before a value alone, without a telling column name, counts.
func phoneShape(s string) (ok, strict bool) {
	if len(s) < 7 || len(s) > 32 {
		return false, false
	}
	digits, seps, groups := 0, 0, 0
	plus, parens, inDigits := false, false, false
	for i, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
			if !inDigits {
				groups++
				inDigits = true
			}
			continue
		case r == '+' && i == 0:
			plus = true
		case r == '(' || r == ')':
			parens = true
			seps++
		case r == ' ' || r == '-' || r == '.' || r == '/':
			seps++
		default:
			return false, false
		}
		inDigits = false
	}
	if digits < 7 || digits > 15 || reDate.MatchString(s) || isIP(s) || thousands(s) {
		return false, false
	}
	strict = (plus && digits >= 8) || parens || (seps >= 2 && groups >= 3)
	return true, strict
}

// thousands matches numbers written with group separators: 1.234.567.
func thousands(s string) bool {
	for _, sep := range []string{".", ","} {
		parts := strings.Split(s, sep)
		if len(parts) < 2 || len(parts[0]) > 3 {
			continue
		}
		ok := true
		for _, p := range parts[1:] {
			if len(p) != 3 {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func containsPhone(s string) bool {
	for _, m := range rePhoneIn.FindAllString(s, 8) {
		if ok, _ := phoneShape(strings.TrimSpace(m)); ok {
			return true
		}
	}
	return false
}

// isIP reports whether s is an IP address or a comma-separated list of them,
// as in X-Forwarded-For.
func isIP(s string) bool {
	if len(s) < 3 {
		return false
	}
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		for _, p := range parts {
			if _, err := netip.ParseAddr(strings.TrimSpace(p)); err != nil {
				return false
			}
		}
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil && s != "::"
}

func containsIP(s string) bool {
	for _, m := range reIPv4In.FindAllString(s, 8) {
		if _, err := netip.ParseAddr(m); err == nil {
			return true
		}
	}
	return false
}

// isIBAN checks the shape of an IBAN and its mod-97 checksum.
func isIBAN(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i < 2 && (c < 'A' || c > 'Z'):
			return false
		case i >= 2 && i < 4 && (c < '0' || c > '9'):
			return false
		case !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z'):
			return false
		}
	}
	rem := 0
	for _, c := range s[4:] + s[:4] {
		if c >= '0' && c <= '9' {
			rem = (rem*10 + int(c-'0')) % 97
		} else {
			rem = (rem*100 + int(c-'A'+10)) % 97
		}
	}
	return rem == 1
}

// Card numbers that payment providers publish for testing.
var testCards = words("4242424242424242 4000056655665556 4111111111111111 4012888888881881 4000000000000002 " +
	"4000002500003155 4000000000003220 5555555555554444 5200828282828210 5105105105105100 2223003122003222 " +
	"378282246310005 371449635398431 6011111111111117 6011000990139424 3056930009020004 36227206271667 " +
	"3566002020360505 6200000000000005")

// cardNumber reports whether s is a payment card number: 13 to 19 digits
// (spaces and dashes allowed), a valid Luhn checksum and a known card
// network prefix. test reports a published test number.
func cardNumber(s string) (ok, test bool) {
	var d []byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			d = append(d, c)
		case c == ' ' || c == '-':
		default:
			return false, false
		}
	}
	if len(d) < 13 || len(d) > 19 || allSame(d) || !luhn(d) || !cardNetwork(d) {
		return false, false
	}
	return true, testCards[string(d)]
}

func containsCard(s string) bool {
	for _, m := range reCardIn.FindAllString(s, 8) {
		if ok, _ := cardNumber(m); ok {
			return true
		}
	}
	return false
}

func allSame(d []byte) bool {
	for _, c := range d[1:] {
		if c != d[0] {
			return false
		}
	}
	return true
}

func luhn(d []byte) bool {
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

func prefixNum(d []byte, n int) int {
	v := 0
	for i := 0; i < n && i < len(d); i++ {
		v = v*10 + int(d[i]-'0')
	}
	return v
}

// cardNetwork checks the issuer prefix and length of the big card networks.
func cardNetwork(d []byte) bool {
	n := len(d)
	p1, p2, p3, p4 := prefixNum(d, 1), prefixNum(d, 2), prefixNum(d, 3), prefixNum(d, 4)
	switch {
	case p1 == 4: // Visa
		return n == 13 || n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720: // Mastercard
		return n == 16
	case p2 == 34 || p2 == 37: // American Express
		return n == 15
	case p4 == 6011, p3 >= 644 && p3 <= 649, p2 == 65: // Discover
		return n >= 16 && n <= 19
	case p4 >= 3528 && p4 <= 3589: // JCB
		return n >= 16 && n <= 19
	case p3 >= 300 && p3 <= 305, p2 == 36, p2 == 38, p2 == 39: // Diners Club
		return n >= 14 && n <= 19
	case p2 == 62: // UnionPay
		return n >= 16 && n <= 19
	}
	return false
}

type hashFormat struct {
	name string
	re   *regexp.Regexp
}

// Password hash formats used by PHP frameworks and other common stacks.
var hashFormats = []hashFormat{
	{"bcrypt", regexp.MustCompile(`^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$`)},
	{"WordPress bcrypt", regexp.MustCompile(`^\$wp\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$`)},
	{"phpass", regexp.MustCompile(`^\$[PH]\$[./0-9A-Za-z]{31}$`)},
	{"argon2", regexp.MustCompile(`^\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)},
	{"sha-crypt", regexp.MustCompile(`^\$[56]\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,86}$`)},
	{"md5-crypt", regexp.MustCompile(`^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$`)},
	{"Drupal", regexp.MustCompile(`^\$S\$[./0-9A-Za-z]{52}$`)},
	{"PBKDF2", regexp.MustCompile(`^pbkdf2_sha(?:1|256|512)\$\d+\$[^$]+\$[A-Za-z0-9+/=]+$`)},
	{"Magento", regexp.MustCompile(`^[0-9a-f]{64}:[A-Za-z0-9]{0,64}:[0-9_]+$`)},
	{"Magento 1", regexp.MustCompile(`^[0-9a-f]{32}:[A-Za-z0-9]{2,32}$`)},
}

func passwordHash(s string) string {
	if len(s) < 30 || len(s) > 512 {
		return ""
	}
	for _, f := range hashFormats {
		if f.re.MatchString(s) {
			return f.name
		}
	}
	return ""
}

func isUserAgent(s string) bool {
	return reUA.MatchString(s) || strings.Contains(s, "AppleWebKit/") || strings.Contains(s, " Gecko/")
}

// SecretHit is one secret-looking string. Mode is "live", "test" or "" when
// the format does not say.
type SecretHit struct {
	Kind string
	Mode string
}

type secretPattern struct {
	kind string
	hint string // cheap substring check before running the regexp
	re   *regexp.Regexp
	mode func(m []string) string
}

func constMode(mode string) func([]string) string { return func([]string) string { return mode } }

// The first submatch holds "live"/"test" or "production"/"sandbox".
func groupMode(m []string) string {
	switch m[1] {
	case "live", "production":
		return "live"
	case "test", "sandbox":
		return "test"
	}
	return ""
}

// Secret formats with a recognisable prefix. A random token without one
// cannot be told from other random strings, so those only show up through
// column names.
var secretPatterns = []secretPattern{
	{"Stripe secret key", "k_", regexp.MustCompile(`\b[sr]k_(live|test)_[0-9A-Za-z]{20,}`), groupMode},
	{"Stripe webhook secret", "whsec_", regexp.MustCompile(`\bwhsec_[0-9A-Za-z+/]{24,}`), constMode("live")},
	{"AWS access key ID", "A", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), constMode("live")},
	{"GitHub token", "gh", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}`), constMode("live")},
	{"GitHub token", "github_pat_", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{22,}`), constMode("live")},
	{"Slack token", "xox", regexp.MustCompile(`\bxox[abposr]-[0-9A-Za-z-]{10,}`), constMode("live")},
	{"Slack webhook URL", "hooks.slack.com", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+`), constMode("live")},
	{"Google API key", "AIza", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`), constMode("live")},
	{"SendGrid API key", "SG.", regexp.MustCompile(`\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`), constMode("live")},
	{"Mailgun API key", "key-", regexp.MustCompile(`\bkey-[0-9a-f]{32}\b`), constMode("live")},
	{"Mailchimp API key", "-us", regexp.MustCompile(`\b[0-9a-f]{32}-us\d{1,2}\b`), constMode("live")},
	{"Twilio API key", "SK", regexp.MustCompile(`\bSK[0-9a-f]{32}\b`), constMode("live")},
	{"Shopify access token", "shp", regexp.MustCompile(`\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b`), constMode("live")},
	{"Anthropic API key", "sk-ant-", regexp.MustCompile(`\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{32,}`), constMode("live")},
	{"OpenAI API key", "sk-", regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}`), constMode("live")},
	{"WooCommerce API key", "_", regexp.MustCompile(`\b(?:ck|cs)_[0-9a-f]{40}\b`), constMode("live")},
	{"PayPal/Braintree access token", "access_token$", regexp.MustCompile(`\baccess_token\$(production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32}`), groupMode},
	{"private key", "PRIVATE KEY", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`), constMode("live")},
	{"JSON Web Token", "eyJ", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), constMode("")},
}

// FindSecrets returns the kinds of secrets that appear in s, once per kind.
func FindSecrets(s string) []SecretHit {
	var hits []SecretHit
	seen := map[string]bool{}
	for i := range secretPatterns {
		p := &secretPatterns[i]
		if !strings.Contains(s, p.hint) {
			continue
		}
		m := p.re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		// An OpenAI-style match on an Anthropic key is the same secret.
		if p.kind == "OpenAI API key" && seen["Anthropic API key"] {
			continue
		}
		h := SecretHit{Kind: p.kind, Mode: p.mode(m)}
		if !seen[h.Kind] {
			seen[h.Kind] = true
			hits = append(hits, h)
		}
	}
	return hits
}
