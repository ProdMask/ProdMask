package detect

import (
	"encoding/base64"
	"math/bits"
	"regexp"
	"strings"
)

// SecretHit is one secret-looking string. Mode is "live", "test" or "" when
// the format does not say.
type SecretHit struct {
	Kind string
	Mode string
}

// What a copy of a secret would do on staging, for the finding's note.
type secretNote int

const (
	noteNone secretNote = iota
	noteChat
	noteWorkflow
)

// edge holds the bytes that may touch a token on one side: none of deny, and
// only allow when it is set. The edge of the value always may.
type edge struct {
	deny, allow [256]bool
	allowSet    bool
}

type secretPattern struct {
	kind string
	re   *regexp.Regexp
	mode func(m []string) string
	// hints are literals, one of which the value must hold; fold matches
	// them ignoring ASCII case. pre is a structural check, for formats whose
	// literal is weak or missing, or that look at the token's edges before
	// any regexp runs. A pattern runs only when it passes both it has.
	hints []string
	fold  bool
	pre   func(s string) bool
	// re matches the token itself; before and after say what may touch it.
	before, after edge
	// group is the submatch that holds the token, for overlaps.
	group int
	valid func(s string, m []string) bool
	// unless lists kinds that, found earlier in the value, skip this pattern.
	unless []string
	// A fallback match is dropped when it overlaps a token already found,
	// another fallback's included.
	fallback bool
	note     secretNote
}

func constMode(mode string) func([]string) string { return func([]string) string { return mode } }

// The first submatch holds the mode: live and production, or test, sandbox,
// sdbx (Paddle) and development (Plaid).
func groupMode(m []string) string {
	switch m[1] {
	case "live", "production":
		return "live"
	case "test", "sandbox", "sdbx", "development":
		return "test"
	}
	return ""
}

// labelledMode reads the mode of a key that labels itself from the words
// before its label: xyz_live_apikey_...
func labelledMode(m []string) string {
	for _, w := range strings.FieldsFunc(strings.ToLower(m[1]), func(r rune) bool { return r == '_' || r == '-' }) {
		switch w {
		case "live", "prod", "production":
			return "live"
		case "test", "sandbox", "sdbx", "dev", "staging":
			return "test"
		}
	}
	return ""
}

func modeRank(mode string) int {
	switch mode {
	case "live":
		return 3
	case "":
		return 2
	}
	return 1
}

// charSet reads a class such as "A-Za-z0-9_-": ranges and single bytes, a
// dash last or first taken as itself.
func charSet(spec string) (set [256]bool) {
	for i := 0; i < len(spec); i++ {
		if i+2 < len(spec) && spec[i+1] == '-' {
			for c := int(spec[i]); c <= int(spec[i+2]); c++ {
				set[c] = true
			}
			i += 2
			continue
		}
		set[spec[i]] = true
	}
	return set
}

func deny(spec string) edge { return edge{deny: charSet(spec)} }

func allowOnly(chars string) edge {
	e := edge{allowSet: true}
	for i := 0; i < len(chars); i++ {
		e.allow[chars[i]] = true
	}
	return e
}

func (e *edge) ok(c byte) bool { return !e.deny[c] && (!e.allowSet || e.allow[c]) }

const (
	b64url = "A-Za-z0-9_-"
	b64any = "A-Za-z0-9+/_-"
)

var (
	edgeB64URL = deny(b64url)
	// Padding only ends base64, so = may come before a token but not after.
	edgeB64Before = deny(b64any)
	edgeB64After  = deny("=" + b64any)
)

func kindsOf(s string) int {
	var lower, upper, digit bool
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit} {
		if b {
			n++
		}
	}
	return n
}

func distinct(s string) int {
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

// Values that stand in for a credential in examples and templates.
var placeholderWords = words("password pass pwd passwd secret xxx *** changeme your_password token")

func placeholder(s string) bool {
	if s == "" || strings.IndexByte("{<$%[", s[0]) >= 0 || distinct(strings.ToLower(s)) <= 1 {
		return true
	}
	return placeholderWords[strings.ToLower(s)]
}

// randomPart reports whether some part of s, split on - and _, has 16 or
// more characters, two kinds of character and 10 distinct ones: a key, not
// a slug or a field name.
func randomPart(s string) bool {
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' }) {
		if len(part) >= 16 && kindsOf(part) >= 2 && distinct(part) >= 10 {
			return true
		}
	}
	return false
}

// strictB64 holds tokens that start with a common base64 run (EAA, ABSK) to
// what a random key looks like, so data inside a blob doesn't count.
func strictB64(tok string) bool {
	if kindsOf(tok) < 3 || distinct(tok) < 20 {
		return false
	}
	run := 1
	for i := 1; i < len(tok); i++ {
		if tok[i] == tok[i-1] {
			if run++; run >= 5 {
				return false
			}
		} else {
			run = 1
		}
	}
	return true
}

// discordID reports whether the first part of a bot token decodes to the
// bot's ID, a snowflake of 17 to 20 digits.
func discordID(_ string, m []string) bool {
	d, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(m[1], "="))
	if err != nil || len(d) < 17 || len(d) > 20 || d[0] == '0' {
		return false
	}
	for _, c := range d {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func bearerToken(_ string, m []string) bool {
	t := m[1]
	if placeholder(t) || (strings.Contains(t, "_") && strings.ToUpper(t) == t && kindsOf(t) <= 2 && !strings.ContainsAny(t, "abcdefghijklmnopqrstuvwxyz")) {
		return false
	}
	return kindsOf(t) >= 2 && distinct(t) >= 8
}

// basicPassword reports whether a Basic credential decodes to user:password
// with a password that isn't a placeholder, the user's name or RFC 7617's
// example.
func basicPassword(_ string, m []string) bool {
	b := strings.TrimRight(m[1], "=")
	d, err := base64.RawStdEncoding.DecodeString(b)
	if err != nil {
		return false
	}
	for _, c := range d {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	user, pw, ok := strings.Cut(string(d), ":")
	if !ok || pw == "" || placeholder(pw) || strings.EqualFold(pw, user) {
		return false
	}
	return !(user == "Aladdin" && pw == "open sesame")
}

func exampleHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range []string{"example.com", "example.net", "example.org"} {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return strings.HasSuffix(h, ".example") || strings.HasSuffix(h, ".test") || strings.HasSuffix(h, ".invalid")
}

func urlPassword(_ string, m []string) bool {
	return !placeholder(m[2]) && !strings.EqualFold(m[2], m[1]) && !exampleHost(m[3])
}

func skKey(_ string, m []string) bool { return randomPart(m[1]) }

func labelledKey(_ string, m []string) bool { return randomPart(m[2]) }

func queryKey(_ string, m []string) bool { return !placeholder(m[1]) && randomPart(m[1]) }

func threeKinds(_ string, m []string) bool { return kindsOf(m[1]) == 3 }

func mixedCase(_ string, m []string) bool {
	return strings.ToLower(m[1]) != m[1] && strings.ToUpper(m[1]) != m[1]
}

func strictToken(_ string, m []string) bool { return strictB64(m[0]) }

func samlRaw(s string, _ []string) bool { return strings.Contains(s, "IssueInstant=") }

// runEnd returns the end of the run of bytes in set that starts at i.
func runEnd(s string, i int, set *[256]bool) int {
	for i < len(s) && set[s[i]] {
		i++
	}
	return i
}

var (
	setAlnum    = charSet("A-Za-z0-9")
	setB64URL   = charSet(b64url)
	setB64Std   = charSet("A-Za-z0-9+/")
	setUpperNum = charSet("A-Z0-9")
	setBase32   = charSet("A-Z2-7")
	setWord     = charSet("A-Za-z0-9_")
	setHex      = charSet("0-9a-f")
)

// boundedToken looks for prefix with an acceptable byte before it, then a
// run of set of min to max bytes (no maximum when max is 0), up to pad =
// signs, and an acceptable byte after it: the whole token as its pattern
// and edges would take it.
func boundedToken(s, prefix string, set *[256]bool, min, max, pad int, before, after *edge) bool {
	for off := 0; ; {
		i := strings.Index(s[off:], prefix)
		if i < 0 {
			return false
		}
		i += off
		if i == 0 || before.ok(s[i-1]) {
			j := runEnd(s, i+len(prefix), set)
			if n := j - i - len(prefix); n >= min && (max == 0 || n <= max) {
				for k := 0; k < pad && j < len(s) && s[j] == '='; k++ {
					j++
				}
				if j == len(s) || after.ok(s[j]) {
					return true
				}
			}
		}
		off = i + 1
	}
}

// Meta, Square and Bedrock tokens: the run after the prefix is the whole
// token, so these checks see what the patterns and edges would take.
func metaShape(s string) bool {
	return boundedToken(s, "EAA", &setAlnum, 100, 0, 0, &edgeB64Before, &edgeB64After)
}

func squareShape(s string) bool {
	return boundedToken(s, "EAAA", &setB64URL, 60, 60, 0, &edgeB64Before, &edgeB64After)
}

func bedrockShape(s string) bool {
	return boundedToken(s, "ABSK", &setB64Std, 109, 269, 2, &edgeB64Before, &edgeB64After)
}

// awsShape looks for an access key ID: one of the prefixes at a word
// boundary, 16 bytes of set, and a word boundary.
func awsShape(s string, prefixes []string, set *[256]bool) bool {
	for _, prefix := range prefixes {
		for off := 0; ; {
			i := strings.Index(s[off:], prefix)
			if i < 0 {
				break
			}
			i += off
			if j := i + 20; j <= len(s) && (i == 0 || !setWord[s[i-1]]) && (j == len(s) || !setWord[s[j]]) &&
				runEnd(s, i+4, set) >= j {
				return true
			}
			off = i + 1
		}
	}
	return false
}

func akiaShape(s string) bool { return awsShape(s, []string{"AKIA", "ASIA"}, &setUpperNum) }
func abiaShape(s string) bool { return awsShape(s, []string{"ABIA", "ACCA"}, &setBase32) }

// discordShape looks for a dot, six base64url characters and a dot, with at
// least 23 base64url characters before the first dot.
func discordShape(s string) bool {
	if len(s) < 58 {
		return false
	}
	for off := 23; off+7 < len(s); {
		j := strings.IndexByte(s[off:], '.')
		if j < 0 {
			return false
		}
		i := off + j
		if i+7 < len(s) && s[i+7] == '.' && runEnd(s, i+1, &setB64URL) == i+7 {
			k := i
			for k > i-23 && setB64URL[s[k-1]] {
				k--
			}
			if k == i-23 {
				return true
			}
		}
		off = i + 1
	}
	return false
}

// mailgunShape looks for 32 hex characters, a dash, 8 hex, a dash and 8 hex.
func mailgunShape(s string) bool {
	if len(s) < 50 {
		return false
	}
	for off := 32; off+18 <= len(s); {
		j := strings.IndexByte(s[off:], '-')
		if j < 0 {
			return false
		}
		i := off + j
		if i+18 <= len(s) && s[i+9] == '-' && runEnd(s, i+1, &setHex) == i+9 && runEnd(s, i+10, &setHex) >= i+18 {
			k := i
			for k > i-32 && setHex[s[k-1]] {
				k--
			}
			if k == i-32 {
				return true
			}
		}
		off = i + 1
	}
	return false
}

// urlUserInfo looks for ://, then a colon, then @, before any /, ?, #,
// space or quote.
func urlUserInfo(s string) bool {
	if strings.IndexByte(s, '@') < 0 {
		return false
	}
	for rest := s; ; {
		i := strings.Index(rest, "://")
		if i < 0 {
			return false
		}
		rest = rest[i+3:]
		colon := false
		for j := 0; j < len(rest); j++ {
			c := rest[j]
			if c == ':' {
				colon = true
			} else if c == '@' {
				if colon {
					return true
				}
				break
			} else if strings.IndexByte("/?#\"' \t\r\n", c) >= 0 {
				break
			}
		}
	}
}

// airtableShape looks for pat, 14 letters or digits, and a dot.
func airtableShape(s string) bool {
	for off := 0; ; {
		i := strings.Index(s[off:], "pat")
		if i < 0 {
			return false
		}
		i += off
		if j := i + 17; j < len(s) && s[j] == '.' && runEnd(s, i+3, &setAlnum) == j {
			return true
		}
		off = i + 1
	}
}

// startsWord reports whether s starts with the lower-case word w, ignoring
// ASCII case, then a space or a tab.
func startsWord(s, w string) bool {
	if len(s) <= len(w) || s[len(w)] != ' ' && s[len(w)] != '\t' {
		return false
	}
	for i := 0; i < len(w); i++ {
		if lowerASCII(s[i]) != w[i] {
			return false
		}
	}
	return true
}

// ci writes a lower-case ASCII word as a pattern that matches it in any
// ASCII case. (?i) would also fold k to the Kelvin sign and s to the long s,
// which the prefilter's ASCII hints don't see.
func ci(word string) string {
	var b strings.Builder
	for i := 0; i < len(word); i++ {
		if c := word[i]; c >= 'a' && c <= 'z' {
			b.WriteString("[" + string(c-'a'+'A') + string(c) + "]")
		} else {
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

func bearerValue(s string) bool { return startsWord(s, "bearer") }
func basicValue(s string) bool  { return startsWord(s, "basic") }

// The lead of an Authorization header in header lines, print_r text,
// JSON, PHP-serialized text and Python-style dicts.
var authLead = ci("authorization") + `\\?["'\]]?\s*(?:=>|[:=,]|;s:\d+:)\s*\\?["']?`

var rx = regexp.MustCompile

// Secret formats with a recognisable shape. A random token without one
// cannot be told from other random strings, so those only show up through
// names. Specific patterns come before generic ones, and fallbacks last.
var secretPatterns = []secretPattern{
	{kind: "Stripe secret key", hints: []string{"sk_", "rk_"}, re: rx(`\b[sr]k_(live|test)_[0-9A-Za-z]{20,}`), mode: groupMode},
	{kind: "Stripe webhook secret", hints: []string{"whsec_"}, re: rx(`\bwhsec_[0-9A-Za-z+/]{24,}`), mode: constMode("live")},
	{kind: "AWS access key ID", hints: []string{"AKIA", "ASIA"}, pre: akiaShape, re: rx(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), mode: constMode("live")},
	{kind: "AWS access key ID", hints: []string{"ABIA", "ACCA"}, pre: abiaShape, re: rx(`\b(?:ABIA|ACCA)[A-Z2-7]{16}\b`), mode: constMode("live")},
	{kind: "Amazon Bedrock API key", hints: []string{"ABSK"}, pre: bedrockShape, re: rx(`ABSK[A-Za-z0-9+/]{109,269}={0,2}`), mode: constMode("live"),
		before: edgeB64Before, after: edgeB64After},
	{kind: "Alibaba Cloud AccessKey ID", hints: []string{"LTAI"}, re: rx(`\bLTAI[A-Za-z0-9]{12,20}`), mode: constMode("live"),
		after: deny("A-Za-z0-9")},
	{kind: "GitHub token", hints: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, re: rx(`\bgh[pousr]_[0-9A-Za-z]{36,}`), mode: constMode("live")},
	{kind: "GitHub token", hints: []string{"github_pat_"}, re: rx(`\bgithub_pat_[0-9A-Za-z_]{22,}`), mode: constMode("live")},
	{kind: "GitLab token", hints: []string{"glpat-", "gldt-", "glrt-", "glptt-", "glcbt-", "gloas-", "glft-", "glimt-", "glsoat-", "glagent-"},
		re: rx(`\b(?:glpat|gldt|glrt|glptt|glcbt|gloas|glft|glimt|glsoat|glagent)-[A-Za-z0-9_-]{20,}`), mode: constMode("live")},
	{kind: "GitLab token", hints: []string{"GR1348941"}, re: rx(`\bGR1348941[A-Za-z0-9_-]{20}`), mode: constMode("live"), after: edgeB64URL},
	{kind: "Slack token", hints: []string{"xox"}, re: rx(`\bxox[abposr]-[0-9A-Za-z-]{10,}`), mode: constMode("live")},
	{kind: "Slack token", hints: []string{"xapp-"}, re: rx(`\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`), mode: constMode("live")},
	{kind: "Slack webhook URL", hints: []string{"hooks.slack.com"}, note: noteChat, mode: constMode("live"),
		re: rx(`https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+`)},
	{kind: "Slack webhook URL", hints: []string{"hooks.slack.com"}, note: noteChat, mode: constMode("live"),
		re: rx(`https://hooks\.slack\.com/(?:workflows|triggers)/T[0-9A-Z]+/[0-9A-Za-z]+/[0-9A-Za-z]+`)},
	{kind: "Discord webhook URL", hints: []string{"/webhooks/"}, note: noteChat, mode: constMode("live"), after: edgeB64URL,
		re: rx(`https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,80}`)},
	{kind: "Discord bot token", pre: discordShape, note: noteChat, mode: constMode("live"), valid: discordID,
		re: rx(`([MNO][A-Za-z0-9_-]{22,26})\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}`), before: edgeB64URL, after: edgeB64URL},
	{kind: "Telegram bot token", hints: []string{":AA"}, note: noteChat, mode: constMode("live"),
		re: rx(`\d{8,12}:AA[A-Za-z0-9_-]{33}`), before: deny("0-9"), after: edgeB64URL},
	{kind: "Microsoft Teams webhook URL", hints: []string{"webhook.office.com"}, note: noteChat, mode: constMode("live"),
		re: rx(`https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[0-9a-f-]{36}@[0-9a-f-]{36}/IncomingWebhook/[0-9A-Za-z]{32}`)},
	{kind: "Microsoft Teams webhook URL", hints: []string{"outlook.office"}, note: noteChat, mode: constMode("live"),
		re: rx(`https://outlook\.office(?:365)?\.com/webhook/[0-9a-f-]{36}@[0-9a-f-]{36}/IncomingWebhook/[0-9A-Za-z]{32}`)},
	{kind: "Power Automate or Logic Apps URL", hints: []string{"logic.azure.com", "api.powerplatform.com"}, note: noteWorkflow,
		mode: constMode("live"),
		re:   rx(`https://[a-z0-9.-]+\.(?:logic\.azure\.com|api\.powerplatform\.com)(?::443)?/[^\s"'<>]*?workflows/[0-9a-f]{32}/[^\s"'<>]*?[?&]sig=[A-Za-z0-9%_-]{20,}`)},
	{kind: "Google API key", hints: []string{"AIza"}, re: rx(`\bAIza[0-9A-Za-z_-]{35}`), mode: constMode("live")},
	{kind: "Google OAuth client secret", hints: []string{"GOCSPX-"}, re: rx(`\bGOCSPX-[A-Za-z0-9_-]{28}`), mode: constMode("live"), after: edgeB64URL},
	{kind: "Google OAuth refresh token", hints: []string{"1//0"}, re: rx(`1//0[A-Za-z0-9_-]{40,}`), mode: constMode("live"),
		before: deny("A-Za-z0-9/")},
	{kind: "Google OAuth access token", hints: []string{"ya29."}, re: rx(`\bya29\.[A-Za-z0-9_-]{30,}`), mode: constMode("")},
	{kind: "Microsoft Entra client secret", hints: []string{"Q~"}, re: rx(`[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}`), mode: constMode("live"),
		before: allowOnly("\\'\"\x60 \t\r\n>=:(,)"), after: allowOnly("\\'\"\x60 \t\r\n<),")},
	{kind: "Meta access token", pre: metaShape, re: rx(`EAA[A-Za-z0-9]{100,}`), mode: constMode(""), valid: strictToken,
		before: edgeB64Before, after: edgeB64After},
	{kind: "SendGrid API key", hints: []string{"SG."}, re: rx(`\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`), mode: constMode("live")},
	{kind: "Mailgun API key", hints: []string{"key-"}, re: rx(`\bkey-[0-9a-f]{32}\b`), mode: constMode("live")},
	{kind: "Mailgun API key", pre: mailgunShape, re: rx(`[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8}`), mode: constMode("live"),
		before: edgeB64URL, after: edgeB64URL},
	{kind: "Mailchimp API key", hints: []string{"-us"}, re: rx(`\b[0-9a-f]{32}-us\d{1,2}\b`), mode: constMode("live")},
	{kind: "Brevo API key", hints: []string{"xkeysib-"}, re: rx(`\bxkeysib-[0-9a-f]{64}-[A-Za-z0-9]{16}\b`), mode: constMode("live")},
	{kind: "Twilio API key", hints: []string{"SK"}, re: rx(`\bSK[0-9a-f]{32}\b`), mode: constMode("live")},
	{kind: "Shopify access token", hints: []string{"shpat_", "shpca_", "shppa_", "shpss_"}, re: rx(`\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b`),
		mode: constMode("live")},
	{kind: "Postman API key", hints: []string{"PMAK-"}, re: rx(`\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b`), mode: constMode("live")},
	{kind: "Paddle API key", hints: []string{"pdl_"}, re: rx(`\bpdl_(live|sdbx)_apikey_[A-Za-z0-9_]{20,}`), mode: groupMode},
	{kind: "Square access token", hints: []string{"sq0atp-"}, re: rx(`\bsq0atp-[A-Za-z0-9_-]{22,}`), mode: constMode("live")},
	{kind: "Square access token", hints: []string{"EAAA"}, pre: squareShape, re: rx(`EAAA[A-Za-z0-9_-]{60}`), mode: constMode(""), valid: strictToken,
		before: edgeB64Before, after: edgeB64After},
	{kind: "Square application secret", hints: []string{"sq0csp-"}, re: rx(`\bsq0csp-[A-Za-z0-9_-]{40,}`), mode: constMode("live")},
	{kind: "Shippo API key", hints: []string{"shippo_"}, re: rx(`\bshippo_(live|test)_[a-f0-9]{40}`), mode: groupMode, after: deny("a-f0-9")},
	{kind: "EasyPost API key", hints: []string{"EZAK"}, re: rx(`\bEZAK[A-Za-z0-9]{54}`), mode: constMode("live"), after: deny("A-Za-z0-9")},
	{kind: "EasyPost API key", hints: []string{"EZTK"}, re: rx(`\bEZTK[A-Za-z0-9]{54}`), mode: constMode("test"), after: deny("A-Za-z0-9")},
	{kind: "Flutterwave secret key", hints: []string{"FLWSECK_TEST-"}, re: rx(`\bFLWSECK_TEST-[A-Za-z0-9]{32}-X`), mode: constMode("test")},
	{kind: "Flutterwave secret key", hints: []string{"FLWSECK-"}, re: rx(`\bFLWSECK-[A-Za-z0-9]{32}-X`), mode: constMode("live")},
	{kind: "Plaid access token", hints: []string{"access-sandbox-", "access-development-", "access-production-"}, mode: groupMode,
		re: rx(`\baccess-(sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), after: deny("0-9a-f")},
	{kind: "Midtrans server key", hints: []string{"SB-Mid-server-"}, re: rx(`SB-Mid-server-([A-Za-z0-9_-]{20,})`), mode: constMode("test"),
		valid: threeKinds, before: edgeB64URL},
	{kind: "Midtrans server key", hints: []string{"Mid-server-"}, re: rx(`Mid-server-([A-Za-z0-9_-]{20,})`), mode: constMode("live"),
		valid: threeKinds, before: edgeB64URL},
	{kind: "Login with Amazon token", hints: []string{"Atzr|"}, re: rx(`Atzr\|[A-Za-z0-9_-]{40,}`), mode: constMode("live")},
	{kind: "Login with Amazon token", hints: []string{"Atza|"}, re: rx(`Atza\|[A-Za-z0-9_-]{40,}`), mode: constMode("")},
	{kind: "Anthropic API key", hints: []string{"sk-ant-"}, re: rx(`\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{32,}`), mode: constMode("live")},
	{kind: "OpenAI API key", hints: []string{"T3BlbkFJ"}, re: rx(`\bsk-[A-Za-z0-9_-]{0,100}T3BlbkFJ[A-Za-z0-9_-]{10,}`), mode: constMode("live")},
	{kind: "OpenRouter API key", hints: []string{"sk-or-v1-"}, re: rx(`\bsk-or-v1-[A-Za-z0-9]{32,}`), mode: constMode("live")},
	{kind: "API key (sk- style)", hints: []string{"sk-"}, re: rx(`\bsk-([A-Za-z0-9_-]{32,})`), mode: constMode("live"), valid: skKey,
		unless: []string{"Anthropic API key", "OpenAI API key", "OpenRouter API key"}},
	{kind: "Groq API key", hints: []string{"gsk_"}, re: rx(`\bgsk_[A-Za-z0-9]{52}`), mode: constMode("live"), after: deny("A-Za-z0-9")},
	{kind: "Perplexity API key", hints: []string{"pplx-"}, re: rx(`\bpplx-[A-Za-z0-9]{48}`), mode: constMode("live"), after: deny("A-Za-z0-9")},
	{kind: "xAI API key", hints: []string{"xai-"}, re: rx(`\bxai-[A-Za-z0-9]{80}`), mode: constMode("live"), after: deny("A-Za-z0-9")},
	{kind: "Hugging Face token", hints: []string{"hf_"}, re: rx(`\bhf_([A-Za-z]{34})`), mode: constMode("live"), valid: mixedCase,
		after: deny("A-Za-z")},
	{kind: "Hugging Face token", hints: []string{"api_org_"}, re: rx(`\bapi_org_([A-Za-z]{34})`), mode: constMode("live"), valid: mixedCase,
		after: deny("A-Za-z")},
	{kind: "WooCommerce API key", hints: []string{"ck_", "cs_"}, re: rx(`\b(?:ck|cs)_[0-9a-f]{40}\b`), mode: constMode("live")},
	{kind: "PayPal/Braintree access token", hints: []string{"access_token$"}, mode: groupMode,
		re: rx(`\baccess_token\$(production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32}`)},
	{kind: "npm token", hints: []string{"npm_"}, re: rx(`\bnpm_[A-Za-z0-9]{36}`), mode: constMode("live"), after: deny("A-Za-z0-9")},
	{kind: "PyPI token", hints: []string{"pypi-AgEIcHlwaS5vcmc"}, re: rx(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`), mode: constMode("live")},
	{kind: "Atlassian API token", hints: []string{"ATATT3"}, re: rx(`\bATATT3[A-Za-z0-9_=-]{150,}`), mode: constMode("live")},
	{kind: "Docker token", hints: []string{"dckr_pat_", "dckr_oat_"}, re: rx(`\bdckr_(?:pat|oat)_[A-Za-z0-9_-]{20,}`), mode: constMode("live")},
	{kind: "Linear API key", hints: []string{"lin_api_"}, re: rx(`\blin_api_[A-Za-z0-9]{40}`), mode: constMode("live"), after: deny("A-Za-z0-9")},
	{kind: "Notion token", hints: []string{"ntn_"}, re: rx(`\bntn_[0-9]{11}[A-Za-z0-9]{35}`), mode: constMode("live"), after: deny("A-Za-z0-9")},
	{kind: "Airtable token", pre: airtableShape, re: rx(`\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}`), mode: constMode("live"), after: deny("a-f0-9")},
	{kind: "Figma token", hints: []string{"figd_"}, re: rx(`\bfigd_[A-Za-z0-9_-]{20,}`), mode: constMode("live")},
	{kind: "Typeform token", hints: []string{"tfp_"}, re: rx(`\btfp_[A-Za-z0-9_.=-]{40,}`), mode: constMode("live")},
	{kind: "DigitalOcean token", hints: []string{"dop_v1_", "doo_v1_", "dor_v1_"}, re: rx(`\bdo[opr]_v1_[a-f0-9]{64}`), mode: constMode("live"),
		after: deny("a-f0-9")},
	{kind: "Heroku API key", hints: []string{"HRKU-AA"}, re: rx(`\bHRKU-AA[0-9A-Za-z_-]{58}`), mode: constMode("live"), after: edgeB64URL},
	{kind: "Grafana token", hints: []string{"glsa_"}, re: rx(`\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`), mode: constMode("live"),
		after: deny("A-Fa-f0-9")},
	{kind: "Grafana token", hints: []string{"glc_"}, re: rx(`\bglc_[A-Za-z0-9+/]{32,}={0,2}`), mode: constMode("live")},
	{kind: "Sentry token", hints: []string{"sntrys_"}, re: rx(`\bsntrys_eyJpYXQiO[A-Za-z0-9+/=_-]{40,}`), mode: constMode("live")},
	{kind: "Sentry token", hints: []string{"sntryu_"}, re: rx(`\bsntryu_[a-f0-9]{64}`), mode: constMode("live"), after: deny("a-f0-9")},
	{kind: "New Relic key", hints: []string{"NRAK-"}, re: rx(`\bNRAK-[A-Z0-9]{27}`), mode: constMode("live"), after: deny("A-Z0-9")},
	{kind: "New Relic key", hints: []string{"NRII-"}, re: rx(`\bNRII-[A-Za-z0-9_-]{32}`), mode: constMode("live"), after: edgeB64URL},
	{kind: "Doppler token", hints: []string{"dp."}, mode: constMode("live"), after: deny("A-Za-z0-9"),
		re: rx(`\bdp\.(?:ct|pt|st(?:\.[a-z0-9_-]{2,35})?|sa|scim|audit)\.[A-Za-z0-9]{40,44}`)},
	{kind: "Vault token", hints: []string{"hvs."}, re: rx(`\bhvs\.[A-Za-z0-9_-]{90,120}`), mode: constMode("live"), after: edgeB64URL},
	{kind: "Vault token", hints: []string{"hvb."}, re: rx(`\bhvb\.[A-Za-z0-9_-]{138,300}`), mode: constMode("live"), after: edgeB64URL},
	{kind: "Terraform Cloud token", hints: []string{".atlasv1."}, re: rx(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}`),
		mode: constMode("live"), after: deny("A-Za-z0-9_=-")},
	{kind: "1Password service account token", hints: []string{"ops_eyJ"}, re: rx(`\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}`), mode: constMode("live")},
	{kind: "age secret key", hints: []string{"AGE-SECRET-KEY-1"}, re: rx(`AGE-SECRET-KEY-1[0-9A-Z]{58}`), mode: constMode("live"),
		after: deny("0-9A-Z")},
	{kind: "PlanetScale token", hints: []string{"pscale_"}, re: rx(`\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,64}`), mode: constMode("live"),
		after: deny("A-Za-z0-9_.-")},
	{kind: "Supabase key", hints: []string{"sbp_"}, re: rx(`\bsbp_[a-f0-9]{40}`), mode: constMode("live"), after: deny("a-f0-9")},
	{kind: "Supabase key", hints: []string{"sb_secret_"}, re: rx(`\bsb_secret_[A-Za-z0-9_-]{20,}`), mode: constMode("live")},
	{kind: "Databricks token", hints: []string{"dapi"}, re: rx(`\bdapi[a-f0-9]{32}(?:-\d)?`), mode: constMode("live"), after: deny("a-f0-9")},
	{kind: "Cloudflare Origin CA key", hints: []string{"v1.0-"}, re: rx(`\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}`), mode: constMode("live"),
		after: deny("a-f0-9")},
	{kind: "SAML message", hints: []string{"PHNhbW", "SAMLResponse="}, mode: constMode(""),
		re: rx(`PHNhbWxwOlJlc3BvbnNl|PHNhbWwycDpSZXNwb25z|PHNhbWw6QXNzZXJ0aW9u|PHNhbWwyOkFzc2VydGlv|SAMLResponse=[A-Za-z0-9%+/=]{100,}`)},
	{kind: "SAML message", hints: []string{"<saml"}, re: rx(`<saml2?p?:(?:Response|Assertion)\b`), mode: constMode(""), valid: samlRaw},
	{kind: "private key", hints: []string{"PRIVATE KEY"}, mode: constMode("live"),
		re: rx(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`)},
	{kind: "JSON Web Token", hints: []string{"eyJ"}, re: rx(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), mode: constMode("")},
	{kind: "password in a Basic Authorization header", hints: []string{"uthorization"}, fold: true, group: 1, mode: constMode("live"),
		re: rx(authLead + ci("basic") + `\s+([A-Za-z0-9+/]{8,}={0,2})`), valid: basicPassword},
	{kind: "password in a Basic Authorization header", pre: basicValue, group: 1, mode: constMode("live"),
		re: rx(`^` + ci("basic") + `[ \t]+([A-Za-z0-9+/]{8,}={0,2})\s*$`), valid: basicPassword},
	{kind: "password in a URL", pre: urlUserInfo, mode: constMode("live"), valid: urlPassword,
		re: rx(`\b[a-z][a-z0-9+.-]{1,15}://([^\s:@/?#"'<>\\]{0,64}):([^\s@/?#"'<>\\]{1,128})@([A-Za-z0-9.-]+)`)},
	// Fallbacks: a known format overlapping one of these is reported as itself. The
	// self-labelled key comes first, so a key with a mode wins over a bearer header.
	{kind: "self-labelled API key", hints: []string{"apikey", "api_key", "api-key"}, fold: true, mode: labelledMode,
		re:     rx(`((?:[A-Za-z0-9]+[_-]){0,4})` + ci("api") + `[_-]?` + ci("key") + `[_-]([A-Za-z0-9][A-Za-z0-9_-]{15,})`),
		before: deny("A-Za-z0-9"), valid: labelledKey,
		fallback: true},
	{kind: "bearer token in an Authorization header", hints: []string{"uthorization"}, fold: true, group: 1, mode: constMode(""),
		re: rx(authLead + ci("bearer") + `\s+([A-Za-z0-9._~+/=-]{20,})`), valid: bearerToken, fallback: true},
	{kind: "bearer token in an Authorization header", pre: bearerValue, group: 1, mode: constMode(""),
		re: rx(`^` + ci("bearer") + `[ \t]+([A-Za-z0-9._~+/=-]{20,})\s*$`), valid: bearerToken, fallback: true},
	{kind: "API key in a URL", hints: []string{"apikey=", "api_key=", "api-key=", "access_token=", "access-token=", "accesstoken=",
		"client_secret=", "client-secret=", "clientsecret="},
		fold: true, group: 1, mode: constMode(""), valid: queryKey, fallback: true,
		re: rx(`[?&](?:` + ci("api") + `[_-]?` + ci("key") + `|` + ci("access") + `[_-]?` + ci("token") + `|` +
			ci("client") + `[_-]?` + ci("secret") + `)=([^&#\s"'<>]{16,})`)},
}

// secretNotes maps each kind to what a copy would do.
var secretNotes = func() map[string]secretNote {
	m := map[string]secretNote{}
	for _, p := range secretPatterns {
		if p.note != noteNone {
			m[p.kind] = p.note
		}
	}
	return m
}()

// The prefilter: one pass over the value, ignoring ASCII case, finds which
// hints occur.
type hintScanner struct {
	hints  []string
	exact  []bool // confirmed with strings.Contains, case and all
	class  [256]uint8
	nclass int
	next   []int32
	term   []bool // states where a hint ends
	// rows and termRow hold the same table with each state as its row
	// offset (state * nclass), which spares the scan a multiplication.
	rows    []int32
	termRow []bool
	out     [][]int
}

const maxHints = 256

type hintSet [maxHints / 64]uint64

func (h *hintSet) set(i int)      { h[i/64] |= 1 << (i % 64) }
func (h *hintSet) has(i int) bool { return h[i/64]&(1<<(i%64)) != 0 }
func (h *hintSet) meets(o *hintSet) bool {
	for i := range h {
		if h[i]&o[i] != 0 {
			return true
		}
	}
	return false
}

func (h *hintSet) empty() bool {
	for _, w := range h {
		if w != 0 {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func newHintScanner(hints []string, exact []bool) *hintScanner {
	h := &hintScanner{hints: hints, exact: exact, nclass: 1}
	for _, s := range hints {
		for i := 0; i < len(s); i++ {
			if c := lowerASCII(s[i]); h.class[c] == 0 {
				h.class[c] = uint8(h.nclass)
				h.nclass++
			}
		}
	}
	for c := 'A'; c <= 'Z'; c++ {
		h.class[c] = h.class[c+'a'-'A']
	}
	// A trie of the lower-cased hints, then failure links, then a full
	// transition table.
	gotoTab := []map[uint8]int32{{}}
	h.out = [][]int{nil}
	for i, s := range hints {
		st := int32(0)
		for j := 0; j < len(s); j++ {
			c := h.class[lowerASCII(s[j])]
			nx, ok := gotoTab[st][c]
			if !ok {
				nx = int32(len(gotoTab))
				gotoTab = append(gotoTab, map[uint8]int32{})
				h.out = append(h.out, nil)
				gotoTab[st][c] = nx
			}
			st = nx
		}
		h.out[st] = append(h.out[st], i)
	}
	fail := make([]int32, len(gotoTab))
	h.next = make([]int32, len(gotoTab)*h.nclass)
	queue := []int32{}
	for c := 0; c < h.nclass; c++ {
		if nx, ok := gotoTab[0][uint8(c)]; ok {
			h.next[c] = nx
			queue = append(queue, nx)
		}
	}
	for len(queue) > 0 {
		st := queue[0]
		queue = queue[1:]
		h.out[st] = append(h.out[st], h.out[fail[st]]...)
		for c := 0; c < h.nclass; c++ {
			if nx, ok := gotoTab[st][uint8(c)]; ok {
				fail[nx] = h.next[int(fail[st])*h.nclass+c]
				h.next[int(st)*h.nclass+c] = nx
				queue = append(queue, nx)
			} else {
				h.next[int(st)*h.nclass+c] = h.next[int(fail[st])*h.nclass+c]
			}
		}
	}
	h.term = make([]bool, len(h.out))
	h.rows = make([]int32, len(h.next))
	h.termRow = make([]bool, len(h.next))
	for i, nx := range h.next {
		h.rows[i] = nx * int32(h.nclass)
	}
	for st, out := range h.out {
		h.term[st] = len(out) > 0
		h.termRow[st*h.nclass] = len(out) > 0
	}
	return h
}

func (h *hintScanner) scan(s string) (found hintSet) {
	rows, class, term, n := h.rows, &h.class, h.termRow, h.nclass
	row := 0
	for i := 0; i < len(s); i++ {
		row = int(rows[row+int(class[s[i]])])
		if term[row] {
			for _, k := range h.out[row/n] {
				found.set(k)
			}
		}
	}
	for w := range found {
		for bitsLeft := found[w]; bitsLeft != 0; bitsLeft &= bitsLeft - 1 {
			i := w*64 + bits.TrailingZeros64(bitsLeft)
			if h.exact[i] && !strings.Contains(s, h.hints[i]) {
				found[w] &^= 1 << (i % 64)
			}
		}
	}
	return found
}

var (
	hints, patternHints = func() (*hintScanner, []hintSet) {
		index := map[string]int{}
		var list []string
		var exact []bool
		per := make([]hintSet, len(secretPatterns))
		for i, p := range secretPatterns {
			for _, s := range p.hints {
				k, ok := index[s]
				if !ok {
					k = len(list)
					index[s] = k
					list = append(list, s)
					exact = append(exact, !p.fold)
				} else if p.fold {
					exact[k] = false
				}
				per[i].set(k)
			}
		}
		if len(list) > maxHints {
			panic("too many secret hints")
		}
		return newHintScanner(list, exact), per
	}()
)

func submatches(s string, loc []int) []string {
	m := make([]string, len(loc)/2)
	for i := range m {
		if loc[2*i] >= 0 {
			m[i] = s[loc[2*i]:loc[2*i+1]]
		}
	}
	return m
}

// FindSecrets returns the kinds of secrets that appear in s, once per kind,
// each with the strongest mode among its matches: live, then unknown, then
// test.
func FindSecrets(s string) []SecretHit { return findSecrets(s, true) }

// findSecrets is FindSecrets with the prefilter and the structural checks
// optional, so tests can check that they never change a result.
func findSecrets(s string, prefilter bool) []SecretHit {
	if len(s) < 12 {
		return nil
	}
	if strings.Contains(s, `\/`) {
		s = strings.ReplaceAll(s, `\/`, "/")
	}
	found := hints.scan(s)
	if prefilter && found.empty() && len(s) < 50 && !strings.Contains(s, "://") && !bearerValue(s) && !basicValue(s) {
		return nil
	}
	var hits []SecretHit
	var spans [][2]int
	for i := range secretPatterns {
		p := &secretPatterns[i]
		if prefilter && (len(p.hints) > 0 && !found.meets(&patternHints[i]) || p.pre != nil && !p.pre(s)) {
			continue
		}
		if p.unless != nil && hasKind(hits, p.unless) {
			continue
		}
		for _, mt := range p.matches(s) {
			if p.fallback && overlaps(spans, mt.span) {
				continue
			}
			spans = append(spans, mt.span)
			hits = addHit(hits, SecretHit{Kind: p.kind, Mode: p.mode(mt.m)})
		}
	}
	return hits
}

// patternMatch is one valid match: its submatches and the token's span.
type patternMatch struct {
	m    []string
	span [2]int
}

// matches returns p's matches in s whose edges and validator pass, up to 8.
func (p *secretPattern) matches(s string) []patternMatch {
	var out []patternMatch
	for _, loc := range p.re.FindAllStringSubmatchIndex(s, 8) {
		if loc[0] > 0 && !p.before.ok(s[loc[0]-1]) || loc[1] < len(s) && !p.after.ok(s[loc[1]]) {
			continue
		}
		m := submatches(s, loc)
		if p.valid != nil && !p.valid(s, m) {
			continue
		}
		out = append(out, patternMatch{m, [2]int{loc[2*p.group], loc[2*p.group+1]}})
	}
	return out
}

func hasKind(hits []SecretHit, kinds []string) bool {
	for _, h := range hits {
		for _, k := range kinds {
			if h.Kind == k {
				return true
			}
		}
	}
	return false
}

func overlaps(spans [][2]int, s [2]int) bool {
	for _, t := range spans {
		if s[0] < t[1] && t[0] < s[1] {
			return true
		}
	}
	return false
}

// addHit keeps one hit per kind, with the strongest mode.
func addHit(hits []SecretHit, h SecretHit) []SecretHit {
	for i := range hits {
		if hits[i].Kind == h.Kind {
			if modeRank(h.Mode) > modeRank(hits[i].Mode) {
				hits[i].Mode = h.Mode
			}
			return hits
		}
	}
	return append(hits, h)
}
