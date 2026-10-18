package detect

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// pwKind is what a value could be when it is stored under a password's
// name: typed as is, a hash in a known format, or a hash-shaped string.
type pwKind uint8

const (
	pwNone       pwKind = iota // can't be a typed password: flags, emails, prose, field names
	pwToken                    // one token that could have been typed
	pwDigits                   // 4 to 12 digits: a PIN or a numeric password
	pwPhrase                   // a few words, as passphrases are
	pwReversible               // {cipher}…, ENC(…): decrypts to the credential
	pwNamed                    // a hash format with a marker: $2y$…, {SSHA}…, *<hex>
	pwHexDigest                // 32, 40, 64 or 128 hex digits
	pwB64Digest                // padded base64 of a digest's length
	pwDES                      // 13 crypt characters
	pwOther                    // other hash shapes
	pwShortHex                 // 16 to 31 hex digits and nothing else
	pwKinds
)

var (
	reMySQLPassword = regexp.MustCompile(`^\*[0-9A-F]{40}$`)
	reASPNetHash    = regexp.MustCompile(`^(?:A[A-Za-z0-9+/]{65}==|AQAAAA[A-Za-z0-9+/]{76}==)$`)
	reScheme        = regexp.MustCompile(`^\{([A-Za-z0-9._-]{1,32})\}(.+)$`)
	reJasypt        = regexp.MustCompile(`^ENC\(.+\)$`)
	reB64Digest     = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{22}==|[A-Za-z0-9+/]{27}=|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)$`)
	reDES           = regexp.MustCompile(`^[./0-9A-Za-z]{13}$`)
	reLongHex       = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	reHexOnly       = regexp.MustCompile(`^[0-9a-fA-F]{16,31}$`)
	reCryptTail     = regexp.MustCompile(`^[A-Za-z0-9./+=]{20,}$`)
	reSchemeTail    = regexp.MustCompile(`^[A-Za-z0-9./+=$]{20,}$`)
	reSlug          = regexp.MustCompile(`^[a-z]+(?:[-_][a-z]+)+$`)
	reCSSValue      = regexp.MustCompile(`^(?:#[0-9a-fA-F]{3,8}|(?:rgba?|hsla?)\(.*\)|[#.][A-Za-z_][\w-]*|\d+(?:\.\d+)?(?:px|em|rem|%|vh|vw|pt))$`)
	reYMD           = regexp.MustCompile(`^(?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])$`)
	reDigitsOnly    = regexp.MustCompile(`^\d+$`)
	reNumberList    = regexp.MustCompile(`^[\d\s.,:;/+-]+$`)
)

var (
	// Status words and algorithm names: what a setting about passwords
	// holds, never a password.
	statusWords = words("ok pass passed fail failed success error pending done valid invalid active inactive")
	algoWords   = words("md5 sha1 sha256 sha512 bcrypt argon2 argon2i argon2id pbkdf2 scrypt crypt des blowfish phpass " +
		"ssha plain plaintext cleartext hashed encrypted")
	redactWords = words("redacted filtered hidden removed masked censored")
	// Schemes that mark the rest of a value as plain text, or as text
	// encrypted with a key the app holds.
	plainSchemes      = words("plain clear cleartext noop")
	reversibleSchemes = words("cipher enc encrypted aes rsa base64 b64")
)

// pwClass classifies one value. format names a marked hash format that
// passwordHash doesn't know, for the "hash formats" reason.
func (p *Profile) pwClass(t string) (kind pwKind, format string) {
	if m := reScheme.FindStringSubmatch(t); m != nil {
		scheme, rest := strings.ToLower(m[1]), m[2]
		switch {
		case reversibleSchemes[scheme]:
			return pwReversible, ""
		case plainSchemes[scheme]:
			// The rest is plain text, judged as it stands: a prefix on it
			// isn't read again, so no value makes this recurse.
			if k, _ := p.pwClassBare(rest); k == pwToken || k == pwDigits || k == pwPhrase {
				return k, ""
			}
			return pwToken, ""
		case passwordHash(rest) != "" || reSchemeTail.MatchString(rest) || hashShaped(rest):
			return pwNamed, "LDAP scheme"
		}
		if k, _ := p.pwClassBare(rest); k == pwNone {
			return pwNone, "" // a lock mark, or nothing, as in {CRYPT}!
		}
	}
	return p.pwClassBare(t)
}

// pwClassBare classifies a value without a scheme prefix. The digest and
// crypt shapes come before the values no one types: a DES hash or a base64
// digest can start with "/" or "." and a letter, like a path or a CSS
// class.
func (p *Profile) pwClassBare(t string) (kind pwKind, format string) {
	switch {
	case reJasypt.MatchString(t):
		return pwReversible, ""
	case passwordHash(t) != "":
		return pwNamed, ""
	case reMySQLPassword.MatchString(t):
		return pwNamed, "MySQL PASSWORD()"
	case reASPNetHash.MatchString(t):
		return pwNamed, "ASP.NET Identity"
	case reHex.MatchString(t):
		return pwHexDigest, ""
	case reB64Digest.MatchString(t):
		return pwB64Digest, ""
	case desShaped(t):
		return pwDES, ""
	case p.notTyped(t):
		return pwNone, ""
	case reDigitsOnly.MatchString(t):
		if len(t) < 4 || len(t) > 12 || (len(t) == 10 && t[0] == '1') || reYMD.MatchString(t) {
			return pwNone, "" // too short or long for a PIN, a Unix time or a YYYYMMDD date
		}
		return pwDigits, ""
	case reHexOnly.MatchString(t):
		return pwShortHex, ""
	case otherHash(t):
		return pwOther, ""
	case reNumberList.MatchString(t):
		return pwNone, ""
	case !strings.ContainsFunc(t, unicode.IsSpace):
		if len(t) >= 4 && len(t) <= 128 {
			return pwToken, ""
		}
	case len(t) <= 128 && len(strings.Fields(t)) >= 2:
		return pwPhrase, ""
	}
	return pwNone, ""
}

// hashShaped reports whether a value has the shape of a digest, a DES
// crypt or some other hash format.
func hashShaped(t string) bool {
	return reHex.MatchString(t) || reB64Digest.MatchString(t) || reHexOnly.MatchString(t) || otherHash(t) || desShaped(t)
}

// desShaped reports whether a value has a DES crypt's shape: 13 characters
// of the crypt alphabet, of two kinds or more, so a mask (XXXXXXXXXXXXX) or
// a number isn't one. Random crypt characters are almost never all of one
// kind.
func desShaped(t string) bool { return reDES.MatchString(t) && charKinds(t) >= 2 }

// otherHash matches hashes in formats the scanner can't name: a long run of
// hex digits (Gitea, MediaWiki's :B:salt:hex, hash:salt pairs), or parts
// split by $, | or } that end in a long run of crypt or base64 characters
// (htpasswd's $apr1$, Drupal 7's U$S$, Nextcloud's 1|$2y$, Werkzeug's
// pbkdf2:sha256:N$…). my$secret$pass is no hash.
func otherHash(t string) bool {
	if reLongHex.MatchString(t) || strings.HasPrefix(t, ":A:") || strings.HasPrefix(t, ":B:") {
		return true
	}
	if !strings.ContainsAny(t, "$|}") {
		return false
	}
	parts := strings.FieldsFunc(t, func(r rune) bool { return r == '$' || r == '|' || r == '}' })
	return len(parts) >= 2 && reCryptTail.MatchString(parts[len(parts)-1])
}

// notTyped reports whether a value can't be a password someone typed:
// flags, status words and algorithm names, masks and redaction markers,
// slugs, CSS values, dates, addresses, URLs and paths, field names,
// placeholders, the field's own name, and code identifiers.
func (p *Profile) notTyped(t string) bool {
	lower := strings.ToLower(t)
	inner := strings.Trim(lower, "<>[]()")
	switch {
	case flagWords[lower] || statusWords[lower] || algoWords[lower] || redactWords[inner]:
		return true
	case strings.Trim(t, "*\xe2\x80\xa2xX") == "": // asterisks, bullets or x's
		return true
	case reSlug.MatchString(t) || reCSSValue.MatchString(t) || reDate.MatchString(t):
		return true
	case IsEmail(t) || emailList(t) != nil || urlLike(t):
		return true
	case fieldName(t) || rePlaceholder.MatchString(t) || reACFKey.MatchString(t) || p.echo(t) || reCode.MatchString(t):
		return true
	}
	return false
}

// charKinds counts the kinds of character in a value: lower case, upper
// case, digits and others.
func charKinds(t string) int {
	var lower, upper, digit, other bool
	for _, r := range t {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

// maxPWMarks caps how many distinct one-kind tokens a profile tells apart.
const maxPWMarks = 512

// addPassword counts a value for password judgements.
func (p *Profile) addPassword(t string) {
	kind, format := p.pwClass(t)
	mixed := 0
	if charKinds(t) >= 2 {
		mixed = 1
	}
	p.pw[kind][mixed]++
	if kind == pwToken && mixed == 0 {
		h := fnv.New64a()
		h.Write([]byte(t))
		k := h.Sum64()
		if p.pwMarks == nil {
			p.pwMarks = map[uint64]int{}
		}
		if _, ok := p.pwMarks[k]; ok || len(p.pwMarks) < maxPWMarks {
			p.pwMarks[k]++
		}
	}
	if format != "" {
		if p.HashFormats == nil {
			p.HashFormats = map[string]int{}
		}
		p.HashFormats[format]++
	}
}

// pwRepeats counts the copies beyond the first of one-kind tokens that
// repeat three or more times: marks such as LOCKED or ldap that stand in
// for a password, which people don't type alike that often.
func (p *Profile) pwRepeats() int {
	n := 0
	for _, c := range p.pwMarks {
		if c >= 3 {
			n += c - 1
		}
	}
	return n
}

// Words that say whose password a name holds. A service word makes it a
// credential for another system, which can't log in with a hash; a name
// made only of password, people and login words is a user's own.
var (
	pwServiceWords = words("smtp mail email imap pop ftp sftp ssh db database datasource proxy api ldap")
	pwOwnWords     = words("password passwords pass hash hashed encrypted account accounts login")
	pwLoginTable   = words("account accounts login logins")
	pwTestWords    = words("sandbox test testmode demo")
)

type pwOwner int

const (
	pwOwn     pwOwner = iota // a user's own password
	pwService                // a credential for a server or an API
	pwOtherOwner
)

// passwordOwner says whose password a name holds. A service word counts in
// the name, the column or meta key, and the parent keys; in the table name
// only when no people or login word is there too, since mail and FTP
// servers keep their users' hashes in tables such as ftp_users.
func passwordOwner(tokens []string, st state) pwOwner {
	if anyIn(tokens, pwServiceWords) || anyIn(st.near, pwServiceWords) ||
		(anyIn(st.table, pwServiceWords) && !anyIn(st.table, peopleWords) && !anyIn(st.table, pwLoginTable)) {
		return pwService
	}
	for _, t := range tokens {
		if !pwOwnWords[t] && !peopleWords[t] && !isDigits(t) {
			return pwOtherOwner
		}
	}
	return pwOwn
}

// judgePassword judges a name that says a password is stored here, with no
// preset hint, from sampled values. Values typed as is make it critical:
// a password hash a copy must replace, in a user's own password column, or
// otherwise a secret. Without them, hashes back the name as before, and a
// service's credential is a secret. It reports false when today's checks
// for a secret's name should decide instead.
func judgePassword(f *model.Finding, nm *NameMatch, tokens []string, p *Profile, st state) bool {
	owner := passwordOwner(tokens, st)
	one := p.NonEmpty == 1
	// count gives the values of a kind that could be typed: a single value
	// must mix two kinds of character, so a mode or a number is no password.
	count := func(k pwKind) int {
		if one {
			return p.pw[k][1]
		}
		return p.pw[k][0] + p.pw[k][1]
	}
	all := func(k pwKind) int { return p.pw[k][0] + p.pw[k][1] }

	plain := count(pwToken) + count(pwReversible)
	if anyIn(tokens, words("passphrase")) {
		plain += count(pwPhrase)
	}
	if p.NonEmpty >= 3 {
		plain += all(pwDigits)
	}
	support := all(pwNamed)
	shapes := map[string]int{}
	if owner == pwService {
		// An app can't log in to a server or an API with a hash.
		plain += count(pwHexDigest) + count(pwB64Digest) + count(pwDES) + count(pwOther) + count(pwShortHex)
	} else {
		support += all(pwHexDigest) + all(pwB64Digest) + all(pwOther)
		shapes["base64 digest"], shapes["other hash format"] = all(pwB64Digest), all(pwOther)
		if owner == pwOwn {
			support += all(pwShortHex)
			shapes["other hash format"] += all(pwShortHex)
		} else {
			plain += count(pwShortHex)
		}
		if des := all(pwDES); des > 0 {
			// A whole column of DES hashes, beside other hashes and values
			// no one types, such as the * or ! of a locked account.
			if p.NonEmpty >= 2 && des+support+all(pwNone) == p.NonEmpty {
				support += des
				shapes["DES crypt"] = des
			} else {
				plain += count(pwDES)
			}
		}
	}

	// Beside hashes, a one-kind token repeated across rows is a mark that
	// stands in for a password (LOCKED, ldap). A path or a column without
	// hashes, such as a login log, can hold one person's password many times.
	if !one && !st.path && support > 0 {
		plain = max(plain-p.pwRepeats(), 0)
	}
	if (plain >= 2 && ratio(plain, p.NonEmpty) >= 0.05) || (one && plain == 1) {
		f.Sampled, f.Matched = p.NonEmpty, plain
		f.Confidence = model.ConfidenceHigh
		f.Severity = model.SeverityCritical
		if anyIn(tokens, pwTestWords) {
			f.Severity = model.SeverityHigh
		}
		f.Source += "+value"
		if support > 0 && nm.Category == model.CatPasswordHash {
			f.Reasons = append(f.Reasons, fmt.Sprintf("%d of %d sampled values match the password hash format", support, p.NonEmpty))
			addHashFormats(f, p, shapes)
		}
		f.Reasons = append(f.Reasons, fmt.Sprintf("%d of %d sampled values aren't password hashes: plain text or reversible encryption",
			plain, p.NonEmpty))
		if owner == pwOwn && !st.path && !st.setting && nm.Category == model.CatPasswordHash {
			f.Note = appendNote(f.Note, "a copy hands out working passwords; this column stores plain text, "+
				"so write the staging password as plain text too")
			return true
		}
		f.Category, f.Mask = model.CatSecret, model.CatSecret.Info().Mask
		f.Note = appendNote(f.Note, "a copy hands out working passwords")
		return true
	}

	if nm.Category != model.CatPasswordHash {
		return false // a secret's name: today's checks decide
	}
	f.Sampled, f.Matched = p.NonEmpty, support
	switch r := ratio(support, p.NonEmpty); {
	case r >= 0.5:
		f.Confidence = model.ConfidenceHigh
		f.Source += "+value"
	case support > 0:
		f.Confidence = model.ConfidenceMedium
		f.Source += "+value"
	case owner == pwService:
		// Like smtp_pass: a credential, whatever its encoding.
		f.Category, f.Mask = model.CatSecret, model.CatSecret.Info().Mask
		f.Severity = pickSeverity(nm.Severity, model.CatSecret)
		f.Matched = 0
		f.Confidence = model.ConfidenceMedium
		switch {
		case p.Flag == p.NonEmpty:
			f.Confidence = model.ConfidenceLow
			f.Note = appendNote(f.Note, "sampled values are all on/off flags")
		case labelLike(model.CatSecret, p):
			f.Confidence = model.ConfidenceLow
			f.Note = appendNote(f.Note, "sampled values look like field names, placeholders or flags")
		}
		return true
	default:
		f.Confidence = model.ConfidenceLow
		f.Note = appendNote(f.Note, "sampled values don't match the password hash format")
	}
	if support > 0 {
		f.Reasons = append(f.Reasons, fmt.Sprintf("%d of %d sampled values match the password hash format", support, p.NonEmpty))
		addHashFormats(f, p, shapes)
	}
	return true
}

// addHashFormats lists the hash formats behind a password hash finding:
// the marked ones, and the hash shapes that count for its name. The names
// are fixed, so no value text reaches a report.
func addHashFormats(f *model.Finding, p *Profile, shapes map[string]int) {
	var fs []string
	for name, n := range p.HashFormats {
		fs = append(fs, fmt.Sprintf("%s %d", name, n))
	}
	for name, n := range shapes {
		if n > 0 {
			fs = append(fs, fmt.Sprintf("%s %d", name, n))
		}
	}
	if len(fs) == 0 {
		return
	}
	sort.Strings(fs)
	f.Reasons = append(f.Reasons, "hash formats: "+strings.Join(fs, ", "))
}
