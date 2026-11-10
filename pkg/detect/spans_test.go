package detect

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// uEsc writes a JSON \u escape of four hex digits.
func uEsc(hex string) string { return `\` + "u" + hex }

// covered returns what each span covers, as kind=text, for test messages.
func covered(s string, spans []Span) []string {
	out := make([]string, len(spans))
	for i, sp := range spans {
		out[i] = sp.Kind + "=" + s[sp.Start:sp.End]
	}
	return out
}

// spanTexts runs the built-in finders and returns the spans of one kind.
func spanTexts(s, kind string) []string {
	var out []string
	for _, sp := range FindSpans(s, SpanFinders()) {
		if sp.Kind == kind {
			out = append(out, s[sp.Start:sp.End])
		}
	}
	return out
}

func checkSpans(t *testing.T, kind string, cases map[string][]string) {
	t.Helper()
	for in, want := range cases {
		got := spanTexts(in, kind)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s spans of %q = %q, want %q (all: %q)", kind, in, got, want, covered(in, FindSpans(in, SpanFinders())))
		}
	}
}

func TestSpanEmails(t *testing.T) {
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, fmt.Sprintf("user%d@mail.fixture.gr", i))
	}
	checkSpans(t, SpanEmail, map[string][]string{
		"Write to jane.doe@mail.fixture.gr, not logo@2x.png":     {"jane.doe@mail.fixture.gr"},
		"https://shop.fixture.gr/?u=jane%40mail.fixture.gr&x=1":  {"jane%40mail.fixture.gr"},
		"<a href=\"mailto:jane@mail.fixture.gr\">Jane</a>":       {"jane@mail.fixture.gr"},
		strings.Join(many, "; "):                                 many,
		"no address here, just @handles and 2@x":                 nil,
		"Write to müller@mail.fixture.de":                        {"müller@mail.fixture.de"},
		`{"note":"Line one\njane@mail.fixture.gr"}`:              {"jane@mail.fixture.gr"},
		`{"note":"caf` + uEsc("00e9") + `jane@mail.fixture.gr"}`: {`caf` + uEsc("00e9") + `jane@mail.fixture.gr`},
		`{"to":"jane` + uEsc("0040") + `mail.fixture.gr"}`:       {`jane` + uEsc("0040") + `mail.fixture.gr`},
		`{"s":"a\\"}, then jane@mail.fixture.gr`:                 {"jane@mail.fixture.gr"},
	})
	sp := FindSpans("ask a@example.com", SpanFinders())
	if len(sp) != 1 || sp[0].Detail != "reserved" {
		t.Errorf("reserved domain: %+v", sp)
	}
}

func TestSpanPhones(t *testing.T) {
	checkSpans(t, SpanPhone, map[string][]string{
		"Call +30 210 555 0123 now":                {"+30 210 555 0123"},
		"US office (555) 010-1234.":                {"(555) 010-1234"},
		"Mobile 07700 900123.":                     {"07700 900123"},
		"Athens 210 123 4567, Patras 2610 123456":  {"210 123 4567", "2610 123456"},
		"On 2024-01-02 210 123 4567 called":        {"210 123 4567"},
		"two: 210 123 4567 / 697 123 4567":         {"210 123 4567", "697 123 4567"},
		"dates 2024-01-02 and 02/01/2024 10:30":    nil,
		"server 192.168.10.20 and 1.234.567 units": nil,
		"ISBN 978-3-16-148410-0 in print":          nil,
		"card 4242 4242 4242 4242 on file":         nil,
		"order 123456, code 42":                    nil,
		"ref ID12345678 stays":                     nil,
		`{"tel":"x\n07700 900123"}`:                {"07700 900123"},
		"Call +447700900123 now":                   {"+447700900123"},
		"jane+447700900123@mail.fixture.gr":        nil,
		"+10.20.30.40 12345":                       nil,
		"card +4242 4242 4242 4242 on file":        nil,
		"Paris +33 6 12 34 56 78 now":              {"+33 6 12 34 56 78"},
		"+14155550123 2024-01-02":                  {"+14155550123"},
		"+30 210 555 0199 4242 4242 4242 4242":     {"+30 210 555 0199"},
	})
	for in, detail := range map[string]string{
		"+30 210 555 0123":        "strict",
		"07700 900123":            "loose",
		"+447700900123":           "strict",
		"+33 6 12 34 56 78":       "strict",
		"+14155550123 2024-01-02": "strict",
	} {
		if sp := FindSpans(in, SpanFinders()); len(sp) != 1 || sp[0].Detail != detail {
			t.Errorf("%q: %+v, want detail %s", in, sp, detail)
		}
	}
}

// strictPhones runs the strict finder alone: through FindSpans, the loose one
// would report what it misses.
func strictPhones(s string) []string {
	var out []string
	for _, sp := range findPhoneSpans(NewTextView(s)) {
		out = append(out, s[sp.Start:sp.End])
	}
	return out
}

func TestStrictPhones(t *testing.T) {
	for in, want := range map[string][]string{
		// No separators, one digit past what groups of four can take.
		"+447700900123":                  {"+447700900123"},
		"+306900000123":                  {"+306900000123"},
		"+442079460123 ok":               {"+442079460123"},
		"tel:+447700900123, mobile":      {"+447700900123"},
		"+447700900123 or +306900000123": {"+447700900123", "+306900000123"},
		`{"tel":"+447700900123"}`:        {"+447700900123"},
		// The same, in a run of digits after a separator.
		"+33 612345678":      {"+33 612345678"},
		"+49 30 12345":       {"+49 30 12345"},
		"+49 30 123456789":   {"+49 30 123456789"},
		"+30 1234 56789 012": {"+30 1234 56789 012"},
		"(210) 123456789":    {"(210) 123456789"},
		"+44 (20) 123456789": {"+44 (20) 123456789"},
		// Found before, and as whole as before.
		"+14155550123":       {"+14155550123"},
		"+44 7700 900123":    {"+44 7700 900123"},
		"(555) 010-1234":     {"(555) 010-1234"},
		"(210) 12345":        {"(210) 12345"},
		"+1 (415) 5550123":   {"+1 (415) 5550123"},
		"+1.415.555.0123":    {"+1.415.555.0123"},
		"+14155550123 phone": {"+14155550123"},
		// One digit after the country code: French and Dutch mobile numbers,
		// and the one-digit area codes of Sydney, Tokyo and Dublin.
		"+33 6 12 34 56 78":               {"+33 6 12 34 56 78"},
		"+33.6.12.34.56.78":               {"+33.6.12.34.56.78"},
		"+33-6-12-34-56-78":               {"+33-6-12-34-56-78"},
		"Call +33 6 12 34 56 78 today.":   {"+33 6 12 34 56 78"},
		"+33 (0)1 23 45 67 89":            {"+33 (0)1 23 45 67 89"},
		"+33 (0) 1 23 45 67 89":           {"+33 (0) 1 23 45 67 89"},
		"+33(0)1 23 45 67 89":             {"+33(0)1 23 45 67 89"},
		"+31 6 12345678":                  {"+31 6 12345678"},
		"+44 7 700 900 123":               {"+44 7 700 900 123"},
		"+61 2 9876 5432, +81 3 12345678": {"+61 2 9876 5432", "+81 3 12345678"},
		"+353 1 234 5678":                 {"+353 1 234 5678"},
		"+54 9 11 1234 5678":              {"+54 9 11 1234 5678"},
		"+54 9 11 12 34 56 78":            {"+54 9 11 12 34 56 78"},
		"+33 6-12-34-56-78":               {"+33 6-12-34-56-78"},
		"+33 (0)6.12.34.56.78":            {"+33 (0)6.12.34.56.78"},
		// One digit anywhere else, or with no number after it, isn't a group.
		"+33 6":              nil,
		"+33 6 123":          nil,
		"+1 (415) 555":       nil,
		"+1 2 3 4 5 6 7 8":   nil,
		"+30 210 5 55 01 23": nil,
		"(0) 1 23 45 67 89":  nil,
		"(210) 5 55 01 23":   nil,
		// A dot beside one digit on one side only is a number with decimals.
		"6722280709661868p+363 1.26301e+125": nil,
		"(-1.00000e+10-1.11000e+100i)":       nil,
		"+18.2-371 18.2-371":                 nil,
		"+12.5 1000 20":                      nil,
		"+3.5 25.00 12.50":                   nil,
		"100.0 +200.0 -300.0":                nil,
		// Two separators in a row aren't one.
		"+33 6  12 34 56 78": nil,
		"+33 6 - 12 34 56":   nil,
		// A number followed by other digits: it ends at a space before them.
		"+14155550123 2024-01-02":                               {"+14155550123"},
		"+447700900123 2024-01-02":                              {"+447700900123"},
		"+30 210 555 0123 2024-01-02":                           {"+30 210 555 0123"},
		"+30-210-555-0123 2024-01-02":                           {"+30-210-555-0123"},
		"(210) 555 0123 2024-01-02":                             {"(210) 555 0123"},
		"+14155550123 12345":                                    {"+14155550123"},
		"+30 210 555 0123 1234567890":                           {"+30 210 555 0123"},
		"+447700900123 12345678901234567890":                    {"+447700900123"},
		"+33 612345678 2024-01-02":                              {"+33 612345678"},
		"sms +14155550123 2024-01-02, +447700900123 2024-01-03": {"+14155550123", "+447700900123"},
		// What follows still counts where the whole can be a number.
		"+14155550123 12":   {"+14155550123 12"},
		"+14155550123 2024": {"+14155550123 2024"},
		// Before that space there's still no number.
		"+1234567 12345678901234":       nil,
		"+1234567890123456 12":          nil,
		"+44 12345678901234567890":      nil,
		"(210) 12345678901234 5678":     nil,
		"+9783161484100 12345":          nil,
		"+978 3161484100 12345":         nil,
		"+978 88 04 12345 3 12345":      nil,
		"+097 (7817) 12345678901234567": nil,
		"(30649)06 1234567890123456":    nil,
		// With no group left for the digits after it, a number stops short.
		"+1 20 20 20 20 12345": {"+1 20 20 20 20"},
		// A digit next to the number makes it part of something longer.
		"1+447700900123":      nil,
		"+1234567890123456":   nil,
		"(210) 1234567890123": nil,
		// ISBNs, whole or with a check digit the pattern can't take. A plus
		// comes from a URL's space, a number in parentheses from a label.
		"+9783161484100":           nil,
		"+978 3161484100":          nil,
		"(978) 3161484100":         nil,
		"(978)3161484100":          nil,
		"+978-3-16-148410-0":       nil,
		"(978-3-16-148410-0)":      nil,
		"q=isbn+978-88-04-12345-3": nil,
		"q=isbn+978-88-12345-67-0": nil,
		"q=isbn+978-88-045-1234-9": nil,
		"+978 88 04 12345 3":       nil,
		"(13) 9783161484100":       nil,
		"+13 9783161484100":        nil,
		"(13) 978-88-04-12345-3":   nil,
		"+978-1-4028-9462-6":       nil,
		"+978-0-306-40615-7":       nil,
		"+978 0 306 40615 7":       nil,
		// With a wrong check digit, none of them is an ISBN.
		"+9783161484101":     {"+9783161484101"},
		"+978 88 04 12345 4": {"+978 88 04 12345"},
		// Dates.
		"(2024-01-15)":              nil,
		"(15/01/2024)":              nil,
		"+15/01/2024":               nil,
		"2024-01-15T10:30:00+0200":  nil,
		"2024-01-15 10:30:00 +0200": nil,
		"+2024-01-15 123456789":     nil,
		"+2024-01-15":               nil,
		"+15.01.2024":               nil,
		"+15.1.2024":                nil,
		"+15-1-2024":                nil,
		"+15.1.2024 12345678901":    nil,
		"+5.1.2024":                 nil,
		"+2024-1-15":                nil,
		// IP addresses.
		"(192.168.100.200)":   nil,
		"+10.0.0.1":           nil,
		"+10.1.20.30":         nil,
		"+192.168.100.200":    nil,
		"10.0.0.1+1234567890": nil,
		"(2001:db8::1)":       nil,
		"+2001:db8::1":        nil,
		// Cards.
		"+4242424242424242":   nil,
		"(4242) 424242424242": nil,
	} {
		if got := strictPhones(in); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("strict phones of %q = %q, want %q", in, got, want)
		}
	}
}

// TestStrictPhoneLengths checks every length of a run of digits after each way
// a number can start: the whole run from the fewest digits a strict number has
// to the 15 a phone number can have, and nothing outside those.
func TestStrictPhoneLengths(t *testing.T) {
	const digits = "447700900123456789012345678901234567"
	for _, c := range []struct {
		start  string
		lo, hi int
	}{
		{"+", 8, 15},
		{"+44 ", 6, 13},
		{"+44-", 6, 13},
		{"(210) ", 4, 12},
		{"(210)", 4, 12},
		{"+44 (20) ", 4, 11},
		{"+33 6 ", 4, 12},
		{"+33 (0)6 ", 4, 11},
	} {
		for n := 1; n <= len(digits); n++ {
			in := c.start + digits[:n]
			var want []string
			if n >= c.lo && n <= c.hi {
				want = []string{in}
			}
			if got := strictPhones(in); strings.Join(got, "|") != strings.Join(want, "|") {
				t.Errorf("strict phones of %q (%d digits after the start) = %q, want %q", in, n, got, want)
			}
			if got := strictPhones("call " + in + " now"); strings.Join(got, "|") != strings.Join(want, "|") {
				t.Errorf("strict phones of %q in text = %q, want %q", in, got, want)
			}
		}
	}
}

// TestLoosePhonesFilteredInTheirFinder checks what FindSpans's doc says: a
// caller that keeps only some loose phones filters them in their finder,
// and the ones it drops then hide nothing.
func TestLoosePhonesFilteredInTheirFinder(t *testing.T) {
	s := "SSN on file: 123-45-6789"
	ssn := SpanFinder{Kind: "national_id", Find: func(s string) []Span {
		var out []Span
		for _, loc := range regexp.MustCompile(`\d{3}-\d{2}-\d{4}`).FindAllStringIndex(s, -1) {
			out = append(out, Span{Start: loc[0], End: loc[1], Kind: "national_id"})
		}
		return out
	}}
	finders := SpanFinders()
	if got := covered(s, FindSpans(s, append(finders, ssn))); strings.Join(got, "|") != "phone=123-45-6789" {
		t.Fatalf("unfiltered: %q", got)
	}
	last := len(finders) - 1
	if finders[last].Kind != SpanLoosePhone {
		t.Fatalf("the loose phone finder isn't last: %s", finders[last].Kind)
	}
	loose := finders[last].FindView
	finders[last] = SpanFinder{Kind: SpanLoosePhone, FindView: func(v *TextView) []Span {
		var out []Span
		for _, sp := range loose(v) {
			if strings.HasSuffix(v.Text[sp.Start:sp.End], "0123") { // a known number
				out = append(out, sp)
			}
		}
		return out
	}}
	if got := covered(s, FindSpans(s, append(finders, ssn))); strings.Join(got, "|") != "national_id=123-45-6789" {
		t.Errorf("filtered: %q", got)
	}
}

func TestSpanIBANs(t *testing.T) {
	checkSpans(t, SpanIBAN, map[string][]string{
		"IBAN GB82 WEST 1234 5698 7654 32 BIC NWBKGB2L": {"GB82 WEST 1234 5698 7654 32"},
		"pay to DE89370400440532013000.":                {"DE89370400440532013000"},
		"Norway: NO9386011117947":                       {"NO9386011117947"},
		"lower case gb82west12345698765432":             {"gb82west12345698765432"},
		"wrong check digits GB82WEST12345698765433":     nil,
		"too short for the country DE8937040044053201":  nil,
		`{"iban":"IBAN\nGB82WEST12345698765432"}`:       {"GB82WEST12345698765432"},
	})
}

func TestSpanCards(t *testing.T) {
	real := luhnNumber("491761234567890")
	checkSpans(t, SpanCard, map[string][]string{
		"card 4242 4242 4242 4242 exp 12/29":    {"4242 4242 4242 4242"},
		"paid with " + real + " yesterday":      {real},
		"4242 4242 4242 4242 123 is the code":   {"4242 4242 4242 4242"},
		"ref 12 4242-4242-4242-4242":            {"4242-4242-4242-4242"},
		"bad checksum 4242 4242 4242 4241":      nil,
		"order id 1234567812345670":             nil,
		`{"note":"Card:\n4242 4242 4242 4242"}`: {"4242 4242 4242 4242"},
		`Card:\t4111111111111111`:               {"4111111111111111"},
	})
	if sp := FindSpans("4242 4242 4242 4242", SpanFinders()); len(sp) != 1 || sp[0].Detail != "test" {
		t.Errorf("test card: %+v", sp)
	}
}

func TestSpanIPs(t *testing.T) {
	checkSpans(t, SpanIP, map[string][]string{
		"login from 203.0.113.7 at noon":            {"203.0.113.7"},
		"XFF: 10.0.0.1, 198.51.100.20":              {"10.0.0.1", "198.51.100.20"},
		"v6 2001:db8::1 and fe80::1%eth0 here":      {"2001:db8::1", "fe80::1"},
		"mapped 2001:db8::192.0.2.1 is one address": {"2001:db8::192.0.2.1"},
		"local 127.0.0.1, ::1 and 0.0.0.0":          nil,
		"version 1.8.5.4 and 1.2.3.4.5":             nil,
		"Foo::bad() at 10:30:45, a::before":         nil,
		`{"ip":"from\n203.0.113.7"}`:                {"203.0.113.7"},
	})
}

func TestSpanSecrets(t *testing.T) {
	g := newTokGen(40)
	var keys []string
	for i := 0; i < 20; i++ {
		keys = append(keys, "sk_"+"live_"+g.of(tAlnum, 24))
	}
	if got := spanTexts(strings.Join(keys, ", "), SpanSecret); strings.Join(got, "|") != strings.Join(keys, "|") {
		t.Errorf("20 keys in one value: got %d spans", len(got))
	}

	// JSON-escaped slashes: the span covers the escaped URL whole.
	url := `https:\/\/hoo` + `ks.slack.com\/services\/T` + g.of(tUpper+tDigit, 8) + `\/B` + g.of(tUpper+tDigit, 8) + `\/` + g.of(tAlnum, 24)
	v := `{"hook":"` + url + `","on":true}`
	if got := spanTexts(v, SpanSecret); len(got) != 1 || got[0] != url {
		t.Errorf("escaped webhook URL: got %q", got)
	}

	// unless skips a generic sk- key in the scan when a specific one is in
	// the value; spans resolve it by overlap, so both are found.
	ant := "sk-" + "ant-api03-" + g.of(tB64U, 40)
	generic := "sk-" + g.mixed(tAlnum, 40)
	v = ant + " and " + generic
	if hits := hitsString(FindSecrets(v)); hits != "Anthropic API key (live)" {
		t.Fatalf("FindSecrets = [%s]", hits)
	}
	sp := FindSpans(v, SpanFinders())
	if len(sp) != 2 || v[sp[0].Start:sp[0].End] != ant || sp[0].Detail != "Anthropic API key" ||
		v[sp[1].Start:sp[1].End] != generic || sp[1].Detail != "API key (sk- style)" {
		t.Errorf("unless pair: %q", covered(v, sp))
	}

	// A Basic credential: only the encoded part is the secret.
	cred := b64("svc:" + g.mixed(tAlnum, 12))
	v = "Authorization: Basic " + cred
	if got := spanTexts(v, SpanSecret); len(got) != 1 || got[0] != cred {
		t.Errorf("Basic credential: got %q", got)
	}
}

// TestSpanStatelessGitHub checks that GitHub's stateless installation token is
// one span from its prefix to the end of its signature, past the JWT's dots and
// base64url's hyphens, wherever it is kept, so a copy clears it whole. A token
// in a URL's password place is the secret finder's, and no address's.
func TestSpanStatelessGitHub(t *testing.T) {
	g := newTokGen(43)
	tok, other, old := g.statelessToken(), g.statelessToken(), "gh"+"s_"+g.of(tAlnum, 36)
	one := func(v, want string) {
		t.Helper()
		sp := FindSpans(v, SpanFinders())
		if len(sp) != 1 || v[sp[0].Start:sp[0].End] != want || sp[0].Kind != SpanSecret || sp[0].Detail != "GitHub token" || sp[0].Mode != "live" {
			t.Errorf("%.30q: %+v, want one span of %d bytes", v, sp, len(want))
		}
	}
	for _, v := range statelessForms(tok) {
		one(v, tok)
	}
	// Cut short, the span is what is left, wherever the cut falls.
	for _, n := range []int{40, 96, 300, 519} {
		one(tok[:n], tok[:n])
	}
	// A dot or a hyphen after an older token isn't taken with it.
	one("the token is "+old+".", old)
	one(old+"-suffix", old)
	checkSpans(t, SpanSecret, map[string][]string{
		tok + "," + other:                                   {tok, other},
		"old " + old + " new " + tok + ".":                  {old, tok},
		`{"a":"` + tok + `","b":"` + other + `","c":"x y"}`: {tok, other},
	})
}

// TestSpanBasicKeys checks that a key inside a Basic credential makes the
// whole encoded credential a span, named after the key, with the strongest
// mode the credential holds.
func TestSpanBasicKeys(t *testing.T) {
	for i, c := range basicKeyCases() {
		cred := b64(c.cred)
		for _, v := range basicForms(cred) {
			sp := FindSpans(v, SpanFinders())
			if len(sp) != 1 || v[sp[0].Start:sp[0].End] != cred || sp[0].Kind != SpanSecret || sp[0].Detail != c.detail || sp[0].Mode != c.mode {
				t.Errorf("case %d in %.20q: %+v, want the credential, %s (%s)", i, v, sp, c.detail, c.mode)
			}
		}
	}
	// A key that overlaps a credential the scan doesn't count is cleared with
	// it, and doesn't read as a placeholder.
	enc := b64("deploybot")
	key := enc + "-api" + "key-" + newTokGen(44).mixed(tAlnum, 32)
	if sp := FindSpans("Authorization: Basic "+key, SpanFinders()); len(sp) != 1 || sp[0].End-sp[0].Start != len(key) || sp[0].Detail == "placeholder" {
		t.Errorf("a key over a placeholder credential: %+v", sp)
	}
}

func TestSpanURLPasswords(t *testing.T) {
	g := newTokGen(41)
	pw := g.mixed(tAlnum, 14)
	checkSpans(t, SpanURLPassword, map[string][]string{
		"DSN mysql://app:" + pw + "@db.internal-host.gr/shop":                 {pw},
		`{"dsn":"mysql:\/\/app:` + pw + `@db.internal-host.gr\/shop"}`:        {pw},
		"weak mysql://root:password@db.internal-host.gr/app":                  {"password"},
		"same mysql://admin:admin@db.internal-host.gr/app":                    {"admin"},
		"example host smtp://mailer:" + pw + "@mail.example.com":              {pw},
		"no user info https://shop.fixture.gr/cart?u=jane@mail.fixture.gr ok": nil,
		// An @ in the user or the password, plain or as %40: the last one
		// before the path ends the password, at any host.
		"mysql://app:%40" + pw + "@db.internal-host.gr/shop":     {"%40" + pw},
		"mysql://app:%40" + pw + "@db/shop":                      {"%40" + pw},
		"mysql://app:ab%40" + pw + "@db/shop":                    {"ab%40" + pw},
		"mysql://app:%21" + pw + "@db/shop":                      {"%21" + pw},
		"mysql://app:ab@" + pw + "@db/shop":                      {"ab@" + pw},
		"mysql://jane%40corp.gr:" + pw + "@db/shop":              {pw},
		"mysql://jane@corp.gr:" + pw + "@db/shop":                {pw},
		`{"dsn":"mysql:\/\/app:%40` + pw + `@db\/shop"}`:         {"%40" + pw},
		`{"dsn":"mysql:\/\/app:` + pw + uEsc("0040") + `db\/x"}`: {pw},
		"https://jane@mail.fixture.gr:8443/account":              nil,
		"ssh://git@git.fixture-host.gr:2222/shop.git":            nil,
		"https://shop.fixture.gr:8443/cart@home":                 nil,
	})
	// The email finder leaves what the password takes, and the user's address.
	checkSpans(t, SpanEmail, map[string][]string{
		"mysql://app:%40" + pw + "@db.internal-host.gr/shop":         nil,
		"mysql://jane%40corp.gr:" + pw + "@db.internal-host.gr/shop": {"jane%40corp.gr"},
		"mysql://jane@corp.gr:" + pw + "@db.internal-host.gr/shop":   {"jane@corp.gr"},
		"https://jane@mail.fixture.gr:8443/account":                  {"jane@mail.fixture.gr"},
	})
	// Placeholders, a password equal to its user and example hosts are
	// found, for a copy to clear, but marked: the scan doesn't count them.
	for in, detail := range map[string]string{
		"mysql://root:password@db.internal-host.gr/app": "placeholder",
		"mysql://app:" + pw + "@db.internal-host.gr/x":  "",
		"mysql://app:%40" + pw + "@db/x":                "",
		"mysql://app:%7Bpassword%7D@db/x":               "placeholder",
		"mysql://app:%24PASSWORD@db/x":                  "placeholder",
		"mysql://app:%PASS%@db/x":                       "placeholder",
		"mysql://app:%40" + pw + "@db.example.com/x":    "placeholder",
		"mysql://%40b:@B@db/x":                          "placeholder",
	} {
		sp := FindSpans(in, SpanFinders())
		if len(sp) != 1 || sp[0].Kind != SpanURLPassword || sp[0].Detail != detail {
			t.Errorf("%q: %+v", in, sp)
		}
	}
}

func TestSpanHashes(t *testing.T) {
	salt := strings.Repeat("aB3./", 11)[:53]
	bcrypt := "$2y$10$" + salt
	phpass := "$P$B" + strings.Repeat("x7Y", 10)
	escaped := strings.ReplaceAll(bcrypt, "/", `\/`)
	checkSpans(t, SpanPasswordHash, map[string][]string{
		"hash=" + bcrypt + ";":             {bcrypt},
		"old " + phpass + " and " + bcrypt: {phpass, bcrypt},
		"too long " + bcrypt + "x":         nil,
		`{"pass":"` + escaped + `"}`:       {escaped},
	})
}

// TestFindSpansOverlaps checks the order: earlier finders win, then longer
// spans; spans a finder gets wrong are dropped.
func TestFindSpansOverlaps(t *testing.T) {
	s := "0123456789"
	finders := []SpanFinder{
		{Kind: "a", Find: func(string) []Span { return []Span{{Start: 2, End: 6, Kind: "a"}} }},
		{Kind: "b", Find: func(string) []Span {
			return []Span{{Start: 0, End: 10, Kind: "b"}, {Start: 6, End: 8, Kind: "b"}, {Start: 7, End: 9, Kind: "b"},
				{Start: -1, End: 2, Kind: "b"}, {Start: 5, End: 5, Kind: "b"}, {Start: 8, End: 100, Kind: "b"}}
		}},
		{Kind: "c", Find: func(string) []Span { return []Span{{Start: 0, End: 2, Kind: "c"}, {Start: 8, End: 10, Kind: "c"}} }},
	}
	got := strings.Join(covered(s, FindSpans(s, finders)), " ")
	if want := "c=01 a=2345 b=67 c=89"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestTextView(t *testing.T) {
	s := `a\"b\\c\/d` + uEsc("00e9") + `e` + uEsc("d83d") + uEsc("de00") + `f\nGH%40i\x\`
	v := NewTextView(s)
	if want := "a\"b\\c/d" + "é" + "e" + "😀" + "f\nGH@i\\x\\"; v.Text != want {
		t.Fatalf("Text %q, want %q", v.Text, want)
	}
	// A span over part of what an escape stands for widens to the escape.
	i := strings.Index(v.Text, "é")
	if sp := v.Span(Span{Start: i + 1, End: i + 2}); s[sp.Start:sp.End] != uEsc("00e9") {
		t.Errorf("inside an escape: %q", s[sp.Start:sp.End])
	}
	i = strings.Index(v.Text, "😀")
	if sp := v.Span(Span{Start: i, End: i + 4}); s[sp.Start:sp.End] != uEsc("d83d")+uEsc("de00") {
		t.Errorf("a surrogate pair: %q", s[sp.Start:sp.End])
	}
	i = strings.Index(v.Text, "GH@i")
	if sp := v.Span(Span{Start: i, End: i + 4}); s[sp.Start:sp.End] != "GH%40i" {
		t.Errorf("after escapes: %q", s[sp.Start:sp.End])
	}
	if v := NewTextView("plain"); v.Text != "plain" || v.Span(Span{Start: 1, End: 3}) != (Span{Start: 1, End: 3}) {
		t.Error("a view without escapes")
	}
}

// TestSpansCoverFindSecrets checks that every kind FindSecrets reports for a
// value of the test corpus is among the span finders' matches.
func TestSpansCoverFindSecrets(t *testing.T) {
	for i, v := range allTestValues() {
		want := FindSecrets(v)
		if len(want) == 0 {
			continue
		}
		got := map[string]bool{}
		view := NewTextView(v)
		for _, m := range secretMatches(view.Text) {
			got[secretPatterns[m.pattern].kind] = true
		}
		if len(findURLPasswordSpans(view)) > 0 {
			got[urlPasswordKind] = true
		}
		for _, h := range want {
			if !got[h.Kind] {
				t.Errorf("value %d: FindSecrets reports %s, the span finders don't", i, h.Kind)
			}
		}
	}
}

func TestKeep(t *testing.T) {
	// Loose phones a caller drops don't hide a later finder's span, whether
	// FindSpans calls Find or FindView.
	finders := SpanFinders()
	for i, f := range finders {
		if f.Kind == SpanLoosePhone {
			finders[i] = f.Keep(func(string, Span) bool { return false })
		}
	}
	id := SpanFinder{Kind: "national_id", Find: func(s string) []Span {
		if i := strings.Index(s, "123-45-6789"); i >= 0 {
			return []Span{{Start: i, End: i + 11, Kind: "national_id"}}
		}
		return nil
	}}
	if got := FindSpans("SSN on file: 123-45-6789", append(finders, id)); len(got) != 1 || got[0].Kind != "national_id" {
		t.Errorf("spans %+v", got)
	}
	// keep gets the text the finder read, and the span by its offsets.
	var seen []string
	email := SpanFinders()[3].Keep(func(text string, sp Span) bool {
		seen = append(seen, text[sp.Start:sp.End])
		return true
	})
	if email.Kind != SpanEmail {
		t.Fatalf("the fourth finder is %s", email.Kind)
	}
	FindSpans("mail jane%40fixture.gr", []SpanFinder{email})
	email.Find("mail jane%40fixture.gr")
	if strings.Join(seen, "|") != "jane@fixture.gr|jane%40fixture.gr" {
		t.Errorf("keep saw %q", seen)
	}
}

// TestFallbacksLast checks that fallback patterns come after every other,
// which secretMatches relies on.
func TestFallbacksLast(t *testing.T) {
	seen := false
	for _, p := range secretPatterns {
		if p.fallback {
			seen = true
		} else if seen {
			t.Errorf("%s comes after a fallback", p.kind)
		}
	}
}

func TestKnownWord(t *testing.T) {
	for _, w := range []string{"billing", "Phone", "name", "mobile", "email", "address"} {
		if !KnownWord(w) {
			t.Errorf("KnownWord(%q) = false", w)
		}
	}
	for _, w := range []string{"maria", "rossi7", "zq7canary4x", ""} {
		if KnownWord(w) {
			t.Errorf("KnownWord(%q) = true", w)
		}
	}
}

func FuzzFindSpans(f *testing.F) {
	g := newTokGen(42)
	for _, c := range positiveCases() {
		f.Add(c.in)
	}
	f.Add(`{"u":"https:\/\/app:` + g.mixed(tAlnum, 12) + `@db.fixture-host.gr\/x","m":"jane%40mail.fixture.gr"}`)
	f.Add("+30 210 555 0123, 07700 900123, GB82 WEST 1234 5698 7654 32, 4242 4242 4242 4242, 2001:db8::1")
	f.Add("%40%40@%40x.gr \\/\\/ 1.2.3.4.5 ::::")
	f.Add(`{"n":"Line\n4242 4242 4242 4242\tjane@x.gr\\"}`)
	f.Add("Authorization: Basic " + b64("sk_"+"live_"+g.of(tAlnum, 24)+":"))
	f.Add("mysql://jane%40corp.gr:%40" + g.mixed(tAlnum, 12) + "@db/x?u=a%40b.gr")
	f.Add("app:" + g.mixed(tAlnum, 12) + "%40tcp(db:3306)/x,b:" + g.mixed(tAlnum, 12) + "@unix(/run/x)/y")
	f.Add("mysql://app:" + g.mixed(tAlnum, 12) + ",sk_" + "live_" + g.of(tAlnum, 24) + "@db/x")
	f.Add("mysql://app:ab/" + g.mixed(tAlnum, 12) + "?c#d'e%40db/x,https://shop:port/u@x.gr")
	f.Fuzz(func(t *testing.T, s string) {
		v := NewTextView(s)
		prev := 0
		for _, sp := range FindSpans(s, SpanFinders()) {
			if sp.Start < prev || sp.Start >= sp.End || sp.End > len(s) {
				t.Fatalf("span %+v out of order or bounds (previous end %d, length %d)", sp, prev, len(s))
			}
			prev = sp.End
			// No span starts or ends inside an escape.
			for _, e := range v.esc {
				for _, at := range []int{sp.Start, sp.End} {
					if at > e.o && at < e.o+e.on {
						t.Fatalf("span %+v splits the escape at %d", sp, e.o)
					}
				}
			}
		}
	})
}
