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
	})
	for in, detail := range map[string]string{"+30 210 555 0123": "strict", "07700 900123": "loose"} {
		if sp := FindSpans(in, SpanFinders()); len(sp) != 1 || sp[0].Detail != detail {
			t.Errorf("%q: %+v, want detail %s", in, sp, detail)
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
	})
	// Placeholders, a password equal to its user and example hosts are
	// found, for a copy to clear, but marked: the scan doesn't count them.
	for in, detail := range map[string]string{
		"mysql://root:password@db.internal-host.gr/app": "placeholder",
		"mysql://app:" + pw + "@db.internal-host.gr/x":  "",
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
