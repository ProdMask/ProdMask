package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// editCorpus holds structured values of the shapes the scan's fixtures and
// real sites hold.
func editCorpus() []string {
	inner := "a:1:{" + phpStr("email") + phpStr("jane@fixture.gr") + "}"
	cmd := `O:8:"SendMail":2:{` + phpStr("to") + phpStr("jane@fixture.gr") + phpStr("\x00SendMail\x00tries") + "i:3;}"
	return []string{
		`{"billing":{"email":"jane@fixture.gr","phone":"+30 210 555 0123"},"items":[{"sku":"A-1","qty":2}],"paid":true,"note":null}`,
		`{"url":"https:\/\/shop.fixture.gr\/cart","name":"Ren\u00e9e","n":-0,"big":1e400,"x":0.1000000000000000055511}`,
		`[{"id":1,"tags":["a","b"]},{"id":2,"tags":[]}]`,
		`{"customers":{"jane@fixture.gr":{"name":"Jane"},"12":{"note":"x"}},"lockouts":{"203.0.113.7":3}}`,
		`{"uuid":"1f0e","data":{"command":` + quoteJSON(cmd) + `},"tags":["a","b"],"n":5}`,
		"a:3:{" + phpStr("email") + phpStr("jane@fixture.gr") + phpStr("billing") + "a:1:{" + phpStr("phone") + phpStr("+30 210 555 0123") + "}" +
			phpStr("items") + "a:2:{i:0;" + phpStr("socks") + "i:1;i:42;}}",
		`O:8:"WC_Thing":2:{` + phpStr("\x00WC_Thing\x00secret") + phpStr("x") + phpStr("customer") + phpStr(inner) + "}",
		"a:2:{" + phpStr("customer") + phpStr(inner) + phpStr("cart") + phpStr(`{"k":{"line_total":12.5,"email":"jane@fixture.gr"}}`) + "}",
		`a:4:{s:1:"b";b:1;s:1:"d";d:0.5;s:1:"n";N;s:1:"r";r:1;}`,
		`C:11:"ArrayObject":` + fmt.Sprint(len(inner)) + ":{" + inner + "}",
		`a:1:{s:4:"suit";E:11:"Suit:Hearts";}`,
		"  " + `{"padded":"yes"}` + "\n",
	}
}

// editLeaves runs the editor without editing and returns the leaves.
func editLeaves(t *testing.T, s string) []Leaf {
	t.Helper()
	var out []Leaf
	got, edited, err := EditStructured(s, func(l Leaf) (string, bool) {
		l.Path = slices.Clone(l.Path)
		out = append(out, l)
		return "", false
	})
	if err != nil || edited || got != s {
		t.Fatalf("no edit on %q: edited %v, err %v, same %v", s, edited, err, got == s)
	}
	return out
}

func TestEditNoEditKeepsBytes(t *testing.T) {
	for _, s := range editCorpus() {
		editLeaves(t, s)
	}
}

// TestEditPathsMatchWalk checks that the editor's leaves have the paths and
// values Walk gives them, data keys at {} included.
func TestEditPathsMatchWalk(t *testing.T) {
	for _, s := range editCorpus() {
		var walked []string
		if !Walk(s, func(path []string, v string) { walked = append(walked, JoinPath(path)+"="+v) }) {
			t.Fatalf("Walk rejected %q", s)
		}
		var edited []string
		for _, l := range editLeaves(t, s) {
			switch l.Kind {
			case LeafKey:
				if keyIsData(l.Key) {
					edited = append(edited, JoinPath(extend(l.Path, keysPath))+"="+l.Key)
				}
			case LeafNull:
			default:
				edited = append(edited, JoinPath(l.Path)+"="+l.Value)
			}
		}
		if !slices.Equal(walked, edited) {
			t.Errorf("%q:\nWalk   %q\neditor %q", s, walked, edited)
		}
	}
}

// TestEditNestedNotWhole checks that fn never sees the leaves of a string
// that looks structured but isn't whole: the string is a leaf of its own.
func TestEditNestedNotWhole(t *testing.T) {
	s := `{"":{"k":"O:8:\"00000000\":1:{s:2:\"00\";"}}`
	var got []string
	for _, l := range editLeaves(t, s) {
		got = append(got, fmt.Sprintf("%d:%s", l.Kind, l.Value))
	}
	if want := []string{"5:", "5:k", `1:O:8:"00000000":1:{s:2:"00";`}; !slices.Equal(got, want) {
		t.Errorf("leaves %q, want %q", got, want)
	}
}

// editWith edits the leaves fn picks and fails the test on an error.
func editWith(t *testing.T, s string, fn func(Leaf) (string, bool)) string {
	t.Helper()
	out, _, err := EditStructured(s, fn)
	if err != nil {
		t.Fatalf("edit %q: %v", s, err)
	}
	return out
}

// valueEdit replaces the string leaf whose value is from.
func valueEdit(from, to string) func(Leaf) (string, bool) {
	return func(l Leaf) (string, bool) { return to, l.Kind == LeafString && l.Value == from }
}

func TestEditJSON(t *testing.T) {
	s := `{"a":"keep \u00e9 \/ me","b":"jane@fixture.gr","n":[1e400,-0,0.1000000000000000055511],"t":true}`
	got := editWith(t, s, valueEdit("jane@fixture.gr", `x"y\z/é😀`+"\n"))
	want := `{"a":"keep \u00e9 \/ me","b":"x\"y\\z\/\u00e9\ud83d\ude00\n","n":[1e400,-0,0.1000000000000000055511],"t":true}`
	if got != want {
		t.Errorf("styled edit:\n got %s\nwant %s", got, want)
	}

	// A text that writes non-ASCII as is gets it as is; only the changed
	// part is written again, so escapes around it stay.
	s = `{"a":"Zoë \u0041 Smith"}`
	if got := editWith(t, s, valueEdit("Zoë A Smith", "Zoë A Brown")); got != `{"a":"Zoë \u0041 Brown"}` {
		t.Errorf("splice: %s", got)
	}

	// Numbers, booleans and nulls.
	s = `{"n":12.50,"b":false,"z":null}`
	got = editWith(t, s, func(l Leaf) (string, bool) {
		switch l.Kind {
		case LeafNumber:
			return "-3.75e2", true
		case LeafBool:
			return "true", true
		}
		return "", false
	})
	if got != `{"n":-3.75e2,"b":true,"z":null}` {
		t.Errorf("scalars: %s", got)
	}
	for _, bad := range []struct {
		kind LeafKind
		to   string
	}{{LeafNumber, "12x"}, {LeafNumber, "01"}, {LeafBool, "yes"}, {LeafNull, "0"}} {
		_, _, err := EditStructured(s, func(l Leaf) (string, bool) { return bad.to, l.Kind == bad.kind })
		if !errors.Is(err, ErrBadEdit) {
			t.Errorf("%d to %q: err %v", bad.kind, bad.to, err)
		}
	}

	// Keys: renamed, escaped, and refused when they'd equal another.
	s = `{"jane@fixture.gr":{"x":1},"other":2}`
	got = editWith(t, s, func(l Leaf) (string, bool) { return `h_"1"`, l.Kind == LeafKey && l.Key == "jane@fixture.gr" })
	if got != `{"h_\"1\"":{"x":1},"other":2}` {
		t.Errorf("key: %s", got)
	}
	_, _, err := EditStructured(s, func(l Leaf) (string, bool) { return "other", l.Kind == LeafKey && l.Key != "other" })
	if !errors.Is(err, ErrBadEdit) {
		t.Errorf("duplicate key: err %v", err)
	}
}

func TestEditPHP(t *testing.T) {
	// The email's new length is written, and so is every length that holds it.
	inner := "a:1:{" + phpStr("email") + phpStr("jane@fixture.gr") + "}"
	s := "a:2:{" + phpStr("customer") + phpStr(inner) + phpStr("n") + "i:7;}"
	got := editWith(t, s, valueEdit("jane@fixture.gr", "é@x.example"))
	want := "a:2:{" + phpStr("customer") + phpStr("a:1:{"+phpStr("email")+phpStr("é@x.example")+"}") + phpStr("n") + "i:7;}"
	if got != want {
		t.Errorf("nested lengths:\n got %q\nwant %q", got, want)
	}

	// JSON inside PHP inside JSON, as Laravel queues hold it.
	cmd := `O:8:"SendMail":1:{` + phpStr("to") + phpStr("jane@fixture.gr") + "}"
	s = `{"data":{"command":` + quoteJSON(cmd) + `}}`
	got = editWith(t, s, valueEdit("jane@fixture.gr", "a/b@x.example"))
	cmd2 := `O:8:"SendMail":1:{` + phpStr("to") + phpStr("a/b@x.example") + "}"
	if want := `{"data":{"command":` + quoteJSON(cmd2) + `}}`; got != want {
		t.Errorf("Laravel payload:\n got %s\nwant %s", got, want)
	}

	// A C: payload's size.
	s = `C:11:"ArrayObject":` + fmt.Sprint(len(inner)) + ":{" + inner + "}"
	got = editWith(t, s, valueEdit("jane@fixture.gr", "j@x.example"))
	in2 := "a:1:{" + phpStr("email") + phpStr("j@x.example") + "}"
	if want := `C:11:"ArrayObject":` + fmt.Sprint(len(in2)) + ":{" + in2 + "}"; got != want {
		t.Errorf("C payload:\n got %q\nwant %q", got, want)
	}

	// Keys: string keys edit to strings and integer keys to integers, and
	// no key can become another key of its map.
	s = "a:3:{i:5;" + phpStr("x") + phpStr("jane") + phpStr("y") + "i:306971234567;" + phpStr("z") + "}"
	var keys []string
	got = editWith(t, s, func(l Leaf) (string, bool) {
		if l.Kind != LeafKey {
			return "", false
		}
		keys = append(keys, l.Key+"/"+l.Segment)
		if l.Segment == "[]" {
			return "7" + l.Key[:1], true
		}
		return "h_ab", true
	})
	if !slices.Equal(keys, []string{"5/[]", "jane/jane", "306971234567/[]"}) ||
		got != "a:3:{i:75;"+phpStr("x")+phpStr("h_ab")+phpStr("y")+"i:73;"+phpStr("z")+"}" {
		t.Errorf("keys %q, got %q", keys, got)
	}
	for name, fn := range map[string]func(Leaf) (string, bool){
		"a string key equal to an integer key": func(l Leaf) (string, bool) { return "5", l.Kind == LeafKey && l.Key == "jane" },
		"an integer key equal to another":      func(l Leaf) (string, bool) { return "5", l.Kind == LeafKey && l.Key != "5" },
		"an integer key edited to text":        func(l Leaf) (string, bool) { return "h_ab", l.Kind == LeafKey && l.Key == "5" },
		"an integer key not written plainly":   func(l Leaf) (string, bool) { return "05", l.Kind == LeafKey && l.Key == "5" },
	} {
		if out, _, err := EditStructured(s, fn); !errors.Is(err, ErrBadEdit) || out != "" {
			t.Errorf("%s: err %v, out %q", name, err, out)
		}
	}

	// Scalars, private properties and enum cases.
	s = `O:3:"Foo":3:{` + phpStr("\x00Foo\x00secret") + phpStr("pw") + phpStr("d") + "d:0.5;" + phpStr("e") + `E:7:"Foo:Bar";}`
	var paths []string
	got = editWith(t, s, func(l Leaf) (string, bool) {
		paths = append(paths, JoinPath(l.Path)+":"+fmt.Sprint(l.Kind))
		switch l.Kind {
		case LeafString:
			return "", true
		case LeafNumber:
			return "1.5E+3", true
		}
		return "", false
	})
	if want := `O:3:"Foo":3:{` + phpStr("\x00Foo\x00secret") + phpStr("") + phpStr("d") + "d:1.5E+3;" + phpStr("e") + `E:7:"Foo:Bar";}`; got != want {
		t.Errorf("object:\n got %q\nwant %q", got, want)
	}
	if want := []string{":5", "secret:1", ":5", "d:2", ":5", "e:6"}; !slices.Equal(paths, want) {
		t.Errorf("paths %q, want %q", paths, want)
	}
	for _, bad := range []func(Leaf) (string, bool){
		func(l Leaf) (string, bool) { return "Foo:Baz", l.Kind == LeafEnum },
		func(l Leaf) (string, bool) { return "1,5", l.Kind == LeafNumber },
	} {
		if _, _, err := EditStructured(s, bad); !errors.Is(err, ErrBadEdit) {
			t.Errorf("bad edit: err %v", err)
		}
	}
}

// TestEditDetails covers what reviews found: data keys marked as Walk marks
// them, numbers that can't be edited to nothing, slash escaping read only
// from real escapes, and plain strings at the nesting limit.
func TestEditDetails(t *testing.T) {
	var data []string
	editLeavesFn := func(s string) {
		if _, _, err := EditStructured(s, func(l Leaf) (string, bool) {
			if l.Kind == LeafKey && l.DataKey {
				data = append(data, l.Key)
			}
			return "", false
		}); err != nil {
			t.Fatal(err)
		}
	}
	editLeavesFn(`{"jane@fixture.gr":1,"203.0.113.7":2,"name":3,"1.8.5.4":4}`)
	editLeavesFn("a:2:{" + phpStr("ann@fixture.gr") + "i:1;i:7;i:2;}")
	if !slices.Equal(data, []string{"jane@fixture.gr", "203.0.113.7", "ann@fixture.gr"}) {
		t.Errorf("data keys %q", data)
	}

	if out, _, err := EditStructured(`{"a":1,"b":[2]}`, func(l Leaf) (string, bool) { return "", l.Kind == LeafNumber }); !errors.Is(err, ErrBadEdit) || out != "" {
		t.Errorf("a number edited to nothing: %q, %v", out, err)
	}

	// An escaped backslash before a slash isn't slash escaping.
	got := editWith(t, `{"p":"a\\/b","e":"x"}`, valueEdit("x", "c/d"))
	if got != `{"p":"a\\/b","e":"c/d"}` {
		t.Errorf("escaped backslash: %s", got)
	}

	// At the nesting limit, a string that only starts like structured data
	// is a string; structured data there is over the limits.
	plain := `"{not json"`
	deep := `"{\"a\":1}"`
	for i := 0; i < maxEditNesting; i++ {
		plain = quoteJSON(`{"a":` + plain + `}`)
		deep = quoteJSON(`{"a":` + deep + `}`)
	}
	plain, deep = `{"a":`+plain+`}`, `{"a":`+deep+`}`
	if _, _, err := EditStructured(plain, func(Leaf) (string, bool) { return "", false }); err != nil {
		t.Errorf("a plain string at the nesting limit: %v", err)
	}
	if _, _, err := EditStructured(deep, func(Leaf) (string, bool) { return "", false }); !errors.Is(err, ErrTooLarge) {
		t.Errorf("structured data past the nesting limit: %v", err)
	}
}

func TestEditKeepsEscapedASCII(t *testing.T) {
	// A JSON string that writes quotes and < > as escapes, as WordPress's
	// block attributes do, keeps them so in the units an edit writes again.
	s := `{"a":"{\u0022name\u0022:\u0022Maria\u0022,\u0022tag\u0022:\u0022\u003cb\u003e\u0022}"}`
	got := editWith(t, s, valueEdit("Maria", "Anna"))
	if want := `{"a":"{\u0022name\u0022:\u0022Anna\u0022,\u0022tag\u0022:\u0022\u003cb\u003e\u0022}"}`; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestEditKeepsOtherBytes(t *testing.T) {
	// Bytes that aren't UTF-8, as in a latin1 column, pass through as they
	// are, edited or not.
	s := "{\"a\":\"caf\xe9 \x81\x8d\",\"b\":\"jane@fixture.gr\"}"
	got := editWith(t, s, valueEdit("jane@fixture.gr", "j@x.example"))
	if got != "{\"a\":\"caf\xe9 \x81\x8d\",\"b\":\"j@x.example\"}" {
		t.Errorf("JSON: %q", got)
	}
	got = editWith(t, s, valueEdit("caf\xe9 \x81\x8d", "caf\xe9 x"))
	if got != "{\"a\":\"caf\xe9 x\",\"b\":\"jane@fixture.gr\"}" {
		t.Errorf("JSON leaf: %q", got)
	}
	s = "a:2:{" + phpStr("a") + phpStr("caf\xe9") + phpStr("b") + phpStr("jane@fixture.gr") + "}"
	got = editWith(t, s, valueEdit("jane@fixture.gr", "j@x.example"))
	if got != "a:2:{"+phpStr("a")+phpStr("caf\xe9")+phpStr("b")+phpStr("j@x.example")+"}" {
		t.Errorf("PHP: %q", got)
	}
}

func TestEditErrors(t *testing.T) {
	keep := func(Leaf) (string, bool) { return "", false }
	nested := `{"a":"b"}`
	for i := 0; i < maxEditNesting; i++ {
		nested = `{"a":` + quoteJSON(nested) + `}`
	}
	cases := map[string]error{
		`{"a":"b"`:                 ErrNotStructured,
		`{"a":"b"} x`:              ErrNotStructured,
		`{"a":"b",}`:               ErrNotStructured,
		`{"a":"b` + "\n" + `"}`:    ErrNotStructured,
		`{"a":"\u12"}`:             ErrNotStructured,
		`a:1:{s:1:"a";s:5:"abc";}`: ErrNotStructured,
		`a:2:{s:1:"a";i:1;}`:       ErrNotStructured,
		`a:1:{s:1:"a";i:1;}x`:      ErrNotStructured,
		`a:1:{s:1:"a";i:x;}`:       ErrNotStructured,
		"plain text":               ErrNotStructured,
		strings.Repeat("[", 600) + strings.Repeat("]", 600): ErrTooLarge,
		"[" + strings.Repeat("0,", maxEditNodes) + "0]":     ErrTooLarge,
		`{"a":` + quoteJSON(nested) + `}`:                   ErrTooLarge,
	}
	for in, want := range cases {
		out, edited, err := EditStructured(in, keep)
		if !errors.Is(err, want) || edited || out != "" {
			name := in
			if len(name) > 40 {
				name = name[:40] + "…"
			}
			t.Errorf("%q: err %v, want %v", name, err, want)
		}
	}
	if _, _, err := EditStructured("["+strings.Repeat(" ", maxEditSize)+"]", keep); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the size limit: err %v", err)
	}
	// Errors are fixed text.
	for _, err := range []error{ErrNotStructured, ErrTooLarge, ErrBadEdit} {
		if strings.ContainsAny(err.Error(), "{[\"") {
			t.Errorf("error text %q", err)
		}
	}
}

// docGen builds random JSON and PHP-serialized values, nested inside each
// other, with strings that need escaping.
type docGen struct{ r *rand.Rand }

var genStrings = []string{"", "jane@fixture.gr", `quote " back \ slash /`, "é ü 😀", "line\nbreak\ttab", "\x01ctl", "latin1 \xe9\x81",
	"12", "true", "a:", "{not json", "plain words here"}

func (g *docGen) str() string {
	s := genStrings[g.r.IntN(len(genStrings))]
	if g.r.IntN(3) == 0 {
		s += fmt.Sprint(g.r.IntN(1000))
	}
	return s
}

// jsonQuote writes s as a JSON string, escaping / and non-ASCII or not.
func (g *docGen) jsonQuote(s string, st jsonStyle) string {
	var b strings.Builder
	b.WriteByte('"')
	st.write(&b, s)
	b.WriteByte('"')
	return b.String()
}

func (g *docGen) json(depth int, st jsonStyle) string {
	switch k := g.r.IntN(8); {
	case depth > 3 || k < 3:
		switch g.r.IntN(5) {
		case 0:
			return []string{"0", "-0", "12.50", "1e400", "-3E-2", "0.1000000000000000055511"}[g.r.IntN(6)]
		case 1:
			return []string{"true", "false", "null"}[g.r.IntN(3)]
		case 2:
			return g.jsonQuote(g.php(depth+1), st)
		}
		return g.jsonQuote(g.str(), st)
	case k < 5:
		n := g.r.IntN(4)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = g.json(depth+1, st)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		n := g.r.IntN(4)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = g.jsonQuote(fmt.Sprintf("k%d_%s", i, g.str()), st) + ":" + g.json(depth+1, st)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
}

func (g *docGen) php(depth int) string {
	switch k := g.r.IntN(8); {
	case depth > 3 || k < 3:
		switch g.r.IntN(5) {
		case 0:
			return []string{"i:0;", "i:-42;", "d:0.5;", "d:1.0E+25;", "d:-INF;", "b:1;", "N;"}[g.r.IntN(7)]
		case 1:
			return phpStr(g.json(depth+1, jsonStyle{slash: g.r.IntN(2) == 0, unicode: g.r.IntN(2) == 0}))
		}
		return phpStr(g.str())
	default:
		n := g.r.IntN(4)
		var b strings.Builder
		fmt.Fprintf(&b, "a:%d:{", n)
		for i := 0; i < n; i++ {
			if g.r.IntN(2) == 0 {
				fmt.Fprintf(&b, "i:%d;", i)
			} else {
				b.WriteString(phpStr(fmt.Sprintf("k%d_%s", i, g.str())))
			}
			b.WriteString(g.php(depth + 1))
		}
		b.WriteString("}")
		return b.String()
	}
}

func (g *docGen) doc() string {
	if g.r.IntN(2) == 0 {
		return "a:1:{" + phpStr("root") + g.php(0) + "}"
	}
	return "[" + g.json(0, jsonStyle{slash: g.r.IntN(2) == 0, unicode: g.r.IntN(2) == 0}) + "]"
}

// checkRandomEdits edits random string leaves and keys of s, then checks
// that the result reads back with exactly those leaves changed.
func checkRandomEdits(t *testing.T, s string, seed uint64) {
	r := rand.New(rand.NewPCG(seed, 1))
	before, _, err := collectLeaves(s)
	if err != nil {
		return
	}
	news := map[int]string{}
	for i, l := range before {
		if r.IntN(3) != 0 {
			continue
		}
		switch {
		case l.Kind == LeafKey && l.Segment == "[]":
			// Integer keys edit to integers, unique in their map.
			news[i] = fmt.Sprint(9000000 + i)
		case l.Kind == LeafString || l.Kind == LeafKey:
			news[i] = []string{"", "x", `new "quoted" \ value /`, "ü😀", "jane@x.example", "\xe9"}[r.IntN(6)] + fmt.Sprintf("~%d", i)
		case l.Kind == LeafNumber:
			news[i] = fmt.Sprint(r.IntN(1000))
		case l.Kind == LeafBool:
			news[i] = map[string]string{"true": "false", "false": "true", "0": "1", "1": "0"}[l.Value]
		}
	}
	i := 0
	out, _, err := EditStructured(s, func(l Leaf) (string, bool) {
		v, ok := news[i]
		i++
		return v, ok
	})
	if err != nil {
		t.Fatalf("edit failed: %v\n%q", err, s)
	}
	after, _, err := collectLeaves(out)
	if err != nil {
		t.Fatalf("the edited value doesn't read back: %v\n in %q\nout %q", err, s, out)
	}
	if len(after) != len(before) {
		t.Fatalf("%d leaves before, %d after\n in %q\nout %q", len(before), len(after), s, out)
	}
	for i := range before {
		want := before[i].Value
		if v, ok := news[i]; ok {
			want = v
		}
		if after[i].Value != want || after[i].Kind != before[i].Kind {
			t.Fatalf("leaf %d: %q (%d), want %q (%d)\n in %q\nout %q", i, after[i].Value, after[i].Kind, want, before[i].Kind, s, out)
		}
	}
	if strings.HasPrefix(s, "[") && json.Valid([]byte(s)) && !json.Valid([]byte(out)) {
		t.Fatalf("valid JSON became invalid\n in %q\nout %q", s, out)
	}
}

func collectLeaves(s string) ([]Leaf, bool, error) {
	var out []Leaf
	_, edited, err := EditStructured(s, func(l Leaf) (string, bool) {
		out = append(out, l)
		return "", false
	})
	return out, edited, err
}

// checkRoundTrip edits random string leaves and keys of s by adding to
// them, then edits them back: the result is s, byte for byte, so nothing
// outside the edits changed. Adding to a value keeps whatever shows how the
// value escapes slashes and characters past ASCII.
func checkRoundTrip(t *testing.T, s string, seed uint64) {
	r := rand.New(rand.NewPCG(seed, 2))
	before, _, err := collectLeaves(s)
	if err != nil {
		return
	}
	// Keys of a map that holds one twice can't be edited back to it.
	seen, twice := map[string]bool{}, map[string]bool{}
	mapOf := func(l Leaf) string { return strings.Join(l.Path, "\x00") }
	for _, l := range before {
		if l.Kind == LeafKey {
			k := mapOf(l) + "\x01" + l.Value
			twice[mapOf(l)] = twice[mapOf(l)] || seen[k]
			seen[k] = true
		}
	}
	news := map[int]string{}
	for i, l := range before {
		if r.IntN(2) == 0 && (l.Kind == LeafString || l.Kind == LeafKey && l.Segment != "[]" && !twice[mapOf(l)]) {
			news[i] = l.Value + fmt.Sprintf("~%d", i)
		}
	}
	edit := func(in string, value func(i int) string) string {
		i := 0
		out, _, err := EditStructured(in, func(Leaf) (string, bool) {
			_, ok := news[i]
			v := value(i)
			i++
			return v, ok
		})
		if err != nil {
			t.Fatalf("edit failed: %v\n%q", err, in)
		}
		return out
	}
	out := edit(s, func(i int) string { return news[i] })
	if after, _, err := collectLeaves(out); err != nil || len(after) != len(before) {
		t.Fatalf("the edited value reads back as %d leaves of %d: %v\n in %q\nout %q", len(after), len(before), err, s, out)
	}
	// A PHP length written with leading zeros is written again without them.
	back := edit(out, func(i int) string { return before[i].Value })
	if rePHPPadded.ReplaceAllString(back, "$1$2") != rePHPPadded.ReplaceAllString(s, "$1$2") {
		t.Fatalf("edited back, the value differs\n  in %q\n out %q\nback %q", s, out, back)
	}
}

var rePHPPadded = regexp.MustCompile(`(s:|":)0+([0-9])`)

func TestEditStructuredRandom(t *testing.T) {
	g := &docGen{rand.New(rand.NewPCG(9, 9))}
	for i := 0; i < 3000; i++ {
		s := g.doc()
		if out, edited, err := EditStructured(s, func(Leaf) (string, bool) { return "", false }); err != nil || edited || out != s {
			t.Fatalf("no edit: err %v, edited %v\n%q", err, edited, s)
		}
		checkRandomEdits(t, s, uint64(i))
		checkRoundTrip(t, s, uint64(i))
	}
	for _, s := range editCorpus() {
		checkRoundTrip(t, s, 1)
	}
}

func FuzzEditStructured(f *testing.F) {
	g := &docGen{rand.New(rand.NewPCG(10, 10))}
	for _, s := range editCorpus() {
		f.Add(s, uint64(1))
	}
	for i := 0; i < 50; i++ {
		f.Add(g.doc(), uint64(i))
	}
	f.Fuzz(func(t *testing.T, s string, seed uint64) {
		out, edited, err := EditStructured(s, func(Leaf) (string, bool) { return "", false })
		if err == nil && (out != s || edited) || err != nil && (out != "" || edited) {
			t.Fatalf("no edit: out %d bytes of %d, edited %v, err %v", len(out), len(s), edited, err)
		}
		if err == nil {
			checkRandomEdits(t, s, seed)
			checkRoundTrip(t, s, seed)
		}
	})
}
