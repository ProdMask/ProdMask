package detect

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// phpStr serializes a string the way PHP does.
func phpStr(s string) string { return fmt.Sprintf("s:%d:\"%s\";", len(s), s) }

func collect(t *testing.T, s string) map[string]string {
	t.Helper()
	got := map[string]string{}
	if !walkStructured(s, func(path []string, v string) { got[JoinPath(path)] = v }) {
		t.Fatalf("walkStructured rejected %q", s)
	}
	return got
}

func TestWalkPHP(t *testing.T) {
	s := "a:3:{" + phpStr("email") + phpStr("jane@fixture.gr") +
		phpStr("billing") + "a:1:{" + phpStr("phone") + phpStr("+30 210 555 0123") + "}" +
		phpStr("items") + "a:2:{i:0;" + phpStr("socks") + "i:1;i:42;}}"
	got := collect(t, s)
	want := map[string]string{
		"email":         "jane@fixture.gr",
		"billing.phone": "+30 210 555 0123",
		"items[]":       "42", // the later leaf wins in this map
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestWalkPHPObjectAndNesting(t *testing.T) {
	// WooCommerce stores the customer as a serialized string inside the
	// serialized session; private properties carry NUL-prefixed names.
	inner := "a:1:{" + phpStr("email") + phpStr("jane@fixture.gr") + "}"
	obj := `O:8:"WC_Thing":2:{` + phpStr("\x00WC_Thing\x00secret") + phpStr("x") + phpStr("customer") + phpStr(inner) + "}"
	got := collect(t, obj)
	if got["customer.email"] != "jane@fixture.gr" || got["secret"] != "x" {
		t.Errorf("got %v", got)
	}
}

func TestWalkPHPTruncated(t *testing.T) {
	s := "a:2:{" + phpStr("email") + phpStr("jane@fixture.gr") + phpStr("note") + `s:500:"cut off here`
	got := collect(t, s)
	if got["email"] != "jane@fixture.gr" || got["note"] != "cut off here" {
		t.Errorf("got %v", got)
	}
}

func TestWalkJSONWithSerializedPHP(t *testing.T) {
	// Laravel queue payloads: JSON with a serialized PHP command inside.
	cmd := `O:8:"SendMail":1:{` + phpStr("to") + phpStr("jane@fixture.gr") + "}"
	s := `{"uuid":"1f0e","data":{"command":` + quoteJSON(cmd) + `},"tags":["a","b"],"n":5}`
	got := collect(t, s)
	if got["data.command.to"] != "jane@fixture.gr" || got["n"] != "5" || got["tags[]"] != "b" {
		t.Errorf("got %v", got)
	}
}

func TestWalkJSONTruncatedAndKeys(t *testing.T) {
	// The decoder cannot hand out half a string, so the cut-off first_name
	// is lost; everything before it is still reported.
	s := `{"customers":{"jane@fixture.gr":{"name":"Jane"},"12":{"note":"x"}},"profile":{"first_name":"Ja`
	got := collect(t, s)
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// The email key itself is reported at {}, the value under it at *.
	want := []string{"customers.*.name", "customers[].note", "customers{}"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("paths = %v, want %v", keys, want)
	}
	if got["customers{}"] != "jane@fixture.gr" {
		t.Errorf("email key not reported as a value: %v", got)
	}
}

func TestNormKey(t *testing.T) {
	cases := map[string]string{
		"billing_email":                    "billing_email",
		"12":                               "[]",
		"e4da3b7fbbce2345d7772b0674a318d5": "*",
		"John Smith":                       "*",
		"\x00*\x00token":                   "token",
		"":                                 "*",
	}
	for in, want := range cases {
		if got := normKey(in); got != want {
			t.Errorf("normKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksStructured(t *testing.T) {
	for _, s := range []string{`{"a":1}`, `[{"a":1}]`, `[ "x" ]`, `a:1:{i:0;i:1;}`, `O:3:"Foo":0:{}`} {
		if !looksStructured(s) {
			t.Errorf("looksStructured(%q) = false", s)
		}
	}
	for _, s := range []string{`[1,2,3]`, `a cat`, `Order #12`, `{`} {
		if looksStructured(s) {
			t.Errorf("looksStructured(%q) = true", s)
		}
	}
}

func quoteJSON(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\x00", `\u0000`)
	return `"` + r.Replace(s) + `"`
}
