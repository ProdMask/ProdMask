package leak

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// found runs extract on one value and lists what it yields as kind:value.
func found(t *testing.T, allow []string, w wants, v string) []string {
	t.Helper()
	list, err := NewAllowlist(allow)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	newExtractor(list).values(v, &w, func(k model.LeakKind, norm string) {
		out = append(out, string(k)+":"+norm)
	})
	return out
}

// live assembles a live-shaped secret at run time, as the repo's other tests
// do, so none sits in a file.
func live() string { return "sk_" + "live_" + strings.Repeat("aB3dE6gH9", 3) }

func basicOf(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}

func testKeyS() string { return "sk_" + "test_" + strings.Repeat("aB3dE6gH9", 3) }

func TestExtractKinds(t *testing.T) {
	cases := []struct {
		name  string
		allow []string
		w     wants
		v     string
		want  []string
	}{
		{name: "email", v: "Jane.Doe@Shop-Mail.dev", want: []string{"email:jane.doe@shop-mail.dev"}},
		{name: "email in text", v: "order note: write to jane@shop-mail.dev soon", want: []string{"email:jane@shop-mail.dev"}},
		{name: "email in JSON", v: `{"billing":{"email":"Jane@Shop-Mail.dev"}}`, want: []string{"email:jane@shop-mail.dev"}},
		{name: "email in PHP", v: `a:1:{s:5:"email";s:19:"jane@shop-mail.dev";}`, want: []string{"email:jane@shop-mail.dev"}},
		{name: "email percent-encoded", v: "https://x.dev/?u=jane%40shop-mail.dev", want: []string{"email:jane@shop-mail.dev"}},
		{name: "email with a JSON escape", v: `{"e":"jane\u0040shop-mail.dev"}`, want: []string{"email:jane@shop-mail.dev"}},
		{name: "reserved domain", v: "jane@example.com, joe@shop.test", want: nil},
		{name: "image name", v: "logo@2x.png", want: nil},
		{name: "allowed domain", allow: []string{"shop-mail.dev"}, v: "jane@shop-mail.dev", want: nil},
		{name: "allowed subdomain", allow: []string{"shop-mail.dev"}, v: "jane@eu.shop-mail.dev", want: nil},
		{name: "not a subdomain", allow: []string{"mail.dev"}, v: "jane@shop-mail.dev", want: []string{"email:jane@shop-mail.dev"}},
		{name: "allowed address", allow: []string{"Jane@Shop-Mail.dev"}, v: "jane@shop-mail.dev joe@shop-mail.dev", want: []string{"email:joe@shop-mail.dev"}},

		{name: "strict phone", v: "call +30 697 123 4567 today", want: []string{"phone:306971234567"}},
		{name: "phone with 00", v: "call +0030 697 123 4567", want: []string{"phone:306971234567"}},
		{name: "domestic phone in text isn't one", v: "order 6971234567 shipped", want: nil},
		{name: "domestic phone in a phone column", w: wants{loosePhone: true}, v: "697 123 4567", want: []string{"phone:6971234567"}},
		{name: "short phone", w: wants{loosePhone: true}, v: "555 0123", want: nil},
		{name: "phone that only counts up", w: wants{loosePhone: true}, v: "1234567890", want: nil},
		{name: "phone that only counts down", w: wants{loosePhone: true}, v: "9876543210", want: nil},
		{name: "phone of one digit", w: wants{loosePhone: true}, v: "0000000000", want: nil},
		{name: "phone of few digits", w: wants{loosePhone: true}, v: "1122112211", want: nil},
		{name: "date isn't a phone", w: wants{loosePhone: true}, v: "2024-01-02", want: nil},

		{name: "IBAN", v: "pay to gb82 west 1234 5698 7654 32", want: []string{"iban:GB82WEST12345698765432"}},
		{name: "secret", v: "key=" + live(), want: []string{"secret:" + live()}},
		{name: "test-mode key", v: "key=" + testKeyS(), want: nil},
		{name: "password hash", v: "$P$BIG6lF4eCQ9vp4EvgA9Trk8JSvnpIo0", want: []string{"password_hash:$P$BIG6lF4eCQ9vp4EvgA9Trk8JSvnpIo0"}},
		{name: "long URL password", v: "https://user:Xy7pQ2mZ9tR4kL8vN3@db.shop-mail.dev/x", want: []string{"secret:Xy7pQ2mZ9tR4kL8vN3"}},
		{name: "short URL password", v: "https://user:Xy7pQ2mZ@db.shop-mail.dev/x", want: nil},
		{name: "card number as a URL password", v: "https://user:4556737586899855@db.shop-mail.dev/x", want: nil},
		{name: "short Basic password", v: "Authorization: Basic " + basicOf("bob", "hunter2"), want: nil},
		{name: "long Basic password", v: "Authorization: Basic " + basicOf("bob", "Xy7pQ2mZ9tR4kL8vN3"), want: []string{"secret:" + basicOf("bob", "Xy7pQ2mZ9tR4kL8vN3")}},
		{name: "card number as a Basic password", v: "Authorization: Basic " + basicOf("bob", "4556737586899855"), want: nil},
		{name: "key in a Basic credential", v: "Authorization: Basic " + basicOf(live(), ""), want: []string{"secret:" + basicOf(live(), "")}},
		{name: "card number isn't hashed", v: "4556737586899855", want: nil},
		{name: "IP address isn't counted", v: "203.0.113.7", want: nil},

		{name: "national ID", w: wants{whole: []model.LeakKind{model.LeakNationalID}}, v: " de-123.456/789 ", want: []string{"national_id:DE123456789"}},
		{name: "short national ID", w: wants{whole: []model.LeakKind{model.LeakNationalID}}, v: "A-123", want: nil},
		{name: "national ID of few characters", w: wants{whole: []model.LeakKind{model.LeakNationalID}}, v: "111111111", want: nil},
		{name: "payment token", w: wants{whole: []model.LeakKind{model.LeakPaymentToken}}, v: "cus_AbC123dEf456", want: []string{"payment_token:cus_AbC123dEf456"}},
		{name: "short payment token", w: wants{whole: []model.LeakKind{model.LeakPaymentToken}}, v: "cus_AbC", want: nil},
		{name: "hex digest as a password hash", w: wants{whole: []model.LeakKind{model.LeakPasswordHash}}, v: "5f4dcc3b5aa765d61d8327deb882cf99", want: []string{"password_hash:5f4dcc3b5aa765d61d8327deb882cf99"}},
		{name: "whole secret", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "mYc0mplic4tedApiT0ken", want: []string{"secret:mYc0mplic4tedApiT0ken"}},
		{name: "short whole secret", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "abc123", want: nil},
		{name: "whole secret of few characters", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "aaaaaaaabbbbbbbbcccccccc", want: nil},
		{name: "too long to be a whole value", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: strings.Repeat("aB3dE6gH9", 100), want: nil},
		{name: "a constant's name as a secret", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "CHANGE_ME_IN_PRODUCTION", want: nil},
		{name: "a template as a secret", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "your-api-key-goes-here", want: nil},
		{name: "a real key in capitals", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "K8S_TOKEN_9F3A7C2E1B4D", want: []string{"secret:K8S_TOKEN_9F3A7C2E1B4D"}},
		{name: "a real key holding a word", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "x9InsertQ7zLp2Wm4Tn8Vb", want: []string{"secret:x9InsertQ7zLp2Wm4Tn8Vb"}},
		{name: "a real key after a word", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "Replace-9f3a7c2e1b4d8c6a", want: []string{"secret:Replace-9f3a7c2e1b4d8c6a"}},
		{name: "letters only, no template word", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "qTzLpWmNvBxKjHgFdS", want: []string{"secret:qTzLpWmNvBxKjHgFdS"}},

		// A test key must not come back as a whole value, nor a blob of them.
		{name: "test key in a secret column", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: testKeyS(), want: nil},
		{name: "settings blob of test keys", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: `{"secret":"` + testKeyS() + `"}`, want: nil},
		{name: "reserved email in a secret column", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "someone@example.com", want: nil},
		{name: "card number in a secret column", w: wants{whole: []model.LeakKind{model.LeakSecret}}, v: "4556737586899855", want: nil},
		{name: "card number in a token column", w: wants{whole: []model.LeakKind{model.LeakPaymentToken}}, v: "4556 7375 8689 9855", want: nil},

		{name: "blank", w: wants{loosePhone: true, whole: []model.LeakKind{model.LeakSecret}}, v: "   ", want: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := found(t, c.allow, c.w, c.v); !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractSameOnBothSides(t *testing.T) {
	// Forms of one value that a copy could hold normalise alike.
	for _, forms := range [][]string{
		{"jane@shop-mail.dev", "JANE@SHOP-MAIL.DEV", "jane%40shop-mail.dev", `{"e":"Jane@Shop-Mail.dev"}`},
		{"+30 697 123 4567", "+306971234567", "+30-697-123-4567", "+0030 697 123 4567"},
	} {
		var first []string
		for i, v := range forms {
			got := found(t, nil, wants{loosePhone: true}, v)
			if i == 0 {
				first = got
				if len(first) != 1 {
					t.Fatalf("%q: %q", v, got)
				}
				continue
			}
			if !slices.Equal(got, first) {
				t.Errorf("%q gives %q, %q gives %q", forms[0], first, v, got)
			}
		}
	}
}

func TestExtractNeverPanics(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	const alphabet = "abc@.+-_ 0123456789\"\\{}:;%$,/()\x00\xff\xc3\xa9"
	w := wants{loosePhone: true, whole: []model.LeakKind{model.LeakSecret, model.LeakNationalID}}
	e := newExtractor(nil)
	for range 20000 {
		b := make([]byte, r.IntN(80))
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}
		e.values(string(b), &w, func(model.LeakKind, string) {})
	}
}

func TestAllowlist(t *testing.T) {
	for _, bad := range []string{"com", "", "@shop.dev", "jane@", "a b.dev", "x@y@z.dev"} {
		if _, err := NewAllowlist([]string{bad}); !errors.Is(err, ErrAllowValue) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	a, err := NewAllowlist([]string{"Shop.Dev", "Jane@Gmail.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(a.Domains, []string{"shop.dev"}) || a.Addresses() != 1 {
		t.Errorf("%+v", a)
	}
	for addr, want := range map[string]bool{"x@shop.dev": true, "x@eu.shop.dev": true, "x@notshop.dev": false,
		"jane@gmail.com": true, "joe@gmail.com": false} {
		if a.has(addr) != want {
			t.Errorf("%s: %v", addr, !want)
		}
	}
}

func keyText(b byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{b, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde}, 4))
}

func TestParseKey(t *testing.T) {
	good := keyText(0xf0)
	for _, text := range []string{good, strings.ToUpper(good), "\n" + good + "\r\n", "\xef\xbb\xbf" + good + "\n"} {
		if _, err := ParseKey([]byte(text)); err != nil {
			t.Errorf("%d bytes: %v", len(text), err)
		}
	}
	for name, text := range map[string]string{
		"empty":      "",
		"short":      good[:62],
		"odd":        good + "a",
		"passphrase": "correct horse battery staple correct horse battery staple correct",
		"not hex":    good[:62] + "zz",
		"few digits": strings.Repeat("ab", 40),
		"all one":    strings.Repeat("0", 64),
	} {
		_, err := ParseKey([]byte(text))
		if !errors.Is(err, ErrKeyFormat) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && text != "" && strings.Contains(err.Error(), text) {
			t.Errorf("%s: the error quotes the key", name)
		}
	}
	var utf16 bytes.Buffer
	for _, c := range []byte(good) {
		utf16.Write([]byte{c, 0})
	}
	if _, err := ParseKey(utf16.Bytes()); !errors.Is(err, ErrKeyUTF16) {
		t.Errorf("UTF-16: %v", err)
	}
	// A key never prints.
	k, _ := ParseKey([]byte(good))
	type holder struct{ key Key }
	raw := fmt.Sprintf("%d", k.secret()[:4])
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s %x %d %p", k, k, k, k, k, k, k),
		fmt.Sprintf("%v %+v %#v %s %x %d %p", holder{k}, holder{k}, holder{k}, holder{k}, holder{k}, holder{k}, holder{k}),
		fmt.Sprintf("%v %s %x", &k, &k, &k)} {
		if strings.Contains(s, good[:16]) || strings.Contains(s, raw[1:len(raw)-1]) {
			t.Errorf("a key printed: %q", s)
		}
	}
}

func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leak.key")
	if err := WriteNewKey(path); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewKey(path); !errors.Is(err, os.ErrExist) {
		t.Errorf("a second write: %v", err)
	}
	k, open, err := ReadKeyFile(path)
	if err != nil || len(k.secret()) != keyBytes {
		t.Fatalf("%v", err)
	}
	if runtime.GOOS != "windows" {
		if open {
			t.Error("a new key file should be owner-only")
		}
		os.Chmod(path, 0o644)
		if _, open, _ := ReadKeyFile(path); !open {
			t.Error("a file others can read should be noted")
		}
	}
	secret := keyText(0xf0)
	if _, _, err := ReadKeyFile(filepath.Join(dir, secret)); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("a missing file: %v", err)
	}
	big := filepath.Join(dir, "big")
	os.WriteFile(big, bytes.Repeat([]byte("a"), maxKeyFile+1), 0o600)
	if _, _, err := ReadKeyFile(big); !errors.Is(err, ErrKeyFormat) {
		t.Errorf("a big file: %v", err)
	}
}

func TestHashesDependOnEverything(t *testing.T) {
	k1, _ := ParseKey([]byte(keyText(0xf0)))
	k2, _ := ParseKey([]byte(keyText(0xf1)))
	salt1, salt2 := bytes.Repeat([]byte{1}, saltLen), bytes.Repeat([]byte{2}, saltLen)
	of := func(k Key, salt []byte, table, column, metaKey string, kind model.LeakKind, v string) [hashLen]byte {
		h := k.hasher(salt)
		return h.of(h.prefix(table, column, metaKey, kind), v)
	}
	base := of(k1, salt1, "t", "c", "", model.LeakEmail, "a@b.dev")
	if base != of(k1, salt1, "t", "c", "", model.LeakEmail, "a@b.dev") {
		t.Error("hashes must be stable")
	}
	for name, h := range map[string][hashLen]byte{
		"key":      of(k2, salt1, "t", "c", "", model.LeakEmail, "a@b.dev"),
		"salt":     of(k1, salt2, "t", "c", "", model.LeakEmail, "a@b.dev"),
		"table":    of(k1, salt1, "u", "c", "", model.LeakEmail, "a@b.dev"),
		"column":   of(k1, salt1, "t", "d", "", model.LeakEmail, "a@b.dev"),
		"key name": of(k1, salt1, "t", "c", "k", model.LeakEmail, "a@b.dev"),
		"kind":     of(k1, salt1, "t", "c", "", model.LeakSecret, "a@b.dev"),
		"value":    of(k1, salt1, "t", "c", "", model.LeakEmail, "c@b.dev"),
		"shift":    of(k1, salt1, "tc", "", "", model.LeakEmail, "a@b.dev"),
	} {
		if h == base {
			t.Errorf("the %s doesn't change the hash", name)
		}
	}
	// One hasher can be used again.
	h := k1.hasher(salt1)
	p := h.prefix("t", "c", "", model.LeakEmail)
	if h.of(p, "x") == h.of(p, "y") || h.of(p, "x") != h.of(p, "x") {
		t.Error("a hasher must reset between values")
	}
}

func testFile(k Key) *File {
	salt := bytes.Repeat([]byte{7}, saltLen)
	return &File{Format: fileFormat, Version: fileVersion, Notice: fileNotice, Database: "shop", Salt: salt, KeyCheck: k.keyCheck(salt),
		SampleRows: DefaultSampleRows,
		Columns: []FileColumn{{Table: "users", Column: "email", Kind: model.LeakEmail, MaxChars: 4096, Sample: model.SampleSpread,
			Values: 2, Hashes: bytes.Repeat([]byte{9}, 2*hashLen)}},
		LeftOut: []model.LeakLeftOut{{Location: "users.name", Why: "only kinds this check doesn't count"}},
	}
}

func TestFileRoundTrip(t *testing.T) {
	k, _ := ParseKey([]byte(keyText(0xf0)))
	f := testFile(k)
	var b bytes.Buffer
	if err := f.Write(&b); err != nil {
		t.Fatal(err)
	}
	got, err := parseFile(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := got.CheckKey(k); err != nil {
		t.Error(err)
	}
	other, _ := ParseKey([]byte(keyText(0xf1)))
	if err := got.CheckKey(other); !errors.Is(err, ErrWrongKey) {
		t.Errorf("another key: %v", err)
	}
	if len(got.Columns) != 1 || !bytes.Equal(got.Columns[0].Hashes, f.Columns[0].Hashes) || len(got.LeftOut) != 1 {
		t.Errorf("%+v", got)
	}
	// With a BOM, as an editor on Windows may leave it.
	if _, err := parseFile(append([]byte("\xef\xbb\xbf"), b.Bytes()...)); err != nil {
		t.Error(err)
	}
	// The key is nowhere in the file, in any form it might take.
	raw := keyText(0xf0)
	decoded, _ := hex.DecodeString(raw)
	for _, s := range []string{raw, strings.ToUpper(raw), base64.StdEncoding.EncodeToString(decoded), base64.RawURLEncoding.EncodeToString(decoded)} {
		if strings.Contains(b.String(), s) {
			t.Errorf("the key is in the file: %q", s)
		}
	}
	if !strings.Contains(b.String(), "Treat this file as personal data") {
		t.Error("the file must say what it is")
	}
}

func TestFileRefused(t *testing.T) {
	k, _ := ParseKey([]byte(keyText(0xf0)))
	encode := func(change func(*File)) []byte {
		f := testFile(k)
		change(f)
		b, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		name string
		b    []byte
		want error
	}{
		{"not JSON", []byte("not json"), ErrFileFormat},
		{"truncated", encode(func(*File) {})[:40], ErrFileFormat},
		{"another format", encode(func(f *File) { f.Format = "x" }), ErrFileFormat},
		{"a newer version", encode(func(f *File) { f.Version = fileVersion + 1 }), ErrFileVersion},
		{"a short salt", encode(func(f *File) { f.Salt = f.Salt[:4] }), ErrFileFormat},
		{"no key check", encode(func(f *File) { f.KeyCheck = nil }), ErrFileFormat},
		{"cut hashes", encode(func(f *File) { f.Columns[0].Hashes = f.Columns[0].Hashes[:5] }), ErrFileFormat},
		{"a wrong count", encode(func(f *File) { f.Columns[0].Values = 3 }), ErrFileFormat},
		{"a key with no key column", encode(func(f *File) { f.Columns[0].MetaKey = "billing_email" }), ErrFileFormat},
	}
	for _, c := range cases {
		if _, err := parseFile(c.b); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	secret := keyText(0xf0)
	if _, err := ReadFile(filepath.Join(t.TempDir(), secret)); !errors.Is(err, ErrFileUnreadable) || strings.Contains(err.Error(), secret) {
		t.Errorf("a missing file: %v", err)
	}
}

func TestKeyMatcher(t *testing.T) {
	// The most literal pattern wins, in either order.
	for _, keys := range [][]string{{"form_*", "form_*_email"}, {"form_*_email", "form_*"}} {
		m := newKeyMatcher(keys)
		if got := keys[m.match("form_1000_email")]; got != "form_*_email" {
			t.Errorf("%q: form_1000_email went to %q", keys, got)
		}
		if got := keys[m.match("form_1000")]; got != "form_*" {
			t.Errorf("%q: form_1000 went to %q", keys, got)
		}
	}
	m := newKeyMatcher([]string{"billing_email", "um_cache_*", "*_phone", "a*b"})
	for key, want := range map[string]int{
		"billing_email": 0, "BILLING_EMAIL": 0, "billing_email ": 0, "um_cache_12": 1, "UM_CACHE_x": 1, "home_phone": 2,
		"a.b": 3, "axb": 3, "billing": -1, "x_um_cache_1": -1, "phone": -1, "a_c": -1,
	} {
		if got := m.match(key); got != want {
			t.Errorf("%q: %d, want %d", key, got, want)
		}
	}
	if got := likePattern("100%_um!*"); got != "100!%!_um!!%" {
		t.Errorf("like pattern %q", got)
	}
	if l, ok := lookupOf("billing_email"); !ok || l.Prefix || l.Key != "billing_email" {
		t.Errorf("%+v", l)
	}
	if l, ok := lookupOf("um_cache_*"); !ok || !l.Prefix || l.Key != "um_cache_" {
		t.Errorf("%+v", l)
	}
	if _, ok := lookupOf("*_phone"); ok {
		t.Error("a pattern that starts with * can't use the index")
	}
}

func TestKeyedExprsBindKeys(t *testing.T) {
	k, v := &model.Column{Name: "meta_key", DataType: "varchar"}, &model.Column{Name: "meta_value", DataType: "longtext"}
	keyExpr, valueExpr, args := keyedExprs(k, v, 4096, []string{"billing_email", "um_*", "billing_phone"})
	want := "`meta_key` LIKE ? ESCAPE '!' OR `meta_key` IN (?, ?)"
	if keyExpr != "IF("+want+", `meta_key`, NULL)" || valueExpr != "IF("+want+", LEFT(`meta_value`, 4096), NULL)" {
		t.Errorf("%s\n%s", keyExpr, valueExpr)
	}
	if strings.Contains(keyExpr, "billing") || strings.Contains(valueExpr, "billing") {
		t.Error("keys must be bound, not written into the statement")
	}
	if len(args) != 6 || args[0] != "um!_%" || args[1] != "billing_email" || args[3] != "um!_%" || args[5] != "billing_phone" {
		t.Errorf("args: %q", args)
	}
}

func TestOdds(t *testing.T) {
	near := func(got, want, within float64) bool { return math.Abs(got-want) <= within }
	for _, c := range []struct{ n, catch, shown float64 }{
		{300, 0.14, 997}, {1000, 0.39, 298}, {3000, 0.78, 98}, {10000, 0.99, 28},
	} {
		if got := CatchChance(c.n, 100000, 50); !near(got, c.catch, 0.01) {
			t.Errorf("catching 50 at %v: %f", c.n, got)
		}
		if got := ShownAt95(c.n, 100000); !near(got, c.shown, 1) {
			t.Errorf("shown at %v: %f", c.n, got)
		}
	}
	if got := CatchChance(3000, 100000, 5); !near(got, 0.14, 0.01) {
		t.Errorf("catching 5 at 3,000: %f", got)
	}
	if CatchChance(100, 100, 1) != 1 || CatchChance(100, 0, 1) != 1 || ShownAt95(100, 100) != 0 || ShownAt95(100, 0) != 0 {
		t.Error("a sample of everything")
	}
	for _, c := range []struct {
		x    float64
		want int64
	}{{42, 42}, {99.6, 100}, {1234, 1200}, {61800, 62000}, {1_500_000, 1_500_000}} {
		if got := roundTwo(c.x); got != c.want {
			t.Errorf("%v rounds to %d", c.x, got)
		}
	}
}

func TestFillOdds(t *testing.T) {
	base := model.LeakColumn{Kind: model.LeakEmail, State: model.LeakRead, Sample: model.SampleSpread, Sampled: 3000, EstimatedValues: 100000}
	mk := func(change func(*model.LeakColumn)) model.LeakColumn {
		c := base
		change(&c)
		fillOdds(&c)
		return c
	}
	if c := mk(func(c *model.LeakColumn) { c.Values = 100000 }); c.ShownAt95 < 90 || c.ShownAt95 > 110 || c.CatchIfAllReal != 0 {
		t.Errorf("a big staging column: %+v", c)
	}
	if c := mk(func(c *model.LeakColumn) { c.Values = 50 }); c.CatchIfAllReal < 0.7 || c.CatchIfAllReal > 0.85 {
		t.Errorf("a small staging column: %+v", c)
	}
	// No odds where the sample says nothing of the whole column.
	for _, method := range []string{model.SampleFirstRows, model.SampleThin, model.SampleCut} {
		if c := mk(func(c *model.LeakColumn) { c.Sample = method; c.Values = 100 }); c.ShownAt95 != 0 {
			t.Errorf("%s: %+v", method, c)
		}
	}
	for name, change := range map[string]func(*model.LeakColumn){
		"estimate 0":          func(c *model.LeakColumn) { c.EstimatedValues = 0 },
		"estimate under n":    func(c *model.LeakColumn) { c.EstimatedValues = 100 },
		"estimate equal to n": func(c *model.LeakColumn) { c.EstimatedValues = 3000 },
		"nothing sampled":     func(c *model.LeakColumn) { c.Sampled = 0 },
		"exact":               func(c *model.LeakColumn) { c.Exact = true },
		"stopped":             func(c *model.LeakColumn) { c.State = model.LeakStopped },
	} {
		c := mk(func(c *model.LeakColumn) { c.Values = 100; change(c) })
		if c.ShownAt95 != 0 || math.IsNaN(c.ShownAt95) || math.IsInf(c.ShownAt95, 0) || c.CatchIfAllReal != 0 {
			t.Errorf("%s: %+v", name, c)
		}
	}
	// Hits: an estimate from 10 up, on a spread sample only.
	if c := mk(func(c *model.LeakColumn) { c.Found = 1860; c.Values = 100000 }); c.EstimateInAll != 62000 {
		t.Errorf("estimate: %d", c.EstimateInAll)
	}
	if c := mk(func(c *model.LeakColumn) { c.Found = 9; c.Values = 100000 }); c.EstimateInAll != 0 {
		t.Errorf("under 10 hits: %d", c.EstimateInAll)
	}
	if c := mk(func(c *model.LeakColumn) { c.Found = 50; c.Sample = model.SampleFirstRows }); c.EstimateInAll != 0 {
		t.Errorf("first rows: %d", c.EstimateInAll)
	}
	// Chance: only phones and IDs, from 0.5 up, and no estimate within twice it.
	phone := func(found int, values int64) model.LeakColumn {
		return mk(func(c *model.LeakColumn) { c.Kind, c.Found, c.Values = model.LeakPhone, found, values })
	}
	if c := phone(30, 1_000_000); c.ChanceMatches != 30 || c.EstimateInAll != 0 {
		t.Errorf("a faked column: %+v", c)
	}
	if c := phone(60, 1_000_000); c.ChanceMatches != 30 || c.EstimateInAll != 0 {
		t.Errorf("twice the figure: %+v", c)
	}
	if c := phone(61, 1_000_000); c.EstimateInAll == 0 {
		t.Errorf("above twice the figure: %+v", c)
	}
	if c := phone(2, 10000); c.ChanceMatches != 0 {
		t.Errorf("a small figure: %+v", c)
	}
	if c := mk(func(c *model.LeakColumn) { c.Found, c.Values = 30, 1_000_000 }); c.ChanceMatches != 0 {
		t.Errorf("emails don't match by chance: %+v", c)
	}
	// An estimate can't be more than staging was seen to hold, where values
	// repeat and N overshoots.
	if c := mk(func(c *model.LeakColumn) { c.Sampled, c.EstimatedValues, c.Found, c.Values = 944, 31000, 944, 2000 }); c.EstimateInAll != 2000 {
		t.Errorf("capped estimate: %d", c.EstimateInAll)
	}
	// N hardly above n gives no figure rather than "about 0".
	if c := mk(func(c *model.LeakColumn) { c.EstimatedValues, c.Values = 3005, 100 }); c.ShownAt95 != 0 || c.CatchIfAllReal != 0 {
		t.Errorf("N just above n: %+v", c)
	}
}

func TestEstimateValues(t *testing.T) {
	plain := &source{rowsRead: 3000, keyRows: 3000, picked: 3000}
	if got := estimateValues(100000, plain, 3000, 3000, false); got != 100000 {
		t.Errorf("plain: %d", got)
	}
	// A sparse column: 1 row in 10 holds one.
	if got := estimateValues(100000, plain, 300, 300, false); got != 10000 {
		t.Errorf("sparse: %d", got)
	}
	// A key on 1 row in 30, seen at a third of the points.
	keyed := &source{rowsRead: 30000, keyRows: 1000, picked: 1000}
	if got := estimateValues(3000000, keyed, 1000, 1000, false); got != 100000 {
		t.Errorf("keyed: %d", got)
	}
	// A dense key: one row picked per point, of 10 seen.
	dense := &source{rowsRead: 30000, keyRows: 30000, picked: 3000}
	if got := estimateValues(3000000, dense, 3000, 3000, false); got != 3000000 {
		t.Errorf("dense: %d", got)
	}
	// Guards.
	if got := estimateValues(0, plain, 3000, 3000, false); got != 3000 {
		t.Errorf("estimate 0: %d", got)
	}
	if got := estimateValues(100, plain, 3000, 3500, false); got != 3500 {
		t.Errorf("estimate under what was found: %d", got)
	}
	if got := estimateValues(100000, plain, 3000, 2800, true); got != 2800 {
		t.Errorf("exact: %d", got)
	}
	if got := estimateValues(100000, &source{}, 0, 12, false); got != 12 {
		t.Errorf("nothing read at the points: %d", got)
	}
}

func TestGate(t *testing.T) {
	high := model.LeakEmail.Severity()
	col := func(found int, state string, change ...func(*model.LeakColumn)) model.LeakColumn {
		c := model.LeakColumn{Table: "t", Column: "c", Kind: model.LeakEmail, Severity: high, Found: found, State: state, Sample: model.SampleSpread}
		for _, f := range change {
			f(&c)
		}
		return c
	}
	secret := func(c *model.LeakColumn) { c.Kind, c.Severity = model.LeakSecret, model.LeakSecret.Severity() }
	except := func(c *model.LeakColumn) { c.Excepted = true }
	cut := func(c *model.LeakColumn) { c.Sample = model.SampleCut }
	cases := []struct {
		name            string
		cols            []model.LeakColumn
		left            []model.LeakLeftOut
		threshold       model.Severity
		hits, unchecked int
	}{
		{"clean read", []model.LeakColumn{col(0, model.LeakRead)}, nil, model.SeverityHigh, 0, 0},
		{"a hit", []model.LeakColumn{col(3, model.LeakRead)}, nil, model.SeverityHigh, 1, 0},
		{"a hit in a stopped column", []model.LeakColumn{col(3, model.LeakStopped)}, nil, model.SeverityHigh, 1, 0},
		{"a hit below the threshold", []model.LeakColumn{col(3, model.LeakRead)}, nil, model.SeverityCritical, 0, 0},
		{"a secret at critical", []model.LeakColumn{col(3, model.LeakRead, secret)}, nil, model.SeverityCritical, 1, 0},
		{"an excepted hit", []model.LeakColumn{col(3, model.LeakRead, except)}, nil, model.SeverityHigh, 0, 0},
		{"stopped", []model.LeakColumn{col(0, model.LeakStopped)}, nil, model.SeverityHigh, 0, 1},
		{"not read", []model.LeakColumn{col(0, model.LeakNotRead)}, nil, model.SeverityHigh, 0, 1},
		{"not on staging", []model.LeakColumn{col(0, model.LeakNotOnStaging)}, nil, model.SeverityHigh, 0, 1},
		{"unreadable", []model.LeakColumn{col(0, model.LeakUnreadable)}, nil, model.SeverityHigh, 0, 1},
		{"excepted, not on staging", []model.LeakColumn{col(0, model.LeakNotOnStaging, except)}, nil, model.SeverityHigh, 0, 0},
		{"unread below the threshold", []model.LeakColumn{col(0, model.LeakNotRead)}, nil, model.SeverityCritical, 0, 0},
		{"a cut sample with no hit", []model.LeakColumn{col(0, model.LeakRead, cut)}, nil, model.SeverityHigh, 0, 1},
		{"a cut sample with a hit", []model.LeakColumn{col(2, model.LeakRead, cut)}, nil, model.SeverityHigh, 1, 0},
		{"left out for good", nil, []model.LeakLeftOut{{Location: "t.c", Why: "hidden"}}, model.SeverityHigh, 0, 0},
		{"could not be sampled", nil, []model.LeakLeftOut{{Location: "t.c", NotRead: true}}, model.SeverityCritical, 0, 1},
		{"excepted, could not be sampled", nil, []model.LeakLeftOut{{Location: "t.c", NotRead: true, Excepted: true}}, model.SeverityHigh, 0, 0},
	}
	for _, c := range cases {
		hits, unchecked := Gate(&model.LeakResult{Columns: c.cols, LeftOut: c.left}, c.threshold)
		if hits != c.hits || unchecked != c.unchecked {
			t.Errorf("%s: %d hits, %d unchecked", c.name, hits, unchecked)
		}
	}
}

func TestLeakExcept(t *testing.T) {
	for _, c := range []struct {
		except, loc string
		want        bool
	}{
		{"wp_users", "wp_users.user_email", true},
		{"WP_USERS.user_email", "wp_users.user_email", true},
		{"wp_usermeta.meta_value", "wp_usermeta.meta_value[billing_phone]", true},
		{"wp_usermeta.meta_value[billing_phone]", "wp_usermeta.meta_value[billing_phone]", true},
		{"wp_usermeta.meta_value[billing_phone]", "wp_usermeta.meta_value[billing_email]", false},
		{"wp_user", "wp_users.user_email", false},
		{"wp_users.user", "wp_users.user_email", false},
	} {
		if got := model.LeakExcept(c.except, c.loc); got != c.want {
			t.Errorf("%q on %q: %v", c.except, c.loc, got)
		}
	}
}
