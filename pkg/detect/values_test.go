package detect

import (
	"strings"
	"testing"
)

// The secret-looking strings below are built at run time so that no
// complete token appears in the repository.

func TestIsEmail(t *testing.T) {
	for _, s := range []string{"jane.doe@mail.fixture.gr", "a+b@sub.domain.co.uk", "o'brien@shop.ie"} {
		if !IsEmail(s) {
			t.Errorf("IsEmail(%q) = false", s)
		}
	}
	for _, s := range []string{"logo@2x.png", "not an email", "jane@localhost", "@example.com", "a@b"} {
		if IsEmail(s) {
			t.Errorf("IsEmail(%q) = true", s)
		}
	}
	if !reservedEmail("user1@example.com") || !reservedEmail("x@shop.test") || reservedEmail("x@fixture.gr") {
		t.Error("reservedEmail misjudged a domain")
	}
	if !containsEmail("please write to jane.doe@mail.fixture.gr today") || containsEmail("see logo@2x.png") {
		t.Error("containsEmail misjudged text")
	}
}

func TestPhoneShape(t *testing.T) {
	cases := []struct {
		in         string
		ok, strict bool
	}{
		{"+30 210 555 0123", true, true},
		{"(555) 010-1234", true, true},
		{"555-010-1234", true, true},
		{"+12025550123", true, true},
		{"5550101234", true, false},
		{"2024-01-15", false, false},
		{"1.234.567", false, false},
		{"192.168.100.200", false, false},
		{"12", false, false},
		{"call me", false, false},
	}
	for _, c := range cases {
		ok, strict := phoneShape(c.in)
		if ok != c.ok || strict != c.strict {
			t.Errorf("phoneShape(%q) = %v, %v; want %v, %v", c.in, ok, strict, c.ok, c.strict)
		}
	}
	if !containsPhone("Call +30 210 555 0123 after 5pm") || containsPhone("Order 1234 shipped on 2024-01-15") {
		t.Error("containsPhone misjudged text")
	}
}

func TestIP(t *testing.T) {
	for _, s := range []string{"192.0.2.10", "2001:db8::1", "203.0.113.5, 10.0.0.1"} {
		if !isIP(s) {
			t.Errorf("isIP(%q) = false", s)
		}
	}
	for _, s := range []string{"1.2.3", "::", "01.2.3.4", "hello", "10.0.0.1, nope"} {
		if isIP(s) {
			t.Errorf("isIP(%q) = true", s)
		}
	}
	if !containsIP("blocked login from 198.51.100.7 at 10:00") {
		t.Error("containsIP missed an address")
	}
}

func TestIBAN(t *testing.T) {
	for _, s := range []string{"GB82 WEST 1234 5698 7654 32", "DE89370400440532013000"} {
		if !isIBAN(s) {
			t.Errorf("isIBAN(%q) = false", s)
		}
	}
	for _, s := range []string{"GB82 WEST 1234 5698 7654 33", "HELLO WORLD 123456", "1234567890123456"} {
		if isIBAN(s) {
			t.Errorf("isIBAN(%q) = true", s)
		}
	}
}

// luhnNumber completes a card number prefix with a valid check digit.
func luhnNumber(prefix string) string {
	for d := byte('0'); d <= '9'; d++ {
		s := prefix + string(d)
		if luhn([]byte(s)) {
			return s
		}
	}
	panic("unreachable")
}

func TestCardNumber(t *testing.T) {
	if ok, test := cardNumber("4242 4242 4242 4242"); !ok || !test {
		t.Errorf("Stripe test card: ok=%v test=%v", ok, test)
	}
	real := luhnNumber("491761234567890")
	if ok, test := cardNumber(real); !ok || test {
		t.Errorf("generated Visa number: ok=%v test=%v", ok, test)
	}
	for _, s := range []string{"4242 4242 4242 4241", "1234567812345670", "0000000000000000", "4242-4242"} {
		if ok, _ := cardNumber(s); ok {
			t.Errorf("cardNumber(%q) = true", s)
		}
	}
	if !containsCard("my card is " + real + " exp 12/29") {
		t.Error("containsCard missed a number in text")
	}
}

func TestPasswordHash(t *testing.T) {
	salt := strings.Repeat("aB3./", 11)[:53]
	cases := map[string]string{
		"$2y$10$" + salt:                   "bcrypt",
		"$wp$2y$10$" + salt:                "WordPress bcrypt",
		"$P$B" + strings.Repeat("x7Y", 10): "phpass",
		strings.Repeat("ab", 32) + ":" + strings.Repeat("Z", 32) + ":3_32_2_67108864": "Magento",
	}
	for in, want := range cases {
		if got := passwordHash(in); got != want {
			t.Errorf("passwordHash(%q) = %q, want %q", in, got, want)
		}
	}
	if passwordHash("correct horse battery staple and more") != "" {
		t.Error("prose taken for a hash")
	}
}

func TestFindSecrets(t *testing.T) {
	stripeLive := "sk_" + "live_" + strings.Repeat("a1B2", 6)
	stripeTest := "sk_" + "test_" + strings.Repeat("c3D4", 6)
	aws := "AKIA" + "IOSFODNN7EXAMPLE"
	jwt := "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + "." + strings.Repeat("sig_", 5)
	ant := "sk-" + "ant-api03-" + strings.Repeat("Ab9_", 10)

	cases := []struct {
		in   string
		kind string
		mode string
	}{
		{"key=" + stripeLive, "Stripe secret key", "live"},
		{stripeTest, "Stripe secret key", "test"},
		{"aws " + aws + " here", "AWS access key ID", "live"},
		{jwt, "JSON Web Token", ""},
		{ant, "Anthropic API key", "live"},
	}
	for _, c := range cases {
		hits := FindSecrets(c.in)
		if len(hits) != 1 || hits[0].Kind != c.kind || hits[0].Mode != c.mode {
			t.Errorf("FindSecrets(%s...) = %+v, want one %s (%s)", c.in[:6], hits, c.kind, c.mode)
		}
	}
	if hits := FindSecrets("plain text with sk_ and AKIA mentioned"); len(hits) != 0 {
		t.Errorf("false positives: %+v", hits)
	}
}
