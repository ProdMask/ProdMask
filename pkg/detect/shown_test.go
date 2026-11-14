package detect

import (
	"sort"
	"strings"
	"testing"
)

// TestShowType checks which polymorphic type values the reports may show: a
// class name or a plain word prints, no type stays empty, and anything else
// is HiddenType.
func TestShowType(t *testing.T) {
	for v, want := range map[string]string{
		`App\Models\User`:  `App\Models\User`,
		`\App\Models\User`: `\App\Models\User`,
		`Admin::Post`:      `Admin::Post`,
		`post`:             `post`,
		`order_item`:       `order_item`,
		`Comment2`:         `Comment2`,
		"":                 "",
		// Shaped like data, or not a name at all. A dot joins no words, so
		// a host name or a login doesn't print.
		`App.Models.Order`:                    HiddenType,
		`shop.example.com`:                    HiddenType,
		`john.smith`:                          HiddenType,
		`https://shop.example/users`:          HiddenType,
		`users/jsmith@example.com`:            HiddenType,
		`jsmith@example.com`:                  HiddenType,
		`App\Models\9f86d081884c7d659a2feaa0`: HiddenType,
		`App\Models\a9f86d081884c7d6`:         HiddenType, // a hash that starts with a letter, which Template finds
		`Order20231114`:                       HiddenType,
		`App\Models\User extra`:               HiddenType,
		`App\\Models`:                         HiddenType,
		`App\Models\`:                         HiddenType,
		`1Post`:                               HiddenType,
		"Post\x1b[2J":                         HiddenType,
		strings.Repeat("A", 129):              HiddenType,
	} {
		if got := ShowType(v); got != want {
			t.Errorf("ShowType(%q) = %q, want %q", v, got, want)
		}
	}
}

// TestShownKeysMatchTheDocs pins what docs/config.md says about keys from the
// data: those shaped like data are hidden; a key that reads as a word, or in
// a key/value table as words with spaces, is shown as stored, so a login used
// as a map key shows; and so is an IP address after a dot or one that reads
// like a version number.
func TestShownKeysMatchTheDocs(t *testing.T) {
	for key, want := range map[string]string{
		"jsmith@example.com":                      HiddenKey,
		"192.168.1.20":                            HiddenKey,
		"3f2504e0-4f89-11d3-9a0c-0305e82c3301":    HiddenKey,
		"9f86d081884c7d659a2feaa0c55ad015":        HiddenKey,
		"x9Kq2mLp7Rt4Vw8Zb3Nc":                    HiddenKey,
		"1234":                                    HiddenKey,
		"a key with a % sign":                     HiddenKey,
		"um_email_as_username_jsmith@example.com": "um_email_as_username_*",
		"jsmith":     "jsmith",
		"John Smith": "John Smith",
		"123":        "123",
		// What the rules let through, by shape.
		"rl.203.0.113.5": "rl.203.0.113.5",
		"1.2.3.4":        "1.2.3.4",
	} {
		if got := ShowKey(key); got != want {
			t.Errorf("ShowKey(%q) = %q, want %q", key, got, want)
		}
	}
	paths := func(s string) string {
		var out []string
		Walk(s, func(path []string, _ string) { out = append(out, JoinPath(path)) })
		sort.Strings(out)
		return strings.Join(out, " ")
	}
	for value, want := range map[string]string{
		`{"jsmith": {"email": "j@example.com"}}`:     "jsmith.email",
		`{"12345": {"email": "j@example.com"}}`:      "[].email",
		`{"123": {"email": "j@example.com"}}`:        "[].email",
		`{"John Smith": {"email": "j@example.com"}}`: "*.email",
	} {
		if got := paths(value); got != want {
			t.Errorf("paths of %s = %q, want %q", value, got, want)
		}
	}
	// A key shaped like data is also handed to the finders as a value, at {}.
	if got := paths(`{"jsmith@example.com": {"email": "j@example.com"}}`); !strings.Contains(" "+got+" ", " *.email ") ||
		strings.Contains(got, "jsmith") {
		t.Errorf("paths of an email-keyed map = %q", got)
	}
}
