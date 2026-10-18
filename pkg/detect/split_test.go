package detect

import (
	"reflect"
	"testing"
)

func TestNameWords(t *testing.T) {
	cases := map[string][]string{
		"regip":            {"reg", "ip"},
		"lastip":           {"last", "ip"},
		"loginkey":         {"login", "key"},
		"authkey":          {"auth", "key"},
		"summonername":     {"summoner", "name"},
		"lastloginip":      {"last", "login", "ip"},
		"appsecret":        {"app", "secret"},
		"adminpass":        {"admin", "pass"},
		"ftppass":          {"ftp", "pass"},
		"newpass":          {"new", "pass"},
		"newemail":         {"new", "email"},
		"srcaddr":          {"src", "addr"},
		"member_login_key": {"member", "login", "key"},
		// Words the rules know, words with no lead word, and IDs stay whole.
		"surname":     {"surname"},
		"telephone":   {"telephone"},
		"password":    {"password"},
		"website":     {"website"},
		"postcode":    {"postcode"},
		"hostname":    {"hostname"},
		"filename":    {"filename"},
		"membership":  {"membership"},
		"tooltip":     {"tooltip"},
		"skip":        {"skip"},
		"sociallogin": {"sociallogin"},
		"daypass":     {"daypass"},
		"pagetoken":   {"pagetoken"},
		"zorgname":    {"zorgname"},
		"authkey_id":  {"auth", "key", "id"},
		"firstlogin":  {"first", "login"},
		"username":    {"user", "name"},
	}
	for in, want := range cases {
		if got := NameWords(in); !reflect.DeepEqual(got, want) {
			t.Errorf("NameWords(%q) = %q, want %q", in, got, want)
		}
	}
	// Tokens itself doesn't split them: relationship inference still looks
	// for an authkey table behind authkey_id.
	if got := Tokens("authkey_id"); !reflect.DeepEqual(got, []string{"authkey", "id"}) {
		t.Errorf("Tokens(authkey_id) = %q", got)
	}
}
