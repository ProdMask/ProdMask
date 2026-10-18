package detect

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestTemplate(t *testing.T) {
	uuid := "1f0e2d3c-4b5a-4968-8776-655443322110"
	token := "Ab3" + strings.Repeat("xY9", 6) // 21 letters and digits
	cases := []struct {
		key, pattern string
		carries      model.Category
	}{
		{"um_cache_userdata_123", "um_cache_userdata_123", ""}, // short runs wait for a group
		{"um_cache_userdata_12345", "um_cache_userdata_*", ""},
		{"_transient_feed_" + md5hex("a"), "_transient_feed_*", ""},
		{"subscribers:jane@mail.fixture.gr", "subscribers:*", model.CatEmail},
		{"login_attempts_192.0.2.10", "login_attempts_*", model.CatIPAddress},
		{"seen_2001:db8::1", "seen_*", model.CatIPAddress},
		{"plugin_version_1.2.3.4", "plugin_version_1.2.3.4", ""},
		{"v1.8.1.2_notes", "v1.8.1.2_notes", ""},
		{"build_1.2.3.4.5", "build_1.2.3.4.5", ""},
		{"cache_" + uuid, "cache_*", ""},
		{"user12345_prefs", "user*_prefs", ""},
		{"token_" + token, "token_*", ""},
		{"_billing_address_1", "_billing_address_1", ""},
		{"um_email_as_username_janedoemailfixturegr", "um_email_as_username_*", model.CatEmail},
		{"App::cache::key", "App::cache::key", ""},
		{"wp_mail_smtp", "wp_mail_smtp", ""},
		// Hashes glued to a word, and addresses written with _ or -.
		{"user3f9a2b7c", "user*", ""},
		{"x3121deadbeef01", "x*", ""},
		{"_transient_ip_192_0_2_10", "_transient_ip_*", model.CatIPAddress},
		{"limit-198-51-100-7", "limit-*", model.CatIPAddress},
		{"seq_1_192_0_2_10", "seq_1_192_0_2_10", ""}, // five numbers in a row are no address
		// A quad of single digits is a version, wherever it stands.
		{"plugin_x_1.8.5.4_notice", "plugin_x_1.8.5.4_notice", ""},
		{"widget_1_2_3_4", "widget_1_2_3_4", ""},
	}
	for _, c := range cases {
		got := Template(c.key)
		if got.Pattern != c.pattern || got.Carries != c.carries {
			t.Errorf("Template(%q) = %q (%q), want %q (%q)", c.key, got.Pattern, got.Carries, c.pattern, c.carries)
		}
	}
	if got := Template("_billing_address_1").Short; got != "_billing_address_*" {
		t.Errorf("short template = %q", got)
	}
}

func TestShowKey(t *testing.T) {
	cases := map[string]string{
		"ip":                             "ip",
		"s3":                             "s3",
		"_billing_email":                 "_billing_email",
		"um_cache_userdata_12345":        "um_cache_userdata_*",
		"a_123456":                       HiddenKey, // a pattern needs three literal letters
		"jane@mail.fixture.gr":           HiddenKey,
		"foo*bar":                        HiddenKey, // a stored * would read as a pattern
		strings.Repeat("long_", 14):      HiddenKey,
		"\xce\xa4\xce\xb7\xce\xbb_phone": HiddenKey,
		"Gift message":                   "Gift message",
	}
	for in, want := range cases {
		if got := ShowKey(in); got != want {
			t.Errorf("ShowKey(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ShowPattern("*_*"); got != HiddenKey {
		t.Errorf("ShowPattern(*_*) = %q", got)
	}
}

func TestGroupKeys(t *testing.T) {
	var keys []string
	for i := 1; i <= 6; i++ {
		keys = append(keys, fmt.Sprintf("um_cache_userdata_%d", i))
	}
	for i := 2; i <= 6; i++ {
		keys = append(keys, fmt.Sprintf("wp_%d_capabilities", i))
	}
	keys = append(keys, "_billing_address_1", "_billing_address_2", "session_tokens", "abc*def_12345",
		"_transient_feed_"+md5hex("a"), "_transient_feed_"+md5hex("b"),
		"subscribers:jane@mail.fixture.gr",
		"um_email_as_username_janedoemailfixturegr", "um_email_as_username_maria1mailfixturegr")
	cache := &Hint{Delete: true, Note: "cache"}
	rules := []FamilyRule{{Prefix: "um_cache_userdata_", Hint: cache}}
	exact := func(k string) bool { return k == "session_tokens" }
	singles, families := GroupKeys(keys, rules, exact)

	wantSingles := []string{"_billing_address_1", "_billing_address_2", "abc*def_12345", "session_tokens"} // a stored * stays alone
	if strings.Join(singles, ",") != strings.Join(wantSingles, ",") {
		t.Errorf("singles = %v, want %v", singles, wantSingles)
	}
	got := map[string]KeyFamily{}
	for _, f := range families {
		got[f.Pattern] = f
	}
	for _, w := range []struct {
		pattern string
		keys    int
		carries model.Category
		known   bool
	}{
		{"um_cache_userdata_*", 6, "", true},
		{"wp_*_capabilities", 5, "", false},
		{"_transient_feed_*", 2, "", false},
		{"subscribers:*", 1, model.CatEmail, false},
		{"um_email_as_username_*", 2, model.CatEmail, true},
	} {
		f, ok := got[w.pattern]
		if !ok || len(f.Keys) != w.keys || f.Carries != w.carries || f.Known() != w.known {
			t.Errorf("family %s: got %+v, want %d keys carrying %q (known %v)", w.pattern, f, w.keys, w.carries, w.known)
		}
	}
	if got["um_cache_userdata_*"].Hint != cache {
		t.Error("the preset rule's hint is lost")
	}
	if len(families) != 5 {
		t.Errorf("got %d families: %+v", len(families), families)
	}
}

func TestKeyNameFinding(t *testing.T) {
	_, fams := GroupKeys([]string{"seen:jane@mail.fixture.gr", "seen:maria@mail.fixture.gr"}, nil, nil)
	if len(fams) != 1 {
		t.Fatalf("families: %+v", fams)
	}
	f := KeyNameFinding("wp_usermeta", "meta_key", fams[0].Pattern, &fams[0], false)
	if !f.KeyName || f.Column != "meta_key" || f.MetaKey != "seen:*" || f.Category != model.CatEmail ||
		f.Keys != 2 || f.Matched != 2 || f.Severity != model.SeverityHigh || f.Mask != "fake_email" {
		t.Fatalf("got %+v", f)
	}
	if want := "2 of 2 key names hold an email address in the part matched by *"; f.Reasons[0] != want {
		t.Errorf("reason %q, want %q", f.Reasons[0], want)
	}
}

func TestNormKeyTemplates(t *testing.T) {
	cases := map[string]string{
		"um_email_as_username_janedoemailfixturegr": "um_email_as_username_*",
		"cart_" + md5hex("x"):                       "cart_*",
		"billing_address_1":                         "billing_address_1",
		"a_123456":                                  "*",
		"session_9876":                              "session_*",
	}
	for in, want := range cases {
		if got := normKey(in); got != want {
			t.Errorf("normKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// Limit Login Attempts keeps visitor IPs as the keys of its arrays.
func TestWalkIPKeys(t *testing.T) {
	lockouts := "a:1:{" + phpStr("192.0.2.10") + "i:1760000000;}"
	got := collect(t, lockouts)
	if got["{}"] != "192.0.2.10" || got["*"] != "1760000000" {
		t.Fatalf("got %v", got)
	}
	logged := "a:1:{" + phpStr("2001:db8::7") + "a:1:{" + phpStr("admin") + "i:3;}}"
	got = collect(t, logged)
	if got["{}"] != "2001:db8::7" || got["*.admin"] != "3" {
		t.Fatalf("got %v", got)
	}
	// A quad of single digits is a version, not a visitor.
	if got := collect(t, "a:1:{"+phpStr("1.8.5.4")+"i:0;}"); got["{}"] != "" {
		t.Errorf("version key taken for an IP: %v", got)
	}
	// One lockout is enough at {}: every key there is an IP by construction.
	fs := Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "limit_login_lockouts",
		Name: "limit_login_lockouts", Sampled: true}, profileOf(lockouts))
	if f := find(fs, model.CatIPAddress, "{}"); f == nil || f.Confidence < model.ConfidenceMedium {
		t.Fatalf("got %+v", fs)
	}
	// Loopback keys identify no one.
	local := "a:1:{" + phpStr("127.0.0.1") + "i:1760000000;}"
	fs = Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "limit_login_lockouts",
		Name: "limit_login_lockouts", Sampled: true}, profileOf(local))
	if f := find(fs, model.CatIPAddress, "{}"); f != nil {
		t.Fatalf("loopback key reported: %+v", f)
	}
	// WPForms keeps install times by version, and 1.8.5.4 reads as an IP.
	versions := "a:2:{" + phpStr("1.6.7.2") + "i:0;" + phpStr("1.8.5.4") + "i:1760000000;}"
	for name, v := range map[string]string{
		"wpforms_versions_lite": versions,
		"plugin_state":          "a:1:{" + phpStr("versions") + versions + "}",
	} {
		p := NewProfileNamed(name)
		p.Add(v)
		fs = Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: name, Name: name, Sampled: true}, p)
		for _, f := range fs {
			if f.Category == model.CatIPAddress {
				t.Errorf("%s: version keys reported as IPs: %+v", name, f)
			}
		}
	}
}

func TestReadKey(t *testing.T) {
	for key, label := range map[string]bool{
		"Your Name": true, "Emergency contact": true, "Delivery date": true, "Gift message": true,
		"Phone number": true, "VAT number": true, "shipping method": true, "Date of birth": true,
		"Bank account": true, "Credit card": true, "Card holder": true,
		"Jane Doe phone": false, "Next of kin": false, "John Street": false, "Peter Pan": false,
		"Shipping Method": false, "Jane Doe": false, "Bank of America": false,
		// A number beside a name is no label word; a label keeps its number.
		"Jane 2": false, "Peter 4": false, "Maria 1": false, "jane2 x": false, "maria3 x": false,
		"Address line 2": true, "Address Line 2": true, "Line 1": true, "Phone 2": true, "Email 2": true, "Your Name 2": true,
	} {
		if got := ReadKey(key).Label; got != label {
			t.Errorf("ReadKey(%q).Label = %v, want %v (%+v)", key, got, label, ReadKey(key))
		}
	}
	if kw := ReadKey("Jane Doe"); len(kw.Known) != 0 || kw.Unknown != 2 {
		t.Errorf("Jane Doe: got %+v", kw)
	}
	if kw := ReadKey("Jane Doe phone"); !reflect.DeepEqual(kw.Known, []string{"phone"}) || kw.Unknown != 2 {
		t.Errorf("Jane Doe phone: got %+v", kw)
	}
	for key, free := range map[string]bool{
		"Jane Doe": true, "Next of kin": true, "Phone number": false, "billing_email": false, "um_key": false,
	} {
		if got := FreeTextKey(key); got != free {
			t.Errorf("FreeTextKey(%q) = %v, want %v", key, got, free)
		}
	}
}
