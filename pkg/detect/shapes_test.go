package detect

import (
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

func TestShapes(t *testing.T) {
	for v, want := range map[string]bool{
		"https://shop.fixture.test/callback?email=jane@mail.fixture.gr":   true,
		"https://shop.fixture.test/callback?email=jane%40mail.fixture.gr": true,
		"/donate?to=jane@mail.fixture.gr":                                 true,
		"a=1&email=jane@mail.fixture.gr":                                  true,
		"https://blog.fixture.test/jane@mail.fixture.gr":                  true,
		"mysql://app:pw@db.fixture.test/shop":                             false,
		"ssh://git@git.fixture.test/repo":                                 false,
		"git@github.com:org/repo.git":                                     false,
		"<id@mail.fixture.test>":                                          false,
		"https://shop.fixture.test/cart":                                  false,
	} {
		if got := inlineEmail(v); got != want {
			t.Errorf("inlineEmail(%q) = %v, want %v", v, got, want)
		}
	}
	for v, want := range map[string]bool{
		"a3bb189e-8bf9-4888-9912-ace4e6543002":                   true,
		"{A3BB189E-8BF9-4888-9912-ACE4E6543002}":                 true,
		"0A1B2C3D-4E5F-4061-8273-94A5B6C7D8E9|00:1A:2B:3C:4D:5E": true,
		"00:1A:2B:3C:4D:5E:6F":                                   true,
		"356938035643809":                                        true,
		"CNC-01":                                                 false,
		"MACHINE-NUMBER-01":                                      false,
	} {
		if got := opaque(v); got != want {
			t.Errorf("opaque(%q) = %v, want %v", v, got, want)
		}
	}
	for v, want := range map[string]bool{
		"From: [your-name] <[your-email]>": true,
		"Hello [name], thanks":             true,
		"Hi {first_name}":                  true,
		"Hi {{ customer.name }}":           true,
		"Dear %name%":                      true,
		"[quote]see above[/quote] I agree": false,
		"[b]Hello[/b] there":               false,
		"[url=https://x.test]link[/url]":   false,
		"Plain words only":                 false,
	} {
		if got := mergeTag(v); got != want {
			t.Errorf("mergeTag(%q) = %v, want %v", v, got, want)
		}
	}
	for v, want := range map[string]bool{
		"1" + strings.Repeat("A1b2C3d4", 4):    true,
		"bc1q" + strings.Repeat("w508d6qe", 4): true,
		"0x" + strings.Repeat("ab12", 10):      true,
		"10 Downing Street":                    false,
	} {
		if got := cryptoAddress(v); got != want {
			t.Errorf("cryptoAddress(%q) = %v, want %v", v, got, want)
		}
	}
}

// Email addresses inside URLs make free text; mailto: links are emails.
func TestAnalyzeInlineEmails(t *testing.T) {
	var urls []string
	for i := 0; i < 10; i++ {
		urls = append(urls, "https://pay.fixture.test/cb?id=1&email=buyer"+strings.Repeat("x", i)+"@mail.fixture.gr")
	}
	fs := Analyze(subject("donations", "callback_url", "varchar"), namedProfile("callback_url", urls...))
	if f := find(fs, model.CatFreeText, ""); f == nil || f.Confidence != model.ConfidenceHigh || f.Mask != "redact" {
		t.Errorf("callback URLs: got %+v", fs)
	}
	fs = Analyze(subject("contacts", "email", "varchar"), namedProfile("email", repeat(5, "mailto:jane@mail.fixture.gr")...))
	if f := find(fs, model.CatEmail, ""); f == nil || f.Confidence != model.ConfidenceHigh {
		t.Errorf("mailto links: got %+v", fs)
	}
	if find(fs, model.CatFreeText, "") != nil {
		t.Errorf("mailto links read as free text: %+v", fs)
	}
	repos := []string{"git@github.com:org/repo.git", "ssh://git@git.fixture.test/r", "mysql://app:pw@db.fixture.test/x"}
	if fs := Analyze(subject("deploys", "remote", "varchar"), namedProfile("remote", repos...)); len(confident(fs)) != 0 {
		t.Errorf("remotes: got %+v", fs)
	}
	// One link with an address among 300 notes stays low, as one address
	// typed into the text would.
	notes := append(repeat(299, "Called back, will ship on Monday"), urls[0])
	fs = Analyze(subject("orders", "notes", "text"), namedProfile("notes", notes...))
	if f := find(fs, model.CatFreeText, ""); f == nil || f.Confidence != model.ConfidenceLow {
		t.Errorf("one link in 300 notes: got %+v", fs)
	}
}

// Values that rule a name out: URLs and paths, cryptocurrency addresses.
func TestAnalyzeValuesRuleOutNames(t *testing.T) {
	paths := []string{"/index.php", "/forum/topic-1", "/members/", "/login", "/search?q=x"}
	fs := Analyze(subject("logs", "address", "varchar"), namedProfile("address", paths...))
	if f := find(fs, model.CatAddress, ""); f == nil || f.Confidence != model.ConfidenceLow || !strings.Contains(f.Note, "URLs") {
		t.Errorf("paths: got %+v", fs)
	}
	btc := repeat(5, "1"+strings.Repeat("A1b2C3d4", 4))
	fs = Analyze(subject("donations", "input_address", "varchar"), namedProfile("input_address", btc...))
	if f := find(fs, model.CatAddress, ""); f == nil || f.Confidence != model.ConfidenceLow || !strings.Contains(f.Note, "cryptocurrency") {
		t.Errorf("wallets: got %+v", fs)
	}
	// A website keeps its URLs.
	fs = Analyze(subject("users", "website", "varchar"), namedProfile("website", repeat(5, "https://blog.fixture.test")...))
	if f := find(fs, model.CatWebsite, ""); f == nil || f.Confidence == model.ConfidenceLow {
		t.Errorf("website: got %+v", fs)
	}
}

// A ban list of email and IP addresses is free text no single check finds.
func TestAnalyzeIdentifierLists(t *testing.T) {
	fs := Analyze(subject("banfilters", "ban_content", "text"), namedProfile("ban_content", "spam@mail.fixture.gr", "203.0.113.7"))
	if f := find(fs, model.CatFreeText, ""); f == nil || f.Confidence != model.ConfidenceMedium {
		t.Errorf("ban list: got %+v", fs)
	}
	// A Unix time isn't a phone number.
	fs = Analyze(subject("bans", "ban_value", "text"), namedProfile("ban_value", "203.0.113.7", "1760000000"))
	if len(confident(fs)) != 0 {
		t.Errorf("IP and Unix time: got %+v", fs)
	}
	// One kind stays with its own check.
	fs = Analyze(subject("bans", "ban_value", "text"), namedProfile("ban_value", "spam@mail.fixture.gr", "junk@mail.fixture.gr"))
	if find(fs, model.CatFreeText, "") != nil || find(fs, model.CatEmail, "") == nil {
		t.Errorf("emails only: got %+v", fs)
	}
	// A free-text name with such values: the values back it.
	fs = Analyze(subject("orders", "notes", "text"), namedProfile("notes", "spam@mail.fixture.gr", "+30 210 555 0123"))
	if f := find(fs, model.CatFreeText, ""); f == nil || f.Confidence != model.ConfidenceMedium || f.Matched != 2 ||
		!strings.Contains(f.Source, "value") || strings.Contains(f.Note, "no personal data spotted") {
		t.Errorf("named list: got %+v", fs)
	}
}

// Messages between people are medium when they're prose, even with no
// email or phone in them; templates and logs aren't messages.
func TestAnalyzeMessages(t *testing.T) {
	titles := []string{"Question about my order", "Re: meeting on Friday", "Thanks for the help!",
		"Can you call me back", "Lost my password again"}
	fs := Analyze(subject("message_topics", "mt_title", "varchar"), namedProfile("mt_title", titles...))
	if f := find(fs, model.CatFreeText, ""); f == nil || f.Confidence != model.ConfidenceMedium ||
		!strings.Contains(f.Note, "messages between people") {
		t.Errorf("message titles: got %+v", fs)
	}
	quoted := repeat(4, "[quote name=\"kostas\"]see above[/quote] I agree with this, thanks")
	fs = Analyze(subject("smf_personal_messages", "body", "text"), namedProfile("body", quoted...))
	if f := find(fs, model.CatFreeText, ""); f == nil || f.Confidence != model.ConfidenceMedium {
		t.Errorf("quoted replies: got %+v", fs)
	}
	// Contact Form 7's mail template, inside a meta value.
	tmpl := "a:2:{" + phpStr("subject") + phpStr("[your-subject] from [name]") +
		phpStr("body") + phpStr("From: [your-name] <[your-email]>\nMessage: [your-message]") + "}"
	fs = Analyze(Subject{Table: "wp_postmeta", Column: "meta_value", MetaKey: "_mail", Name: "_mail",
		Context: Tokens("wp_postmeta"), Sampled: true}, namedProfile("_mail", repeat(4, tmpl)...))
	if len(confident(fs)) != 0 {
		t.Errorf("mail templates: got %+v", fs)
	}
	// One address in many messages still leaves them at medium at least.
	many := append(repeat(29, "See you at the meeting on Friday"), "Write to me at jane@mail.fixture.gr please")
	fs = Analyze(subject("message_topics", "mt_title", "varchar"), namedProfile("mt_title", many...))
	if f := find(fs, model.CatFreeText, ""); f == nil || f.Confidence != model.ConfidenceMedium {
		t.Errorf("messages with one address: got %+v", fs)
	}
	// Free text the old rule matches keeps today's behaviour.
	fs = Analyze(subject("aiowps_message_store", "message_value", "text"), namedProfile("message_value", titles...))
	if f := find(fs, model.CatFreeText, ""); f == nil || f.Confidence != model.ConfidenceLow {
		t.Errorf("old free-text rule: got %+v", fs)
	}
	// Titles in Greek are prose too.
	greek := []string{
		"\xce\x95\xcf\x81\xcf\x8e\xcf\x84\xce\xb7\xcf\x83\xce\xb7 \xce\xb3\xce\xb9\xce\xb1 \xcf\x84\xce\xb7\xce\xbd \xcf\x80\xce\xb1\xcf\x81\xce\xb1\xce\xb3\xce\xb3\xce\xb5\xce\xbb\xce\xaf\xce\xb1 \xce\xbc\xce\xbf\xcf\x85",
		"\xce\x95\xcf\x85\xcf\x87\xce\xb1\xcf\x81\xce\xb9\xcf\x83\xcf\x84\xcf\x8e \xcf\x80\xce\xbf\xce\xbb\xcf\x8d \xce\xb3\xce\xb9\xce\xb1 \xcf\x84\xce\xb7 \xce\xb2\xce\xbf\xce\xae\xce\xb8\xce\xb5\xce\xb9\xce\xb1",
		"\xce\x9c\xcf\x80\xce\xbf\xcf\x81\xce\xb5\xce\xaf\xcf\x84\xce\xb5 \xce\xbd\xce\xb1 \xce\xbc\xce\xb5 \xce\xba\xce\xb1\xce\xbb\xce\xad\xcf\x83\xce\xb5\xcf\x84\xce\xb5 \xce\xb1\xcf\x8d\xcf\x81\xce\xb9\xce\xbf",
		"\xce\xa3\xcf\x85\xce\xbd\xce\xac\xce\xbd\xcf\x84\xce\xb7\xcf\x83\xce\xb7 \xcf\x84\xce\xb7\xce\xbd \xce\xa0\xce\xb1\xcf\x81\xce\xb1\xcf\x83\xce\xba\xce\xb5\xcf\x85\xce\xae \xcf\x84\xce\xbf \xcf\x80\xcf\x81\xcf\x89\xce\xaf",
		"\xce\x88\xcf\x87\xce\xb1\xcf\x83\xce\xb1 \xce\xbe\xce\xb1\xce\xbd\xce\xac \xcf\x84\xce\xbf\xce\xbd \xce\xba\xcf\x89\xce\xb4\xce\xb9\xce\xba\xcf\x8c \xce\xbc\xce\xbf\xcf\x85",
	}
	fs = Analyze(subject("message_topics", "mt_title", "varchar"), namedProfile("mt_title", greek...))
	if f := find(fs, model.CatFreeText, ""); f == nil || f.Confidence != model.ConfidenceMedium {
		t.Errorf("Greek titles: got %+v", fs)
	}
}

// A day, month or year of birth on its own is emptied, not faked.
func TestAnalyzeBirthdayParts(t *testing.T) {
	for _, c := range []struct {
		column, dataType string
		values           []string
		mask             string
	}{
		{"bday_day", "int", []string{"12", "3", "28"}, "null"},
		{"birth_month", "int", []string{"4", "11", "7"}, "null"},
		{"birth_year", "int", []string{"1985", "1990", "2001"}, "null"},
		{"bday_month", "varchar", []string{"4", "11", "7"}, "null"},
		{"birth_day", "varchar", []string{"1985-04-12", "1990-11-03", "2001-07-30"}, "fake_date"},
	} {
		fs := Analyze(subject("members", c.column, c.dataType), namedProfile(c.column, c.values...))
		f := find(fs, model.CatDateOfBirth, "")
		if f == nil || f.Confidence == model.ConfidenceLow || f.Mask != c.mask {
			t.Errorf("%s: got %+v", c.column, fs)
		}
	}
	// A whole date stored as a number, as YYYYMMDD or a Unix time, is
	// emptied too, but it isn't a part.
	for _, values := range [][]string{{"19850412", "19901103", "20010730"}, {"482112000", "657590400", "996451200"}} {
		fs := Analyze(subject("members", "birthday", "int"), namedProfile("birthday", values...))
		f := find(fs, model.CatDateOfBirth, "")
		if f == nil || f.Mask != "null" || strings.Contains(f.Note, "split") || !strings.Contains(f.Note, "stored as a number") {
			t.Errorf("birthday %v: got %+v", values, fs)
		}
	}
}

// Device IDs need opaque values to be sure of them. An IMEI stored as a
// number gets a number, which a hash wouldn't be.
func TestAnalyzeDeviceIDs(t *testing.T) {
	for _, c := range []struct {
		column, dataType string
		values           []string
		conf             model.Confidence
		mask             string
	}{
		{"machine_id", "varchar", []string{"CNC-01", "CNC-02", "LATHE-3"}, model.ConfidenceLow, "hash"},
		{"imei", "bigint", []string{"356938035643809", "490154203237518"}, model.ConfidenceHigh, "fake_number"},
		{"hwid", "text", repeat(3, strings.Repeat("9f8e7d6c", 4)), model.ConfidenceHigh, "hash"},
		{"hwid", "text", repeat(3, "{A3BB189E-8BF9-4888-9912-ACE4E6543002}"), model.ConfidenceHigh, "hash"},
		{"hwid", "text", repeat(3, "0A1B2C3D-4E5F-4061-8273-94A5B6C7D8E9|00:1A:2B:3C:4D:5E"), model.ConfidenceHigh, "hash"},
	} {
		fs := Analyze(subject("members", c.column, c.dataType), namedProfile(c.column, c.values...))
		f := find(fs, model.CatDeviceID, "")
		if f == nil || f.Confidence != c.conf || f.Mask != c.mask {
			t.Errorf("%s %v: got %+v", c.column, c.values, fs)
		}
	}
}

// A number column takes only numbers: where a category's fake isn't one,
// the finding suggests fake_number, a number of the original's shape, and
// says why. Phones and cards stay, and so do the masks that make no fake,
// and an IP address in an INT or a BIGINT, which a copy writes as its
// number; one in a smaller integer column gets a number too. Text keeps its
// fakes.
func TestAnalyzeNumberColumns(t *testing.T) {
	const note = "stored as a number, which a fake "
	for _, c := range []struct {
		column, dataType string
		values           []string
		cat              model.Category
		mask             string
	}{
		{"zip", "int", []string{"10115", "8542", "30001"}, model.CatPostcode, "fake_number"},
		{"postcode", "mediumint", []string{"10115", "8542", "30001"}, model.CatPostcode, "fake_number"},
		{"account_number", "bigint", []string{"12345678901", "98765432109"}, model.CatBankAccount, "fake_number"},
		{"imei", "bigint", []string{"356938035643809", "490154203237518"}, model.CatDeviceID, "fake_number"},
		{"mobile", "bigint", []string{"12125550101", "12125550102", "12125550103"}, model.CatPhone, "fake_phone"},
		{"card_number", "bigint", []string{"4242424242424242", "5555555555554444"}, model.CatCardNumber, "test_card"},
		{"gender", "int", []string{"1", "2", "1"}, model.CatGender, "keep"},
		{"birth_year", "int", []string{"1985", "1990", "2001"}, model.CatDateOfBirth, "null"},
		{"lat", "decimal", []string{"37.9838", "40.6401"}, model.CatGeo, "null"},
		{"last_ip", "int", []string{"3232235777", "167772161", "2886729729"}, model.CatIPAddress, "fake_ip"},
		{"remote_ip", "bigint", []string{"3232235777", "167772161", "2886729729"}, model.CatIPAddress, "fake_ip"},
		{"ip", "smallint", nil, model.CatIPAddress, "fake_number"},
		{"zip", "varchar", []string{"10115", "8542", "30001"}, model.CatPostcode, "fake_postcode"},
		{"account_number", "varchar", []string{"12345678901", "98765432109"}, model.CatBankAccount, "fake_iban"},
	} {
		sub := subject("members", c.column, c.dataType)
		var p *Profile
		if c.values == nil {
			sub.Sampled = false
		} else {
			p = namedProfile(c.column, c.values...)
		}
		f := find(Analyze(sub, p), c.cat, "")
		if f == nil || f.Confidence == model.ConfidenceLow || f.Mask != c.mask || strings.Contains(f.Note, note) != (c.mask == "fake_number") {
			t.Errorf("%s %s: got %+v", c.column, c.dataType, f)
		}
	}
	// Unsampled, the name decides alone.
	sub := subject("members", "zip", "int")
	sub.Sampled = false
	if f := find(Analyze(sub, nil), model.CatPostcode, ""); f == nil || f.Mask != "fake_number" {
		t.Errorf("an unsampled INT zip: got %+v", f)
	}
	// A preset's masks for some of the rows take numbers too, with the same
	// note, but those that make no fake; the preset's own stay as they were.
	rows := []model.RowMask{{Where: "kind = 'shop'", Mask: "fake_postcode"}, {Where: "kind = 'staff'", Mask: "keep"}}
	sub = subject("members", "zip", "int")
	sub.Hint = &Hint{Category: model.CatPostcode, Mask: "fake_postcode", Rows: rows, Source: "preset:test"}
	f := find(Analyze(sub, namedProfile("zip", "10115", "8542", "30001")), model.CatPostcode, "")
	if f == nil || f.Mask != "fake_number" || len(f.RowMasks) != 2 || f.RowMasks[0].Mask != "fake_number" ||
		!strings.Contains(f.RowMasks[0].Note, note) || f.RowMasks[1].Mask != "keep" || f.RowMasks[1].Note != "" {
		t.Errorf("an INT zip with a preset's row masks: got %+v", f)
	}
	if rows[0].Mask != "fake_postcode" || rows[0].Note != "" {
		t.Errorf("the preset's row masks changed: %+v", rows)
	}
}

// Whole numbers in an IP-named INT or BIGINT column read as IPv4 addresses
// written as numbers, unsigned as INET_ATON writes them or signed as
// ip2long can: they make a confident IP finding. 0.0.0.0 and loopback ones
// don't count, and nor does a number past 32 bits, or one in a column whose
// name says nothing of IP addresses or whose type can't hold one.
func TestAnalyzeIPNumbers(t *testing.T) {
	for _, c := range []struct {
		column, dataType string
		values           []string
		conf             model.Confidence
	}{
		{"last_ip", "int", []string{"3232235777", "167772161", "2886729729", "3405803777"}, model.ConfidenceHigh},
		{"ip", "bigint", []string{"3232235777", "167772161", "2886729729"}, model.ConfidenceHigh},
		{"user_ip", "int", []string{"-1062731519", "-1408237567", "167772161"}, model.ConfidenceHigh},
		{"user_ip", "int", []string{"3232235777", "0", "2130706433", "2130706434"}, model.ConfidenceMedium},
		{"user_ip", "bigint", []string{"4294967296", "9999999999", "3232235777"}, model.ConfidenceMedium},
		{"user_ip", "int", []string{"0", "2130706433"}, model.ConfidenceLow},
		{"ip", "smallint", []string{"3", "17", "255"}, model.ConfidenceLow},
		{"ip", "varchar", []string{"3232235777", "167772161", "2886729729"}, model.ConfidenceLow},
	} {
		fs := Analyze(subject("logins", c.column, c.dataType), namedProfile(c.column, c.values...))
		f := find(fs, model.CatIPAddress, "")
		if f == nil || f.Confidence != c.conf {
			t.Errorf("%s %s %v: got %+v", c.column, c.dataType, c.values, fs)
			continue
		}
		if c.conf > model.ConfidenceLow && !strings.Contains(strings.Join(f.Reasons, "; "), "read as IP addresses written as numbers") {
			t.Errorf("%s %s: reasons %v", c.column, c.dataType, f.Reasons)
		}
	}
	// Numbers in a column no name rule calls an IP's are no addresses.
	if f := find(Analyze(subject("orders", "total", "int"), namedProfile("total", "3232235777", "167772161", "2886729729")),
		model.CatIPAddress, ""); f != nil {
		t.Errorf("numbers read as IP addresses: %+v", f)
	}
}

// WordPress's role map: a role's name repeats its key.
func TestAnalyzeRoleNames(t *testing.T) {
	roles := "a:3:{" + phpStr("author") + "a:1:{" + phpStr("name") + phpStr("Author") + "}" +
		phpStr("customer") + "a:1:{" + phpStr("name") + phpStr("Customer") + "}" +
		phpStr("um_member") + "a:1:{" + phpStr("name") + phpStr("Member") + "}}"
	fs := Analyze(setting("wp_options", "wp_user_roles"), namedProfile("wp_user_roles", roles))
	for _, f := range confident(fs) {
		if f.Category == model.CatPersonName {
			t.Errorf("role name read as a person's: %+v", f)
		}
	}
}

// Keys of a translation table are judged by their values only.
func TestAnalyzeLabels(t *testing.T) {
	sub := Subject{Table: "ab_language_definitions", Column: "language_value", MetaKey: "entry_email_address",
		Name: "entry_email_address", Context: Tokens("ab_language_definitions"), Sampled: true, Labels: true}
	if fs := Analyze(sub, namedProfile(sub.Name, "E-Mail Address:")); len(confident(fs)) != 0 {
		t.Errorf("label: got %+v", fs)
	}
	if f := find(Analyze(sub, namedProfile(sub.Name, "jane@mail.fixture.gr")), model.CatEmail, ""); f == nil {
		t.Errorf("an address typed into a label is still found")
	}
	// A key whose name alone would be a secret.
	sub.MetaKey, sub.Name = "text_api_key", "text_api_key"
	if fs := Analyze(sub, namedProfile(sub.Name, "API key:")); len(confident(fs)) != 0 {
		t.Errorf("secret label: got %+v", fs)
	}
}
