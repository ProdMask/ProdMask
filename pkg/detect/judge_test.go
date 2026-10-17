package detect

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

func namedProfile(name string, values ...string) *Profile {
	p := NewProfileNamed(name)
	for _, v := range values {
		p.Add(v)
	}
	return p
}

func repeat(n int, v string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func confident(fs []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Confidence > model.ConfidenceLow {
			out = append(out, f)
		}
	}
	return out
}

// A cache gets one finding that suggests deleting it, whatever it holds.
func TestAnalyzeDeleteHint(t *testing.T) {
	profile := `a:3:{` + phpStr("user_email") + phpStr("jane@mail.fixture.gr") +
		phpStr("user_pass") + phpStr("$P$B"+strings.Repeat("a1", 15)) +
		phpStr("billing_phone") + phpStr("+30 210 555 0123") + `}`
	sub := Subject{Table: "wp_options", Column: "option_value", MetaKey: "um_cache_userdata_*", Name: "um_cache_userdata_*",
		Sampled: true, Keys: 541, Hint: &Hint{Delete: true, Note: "a cache the plugin rebuilds"}}
	fs := Analyze(sub, profileOf(profile, profile))
	if len(fs) != 1 {
		t.Fatalf("want one finding, got %+v", fs)
	}
	f := fs[0]
	if f.Mask != "delete" || f.Path != "" || f.Keys != 541 || f.Confidence == model.ConfidenceLow ||
		!strings.Contains(f.Note, "rebuilds") || !strings.Contains(strings.Join(f.Reasons, "; "), "also holds:") {
		t.Fatalf("got %+v", f)
	}
	// The reasons came from a path inside the value, not from the key's name.
	if !slices.ContainsFunc([]string{"user_email: ", "user_pass: ", "billing_phone: "}, func(p string) bool {
		return strings.HasPrefix(f.Reasons[0], p)
	}) {
		t.Errorf("reasons don't say where they apply: %q", f.Reasons)
	}
}

// A delete-only hint doesn't say what the data is: a transient whose name
// matches a rule but whose values don't fit stays weak.
func TestAnalyzeDeleteHintWithoutCategory(t *testing.T) {
	sub := Subject{Table: "wp_options", Column: "option_value", MetaKey: "_transient_wc_customer_email",
		Name: "_transient_wc_customer_email", Sampled: true, Setting: true,
		Hint: &Hint{Delete: true, Note: "a transient"}}
	fs := Analyze(sub, profileOf("42"))
	if len(confident(fs)) != 0 {
		t.Fatalf("got %+v", fs)
	}
	for _, f := range fs {
		if f.Severity != model.SeverityLow {
			t.Errorf("weak finding keeps severity %s", f.Severity)
		}
	}
}

func TestAnalyzeSingleValues(t *testing.T) {
	// A setting holds one value: one address is enough.
	fs := Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "fixture_admin_recipient",
		Name: "fixture_admin_recipient", Sampled: true, Setting: true}, profileOf("manager@mail.fixture.gr"))
	if f := find(fs, model.CatEmail, ""); f == nil || f.Confidence < model.ConfidenceMedium {
		t.Fatalf("recipient: got %+v", fs)
	}
	// Recipient lists inside a serialized WooCommerce email setting.
	v := `a:2:{` + phpStr("enabled") + phpStr("yes") + phpStr("recipient") +
		phpStr("staff@mail.fixture.gr, owner@mail.fixture.gr") + `}`
	fs = Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "woocommerce_new_order_settings",
		Name: "woocommerce_new_order_settings", Sampled: true, Setting: true}, profileOf(v))
	if f := find(fs, model.CatEmail, "recipient"); f == nil {
		t.Fatalf("recipient list: got %+v", fs)
	}
	// Version numbers parse as IPv4; one of them is not an IP finding.
	fs = Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "fixture_db_version",
		Name: "fixture_db_version", Sampled: true, Setting: true}, profileOf("1.8.1.2"))
	if f := find(fs, model.CatIPAddress, ""); f != nil {
		t.Fatalf("version taken for an IP: %+v", f)
	}
	// With no name to back it, one value of a sure format is medium, not high.
	for _, c := range []struct {
		name, value string
		cat         model.Category
	}{
		{"fixture_contact", "jane@mail.fixture.gr", model.CatEmail},
		{"fixture_blob", "$P$B" + strings.Repeat("a1", 15), model.CatPasswordHash},
		{"fixture_ref", "cus_" + strings.Repeat("Q1w2", 4), model.CatPaymentToken},
	} {
		fs = Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: c.name, Name: c.name,
			Sampled: true, Setting: true}, profileOf(c.value))
		if f := find(fs, c.cat, ""); f == nil || f.Confidence != model.ConfidenceMedium {
			t.Errorf("%s: got %+v", c.name, fs)
		}
	}
	// A secret's name with an on/off value is a switch.
	fs = Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "fixture_api_key", Name: "fixture_api_key",
		Sampled: true, Setting: true}, profileOf("yes"))
	if f := find(fs, model.CatSecret, ""); f == nil || f.Confidence != model.ConfidenceLow {
		t.Errorf("api key switch: got %+v", fs)
	}
}

// Empty arrays store nothing, whatever a preset says the key holds:
// WordPress keeps recovery_keys as a:0:{} on nearly every site.
func TestAnalyzeEmptyStructures(t *testing.T) {
	hint := &Hint{Category: model.CatSecret, Source: "preset:wordpress", Note: "recovery mode keys"}
	for _, v := range []string{"a:0:{}", "{}", "[]", `a:1:{s:3:"key";s:0:"";}`} {
		fs := Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "recovery_keys", Name: "recovery_keys",
			Hint: hint, Sampled: true, Setting: true}, profileOf(v))
		if len(confident(fs)) != 0 {
			t.Errorf("%s: got %+v", v, fs)
		}
	}
	// A setting whose read returned no rows says nothing either way.
	fs := Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "recovery_keys", Name: "recovery_keys",
		Hint: hint, Sampled: true, Setting: true}, profileOf())
	if f := find(fs, model.CatSecret, ""); f == nil || f.Confidence != model.ConfidenceMedium {
		t.Errorf("no rows: got %+v", fs)
	}
	// A real key stays.
	v := `a:1:{` + phpStr("k1") + `a:1:{` + phpStr("hashed_key") + phpStr("$P$B"+strings.Repeat("a1", 15)) + `}}`
	fs = Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "recovery_keys", Name: "recovery_keys",
		Hint: hint, Sampled: true, Setting: true}, profileOf(v))
	if f := find(fs, model.CatSecret, ""); f == nil || f.Confidence != model.ConfidenceHigh {
		t.Errorf("stored key: got %+v", fs)
	}
}

func TestAnalyzeEmailsInNames(t *testing.T) {
	logins := func(emails, total int) []string {
		var vs []string
		for i := 0; i < total; i++ {
			if i < emails {
				vs = append(vs, fmt.Sprintf("user%03d@mail.fixture.gr", i))
			} else {
				vs = append(vs, fmt.Sprintf("login_%03d", i))
			}
		}
		return vs
	}
	// 16% of the logins are addresses: email at high severity, but the
	// column keeps its username mask.
	fs := Analyze(subject("wp_users", "user_login", "varchar"), profileOf(logins(48, 300)...))
	f := find(fs, model.CatEmail, "")
	if f == nil || f.Severity != model.SeverityHigh || f.Confidence != model.ConfidenceMedium ||
		f.Mask != "fake_username" || !strings.Contains(f.Note, "email-shaped") {
		t.Fatalf("mixed logins: got %+v", fs)
	}
	// Mostly addresses: the email mask.
	fs = Analyze(subject("wp_users", "user_login", "varchar"), profileOf(logins(200, 300)...))
	if f := find(fs, model.CatEmail, ""); f == nil || f.Confidence != model.ConfidenceHigh || f.Mask != "fake_email" {
		t.Fatalf("email logins: got %+v", fs)
	}
	// One stray address in 300 names is not enough.
	fs = Analyze(subject("wp_users", "display_name", "varchar"), profileOf(logins(1, 300)...))
	if f := find(fs, model.CatEmail, ""); f != nil {
		t.Fatalf("one address: got %+v", f)
	}
}

func TestAnalyzeWeakNameMatches(t *testing.T) {
	cases := []struct {
		name, column string
		cat          model.Category
		values       []string
		weak         bool
	}{
		{"flags", "vat_number", model.CatNationalID, []string{"yes", "no", "yes"}, true},
		{"no digits", "vat_number", model.CatNationalID, []string{"GR", "DE", "FR"}, true},
		{"real VAT numbers", "vat_number", model.CatNationalID, []string{"EL123456789", "DE987654321"}, false},
		{"field names", "billing_address", model.CatAddress, repeat(5, "billing_address_1"), true},
		{"placeholders", "contact_name", model.CatPersonName, repeat(5, "{first_name}"), true},
		{"slugs", "address", model.CatAddress, repeat(5, "edit-billing-address"), true},
		{"handles stay names", "full_name", model.CatPersonName, []string{"john_smith", "maria-p", "eleni_k"}, false},
		{"website handles stay", "facebook", model.CatWebsite, repeat(5, "jane-doe-1a2b3c"), false},
		{"gender flags stay", "gender", model.CatGender, []string{"0", "1", "1"}, false},
		{"usernames stay", "user_login", model.CatUsername, repeat(5, "redirect_to_profile_page"), false},
		// An import plugin's column mapping: each field's name, or a flag.
		{"mappings", "billing_address_1", model.CatAddress, []string{"billing_address_1", "1", "1", "billing_address_1", "0"}, true},
		{"mapped secrets", "session_tokens", model.CatSecret, []string{"session_tokens", "1", "0"}, true},
		{"a username field's own name", "user_login", model.CatUsername, []string{"user_login", "user_login", "user_login"}, true},
		{"real names among flags", "first_name", model.CatPersonName, []string{"Maria", "1", "Eleni", "0"}, false},
		// Amounts and flags inside a serialized value named for VAT.
		{"serialized amounts", "vat_paid", model.CatNationalID,
			[]string{"a:3:{" + phpStr("total") + phpStr("24") + phpStr("rate") + phpStr("0.2") + phpStr("paid") + phpStr("1") + "}"}, true},
		{"UK postcodes", "postcode", model.CatPostcode, []string{"SW1A 1AA", "EC1A 1BB"}, false},
		// A licence key that happens to start with a letter is no slug, and
		// secrets can be words joined by hyphens.
		{"UUID keys", "license_key", model.CatSecret, []string{"a3bb189e-8bf9-4888-9912-ace4e6543002"}, false},
		{"passphrases", "license_key", model.CatSecret, []string{"correct-horse-battery-staple"}, false},
		// A card type setting names a layout, not a card.
		{"card type labels", "twitter_card_type", model.CatCardMeta, repeat(3, "summary_large_image"), true},
		// ACF keeps each field's key beside its value, as _first_name.
		{"ACF field keys", "first_name", model.CatPersonName, repeat(3, "field_5f3a2b1c9d8e7"), true},
	}
	for _, c := range cases {
		fs := Analyze(subject("people", c.column, "varchar"), namedProfile(c.column, c.values...))
		f := find(fs, c.cat, "")
		if f == nil {
			t.Errorf("%s: no %s finding in %+v", c.name, c.cat, fs)
			continue
		}
		if weak := f.Confidence == model.ConfidenceLow; weak != c.weak {
			t.Errorf("%s: confidence %s, note %q", c.name, f.Confidence, f.Note)
		}
		if f.Confidence == model.ConfidenceLow && f.Severity != model.SeverityLow {
			t.Errorf("%s: weak finding keeps severity %s", c.name, f.Severity)
		}
	}
	// A Stripe key has three snake_case parts, but it is no field name.
	stripe := "sk_" + "live_" + strings.Repeat("a1B2", 6)
	f := find(Analyze(subject("settings", "secret_key", "varchar"), namedProfile("secret_key", stripe)), model.CatSecret, "")
	if f == nil || f.Confidence != model.ConfidenceHigh || f.Note != "" {
		t.Errorf("stripe key: got %+v", f)
	}
	// A translation table: the value only repeats the field's own name.
	fs := Analyze(Subject{Table: "translations", Column: "string_value", MetaKey: "first_name", Name: "first_name",
		Sampled: true}, namedProfile("first_name", "First name", "First Name"))
	if len(confident(fs)) != 0 {
		t.Errorf("label values: got %+v", fs)
	}
}

func TestAnalyzeEmptyValues(t *testing.T) {
	// An empty setting stores nothing.
	sub := Subject{Table: "wp_options", Column: "option_value", MetaKey: "fixture_api_key", Name: "fixture_api_key",
		Sampled: true, Setting: true}
	if fs := confident(Analyze(sub, profileOf(""))); len(fs) != 0 {
		t.Errorf("empty setting: got %+v", fs)
	}
	// A sparse column, such as a password reset token, stays reported.
	if f := find(Analyze(subject("admin_user", "rp_token", "varchar"), profileOf("", "", "")), model.CatSecret, ""); f == nil ||
		f.Confidence != model.ConfidenceMedium {
		t.Errorf("sparse column: got %+v", f)
	}
	// Keys left without values by a limit stay weak.
	sub = Subject{Table: "wp_options", Column: "option_value", MetaKey: "fixture_secret", Name: "fixture_secret", Skipped: true}
	if f := find(Analyze(sub, nil), model.CatSecret, ""); f == nil || f.Confidence != model.ConfidenceLow ||
		!strings.Contains(f.Note, "over the per-table limit") {
		t.Errorf("skipped key: got %+v", f)
	}
}

// Big settings arrays: past the path cap, names that match a rule are
// still tracked and every other leaf is still checked for secrets.
func TestAnalyzePathCap(t *testing.T) {
	m := map[string]string{}
	letters := "abcdefghijklmnopqrstuvwxyz"
	for i := 0; i < maxPaths+100; i++ {
		// Letters only, so no two keys share a template.
		name := "setting_" + string(letters[i/676%26]) + string(letters[i/26%26]) + string(letters[i%26])
		m[name] = "on"
	}
	m["zz_facebook_secret"] = "fixture" + strings.Repeat("Q7", 12)
	m["zz_other_key"] = "AIza" + strings.Repeat("Bx3_", 8) + "Bx3"
	raw, _ := json.Marshal(m)
	p := profileOf(string(raw))
	if len(p.Paths) < maxPaths {
		t.Fatalf("only %d paths: the cap is not reached", len(p.Paths))
	}
	fs := Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "rank-math-options-titles",
		Name: "rank-math-options-titles", Sampled: true, Setting: true}, p)
	if f := find(fs, model.CatSecret, "zz_facebook_secret"); f == nil {
		t.Errorf("named path past the cap is lost")
	}
	if find(fs, model.CatSecret, "zz_other_key") != nil {
		t.Errorf("unnamed path past the cap was tracked")
	}
	// The overflow leaf's secret is counted on the value itself.
	if f := find(fs, model.CatSecret, ""); f == nil || !strings.Contains(strings.Join(f.Reasons, " "), "Google API key") {
		t.Errorf("secret past the cap is lost: %+v", fs)
	}
}

// No key name with data and no value may appear in a finding.
func TestFindingsNeverContainKeyData(t *testing.T) {
	canary := "zq7canary"
	v := `a:2:{` + phpStr("um_email_as_username_"+canary+"mailfixturegr") + phpStr(canary+"@mail.fixture.gr") +
		phpStr("seen_"+canary+"@mail.fixture.gr") + phpStr("1") + `}`
	fs := Analyze(Subject{Table: "wp_options", Column: "option_value", MetaKey: "um_cache_userdata_*",
		Name: "um_cache_userdata_*", Sampled: true}, profileOf(v))
	raw, _ := json.Marshal(fs)
	if len(fs) == 0 || strings.Contains(string(raw), canary) {
		t.Fatalf("got %s", raw)
	}
}
