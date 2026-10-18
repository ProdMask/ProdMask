package detect

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

func profileOf(values ...string) *Profile {
	p := NewProfile()
	for _, v := range values {
		p.Add(v)
	}
	return p
}

func emails(n int, domain string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("customer%03d@%s", i, domain)
	}
	return out
}

func find(fs []model.Finding, cat model.Category, path string) *model.Finding {
	for i := range fs {
		if fs[i].Category == cat && fs[i].Path == path {
			return &fs[i]
		}
	}
	return nil
}

func subject(table, column, dataType string) Subject {
	return Subject{Table: table, Column: column, Name: column, DataType: dataType, Context: Tokens(table), Sampled: true}
}

func TestAnalyzeNameAndValues(t *testing.T) {
	fs := Analyze(subject("wp_users", "user_email", "varchar"), profileOf(emails(40, "mail.fixture.gr")...))
	f := find(fs, model.CatEmail, "")
	if f == nil || f.Confidence != model.ConfidenceHigh || f.Severity != model.SeverityHigh || f.Matched != 40 {
		t.Fatalf("got %+v", fs)
	}
	if f.Source != "name+value" || f.Mask != "fake_email" {
		t.Errorf("source %q mask %q", f.Source, f.Mask)
	}
}

func TestAnalyzeNameContradicted(t *testing.T) {
	fs := Analyze(subject("t", "email", "varchar"), profileOf("yes", "no", "yes", "yes", "no", "no"))
	f := find(fs, model.CatEmail, "")
	if f == nil || f.Confidence != model.ConfidenceLow {
		t.Fatalf("got %+v", fs)
	}
}

func TestAnalyzeValueOnly(t *testing.T) {
	fs := Analyze(subject("t", "contact", "varchar"), profileOf(emails(10, "mail.fixture.gr")...))
	if f := find(fs, model.CatEmail, ""); f == nil || f.Source != "value" {
		t.Fatalf("got %+v", fs)
	}
	// A username column full of email addresses is both.
	fs = Analyze(subject("users", "username", "varchar"), profileOf(emails(10, "mail.fixture.gr")...))
	if find(fs, model.CatUsername, "") == nil || find(fs, model.CatEmail, "") == nil {
		t.Fatalf("got %+v", fs)
	}
}

func TestAnalyzeMaskedEmails(t *testing.T) {
	fs := Analyze(subject("users", "email", "varchar"), profileOf(emails(20, "example.com")...))
	f := find(fs, model.CatEmail, "")
	if f == nil || f.Severity != model.SeverityLow || !strings.Contains(f.Note, "masked") {
		t.Fatalf("got %+v", fs)
	}
}

func TestAnalyzeSecrets(t *testing.T) {
	live := "sk_" + "live_" + strings.Repeat("Zx9", 9)
	cfg := map[string]any{"enabled": "yes", "testmode": "no", "secret_key": live}
	raw, _ := json.Marshal(cfg)
	fs := Analyze(subject("settings", "value", "longtext"), profileOf(string(raw)))
	f := find(fs, model.CatSecret, "secret_key")
	if f == nil || f.Severity != model.SeverityCritical {
		t.Fatalf("got %+v", fs)
	}
	test := "sk_" + "test_" + strings.Repeat("Zx9", 9)
	fs = Analyze(subject("settings", "notes", "text"), profileOf("use "+test+" for the sandbox please"))
	f = find(fs, model.CatSecret, "")
	if f == nil || f.Severity != model.SeverityMedium || !strings.Contains(f.Note, "test-mode") {
		t.Fatalf("got %+v", fs)
	}
}

func TestAnalyzeCards(t *testing.T) {
	real := luhnNumber("491761234567890")
	fs := Analyze(subject("payments", "pan", "varchar"), profileOf(real, real))
	if f := find(fs, model.CatCardNumber, ""); f == nil || f.Severity != model.SeverityCritical {
		t.Fatalf("got %+v", fs)
	}
	fs = Analyze(subject("payments", "card_number", "varchar"), profileOf("4242424242424242", "4111 1111 1111 1111"))
	if f := find(fs, model.CatCardNumber, ""); f == nil || f.Severity != model.SeverityMedium {
		t.Fatalf("test cards: got %+v", fs)
	}
}

func TestAnalyzeFreeText(t *testing.T) {
	var vals []string
	for i := 0; i < 10; i++ {
		vals = append(vals, fmt.Sprintf("Please deliver to the back door, call +30 210 555 01%02d if needed", i))
	}
	vals = append(vals, "Contact me at jane.doe@mail.fixture.gr about the invoice please")
	fs := Analyze(subject("wc_orders", "customer_note", "text"), profileOf(vals...))
	f := find(fs, model.CatFreeText, "")
	if f == nil || f.Confidence != model.ConfidenceHigh || !strings.Contains(strings.Join(f.Reasons, " "), "phone numbers") {
		t.Fatalf("got %+v", fs)
	}
}

func TestAnalyzeStructuredPaths(t *testing.T) {
	var vals []string
	for i := 0; i < 5; i++ {
		v, _ := json.Marshal(map[string]any{
			"billing":  map[string]any{"email": fmt.Sprintf("buyer%d@mail.fixture.gr", i), "first_name": "Maria"},
			"customer": map[string]any{"name": "Maria Papadopoulou"},
			"product":  map[string]any{"name": "Blue socks"},
			"ip":       "198.51.100.7",
		})
		vals = append(vals, string(v))
	}
	fs := Analyze(subject("notifications", "data", "text"), profileOf(vals...))
	for _, want := range []struct {
		cat  model.Category
		path string
	}{
		{model.CatEmail, "billing.email"},
		{model.CatPersonName, "billing.first_name"},
		{model.CatPersonName, "customer.name"},
		{model.CatIPAddress, "ip"},
	} {
		if find(fs, want.cat, want.path) == nil {
			t.Errorf("missing %s at %s in %+v", want.cat, want.path, fs)
		}
	}
	if find(fs, model.CatPersonName, "product.name") != nil {
		t.Errorf("product.name taken for a person name")
	}
}

func TestAnalyzeNoSamples(t *testing.T) {
	sub := subject("users", "email", "varchar")
	sub.Sampled = false
	fs := Analyze(sub, nil)
	if f := find(fs, model.CatEmail, ""); f == nil || f.Confidence != model.ConfidenceMedium {
		t.Fatalf("got %+v", fs)
	}
}

func TestAnalyzeHint(t *testing.T) {
	sub := subject("wp_comments", "comment_agent", "varchar")
	sub.Hint = &Hint{Category: model.CatUserAgent, Source: "preset:wordpress"}
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
	fs := Analyze(sub, profileOf(ua, ua, ua))
	f := find(fs, model.CatUserAgent, "")
	if f == nil || f.Source != "preset:wordpress+value" || f.Confidence != model.ConfidenceHigh {
		t.Fatalf("got %+v", fs)
	}
	sub.Hint = &Hint{Ignore: true}
	if fs := Analyze(sub, profileOf(ua)); len(fs) != 0 {
		t.Fatalf("ignored subject produced %+v", fs)
	}
}

func TestAnalyzeHintRowMasks(t *testing.T) {
	rows := []model.RowMask{{Where: "post_type IN ('shop_order')", Mask: "null", Note: "order keys"}}
	sub := subject("wp_posts", "post_password", "varchar")
	sub.Hint = &Hint{Category: model.CatSecret, Mask: "keep", Rows: rows, Source: "preset:woocommerce"}
	fs := Analyze(sub, profileOf("a@mail.fixture.gr", "b@mail.fixture.gr", "c@mail.fixture.gr"))
	f := find(fs, model.CatSecret, "")
	if f == nil || f.Mask != "keep" || !reflect.DeepEqual(f.RowMasks, rows) {
		t.Fatalf("got %+v", fs)
	}
	// The masks belong to what the preset knows, not to what the values look like.
	if e := find(fs, model.CatEmail, ""); e == nil || e.RowMasks != nil {
		t.Fatalf("value finding: got %+v", fs)
	}
	f.RowMasks[0].Mask = "keep"
	if rows[0].Mask != "null" {
		t.Fatal("the finding shares its row masks with the preset hint")
	}
}

// No sampled value may ever appear in a finding.
func TestFindingsNeverContainValues(t *testing.T) {
	canary := "zq7canary"
	secret := "sk_" + "live_" + canary + strings.Repeat("Q", 20)
	values := []string{
		canary + "@mail.fixture.gr",
		"+30 210 555 0199",
		`{"` + canary + `@mail.fixture.gr":{"email":"` + canary + `@x.gr"},"note":"call ` + canary + `"}`,
		"a:1:{" + phpStr("token") + phpStr(secret) + "}",
		"free text mentioning " + canary + "@mail.fixture.gr and more words here",
	}
	fs := Analyze(subject("t", "payload", "text"), profileOf(values...))
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	raw, _ := json.Marshal(fs)
	if strings.Contains(string(raw), canary) || strings.Contains(string(raw), "0199") {
		t.Fatalf("a sampled value leaked into findings: %s", raw)
	}
}

// TestAnalyzeNewSecrets checks severities and notes for v0.5.0's formats,
// push tokens and webhook names.
func TestAnalyzeNewSecrets(t *testing.T) {
	g := newTokGen(20)
	webhook := "https://disc" + "ord.com/api/web" + "hooks/1" + g.of(tDigit, 18) + "/" + g.of(tB64U, 68)
	raw, _ := json.Marshal(map[string]any{"discord": map[string]any{"webhook": webhook}, "enabled": "yes"})
	fs := Analyze(subject("settings", "value", "longtext"), profileOf(string(raw)))
	if f := find(fs, model.CatSecret, "discord.webhook"); f == nil || f.Severity != model.SeverityCritical ||
		!strings.Contains(f.Note, "real chat channels") {
		t.Errorf("Discord webhook in settings: %+v", fs)
	}
	logic := "https://prod-21.westeurope.logic.azure.com:443/workflows/" + g.of(tHex, 32) +
		"/triggers/manual/paths/invoke?api-version=2016-06-01&sig=" + g.of(tB64U, 43)
	fs = Analyze(subject("integrations", "endpoint", "varchar"), profileOf(logic))
	if f := find(fs, model.CatSecret, ""); f == nil || !strings.Contains(f.Note, "trigger the real workflow") {
		t.Errorf("Logic Apps URL: %+v", fs)
	}
	fs = Analyze(subject("request_log", "headers", "text"),
		profileOf("GET /api/orders Authorization: Bearer "+g.mixed(tAlnum, 40)+" 200"))
	if f := find(fs, model.CatSecret, ""); f == nil || f.Severity != model.SeverityHigh {
		t.Errorf("bearer header in a log: %+v", fs)
	}
	fs = Analyze(subject("request_log", "headers", "text"),
		profileOf("Authorization: Basic "+b64("svc_"+g.of(tLower, 8)+":"+g.mixed(tAlnum, 14))))
	if f := find(fs, model.CatSecret, ""); f == nil || f.Severity != model.SeverityCritical {
		t.Errorf("Basic header: %+v", fs)
	}
	two := "keys " + "sk_" + "live_" + g.of(tAlnum, 24) + " and " + "AK" + "IA" + g.of(tUpper+tDigit, 16)
	fs = Analyze(subject("settings", "notes", "text"), profileOf(two))
	if f := find(fs, model.CatSecret, ""); f == nil || f.Matched != 1 || f.Sampled != 1 {
		t.Errorf("a value with two kinds counts once: %+v", fs)
	}
	paddle := "pdl_" + "sdbx_apikey_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22) + "_" + g.of(tAlnum, 3)
	fs = Analyze(subject("settings", "notes", "text"), profileOf("sandbox key "+paddle))
	if f := find(fs, model.CatSecret, ""); f == nil || f.Severity != model.SeverityMedium || !strings.Contains(f.Note, "test-mode") {
		t.Errorf("sandbox Paddle key: %+v", fs)
	}
	var push []string
	for i := 0; i < 3; i++ {
		push = append(push, g.of(tB64U, 22)+":APA91b"+g.of(tB64U, 134))
	}
	fs = Analyze(subject("push_devices", "registration_id", "varchar"), profileOf(push...))
	if f := find(fs, model.CatDeviceID, ""); f == nil || f.Mask != "hash" || !strings.Contains(f.Note, "push notifications") {
		t.Errorf("FCM tokens: %+v", fs)
	}
	fs = Analyze(subject("push_devices", "fcm_token", "varchar"), profileOf(push...))
	if len(fs) != 1 || fs[0].Category != model.CatSecret {
		t.Errorf("FCM tokens under a token name: %+v", fs)
	}
	fs = Analyze(subject("integrations", "webhook_url", "varchar"),
		profileOf("https://erp.fixture-partner.gr/hooks/orders", "https://crm.fixture-partner.gr/hooks/customers"))
	if len(fs) != 1 || fs[0].Category != model.CatSecret || fs[0].Severity != model.SeverityMedium {
		t.Errorf("webhook name with plain URLs: %+v", fs)
	}
}

// TestAnalyzeMatchedAndPushTokens checks Matched over several values, and
// push tokens under a device name, alone, and from Expo.
func TestAnalyzeMatchedAndPushTokens(t *testing.T) {
	g := newTokGen(21)
	vals := []string{"key " + "sk_" + "live_" + g.of(tAlnum, 24), "plain words and nothing else in this note",
		"keys " + "sk_" + "live_" + g.of(tAlnum, 24) + " and " + "AK" + "IA" + g.of(tUpper+tDigit, 16)}
	fs := Analyze(subject("settings", "notes", "text"), profileOf(vals...))
	if f := find(fs, model.CatSecret, ""); f == nil || f.Matched != 2 || f.Sampled != 3 {
		t.Errorf("two values of three hold secrets: %+v", fs)
	}
	raw, _ := json.Marshal(map[string]any{"api_key": "sk_" + "live_" + g.of(tAlnum, 24)})
	fs = Analyze(subject("settings", "value", "longtext"), profileOf(string(raw), string(raw), "{\"api_key\":\"\"}"))
	if f := find(fs, model.CatSecret, "api_key"); f == nil || f.Matched != 2 {
		t.Errorf("a named secret path: %+v", fs)
	}
	fs = Analyze(subject("settings", "api_key", "varchar"),
		profileOf("sk_"+"live_"+g.of(tAlnum, 24), "sk_"+"live_"+g.of(tAlnum, 24), "Zq8x2LmN4pR7tY9w"))
	if f := find(fs, model.CatSecret, ""); f == nil || f.Matched != 2 || f.Sampled != 3 {
		t.Errorf("a secret name with two keys in three values: %+v", fs)
	}
	fcm := func() string { return g.of(tB64U, 22) + ":APA91b" + g.of(tB64U, 134) }
	var expoUUIDs []string
	for i := 0; i < 3; i++ {
		expoUUIDs = append(expoUUIDs, "ExponentPush"+"Token["+g.of(tB64U, 22)+"]")
	}
	fs = Analyze(subject("members", "udid", "varchar"), profileOf(expoUUIDs...))
	if f := find(fs, model.CatDeviceID, ""); f == nil || f.Confidence != model.ConfidenceHigh {
		t.Errorf("push tokens under a device name: %+v", fs)
	}
	fs = Analyze(subject("push_devices", "registration_id", "varchar"), profileOf(fcm()))
	if f := find(fs, model.CatDeviceID, ""); f == nil {
		t.Errorf("a single push token: %+v", fs)
	}
	var expo []string
	for i := 0; i < 3; i++ {
		expo = append(expo, "ExponentPush"+"Token["+g.of(tB64U, 22)+"]")
	}
	fs = Analyze(subject("push_devices", "registration_id", "varchar"), profileOf(expo...))
	if f := find(fs, model.CatDeviceID, ""); f == nil || !strings.Contains(f.Note, "push notifications") {
		t.Errorf("Expo push tokens: %+v", fs)
	}
}
