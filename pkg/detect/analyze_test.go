package detect

import (
	"encoding/json"
	"fmt"
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
