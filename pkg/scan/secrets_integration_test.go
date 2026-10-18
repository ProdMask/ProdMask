package scan_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/model"
)

// checkPlanted checks that no rendered output and no golden file holds a
// planted secret, its base64 or decoded form, or eight characters in a row
// of its generated parts, and that the scanner's own matcher finds nothing
// in them. Failures name the output and the index, never the value.
func checkPlanted(t *testing.T, name string, p *fixture.Planted, outputs map[string]string) {
	t.Helper()
	texts := map[string]string{}
	for k, v := range outputs {
		texts[k] = v
	}
	if golden, err := os.ReadFile(filepath.Join("testdata", name+".findings")); err == nil {
		texts["golden"] = string(golden)
	}
	var forms []string
	for _, v := range p.Values {
		forms = append(forms, v, base64.StdEncoding.EncodeToString([]byte(v)))
		if d, err := base64.StdEncoding.DecodeString(v); err == nil && utf8.Valid(d) {
			forms = append(forms, string(d))
		}
	}
	for out, text := range texts {
		for i, f := range forms {
			if len(f) >= 8 && strings.Contains(text, f) {
				t.Errorf("the %s output holds planted form %d", out, i)
			}
		}
		for i, r := range p.Random {
			for j := 0; j+8 <= len(r); j++ {
				if strings.Contains(text, r[j:j+8]) {
					t.Errorf("the %s output holds 8 characters of planted part %d", out, i)
					break
				}
			}
		}
		var pieces []string
		pieces = append(pieces, text)
		pieces = append(pieces, strings.Split(text, "\n")...)
		if out == "json" {
			var v any
			if err := json.Unmarshal([]byte(text), &v); err != nil {
				t.Fatalf("the JSON output doesn't parse: %v", err)
			}
			pieces = append(pieces, jsonStrings(v)...)
		}
		for _, s := range pieces {
			for _, h := range detect.FindSecrets(s) {
				t.Errorf("the %s output holds a %s", out, h.Kind)
			}
		}
	}
}

func jsonStrings(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, e := range x {
			out = append(out, jsonStrings(e)...)
		}
	case map[string]any:
		for k, e := range x {
			out = append(out, k)
			out = append(out, jsonStrings(e)...)
		}
	}
	return out
}

// findingOf returns the finding of a category at a place, at any
// confidence.
func findingOf(res *model.Result, table, column, path string, cat model.Category) *model.Finding {
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Table == table && f.Column == column && f.MetaKey == "" && f.Path == path && f.Category == cat {
			return f
		}
	}
	return nil
}

// checkGenericSecrets checks the generic fixture's secret tables: every
// format found with its severity and notes, credentials in logged requests,
// push tokens, and no secret finding on the look-alikes.
func checkGenericSecrets(t *testing.T, res *model.Result) {
	t.Helper()
	cred := findingOf(res, "integrations", "credential", "", model.CatSecret)
	if cred == nil || cred.Severity != model.SeverityCritical {
		t.Fatalf("integrations.credential: %+v", cred)
	}
	reasons := strings.Join(cred.Reasons, " ")
	for _, kind := range []string{"Discord webhook URL", "Discord bot token", "Telegram bot token", "Microsoft Teams webhook URL",
		"Power Automate or Logic Apps URL", "Slack webhook URL", "Slack token", "Postman API key", "Paddle API key (1 live, 1 test)",
		"Square access token", "Square application secret", "Brevo API key", "Mailgun API key", "Google OAuth client secret",
		"Google OAuth refresh token", "Google OAuth access token", "Microsoft Entra client secret", "Meta access token",
		"password in a URL", "OpenAI API key", "API key (sk- style)", "OpenRouter API key", "GitLab token", "npm token",
		"PyPI token", "Atlassian API token", "Docker token", "Linear API key", "Notion token", "Airtable token", "Figma token",
		"Typeform token", "DigitalOcean token", "Heroku API key", "Grafana token", "Sentry token", "New Relic key",
		"Doppler token", "Vault token", "Terraform Cloud token", "1Password service account token", "age secret key",
		"PlanetScale token", "Supabase key", "Databricks token", "Cloudflare Origin CA key", "Hugging Face token",
		"Groq API key", "Perplexity API key", "xAI API key", "Shippo API key", "EasyPost API key", "Flutterwave secret key",
		"Plaid access token", "Midtrans server key", "Login with Amazon token", "AWS access key ID", "Amazon Bedrock API key",
		"Alibaba Cloud AccessKey ID", "SAML message", "self-labelled API key"} {
		if !strings.Contains(reasons, kind) {
			t.Errorf("integrations.credential: %s not found", kind)
		}
	}
	if !strings.Contains(cred.Note, "real chat channels") || !strings.Contains(cred.Note, "trigger the real workflow") {
		t.Errorf("integrations.credential note: %q", cred.Note)
	}
	if cred.Matched > cred.Sampled {
		t.Errorf("integrations.credential: %d matched of %d sampled", cred.Matched, cred.Sampled)
	}
	for _, c := range []struct {
		table, column, path string
		sev                 model.Severity
		note                string
	}{
		{"integrations", "settings", "discord.webhook", model.SeverityCritical, "real chat channels"},
		{"integrations", "settings", "paddle.api_key", model.SeverityCritical, ""},
		{"integrations", "settings", "google.refresh_token", model.SeverityCritical, ""},
		{"integrations", "discord_webhook", "", model.SeverityCritical, "real chat channels"},
		{"integrations", "webhook_url", "", model.SeverityMedium, ""},
		{"api_request_log", "request_headers", "", model.SeverityCritical, ""},
		{"api_request_log", "request_headers", "Authorization", model.SeverityHigh, ""},
		{"api_request_log", "headers", "Authorization", model.SeverityCritical, ""},
		{"api_request_log", "request_line", "", model.SeverityHigh, ""},
		{"api_request_log", "request_url", "", model.SeverityHigh, ""},
		{"api_request_log", "payload", "", model.SeverityCritical, "real chat channels"},
		{"api_request_log", "server_vars", "PHP_AUTH_PW", model.SeverityCritical, ""},
		{"push_devices", "expo_token", "", model.SeverityHigh, ""},
	} {
		f := findingOf(res, c.table, c.column, c.path, model.CatSecret)
		if f == nil || f.Severity != c.sev || !strings.Contains(f.Note, c.note) {
			t.Errorf("%s.%s %s: %+v", c.table, c.column, c.path, f)
		}
	}
	if f := findingOf(res, "push_devices", "registration_id", "", model.CatDeviceID); f == nil || f.Mask != "hash" ||
		!strings.Contains(f.Note, "push notifications") {
		t.Errorf("push_devices.registration_id: %+v", f)
	}
	if f := findingOf(res, "push_devices", "expo_token", "", model.CatDeviceID); f != nil {
		t.Errorf("push_devices.expo_token has a device ID finding too: %+v", f)
	}
	for _, c := range [][2]string{{"integrations", "docs_url"}, {"integrations", "plugin_option"}, {"integrations", "post_name"},
		{"integrations", "photo"}, {"api_request_log", "sample_header"}} {
		for _, f := range res.Findings {
			if f.Table == c[0] && f.Column == c[1] && f.Category == model.CatSecret {
				t.Errorf("%s.%s is a look-alike, but has a secret finding: %+v", c[0], c[1], f)
			}
		}
	}
}
