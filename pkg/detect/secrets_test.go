package detect

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// Secret-shaped test values are assembled at run time from split prefixes
// and generated tails, so no complete token sits in the source.
const (
	tLower = "abcdefghijklmnopqrstuvwxyz"
	tUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	tDigit = "0123456789"
	tAlnum = tUpper + tLower + tDigit
	tHex   = "0123456789abcdef"
	tB64U  = tAlnum + "_-"
	tB64   = tAlnum + "+/"
)

type tokGen struct{ r *rand.Rand }

func newTokGen(seed uint64) *tokGen { return &tokGen{rand.New(rand.NewPCG(seed, seed*31+7))} }

func (g *tokGen) of(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[g.r.IntN(len(set))]
	}
	return string(b)
}

// mixed returns n characters of set that hold a lower-case letter, a
// capital and a digit.
func (g *tokGen) mixed(set string, n int) string { return "aZ7" + g.of(set, n-3) }

func (g *tokGen) uuid() string {
	return g.of(tHex, 8) + "-" + g.of(tHex, 4) + "-" + g.of(tHex, 4) + "-" + g.of(tHex, 4) + "-" + g.of(tHex, 12)
}

// botToken returns a Discord bot token whose first part encodes id.
func (g *tokGen) botToken(id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(id)) + "." + g.of(tB64U, 6) + "." + g.of(tB64U, 38)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

type secretCase struct {
	in, kind, mode string
}

// positiveCases holds one value for every pattern, each with the one hit it
// must give.
func positiveCases() []secretCase {
	g := newTokGen(1)
	slack := "https://hoo" + "ks.slack.com/"
	return []secretCase{
		{"key=" + "sk_" + "live_" + g.of(tAlnum, 24), "Stripe secret key", "live"},
		{"sk_" + "test_" + g.of(tAlnum, 24), "Stripe secret key", "test"},
		{"wh" + "sec_" + g.of(tAlnum, 32), "Stripe webhook secret", "live"},
		{"aws " + "AK" + "IA" + g.of(tUpper+tDigit, 16) + " here", "AWS access key ID", "live"},
		{"AB" + "IA" + g.of(tUpper+"234567", 16), "AWS access key ID", "live"},
		{"AB" + "SK" + g.mixed(tB64, 150), "Amazon Bedrock API key", "live"},
		{"LT" + "AI" + g.of(tAlnum, 16), "Alibaba Cloud AccessKey ID", "live"},
		{"gh" + "p_" + g.of(tAlnum, 36), "GitHub token", "live"},
		{"github" + "_pat_" + g.of(tAlnum+"_", 40), "GitHub token", "live"},
		{"gl" + "pat-" + g.of(tB64U, 20), "GitLab token", "live"},
		{"GR13" + "48941" + g.of(tB64U, 20), "GitLab token", "live"},
		{"xo" + "xb-" + g.of(tDigit, 12) + "-" + g.of(tAlnum, 24), "Slack token", "live"},
		{"xa" + "pp-1-A" + g.of(tUpper+tDigit, 10) + "-" + g.of(tDigit, 13) + "-" + g.of(tHex, 64), "Slack token", "live"},
		{slack + "services/T" + g.of(tUpper+tDigit, 8) + "/B" + g.of(tUpper+tDigit, 8) + "/" + g.of(tAlnum, 24), "Slack webhook URL", "live"},
		{slack + "workflows/T" + g.of(tUpper+tDigit, 9) + "/A" + g.of(tUpper+tDigit, 10) + "/" + g.of(tDigit, 18) + "/" + g.of(tAlnum, 24),
			"Slack webhook URL", "live"},
		{slack + "triggers/T" + g.of(tUpper+tDigit, 9) + "/" + g.of(tDigit, 13) + "/" + g.of(tHex, 32), "Slack webhook URL", "live"},
		{"https://disc" + "ord.com/api/web" + "hooks/1" + g.of(tDigit, 18) + "/" + g.of(tB64U, 68), "Discord webhook URL", "live"},
		{"token: " + g.botToken("1"+g.of(tDigit, 17)), "Discord bot token", "live"},
		{"https://api.telegram.org/bot" + "7" + g.of(tDigit, 9) + ":A" + "A" + g.of(tB64U, 33) + "/sendMessage", "Telegram bot token", "live"},
		{"https://fixture.webhook.office.com/webhookb2/" + g.uuid() + "@" + g.uuid() + "/IncomingWebhook/" + g.of(tHex, 32) + "/" + g.uuid(),
			"Microsoft Teams webhook URL", "live"},
		{"https://outlook.office.com/webhook/" + g.uuid() + "@" + g.uuid() + "/IncomingWebhook/" + g.of(tAlnum, 32) + "/" + g.uuid(),
			"Microsoft Teams webhook URL", "live"},
		{"https://prod-21.westeurope.logic.azure.com:443/workflows/" + g.of(tHex, 32) +
			"/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" + g.of(tB64U, 43),
			"Power Automate or Logic Apps URL", "live"},
		{"AI" + "za" + g.of(tB64U, 35), "Google API key", "live"},
		{"GOC" + "SPX-" + g.of(tB64U, 28), "Google OAuth client secret", "live"},
		{"refresh 1/" + "/0" + g.of(tB64U, 90), "Google OAuth refresh token", "live"},
		{"ya" + "29." + g.of(tB64U, 120), "Google OAuth access token", ""},
		{"secret=\"" + g.of(tAlnum, 3) + "8Q" + "~" + g.of(tAlnum+"_~.-", 34) + "\"", "Microsoft Entra client secret", "live"},
		{"EA" + "AG" + g.mixed(tAlnum, 180), "Meta access token", ""},
		{"SG" + "." + g.of(tB64U, 22) + "." + g.of(tB64U, 43), "SendGrid API key", "live"},
		{"ke" + "y-" + g.of(tHex, 32), "Mailgun API key", "live"},
		{g.of(tHex, 32) + "-" + g.of(tHex, 8) + "-" + g.of(tHex, 8), "Mailgun API key", "live"},
		{g.of(tHex, 32) + "-u" + "s14", "Mailchimp API key", "live"},
		{"xke" + "ysib-" + g.of(tHex, 64) + "-" + g.of(tAlnum, 16), "Brevo API key", "live"},
		{"S" + "K" + g.of(tHex, 32), "Twilio API key", "live"},
		{"shp" + "at_" + g.of(tHex, 32), "Shopify access token", "live"},
		{"PM" + "AK-" + g.of(tHex, 24) + "-" + g.of(tHex, 34), "Postman API key", "live"},
		{"pdl_" + "live_apikey_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22) + "_" + g.of(tAlnum, 3), "Paddle API key", "live"},
		{"pdl_" + "sdbx_apikey_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22) + "_" + g.of(tAlnum, 3), "Paddle API key", "test"},
		{"sq0" + "atp-" + g.of(tB64U, 22), "Square access token", "live"},
		{"EA" + "AA" + g.mixed(tAlnum, 60), "Square access token", ""},
		{"sq0" + "csp-" + g.of(tB64U, 43), "Square application secret", "live"},
		{"shippo_" + "live_" + g.of(tHex, 40), "Shippo API key", "live"},
		{"shippo_" + "test_" + g.of(tHex, 40), "Shippo API key", "test"},
		{"EZ" + "AK" + g.of(tAlnum, 54), "EasyPost API key", "live"},
		{"EZ" + "TK" + g.of(tAlnum, 54), "EasyPost API key", "test"},
		{"FLWSECK" + "_TEST-" + g.of(tAlnum, 32) + "-X", "Flutterwave secret key", "test"},
		{"FLWSECK" + "-" + g.of(tAlnum, 32) + "-X", "Flutterwave secret key", "live"},
		{"access-" + "production-" + g.uuid(), "Plaid access token", "live"},
		{"access-" + "sandbox-" + g.uuid(), "Plaid access token", "test"},
		{"access-" + "development-" + g.uuid(), "Plaid access token", "test"},
		{"SB-Mid-" + "server-" + g.mixed(tB64U, 24), "Midtrans server key", "test"},
		{"Mid-" + "server-" + g.mixed(tB64U, 24), "Midtrans server key", "live"},
		{"At" + "zr|" + g.of(tB64U, 60), "Login with Amazon token", "live"},
		{"At" + "za|" + g.of(tB64U, 60), "Login with Amazon token", ""},
		{"sk-" + "ant-api03-" + g.of(tB64U, 40), "Anthropic API key", "live"},
		{"sk-" + "proj-" + g.of(tB64U, 74) + "T3Blbk" + "FJ" + g.of(tB64U, 74), "OpenAI API key", "live"},
		{"sk-" + "or-v1-" + g.of(tHex, 64), "OpenRouter API key", "live"},
		{"sk-" + g.of(tHex, 32), "API key (sk- style)", "live"},
		{"gs" + "k_" + g.of(tAlnum, 52), "Groq API key", "live"},
		{"pp" + "lx-" + g.of(tAlnum, 48), "Perplexity API key", "live"},
		{"xa" + "i-" + g.of(tAlnum, 80), "xAI API key", "live"},
		{"h" + "f_" + "aZ" + g.of(tLower+tUpper, 32), "Hugging Face token", "live"},
		{"api_" + "org_" + "aZ" + g.of(tLower+tUpper, 32), "Hugging Face token", "live"},
		{"c" + "k_" + g.of(tHex, 40), "WooCommerce API key", "live"},
		{"access_token$" + "production$" + g.of(tLower+tDigit, 16) + "$" + g.of(tHex, 32), "PayPal/Braintree access token", "live"},
		{"np" + "m_" + g.of(tAlnum, 36), "npm token", "live"},
		{"pypi-" + "AgEIcHlwaS5vcmc" + g.of(tB64U, 70), "PyPI token", "live"},
		{"ATAT" + "T3" + g.of(tB64U, 180), "Atlassian API token", "live"},
		{"dckr_" + "pat_" + g.of(tB64U, 27), "Docker token", "live"},
		{"lin_" + "api_" + g.of(tAlnum, 40), "Linear API key", "live"},
		{"nt" + "n_" + g.of(tDigit, 11) + g.of(tAlnum, 35), "Notion token", "live"},
		{"pa" + "t" + g.of(tAlnum, 14) + "." + g.of(tHex, 64), "Airtable token", "live"},
		{"fi" + "gd_" + g.of(tB64U, 40), "Figma token", "live"},
		{"tf" + "p_" + g.of(tAlnum, 59), "Typeform token", "live"},
		{"dop_" + "v1_" + g.of(tHex, 64), "DigitalOcean token", "live"},
		{"HRKU" + "-AA" + g.of(tB64U, 58), "Heroku API key", "live"},
		{"gl" + "sa_" + g.of(tAlnum, 32) + "_" + g.of(tHex, 8), "Grafana token", "live"},
		{"gl" + "c_" + g.of(tAlnum, 60), "Grafana token", "live"},
		{"sntrys_" + "eyJpYXQiO" + g.of(tB64U, 60), "Sentry token", "live"},
		{"sntryu_" + g.of(tHex, 64), "Sentry token", "live"},
		{"NR" + "AK-" + g.of(tUpper+tDigit, 27), "New Relic key", "live"},
		{"NR" + "II-" + g.of(tB64U, 32), "New Relic key", "live"},
		{"dp." + "pt." + g.of(tAlnum, 43), "Doppler token", "live"},
		{"dp." + "st.dev." + g.of(tAlnum, 43), "Doppler token", "live"},
		{"hv" + "s." + g.of(tB64U, 100), "Vault token", "live"},
		{"hv" + "b." + g.of(tB64U, 150), "Vault token", "live"},
		{g.of(tAlnum, 14) + ".atlas" + "v1." + g.of(tAlnum, 67), "Terraform Cloud token", "live"},
		{"ops_" + "eyJ" + g.of(tB64, 300), "1Password service account token", "live"},
		{"AGE-SECRET" + "-KEY-1" + g.of(tUpper+tDigit, 58), "age secret key", "live"},
		{"pscale_" + "pw_" + g.of(tAlnum, 43), "PlanetScale token", "live"},
		{"sb" + "p_" + g.of(tHex, 40), "Supabase key", "live"},
		{"sb_" + "secret_" + g.of(tB64U, 30), "Supabase key", "live"},
		{"da" + "pi" + g.of(tHex, 32), "Databricks token", "live"},
		{"v1." + "0-" + g.of(tHex, 24) + "-" + g.of(tHex, 146), "Cloudflare Origin CA key", "live"},
		{"SAMLResponse=" + "PHNhbWxwOlJlc3BvbnNl" + g.of(tB64, 200), "SAML message", ""},
		{"<saml:Assertion ID=\"_" + g.of(tHex, 16) + "\" IssueInstant=\"2026-10-18T10:00:00Z\" Version=\"2.0\">", "SAML message", ""},
		{"-----BEGIN RSA PRIVATE" + " KEY-----", "private key", "live"},
		{"ey" + "J" + g.of(tB64U, 20) + ".ey" + "J" + g.of(tB64U, 30) + "." + g.of(tB64U, 20), "JSON Web Token", ""},
		{"Authorization: Basic " + b64("svc_"+g.of(tLower, 8)+":"+g.mixed(tAlnum, 14)), "password in a Basic Authorization header", "live"},
		{"Basic " + b64("svc_"+g.of(tLower, 8)+":"+g.mixed(tAlnum, 14)), "password in a Basic Authorization header", "live"},
		{"smtp://mailer" + g.of(tLower, 4) + ":" + g.mixed(tAlnum, 14) + "@mail.fixture-host.gr:587", "password in a URL", "live"},
		{"Authorization: Bearer " + g.mixed(tAlnum+"._-", 40), "bearer token in an Authorization header", ""},
		{"Bearer " + g.mixed(tAlnum+"._-", 40), "bearer token in an Authorization header", ""},
		{"xyz_" + "live_api" + "key_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22), "self-labelled API key", "live"},
		{"acme_" + "test_api" + "key_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22), "self-labelled API key", "test"},
		{"api" + "key-" + g.mixed(tAlnum, 32), "self-labelled API key", ""},
		{"https://api.fixture-host.gr/v1/items?api" + "_key=" + g.mixed(tAlnum, 32) + "&page=2", "API key in a URL", ""},
	}
}

// negativeCases holds values that must give no hit at all.
func negativeCases() []string {
	g := newTokGen(2)
	return []string{
		"plain text with sk_ and AKIA mentioned",
		"plugin_apikey_label",
		"your_apikey_xxxxxxxxxxxxxxxx",
		"my_api_key_field_settings_section",
		"https://api.fixture-host.gr/v1?api_key={key}",
		"https://api.fixture-host.gr/v1?apikey=YOUR_API_KEY_HERE",
		"sk-lovensko-najlepsie-hotely-a-penziony-v-tatrach",
		"/blog/sk-hynix-q3-2024-earnings-beat-expectations-on-hbm-demand/",
		"token: " + g.botToken("1abcdefghijklmnopq"),
		"Authorization: Basic " + b64("nocolonhere12345"),
		"Authorization: Basic " + b64("admin:password"),
		func() string {
			u := "guest" + g.of(tAlnum, 6)
			return "Authorization: Basic " + b64(u+":"+strings.ToUpper(u))
		}(),
		"Basic " + b64("Aladdin:open sesame"),
		"Basic plan",
		"Basic Membership",
		"mysql://user:password@db.internal-host.gr/app",
		"smtp://mailer:" + g.mixed(tAlnum, 12) + "@mail.example.com",
		"smtp://mailer:" + g.mixed(tAlnum, 12) + "@db.example.org",
		"ftp://guest:GUEST@ftp.fixture-host.gr",
		"https://shop.fixture.gr:8443?x=1&email=jane@mail.fixture.gr",
		"GET http://shop.fixture.gr:80/cart?u=jane@mail.fixture.gr HTTP/1.1",
		"Authorization: Bearer YOUR_ACCESS_TOKEN_HERE",
		"Bearer " + g.mixed(tAlnum, 19),
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
		"Authorization: Bearer " + strings.Repeat("a1", 12),
		// Tokens whose edges pass but which don't look random.
		"token=" + "EA" + "A" + strings.Repeat("Ab1", 40),
		"token=" + "EA" + "A" + g.mixed(tAlnum, 60) + "QQQQQ" + g.of(tAlnum, 60),
		"access_token=" + "EA" + "AA" + strings.Repeat("Ab1", 20),
		"7" + g.of(tDigit, 9) + ":AA" + g.of(tB64U, 32),
		"7" + g.of(tDigit, 9) + ":Ab" + g.of(tB64U, 33),
		"x" + g.of(tAlnum, 3) + "8Q~" + g.of(tAlnum, 34) + "\"",
		g.of(tB64, 40) + "EAA" + g.mixed(tAlnum, 120) + "+/" + g.of(tB64, 40),
		"data:image/bmp;base64," + "EAA" + g.mixed(tAlnum, 120) + "+" + g.of(tB64, 40),
		g.of(tB64, 40) + "EAAA" + g.mixed(tAlnum, 60) + "/" + g.of(tB64, 40),
		g.of(tB64, 40) + "ABSK" + g.mixed(tB64, 150) + "=QUJD",
		"<p>quoting <saml:Assertion ID=\"x\"> from the docs</p>",
		"h" + "f_" + g.of(tLower, 34),
		"AC" + "CAP9ADVANCEDAUDIT1",
		"Mid-" + "server-guide-for-merchants-2024.pdf",
		// One character short and one long, for exact lengths.
		"PM" + "AK-" + g.of(tHex, 24) + "-" + g.of(tHex, 33),
		"PM" + "AK-" + g.of(tHex, 24) + "-" + g.of(tHex, 35),
		"GOC" + "SPX-" + g.of(tB64U, 27),
		"GOC" + "SPX-" + g.of(tB64U, 29),
		"HRKU" + "-AA" + g.of(tB64U, 57),
		"HRKU" + "-AA" + g.of(tB64U, 59),
		"NR" + "II-" + g.of(tB64U, 31),
		"NR" + "II-" + g.of(tB64U, 33),
		"AGE-SECRET" + "-KEY-1" + g.of(tUpper+tDigit, 57),
		"AGE-SECRET" + "-KEY-1" + g.of(tUpper+tDigit, 59),
		"GR13" + "48941" + g.of(tB64U, 19),
		"GR13" + "48941" + g.of(tB64U, 21),
		"access-" + "production-" + g.uuid() + "a",
		"np" + "m_" + g.of(tAlnum, 35),
		"np" + "m_" + g.of(tAlnum, 37),
		"gs" + "k_" + g.of(tAlnum, 53),
		"dop_" + "v1_" + g.of(tHex, 65),
		"xke" + "ysib-" + g.of(tHex, 64) + "-" + g.of(tAlnum, 15),
		"EZ" + "AK" + g.of(tAlnum, 55),
		g.of(tHex, 32) + "-" + g.of(tHex, 8) + "-" + g.of(tHex, 9),
		"LT" + "AI" + g.of(tAlnum, 30),
		"sk_" + "live_x",
	}
}

func hitsString(hits []SecretHit) string {
	var parts []string
	for _, h := range hits {
		parts = append(parts, h.Kind+" ("+h.Mode+")")
	}
	slices.Sort(parts)
	return strings.Join(parts, ", ")
}

func TestFindSecrets(t *testing.T) {
	kinds := map[string]bool{}
	for _, c := range positiveCases() {
		kinds[c.kind] = true
		hits := FindSecrets(c.in)
		if len(hits) != 1 || hits[0].Kind != c.kind || hits[0].Mode != c.mode {
			t.Errorf("%s: got [%s], want one hit (%s)", c.kind, hitsString(hits), c.mode)
		}
	}
	// Every kind in the table has a positive case.
	for _, p := range secretPatterns {
		if !kinds[p.kind] {
			t.Errorf("no positive case for %s", p.kind)
		}
	}
	for i, v := range negativeCases() {
		if hits := FindSecrets(v); len(hits) != 0 {
			t.Errorf("negative %d: got [%s]", i, hitsString(hits))
		}
	}
}

// TestFindSecretsForms checks Authorization headers in the forms logs and
// stored requests keep them, and tokens after = in key=value text.
func TestFindSecretsForms(t *testing.T) {
	g := newTokGen(3)
	tok := g.mixed(tAlnum+"._-", 40)
	basic := b64("svc_" + g.of(tLower, 8) + ":" + g.mixed(tAlnum, 14))
	const bearerKind, basicKind = "bearer token in an Authorization header", "password in a Basic Authorization header"
	cases := []secretCase{
		{"Authorization: Bearer " + tok, bearerKind, ""},
		{"[HTTP_AUTHORIZATION] => Basic " + basic, basicKind, "live"},
		{`{"Authorization":"Bearer ` + tok + `"}`, bearerKind, ""},
		{`{\"Authorization\":\"Bearer ` + tok + `\"}`, bearerKind, ""},
		{`a:1:{s:13:"Authorization";s:47:"Bearer ` + tok + `";}`, bearerKind, ""},
		{`{'Authorization': 'Basic ` + basic + `'}`, basicKind, "live"},
		{"HTTP_AUTHORIZATION=Basic " + basic, basicKind, "live"},
		{"Bearer " + tok, bearerKind, ""},
		{"Basic " + basic, basicKind, "live"},
		// Whole values under 50 bytes, as parsed JSON and PHP leaves arrive.
		{"Basic " + b64("u"+g.of(tDigit, 7)+":"+g.mixed(tAlnum, 10)), basicKind, "live"},
		{"Bearer " + g.mixed(tAlnum, 24), bearerKind, ""},
		{"token=" + "EA" + "A" + g.mixed(tAlnum, 150), "Meta access token", ""},
		{"access_token=" + "EA" + "AA" + g.mixed(tAlnum, 60), "Square access token", ""},
		{"AWS_BEARER_TOKEN_BEDROCK=" + "AB" + "SK" + g.mixed(tB64, 150), "Amazon Bedrock API key", "live"},
	}
	for i, c := range cases {
		if len(c.in) < 50 && i >= 9 && i <= 10 {
			// The early return must let these through.
		} else if i >= 9 && i <= 10 {
			t.Fatalf("case %d should be under 50 bytes, is %d", i, len(c.in))
		}
		hits := FindSecrets(c.in)
		if len(hits) != 1 || hits[0].Kind != c.kind || hits[0].Mode != c.mode {
			t.Errorf("case %d: got [%s], want one %s (%s)", i, hitsString(hits), c.kind, c.mode)
		}
	}
}

// escapedCases are URLs and tokens with JSON-escaped slashes in log lines,
// which no parser unescapes.
func escapedCases() []secretCase {
	var out []secretCase
	for _, c := range positiveCases() {
		switch c.kind {
		case "Discord webhook URL", "Slack webhook URL", "Microsoft Teams webhook URL", "Power Automate or Logic Apps URL",
			"Google OAuth refresh token":
			esc := strings.ReplaceAll(c.in, "/", `\/`)
			out = append(out, secretCase{`2026-10-18 POST payload={"hook":"` + esc + `"} sent`, c.kind, c.mode})
		}
	}
	return out
}

func TestFindSecretsEscapedSlashes(t *testing.T) {
	cases := escapedCases()
	if len(cases) < 7 {
		t.Fatalf("only %d escaped cases", len(cases))
	}
	for _, c := range cases {
		hits := FindSecrets(c.in)
		if len(hits) != 1 || hits[0].Kind != c.kind {
			t.Errorf("%s with escaped slashes: got [%s]", c.kind, hitsString(hits))
		}
	}
}

// TestFindSecretsStrongestMode checks that a value with a test key and then
// a live key of the same kind reports live.
func TestFindSecretsStrongestMode(t *testing.T) {
	g := newTokGen(4)
	paddle := func(mode string) string {
		return "pdl_" + mode + "_apikey_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22) + "_" + g.of(tAlnum, 3)
	}
	for _, c := range []secretCase{
		{"test " + "sk_" + "test_" + g.of(tAlnum, 24) + " live " + "sk_" + "live_" + g.of(tAlnum, 24), "Stripe secret key", "live"},
		{paddle("sdbx") + " " + paddle("live"), "Paddle API key", "live"},
		{"SB-Mid-" + "server-" + g.mixed(tB64U, 24) + " Mid-" + "server-" + g.mixed(tB64U, 24), "Midtrans server key", "live"},
	} {
		hits := FindSecrets(c.in)
		if len(hits) != 1 || hits[0].Kind != c.kind || hits[0].Mode != c.mode {
			t.Errorf("%s: got [%s], want %s", c.kind, hitsString(hits), c.mode)
		}
	}
}

// TestFindSecretsOverlaps checks which kinds a value gives when tokens meet.
func TestFindSecretsOverlaps(t *testing.T) {
	g := newTokGen(5)
	jwt := "ey" + "J" + g.of(tB64U, 20) + ".ey" + "J" + g.of(tB64U, 30) + "." + g.of(tB64U, 20)
	paddle := "pdl_" + "live_apikey_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22) + "_" + g.of(tAlnum, 3)
	labelled := "acme_" + "live_api" + "key_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22)
	for _, c := range []struct{ in, want string }{
		{"sk-" + "or-v1-" + g.of(tHex, 64), "OpenRouter API key (live)"},
		{"sk-" + "ant-api03-" + g.of(tB64U, 40), "Anthropic API key (live)"},
		{paddle, "Paddle API key (live)"},
		{"Authorization: Bearer " + jwt, "JSON Web Token ()"},
		{"Authorization: Bearer " + g.mixed(tAlnum, 40) + " key " + "sk_" + "test_" + g.of(tAlnum, 24),
			"Stripe secret key (test), bearer token in an Authorization header ()"},
		{jwt + " " + labelled, "JSON Web Token (), self-labelled API key (live)"},
	} {
		if got := hitsString(FindSecrets(c.in)); got != c.want {
			t.Errorf("got [%s], want [%s]", got, c.want)
		}
	}
}

// TestFindSecretsAfterInvalid checks that a valid token right after an
// invalid one of the same shape is still found, whatever separates them.
func TestFindSecretsAfterInvalid(t *testing.T) {
	g := newTokGen(6)
	for _, sep := range []string{" ", "\n", ","} {
		v := g.botToken("1abcdefghijklmnopq") + sep + g.botToken("1"+g.of(tDigit, 17))
		if got := hitsString(FindSecrets(v)); got != "Discord bot token (live)" {
			t.Errorf("separator %q: got [%s]", sep, got)
		}
	}
}

// allTestValues gathers every value the tests use, and the benchmark's.
func allTestValues() []string {
	var out []string
	for _, c := range positiveCases() {
		out = append(out, c.in)
	}
	out = append(out, negativeCases()...)
	for _, c := range escapedCases() {
		out = append(out, c.in)
	}
	for _, c := range hintCases() {
		out = append(out, c.in)
	}
	out = append(out, prefilterEdgeCases()...)
	for _, values := range benchCorpora() {
		out = append(out, values...)
	}
	return out
}

// TestFindSecretsPrefilter checks that the prefilter and the structural
// checks never change a result.
func TestFindSecretsPrefilter(t *testing.T) {
	for i, v := range allTestValues() {
		if a, b := hitsString(findSecrets(v, true)), hitsString(findSecrets(v, false)); a != b {
			t.Errorf("value %d: prefilter gives [%s], without it [%s]", i, a, b)
		}
	}
}

func FuzzFindSecrets(f *testing.F) {
	g := newTokGen(7)
	for _, c := range append(positiveCases(), hintCases()...) {
		f.Add(c.in)
	}
	for _, v := range prefilterEdgeCases() {
		f.Add(v)
	}
	f.Add("Authorization: Basic " + b64("svc:"+g.mixed(tAlnum, 12)))
	f.Add(`{"url":"https:\/\/hooks.example\/x"}`)
	kinds := map[string]bool{}
	for _, p := range secretPatterns {
		kinds[p.kind] = true
	}
	f.Fuzz(func(t *testing.T, s string) {
		hits := FindSecrets(s)
		for _, h := range hits {
			if !kinds[h.Kind] {
				t.Fatalf("unknown kind %q", h.Kind)
			}
		}
		if a, b := hitsString(hits), hitsString(findSecrets(s, false)); a != b {
			t.Fatalf("prefilter gives [%s], without it [%s]", a, b)
		}
	})
}

// TestSecretValues checks that a value counts once, however many secrets
// it holds, also when they sit in leaves past the path cap.
func TestSecretValues(t *testing.T) {
	g := newTokGen(8)
	stripe, aws := "sk_"+"live_"+g.of(tAlnum, 24), "AK"+"IA"+g.of(tUpper+tDigit, 16)
	p := NewProfile()
	p.Add("keys: " + stripe + " and " + aws)
	if p.SecretValues != 1 {
		t.Errorf("two kinds in one value: SecretValues = %d", p.SecretValues)
	}
	// Letter-only keys stay paths of their own; keys with digits would fold
	// into one map path.
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < maxPaths+5; i++ {
		fmt.Fprintf(&b, `"f%c%c%c":"v",`, 'a'+i/676, 'a'+i/26%26, 'a'+i%26)
	}
	fmt.Fprintf(&b, `"zzone":"%s","zztwo":"%s"}`, stripe, aws)
	p = NewProfile()
	p.Add(b.String())
	if live, _, _ := p.SecretTotals(); live != 2 || p.SecretValues != 1 {
		t.Errorf("overflow leaves: live = %d, SecretValues = %d", live, p.SecretValues)
	}
}
