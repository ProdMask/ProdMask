package detect

import (
	"strings"
	"testing"
)

// lengthCase is a format with an exact length or bounds: prefix, tail class,
// shortest and longest tail, and what follows the tail.
type lengthCase struct {
	kind, prefix, set string
	min, max          int
	suffix            string
}

func lengthCases() []lengthCase {
	g := newTokGen(30)
	return []lengthCase{
		{"Postman API key", "PM" + "AK-" + g.of(tHex, 24) + "-", tHex, 34, 34, ""},
		{"Google OAuth client secret", "GOC" + "SPX-", tB64U, 28, 28, ""},
		{"Heroku API key", "HRKU" + "-AA", tB64U, 58, 58, ""},
		{"New Relic key", "NR" + "II-", tB64U, 32, 32, ""},
		{"New Relic key", "NR" + "AK-", tUpper + tDigit, 27, 27, ""},
		{"age secret key", "AGE-SECRET" + "-KEY-1", tUpper + tDigit, 58, 58, ""},
		{"GitLab token", "GR13" + "48941", tB64U, 20, 20, ""},
		{"npm token", "np" + "m_", tAlnum, 36, 36, ""},
		{"Groq API key", "gs" + "k_", tAlnum, 52, 52, ""},
		{"Perplexity API key", "pp" + "lx-", tAlnum, 48, 48, ""},
		{"xAI API key", "xa" + "i-", tAlnum, 80, 80, ""},
		{"Linear API key", "lin_" + "api_", tAlnum, 40, 40, ""},
		{"Notion token", "nt" + "n_" + g.of(tDigit, 11), tAlnum, 35, 35, ""},
		{"Airtable token", "pa" + "t" + g.of(tAlnum, 14) + ".", tHex, 64, 64, ""},
		{"DigitalOcean token", "dop_" + "v1_", tHex, 64, 64, ""},
		{"Sentry token", "sntryu_", tHex, 64, 64, ""},
		{"Grafana token", "gl" + "sa_" + g.of(tAlnum, 32) + "_", tHex, 8, 8, ""},
		{"Brevo API key", "xke" + "ysib-" + g.of(tHex, 64) + "-", tAlnum, 16, 16, ""},
		{"EasyPost API key", "EZ" + "AK", tAlnum, 54, 54, ""},
		{"Telegram bot token", "7" + g.of(tDigit, 9) + ":A" + "A", tB64U, 33, 33, ""},
		{"AWS access key ID", "AB" + "IA", tUpper + "234567", 16, 16, ""},
		{"Databricks token", "da" + "pi", tHex, 32, 32, ""},
		{"Cloudflare Origin CA key", "v1." + "0-" + g.of(tHex, 24) + "-", tHex, 146, 146, ""},
		{"Flutterwave secret key", "FLWSECK" + "-", tAlnum, 32, 32, "-X"},
		{"Hugging Face token", "h" + "f_aZ", tLower + tUpper, 32, 32, ""},
		{"Shippo API key", "shippo_" + "live_", tHex, 40, 40, ""},
		{"Supabase key", "sb" + "p_", tHex, 40, 40, ""},
		{"Plaid access token", "access-" + "production-" + g.of(tHex, 8) + "-" + g.of(tHex, 4) + "-" + g.of(tHex, 4) + "-" +
			g.of(tHex, 4) + "-", tHex, 12, 12, ""},
		{"Mailgun API key", g.of(tHex, 32) + "-" + g.of(tHex, 8) + "-", tHex, 8, 8, ""},
		{"Discord webhook URL", "https://disc" + "ord.com/api/web" + "hooks/1" + g.of(tDigit, 18) + "/", tB64U, 60, 80, ""},
		{"Discord bot token", g.botToken("1" + g.of(tDigit, 17))[:32], tB64U, 27, 38, ""},
		{"Microsoft Entra client secret", "\"" + g.of(tAlnum, 3) + "8Q~", tAlnum + "_~.-", 31, 34, "\""},
		{"Doppler token", "dp." + "pt.", tAlnum, 40, 44, ""},
		{"Vault token", "hv" + "s.", tB64U, 90, 120, ""},
		{"Vault token", "hv" + "b.", tB64U, 138, 300, ""},
		{"Terraform Cloud token", g.of(tAlnum, 14) + ".atlas" + "v1.", tAlnum, 60, 70, ""},
		{"PlanetScale token", "pscale_" + "pw_", tAlnum, 32, 64, ""},
		{"Alibaba Cloud AccessKey ID", "LT" + "AI", tAlnum, 12, 20, ""},
	}
}

func hasHitKind(hits []SecretHit, kind string) bool {
	for _, h := range hits {
		if h.Kind == kind {
			return true
		}
	}
	return false
}

// TestFindSecretsLengths checks each exact length and each bound: the
// shortest and longest tails match, one less and one more don't.
func TestFindSecretsLengths(t *testing.T) {
	g := newTokGen(31)
	for i, c := range lengthCases() {
		tail := func(n int) string { return g.mixed(c.set, n) }
		if !strings.ContainsAny(c.set, tUpper) || !strings.ContainsAny(c.set, tLower) || !strings.ContainsAny(c.set, tDigit) {
			tail = func(n int) string { return g.of(c.set, n) }
		}
		for _, n := range []int{c.min, c.max} {
			if v := c.prefix + tail(n) + c.suffix; !hasHitKind(FindSecrets(v), c.kind) {
				t.Errorf("case %d (%s): a tail of %d isn't found", i, c.kind, n)
			}
		}
		if v := c.prefix + tail(c.min-1) + c.suffix; hasHitKind(FindSecrets(v), c.kind) {
			t.Errorf("case %d (%s): a tail of %d is found", i, c.kind, c.min-1)
		}
		if v := c.prefix + tail(c.max+1) + c.suffix; hasHitKind(FindSecrets(v), c.kind) {
			t.Errorf("case %d (%s): a tail of %d is found", i, c.kind, c.max+1)
		}
	}
}

// TestFindSecretsEdges checks that a token glued to a byte its edges refuse
// isn't found.
func TestFindSecretsEdges(t *testing.T) {
	g := newTokGen(32)
	bot := g.botToken("1" + g.of(tDigit, 17))
	mailgun := g.of(tHex, 32) + "-" + g.of(tHex, 8) + "-" + g.of(tHex, 8)
	entra := g.of(tAlnum, 3) + "8Q~" + g.of(tAlnum, 34)
	cases := []struct{ kind, in string }{
		{"Telegram bot token", g.of("123456789", 13) + ":A" + "A" + g.of(tB64U, 33)},
		{"Telegram bot token", "7" + g.of(tDigit, 9) + ":A" + "A" + g.of(tB64U, 33) + "x"},
		{"Discord bot token", "x" + bot},
		{"Discord bot token", bot + "x"},
		{"Mailgun API key", "a" + mailgun},
		{"Mailgun API key", mailgun + "a"},
		{"Microsoft Entra client secret", "x" + entra + "\""},
		{"Microsoft Entra client secret", "\"" + entra + "x"},
		{"Google OAuth refresh token", "a1/" + "/0" + g.of(tB64U, 90)},
		{"Google OAuth refresh token", "/1/" + "/0" + g.of(tB64U, 90)},
		{"Shippo API key", "shippo_" + "live_" + g.of(tHex, 40) + "a"},
		{"Midtrans server key", "xSB-Mid-" + "server-" + g.mixed(tB64U, 24)},
		{"Midtrans server key", "xMid-" + "server-" + g.mixed(tB64U, 24)},
		{"Square access token", "A" + "EA" + "AA" + g.mixed(tAlnum, 60)},
		{"Meta access token", "A" + "EA" + "A" + g.mixed(tAlnum, 150)},
		{"Amazon Bedrock API key", "A" + "AB" + "SK" + g.mixed(tB64, 150)},
		{"Amazon Bedrock API key", "AB" + "SK" + g.mixed(tB64, 150) + "==="},
		{"self-labelled API key", "x" + "api" + "key-" + g.mixed(tAlnum, 32)},
	}
	for i, c := range cases {
		if hasHitKind(FindSecrets(c.in), c.kind) {
			t.Errorf("case %d (%s): found though glued", i, c.kind)
		}
	}
}

// TestFindSecretsValidators checks each validator's thresholds and the
// modes that self-labelled keys read from their words.
func TestFindSecretsValidators(t *testing.T) {
	g := newTokGen(33)
	labelled := func(words string) string {
		return words + "_api" + "key_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22)
	}
	url := "https://api.fixture-host.gr/v1?"
	for _, c := range []secretCase{
		{labelled("acme_sandbox"), "self-labelled API key", "test"},
		{labelled("acme_sdbx"), "self-labelled API key", "test"},
		{labelled("acme_dev"), "self-labelled API key", "test"},
		{labelled("acme_staging"), "self-labelled API key", "test"},
		{labelled("acme_prod"), "self-labelled API key", "live"},
		{labelled("acme_production"), "self-labelled API key", "live"},
		{"api" + "_key_" + g.mixed(tAlnum, 32), "self-labelled API key", ""},
		{"api" + "-key-" + g.mixed(tAlnum, 32), "self-labelled API key", ""},
		{url + "api" + "-key=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		{url + "api" + "key=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		{url + "access" + "-token=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		{url + "access" + "_token=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		{url + "access" + "token=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		{url + "client" + "-secret=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		{url + "client" + "_secret=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		{url + "client" + "secret=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
	} {
		hits := FindSecrets(c.in)
		if len(hits) != 1 || hits[0].Kind != c.kind || hits[0].Mode != c.mode {
			t.Errorf("%s (%s): got [%s]", c.kind, c.mode, hitsString(hits))
		}
	}
	for i, v := range []string{
		"token: " + g.botToken("0"+g.of(tDigit, 17)),
		"token=" + "EA" + "A" + g.of(tUpper+tDigit, 150),
		"x " + "EA" + "AA" + g.of(tUpper+tDigit, 60),
		"sk-uncharacteristically-cold-winter-in-the-alps",
		"sk-ab12ab12ab12ab12-release-notes-and-more",
		"sk-release-x1y2z3a4b5c6-notes-and-more-here",
		"Authorization: Bearer YOUR_TOKEN_HERE_123456789",
		"smtp://mailer:aaaaaaaaaaaa@mail.fixture-host.gr",
		"smtp://mailer:{password}@mail.fixture-host.gr",
		"smtp://mailer:$PASSWORD@mail.fixture-host.gr",
		"smtp://mailer:%PASS%@mail.fixture-host.gr",
		"smtp://mailer:[secret]@mail.fixture-host.gr",
		"h" + "f_" + g.of(tUpper, 34),
	} {
		if hits := FindSecrets(v); len(hits) != 0 {
			t.Errorf("validator negative %d: got [%s]", i, hitsString(hits))
		}
	}
}

// prefilterEdgeCases are values the prefilter once let through differently:
// whole-value forms with other spacing, and keywords that only Unicode case
// folding would match (the Kelvin sign and the long s).
func prefilterEdgeCases() []string {
	g := newTokGen(34)
	tok, basic := g.mixed(tAlnum, 40), b64("svc_"+g.of(tLower, 8)+":"+g.mixed(tAlnum, 14))
	const kelvin, longS = "\xe2\x84\xaa", "\xc5\xbf"
	return []string{
		" Bearer " + tok, "Bearer\n" + tok, "Bearer\t" + tok, "Basic\f" + basic, "Basic\r" + basic, " Basic " + basic,
		"api_" + kelvin + "ey_" + g.mixed(tAlnum, 32),
		"https://api.fixture-host.gr/v1?api_" + kelvin + "ey=" + g.mixed(tAlnum, 32),
		"https://api.fixture-host.gr/v1?acce" + longS + longS + "_token=" + g.mixed(tAlnum, 32),
		"ba" + longS + "ic " + basic,
		"Authorization: Ba" + longS + "ic " + basic,
	}
}

// TestPatternsHaveGates checks that every pattern has hints or a structural
// check, which the early return in findSecrets relies on.
func TestPatternsHaveGates(t *testing.T) {
	for i, p := range secretPatterns {
		if len(p.hints) == 0 && p.pre == nil {
			t.Errorf("pattern %d (%s) has neither hints nor a check", i, p.kind)
		}
	}
}

// hintCases are positives for the hints and alternatives the other cases
// don't reach, so the prefilter test exercises each one.
func hintCases() []secretCase {
	g := newTokGen(35)
	var out []secretCase
	for _, p := range []string{"glpat-", "gldt-", "glrt-", "glptt-", "glcbt-", "gloas-", "glft-", "glimt-", "glsoat-", "glagent-"} {
		out = append(out, secretCase{p + g.of(tB64U, 24), "GitLab token", "live"})
	}
	for _, p := range []string{"gh" + "o_", "gh" + "u_", "gh" + "s_", "gh" + "r_"} {
		out = append(out, secretCase{p + g.of(tAlnum, 36), "GitHub token", "live"})
	}
	for _, p := range []string{"shp" + "ca_", "shp" + "pa_", "shp" + "ss_"} {
		out = append(out, secretCase{p + g.of(tHex, 32), "Shopify access token", "live"})
	}
	for _, p := range []string{"doo_" + "v1_", "dor_" + "v1_"} {
		out = append(out, secretCase{p + g.of(tHex, 64), "DigitalOcean token", "live"})
	}
	for _, p := range []string{"pscale_" + "tkn_", "pscale_" + "oauth_"} {
		out = append(out, secretCase{p + g.of(tAlnum, 43), "PlanetScale token", "live"})
	}
	for _, p := range []string{"dp." + "ct.", "dp." + "sa.", "dp." + "scim.", "dp." + "audit."} {
		out = append(out, secretCase{p + g.of(tAlnum, 43), "Doppler token", "live"})
	}
	for _, o := range []string{"PHNhbWwycDpSZXNwb25z", "PHNhbWw6QXNzZXJ0aW9u", "PHNhbWwyOkFzc2VydGlv"} {
		out = append(out, secretCase{o + g.of(tB64, 100), "SAML message", ""})
	}
	return append(out,
		secretCase{"dckr_" + "oat_" + g.of(tB64U, 27), "Docker token", "live"},
		secretCase{"r" + "k_" + "live_" + g.of(tAlnum, 24), "Stripe secret key", "live"},
		secretCase{"AS" + "IA" + g.of(tUpper+tDigit, 16), "AWS access key ID", "live"},
		secretCase{"AC" + "CA" + g.of(tUpper+"234567", 16), "AWS access key ID", "live"},
		secretCase{"c" + "s_" + g.of(tHex, 40), "WooCommerce API key", "live"},
		secretCase{"https://default1234.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/" +
			g.of(tHex, 32) + "/triggers/manual/paths/invoke?api-version=1&sv=1.0&sig=" + g.of(tB64U, 43),
			"Power Automate or Logic Apps URL", "live"},
		secretCase{"https://api.fixture-host.gr/v1?api" + "-key=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		secretCase{"https://api.fixture-host.gr/v1?api" + "key=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		secretCase{"https://api.fixture-host.gr/v1?access" + "-token=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		secretCase{"https://api.fixture-host.gr/v1?access" + "token=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		secretCase{"https://api.fixture-host.gr/v1?access" + "_token=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		secretCase{"https://api.fixture-host.gr/v1?client" + "-secret=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		secretCase{"https://api.fixture-host.gr/v1?client" + "_secret=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		secretCase{"https://api.fixture-host.gr/v1?client" + "secret=" + g.mixed(tAlnum, 32), "API key in a URL", ""},
		secretCase{"api" + "_key_" + g.mixed(tAlnum, 32), "self-labelled API key", ""},
		secretCase{"api" + "-key-" + g.mixed(tAlnum, 32), "self-labelled API key", ""},
	)
}

func TestFindSecretsHints(t *testing.T) {
	for _, c := range hintCases() {
		hits := FindSecrets(c.in)
		if len(hits) != 1 || hits[0].Kind != c.kind || hits[0].Mode != c.mode {
			t.Errorf("%s: got [%s], want %s (%s)", c.kind, hitsString(hits), c.kind, c.mode)
		}
	}
	// Every hint appears in some test value.
	var all []string
	for _, c := range append(positiveCases(), hintCases()...) {
		all = append(all, strings.ToLower(c.in))
	}
	joined := strings.Join(all, "\n")
	for _, p := range secretPatterns {
		for _, h := range p.hints {
			if !strings.Contains(joined, strings.ToLower(h)) {
				t.Errorf("no test value holds the hint %q (%s)", h, p.kind)
			}
		}
	}
}

// TestEveryPatternHasPositive checks that each pattern, not only each kind,
// matches some positive value by itself.
func TestEveryPatternHasPositive(t *testing.T) {
	var values []string
	for _, c := range append(positiveCases(), hintCases()...) {
		values = append(values, c.in)
	}
	for i := range secretPatterns {
		p := &secretPatterns[i]
		found := false
		for _, v := range values {
			if len(p.matches(v)) > 0 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("pattern %d (%s) matches no positive value", i, p.kind)
		}
	}
}

// TestFallbacksDontStack checks that a fallback match yields to another
// fallback's token it overlaps.
func TestFallbacksDontStack(t *testing.T) {
	g := newTokGen(36)
	key := "acme_" + "live_api" + "key_" + g.of(tLower+tDigit, 26) + "_" + g.of(tAlnum, 22)
	// The self-labelled key carries a mode, so it wins over the URL and
	// bearer fallbacks that hold it, and the value stays critical.
	for _, v := range []string{"https://api.fixture-host.gr/v1?api" + "_key=" + key, "Authorization: Bearer " + key, "Bearer " + key} {
		if got := hitsString(FindSecrets(v)); got != "self-labelled API key (live)" {
			t.Errorf("%s: got [%s]", v[:16], got)
		}
	}
}
