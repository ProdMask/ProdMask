package fixture

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Planted lists the secrets a fixture plants, for leak tests: the values,
// and the generated parts of each, of which no output may hold any eight
// characters in a row. It is kept in memory only, never written to a file.
type Planted struct {
	Values []string
	Random []string
}

// plant records a value and its generated parts, and returns the value.
func (f *filler) plant(value string, random ...string) string {
	if f.planted != nil {
		f.planted.Values = append(f.planted.Values, value)
		f.planted.Random = append(f.planted.Random, random...)
	}
	return value
}

const (
	hexChars    = "0123456789abcdef"
	lowerDigits = "abcdefghijklmnopqrstuvwxyz0123456789"
	b64urlChars = alnumChars + "_-"
	b64Chars    = alnumChars + "+/"
	base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// secretTables fills three tables: integrations holding every secret format
// the scanner knows by its shape, a log of API requests with credentials in
// headers, URLs and $_SERVER dumps, and push tokens; with look-alikes that
// must not count. Values come from a generator of their own, so the values
// before them stay as they were. Every token is assembled here from pieces.
func (f *filler) secretTables() {
	g := newGen(4301)
	c := f.canary
	r := g.chars
	// tok plants prefix+tail, the tail generated, and returns it.
	tok := func(prefix, tail string, more ...string) string {
		return f.plant(prefix+tail+strings.Join(more, ""), tail)
	}
	mixed := func(set string, n int) string { return "aZ7" + r(set, n-3) }
	uuid := func() string {
		return r(hexChars, 8) + "-" + r(hexChars, 4) + "-" + r(hexChars, 4) + "-" + r(hexChars, 4) + "-" + r(hexChars, 12)
	}
	// Every generated piece of a token is recorded, so an echo of any part shows.
	botNum := f.plant("1" + r("0123456789", 17))
	botID, botMid, botSig := base64.RawURLEncoding.EncodeToString([]byte(botNum)), r(b64urlChars, 6), r(b64urlChars, 38)
	teamsA, teamsB, teamsKey, teamsC := uuid(), uuid(), r(hexChars, 32), uuid()
	oldA, oldB, oldKey, oldC := uuid(), uuid(), r(alnumChars, 32), uuid()
	flowID, flowSig := r(hexChars, 32), r(b64urlChars, 43)
	discordURL := func() string {
		return tok("https://disc"+"ord.com/api/web"+"hooks/1"+r("0123456789", 18)+"/", c+r(b64urlChars, 57))
	}
	paddle := func(mode string) string {
		return tok("pdl_"+mode+"_api"+"key_", c+r(lowerDigits, 15)+"_"+r(alnumChars, 22)+"_"+r(alnumChars, 3))
	}
	creds := []struct{ service, value string }{
		{"discord", discordURL()},
		{"discord", f.plant(botID+"."+botMid+"."+botSig, botID, botSig)},
		{"telegram", tok("7"+r("0123456789", 9)+":A"+"A", c+r(b64urlChars, 22))},
		{"teams", f.plant("https://fixture.webhook.office.com/webhookb2/"+teamsA+"@"+teamsB+"/IncomingWebhook/"+teamsKey+"/"+teamsC,
			teamsA, teamsB, teamsKey, teamsC)},
		{"teams", f.plant("https://outlook.office.com/webhook/"+oldA+"@"+oldB+"/IncomingWebhook/"+oldKey+"/"+oldC, oldA, oldB, oldKey, oldC)},
		{"flows", f.plant("https://prod-21.westeurope.logic.azure.com:443/workflows/"+flowID+
			"/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig="+flowSig, flowID, flowSig)},
		{"slack", tok("https://hoo"+"ks.slack.com/workflows/T"+r(upperChars, 9)+"/A"+r(upperChars, 10)+"/", r("0123456789", 18)+"/"+r(alnumChars, 24))},
		{"slack", tok("https://hoo"+"ks.slack.com/triggers/T"+r(upperChars, 9)+"/", r("0123456789", 13)+"/"+r(hexChars, 32))},
		{"slack", tok("xa"+"pp-1-A"+r(upperChars, 10)+"-", r("0123456789", 13)+"-"+r(hexChars, 64))},
		{"postman", tok("PM"+"AK-", r(hexChars, 24)+"-"+r(hexChars, 34))},
		{"paddle", paddle("live")},
		{"paddle", paddle("sdbx")},
		{"square", tok("sq0"+"atp-", c+r(b64urlChars, 11))},
		{"square", tok("EA"+"AA", mixed(alnumChars, 60))},
		{"square", tok("sq0"+"csp-", c+r(b64urlChars, 32))},
		{"brevo", tok("xke"+"ysib-", r(hexChars, 64)+"-"+r(alnumChars, 16))},
		{"mailgun", tok("", r(hexChars, 32)+"-"+r(hexChars, 8)+"-"+r(hexChars, 8))},
		{"google", tok("GOC"+"SPX-", c+r(b64urlChars, 17))},
		{"google", tok("1/"+"/0", c+r(b64urlChars, 79))},
		{"google", tok("ya"+"29.", c+r(b64urlChars, 109))},
		{"entra", "client_secret=\"" + tok("", r(alnumChars, 3)+"8Q"+"~"+r(alnumChars+"_~.-", 34)) + "\""},
		{"meta", tok("EA"+"AG", mixed(alnumChars, 180))},
		{"smtp", f.urlCredential(g)},
		{"openai", tok("sk-"+"proj-", r(b64urlChars, 74)+"T3Blbk"+"FJ"+r(b64urlChars, 74))},
		{"deepseek", tok("sk-", r(hexChars, 32))},
		{"openrouter", tok("sk-"+"or-v1-", r(hexChars, 64))},
		{"gitlab", tok("gl"+"pat-", c+r(b64urlChars, 9))},
		{"gitlab", tok("GR13"+"48941", r(b64urlChars, 20))},
		{"npm", tok("np"+"m_", c+r(alnumChars, 25))},
		{"pypi", tok("pypi-"+"AgEIcHlwaS5vcmc", r(b64urlChars, 70))},
		{"atlassian", tok("ATAT"+"T3", r(b64urlChars, 180))},
		{"docker", tok("dckr_"+"pat_", c+r(b64urlChars, 16))},
		{"linear", tok("lin_"+"api_", c+r(alnumChars, 29))},
		{"notion", tok("nt"+"n_", r("0123456789", 11)+c+r(alnumChars, 24))},
		{"airtable", tok("pa"+"t", r(alnumChars, 14)+"."+r(hexChars, 64))},
		{"figma", tok("fi"+"gd_", c+r(b64urlChars, 29))},
		{"typeform", tok("tf"+"p_", c+r(alnumChars, 48))},
		{"digitalocean", tok("dop_"+"v1_", r(hexChars, 64))},
		{"heroku", tok("HRKU"+"-AA", c+r(b64urlChars, 47))},
		{"grafana", tok("gl"+"sa_", r(alnumChars, 32)+"_"+r(hexChars, 8))},
		{"grafana", tok("gl"+"c_", c+r(alnumChars, 49))},
		{"sentry", tok("sntrys_"+"eyJpYXQiO", r(b64urlChars, 60))},
		{"sentry", tok("sntryu_", r(hexChars, 64))},
		{"newrelic", tok("NR"+"AK-", r(upperChars, 27))},
		{"newrelic", tok("NR"+"II-", c+r(b64urlChars, 21))},
		{"doppler", tok("dp."+"pt.", c+r(alnumChars, 32))},
		{"doppler", tok("dp."+"st.dev.", r(alnumChars, 43))},
		{"vault", tok("hv"+"s.", c+r(b64urlChars, 89))},
		{"vault", tok("hv"+"b.", r(b64urlChars, 150))},
		{"terraform", tok(r(alnumChars, 14)+".atlas"+"v1.", c+r(alnumChars, 56))},
		{"1password", tok("ops_"+"eyJ", r(b64Chars, 300))},
		{"age", tok("AGE-SECRET"+"-KEY-1", r(upperChars, 58))},
		{"planetscale", tok("pscale_"+"pw_", c+r(alnumChars, 32))},
		{"supabase", tok("sb"+"p_", r(hexChars, 40))},
		{"supabase", tok("sb_"+"secret_", c+r(b64urlChars, 19))},
		{"databricks", tok("da"+"pi", r(hexChars, 32))},
		{"cloudflare", tok("v1."+"0-", r(hexChars, 24)+"-"+r(hexChars, 146))},
		{"huggingface", tok("h"+"f_", "aZ"+r("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 32))},
		{"huggingface", tok("api_"+"org_", "aZ"+r("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 32))},
		{"groq", tok("gs"+"k_", c+r(alnumChars, 41))},
		{"perplexity", tok("pp"+"lx-", c+r(alnumChars, 37))},
		{"xai", tok("xa"+"i-", c+r(alnumChars, 69))},
		{"shippo", tok("shippo_"+"live_", r(hexChars, 40))},
		{"shippo", tok("shippo_"+"test_", r(hexChars, 40))},
		{"easypost", tok("EZ"+"AK", c+r(alnumChars, 43))},
		{"easypost", tok("EZ"+"TK", c+r(alnumChars, 43))},
		{"flutterwave", tok("FLWSECK"+"_TEST-", c+r(alnumChars, 21), "-X")},
		{"flutterwave", tok("FLWSECK"+"-", c+r(alnumChars, 21), "-X")},
		{"plaid", tok("access-"+"production-", uuid())},
		{"plaid", tok("access-"+"sandbox-", uuid())},
		{"plaid", tok("access-"+"development-", uuid())},
		{"midtrans", tok("SB-Mid-"+"server-", mixed(b64urlChars, 24))},
		{"midtrans", tok("Mid-"+"server-", mixed(b64urlChars, 24))},
		{"amazon", tok("At"+"zr|", c+r(b64urlChars, 49))},
		{"amazon", tok("At"+"za|", c+r(b64urlChars, 49))},
		{"aws", tok("AB"+"IA", r(base32Chars, 16))},
		{"bedrock", tok("AB"+"SK", mixed(b64Chars, 150))},
		{"alibaba", tok("LT"+"AI", r(alnumChars, 16))},
		{"saml", tok("SAMLResponse="+"PHNhbWxwOlJlc3BvbnNl", r(b64Chars, 200))},
		{"saml", "<saml:Assertion ID=\"_" + tok("", r(hexChars, 16)) + "\" IssueInstant=\"2026-10-18T10:00:00Z\" Version=\"2.0\">"},
		{"acme", tok("acme_"+"live_api"+"key_", c+r(lowerDigits, 15)+"_"+r(alnumChars, 22))},
	}
	settings := func() string {
		b, _ := json.Marshal(map[string]any{"discord": map[string]any{"webhook": discordURL()},
			"paddle": map[string]any{"api_key": paddle("live")}, "google": map[string]any{"refresh_token": tok("1/"+"/0", r(b64urlChars, 90))}})
		return string(b)
	}
	var rows [][]any
	for i, cr := range creds {
		var set, discord, hook, photo any
		if i < 3 {
			set, discord = settings(), discordURL()
			hook = fmt.Sprintf("https://erp.fixture-partner.gr/hooks/orders/%d", i+1)
		}
		if i < 4 {
			photo = bmpLike(g)
		}
		rows = append(rows, []any{cr.service, cr.value, set, discord, hook, "mysql://user:password@db.example.com/app",
			"plugin_apikey_label", "sk-hynix-q3-2024-earnings-beat-expectations-on-hbm-demand", photo})
	}
	f.insert("integrations", []string{"service", "credential", "settings", "discord_webhook", "webhook_url", "docs_url",
		"plugin_option", "post_name", "photo"}, rows)

	var logs [][]any
	for i := 0; i < 6; i++ {
		bearer := tok("", c+mixed(alnumChars+"._-", 29))
		user, pass := f.plant("svc"+c, c), tok("", c+mixed(alnumChars, 9))
		basic := f.plant(base64.StdEncoding.EncodeToString([]byte(user + ":" + pass)))
		var headers string
		switch i % 3 {
		case 0:
			headers = "Host: api.fixture-host.gr\nAuthorization: Bearer " + bearer + "\nAccept: */*"
		case 1:
			headers = "Array\n(\n    [HTTP_AUTHORIZATION] => Basic " + basic + "\n)"
		default:
			headers = php(kv{"Authorization", "Bearer " + bearer, "Host", "api.fixture-host.gr"})
		}
		jsonHeaders, _ := json.Marshal(map[string]string{"Authorization": "Basic " + basic, "Accept": "application/json"})
		server, _ := json.Marshal(map[string]string{"PHP_AUTH_USER": "svc", "PHP_AUTH_PW": tok("", c+"Pw"+mixed(alnumChars, 10)),
			"REQUEST_METHOD": "POST"})
		escaped := strings.ReplaceAll(discordURL(), "/", `\/`)
		logs = append(logs, []any{
			"GET https://api.fixture-host.gr/v1/orders?api" + "_key=" + tok("", c+mixed(alnumChars, 21)) + "&page=1 HTTP/1.1",
			headers, string(jsonHeaders),
			"https://api.fixture-host.gr/v1/items?access" + "_token=" + tok("", c+mixed(alnumChars, 21)),
			`2026-10-18 10:00:0` + fmt.Sprint(i) + ` POST /hooks payload={"url":"` + escaped + `"} sent`,
			string(server), "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"})
	}
	f.insert("api_request_log", []string{"request_line", "request_headers", "headers", "request_url", "payload", "server_vars",
		"sample_header"}, logs)

	var devices [][]any
	for i := 0; i < 5; i++ {
		fcm := tok("", r(b64urlChars, 22)+":APA91b"+r(b64urlChars, 134))
		expo := tok("ExponentPush"+"Token[", r(b64urlChars, 22), "]")
		devices = append(devices, []any{"shop-app", fcm, expo})
	}
	f.insert("push_devices", []string{"app_name", "registration_id", "expo_token"}, devices)
}

// urlCredential plants an SMTP URL with a user and password, recording
// each part.
func (f *filler) urlCredential(g *gen) string {
	user := f.plant("mailer"+f.canary, f.canary)
	pass := f.plant("aZ7"+f.canary+g.chars(alnumChars, 8), f.canary)
	host := f.plant(f.canary+".fixture-host.gr", f.canary)
	return f.plant("smtp://" + user + ":" + pass + "@" + host + ":587")
}

// bmpLike returns base64 of uncompressed image-like bytes, mostly zeros,
// which hold runs such as EAAA and ABSK by chance.
func bmpLike(g *gen) string {
	b := make([]byte, 3072)
	for i := range b {
		if g.intn(3) == 0 {
			b[i] = byte(g.intn(256))
		}
	}
	return base64.StdEncoding.EncodeToString(b)
}
