package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// fill repeats seed to exactly n characters, for hash-shaped test values.
func fill(seed string, n int) string { return strings.Repeat(seed, n/len(seed)+1)[:n] }

func bcryptValue(i int) string { return "$2y$10$" + fill(fmt.Sprintf("Kq%02dz./", i%100), 53) }

// desValue makes a DES crypt-shaped value: 13 characters of the crypt
// alphabet, from a fixed sequence.
func desValue(i int) string {
	const crypt = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 13)
	x := uint32(i)*2654435761 + 12345
	for j := range b {
		x = x*1103515245 + 12345
		b[j] = crypt[(x>>16)%64]
	}
	return string(b)
}

func hexValue(seed string, n int) string { return fill(seed, n) }

func setting(table, key string) Subject {
	return Subject{Table: table, Column: "option_value", MetaKey: key, Name: key, Context: Tokens(table),
		Sampled: true, Setting: true}
}

var typed = []string{"hunter22", "Summer2016", "qwerty12!", "Passw0rd99", "letmein77"}

type pwCase struct {
	name   string
	sub    Subject
	values []string
	cat    model.Category
	sev    model.Severity
	conf   model.Confidence
	mask   string
}

func checkPW(t *testing.T, cases []pwCase) {
	t.Helper()
	for _, c := range cases {
		fs := Analyze(c.sub, namedProfile(c.sub.Name, c.values...))
		f := find(fs, c.cat, "")
		if f == nil {
			t.Errorf("%s: no %s finding in %+v", c.name, c.cat, fs)
			continue
		}
		if f.Severity != c.sev || f.Confidence != c.conf || (c.mask != "" && f.Mask != c.mask) {
			t.Errorf("%s: got %s, %s confidence, mask %q (%q; %q); want %s, %s, %q",
				c.name, f.Severity, f.Confidence, f.Mask, f.Reasons, f.Note, c.sev, c.conf, c.mask)
		}
		for _, g := range fs {
			if g.Severity == model.SeverityCritical && c.sev != model.SeverityCritical {
				t.Errorf("%s: unexpected critical finding %+v", c.name, g)
			}
		}
	}
}

// Passwords stored as typed are critical: a password column keeps its
// staging password, anything else becomes a secret to empty.
func TestPasswordPlainText(t *testing.T) {
	mixed := append(repeat(7, bcryptValue(1)), typed[:3]...)
	checkPW(t, []pwCase{
		{"user column", subject("users", "password", "varchar"), typed,
			model.CatPasswordHash, model.SeverityCritical, model.ConfidenceHigh, "staging_password"},
		{"hashes and plain text", subject("users", "password", "varchar"), mixed,
			model.CatPasswordHash, model.SeverityCritical, model.ConfidenceHigh, "staging_password"},
		{"account column", subject("accounts", "account_password", "varchar"), typed[:3],
			model.CatPasswordHash, model.SeverityCritical, model.ConfidenceHigh, "staging_password"},
		{"other words", subject("users", "new_password", "varchar"), typed[:3],
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"plain schemes", subject("users", "password", "varchar"), []string{"{PLAIN}hunter22", "{noop}Summer2016"},
			model.CatPasswordHash, model.SeverityCritical, model.ConfidenceHigh, "staging_password"},
		{"one plain setting", setting("wp_options", "smtp_pass"), []string{"Xy9pQr2mWz"},
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"test mode", setting("wp_options", "sandbox_api_password"), []string{"Xy9pQr2mWz"},
			model.CatSecret, model.SeverityHigh, model.ConfidenceHigh, "null"},
		{"passphrase", setting("wallets", "wallet_passphrase"), []string{"correct horse battery staple"},
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"unpadded base64", setting("wp_options", "smtp_pass"), []string{strings.Repeat("Ab3+", 11)},
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"one 13-character value among plain ones", subject("users", "password", "varchar"),
			[]string{typed[0], typed[1], "ab12CDef34GHi"},
			model.CatPasswordHash, model.SeverityCritical, model.ConfidenceHigh, "staging_password"},
		{"dollar signs", subject("users", "password", "varchar"), []string{"my$secret$pass", "our$secret$pass"},
			model.CatPasswordHash, model.SeverityCritical, model.ConfidenceHigh, "staging_password"},
	})
	f := find(Analyze(subject("users", "password", "varchar"), namedProfile("password", typed...)), model.CatPasswordHash, "")
	if f == nil || !strings.Contains(f.Note, "plain text") || f.Matched != len(typed) ||
		!strings.Contains(strings.Join(f.Reasons, "; "), "5 of 5 sampled values aren't password hashes") {
		t.Errorf("user column: got %+v", f)
	}
	// Distinct typed passwords beside hashes are plain text, unlike a mark.
	var many []string
	for i := 0; i < 30; i++ {
		many = append(many, fmt.Sprintf("spring%04d", i))
	}
	checkPW(t, []pwCase{{"typed passwords among hashes", subject("users", "password", "varchar"),
		append(repeat(270, bcryptValue(5)), many...),
		model.CatPasswordHash, model.SeverityCritical, model.ConfidenceHigh, "staging_password"}})
	// Without hashes beside it, one person's password typed again and again
	// is still plain text: a login log, and a POST log's path.
	checkPW(t, []pwCase{{"a login log", subject("login_attempts", "password", "varchar"), repeat(40, "dragonfly"),
		model.CatPasswordHash, model.SeverityCritical, model.ConfidenceHigh, ""}})
	post := "a:2:{" + phpStr("username") + phpStr("admin") + phpStr("password") + phpStr("dragonfly") + "}"
	fs := Analyze(Subject{Table: "admin_login_logs", Column: "admin_post_details", Name: "admin_post_details",
		DataType: "text", Context: Tokens("admin_login_logs"), Sampled: true}, namedProfile("admin_post_details", repeat(40, post)...))
	if f := find(fs, model.CatSecret, "password"); f == nil || f.Severity != model.SeverityCritical {
		t.Errorf("a POST log with one password: got %+v", fs)
	}
}

// Scheme prefixes are read once, so a value made of them can't slow a scan.
func TestPasswordSchemePrefixes(t *testing.T) {
	p := NewProfile()
	value := strings.Repeat("{PLAIN}", 64<<10/7) + "hunter22"
	start := time.Now()
	if k, _ := p.pwClass(value); k != pwToken {
		t.Errorf("got kind %d", k)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("classifying %d bytes took %v", len(value), d)
	}
}

// An app can't log in to a server or an API with a hash, so under a
// service's name a hash-shaped value is a credential.
func TestPasswordServices(t *testing.T) {
	brevo := "xsmtp" + "sib-" + hexValue("0a1b2c3d", 64) + "-" + fill("Qw3Er5", 16)
	checkPW(t, []pwCase{
		{"reversible scheme", Subject{Table: "config", Column: "VALUE", MetaKey: "spring.datasource.password",
			Name: "spring.datasource.password", Context: Tokens("config"), Sampled: true, Setting: true},
			[]string{"{cipher}" + fill("AQB9x", 60)}, model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"SMTP key", setting("wp_options", "smtp_password"), []string{brevo},
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"hex password", setting("wp_options", "db_password"), []string{hexValue("a1b2c3", 24)},
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"base64 password", setting("wp_options", "db_password"), []string{fill("Qk3x+9Zm", 43) + "="},
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"Jasypt", setting("wp_options", "db_password"), []string{"ENC(" + fill("Qk3x9Zm", 32) + ")"},
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"DES shapes", subject("servers", "ftp_password", "varchar"), []string{"ab12CDef34GHi", "Zx9yW8vU7tS6r"},
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"server table", subject("smtp_servers", "password", "varchar"), repeat(3, hexValue("9f8e7d6c", 40)),
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		// Mail and FTP servers keep their users' hashes unmarked.
		{"FTP users", subject("ftp_users", "password", "varchar"), repeat(3, hexValue("5f4dcc3b", 32)),
			model.CatPasswordHash, model.SeverityHigh, model.ConfidenceHigh, "staging_password"},
		{"FTP users' pass", subject("ftp_users", "pass", "varchar"), repeat(3, hexValue("5f4dcc3b", 32)),
			model.CatPasswordHash, model.SeverityHigh, model.ConfidenceHigh, "staging_password"},
		{"email account password", setting("wp_options", "email_pass"), []string{"Xy9pQr2mWz"},
			model.CatSecret, model.SeverityCritical, model.ConfidenceHigh, "null"},
		{"mail accounts", subject("smtp_accounts", "password", "varchar"), repeat(3, hexValue("5baa61e4", 40)),
			model.CatPasswordHash, model.SeverityHigh, model.ConfidenceHigh, "staging_password"},
		// No plain value: a service's password is a secret, encrypted or not.
		{"encrypted", setting("wp_options", "smtp_password"), []string{fill("eyJpdiI6", 200)},
			model.CatSecret, model.SeverityHigh, model.ConfidenceMedium, "null"},
	})
}

// Values that aren't typed passwords leave the finding as it was.
func TestPasswordNotPlain(t *testing.T) {
	checkPW(t, []pwCase{
		{"number setting", setting("wp_options", "smtp_pass"), []string{"20152016"},
			model.CatSecret, model.SeverityHigh, model.ConfidenceMedium, "null"},
		{"long encrypted value", setting("wp_options", "smtp_pass"), []string{fill("eyJpdiI6", 200)},
			model.CatSecret, model.SeverityHigh, model.ConfidenceMedium, "null"},
		{"one plain value among three", subject("users", "password", "varchar"), []string{bcryptValue(1), "hunter22", "!"},
			model.CatPasswordHash, model.SeverityHigh, model.ConfidenceMedium, "staging_password"},
		{"one plain value in 300", subject("users", "password", "varchar"), append(repeat(299, bcryptValue(2)), "hunter22"),
			model.CatPasswordHash, model.SeverityHigh, model.ConfidenceHigh, "staging_password"},
		// Marks that stand in for a password on some accounts.
		{"a repeated mark", subject("users", "password", "varchar"), append(repeat(270, bcryptValue(3)), repeat(30, "LOCKED")...),
			model.CatPasswordHash, model.SeverityHigh, model.ConfidenceHigh, "staging_password"},
		{"two repeated marks", subject("users", "password", "varchar"),
			append(append(repeat(270, bcryptValue(4)), repeat(15, "LOCKED")...), repeat(15, "ldap")...),
			model.CatPasswordHash, model.SeverityHigh, model.ConfidenceHigh, "staging_password"},
		{"redactions", subject("users", "password", "varchar"), []string{"REDACTED", "<redacted>", "XXXXXXXX"},
			model.CatPasswordHash, model.SeverityLow, model.ConfidenceLow, ""},
		// A 13-character mask has a DES hash's length, not its mix.
		{"13-character masks", subject("users", "password", "varchar"), repeat(3, strings.Repeat("X", 13)),
			model.CatPasswordHash, model.SeverityLow, model.ConfidenceLow, ""},
		{"13-character masks of a service", subject("servers", "ftp_password", "varchar"), repeat(3, strings.Repeat("X", 13)),
			model.CatSecret, model.SeverityHigh, model.ConfidenceMedium, "null"},
		{"pass or fail", subject("students", "pass", "varchar"), []string{"pass", "fail", "pass"},
			model.CatPasswordHash, model.SeverityLow, model.ConfidenceLow, ""},
		{"two numbers", subject("users", "password", "varchar"), []string{"1234", "5678"},
			model.CatPasswordHash, model.SeverityLow, model.ConfidenceLow, ""},
		{"Unix times", subject("users", "password_last_set", "varchar"), []string{"1700000000", "1700000500", "1700001000"},
			model.CatPasswordHash, model.SeverityLow, model.ConfidenceLow, ""},
		{"ISO times", subject("users", "password_last_set", "varchar"),
			[]string{"2024-01-15T10:00:00Z", "2024-02-15T10:00:00Z", "2024-03-15T10:00:00Z"},
			model.CatPasswordHash, model.SeverityLow, model.ConfidenceLow, ""},
		{"YYYYMMDD dates", subject("users", "password_last_set", "varchar"), []string{"20240115", "20240116", "20240117"},
			model.CatPasswordHash, model.SeverityLow, model.ConfidenceLow, ""},
		{"algorithm name", setting("wp_options", "admin_password"), []string{"sha256"},
			model.CatPasswordHash, model.SeverityLow, model.ConfidenceLow, ""},
	})
	// Names that describe passwords aren't judged as passwords at all.
	for _, c := range []struct{ key, value string }{
		{"password_type", "bcrypt"}, {"password_mode", "plain"}, {"password_rules", "alpha_num"},
		{"password_page", "set-password"}, {"password_timeout", "10800"}, {"password_field_color", "#cccccc"},
		{"password_selector", "#user_pass"}, {"password_width", "100%"}, {"password_set_by", "admin"},
	} {
		for _, f := range Analyze(setting("wp_options", c.key), namedProfile(c.key, c.value)) {
			if f.Category == model.CatPasswordHash || f.Severity == model.SeverityCritical {
				t.Errorf("%s: got %+v", c.key, f)
			}
		}
	}
	// A salt is a secret, not a password.
	if f := find(Analyze(subject("users", "password_salt", "varchar"), namedProfile("password_salt", typed...)),
		model.CatSecret, ""); f == nil || f.Severity == model.SeverityCritical {
		t.Errorf("password_salt: got %+v", f)
	}
}

// Hashes in formats the scanner knows, or in shapes it can't name, keep
// today's result: a password hash, with no plain values.
func TestPasswordHashFormats(t *testing.T) {
	sha := "$6$abcdefgh$" + fill("Qk3x9Zm.", 86)
	argon := "$argon2id$v=19$m=65536,t=4,p=1$" + fill("c2FsdHNh", 22) + "$" + fill("aGFzaGhh", 43)
	formats := map[string]string{
		"base64 MD5":     fill("Qk3x+9Zm", 22) + "==",
		"base64 SHA-1":   fill("Qk3x+9Zm", 27) + "=",
		"base64 SHA-256": fill("Qk3x+9Zm", 43) + "=",
		"base64 SHA-512": fill("Qk3x+9Zm", 86) + "==",
		"ASP.NET v2":     "A" + fill("Qk3x9Zm+", 65) + "==",
		"ASP.NET v3":     "AQAAAA" + fill("Qk3x9Zm+", 76) + "==",
		"MySQL":          "*" + strings.ToUpper(hexValue("a1b2c3d4", 40)),
		"MySQL old":      hexValue("6f8c1a2b", 16),
		"LDAP SSHA":      "{SSHA}" + fill("Qk3x9Zm+", 32),
		"Dovecot SHA512": "{SHA512-CRYPT}" + sha,
		"Dovecot bcrypt": "{BLF-CRYPT}" + bcryptValue(3),
		"Drupal 7":       "U$S$" + fill("Qk3x9Zm.", 52),
		"Nextcloud":      "1|" + bcryptValue(4),
		"Nextcloud v3":   "3|" + argon,
		"MediaWiki A":    ":A:" + hexValue("5f4dcc3b", 32),
		"MediaWiki B":    ":B:1a2b3c4d:" + hexValue("5f4dcc3b", 32),
		"htpasswd":       "$apr1$salt1234$" + fill("Qk3x9Zm.", 22),
		"phpBB":          "$CP$" + bcryptValue(5),
		"TYPO3":          "$pbkdf2-sha256$25000$" + fill("c2FsdHNh", 22) + "$" + fill("aGFzaGhh", 43),
		"Gitea":          hexValue("0f1e2d3c", 100),
		"Django":         "bcrypt_sha256$" + bcryptValue(6),
		"Werkzeug":       "pbkdf2:sha256:600000$saltsalt$" + hexValue("9f8e7d6c", 64),
		"Magento 1":      hexValue("5f4dcc3b", 32) + ":abcdefghij:0",
		"DES":            "ab12CDef34GHi",
	}
	for name, v := range formats {
		fs := Analyze(subject("users", "password", "varchar"), namedProfile("password", repeat(3, v)...))
		f := find(fs, model.CatPasswordHash, "")
		if f == nil || f.Confidence != model.ConfidenceHigh || f.Severity != model.SeverityHigh {
			t.Errorf("%s: got %+v", name, fs)
		}
	}
	// DES hashes left among bcrypt ones by a migration.
	f := find(Analyze(subject("users", "password", "varchar"),
		namedProfile("password", bcryptValue(1), bcryptValue(2), bcryptValue(3), "ab12CDef34GHi")), model.CatPasswordHash, "")
	if f == nil || f.Severity != model.SeverityHigh || f.Matched != 4 {
		t.Errorf("DES among bcrypt: got %+v", f)
	}
	// A whole column of DES hashes, some starting with / or . and a letter
	// like a path or a CSS class, beside the * and ! of locked accounts.
	var des []string
	for i := 0; i < 40; i++ {
		des = append(des, desValue(i))
	}
	des = append(des, "/"+desValue(40)[1:], "."+"k"+desValue(41)[2:], "./"+desValue(42)[2:], "*", "!")
	f = find(Analyze(subject("users", "password", "varchar"), namedProfile("password", des...)), model.CatPasswordHash, "")
	if f == nil || f.Severity != model.SeverityHigh || f.Confidence != model.ConfidenceHigh || strings.Contains(f.Note, "plain text") {
		t.Errorf("DES column: got %+v", f)
	}
	// Dovecot's and OpenLDAP's {CRYPT}, with a DES hash or a lock mark.
	f = find(Analyze(subject("users", "password", "varchar"),
		namedProfile("password", "{CRYPT}"+desValue(1), "{CRYPT}"+desValue(2), "{CRYPT}!")), model.CatPasswordHash, "")
	if f == nil || f.Severity != model.SeverityHigh || f.Confidence != model.ConfidenceHigh {
		t.Errorf("{CRYPT}: got %+v", f)
	}
	// The shapes are named in the reason, and no value text reaches it.
	f = find(Analyze(subject("users", "password", "varchar"), namedProfile("password", repeat(3, formats["base64 SHA-256"])...)),
		model.CatPasswordHash, "")
	if f == nil || !strings.Contains(strings.Join(f.Reasons, "; "), "hash formats: base64 digest 3") {
		t.Errorf("base64 reason: got %+v", f)
	}
	// 16 to 31 hex digits are a hash only for a user's own password.
	f = find(Analyze(subject("routers", "wifi_password", "varchar"), namedProfile("wifi_password", repeat(3, formats["MySQL old"])...)),
		model.CatSecret, "")
	if f == nil || f.Severity != model.SeverityCritical {
		t.Errorf("short hex under another name: got %+v", f)
	}
	// Digests in columns no rule names stay unflagged.
	for _, col := range []string{"iv", "checksum", "etag", "content_md5", "file_sha256"} {
		for _, v := range []string{formats["base64 MD5"], hexValue("5f4dcc3b", 64)} {
			for _, g := range Analyze(subject("files", col, "varchar"), namedProfile(col, repeat(5, v)...)) {
				if g.Category == model.CatPasswordHash {
					t.Errorf("%s: got %+v", col, g)
				}
			}
		}
	}
}

// Passwords inside JSON and serialized values: a POST log, a settings blob.
func TestPasswordPaths(t *testing.T) {
	var rows []string
	for i := 0; i < 5; i++ {
		rows = append(rows, "a:4:{"+phpStr("username")+phpStr("admin")+
			phpStr("password")+phpStr(fmt.Sprintf("Secret%03d", i))+
			phpStr("newpass")+phpStr(fmt.Sprintf("Newpass%02d", i))+
			phpStr("set_password")+phpStr(fmt.Sprintf("Setpass%02d", i))+"}")
	}
	sub := Subject{Table: "admin_login_logs", Column: "admin_post_details", Name: "admin_post_details",
		DataType: "text", Context: Tokens("admin_login_logs"), Sampled: true}
	fs := Analyze(sub, namedProfile(sub.Name, rows...))
	for _, path := range []string{"password", "newpass", "set_password"} {
		if f := find(fs, model.CatSecret, path); f == nil || f.Severity != model.SeverityCritical || f.Mask != "null" {
			t.Errorf("POST log %s: got %+v", path, fs)
		}
	}
	// A settings blob: the service is named by a key above the password.
	blob := `{"smtp_settings":{"host":"smtp.mail.fixture.test","password":"` + hexValue("9f8e7d6c", 40) + `"}}`
	fs = Analyze(setting("wp_options", "swpsmtp_options"), namedProfile("swpsmtp_options", blob))
	if f := find(fs, model.CatSecret, "smtp_settings.password"); f == nil || f.Severity != model.SeverityCritical {
		t.Errorf("settings blob: got %+v", fs)
	}
	// UpdraftPlus: only the option's own name says the password is FTP's.
	updraft := `{"settings":{"s-` + hexValue("9f8e7d6c", 16) + `":{"host":"ftp.fixture.test","pass":"Xy9pQr2mWz"}}}`
	fs = Analyze(setting("wp_options", "updraft_ftp"), namedProfile("updraft_ftp", updraft))
	if f := find(fs, model.CatSecret, "settings.*.pass"); f == nil || f.Severity != model.SeverityCritical {
		t.Errorf("UpdraftPlus FTP password: got %+v", fs)
	}
	// A service named above a path in a user's settings: still a secret.
	prefs := `{"smtp":{"host":"smtp.fixture.test","pass":"Xy9pQr2mWz"}}`
	fs = Analyze(Subject{Table: "users", Column: "settings", Name: "settings", DataType: "text", Context: Tokens("users"),
		Sampled: true}, namedProfile("settings", prefs))
	if f := find(fs, model.CatSecret, "smtp.pass"); f == nil || f.Severity != model.SeverityCritical || f.Mask != "null" {
		t.Errorf("SMTP password in a user's settings: got %+v", fs)
	}
	// PayPal's NVP credentials, as WooCommerce and IP.Nexus keep them.
	paypal := "a:3:{" + phpStr("api_username") + phpStr("seller_api1.shop.fixture.test") +
		phpStr("api_password") + phpStr(strings.ToUpper(fill("qw3rt7yu1op2", 16))) + phpStr("api_signature") +
		phpStr(fill("Ab3dEf6hIj9k", 56)) + "}"
	fs = Analyze(setting("wp_options", "woocommerce_paypal_settings"), namedProfile("woocommerce_paypal_settings", paypal))
	if f := find(fs, model.CatSecret, "api_password"); f == nil || f.Severity != model.SeverityCritical {
		t.Errorf("api_password: got %+v", fs)
	}
	if f := find(fs, model.CatSecret, "api_signature"); f == nil || f.Confidence == model.ConfidenceLow {
		t.Errorf("api_signature: got %+v", fs)
	}
}
