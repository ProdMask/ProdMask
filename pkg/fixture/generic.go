package fixture

import (
	"fmt"
	"net/netip"
	"strings"
)

// generic fills a schema no preset knows: a forum's admin login log,
// members, private messages, notifications and caches; a billing app's
// settings and admins; a shop's translation table and customer groups;
// custom apps' settings, donations, PayPal IPN log, game log and form
// entries; and tables shaped like key/value stores that hold people.
func (f *filler) generic() {
	g := f.g

	var logs [][]any
	for i := 1; i <= 12; i++ {
		pw := g.alnum(10)
		if i == 5 {
			pw = f.canary + "Pw1"
		}
		post := php(kv{"username", "admin" + fmt.Sprint(i%3), "password", pw, "newpass", g.alnum(9) + "7",
			"set_password", g.alnum(8) + "Q2", "remember", "1"})
		logs = append(logs, []any{i, "admin" + fmt.Sprint(i%3), 1700000000 + i*3600, post})
	}
	f.insert("admin_login_logs", []string{"admin_id", "admin_username", "admin_time", "admin_post_details"}, logs)

	var members [][]any
	for id := 1; id <= 30; id++ {
		p := g.person(900 + id)
		display := p.first + " " + p.last
		var hwid, day, month, year any
		if g.chance(0.6) {
			hwid = strings.ToUpper(fmt.Sprintf("%s-%s-%s-%s-%s", g.hex(8), g.hex(4), g.hex(4), g.hex(4), g.hex(12)))
		}
		if id%5 == 0 {
			day, month, year = 1+g.intn(28), 1+g.intn(12), 1960+g.intn(45)
		}
		var regip []byte
		if id%7 == 0 {
			regip = binaryIP(fmt.Sprintf("2001:db8::%x", 0x100+id))
		} else {
			regip = binaryIP(fmt.Sprintf("192.0.2.%d", 10+id))
		}
		members = append(members, []any{id, display, p.email, display,
			strings.ToLower(p.first + "-" + p.last), g.hex(32), hwid, day, month, year, g.hex(32), g.alnum(5),
			regip, binaryIP(fmt.Sprintf("198.51.100.%d", 10+id)), []byte(fmt.Sprintf("203.0.113.%d", 10+id)),
			g.bytes(16), g.bytes(16)})
	}
	f.insert("members", []string{"member_id", "name", "email", "members_display_name", "members_seo_name",
		"member_login_key", "hwid", "bday_day", "bday_month", "bday_year", "members_pass_hash", "members_pass_salt",
		"regip", "lastip", "poster_ip", "device_uuid", "ip_hash"}, members)

	var topics, notes [][]any
	titles := []string{"Question about my order", "Re: meeting on Friday", "Thanks for the help", "Can you call me back",
		"Lost my password again", "Photos from the trip", "Selling my old keyboard", "Welcome to the team"}
	for i := 1; i <= 20; i++ {
		title := titles[i%len(titles)]
		if i == 9 {
			title = "Re: photos for " + f.canary
		}
		topics = append(topics, []any{i, title, 1 + g.intn(30)})
		notes = append(notes, []any{i, 1 + g.intn(30), g.sentence(12) + " " + g.sentence(8)})
	}
	f.insert("message_topics", []string{"mt_id", "mt_title", "mt_starter_id"}, topics)
	f.insert("inline_notifications", []string{"notify_id", "notify_to_id", "notify_text"}, notes)

	var cached [][]any
	for i := 1; i <= 10; i++ {
		body := "<p>" + g.sentence(20) + "</p>"
		if i == 4 {
			body = "<p>Thanks " + f.canary + " for the post.</p>"
		}
		cached = append(cached, []any{i, body, 1700000000 + i})
	}
	f.insert("content_cache_posts", []string{"cache_content_id", "cache_content", "cache_updated"}, cached)
	admin := g.person(990)
	f.insert("cache_store", []string{"cs_key", "cs_value", "cs_updated"}, [][]any{
		{"forum_cache", php(kv{"posts", 1200, "topics", 340}), 1700000000},
		{"settings", php(kv{"board_name", "Fixture Forum", "email_in", admin.email, "upload_dir", "/uploads"}), 1700000000},
		{"bbcode", php([]any{"b", "i", "quote"}), 1700000000},
		{"emoticons", php([]any{":)", ":("}), 1700000000},
		{"member_stats", php(kv{"members", 30, "last_member", 30}), 1700000000},
	})
	f.insert("banfilters", []string{"ban_id", "ban_type", "ban_content"}, [][]any{
		{1, "email", "spam" + fmt.Sprint(g.intn(90)+10) + "@" + domains[0]},
		{2, "ip", "203.0.113.66"},
	})

	f.insert("setting", []string{"param", "value"}, [][]any{
		{"company_name", companies[1]}, {"company_email", admin.email}, {"company_tel", admin.phone},
		{"company_address_1", admin.street}, {"company_note", "Ask " + f.canary + " about invoices"},
		{"invoice_prefix", "BB"}, {"currency", "EUR"}, {"theme", "boxbilling"}, {"timezone", "Europe/Athens"},
		{"smtp_host", "smtp.fixture-mail.gr"}, {"smtp_user", "billing"}, {"logo_url", ""},
	})
	f.insert("admin", []string{"email", "pass", "salt", "name"}, [][]any{
		{admin.email, g.hex(40), g.hex(16), admin.first + " " + admin.last},
		{g.person(991).email, g.hex(40), g.hex(16), "Support"},
	})

	var defs [][]any
	labels := [][2]string{{"entry_email_address", "E-Mail Address:"}, {"entry_telephone", "Telephone:"},
		{"entry_password", "Password:"}, {"text_api_key", "API key:"}, {"entry_firstname", "First Name:"},
		{"entry_lastname", "Last Name:"}, {"entry_address_1", "Address 1:"}, {"entry_postcode", "Post Code:"},
		{"text_welcome", "Welcome back, " + f.canary + "!"}, {"text_contact", "Write to us anytime."},
		{"entry_company", "Company:"}, {"entry_city", "City:"}}
	for i, l := range labels {
		defs = append(defs, []any{i + 1, 1, l[0], l[1]})
	}
	f.insert("ab_language_definitions", []string{"language_definition_id", "language_id", "language_key", "language_value"}, defs)
	f.insert("ab_customer_groups", []string{"name"}, [][]any{{"Default"}, {"Wholesale"}, {"Newsletter"}})

	f.insert("settings", []string{"setting_name", "setting_value"}, [][]any{
		{"site_name", "Fixture Arena"}, {"admin_email", admin.email}, {"smtp_password", g.alnum(12) + "9"},
		{"motd", "Welcome " + f.canary}, {"max_players", "64"},
	})

	var donations, ipn, games [][]any
	const base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for i := 1; i <= 15; i++ {
		p := g.person(1000 + i)
		donations = append(donations, []any{i, jsonString(map[string]any{
			"callback_url":  fmt.Sprintf("https://pay.fixture-store.test/cb?id=%d&email=%s", i, p.email),
			"input_address": "1" + g.chars(base58, 33), "amount": "5.00"})})
	}
	for i := 1; i <= 10; i++ {
		p := g.person(1100 + i)
		ipn = append(ipn, []any{i, jsonString(map[string]any{
			"first_name": p.first, "last_name": p.last, "payer_email": p.email, "address_name": p.first + " " + p.last,
			"address_street": p.street, "address_city": p.city, "address_state": p.region, "address_zip": p.postcode,
			"address_country": p.country, "address_country_code": p.country, "address_status": "confirmed"})})
	}
	for i := 1; i <= 30; i++ {
		games = append(games, []any{i, g.pick([]string{"Shadow", "Blaze", "Nova", "Rune"}) + fmt.Sprint(g.intn(9000)+100)})
	}
	f.insert("donations", []string{"id", "data"}, donations)
	f.insert("paypal_ipn", []string{"id", "ipn_data"}, ipn)
	f.insert("game_logs", []string{"id", "summonername"}, games)

	// A contact form's entries, keyed by field labels; one key names a
	// person and must never be shown.
	var entries [][]any
	for e := 1; e <= 5; e++ {
		p := g.person(1200 + e)
		for _, kvp := range [][2]string{{"Your Name", p.first + " " + p.last}, {"Emergency contact", p.phone},
			{"Phone number", p.phone}, {"Gift message", "Happy birthday, see you soon"}, {"VAT number", "EL0" + g.chars("0123456789", 8)},
			{"Date of birth", ts(g.date(1960, 2004))[:10]}, {f.canary + " quill phone", g.phone()}} {
			entries = append(entries, []any{e, kvp[0], kvp[1]})
		}
	}
	f.insert("form_entries", []string{"entry_id", "field_key", "field_value"}, entries)

	var contacts, customers, memberSettings, kvRows [][]any
	for i := 1; i <= 10; i++ {
		p := g.person(1300 + i)
		contacts = append(contacts, []any{p.first + " " + p.last, p.phone})
		customers = append(customers, []any{p.first + " " + p.last, p.email})
		memberSettings = append(memberSettings, []any{strings.ToLower(p.first) + fmt.Sprint(i), p.email})
		key := p.first + " " + p.last
		if i == 6 {
			key = f.canary + " Roe"
		}
		kvRows = append(kvRows, []any{key, p.phone})
	}
	f.insert("contacts", []string{"contact_name", "contact_value"}, contacts)
	f.insert("customers", []string{"customer_name", "customer_value"}, customers)
	f.insert("member_settings", []string{"member_name", "member_value"}, memberSettings)
	f.insert("kv", []string{"key", "value"}, kvRows)
}

// binaryIP returns an address as the bytes an app stores: 4 for IPv4, 16
// for IPv6.
func binaryIP(s string) []byte {
	a := netip.MustParseAddr(s)
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

// bytes returns n random bytes, such as a hash or a binary UUID.
func (g *gen) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(g.intn(256))
	}
	return b
}
