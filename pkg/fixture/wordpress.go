package fixture

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// wordpress fills a WordPress + WooCommerce shop: customers with billing
// details, legacy orders in postmeta, HPOS orders, sessions, saved cards,
// webhooks, scheduled renewals and payment/mail settings in live mode.
func (f *filler) wordpress() {
	g := f.g
	const nUsers = 60
	people := make([]person, nUsers+1)

	var users, usermeta [][]any
	logins := make([]string, nUsers+1)
	for id := 1; id <= nUsers; id++ {
		p := g.person(id)
		if id == 7 {
			p.email = f.canary + "@fixture-mail.gr"
		}
		people[id] = p
		login := fmt.Sprintf("%s.%s%d", strings.ToLower(p.first), strings.ToLower(p.last[:1]), id)
		display := p.first + " " + p.last
		if id >= 21 && id <= 30 {
			// Sites that let people sign up with their email address.
			login, display = p.email, p.email
		}
		logins[id] = login
		pass := g.phpass()
		if id%3 == 0 {
			pass = g.wpBcrypt()
		}
		url, activation := "", ""
		if g.chance(0.2) {
			url = "https://blog.fixture-sites.net/" + login
		}
		if g.chance(0.1) {
			activation = fmt.Sprintf("%d:%s", 1700000000+g.intn(10000000), g.phpass())
		}
		users = append(users, []any{id, login, pass, login, p.email, url, ts(g.date(2019, 2025)), activation, 0, display})

		role := "customer"
		if id == 1 {
			role = "administrator"
		}
		um := func(k, v string) { usermeta = append(usermeta, []any{id, k, v}) }
		um("nickname", login)
		um("first_name", p.first)
		um("last_name", p.last)
		switch {
		case id == 1:
			um("description", "Shop owner. Write to me at "+p.email+" or call "+p.phone+".")
		case g.chance(0.3):
			um("description", g.sentence(12))
		default:
			um("description", "")
		}
		um("wp_capabilities", php(kv{role, true}))
		um("wp_user_level", "0")
		um("billing_first_name", p.first)
		um("billing_last_name", p.last)
		if g.chance(0.3) {
			um("billing_company", p.company)
		}
		um("billing_address_1", p.street)
		um("billing_city", p.city)
		um("billing_postcode", p.postcode)
		um("billing_country", p.country)
		um("billing_state", p.region)
		um("billing_email", p.email)
		um("billing_phone", p.phone)
		um("shipping_first_name", p.first)
		um("shipping_last_name", p.last)
		um("shipping_address_1", p.street)
		um("shipping_city", p.city)
		um("shipping_postcode", p.postcode)
		um("shipping_country", p.country)
		um("session_tokens", php(kv{g.hex(64), kv{"expiration", 1760000000 + g.intn(900000), "ip", p.ip, "ua", p.agent, "login", 1759000000 + g.intn(900000)}}))
		um("wc_last_active", fmt.Sprint(1759000000+g.intn(900000)))
		um("_woocommerce_persistent_cart_1", php(kv{"cart", kv{g.hex(32), kv{"key", g.hex(32), "product_id", 41 + g.intn(40), "quantity", 1 + g.intn(3), "line_total", 19.9}}}))
		if g.chance(0.3) {
			um("community-events-location", php(kv{"description", p.city, "latitude", "37.9800", "longitude", "23.7200", "country", p.country, "ip", p.ip}))
		}
		if umEmailUser(id) {
			// Ultimate Member puts the user's email address in a key name.
			um(umEmailKey(p.email), p.email)
		}
		if id >= 2 && id <= 6 {
			um("default_password_nag", "")
		}
	}
	f.insert("wp_users", []string{"ID", "user_login", "user_pass", "user_nicename", "user_email", "user_url",
		"user_registered", "user_activation_key", "user_status", "display_name"}, users)
	f.insert("wp_usermeta", []string{"user_id", "meta_key", "meta_value"}, usermeta)

	// Posts: blog posts 1-30, pages 31-40, products 41-80, attachments
	// 81-110, legacy orders 111-260.
	var posts, postmeta [][]any
	post := func(id, author int, typ, status, title, content, password string, parent int, mime string) {
		d := ts(g.date(2020, 2025))
		posts = append(posts, []any{id, author, d, d, content, title, "", status, "open", "open", password,
			strings.ToLower(strings.ReplaceAll(title, " ", "-")), d, d, parent,
			fmt.Sprintf("https://shop.fixture-store.test/?p=%d", id), 0, typ, mime, 0})
	}
	pm := func(id int, k, v string) { postmeta = append(postmeta, []any{id, k, v}) }
	for id := 1; id <= 30; id++ {
		body := g.sentence(40) + "\n\n" + g.sentence(30)
		if id == 5 {
			body += " Thanks to " + f.canary + " for the photos."
		}
		post(id, 1, "post", "publish", "Journal entry "+fmt.Sprint(id), body, "", 0, "")
		pm(id, "_edit_lock", fmt.Sprintf("%d:1", 1750000000+g.intn(1000000)))
		pm(id, "_edit_last", "1")
		pm(id, "_thumbnail_id", fmt.Sprint(81+g.intn(30)))
	}
	for id := 31; id <= 40; id++ {
		body := g.sentence(60)
		if id == 31 {
			body = "Privacy policy. Questions? Write to privacy@fixture-store.gr. " + body
		}
		post(id, 1, "page", "publish", "Page "+fmt.Sprint(id), body, "", 0, "")
	}
	for id := 41; id <= 80; id++ {
		post(id, 1, "product", "publish", "Product "+fmt.Sprint(id), g.sentence(25), "", 0, "")
		price := fmt.Sprintf("%d.90", 9+g.intn(80))
		pm(id, "_price", price)
		pm(id, "_regular_price", price)
		pm(id, "_sku", fmt.Sprintf("FX-%04d", id))
		pm(id, "_stock_status", "instock")
		pm(id, "total_sales", fmt.Sprint(g.intn(500)))
		pm(id, "_product_attributes", php(kv{"pa_size", kv{"name", "pa_size", "value", "", "position", 0, "is_visible", 1, "is_variation", 1, "is_taxonomy", 1}}))
	}
	for id := 81; id <= 110; id++ {
		post(id, 1, "attachment", "inherit", fmt.Sprintf("IMG_%04d", 1000+id), "", "", 0, "image/jpeg")
		file := fmt.Sprintf("2024/%02d/photo-%d.jpg", 1+g.intn(12), id)
		pm(id, "_wp_attached_file", file)
		pm(id, "_wp_attachment_metadata", php(kv{"width", 1600, "height", 1200, "file", file,
			"sizes", kv{"thumbnail", kv{"file", "photo-150x150.jpg", "width", 150, "height", 150}},
			"image_meta", kv{"credit", "Photo: " + g.pick(firstNames) + " " + g.pick(lastNames), "camera", "Canon EOS R6", "copyright", "", "title", ""}}))
	}
	for id := 111; id <= 260; id++ {
		uid := 0
		if g.chance(0.7) {
			uid = 2 + g.intn(nUsers-1)
		}
		p := g.person(1000 + id)
		if uid > 0 {
			p = people[uid]
		}
		key := "wc_order_" + g.alnum(13)
		post(id, 1, "shop_order", "wc-completed", "Order", "", key, 0, "")
		addr := strings.Join([]string{p.first, p.last, p.street, p.city, p.region, p.postcode, p.country, p.email, p.phone}, " ")
		if id == 120 {
			addr += " " + f.canary
		}
		for _, m := range [][2]string{
			{"_order_key", key}, {"_customer_user", fmt.Sprint(uid)},
			{"_billing_first_name", p.first}, {"_billing_last_name", p.last}, {"_billing_company", p.company},
			{"_billing_address_1", p.street}, {"_billing_city", p.city}, {"_billing_state", p.region},
			{"_billing_postcode", p.postcode}, {"_billing_country", p.country}, {"_billing_email", p.email},
			{"_billing_phone", p.phone}, {"_shipping_first_name", p.first}, {"_shipping_last_name", p.last},
			{"_shipping_address_1", p.street}, {"_shipping_city", p.city}, {"_shipping_postcode", p.postcode},
			{"_shipping_country", p.country}, {"_payment_method", "stripe"}, {"_payment_method_title", "Credit card"},
			{"_transaction_id", "ch_" + g.alnum(24)}, {"_customer_ip_address", p.ip}, {"_customer_user_agent", p.agent},
			{"_order_total", fmt.Sprintf("%d.%02d", 10+g.intn(200), g.intn(100))}, {"_order_currency", "EUR"},
			{"_billing_address_index", addr}, {"_shipping_address_index", addr},
			{"_stripe_customer_id", "cus_" + g.alnum(14)}, {"_stripe_source_id", "src_" + g.alnum(24)},
		} {
			pm(id, m[0], m[1])
		}
	}
	// bbPress replies, a coupon for named customers, two Contact Form 7
	// forms (one in demo mode) and a privacy request.
	for id := 300; id <= 303; id++ {
		post(id, 2+id%5, "reply", "publish", "Re: delivery times", g.sentence(15), "", 0, "")
	}
	post(310, 1, "shop_coupon", "publish", "VIPONLY", "", "", 0, "")
	post(320, 1, "wpcf7_contact_form", "publish", "Contact form", "[text* your-name] [email* your-email]", "", 0, "")
	post(321, 1, "wpcf7_contact_form", "publish", "Test form", "[email* your-email]", "", 0, "")
	d := ts(g.date(2025, 2025))
	posts = append(posts, []any{330, 0, d, d, `{"type":"export_personal_data"}`, "requester@fixture-mail.gr", "",
		"request-confirmed", "closed", "closed", g.phpass(), "export_personal_data", d, d, 0, "", 0, "user_request", "", 0})
	special := map[int]func(){
		290: func() { pm(300, "_bbp_author_ip", g.ip()); pm(301, "_bbp_author_ip", g.ip()) },
		700: func() {
			pm(310, "customer_email", php([]any{"vip@fixture-mail.gr", "maria.p@fixture-mail.gr"}))
			pm(310, "discount_type", "percent")
		},
		1900: func() {
			pm(320, "_mail", php(kv{"subject", "[your-subject]", "sender", "[_site_title] <wordpress@fixture-store.test>",
				"body", "From: [your-name]", "recipient", "office@fixture-store.gr", "additional_headers", "Reply-To: [your-email]"}))
			pm(321, "_mail", php(kv{"subject", "Test", "recipient", "[_site_admin_email]", "body", "[your-email]"}))
			pm(321, "_additional_settings", "demo_mode: on")
		},
		2640: func() { pm(302, "_bbp_author_ip", g.ip()); pm(303, "_bbp_author_ip", g.ip()) },
	}
	// Years of edits make wp_postmeta bigger than a scan reads whole: old
	// slugs, page templates, ratings and image backups on the posts above.
	// The keys above sit deep inside, away from the oldest, middle and
	// newest rows a window sample reads.
	for n := 0; n < 3500; n++ {
		if add := special[n]; add != nil {
			add()
		}
		pm(1+n%30, "_wp_old_slug", fmt.Sprintf("journal-entry-draft-%d", n))
		pm(1+n%30, "_wp_page_template", "default")
		pm(41+n%40, "_wc_average_rating", fmt.Sprintf("%d.%d", 3+g.intn(2), g.intn(10)))
		pm(41+n%40, "_wc_review_count", fmt.Sprint(g.intn(40)))
		pm(81+n%30, "_wp_attachment_backup_sizes", php(kv{"full-orig", kv{"width", 1600, "height", 1200, "file", fmt.Sprintf("photo-%d.jpg", n)}}))
	}
	f.insert("wp_posts", []string{"ID", "post_author", "post_date", "post_date_gmt", "post_content", "post_title",
		"post_excerpt", "post_status", "comment_status", "ping_status", "post_password", "post_name", "post_modified",
		"post_modified_gmt", "post_parent", "guid", "menu_order", "post_type", "post_mime_type", "comment_count"}, posts)
	f.insert("wp_postmeta", []string{"post_id", "meta_key", "meta_value"}, postmeta)

	// Comments: product reviews, blog comments and order notes.
	var comments, commentmeta [][]any
	for id := 1; id <= 140; id++ {
		p := g.person(2000 + id)
		uid := 0
		if g.chance(0.4) {
			uid = 2 + g.intn(nUsers-1)
			p = people[uid]
		}
		postID, typ := 1+g.intn(30), "comment"
		content := g.sentence(10 + g.intn(20))
		switch {
		case id%3 == 0:
			postID, typ = 41+g.intn(40), "review"
		case id%10 == 1:
			postID, typ = 111+g.intn(150), "order_note"
			p = person{first: "WooCommerce", email: "woocommerce@fixture-store.gr"}
			content = "Order status changed from Processing to Completed."
		}
		if id%11 == 0 {
			content += " You can reach me on " + p.phone + "."
		}
		if id%17 == 0 {
			content += " My email is " + p.email + "."
		}
		author := strings.TrimSpace(p.first + " " + p.last)
		url := ""
		if g.chance(0.15) {
			url = "https://blog.fixture-sites.net/" + strings.ToLower(p.first)
		}
		d := ts(g.date(2021, 2025))
		comments = append(comments, []any{id, postID, author, p.email, url, p.ip, d, d, content, 0, "1", p.agent, typ, 0, uid})
		if typ == "review" {
			commentmeta = append(commentmeta, []any{id, "rating", fmt.Sprint(1 + g.intn(5))}, []any{id, "verified", fmt.Sprint(g.intn(2))})
		}
		if typ != "order_note" {
			commentmeta = append(commentmeta, []any{id, "akismet_result", "false"},
				[]any{id, "akismet_as_submitted", php(kv{"comment_author", author, "comment_author_email", p.email,
					"comment_author_url", url, "comment_content", content, "user_ip", p.ip, "user_agent", p.agent,
					"blog", "https://shop.fixture-store.test", "blog_lang", "en_US"})})
		}
	}
	f.insert("wp_comments", []string{"comment_ID", "comment_post_ID", "comment_author", "comment_author_email",
		"comment_author_url", "comment_author_IP", "comment_date", "comment_date_gmt", "comment_content", "comment_karma",
		"comment_approved", "comment_agent", "comment_type", "comment_parent", "user_id"}, comments)
	f.insert("wp_commentmeta", []string{"comment_id", "meta_key", "meta_value"}, commentmeta)

	f.wordpressOptions(people, logins)
	f.wordpressTerms()
	f.wordpressPlugins()
	f.woocommerceOrders(people)
	f.woocommerceRest(people)
}

// umEmailUser lists the users who signed up through Ultimate Member with
// their email address as username; the canary's user is one of them.
func umEmailUser(id int) bool { return id == 7 || (id >= 10 && id <= 14) }

// umEmailKey is the user meta key Ultimate Member builds from an email
// address, with the @ and the dots taken out.
func umEmailKey(email string) string {
	return "um_email_as_username_" + strings.NewReplacer("@", "", ".", "").Replace(strings.ToLower(email))
}

func (f *filler) wordpressOptions(people []person, logins []string) {
	g := f.g
	admin := people[1]
	event := func(schedule string, interval int) kv {
		return kv{g.hex(32), kv{"schedule", schedule, "args", []any{}, "interval", interval}}
	}
	opts := [][]any{
		{"siteurl", "https://shop.fixture-store.test", "yes"},
		{"home", "https://shop.fixture-store.test", "yes"},
		{"blogname", "Fixture Store", "yes"},
		{"admin_email", admin.email, "yes"},
		{"db_version", "60421", "yes"},
		{"logged_in_salt", g.chars(cryptChars+"!@#%^&*()-_=+[]{}<>~", 64), "no"},
		{"woocommerce_version", "9.3.3", "yes"},
		{"woocommerce_db_version", "9.3.3", "yes"},
		{"woocommerce_custom_orders_table_enabled", "yes", "yes"},
		{"woocommerce_stripe_settings", php(kv{"enabled", "yes", "title", "Credit card", "testmode", "no",
			"publishable_key", "pk_" + "live_" + g.alnum(24), "secret_key", g.stripeKey("live"),
			"test_secret_key", g.stripeKey("test"), "webhook_secret", "whsec_" + g.alnum(32)}), "yes"},
		{"woocommerce_cod_settings", php(kv{"enabled", "yes", "title", "Cash on delivery"}), "yes"},
		// PayPal's NVP API credentials, from fixed pieces so the generator's
		// sequence, and every value after it, stays as it was.
		{"woocommerce_paypal_settings", php(kv{"enabled", "no", "testmode", "no", "email", admin.email,
			"api_username", "seller_api1.fixture-store.test", "api_password", "Pw7" + f.canary + "X",
			"api_signature", strings.Repeat("A1b2C3d4", 7), "sandbox_api_password", "Sb" + "x9Kq2mP4"}), "yes"},
		{"wp_mail_smtp", php(kv{"mail", kv{"from_email", "shop@fixture-store.gr", "from_name", "Fixture Store", "mailer", "sendgrid"},
			"sendgrid", kv{"api_key", g.sendgridKey(), "domain", ""}}), "yes"},
		{"as3cf_settings", php(kv{"provider", "aws", "access-key-id", g.awsKeyID(), "bucket", "fixture-media"}), "yes"},
		{"active_plugins", php([]any{"woocommerce/woocommerce.php", "wp-mail-smtp/wp_mail_smtp.php",
			"woocommerce-gateway-stripe/woocommerce-gateway-stripe.php", "woocommerce-shipping/woocommerce-shipping.php"}), "yes"},
		{"cron", php(kv{
			1760000000, kv{"wp_version_check", event("twicedaily", 43200)},
			1760000100, kv{"updraft_backup", event("daily", 86400)},
			1760000200, kv{"woocommerce_tracker_send_event", event("daily", 86400)},
			1760000300, kv{"wpforms_email_summaries_cron", event("weekly", 604800)},
			1760000400, kv{"um_daily_scheduled_events", event("daily", 86400)},
			"version", 2}), "yes"},
	}
	opts = append(opts, f.wordpressSettings(people, logins)...)
	for i := 0; i < 150; i++ {
		switch i % 3 {
		case 0:
			opts = append(opts, []any{fmt.Sprintf("_transient_wc_product_children_%d", 41+i), php(kv{"all", []any{}, "visible", []any{}}), "no"})
		case 1:
			opts = append(opts, []any{fmt.Sprintf("_transient_timeout_wc_report_%d", i), fmt.Sprint(1760000000 + i), "no"})
		default:
			opts = append(opts, []any{fmt.Sprintf("widget_block_%d", i), php(kv{2, kv{"content", "<p>" + g.sentence(6) + "</p>"}, "_multiwidget", 1}), "yes"})
		}
	}
	f.insert("wp_options", []string{"option_name", "option_value", "autoload"}, opts)
}

// wordpressSettings returns plugin settings that hold personal data or
// secrets, and some that only look as if they did. They sit between the
// first options and the filler, away from the rows a window sample reads.
func (f *filler) wordpressSettings(people []person, logins []string) [][]any {
	g := f.g
	var opts [][]any
	opt := func(name, value string) { opts = append(opts, []any{name, value, "no"}) }

	// Ultimate Member's per-user profile caches.
	for id := 1; id < len(people); id++ {
		p := people[id]
		profile := kv{"ID", id, "user_login", logins[id], "user_email", p.email, "user_pass", g.phpass(),
			"display_name", p.first + " " + p.last, "account_status", "approved"}
		if umEmailUser(id) {
			profile = append(profile, umEmailKey(p.email), p.email)
		}
		opt(fmt.Sprintf("um_cache_userdata_%d", id), php(profile))
	}

	// Secrets, assembled at run time.
	opt("secret_key", g.chars(cryptChars+"!@#%^&*()-_=+[]{}<>~", 64))
	opt("wp_mail_smtp_mail_key", base64.StdEncoding.EncodeToString([]byte(g.alnum(32))))
	opt("wpgmza_temp_api", "AI"+"za"+g.chars(alnumChars+"_-", 35))
	opt("fixture_hashids_salt", g.alnum(32))
	titles := kv{}
	for i := 0; i < 60; i++ {
		titles = append(titles, fmt.Sprintf("pt_type_%c%c_title", 'a'+i/26, 'a'+i%26), "%title% %sep% %sitename% "+g.sentence(8))
	}
	titles = append(titles, "facebook_admin_id", "", "facebook_secret", g.alnum(32))
	opt("rank-math-options-titles", php(titles))

	// Limit Login Attempts keys its arrays by visitor IP.
	ip1, ip2, ip3 := g.ip(), g.ip(), g.ip()
	opt("limit_login_lockouts", php(kv{ip1, 1760000000, ip2, 1760000300}))
	opt("limit_login_retries", php(kv{ip3, 2}))
	opt("limit_login_retries_valid", php(kv{ip3, 1760000600}))
	opt("limit_login_logged", php(kv{ip1, kv{"admin", 3}}))

	// Staff notifications.
	opt("woocommerce_new_order_settings", php(kv{"enabled", "yes", "recipient", "staff@fixture-store.gr, owner@fixture-store.gr",
		"subject", "", "heading", "", "email_type", "html"}))
	opt("woocommerce_cancelled_order_settings", php(kv{"enabled", "yes", "recipient", "staff@fixture-store.gr"}))
	opt("woocommerce_failed_order_settings", php(kv{"enabled", "no", "recipient", ""}))
	opt("fixture_admin_recipient", "manager@fixture-store.gr")
	opt("woocommerce_wc_memberships_user_membership_ending_soon_email_settings", php(kv{"enabled", "yes"}))
	opt("woocommerce_wc_memberships_user_membership_ended_email_settings", php(kv{"enabled", "yes"}))
	opt("woocommerce_wc_memberships_user_membership_renewal_reminder_email_settings", php(kv{"enabled", "no"}))

	// Connected services, tracking and backups.
	opt("jetpack_private_options", php(kv{"blog_token", g.alnum(32) + "." + g.alnum(32)}))
	opt("woocommerce_allow_tracking", "yes")
	opt("updraft_service", php([]any{"s3"}))

	// Names that say more than the values hold.
	opt("fixture_db_version", "1.8.1.2")
	opt("woocommerce_registration_generate_password", "yes")
	opt("woocommerce_myaccount_lost_password_endpoint", "lost-password")
	opt("woocommerce_myaccount_edit_address_endpoint", "edit-address")
	opt("woocommerce_email_background_color", "#f7f7f7")
	opt("woocommerce_eu_vat_number_validate", "yes")
	opt("_transient_fixture_customer_email", "42")
	return opts
}

// wordpressPlugins fills plugin tables: WooCommerce admin notes, an
// import plugin's column mappings and Ultimate Member's member fields.
func (f *filler) wordpressPlugins() {
	g := f.g
	var notes [][]any
	for i, name := range []string{"wc-admin-new-sales-record", "wc-admin-onboarding-email-marketing", "wc-admin-mobile-app",
		"wc-admin-store-notice-giving-feedback", "wc-admin-insight-first-sale", "wc-admin-launch-checklist"} {
		notes = append(notes, []any{name, "info", "en_US", "Note " + fmt.Sprint(i), "unactioned"})
	}
	f.insert("wp_wc_admin_notes", []string{"name", "type", "locale", "title", "status"}, notes)

	mapping := php(kv{"mapping_fields", kv{"billing_address_1", "billing_address_1", "billing_first_name", "billing_first_name",
		"billing_last_name", "billing_last_name", "billing_city", "{billing_city}", "billing_postcode", "{billing_postcode}"}})
	f.insert("wp_wt_iew_mapping_template", []string{"template_type", "item_type", "name", "data"}, [][]any{
		{"export", "user", "Customers", mapping}, {"import", "user", "Customers in", mapping},
	})

	var meta [][]any
	for uid := 2; uid <= 20; uid++ {
		meta = append(meta, []any{uid, "account_status", "approved"}, []any{uid, "_um_last_login", fmt.Sprint(1759000000 + g.intn(900000))},
			[]any{uid, "mobile_number", g.phone()})
	}
	f.insert("wp_um_metadata", []string{"user_id", "um_key", "um_value"}, meta)
}

func (f *filler) wordpressTerms() {
	var terms, taxonomy, rels [][]any
	for id := 1; id <= 12; id++ {
		tax := "product_cat"
		if id > 8 {
			tax = "category"
		}
		terms = append(terms, []any{id, fmt.Sprintf("Term %d", id), fmt.Sprintf("term-%d", id), 0})
		taxonomy = append(taxonomy, []any{id, id, tax, "", 0, 0})
	}
	for id := 41; id <= 80; id++ {
		rels = append(rels, []any{id, 1 + id%8, 0})
	}
	for id := 1; id <= 30; id++ {
		rels = append(rels, []any{id, 9 + id%4, 0})
	}
	f.insert("wp_terms", []string{"term_id", "name", "slug", "term_group"}, terms)
	f.insert("wp_term_taxonomy", []string{"term_taxonomy_id", "term_id", "taxonomy", "description", "parent", "count"}, taxonomy)
	f.insert("wp_term_relationships", []string{"object_id", "term_taxonomy_id", "term_order"}, rels)
}

func (f *filler) woocommerceOrders(people []person) {
	g := f.g
	nUsers := len(people) - 1
	var orders, addresses, meta, ops, items, itemmeta [][]any
	itemID := 0
	for n := 0; n < 400; n++ {
		id := 5001 + n
		uid := 0
		p := g.person(3000 + n)
		if g.chance(0.6) {
			uid = 2 + g.intn(nUsers-1)
			p = people[uid]
		}
		note := ""
		switch {
		case n == 17 || n == 233:
			note = "Please charge my other card " + g.cardNumber() + " instead, thanks"
		case n%9 == 0:
			note = "Leave it with the neighbour if nobody answers, or call " + p.phone
		case n%5 == 0:
			note = g.sentence(8)
		}
		if n == 50 {
			note = "Gift for " + f.canary + ", please wrap it"
		}
		created := ts(g.date(2023, 2025))
		method, title := "stripe", "Credit card"
		if g.chance(0.2) {
			method, title = "cod", "Cash on delivery"
		}
		orders = append(orders, []any{id, "wc-completed", "EUR", "shop_order", "3.80", fmt.Sprintf("%d.90", 15+g.intn(200)),
			uid, p.email, created, created, nil, method, title, "ch_" + g.alnum(24), p.ip, p.agent, note})
		for _, typ := range []string{"billing", "shipping"} {
			addresses = append(addresses, []any{id, typ, p.first, p.last, p.company, p.street, "", p.city, p.region, p.postcode, p.country, p.email, p.phone})
		}
		index := strings.Join([]string{p.first, p.last, p.street, p.city, p.postcode, p.country, p.email, p.phone}, " ")
		for _, m := range [][2]string{
			{"_billing_address_index", index}, {"_shipping_address_index", index}, {"is_vat_exempt", "no"},
			{"_stripe_customer_id", "cus_" + g.alnum(14)}, {"_wc_order_attribution_user_agent", p.agent},
			{"_wc_order_attribution_source_type", g.pick([]string{"typein", "organic", "referral"})},
		} {
			meta = append(meta, []any{id, m[0], m[1]})
		}
		ops = append(ops, []any{id, "checkout", "9.3.3", 1, g.hex(32), 1, "wc_order_" + g.alnum(13), created})
		for k := 0; k < 1+g.intn(3); k++ {
			itemID++
			items = append(items, []any{itemID, fmt.Sprintf("Product %d", 41+g.intn(40)), "line_item", id})
			itemmeta = append(itemmeta, []any{itemID, "_product_id", fmt.Sprint(41 + g.intn(40))},
				[]any{itemID, "_qty", fmt.Sprint(1 + g.intn(3))}, []any{itemID, "_line_total", fmt.Sprintf("%d.90", 9+g.intn(80))})
			if itemID%20 == 0 {
				itemmeta = append(itemmeta, []any{itemID, "Gift message", "Happy birthday " + g.pick(firstNames) + "! Love, " + g.pick(firstNames)})
			}
		}
	}
	f.insert("wp_wc_orders", []string{"id", "status", "currency", "type", "tax_amount", "total_amount", "customer_id",
		"billing_email", "date_created_gmt", "date_updated_gmt", "parent_order_id", "payment_method", "payment_method_title",
		"transaction_id", "ip_address", "user_agent", "customer_note"}, orders)
	f.insert("wp_wc_order_addresses", []string{"order_id", "address_type", "first_name", "last_name", "company",
		"address_1", "address_2", "city", "state", "postcode", "country", "email", "phone"}, addresses)
	f.insert("wp_wc_orders_meta", []string{"order_id", "meta_key", "meta_value"}, meta)
	f.insert("wp_wc_order_operational_data", []string{"order_id", "created_via", "woocommerce_version",
		"prices_include_tax", "cart_hash", "new_order_email_sent", "order_key", "date_paid_gmt"}, ops)
	f.insert("wp_woocommerce_order_items", []string{"order_item_id", "order_item_name", "order_item_type", "order_id"}, items)
	f.insert("wp_woocommerce_order_itemmeta", []string{"order_item_id", "meta_key", "meta_value"}, itemmeta)

	var lookup [][]any
	for uid := 2; uid <= nUsers; uid++ {
		p := people[uid]
		lookup = append(lookup, []any{uid, fmt.Sprintf("customer%d", uid), p.first, p.last, p.email, p.country, p.postcode, p.city, p.region})
	}
	f.insert("wp_wc_customer_lookup", []string{"user_id", "username", "first_name", "last_name", "email",
		"country", "postcode", "city", "state"}, lookup)
}

func (f *filler) woocommerceRest(people []person) {
	g := f.g
	nUsers := len(people) - 1

	var sessions [][]any
	for i := 0; i < 25; i++ {
		p := people[2+g.intn(nUsers-1)]
		key := fmt.Sprint(2 + i)
		if i%2 == 0 {
			key = "t_" + g.hex(30)
		}
		customer := php(kv{"id", key, "first_name", p.first, "last_name", p.last, "email", p.email, "phone", p.phone,
			"address_1", p.street, "city", p.city, "postcode", p.postcode, "country", p.country})
		if i == 3 {
			customer = php(kv{"id", key, "email", f.canary + "@fixture-mail.gr"})
		}
		value := php(kv{"cart", php(kv{g.hex(32), kv{"product_id", 41 + g.intn(40), "quantity", 1}}),
			"customer", customer, "chosen_shipping_methods", php([]any{"flat_rate:1"})})
		sessions = append(sessions, []any{key, value, 1760000000 + g.intn(900000)})
	}
	f.insert("wp_woocommerce_sessions", []string{"session_key", "session_value", "session_expiry"}, sessions)

	var keys [][]any
	for i := 0; i < 2; i++ {
		ck := "ck_" + g.hex(40)
		keys = append(keys, []any{1, "ERP sync", "read_write", sha256hex(ck), "cs_" + g.hex(40), ck[len(ck)-7:]})
	}
	f.insert("wp_woocommerce_api_keys", []string{"user_id", "description", "permissions", "consumer_key",
		"consumer_secret", "truncated_key"}, keys)

	var tokens, tokenmeta [][]any
	for id := 1; id <= 20; id++ {
		tokens = append(tokens, []any{id, "stripe", "pm_" + g.alnum(24), 2 + g.intn(nUsers-1), "CC", id % 2})
		for _, m := range [][2]string{{"last4", fmt.Sprintf("%04d", g.intn(10000))}, {"expiry_year", "2028"},
			{"expiry_month", fmt.Sprintf("%02d", 1+g.intn(12))}, {"card_type", "visa"}} {
			tokenmeta = append(tokenmeta, []any{id, m[0], m[1]})
		}
	}
	f.insert("wp_woocommerce_payment_tokens", []string{"token_id", "gateway_id", "token", "user_id", "type", "is_default"}, tokens)
	f.insert("wp_woocommerce_payment_tokenmeta", []string{"payment_token_id", "meta_key", "meta_value"}, tokenmeta)

	f.insert("wp_wc_webhooks", []string{"status", "name", "user_id", "delivery_url", "secret", "topic", "api_version"}, [][]any{
		{"active", "Order created to ERP", 1, "https://erp.fixture-partner.example/hooks/orders", g.alnum(40), "order.created", 3},
		{"active", "Customer created to CRM", 1, "https://crm.fixture-partner.example/hooks/customers", g.alnum(40), "customer.created", 3},
		{"paused", "Old integration", 1, "https://old.fixture-partner.example/hook", g.alnum(40), "order.updated", 3},
	})

	f.insert("wp_actionscheduler_groups", []string{"group_id", "slug"}, [][]any{
		{1, "woocommerce-db-updates"}, {2, "wc-admin-data"}, {3, "wcs-renewals"},
	})
	var actions, logs [][]any
	for id := 1; id <= 220; id++ {
		hook, status, group, args := "woocommerce_cleanup_draft_orders", "complete", 1, "[]"
		switch {
		case id > 214:
			hook, status, group, args = "woocommerce_scheduled_subscription_payment", "pending", 3, fmt.Sprintf(`{"subscription_id":%d}`, 9000+id)
		case id > 200:
			hook, status, group = "wc-admin_import_orders", "pending", 2
			args = fmt.Sprintf("[%d]", 5001+g.intn(400))
		case id > 180:
			status = "pending"
		case id%2 == 0:
			hook, group = "wc-admin_import_orders", 2
		}
		actions = append(actions, []any{id, hook, status, ts(g.date(2025, 2026)), args, php(nil), group, 0})
		logs = append(logs, []any{id, "action created"}, []any{id, "action complete via WP Cron"})
	}
	logs = append(logs, []any{12, "Webhook delivery failed for " + people[3].email + ": timeout"})
	f.insert("wp_actionscheduler_actions", []string{"action_id", "hook", "status", "scheduled_date_gmt", "args",
		"schedule", "group_id", "attempts"}, actions)
	f.insert("wp_actionscheduler_logs", []string{"action_id", "message"}, logs)
}
