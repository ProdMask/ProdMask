package fixture

import (
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
	for id := 1; id <= nUsers; id++ {
		p := g.person(id)
		if id == 7 {
			p.email = f.canary + "@fixture-mail.gr"
		}
		people[id] = p
		login := fmt.Sprintf("%s.%s%d", strings.ToLower(p.first), strings.ToLower(p.last[:1]), id)
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
		users = append(users, []any{id, login, pass, login, p.email, url, ts(g.date(2019, 2025)), activation, 0, p.first + " " + p.last})

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

	f.wordpressOptions(people[1])
	f.wordpressTerms()
	f.woocommerceOrders(people)
	f.woocommerceRest(people)
}

func (f *filler) wordpressOptions(admin person) {
	g := f.g
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
		{"woocommerce_paypal_settings", php(kv{"enabled", "no", "testmode", "no", "email", admin.email}), "yes"},
		{"wp_mail_smtp", php(kv{"mail", kv{"from_email", "shop@fixture-store.gr", "from_name", "Fixture Store", "mailer", "sendgrid"},
			"sendgrid", kv{"api_key", g.sendgridKey(), "domain", ""}}), "yes"},
		{"as3cf_settings", php(kv{"provider", "aws", "access-key-id", g.awsKeyID(), "bucket", "fixture-media"}), "yes"},
		{"active_plugins", php([]any{"woocommerce/woocommerce.php", "wp-mail-smtp/wp_mail_smtp.php",
			"woocommerce-gateway-stripe/woocommerce-gateway-stripe.php"}), "yes"},
		{"cron", php(kv{1760000000, kv{"wp_version_check", kv{g.hex(32), kv{"schedule", "twicedaily", "args", []any{}}}}, "version", 2}), "yes"},
	}
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
