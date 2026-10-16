package fixture

import (
	"fmt"
	"strings"
)

// magento fills a Magento 2 store: customers with addresses and custom EAV
// attributes, guest and customer orders, payments, newsletter subscribers,
// admins, saved cards, and settings with a live payment method and email on.
func (f *filler) magento() {
	g := f.g
	f.insert("store", []string{"store_id", "code", "website_id", "group_id", "name", "is_active"}, [][]any{
		{0, "admin", 0, 0, "Admin", 1}, {1, "default", 1, 1, "Default Store View", 1}, {2, "el", 1, 1, "Greek", 1},
	})

	cfg := [][]any{
		{"default", 0, "web/unsecure/base_url", "https://fixture-store.test/"},
		{"default", 0, "general/store_information/name", "Fixture Store"},
		{"default", 0, "trans_email/ident_general/email", "hello@fixture-store.gr"},
		{"default", 0, "trans_email/ident_sales/email", "sales@fixture-store.gr"},
		{"default", 0, "sales_email/order/copy_to", "orders@fixture-store.gr"},
		{"default", 0, "sales_email/general/async_sending", "1"},
		{"default", 0, "system/smtp/disable", "0"},
		{"default", 0, "payment/braintree/active", "1"},
		{"default", 0, "payment/braintree/environment", "production"},
		{"default", 0, "payment/braintree/merchant_id", g.alnum(16)},
		{"default", 0, "payment/braintree/public_key", g.magentoEncrypted()},
		{"default", 0, "payment/braintree/private_key", g.magentoEncrypted()},
		{"default", 0, "payment/checkmo/active", "1"},
		{"default", 0, "payment/paypal_express/active", "0"},
		{"default", 0, "payment/paypal_express/sandbox_flag", "0"},
		{"default", 0, "carriers/ups/password", g.magentoEncrypted()},
		{"default", 0, "carriers/ups/username", g.magentoEncrypted()},
	}
	for i := 0; i < 60; i++ {
		cfg = append(cfg, []any{"default", 0, fmt.Sprintf("catalog/fixture/setting_%02d", i), fmt.Sprint(g.intn(2))})
	}
	f.insert("core_config_data", []string{"scope", "scope_id", "path", "value"}, cfg)

	f.insert("eav_entity_type", []string{"entity_type_id", "entity_type_code", "entity_table"}, [][]any{
		{1, "customer", "customer_entity"}, {2, "customer_address", "customer_address_entity"}, {4, "catalog_product", "catalog_product_entity"},
	})
	f.insert("eav_attribute", []string{"attribute_id", "entity_type_id", "attribute_code", "backend_type", "frontend_input", "frontend_label"}, [][]any{
		{5, 1, "firstname", "static", "text", "First Name"}, {7, 1, "lastname", "static", "text", "Last Name"},
		{9, 1, "email", "static", "text", "Email"}, {11, 1, "dob", "static", "date", "Date of Birth"},
		{15, 1, "taxvat", "static", "text", "Tax/VAT number"}, {18, 1, "gender", "static", "select", "Gender"},
		{180, 1, "mobile_phone", "varchar", "text", "Mobile phone"}, {181, 1, "instagram", "varchar", "text", "Instagram"},
		{182, 1, "preferred_store", "varchar", "select", "Preferred store"},
		{26, 2, "city", "static", "text", "City"}, {73, 4, "name", "varchar", "text", "Product Name"},
	})

	const nCustomers = 150
	people := make([]person, nCustomers+1)
	var customers, varchars, addresses, grid [][]any
	addressID := 0
	for id := 1; id <= nCustomers; id++ {
		p := g.person(id)
		if id == 9 {
			p.email = f.canary + "@fixture-mail.gr"
		}
		people[id] = p
		addressID++
		var taxvat any
		if g.chance(0.4) {
			taxvat = fmt.Sprintf("EL%09d", g.intn(1000000000))
		}
		var rp any
		if g.chance(0.1) {
			rp = g.alnum(32)
		}
		dob := fmt.Sprintf("%d-%02d-%02d", 1950+g.intn(55), 1+g.intn(12), 1+g.intn(28))
		hash := g.hex(64) + ":" + g.alnum(32) + ":3_32_2_67108864"
		customers = append(customers, []any{id, 1, p.email, 1, 1, "Default Store View", p.first, p.last, dob, hash, rp,
			addressID, addressID, taxvat, 1 + g.intn(2)})
		varchars = append(varchars, []any{180, id, g.phone()})
		if g.chance(0.3) {
			varchars = append(varchars, []any{181, id, "https://instagram.com/" + strings.ToLower(p.first) + fmt.Sprint(id)})
		}
		varchars = append(varchars, []any{182, id, g.pick([]string{"athens", "thessaloniki", "online"})})
		var vat any
		if g.chance(0.2) {
			vat = fmt.Sprintf("EL%09d", g.intn(1000000000))
		}
		addresses = append(addresses, []any{addressID, id, p.city, p.company, p.country, nil, p.first, p.last,
			p.postcode, p.region, p.street, p.phone, vat})
		full := strings.Join([]string{p.street, p.city, p.region, p.postcode}, " ")
		grid = append(grid, []any{id, p.first + " " + p.last, p.email, dob, full, full, p.first, p.last, p.phone,
			p.postcode, p.country, p.city, p.street})
	}
	f.insert("customer_entity", []string{"entity_id", "website_id", "email", "group_id", "store_id", "created_in",
		"firstname", "lastname", "dob", "password_hash", "rp_token", "default_billing", "default_shipping", "taxvat", "gender"}, customers)
	f.insert("customer_entity_varchar", []string{"attribute_id", "entity_id", "value"}, varchars)
	f.insert("customer_address_entity", []string{"entity_id", "parent_id", "city", "company", "country_id", "fax",
		"firstname", "lastname", "postcode", "region", "street", "telephone", "vat_id"}, addresses)
	f.insert("customer_grid_flat", []string{"entity_id", "name", "email", "dob", "shipping_full", "billing_full",
		"billing_firstname", "billing_lastname", "billing_telephone", "billing_postcode", "billing_country_id",
		"billing_city", "billing_street"}, grid)

	var quotes, orders, orderAddresses, payments [][]any
	for id := 1; id <= 700; id++ {
		var cid any
		p := g.person(5000 + id)
		if g.chance(0.6) {
			c := 1 + g.intn(nCustomers)
			cid, p = c, people[c]
		}
		quotes = append(quotes, []any{id, 1, cid, p.email, p.first, p.last, p.ip, fmt.Sprintf("%d.00", 10+g.intn(300))})
		if id > 600 {
			continue // quotes that never became orders
		}
		note := any(nil)
		switch {
		case id%13 == 0:
			note = "Ring the bell twice. Mobile " + p.phone
		case id%7 == 0:
			note = g.sentence(6)
		}
		emailSent := any(1)
		if id > 593 {
			emailSent = nil // queued for asynchronous sending
		}
		xff := any(nil)
		if g.chance(0.3) {
			xff = p.ip + ", 10.0.0.12"
		}
		orders = append(orders, []any{id, "complete", "complete", g.hex(6), cid, id, fmt.Sprintf("0000%05d", id),
			fmt.Sprintf("%d.00", 10+g.intn(300)), p.email, p.first, p.last, p.ip, xff, note, 1, emailSent})
		for _, typ := range []string{"billing", "shipping"} {
			orderAddresses = append(orderAddresses, []any{id, cid, p.region, p.postcode, p.last, p.street, p.city,
				p.email, p.phone, p.country, p.first, typ, p.company})
		}
		method := "braintree"
		info := jsonString(map[string]any{"method_title": "Credit Card", "cc_type": "VI", "cc_last4": "1111",
			"payment_method_nonce": g.alnum(24)})
		var enc any
		if id <= 20 {
			method, enc = "ccsave", g.magentoEncrypted() // a legacy module that stored encrypted card numbers
		} else if g.chance(0.2) {
			method, info = "checkmo", jsonString(map[string]any{"method_title": "Check / Money order"})
		}
		payments = append(payments, []any{id, method, fmt.Sprint(1 + g.intn(12)), "2029", "1111",
			p.first + " " + p.last, "VI", enc, g.alnum(8), info})
	}
	f.insert("quote", []string{"entity_id", "store_id", "customer_id", "customer_email", "customer_firstname",
		"customer_lastname", "remote_ip", "grand_total"}, quotes)
	f.insert("sales_order", []string{"entity_id", "state", "status", "protect_code", "customer_id", "quote_id",
		"increment_id", "grand_total", "customer_email", "customer_firstname", "customer_lastname", "remote_ip",
		"x_forwarded_for", "customer_note", "send_email", "email_sent"}, orders)
	f.insert("sales_order_address", []string{"parent_id", "customer_id", "region", "postcode", "lastname", "street",
		"city", "email", "telephone", "country_id", "firstname", "address_type", "company"}, orderAddresses)
	f.insert("sales_order_payment", []string{"parent_id", "method", "cc_exp_month", "cc_exp_year", "cc_last_4",
		"cc_owner", "cc_type", "cc_number_enc", "last_trans_id", "additional_information"}, payments)

	var subscribers [][]any
	for id := 1; id <= 120; id++ {
		cid, email := 0, g.person(8000+id).email
		if id <= nCustomers && g.chance(0.5) {
			cid, email = id, people[id].email
		}
		subscribers = append(subscribers, []any{1, cid, email, 1, g.alnum(32)})
	}
	f.insert("newsletter_subscriber", []string{"store_id", "customer_id", "subscriber_email", "subscriber_status",
		"subscriber_confirm_code"}, subscribers)

	var admins [][]any
	for id := 1; id <= 4; id++ {
		p := g.person(9000 + id)
		admins = append(admins, []any{p.first, p.last, p.email, fmt.Sprintf("admin%d", id),
			g.hex(64) + ":" + g.alnum(32) + ":3_32_2_67108864", php(kv{"configState", kv{"general_country", "1"}}), nil})
	}
	f.insert("admin_user", []string{"firstname", "lastname", "email", "username", "password", "extra", "rp_token"}, admins)

	var visitors, tokens, cron [][]any
	for i := 0; i < 300; i++ {
		var cid any
		if g.chance(0.3) {
			cid = 1 + g.intn(nCustomers)
		}
		visitors = append(visitors, []any{cid})
	}
	for i := 0; i < 40; i++ {
		tokens = append(tokens, []any{1 + g.intn(nCustomers), g.hex(64), "braintree", "card", g.alnum(12),
			jsonString(map[string]any{"type": "VI", "maskedCC": fmt.Sprintf("%04d", g.intn(10000)), "expirationDate": "12/2028"})})
	}
	for i := 0; i < 250; i++ {
		status := "success"
		if i >= 200 {
			status = "pending"
		}
		cron = append(cron, []any{g.pick([]string{"indexer_reindex_all_invalid", "sales_send_order_emails", "newsletter_send_all"}), status})
	}
	f.insert("customer_visitor", []string{"customer_id"}, visitors)
	f.insert("vault_payment_token", []string{"customer_id", "public_hash", "payment_method_code", "type",
		"gateway_token", "details"}, tokens)
	f.insert("cron_schedule", []string{"job_code", "status"}, cron)
}
