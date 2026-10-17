package preset

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

const (
	wp = "wordpress"
	wc = "woocommerce"
)

// wooOrderTypes are the post types of orders stored as posts: orders,
// refunds, HPOS placeholders and WooCommerce Subscriptions subscriptions.
var wooOrderTypes = []string{"shop_order", "shop_order_refund", "shop_order_placehold", "shop_subscription"}

// postPasswordHint describes wp_posts.post_password: posts and pages keep
// their passwords, but orders stored as posts (by the legacy store, or in
// HPOS compatibility mode) keep their order key there. The rows rule comes
// with every WordPress site, because it matches nothing where there are no
// orders, and a site scanned without the WooCommerce preset may have them.
func postPasswordHint(sev model.Severity, platform, note string) *detect.Hint {
	return &detect.Hint{Category: model.CatSecret, Severity: sev, Mask: "keep", Source: "preset:" + platform, Note: note,
		Rows: []model.RowMask{{Where: "post_type IN ('" + strings.Join(wooOrderTypes, "', '") + "')", Mask: "null",
			Note: "WooCommerce order keys; anyone with one in a link can view the order"}}}
}

// wordpressPrefixes finds the table prefix of every WordPress site in the
// database: wp_ for a single site, wp_ plus wp_2_, wp_3_ ... for multisite.
func wordpressPrefixes(s *model.Schema) []string {
	var out []string
	for _, t := range s.Tables {
		if !strings.HasSuffix(t.Name, "options") || t.Column("option_name") == nil || t.Column("option_value") == nil {
			continue
		}
		p := strings.TrimSuffix(t.Name, "options")
		if s.Table(p+"posts") != nil && s.Table(p+"postmeta") != nil {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) < len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// wordpress handles WordPress and, when woo is set, WooCommerce. It reports
// whether each was found.
func (e *env) wordpress(woo bool) (bool, bool) {
	prefixes := wordpressPrefixes(e.schema)
	if len(prefixes) == 0 {
		return false, false
	}
	base := prefixes[0]
	for _, p := range prefixes {
		if e.has(p + "users") {
			base = p
			break
		}
	}
	e.res.Prefixes = append(e.res.Prefixes, prefixes...)

	baseOpts := e.siteOptions(base)
	pl := model.Platform{Name: wp, Label: "WordPress", Prefix: base}
	if v := baseOpts["db_version"]; v != "" {
		pl.Details = append(pl.Details, "db_version "+Safe(v))
	}
	if len(prefixes) > 1 {
		pl.Details = append(pl.Details, fmt.Sprintf("multisite, %d sites", len(prefixes)))
	}
	e.res.Platforms = append(e.res.Platforms, pl)

	e.wordpressUsers(base)
	foundWoo := false
	for _, p := range prefixes {
		opts := baseOpts
		if p != base {
			opts = e.siteOptions(p)
		}
		e.wordpressSite(p, base)
		if woo && (e.has(p+"woocommerce_order_items") || e.has(p+"wc_orders") || opts["woocommerce_version"] != "") {
			e.woocommerce(p, base, opts)
			foundWoo = true
		}
	}
	return true, foundWoo
}

func (e *env) siteOptions(p string) map[string]string {
	return e.options(p+"options", "option_name", "option_value", []string{
		"db_version", "woocommerce_version", "woocommerce_custom_orders_table_enabled",
	})
}

func metaHint(platform string, cat model.Category, note string) *detect.Hint {
	return &detect.Hint{Category: cat, Note: note, Source: "preset:" + platform}
}

func (e *env) wordpressUsers(b string) {
	users, usermeta := b+"users", b+"usermeta"
	e.column(users, "user_activation_key", hint(wp, model.CatSecret, "password reset key"))
	e.meta(usermeta, &MetaTable{
		Key: "meta_key", Value: "meta_value", Platform: wp,
		Keys: map[string]*detect.Hint{
			"session_tokens": {Category: model.CatSecret, Mask: "delete", Source: "preset:" + wp,
				Note: "login sessions, with IP addresses and user agents"},
			"community-events-location": metaHint(wp, model.CatGeo, "IP address and city saved by the dashboard events widget"),
			"description":               metaHint(wp, model.CatFreeText, "user biography"),
			"_application_passwords":    metaHint(wp, model.CatPasswordHash, "application password hashes"),
		},
		Probe: []string{"first_name", "last_name", "nickname", "description", "session_tokens",
			"billing_email", "billing_phone", "billing_address_1", "shipping_address_1"},
	})
	e.rel(wp, usermeta, "user_id", users, "ID")
}

func (e *env) wordpressSite(p, b string) {
	users := b + "users"
	posts, postmeta, comments, commentmeta := p+"posts", p+"postmeta", p+"comments", p+"commentmeta"
	options := p + "options"

	e.column(posts, "post_password", postPasswordHint(model.SeverityLow, wp, "WordPress stores post passwords in plain text"))
	e.column(comments, "comment_agent", hint(wp, model.CatUserAgent, ""))

	e.meta(postmeta, &MetaTable{
		Key: "meta_key", Value: "meta_value", Platform: wp,
		Keys: map[string]*detect.Hint{
			"_order_key": {Category: model.CatSecret, Severity: model.SeverityMedium, Source: "preset:" + wc,
				Note: "anyone with this key in a link can view the order"},
		},
	})
	e.meta(commentmeta, &MetaTable{Key: "meta_key", Value: "meta_value", Platform: wp})

	salt := &detect.Hint{Category: model.CatSecret, Source: "preset:" + wp,
		Note: "authentication key or salt; a copy that keeps it trusts production login cookies"}
	optionKeys := map[string]*detect.Hint{
		"admin_email":      metaHint(wp, model.CatEmail, "site administrator"),
		"new_admin_email":  metaHint(wp, model.CatEmail, "site administrator"),
		"mailserver_login": metaHint(wp, model.CatEmail, "post-by-email mailbox"),
		"mailserver_pass":  metaHint(wp, model.CatSecret, "post-by-email mailbox password"),
		"recovery_keys":    metaHint(wp, model.CatSecret, "recovery mode keys"),
	}
	for _, k := range []string{"auth_key", "auth_salt", "secure_auth_key", "secure_auth_salt",
		"logged_in_key", "logged_in_salt", "nonce_key", "nonce_salt"} {
		optionKeys[k] = salt
	}
	e.meta(options, &MetaTable{
		Key: "option_name", Value: "option_value", Platform: wp, Keys: optionKeys,
		Probe: []string{"admin_email", "mailserver_pass", "auth_salt", "logged_in_salt"},
	})

	e.rel(wp, postmeta, "post_id", posts, "ID")
	e.rel(wp, posts, "post_author", users, "ID")
	e.rel(wp, posts, "post_parent", posts, "ID")
	e.rel(wp, comments, "comment_post_ID", posts, "ID")
	e.rel(wp, comments, "user_id", users, "ID")
	e.rel(wp, comments, "comment_parent", comments, "comment_ID")
	e.rel(wp, commentmeta, "comment_id", comments, "comment_ID")
	e.rel(wp, p+"term_relationships", "object_id", posts, "ID")
	e.rel(wp, p+"term_relationships", "term_taxonomy_id", p+"term_taxonomy", "term_taxonomy_id")
	e.rel(wp, p+"term_taxonomy", "term_id", p+"terms", "term_id")
	e.rel(wp, p+"termmeta", "term_id", p+"terms", "term_id")
	e.rel(wp, p+"links", "link_owner", users, "ID")

	e.wordpressMail(p)
}

// Mail plugins whose settings mean the site sends email through a service.
var mailPlugins = []struct{ option, label string }{
	{"wp_mail_smtp", "WP Mail SMTP"},
	{"postman_options", "Post SMTP"},
	{"fluentmail-settings", "FluentSMTP"},
	{"swpsmtp_options", "Easy WP SMTP"},
	{"easy_wp_smtp", "Easy WP SMTP"},
	{"mailgun", "Mailgun for WordPress"},
	{"sendgrid_api_key", "SendGrid"},
}

func (e *env) wordpressMail(p string) {
	keys := make([]string, len(mailPlugins))
	for i, m := range mailPlugins {
		keys[i] = m.option
	}
	opts := e.options(p+"options", "option_name", "option_value", keys)
	for _, m := range mailPlugins {
		raw, ok := opts[m.option]
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		detail := ""
		if mailer := detect.Flatten(raw)["mail.mailer"]; mailer != "" {
			detail = " (mailer: " + Safe(mailer) + ")"
		}
		e.sideEffect(model.SideEffect{
			Platform: wp, Kind: "email", Table: p + "options", Item: m.option, Severity: model.SeverityHigh,
			Summary: "Outgoing email is sent through " + m.label + detail,
			Fix:     "Point the mailer at a mail catcher such as Mailpit, or turn it off, in the copy",
		})
		if meta := e.res.Meta[p+"options"]; meta != nil {
			meta.Probe = append(meta.Probe, m.option)
		}
	}
}

func (e *env) woocommerce(p, b string, opts map[string]string) {
	users := b + "users"
	pl := model.Platform{Name: wc, Label: "WooCommerce", Prefix: p}
	if v := opts["woocommerce_version"]; v != "" {
		pl.Version = Safe(v)
	}
	hpos := opts["woocommerce_custom_orders_table_enabled"] == "yes" && e.has(p+"wc_orders")
	switch {
	case hpos:
		pl.Details = append(pl.Details, "orders in HPOS tables")
	case e.has(p + "wc_orders"):
		pl.Details = append(pl.Details, "orders stored as posts (HPOS tables exist but are not in use)")
	default:
		pl.Details = append(pl.Details, "orders stored as posts")
	}
	e.res.Platforms = append(e.res.Platforms, pl)

	orderKey := &detect.Hint{Category: model.CatSecret, Severity: model.SeverityMedium, Source: "preset:" + wc,
		Note: "anyone with this key in a link can view the order"}
	// On a shop the column holds order keys, as sensitive as _order_key.
	e.column(p+"posts", "post_password", postPasswordHint(model.SeverityMedium, wc,
		"WordPress post passwords in plain text, and the key of each order stored as a post"))
	e.column(p+"wc_order_addresses", "state", hint(wc, model.CatRegion, ""))
	e.column(p+"wc_customer_lookup", "state", hint(wc, model.CatRegion, ""))
	e.column(p+"wc_order_operational_data", "order_key", orderKey)
	e.column(p+"woocommerce_downloadable_product_permissions", "order_key", orderKey)
	e.column(p+"woocommerce_sessions", "session_value", hint(wc, model.CatSessionData, "carts and checkout details of visitors"))
	e.column(p+"woocommerce_api_keys", "consumer_key", hint(wc, model.CatSecret, "hashed REST API key"))
	e.column(p+"woocommerce_api_keys", "consumer_secret", hint(wc, model.CatSecret, "REST API secret"))
	e.column(p+"woocommerce_api_keys", "truncated_key", &detect.Hint{Ignore: true})
	e.column(p+"woocommerce_payment_tokens", "token", hint(wc, model.CatPaymentToken, "saved payment method at the gateway"))

	addressIndex := &detect.Hint{Category: model.CatAddress, Mask: "null", Source: "preset:" + wc,
		Note: "search index of the full address, email and phone; WooCommerce rebuilds it"}
	orderMeta := map[string]*detect.Hint{"_order_key": orderKey,
		"_billing_address_index": addressIndex, "_shipping_address_index": addressIndex}
	if meta := e.res.Meta[p+"postmeta"]; meta != nil {
		for k, h := range orderMeta {
			meta.Keys[k] = h
		}
	}
	orderProbe := []string{"_billing_email", "_billing_phone", "_billing_first_name", "_billing_last_name",
		"_billing_address_1", "_billing_postcode", "_shipping_address_1", "_customer_ip_address",
		"_customer_user_agent", "_billing_address_index", "_shipping_address_index", "_stripe_customer_id"}
	if meta := e.res.Meta[p+"postmeta"]; meta != nil && !hpos {
		meta.Probe = append(meta.Probe, orderProbe...)
	}
	e.meta(p+"wc_orders_meta", &MetaTable{Key: "meta_key", Value: "meta_value", Platform: wc, Keys: orderMeta,
		Probe: []string{"_billing_address_index", "_shipping_address_index", "_stripe_customer_id"}})
	e.meta(p+"woocommerce_order_itemmeta", &MetaTable{Key: "meta_key", Value: "meta_value", Platform: wc})
	cardMeta := metaHint(wc, model.CatCardMeta, "")
	e.meta(p+"woocommerce_payment_tokenmeta", &MetaTable{Key: "meta_key", Value: "meta_value", Platform: wc,
		Keys: map[string]*detect.Hint{"last4": cardMeta, "expiry_year": cardMeta, "expiry_month": cardMeta, "card_type": cardMeta}})

	e.action(p+"woocommerce_sessions", "truncate", "carts and checkout details of live visitors")
	e.action(p+"woocommerce_api_keys", "truncate", "REST API credentials of the live store")
	e.action(p+"woocommerce_log", "truncate", "log messages often quote customer data")
	e.action(p+"actionscheduler_logs", "truncate", "background job logs")

	orders, ordersPK := p+"posts", "ID"
	if hpos {
		orders, ordersPK = p+"wc_orders", "id"
	}
	e.rel(wc, p+"wc_orders", "customer_id", users, "ID")
	e.rel(wc, p+"wc_orders", "parent_order_id", p+"wc_orders", "id")
	e.rel(wc, p+"wc_order_addresses", "order_id", p+"wc_orders", "id")
	e.rel(wc, p+"wc_orders_meta", "order_id", p+"wc_orders", "id")
	e.rel(wc, p+"wc_order_operational_data", "order_id", p+"wc_orders", "id")
	e.rel(wc, p+"woocommerce_order_items", "order_id", orders, ordersPK)
	e.rel(wc, p+"woocommerce_order_itemmeta", "order_item_id", p+"woocommerce_order_items", "order_item_id")
	e.rel(wc, p+"wc_customer_lookup", "user_id", users, "ID")
	e.rel(wc, p+"wc_order_stats", "order_id", orders, ordersPK)
	e.rel(wc, p+"wc_order_stats", "customer_id", p+"wc_customer_lookup", "customer_id")
	e.rel(wc, p+"wc_order_product_lookup", "order_id", orders, ordersPK)
	e.rel(wc, p+"wc_order_product_lookup", "customer_id", p+"wc_customer_lookup", "customer_id")
	e.rel(wc, p+"woocommerce_payment_tokens", "user_id", users, "ID")
	e.rel(wc, p+"woocommerce_payment_tokenmeta", "payment_token_id", p+"woocommerce_payment_tokens", "token_id")
	e.rel(wc, p+"woocommerce_downloadable_product_permissions", "order_id", orders, ordersPK)
	e.rel(wc, p+"woocommerce_downloadable_product_permissions", "user_id", users, "ID")
	e.rel(wc, p+"woocommerce_api_keys", "user_id", users, "ID")
	e.rel(wc, p+"wc_webhooks", "user_id", users, "ID")
	e.rel(wc, p+"actionscheduler_actions", "group_id", p+"actionscheduler_groups", "group_id")
	e.rel(wc, p+"actionscheduler_logs", "action_id", p+"actionscheduler_actions", "action_id")

	e.wooGateways(p)
	e.wooWebhooks(p)
	e.actionScheduler(p)
}

func yes(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "1", "true", "on":
		return true
	}
	return false
}

func (e *env) wooGateways(p string) {
	opts := p + "options"
	if !e.has(opts, "option_name", "option_value") {
		return
	}
	rows, err := e.rows("SELECT option_name, LEFT(option_value, 65535) FROM "+sample.QuoteIdent(opts)+
		" WHERE option_name LIKE ? ESCAPE '!' OR option_name = 'woocommerce-ppcp-settings' LIMIT 300",
		"woocommerce!_%!_settings")
	if err != nil {
		e.warn(fmt.Sprintf("could not read WooCommerce payment settings: %v", err))
		return
	}
	for _, r := range rows {
		name, kv := r[0], detect.Flatten(r[1])
		live, known := liveMode(kv)
		if !known {
			continue
		}
		if v, ok := kv["enabled"]; ok && !yes(v) {
			continue
		}
		if meta := e.res.Meta[opts]; meta != nil {
			meta.Probe = append(meta.Probe, name) // so its keys get checked for secrets
		}
		if !live {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "woocommerce_"), "_settings")
		e.sideEffect(model.SideEffect{
			Platform: wc, Kind: "payments", Table: opts, Item: name, Severity: model.SeverityHigh,
			Summary: fmt.Sprintf("Payment gateway %q is enabled in live mode", Safe(id)),
			Fix:     "Switch the gateway to test or sandbox mode and remove the live keys in the copy",
		})
	}
}

func (e *env) wooWebhooks(p string) {
	t := p + "wc_webhooks"
	if !e.has(t, "status") {
		return
	}
	n, err := e.count("SELECT COUNT(*) FROM " + sample.QuoteIdent(t) + " WHERE status = 'active'")
	if err != nil {
		e.warn(fmt.Sprintf("could not count webhooks: %v", err))
		return
	}
	if n > 0 {
		e.sideEffect(model.SideEffect{
			Platform: wc, Kind: "webhooks", Table: t, Severity: model.SeverityHigh, Count: n,
			Summary: fmt.Sprintf("%d active webhooks would send order and customer data from staging to their delivery URLs", n),
			Fix:     "Set status to 'disabled' (or delete the rows) in the copy",
		})
	}
}

func (e *env) actionScheduler(p string) {
	t := p + "actionscheduler_actions"
	if !e.has(t, "hook", "status") {
		return
	}
	q := sample.QuoteIdent(t)
	total, err := e.count("SELECT COUNT(*) FROM " + q + " WHERE status = 'pending'")
	if err != nil {
		e.warn(fmt.Sprintf("could not count scheduled actions: %v", err))
		return
	}
	if total == 0 {
		return
	}
	rows, err := e.rows("SELECT hook, COUNT(*) FROM " + q + " WHERE status = 'pending' GROUP BY hook ORDER BY COUNT(*) DESC LIMIT 10")
	if err != nil {
		e.warn(fmt.Sprintf("could not group scheduled actions: %v", err))
	}
	for _, r := range rows {
		if strings.Contains(r[0], "scheduled_subscription_payment") {
			e.sideEffect(model.SideEffect{
				Platform: wc, Kind: "payments", Table: t, Item: Safe(r[0]), Severity: model.SeverityCritical,
				Count:   parseCount(r[1]),
				Summary: fmt.Sprintf("%s subscription renewal payments are scheduled; staging would try to charge customers when they fall due", r[1]),
				Fix:     "Cancel these actions in the copy, or make sure WooCommerce Subscriptions starts in staging mode",
			})
		}
	}
	e.sideEffect(model.SideEffect{
		Platform: wc, Kind: "scheduled_jobs", Table: t, Severity: model.SeverityMedium, Count: total,
		Summary: fmt.Sprintf("%d pending scheduled actions would run on staging (most common: %s)", total, topCounts(rows, 3)),
		Fix:     "Cancel pending actions in the copy, or turn off WP-Cron and Action Scheduler there",
	})
}

func parseCount(s string) int64 {
	var n int64
	fmt.Sscan(s, &n)
	return n
}
