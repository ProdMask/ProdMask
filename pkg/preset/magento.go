package preset

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

const mg = "magento2"

// magento handles Magento 2 and Adobe Commerce, with or without a table
// prefix.
func (e *env) magento() bool {
	prefix, found := "", false
	for _, t := range e.schema.Tables {
		if !strings.HasSuffix(t.Name, "core_config_data") || t.Column("path") == nil || t.Column("value") == nil {
			continue
		}
		p := strings.TrimSuffix(t.Name, "core_config_data")
		if e.has(p+"eav_attribute") && (e.has(p+"sales_order") || e.has(p+"customer_entity")) {
			prefix, found = p, true
			break
		}
	}
	if !found {
		return false
	}
	p := prefix
	if p != "" {
		e.res.Prefixes = append(e.res.Prefixes, p)
	}
	pl := model.Platform{Name: mg, Label: "Magento 2", Prefix: p}
	if e.has(p+"store", "store_id") {
		if n, err := e.count("SELECT COUNT(*) FROM " + sample.QuoteIdent(p+"store") + " WHERE store_id > 0"); err == nil {
			pl.Details = append(pl.Details, fmt.Sprintf("%d store views", n))
		}
	}
	e.res.Platforms = append(e.res.Platforms, pl)

	e.column(p+"customer_grid_flat", "billing_full", hint(mg, model.CatAddress, "full billing address"))
	e.column(p+"customer_grid_flat", "shipping_full", hint(mg, model.CatAddress, "full shipping address"))
	e.column(p+"customer_entity", "confirmation", &detect.Hint{Category: model.CatSecret, Severity: model.SeverityLow,
		Source: "preset:" + mg, Note: "email confirmation key"})
	e.column(p+"sales_order", "protect_code", &detect.Hint{Category: model.CatSecret, Severity: model.SeverityMedium,
		Source: "preset:" + mg, Note: "lets guests look up the order"})
	for _, t := range []string{"sales_order_payment", "quote_payment"} {
		e.column(p+t, "cc_number_enc", &detect.Hint{Category: model.CatCardNumber, Severity: model.SeverityHigh,
			Source: "preset:" + mg, Note: "encrypted with the store's crypt key; anyone with app/etc/env.php can decrypt it"})
		e.column(p+t, "echeck_account_name", hint(mg, model.CatPersonName, "bank account holder"))
	}
	e.column(p+"newsletter_subscriber", "subscriber_confirm_code", &detect.Hint{Category: model.CatSecret,
		Severity: model.SeverityLow, Source: "preset:" + mg, Note: "newsletter confirmation code"})
	e.column(p+"review_detail", "detail", hint(mg, model.CatFreeText, "review text"))
	e.column(p+"oauth_token", "verifier", hint(mg, model.CatSecret, ""))
	e.column(p+"vault_payment_token", "gateway_token", hint(mg, model.CatPaymentToken, "saved card at the payment gateway"))

	e.meta(p+"core_config_data", &MetaTable{Key: "path", Value: "value", Platform: mg, HintFor: magentoConfigHint})
	labels := e.eavLabels(p)
	for _, entity := range []string{"customer_entity", "customer_address_entity"} {
		for _, typ := range []string{"varchar", "int", "text", "datetime", "decimal"} {
			e.meta(p+entity+"_"+typ, &MetaTable{Key: "attribute_id", Value: "value", Platform: mg, Label: labels})
		}
	}

	for t, why := range map[string]string{
		"customer_visitor":              "visitor sessions",
		"persistent_session":            "'remember me' sessions",
		"session":                       "PHP sessions stored in the database",
		"admin_user_session":            "admin sessions",
		"oauth_token":                   "integration access tokens",
		"oauth_nonce":                   "OAuth nonces",
		"password_reset_request_event":  "password reset requests",
		"login_as_customer":             "login-as-customer secrets",
		"report_event":                  "customer browsing events",
		"report_viewed_product_index":   "products customers viewed",
		"report_compared_product_index": "products customers compared",
		"search_query":                  "search terms typed by visitors",
		"cron_schedule":                 "pending cron jobs would run on staging",
		"queue_message":                 "queued messages would be processed on staging",
		"queue_message_status":          "queued messages would be processed on staging",
	} {
		e.action(p+t, "truncate", why)
	}

	customers := p + "customer_entity"
	e.rel(mg, p+"sales_order", "customer_id", customers, "entity_id")
	e.rel(mg, p+"sales_order", "quote_id", p+"quote", "entity_id")
	e.rel(mg, p+"sales_order_grid", "customer_id", customers, "entity_id")
	e.rel(mg, p+"sales_order_address", "customer_id", customers, "entity_id")
	e.rel(mg, p+"sales_order_address", "customer_address_id", p+"customer_address_entity", "entity_id")
	e.rel(mg, p+"quote", "customer_id", customers, "entity_id")
	e.rel(mg, p+"newsletter_subscriber", "customer_id", customers, "entity_id")
	e.rel(mg, p+"review_detail", "customer_id", customers, "entity_id")
	e.rel(mg, p+"vault_payment_token", "customer_id", customers, "entity_id")
	e.rel(mg, p+"customer_grid_flat", "entity_id", customers, "entity_id")

	e.magentoPayments(p)
	e.magentoEmail(p)
	e.magentoCron(p)
	return true
}

var reMagentoSecretPath = regexp.MustCompile(`(?i)(?:^|[/_])(?:api_?key|apikey|api_?secret|secret|secret_?key|private_?key|` +
	`password|passwd|access_?token|token|merchant_?key|signature|client_?secret|webhook_?secret|license_?key|encryption_?key)$`)

func magentoConfigHint(path string) *detect.Hint {
	if reMagentoSecretPath.MatchString(path) {
		return &detect.Hint{Category: model.CatSecret, Source: "preset:" + mg,
			Note: "Magento encrypts most stored credentials with the crypt key in app/etc/env.php, which a copy usually shares"}
	}
	return nil
}

// eavLabels maps customer and address attribute IDs to attribute codes, so
// the value tables can be judged by name like ordinary columns.
func (e *env) eavLabels(p string) func(string) string {
	labels := map[string]string{}
	attrs, types := p+"eav_attribute", p+"eav_entity_type"
	if e.has(attrs, "attribute_id", "attribute_code", "entity_type_id") && e.has(types, "entity_type_id", "entity_type_code") {
		rows, err := e.rows("SELECT a.attribute_id, a.attribute_code FROM " + sample.QuoteIdent(attrs) + " a JOIN " +
			sample.QuoteIdent(types) + " t ON t.entity_type_id = a.entity_type_id " +
			"WHERE t.entity_type_code IN ('customer', 'customer_address')")
		if err != nil {
			e.warn(fmt.Sprintf("could not read Magento attribute codes: %v", err))
		}
		for _, r := range rows {
			labels[r[0]] = Safe(r[1])
		}
	}
	return func(id string) string {
		if l, ok := labels[id]; ok {
			return l
		}
		return "attribute_" + Safe(id)
	}
}

func (e *env) magentoPayments(p string) {
	cfg := p + "core_config_data"
	rows, err := e.rows("SELECT path, value FROM " + sample.QuoteIdent(cfg) + " WHERE path LIKE 'payment/%' LIMIT 5000")
	if err != nil {
		e.warn(fmt.Sprintf("could not read Magento payment settings: %v", err))
		return
	}
	methods := map[string]map[string]string{}
	for _, r := range rows {
		parts := strings.SplitN(r[0], "/", 3)
		if len(parts) != 3 {
			continue
		}
		if methods[parts[1]] == nil {
			methods[parts[1]] = map[string]string{}
		}
		// Any scope that turns a method on or to live mode counts.
		if old, ok := methods[parts[1]][parts[2]]; !ok || old == "0" || old == "" {
			methods[parts[1]][parts[2]] = r[1]
		}
	}
	names := make([]string, 0, len(methods))
	for m := range methods {
		names = append(names, m)
	}
	sort.Strings(names)
	for _, m := range names {
		kv := methods[m]
		if !yes(kv["active"]) {
			continue
		}
		if live, known := liveMode(kv); known && live {
			e.sideEffect(model.SideEffect{
				Platform: mg, Kind: "payments", Table: cfg, Item: "payment/" + Safe(m), Severity: model.SeverityHigh,
				Summary: fmt.Sprintf("Payment method %q is active in live mode", Safe(m)),
				Fix:     "Switch it to sandbox or test mode and replace the live credentials in the copy",
			})
		}
	}
}

func (e *env) magentoEmail(p string) {
	cfg := p + "core_config_data"
	opts, err := e.rows("SELECT value FROM "+sample.QuoteIdent(cfg)+" WHERE path = ? AND scope = 'default'", "system/smtp/disable")
	if err == nil && (len(opts) == 0 || !yes(opts[0][0])) {
		e.sideEffect(model.SideEffect{
			Platform: mg, Kind: "email", Table: cfg, Item: "system/smtp/disable", Severity: model.SeverityMedium,
			Summary: "Email sending is on (system/smtp/disable is not set)",
			Fix:     "Set system/smtp/disable to 1 in the copy, or route mail to a catcher such as Mailpit",
		})
	}
	orders := p + "sales_order"
	if e.has(orders, "send_email", "email_sent") {
		n, err := e.count("SELECT COUNT(*) FROM " + sample.QuoteIdent(orders) + " WHERE send_email = 1 AND email_sent IS NULL")
		if err != nil {
			e.warn(fmt.Sprintf("could not count queued order emails: %v", err))
		} else if n > 0 {
			e.sideEffect(model.SideEffect{
				Platform: mg, Kind: "email", Table: orders, Severity: model.SeverityHigh, Count: n,
				Summary: fmt.Sprintf("%d order emails are queued; with asynchronous sending, staging cron would send them to customers", n),
				Fix:     "Set send_email = 0 on unsent orders in the copy",
			})
		}
	}
}

func (e *env) magentoCron(p string) {
	t := p + "cron_schedule"
	if !e.has(t, "job_code", "status") {
		return
	}
	q := sample.QuoteIdent(t)
	total, err := e.count("SELECT COUNT(*) FROM " + q + " WHERE status = 'pending'")
	if err != nil || total == 0 {
		return
	}
	rows, _ := e.rows("SELECT job_code, COUNT(*) FROM " + q + " WHERE status = 'pending' GROUP BY job_code ORDER BY COUNT(*) DESC LIMIT 5")
	e.sideEffect(model.SideEffect{
		Platform: mg, Kind: "scheduled_jobs", Table: t, Severity: model.SeverityMedium, Count: total,
		Summary: fmt.Sprintf("%d pending cron jobs would run on staging (most common: %s)", total, topCounts(rows, 3)),
		Fix:     "Empty cron_schedule in the copy and keep cron off until the copy is checked",
	})
}
