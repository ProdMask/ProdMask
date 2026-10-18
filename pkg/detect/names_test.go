package detect

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

func TestTokens(t *testing.T) {
	cases := map[string][]string{
		"customerEmail":     {"customer", "email"},
		"billing_address_1": {"billing", "address", "1"},
		"IPAddress":         {"ip", "address"},
		"comment_author_IP": {"comment", "author", "ip"},
		"x-forwarded-for":   {"x", "forwarded", "for"},
		"cc_last4":          {"cc", "last", "4"},
		"firstname":         {"first", "name"},
		"user_pass":         {"user", "pass"},
		"ID":                {"id"},
		"post_ID":           {"post", "id"},
		"_billing_email":    {"billing", "email"},
		"HTTPUserAgent":     {"http", "user", "agent"},
	}
	for in, want := range cases {
		if got := Tokens(in); !reflect.DeepEqual(got, want) {
			t.Errorf("Tokens(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchName(t *testing.T) {
	cases := []struct {
		table, column, dataType string
		want                    model.Category
	}{
		// WordPress
		{"wp_users", "user_email", "varchar", model.CatEmail},
		{"wp_users", "user_pass", "varchar", model.CatPasswordHash},
		{"wp_users", "user_login", "varchar", model.CatUsername},
		{"wp_users", "user_nicename", "varchar", model.CatUsername},
		{"wp_users", "display_name", "varchar", model.CatPersonName},
		{"wp_users", "user_url", "varchar", model.CatWebsite},
		{"wp_users", "user_activation_key", "varchar", model.CatSecret},
		{"wp_users", "user_registered", "datetime", ""},
		{"wp_users", "user_status", "int", ""},
		{"wp_users", "ID", "bigint", ""},
		{"wp_comments", "comment_author", "tinytext", model.CatPersonName},
		{"wp_comments", "comment_author_email", "varchar", model.CatEmail},
		{"wp_comments", "comment_author_IP", "varchar", model.CatIPAddress},
		{"wp_comments", "comment_author_url", "varchar", model.CatWebsite},
		{"wp_comments", "comment_post_ID", "bigint", ""},
		{"wp_comments", "comment_count", "bigint", ""},
		{"wp_comments", "comment_content", "text", model.CatFreeText},
		{"wp_comments", "comment_approved", "varchar", ""},
		{"wp_comments", "comment_karma", "int", ""},
		{"wp_posts", "post_author", "bigint", ""},
		{"wp_posts", "post_title", "text", ""},
		// Meta keys are judged as text.
		{"wp_postmeta", "_billing_phone", "", model.CatPhone},
		{"wp_postmeta", "_billing_first_name", "", model.CatPersonName},
		{"wp_postmeta", "_customer_ip_address", "", model.CatIPAddress},
		{"wp_postmeta", "_customer_user_agent", "", model.CatUserAgent},
		{"wp_postmeta", "_billing_address_index", "", model.CatAddress},
		{"wp_postmeta", "_stripe_customer_id", "", model.CatPaymentToken},
		{"wp_postmeta", "_transaction_id", "", ""},
		{"wp_usermeta", "session_tokens", "", model.CatSecret},
		{"wp_usermeta", "billing_state", "", model.CatRegion},
		{"wp_usermeta", "billing_company", "", model.CatCompany},
		{"wp_usermeta", "nickname", "", model.CatPersonName},
		{"wp_options", "mailserver_pass", "", model.CatSecret},
		// Magento 2
		{"customer_entity", "firstname", "varchar", model.CatPersonName},
		{"customer_entity", "dob", "date", model.CatDateOfBirth},
		{"customer_entity", "taxvat", "varchar", model.CatNationalID},
		{"customer_entity", "gender", "int", model.CatGender},
		{"customer_entity", "password_hash", "varchar", model.CatPasswordHash},
		{"customer_entity", "rp_token", "varchar", model.CatSecret},
		{"customer_entity", "rp_token_created_at", "datetime", ""},
		{"customer_entity", "default_billing", "int", ""},
		{"customer_entity", "failures_num", "smallint", ""},
		{"customer_address_entity", "street", "text", model.CatAddress},
		{"customer_address_entity", "telephone", "varchar", model.CatPhone},
		{"customer_address_entity", "fax", "varchar", model.CatPhone},
		{"customer_address_entity", "postcode", "varchar", model.CatPostcode},
		{"customer_address_entity", "country_id", "varchar", model.CatCountry},
		{"customer_address_entity", "region", "varchar", model.CatRegion},
		{"customer_address_entity", "region_id", "int", ""},
		{"customer_address_entity", "vat_id", "varchar", model.CatNationalID},
		{"customer_address_entity", "vat_is_valid", "int", ""},
		{"customer_address_entity", "vat_request_id", "varchar", ""},
		{"sales_order", "remote_ip", "varchar", model.CatIPAddress},
		{"sales_order", "x_forwarded_for", "varchar", model.CatIPAddress},
		{"sales_order", "customer_note", "text", model.CatFreeText},
		{"sales_order", "customer_note_notify", "smallint", ""},
		{"sales_order", "customer_id", "int", ""},
		{"sales_order", "state", "varchar", ""},
		{"sales_order", "increment_id", "varchar", ""},
		{"sales_order_tax", "tax_id", "int", ""},
		{"sales_order_payment", "cc_last_4", "varchar", model.CatCardMeta},
		{"sales_order_payment", "cc_owner", "varchar", model.CatPersonName},
		{"sales_order_payment", "cc_exp_month", "varchar", model.CatCardMeta},
		{"customer_grid_flat", "name", "text", model.CatPersonName},
		// Laravel
		{"users", "name", "varchar", model.CatPersonName},
		{"users", "email", "varchar", model.CatEmail},
		{"users", "email_verified_at", "timestamp", ""},
		{"users", "remember_token", "varchar", model.CatSecret},
		{"users", "two_factor_secret", "text", model.CatSecret},
		{"users", "two_factor_recovery_codes", "text", model.CatSecret},
		{"users", "two_factor_confirmed_at", "timestamp", ""},
		{"users", "stripe_id", "varchar", model.CatPaymentToken},
		{"users", "pm_last_four", "varchar", model.CatCardMeta},
		{"sessions", "ip_address", "varchar", model.CatIPAddress},
		{"sessions", "user_agent", "text", model.CatUserAgent},
		{"sessions", "last_activity", "int", ""},
		{"personal_access_tokens", "token", "varchar", model.CatSecret},
		{"personal_access_tokens", "tokenable_type", "varchar", ""},
		// Generic
		{"products", "name", "varchar", ""},
		{"settings", "email_enabled", "tinyint", ""},
		{"users", "email_hash", "varchar", ""},
		{"users", "mobile", "tinyint", ""},
		{"orders", "zip", "varchar", model.CatPostcode},
		{"backups", "zip_file", "varchar", ""},
		{"stores", "lat", "decimal", model.CatGeo},
		{"orders", "phone_country_code", "varchar", ""},
		{"payments", "iban", "varchar", model.CatBankAccount},
		{"payments", "cvv", "varchar", model.CatCardMeta},
		{"payments", "card_number", "varchar", model.CatCardNumber},
		{"tickets", "message", "text", model.CatFreeText},
		{"geo", "geo_country", "varchar", model.CatCountry},
		{"accounts", "last_login", "datetime", ""},
		{"accounts", "login", "varchar", model.CatUsername},
		{"subscribers", "address_id", "int", ""},
		{"servers", "mac_address", "varchar", ""},
		{"smtp", "smtp_password", "varchar", model.CatPasswordHash},
		// Settings whose names say more than they hold.
		{"wp_usermeta", "default_password_nag", "", ""},
		{"wp_options", "woocommerce_registration_generate_password", "", ""},
		{"wp_options", "woocommerce_myaccount_lost_password_endpoint", "", ""},
		{"wp_options", "woocommerce_myaccount_edit_address_endpoint", "", ""},
		{"wp_options", "woocommerce_email_background_color", "", ""},
		{"rank_math_analytics_objects", "mobile_pagescore", "varchar", ""},
		{"rank_math_analytics_objects", "mobile_interactive", "double", ""},
		{"um_role", "_um_after_login", "", ""},
		{"um_options", "login_align", "", ""},
		{"um_options", "login_primary_btn_word", "", ""},
		{"wp_options", "smtp_login", "", model.CatUsername},
		{"wp_options", "smtp_login_2", "", model.CatUsername},
		{"users", "generated_password", "varchar", model.CatPasswordHash},
		// Notification recipients are email addresses.
		{"wp_options", "fixture_admin_recipient", "", model.CatEmail},
		{"settings", "recipients", "varchar", model.CatEmail},
		{"orders", "recipient_name", "varchar", model.CatPersonName},
		{"gifts", "recipient_message", "text", model.CatFreeText},
		// Passwords named pass: a person's, a service's, or no password.
		{"admin", "pass", "varchar", model.CatPasswordHash},
		{"client", "pass", "varchar", model.CatPasswordHash},
		{"settings", "admin_pass", "varchar", model.CatPasswordHash},
		{"servers", "ftppass", "varchar", model.CatSecret},
		{"servers", "sshpass", "varchar", model.CatSecret},
		{"servers", "db_pass", "varchar", model.CatSecret},
		{"games", "battle_pass", "varchar", ""},
		{"games", "season_pass", "varchar", ""},
		{"games", "boarding_pass", "varchar", ""},
		{"games", "day_pass", "varchar", ""},
		{"games", "test_pass", "varchar", ""},
		{"players", "current_pass", "varchar", ""},
		{"users", "new_pass", "varchar", model.CatPasswordHash},
		// Names that describe passwords rather than hold one.
		{"settings", "password_type", "varchar", ""},
		{"settings", "password_mode", "varchar", ""},
		{"settings", "password_rules", "varchar", ""},
		{"settings", "password_page", "varchar", ""},
		{"settings", "password_timeout", "int", ""},
		{"settings", "password_field_color", "varchar", ""},
		{"users", "password_set_by", "varchar", ""},
		{"users", "password_salt", "varchar", model.CatSecret},
		{"users", "password_iv", "varchar", ""},
		{"users", "password_last_set", "varchar", model.CatPasswordHash},
		{"users", "set_password", "varchar", model.CatPasswordHash},
		// Login keys, signatures, Twitter's abbreviations, BYOND's ckey.
		{"members", "member_login_key", "varchar", model.CatSecret},
		{"core_sys_cp_sessions", "session_member_login_key", "varchar", model.CatSecret},
		{"mybb_users", "loginkey", "varchar", model.CatSecret},
		{"settings", "api_signature", "", model.CatSecret},
		{"core_sys_conf_settings", "shoutbox_twitter_ckey", "", model.CatSecret},
		{"core_sys_conf_settings", "shoutbox_twitter_csecret", "", model.CatSecret},
		{"core_sys_conf_settings", "shoutbox_twitter_asecret", "", model.CatSecret},
		{"core_sys_conf_settings", "shoutbox_twitter_atoken", "", model.CatSecret},
		{"player", "ckey", "varchar", ""},
		{"ban", "ckey", "varchar", ""},
		// Run-together IPs, and network addresses that aren't streets.
		{"mybb_users", "regip", "varbinary", model.CatIPAddress},
		{"mybb_users", "lastip", "varbinary", model.CatIPAddress},
		{"flows", "src_addr", "varchar", model.CatIPAddress},
		{"flows", "srcaddr", "varchar", model.CatIPAddress},
		{"flows", "clientaddr", "varchar", model.CatIPAddress},
		{"bot_visits", "request_addr", "text", ""},
		// Address parts, and the name on an address.
		{"addresses", "street_name", "varchar", model.CatAddress},
		{"addresses", "street_code", "varchar", model.CatAddress},
		{"paypal_ipn", "address_street", "", model.CatAddress},
		{"paypal_ipn", "address_city", "", model.CatCity},
		{"paypal_ipn", "address_state", "", model.CatRegion},
		{"paypal_ipn", "address_zip", "", model.CatPostcode},
		{"paypal_ipn", "address_country", "", model.CatCountry},
		{"paypal_ipn", "address_country_code", "", model.CatCountry},
		{"paypal_ipn", "address_name", "", model.CatPersonName},
		{"paypal_ipn", "address_status", "", ""},
		{"addresses", "address_name", "varchar", ""},
		{"orders", "shipping_address_name", "varchar", model.CatPersonName},
		// Group, role and product names aren't people's.
		{"admin_group", "name", "varchar", ""},
		{"ab_customer_groups", "name", "varchar", ""},
		{"ab_user_groups", "name", "varchar", ""},
		{"user_roles", "name", "varchar", ""},
		{"user_products", "name", "varchar", ""},
		{"team_members", "name", "varchar", model.CatPersonName},
		{"members", "name", "varchar", model.CatPersonName},
		// Names, handles and birthdays the rules missed.
		{"members", "members_seo_name", "varchar", model.CatUsername},
		{"nexus_packages", "p_seo_name", "varchar", ""},
		{"core_sys_conf_settings", "username_characters", "", ""},
		{"members", "first_login", "varchar", ""},
		{"game_logs", "summonername", "varchar", model.CatUsername},
		{"stats", "player_name", "varchar", model.CatUsername},
		{"members", "bday_day", "int", model.CatDateOfBirth},
		{"members", "bday_month", "int", model.CatDateOfBirth},
		{"members", "bday_year", "int", model.CatDateOfBirth},
		{"members", "birth_month", "int", model.CatDateOfBirth},
		// Device and hardware IDs; a bare device_id points at a devices table.
		{"members", "hwid", "text", model.CatDeviceID},
		{"activations", "hwid", "varchar", model.CatDeviceID},
		{"members", "hwid_updated_date", "datetime", ""},
		{"jobs", "machine_id", "varchar", model.CatDeviceID},
		{"phones", "imei", "bigint", model.CatDeviceID},
		{"devices", "device_id", "varchar", ""},
		// Messages between people, and text that isn't one.
		{"message_topics", "mt_title", "varchar", model.CatFreeText},
		{"inline_notifications", "notify_text", "text", model.CatFreeText},
		{"message_posts", "msg_post", "mediumtext", model.CatFreeText},
		{"mybb_privatemessages", "subject", "varchar", model.CatFreeText},
		{"phpbb_privmsgs", "message_subject", "varchar", model.CatFreeText},
		{"pmtext", "title", "varchar", model.CatFreeText},
		{"profile_portal", "signature", "text", model.CatFreeText},
		{"wp_pm_tasks", "title", "varchar", ""},
		{"email_templates", "subject", "varchar", ""},
		{"bulk_mail", "mail_subject", "varchar", ""},
		{"message_translations", "text", "text", ""},
		{"logs", "msg", "text", ""},
		{"logs", "error_msg", "text", ""},
		{"gf_form_meta", "notifications", "longtext", ""},
		{"adminnotification_inbox", "title", "varchar", ""},
		{"ab_ant_messages", "title", "varchar", ""},
		// Company settings that aren't company names.
		{"setting", "company_privacy_policy", "", ""},
		{"setting", "company_tos", "", ""},
		{"setting", "company_signature", "", model.CatFreeText},
		{"setting", "company_note", "", model.CatFreeText},
		{"setting", "company_name", "", model.CatCompany},
		// Words that describe a password rule a name out only after it.
		{"node__field_wifi_password", "field_wifi_password_value", "varchar", model.CatPasswordHash},
		{"wp_posts", "page_password", "varchar", model.CatPasswordHash},
		{"settings", "password_field_class", "varchar", ""},
		{"settings", "password_page", "varchar", ""},
		// An email account's password; a mail or FTP server's users' hashes.
		{"settings", "emailpass", "varchar", model.CatSecret},
		{"settings", "email_pass", "varchar", model.CatSecret},
		{"ftp_users", "pass", "varchar", model.CatPasswordHash},
		{"proxy_accounts", "pass", "varchar", model.CatPasswordHash},
		{"smtp_logins", "pass", "varchar", model.CatPasswordHash},
		{"smtp_servers", "pass", "varchar", model.CatSecret},
		// A message's type, status and key, and the types, statuses and
		// categories of tickets, aren't messages.
		{"messages", "content_type", "varchar", ""},
		{"chat_messages", "post_status", "varchar", ""},
		{"message_posts", "msg_post_key", "varchar", ""},
		{"ticket_types", "title", "varchar", ""},
		{"ticket_statuses", "title", "varchar", ""},
		{"notification_types", "title", "varchar", ""},
		{"ticket_categories", "title", "varchar", ""},
		{"ticket_priorities", "title", "varchar", ""},
		{"chat_rooms", "title", "varchar", ""},
		{"message_folders", "title", "varchar", ""},
		{"tickets", "title", "varchar", model.CatFreeText},
		{"room_messages", "text", "text", model.CatFreeText},
	}
	for _, c := range cases {
		tc := tStr
		if c.dataType != "" {
			tc = classOf(c.dataType)
		}
		var got model.Category
		if m := MatchName(NameWords(c.column), Tokens(c.table), tc); m != nil {
			got = m.Category
		}
		if got != c.want {
			t.Errorf("%s.%s (%s): got %q, want %q", c.table, c.column, c.dataType, got, c.want)
		}
	}
}

// Paths are named in the context of the table, the column or meta key
// holding them, and the keys above them.
func TestMatchNameInContext(t *testing.T) {
	cases := []struct {
		name, ctx string
		want      model.Category
	}{
		// WP Mail SMTP's smtp.pass and UpdraftPlus's FTP settings.
		{"pass", "wp options wp mail smtp smtp", model.CatSecret},
		{"pass", "wp options updraft ftp settings", model.CatSecret},
		// POST data in an admin login log.
		{"newpass", "admin login logs admin post details post", model.CatPasswordHash},
		{"currentpass", "admin login logs admin post details post", model.CatPasswordHash},
		// IPN data in a log column, and in a table named with one run-together word.
		{"address_name", "logs ipn data", model.CatPersonName},
		{"address_name", "paypalsales data", model.CatPersonName},
		{"address_name", "addresses data", ""},
		// WooCommerce's remote specs: plugin and action names aren't people's,
		// although the option's own name says admin.
		{"name", "wp options transient woocommerce admin remote free extensions specs en us plugins", ""},
		{"name", "wp options transient woocommerce admin remote inbox notifications specs en us install actions", ""},
		{"title", "wp options transient woocommerce admin remote inbox notifications specs en us", ""},
		// IPB's cached app menu: the shoutbox's menu titles aren't messages.
		{"title", "cache store app menu cache shoutbox items", ""},
		// The head noun of the context decides what a bare name names.
		{"name", "app data user groups", ""},
		{"name", "app data group owner", model.CatPersonName},
		{"name", "contact submissions data fields", model.CatPersonName},
		{"name", "customer attributes", model.CatPersonName},
		{"name", "orders shipping address", model.CatPersonName},
		// A company's or a store's name isn't a person's, even under a customer.
		{"name", "orders customer company", ""},
		{"name", "orders customer store", ""},
		// A service named above a user's settings: people come first by
		// name, and the values decide.
		{"pass", "users settings smtp", model.CatPasswordHash},
	}
	for _, c := range cases {
		var got model.Category
		if m := MatchName(NameWords(c.name), strings.Fields(c.ctx), tStr|tJSON); m != nil {
			got = m.Category
		}
		if got != c.want {
			t.Errorf("%s in %q: got %q, want %q", c.name, c.ctx, got, c.want)
		}
	}
	// The message rule marks its matches; password names are marked too.
	if m := MatchName(NameWords("mt_title"), Tokens("message_topics"), tStr); m == nil || !m.Messages {
		t.Errorf("mt_title: got %+v, want a message match", m)
	}
	for _, name := range []string{"user_pass", "smtp_pass", "wallet_passphrase", "adminpass"} {
		if m := MatchName(NameWords(name), nil, tStr); m == nil || !m.Password {
			t.Errorf("%s: got %+v, want a password match", name, m)
		}
	}
	if m := MatchName(NameWords("api_key"), nil, tStr); m == nil || m.Password {
		t.Errorf("api_key: got %+v, want a secret that isn't a password", m)
	}
}

func TestCVVSeverity(t *testing.T) {
	m := MatchName(Tokens("cvv"), nil, tStr)
	if m == nil || m.Severity != model.SeverityHigh || m.Note == "" {
		t.Fatalf("cvv: got %+v, want high severity with a note", m)
	}
}
