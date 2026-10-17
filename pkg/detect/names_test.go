package detect

import (
	"reflect"
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
	}
	for _, c := range cases {
		tc := tStr
		if c.dataType != "" {
			tc = classOf(c.dataType)
		}
		var got model.Category
		if m := MatchName(Tokens(c.column), Tokens(c.table), tc); m != nil {
			got = m.Category
		}
		if got != c.want {
			t.Errorf("%s.%s (%s): got %q, want %q", c.table, c.column, c.dataType, got, c.want)
		}
	}
}

func TestCVVSeverity(t *testing.T) {
	m := MatchName(Tokens("cvv"), nil, tStr)
	if m == nil || m.Severity != model.SeverityHigh || m.Note == "" {
		t.Fatalf("cvv: got %+v, want high severity with a note", m)
	}
}
