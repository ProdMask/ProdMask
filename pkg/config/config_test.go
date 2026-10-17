package config

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
)

func TestScalar(t *testing.T) {
	cases := map[string]string{
		"fake_email":                 "fake_email",
		"wp_users":                   "wp_users",
		"payment/braintree/password": "payment/braintree/password",
		"null":                       `"null"`,
		"Yes":                        `"Yes"`,
		"0123":                       `"0123"`,
		"1e5":                        `"1e5"`,
		"items[].email":              `"items[].email"`,
		"Gift message":               `"Gift message"`,
		`a "quoted" \ value`:         `"a \"quoted\" \\ value"`,
		"line\nbreak":                `"line\nbreak"`,
		"commentable_type = App\\X":  `"commentable_type = App\\X"`,
	}
	for in, want := range cases {
		if got := scalar(in); got != want {
			t.Errorf("scalar(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestWrite(t *testing.T) {
	res := &model.Result{
		Version: "test", Database: "shop", GeneratedAt: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC),
		Server:    model.ServerInfo{Flavor: "mariadb", Version: "11.8.9-MariaDB"},
		Platforms: []model.Platform{{Name: "wordpress"}},
		Tables: []model.TableSummary{
			{Name: "wp_usermeta", Kind: "key/value", KeyColumn: "meta_key", ValueColumn: "meta_value"},
			{Name: "wp_woocommerce_sessions", Action: "truncate", ActionReason: "carts of live visitors"},
		},
		Findings: []model.Finding{
			{Table: "wp_users", Column: "user_email", Category: model.CatEmail, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email"},
			{Table: "wp_users", Column: "user_login", Category: model.CatUsername, Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium, Mask: "fake_username"},
			{Table: "wp_users", Column: "user_login", Category: model.CatEmail, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email"},
			{Table: "wp_users", Column: "notes", Category: model.CatFreeText, Severity: model.SeverityMedium, Confidence: model.ConfidenceLow, Mask: "redact"},
			{Table: "wp_usermeta", Column: "meta_value", MetaKey: "billing_phone", Category: model.CatPhone, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_phone"},
			{Table: "wp_usermeta", Column: "meta_value", MetaKey: "session_tokens", Path: "*.ip", Category: model.CatIPAddress, Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh, Mask: "fake_ip"},
		},
		Relationships: []model.Relationship{
			{ChildTable: "wp_postmeta", ChildColumns: []string{"post_id"}, ParentTable: "wp_posts", ParentColumns: []string{"ID"},
				Source: "preset:wordpress", Status: model.RelConfirmed, Checked: 10, Found: 10},
			{ChildTable: "orders", ChildColumns: []string{"user_id"}, ParentTable: "users", ParentColumns: []string{"id"},
				Source: "declared", Status: model.RelDeclared},
		},
	}
	var b bytes.Buffer
	if err := Write(&b, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"version: 1\n",
		"      user_email: fake_email  # email address, high confidence\n",
		"      user_login: fake_email  # email address, high confidence; also username\n",
		"      # notes: redact",
		"    key_column: meta_key\n    value_column: meta_value\n",
		"      billing_phone: fake_phone",
		"      session_tokens:\n        paths:\n          \"*.ip\": fake_ip",
		"  wp_woocommerce_sessions:\n    action: truncate  # carts of live visitors\n",
		"  - from: wp_postmeta.post_id\n    to: wp_posts.ID\n    status: confirmed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "orders.user_id") {
		t.Error("declared foreign keys belong to the schema, not the config")
	}
}

func TestWriteRowMasks(t *testing.T) {
	orders := model.RowMask{Where: "post_type IN ('shop_order', 'shop_order_refund')", Mask: "null", Note: "order keys"}
	res := &model.Result{
		Version: "test", Database: "shop", GeneratedAt: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC),
		Findings: []model.Finding{
			{Table: "wp_posts", Column: "post_password", Category: model.CatSecret, Severity: model.SeverityMedium,
				Confidence: model.ConfidenceHigh, Mask: "keep", RowMasks: []model.RowMask{orders}, Note: "post passwords"},
			// A more severe finding decides the column's mask; the row masks stay.
			{Table: "wp_posts", Column: "post_password", Category: model.CatEmail, Severity: model.SeverityHigh,
				Confidence: model.ConfidenceHigh, Mask: "fake_email", RowMasks: []model.RowMask{orders}},
			{Table: "wp_posts", Column: "post_excerpt", Category: model.CatFreeText, Severity: model.SeverityMedium,
				Confidence: model.ConfidenceLow, Mask: "redact", RowMasks: []model.RowMask{{Where: "post_type = 'shop_order'", Mask: "empty"}}},
			{Table: "wp_posts", Column: "post_title", Category: model.CatPersonName, Severity: model.SeverityMedium,
				Confidence: model.ConfidenceHigh, Mask: "fake_name", RowMasks: []model.RowMask{
					{Where: "post_type = 'b'", Mask: "null"}, {Where: "post_type = 'a'", Mask: "redact"}, {Where: "post_type = 'a'", Mask: "empty"}}},
		},
	}
	var b bytes.Buffer
	if err := Write(&b, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"      post_password:\n" +
			"        mask: fake_email  # email address, high confidence; also secret, key or token\n" +
			"        rows:  # for the rows that match, these replace the mask above\n" +
			"          - where: \"post_type IN ('shop_order', 'shop_order_refund')\"\n" +
			"            mask: \"null\"  # order keys\n",
		// Weak matches stay commented out, with their row masks.
		"      # post_excerpt:\n" +
			"        # mask: redact  # free text with personal data, low confidence\n" +
			"        # rows:  # for the rows that match, these replace the mask above\n" +
			"          # - where: \"post_type = 'shop_order'\"\n" +
			"          #   mask: empty\n",
		// In a fixed order.
		"          - where: \"post_type = 'a'\"\n            mask: empty\n" +
			"          - where: \"post_type = 'a'\"\n            mask: redact\n" +
			"          - where: \"post_type = 'b'\"\n            mask: \"null\"\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config is missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "- where:"); n != 5 {
		t.Errorf("want each row mask once, got %d:\n%s", n, out)
	}
}
