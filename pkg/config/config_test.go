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
