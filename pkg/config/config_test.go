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
	checkTables(t, out)
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
	checkTables(t, out)
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

func TestWriteKeyPatterns(t *testing.T) {
	res := &model.Result{
		Version: "test", Database: "shop", GeneratedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC),
		Tables: []model.TableSummary{
			{Name: "wp_options", Kind: "key/value", KeyColumn: "option_name", ValueColumn: "option_value"},
			{Name: "wp_usermeta", Kind: "key/value", KeyColumn: "meta_key", ValueColumn: "meta_value"},
		},
		Findings: []model.Finding{
			{Table: "wp_options", Column: "option_value", MetaKey: "um_cache_userdata_*", Keys: 541, Category: model.CatPasswordHash,
				Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "delete", Note: "a cache"},
			// A cache whose names also hold data gets no name: rule.
			{Table: "wp_options", Column: "option_name", MetaKey: "seen_*", KeyName: true, Keys: 3, Category: model.CatEmail,
				Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email"},
			{Table: "wp_options", Column: "option_value", MetaKey: "seen_*", Keys: 3, Category: model.CatEmail,
				Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "delete"},
			{Table: "wp_usermeta", Column: "meta_key", MetaKey: "um_email_as_username_*", KeyName: true, Keys: 31,
				Category: model.CatEmail, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email"},
			{Table: "wp_usermeta", Column: "meta_value", MetaKey: "um_email_as_username_*", Keys: 20, KeysPartial: true,
				Category: model.CatEmail, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email"},
		},
	}
	var b bytes.Buffer
	if err := Write(&b, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	checkTables(t, out)
	for _, want := range []string{
		"# In keys and in path segments alike, * stands for one or more characters that vary",
		"plain-named keys beside them keep their own rules. Stored keys never contain *.",
		"      \"um_cache_userdata_*\": delete  # password hash, high confidence; 541 keys; a cache\n",
		"      \"seen_*\": delete  # email address, high confidence; 3 keys\n",
		"      \"um_email_as_username_*\":\n" +
			"        name: fake_email  # email address in the key name, high confidence; 31 keys\n" +
			"        mask: fake_email  # email address, high confidence; at least 20 keys\n",
		"    key_column: meta_key\n    value_column: meta_value\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "key_column: option_value") || strings.Contains(out, "value_column: meta_key") {
		t.Errorf("a key-name finding was taken for the value column:\n%s", out)
	}
}

func TestWriteWhereAndMixedColumns(t *testing.T) {
	res := &model.Result{
		Version: "test", Database: "shop", GeneratedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC),
		Findings: []model.Finding{
			// Privacy requests among posts: rows only, never the column's mask.
			{Table: "wp_posts", Column: "post_title", Where: "post_type = 'user_request'", Category: model.CatEmail,
				Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email", Note: "privacy requests"},
			// A login column where a sixth of the values are addresses.
			{Table: "wp_users", Column: "user_login", Category: model.CatUsername, Severity: model.SeverityMedium,
				Confidence: model.ConfidenceMedium, Mask: "fake_username"},
			{Table: "wp_users", Column: "user_login", Category: model.CatEmail, Severity: model.SeverityHigh,
				Confidence: model.ConfidenceMedium, Mask: "fake_username", Note: "48 of 300 values are email addresses; keep them email-shaped when masking"},
		},
	}
	var b bytes.Buffer
	if err := Write(&b, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	checkTables(t, out)
	for _, want := range []string{
		"      post_title:\n        rows:  # for the rows that match; the other rows keep their values\n" +
			"          - where: \"post_type = 'user_request'\"\n            mask: fake_email  # email address, high confidence; privacy requests\n",
		"      user_login: fake_username  # email address, medium confidence; also username; 48 of 300 values are email addresses",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "post_title: fake_email") || strings.Contains(out, "\n        mask: fake_email") {
		t.Errorf("a row finding set the column mask:\n%s", out)
	}
}

// checkTables checks the shape of a config's tables: section, as a YAML
// parser would read it: every line sits inside the section, every live
// table has a live line under it, and the section holds either live tables
// or {}.
func checkTables(t *testing.T, yml string) {
	t.Helper()
	_, section, ok := strings.Cut(yml, "\ntables:\n")
	if !ok {
		t.Fatalf("no tables: section in\n%s", yml)
	}
	section, _, _ = strings.Cut(section, "\n\n")
	lines := strings.Split(section, "\n")
	live, empty := 0, false
	for i, l := range lines {
		switch {
		case l == "":
			continue
		case !strings.HasPrefix(l, "  "):
			t.Errorf("line %q is outside the tables: section in YAML:\n%s", l, section)
			continue
		case strings.HasPrefix(l, "  {}"):
			empty = true
			continue
		case strings.HasPrefix(l, "   ") || strings.HasPrefix(l, "  #"):
			continue
		}
		// A live table name: the next live line must sit under it.
		live++
		next := ""
		for _, m := range lines[i+1:] {
			if !strings.HasPrefix(strings.TrimSpace(m), "#") {
				next = m
				break
			}
		}
		if !strings.HasPrefix(next, "    ") {
			t.Errorf("table %q is empty in YAML:\n%s", l, section)
		}
	}
	if (live == 0) != empty {
		t.Errorf("tables: holds %d live tables and {} %v in YAML:\n%s", live, empty, section)
	}
}

func TestWriteSuggestionsAndHiddenKeys(t *testing.T) {
	cache := model.TableSummary{Name: "content_cache_posts", PossibleAction: "truncate",
		PossibleActionReason: "looks like a cache: applications rebuild their caches"}
	write := func(res *model.Result) string {
		t.Helper()
		var b bytes.Buffer
		if err := Write(&b, res); err != nil {
			t.Fatal(err)
		}
		checkTables(t, b.String())
		return b.String()
	}
	// A cache that is all the config has: commented out, and tables: {}.
	yml := write(&model.Result{Database: "forum", Tables: []model.TableSummary{cache}})
	if !strings.Contains(yml, "\ntables:\n  {}  # delete this line when you uncomment a table\n"+
		"  # content_cache_posts:\n  #   action: truncate  # looks like a cache") {
		t.Errorf("cache-only config:\n%s", yml)
	}
	if !strings.Contains(yml, "# Lines starting with \"# \" are weak matches or suggestions") {
		t.Errorf("header:\n%s", yml)
	}
	// A cache with columns keeps its name and comments its suggestion.
	yml = write(&model.Result{Database: "forum", Tables: []model.TableSummary{cache}, Findings: []model.Finding{
		{Table: "content_cache_posts", Column: "cache_content", Category: model.CatFreeText, Severity: model.SeverityMedium,
			Confidence: model.ConfidenceMedium, Mask: "redact"}}})
	if !strings.Contains(yml, "\n  content_cache_posts:\n    # action: truncate  # looks like a cache") ||
		!strings.Contains(yml, "      cache_content: redact") {
		t.Errorf("cache with columns:\n%s", yml)
	}
	// Hidden keys: categories, a count and the columns, never a key.
	entries := model.TableSummary{Name: "form_entries", Kind: "key/value", KeyColumn: "field_key", ValueColumn: "field_value",
		HiddenKeys: 2}
	hidden := []model.Finding{
		{Table: "form_entries", Column: "field_value", MetaKey: "(key hidden)", Category: model.CatPhone,
			Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_phone"},
		{Table: "form_entries", Column: "field_value", MetaKey: "(key hidden)", Category: model.CatEmail,
			Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Mask: "fake_email"},
	}
	yml = write(&model.Result{Database: "site", Tables: []model.TableSummary{entries}, Findings: hidden})
	want := "  # form_entries:\n  #   # 2 keys not shown hold: email address, phone number; their values are copied " +
		"unmasked unless you add rules for them (key column field_key, value column field_value)\n"
	if !strings.Contains(yml, want) || strings.Contains(yml, "(key hidden)") {
		t.Errorf("hidden keys only:\n%s", yml)
	}
	// Beside shown keys, the note sits inside the live table.
	yml = write(&model.Result{Database: "site", Tables: []model.TableSummary{entries}, Findings: append(hidden,
		model.Finding{Table: "form_entries", Column: "field_value", MetaKey: "Phone number", Category: model.CatPhone,
			Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_phone"})})
	if !strings.Contains(yml, "\n  form_entries:\n    # 2 keys not shown hold:") || !strings.Contains(yml, "\"Phone number\": fake_phone") {
		t.Errorf("hidden keys beside shown ones:\n%s", yml)
	}
	// A column name with a line break stays inside the comment.
	odd := entries
	odd.KeyColumn = "field\nkey"
	yml = write(&model.Result{Database: "site", Tables: []model.TableSummary{odd}, Findings: hidden})
	if !strings.Contains(yml, "(key column field key, value column field_value)\n") {
		t.Errorf("odd column name:\n%s", yml)
	}
}
