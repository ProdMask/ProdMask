package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

func TestMarkdownRowMasks(t *testing.T) {
	res := &model.Result{
		Database: "shop",
		Findings: []model.Finding{
			{Table: "wp_posts", Column: "post_password", Category: model.CatSecret, Severity: model.SeverityMedium,
				Confidence: model.ConfidenceHigh, Mask: "keep",
				RowMasks: []model.RowMask{{Where: "post_type IN ('shop_order', 'shop_order_refund')", Mask: "null"}}},
			{Table: "wp_users", Column: "user_email", Category: model.CatEmail, Severity: model.SeverityHigh,
				Confidence: model.ConfidenceHigh, Mask: "fake_email"},
		},
	}
	var b bytes.Buffer
	if err := Markdown(&b, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"| `keep`; `null` where `post_type IN ('shop_order', 'shop_order_refund')` |\n",
		"| `fake_email` |\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q:\n%s", want, out)
		}
	}
}

func TestReportsKeyPatterns(t *testing.T) {
	res := &model.Result{
		Database: "shop",
		Tables: []model.TableSummary{{Name: "wp_usermeta", Kind: "key/value", KeyColumn: "meta_key", ValueColumn: "meta_value",
			Keys: 208, RowsEstimate: 32555}},
		Findings: []model.Finding{
			{Table: "wp_usermeta", Column: "meta_key", MetaKey: "um_email_as_username_*", KeyName: true, Keys: 31,
				Category: model.CatEmail, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email",
				Reasons: []string{"known key family"}},
			{Table: "wp_usermeta", Column: "meta_value", MetaKey: "um_email_as_username_*", Keys: 20, KeysPartial: true,
				Category: model.CatEmail, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email"},
			{Table: "wp_posts", Column: "post_title", Where: "post_type = 'user_request'", Category: model.CatEmail,
				Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email"},
		},
	}
	var md, txt bytes.Buffer
	if err := Markdown(&md, res); err != nil {
		t.Fatal(err)
	}
	if err := Text(&txt, res, TextOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"`wp_usermeta.meta_key[um_email_as_username_*]` | email address | high | 31 keys; known key family",
		"`wp_usermeta.meta_value[um_email_as_username_*]` | email address | high | at least 20 keys",
		"`wp_posts.post_title where post_type = 'user_request'`",
	} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("Markdown is missing %q:\n%s", want, md.String())
		}
	}
	for _, want := range []string{
		"key/value: meta_key → meta_value · 208 keys · ~32,555 rows",
		"meta_key[um_email_as_username_*]",
		"[um_email_as_username_*]",
		"post_title where post_type = 'user_request'",
	} {
		if !strings.Contains(txt.String(), want) {
			t.Errorf("text report is missing %q:\n%s", want, txt.String())
		}
	}
}
