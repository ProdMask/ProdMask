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
