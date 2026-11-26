package model

import (
	"encoding/json"
	"testing"
)

// The JSON report holds a side effect's label but never its lead, which is
// only the start of its summary.
func TestSideEffectJSON(t *testing.T) {
	b, err := json.Marshal(SideEffect{Platform: "wordpress", Kind: "email", Label: "send email", Table: "wp_options",
		Severity: SeverityHigh, Lead: "Outgoing email", Summary: "Outgoing email is sent through WP Mail SMTP", Fix: "turn it off"})
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	if keys["label"] != "send email" {
		t.Errorf("label: got %v in %s", keys["label"], b)
	}
	for k := range keys {
		switch k {
		case "platform", "kind", "label", "table", "severity", "summary", "fix":
		default:
			t.Errorf("unexpected key %q in %s", k, b)
		}
	}
}
