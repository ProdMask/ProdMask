package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The fake shop's Markdown and JSON reports, so a reviewer sees them.
func TestFormatGoldens(t *testing.T) {
	res := fakeShop(t)
	var md, js bytes.Buffer
	if err := Markdown(&md, res); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&js, res); err != nil {
		t.Fatal(err)
	}
	compareFile(t, "fakeshop.md", md.String())
	compareFile(t, "fakeshop.report.json", js.String())
}

// Markdown's side-effects table leads with the label, in a column of its
// own, "Staging would"; the cells after it are the ones it had before.
func TestMarkdownLabels(t *testing.T) {
	res := fakeShop(t)
	var md bytes.Buffer
	if err := Markdown(&md, res); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(md.String(), "\n")
	i := indexOf(lines, "| Staging would | Severity | What | Where | Fix in the copy |")
	if i < 0 || lines[i+1] != "|---|---|---|---|---|" {
		t.Fatalf("no side-effects table with the label column:\n%s", md.String())
	}
	for j, se := range res.SideEffects {
		row := lines[i+2+j]
		if !strings.HasPrefix(row, "| "+se.Label+" | ") || strings.Count(row, " | ") != 4 {
			t.Errorf("side effect %d's row: %q", j, row)
		}
	}
}

// The JSON report adds each side effect's label to what v0.14.0 wrote, and
// nothing else: no lead.
func TestJSONAddsOnlyLabels(t *testing.T) {
	res := fakeShop(t)
	var js bytes.Buffer
	if err := JSON(&js, res); err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(js.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("testdata", "fakeshop.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	effects, _ := got["side_effects"].([]any)
	for i, x := range effects {
		se, _ := x.(map[string]any)
		if label, _ := se["label"].(string); label != res.SideEffects[i].Label {
			t.Errorf("side effect %d: label %q", i, se["label"])
		}
		delete(se, "label")
	}
	if !reflect.DeepEqual(got, want) {
		for k := range want {
			if !reflect.DeepEqual(got[k], want[k]) {
				t.Errorf("the JSON report's %q differs from v0.14.0's beyond the labels", k)
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Errorf("the JSON report has a new key %q", k)
			}
		}
	}
}
