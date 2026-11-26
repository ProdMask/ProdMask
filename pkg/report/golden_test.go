package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/config"
	"github.com/ProdMask/ProdMask/pkg/model"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// compareFile compares got with testdata/<name>, or rewrites the file with
// -update. Every line that changes must be a change the release means to
// make.
func compareFile(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if string(want) != got {
		t.Errorf("the output differs from %s; check the change, then run with -update:\n%s", path, got)
	}
}

// loadFakeShop reads testdata/fakeshop.json, the fake shop's JSON report
// from the v0.14.0 tag (examples/shop.sql, made-up data), into a Result. The
// JSON writes severities and confidences as words, which the model doesn't
// read back, so they become their numbers first.
func loadFakeShop(t *testing.T) *model.Result {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fakeshop.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatal(err)
	}
	confidences := map[string]model.Confidence{}
	for c := model.ConfidenceLow; c <= model.ConfidenceHigh; c++ {
		confidences[c.String()] = c
	}
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				s, isWord := x.(string)
				switch {
				case isWord && (k == "severity" || k == "highest_severity"):
					sev, err := model.ParseSeverity(s)
					if err != nil {
						t.Fatalf("%s %q: %v", k, s, err)
					}
					v[k] = int(sev)
				case isWord && k == "confidence":
					c, ok := confidences[s]
					if !ok {
						t.Fatalf("confidence %q", s)
					}
					v[k] = int(c)
				default:
					walk(x)
				}
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(tree)
	data, err = json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	res := &model.Result{}
	if err := json.Unmarshal(data, res); err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 || len(res.SideEffects) == 0 {
		t.Fatalf("the fake shop holds %d findings and %d side effects", len(res.Findings), len(res.SideEffects))
	}
	return res
}

// TestStarterConfigGolden holds the starter config written from the fake
// shop, its side effects labelled, byte for byte: the report's changes must
// leave the file Pro reads as it is, its keys and every side effect's kind,
// where, why and fix, with no label or lead in it.
func TestStarterConfigGolden(t *testing.T) {
	res := fakeShop(t)
	var b bytes.Buffer
	if err := config.Write(&b, res); err != nil {
		t.Fatal(err)
	}
	compareFile(t, "fakeshop.starter.yml", b.String())
}
