package scan_test

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// checkGolden compares a scan's findings with testdata/<name>.findings, one
// line per finding: where it is, what it is, how bad, how sure and how it is
// masked. With -update it rewrites the file instead, and every line that
// changes must be a change the release means to make.
func checkGolden(t *testing.T, name string, res *model.Result) {
	t.Helper()
	got := goldenLines(res)
	if strings.Contains(got, canary) {
		t.Errorf("the findings for %s contain a sampled value", name)
	}
	path := filepath.Join("testdata", name+".findings")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if d := lineDiff(string(want), got); d != "" {
		t.Errorf("the findings differ from %s; check each change, then run with -update:\n%s", path, d)
	}
}

func goldenLines(res *model.Result) string {
	lines := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		key := f.MetaKey
		if f.KeyName {
			key += " (name)"
		}
		lines = append(lines, strings.Join([]string{f.Table, f.Column, key, f.Path, f.Where,
			string(f.Category), f.Severity.String(), f.Confidence.String(), f.Mask}, "\t"))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

// lineDiff lists the lines only in want (-) and only in got (+).
func lineDiff(want, got string) string {
	count := map[string]int{}
	for _, l := range strings.Split(strings.TrimSuffix(want, "\n"), "\n") {
		count[l]++
	}
	for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		count[l]--
	}
	var out []string
	for l, n := range count {
		for ; n > 0; n-- {
			out = append(out, "- "+l)
		}
		for ; n < 0; n++ {
			out = append(out, "+ "+l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][2:] < out[j][2:] || (out[i][2:] == out[j][2:] && out[i] < out[j]) })
	return strings.Join(out, "\n")
}
