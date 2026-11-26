package scan_test

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// checkGolden compares a scan's findings with testdata/<name>.findings, one
// line per finding: where it is, what it is, how bad, how sure and how it is
// masked, and its side effects with their golden. With -update it rewrites
// the files instead, and every line that changes must be a change the
// release means to make.
func checkGolden(t *testing.T, name string, res *model.Result) {
	t.Helper()
	got := goldenLines(res)
	if strings.Contains(got, canary) {
		t.Errorf("the findings for %s contain a sampled value", name)
	}
	compareGolden(t, filepath.Join("testdata", name+".findings"), got, "findings")
	checkSideEffects(t, name, res)
}

// checkSideEffects compares a scan's side effects with
// testdata/<name>.sideeffects, one line per side effect with every field the
// reports and the starter config read. Where the two servers order a tie
// differently, a flavour can have its own file,
// testdata/<name>.<flavour>.sideeffects, which is read when it exists: the
// Laravel fixture's two queues tie at 6 jobs, though both servers order them
// alike today. With -update the file that would be read is rewritten, or the
// flavour's own one when there is none, so a first capture on each server
// can be compared before the two are made one.
func checkSideEffects(t *testing.T, name string, res *model.Result) {
	t.Helper()
	got := sideEffectLines(res)
	if strings.Contains(got, canary) {
		t.Errorf("the side effects for %s contain a sampled value", name)
	}
	path := filepath.Join("testdata", name+"."+res.Server.Flavor+".sideeffects")
	if shared := filepath.Join("testdata", name+".sideeffects"); !fileExists(path) && fileExists(shared) {
		path = shared
	}
	compareGolden(t, path, got, "side effects")
}

// compareGolden compares got with the golden file at path, or rewrites the
// file with -update.
func compareGolden(t *testing.T, path, got, what string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
		t.Errorf("the %s differ from %s; check each change, then run with -update:\n%s", what, path, d)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// sideEffectLines renders each side effect as one line, tab-separated:
// platform, kind, table, item, severity, count, summary, fix, label and
// lead, sorted. The text report shows the label and the lead, and the other
// reports the rest. A scan without side effects gives an empty file.
func sideEffectLines(res *model.Result) string {
	lines := make([]string, 0, len(res.SideEffects))
	for _, s := range res.SideEffects {
		lines = append(lines, strings.Join([]string{s.Platform, s.Kind, s.Table, s.Item, s.Severity.String(),
			strconv.FormatInt(s.Count, 10), s.Summary, s.Fix, s.Label, s.Lead}, "\t"))
	}
	sort.Strings(lines)
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.String()
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
