package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// TestEdition: a build with an edition names it, with its version's build
// metadata dropped, in the text and Markdown reports, and prints no line
// about prodmask Pro; its JSON keeps the whole version and adds the edition.
// The free build's reports are as before, with the free line.
func TestEdition(t *testing.T) {
	pro := &model.Result{Version: "1.0.0-beta.1+pro", Edition: "Pro", Database: "shop"}
	var txt, md, js bytes.Buffer
	if err := Text(&txt, pro, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := Markdown(&md, pro); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&js, pro); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(txt.String(), "prodmask Pro 1.0.0-beta.1 scan · shop · ") {
		t.Errorf("a Pro build's text report starts:\n%s", firstLine(txt.String()))
	}
	if !strings.Contains(md.String(), "- **Tool:** prodmask Pro 1.0.0-beta.1. ") {
		t.Errorf("a Pro build's Markdown report has no tool line naming the edition:\n%s", md.String())
	}
	for name, out := range map[string]string{"text": txt.String(), "Markdown": md.String()} {
		if strings.Contains(out, "+pro") || strings.Contains(out, "https://prodmask.com") {
			t.Errorf("a Pro build's %s report shows +pro or the line about prodmask Pro:\n%s", name, out)
		}
	}
	var got struct{ Version, Edition string }
	if err := json.Unmarshal(js.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "1.0.0-beta.1+pro" || got.Edition != "Pro" {
		t.Errorf("a Pro build's JSON report: version %q, edition %q", got.Version, got.Edition)
	}

	free := &model.Result{Version: "0.13.0", Database: "shop"}
	txt.Reset()
	md.Reset()
	js.Reset()
	if err := Text(&txt, free, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := Markdown(&md, free); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&js, free); err != nil {
		t.Fatal(err)
	}
	const line = "prodmask Pro makes copies of this database with the real shape and fake customers: https://prodmask.com\n"
	if !strings.HasPrefix(txt.String(), "prodmask scan · shop · ") || !strings.HasSuffix(txt.String(), line) {
		t.Errorf("the free text report:\n%s", txt.String())
	}
	if !strings.Contains(md.String(), "- **Tool:** prodmask 0.13.0. ") || !strings.HasSuffix(md.String(), "---\n\n"+line) {
		t.Errorf("the free Markdown report:\n%s", md.String())
	}
	if strings.Contains(js.String(), `"edition"`) {
		t.Errorf("the free JSON report has an edition:\n%s", js.String())
	}
}

// TestLeakEdition: a build with an edition names it in the leak check's text
// report, with the version's build metadata dropped, and prints no line about
// prodmask Pro; its JSON adds the edition. The free build's text report is as
// before, with the free line.
func TestLeakEdition(t *testing.T) {
	const line = "prodmask Pro makes staging copies with fake customers and checks the result row by row: https://prodmask.com/leak-check\n"
	res := leakFixture()
	var free bytes.Buffer
	if err := LeakText(&free, res, false); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(free.String(), "prodmask leak-check · shop · ") || !strings.HasSuffix(free.String(), "\n\n"+line) {
		t.Errorf("the free leak report:\n%s", free.String())
	}
	res.Version, res.Edition = "1.0.0+pro", "Pro"
	var txt, js bytes.Buffer
	if err := LeakText(&txt, res, false); err != nil {
		t.Fatal(err)
	}
	if err := LeakJSON(&js, res); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(txt.String(), "prodmask Pro 1.0.0 leak-check · shop · ") || strings.Contains(txt.String(), "prodmask.com/leak-check") {
		t.Errorf("a Pro build's leak report:\n%s", txt.String())
	}
	var got struct{ Version, Edition string }
	if err := json.Unmarshal(js.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "1.0.0+pro" || got.Edition != "Pro" {
		t.Errorf("a Pro build's leak JSON: version %q, edition %q", got.Version, got.Edition)
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
