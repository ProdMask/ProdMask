package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// TestTypeValuesShown checks that the text, Markdown and JSON reports show a
// polymorphic link's type value only when it reads as a class name: a URL
// that ends in a table's name prints as (type hidden). scan.Run already
// filters its result; this covers a result built elsewhere, which the
// writers leave as it is.
func TestTypeValuesShown(t *testing.T) {
	canary := "Qz8" + "typeCanary"
	stored := "https://" + canary + ".example/users"
	link := func(parent, typ string) model.Relationship {
		return model.Relationship{ChildTable: "comments", ChildColumns: []string{"commentable_id"}, ParentTable: parent,
			ParentColumns: []string{"id"}, Source: "polymorphic", Status: model.RelConfirmed, Checked: 3, Found: 3,
			TypeColumn: "commentable_type", TypeValue: typ}
	}
	res := &model.Result{Database: "shop", Relationships: []model.Relationship{link("posts", `App\Models\Post`), link("users", stored)}}
	var txt, md, js bytes.Buffer
	if err := Text(&txt, res, TextOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if err := Markdown(&md, res); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&js, res); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": txt.String(), "Markdown": md.String(), "JSON": js.String()} {
		if strings.Contains(out, canary) {
			t.Errorf("the %s report shows the stored type value:\n%s", name, out)
		}
		if !strings.Contains(out, "(type hidden)") || !strings.Contains(out, "Models") {
			t.Errorf("the %s report should show the class name and hide the other:\n%s", name, out)
		}
	}
	if res.Relationships[1].TypeValue != stored {
		t.Errorf("the result's type value changed: %q", res.Relationships[1].TypeValue)
	}
}

// steering are characters a name from the database could use to steer a
// terminal: escape, bell, carriage return, a C1 CSI and a bidi override.
const steering = "\x1b\x07\r\u009b\u202e"

// ownColours matches the colour codes the reports write themselves.
var ownColours = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// TestTextCleansNames checks that the text report writes characters that
// steer a terminal in names from the database as ?, while its own colour
// codes stay, the finding row's among them.
func TestTextCleansNames(t *testing.T) {
	res := &model.Result{
		Database: "shop\x1b]0;owned\x07",
		Findings: []model.Finding{{Table: "wp\x1b[2Jusers", Column: "email\r\x9b\u202e", Category: model.CatEmail,
			Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Mask: "fake_email"}},
	}
	var b bytes.Buffer
	if err := Text(&b, res, TextOptions{Color: true, Verbose: true}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if rest := ownColours.ReplaceAllString(out, ""); strings.ContainsAny(rest, steering) {
		t.Errorf("a character that steers a terminal reached it:\n%q", out)
	}
	for _, want := range []string{"shop?]0;owned?", "wp?[2Jusers", "    \x1b[31mHIGH    \x1b[0m  email???"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%q", want, out)
		}
	}
}

// TestLeakTextCleansNames checks the same of the leak check's terminal
// report, with the names of both databases and a column's.
func TestLeakTextCleansNames(t *testing.T) {
	res := leakFixture()
	res.Database = "shop\x1b[2J"
	res.Hashes.Database = "prod\x1b]0;owned\x07"
	res.Columns = []model.LeakColumn{spreadColumn(model.LeakColumn{Table: "wp\x1b[2Jusers", Column: "user_email\r\u202e",
		Kind: model.LeakEmail, Sampled: 3000, EstimatedValues: 100000, Found: 10, Rows: 10, Values: 90000, RowsRead: 100000,
		EstimateInAll: 300})}
	res.Summary = model.LeakSummary{Columns: 1, ColumnsRead: 1, ColumnsWithHit: 1, Sampled: 3000, Found: 10, RowsRead: 100000, DurationMillis: 1000}
	var b bytes.Buffer
	if err := LeakText(&b, res, true); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if rest := ownColours.ReplaceAllString(out, ""); strings.ContainsAny(rest, steering) {
		t.Errorf("a character that steers a terminal reached it:\n%q", out)
	}
	for _, want := range []string{"shop?[2J", "prod?]0;owned?", "wp?[2Jusers.user_email??"} {
		if !strings.Contains(out, want) {
			t.Errorf("the leak report is missing %q:\n%q", want, out)
		}
	}
	if !ownColours.MatchString(out) {
		t.Errorf("the leak report lost its colours:\n%q", out)
	}
}

// TestClean checks what Clean writes as ?: control characters, C1 ones and
// DEL among them, format characters such as a bidi override or a zero-width
// space, line and paragraph separators, and each byte that isn't UTF-8.
// Letters in any script stay.
func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"wp_users": "wp_users",
		"caf\xc3\xa9 \xce\x95\xce\xbb \xe5\x90\x8d": "caf\xc3\xa9 \xce\x95\xce\xbb \xe5\x90\x8d",
		"a\tb\nc":                     "a?b?c",
		"\x1b[2J\x07\x7f":             "?[2J??",
		"\xc2\x9b2J":                  "?2J",
		"\xe2\x80\xaeevil":            "?evil",
		"zero\xe2\x80\x8bwidth":       "zero?width",
		"\xef\xbb\xbfbom":             "?bom",
		"a\xe2\x80\xa8b\xe2\x80\xa9c": "a?b?c",
		"bad\xff\xfe":                 "bad??",
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNamesOnly checks what the text and Markdown reports say a scan with
// --no-samples read: the schema alone, or settings rows too when a platform
// was checked.
func TestNamesOnly(t *testing.T) {
	for _, c := range []struct {
		platforms []model.Platform
		want      string
	}{
		{nil, "names only, nothing read but the schema"},
		{[]model.Platform{{Name: "wordpress", Label: "WordPress"}}, "names only, no rows sampled; the platform checks read settings rows"},
	} {
		res := &model.Result{Database: "shop", Platforms: c.platforms}
		var txt, md bytes.Buffer
		if err := Text(&txt, res, TextOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := Markdown(&md, res); err != nil {
			t.Fatal(err)
		}
		for name, out := range map[string]string{"text": txt.String(), "Markdown": md.String()} {
			if !strings.Contains(out, c.want) {
				t.Errorf("the %s report with %d platforms is missing %q:\n%s", name, len(c.platforms), c.want, out)
			}
		}
	}
}
