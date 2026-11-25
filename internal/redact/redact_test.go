package redact

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// table builds a base table from "name type" pairs.
func table(name string, cols ...string) *model.Table {
	t := &model.Table{Name: name, Type: "BASE TABLE"}
	for i, c := range cols {
		n, typ, _ := strings.Cut(c, " ")
		t.Columns = append(t.Columns, &model.Column{Name: n, Position: i + 1, DataType: typ, ColumnType: typ})
	}
	return t
}

// harness is a Redactor over tables judged by the scan's own name rules
// (JudgeTable with no samples, so no database), plus findings a test adds
// as if the scan had sampled them.
type harness struct {
	r     *Redactor
	calls map[string]int
}

func newHarness(copy bool, extra []model.Finding, tables ...*model.Table) *harness {
	h := &harness{calls: map[string]int{}}
	schema := &model.Schema{Database: "shop", Tables: tables}
	src := Source{Schema: schema, Judge: func(ctx context.Context, t *model.Table) scan.TableVerdict {
		h.calls[t.Name]++
		v := scan.JudgeTable(ctx, nil, nil, t, scan.Options{})
		for _, f := range extra {
			if f.Table == t.Name {
				v.Findings = append(v.Findings, f)
			}
		}
		return v
	}}
	h.r = New(src, copy, make([]byte, 32))
	return h
}

func text(s string) Value { return Value{Bytes: []byte(s)} }

// run shows a result whose columns are "name TYPE" pairs.
func (h *harness) run(statement string, cols []string, rows ...[]Value) Shown {
	var cs []Column
	for _, c := range cols {
		n, typ, _ := strings.Cut(c, " ")
		cs = append(cs, Column{Name: n, Type: typ})
	}
	return h.r.Result(context.Background(), statement, cs, rows)
}

var tokenShape = regexp.MustCompile(`^\[([a-z_]+) [0-9a-f]{12}\]$`)

// kindOf is a shown value's token kind, or "" when it isn't one token.
func kindOf(v any) string {
	s, _ := v.(string)
	if m := tokenShape.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func hasNote(out Shown, want string) bool {
	for _, n := range out.Notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}

var customers = func() *model.Table {
	return table("customers", "id int", "first_name varchar", "last_name varchar", "street_address varchar",
		"birth_date date", "city varchar", "status varchar")
}

// TestByName replaces columns whose names say what they hold, in kinds no
// span finder sees, and says so.
func TestByName(t *testing.T) {
	h := newHarness(false, nil, customers())
	out := h.run("SELECT c.first_name, c.street_address, c.birth_date, c.status FROM customers c",
		[]string{"c.first_name VARCHAR", "c.street_address VARCHAR", "c.birth_date DATE", "c.status VARCHAR"},
		[]Value{text("Ada"), text("12 Ermou"), text("1990-01-02"), text("active")})
	row := out.Rows[0]
	if kindOf(row[0]) != "person_name" || kindOf(row[1]) == "" || kindOf(row[2]) == "" || row[3] != "active" {
		t.Errorf("row: %v", row)
	}
	if !hasNote(out, "first_name: 1 value replaced (person_name, by name)") {
		t.Errorf("notes: %v", out.Notes)
	}
}

// TestTableVerdict replaces a one-row result's column by its table's verdict,
// made from values the scan sampled, in kinds no span finder sees.
func TestTableVerdict(t *testing.T) {
	h := newHarness(false, []model.Finding{
		{Table: "visits", Column: "ua", Category: model.CatUserAgent, Severity: model.SeverityLow, Confidence: model.ConfidenceHigh, Matched: 30},
		{Table: "visits", Column: "ref", Category: model.CatPaymentToken, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Matched: 12},
	}, table("visits", "id int", "ua varchar", "ref varchar"))
	out := h.run("SELECT v.ua, v.ref FROM visits v", []string{"v.ua VARCHAR", "v.ref VARCHAR"},
		[]Value{text("Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"), text("pi_3Qx7Lm2eZvKYlo2C")})
	if kindOf(out.Rows[0][0]) != "user_agent" || kindOf(out.Rows[0][1]) != "payment_token" {
		t.Errorf("row: %v", out.Rows[0])
	}
	if !hasNote(out, "ua: 1 value replaced (user_agent, by its values)") {
		t.Errorf("notes: %v", out.Notes)
	}
}

func TestRenamed(t *testing.T) {
	usermeta := table("wp_usermeta", "umeta_id int", "user_id int", "meta_key varchar", "meta_value longtext")
	h := newHarness(false, nil, customers(), usermeta)
	cases := []struct {
		stmt, col string
		value     string
		want      string // a token's kind, or withheld
	}{
		{"SELECT c.first_name AS label FROM customers c", "c.label VARCHAR", "Ada", "token"},
		{"SELECT c.city AS town FROM customers c", "c.town VARCHAR", "Athens", "token"},
		// A string against a number: a rename, not id's verdict, so it
		// takes the table's worst string verdict.
		{"SELECT c.last_name AS id FROM customers c", "c.id VARCHAR", "Lovelace", "token"},
		{"SELECT m.meta_value AS v FROM wp_usermeta m", "m.v LONGTEXT", "Ada", "withheld"},
	}
	for _, c := range cases {
		out := h.run(c.stmt, []string{c.col}, []Value{text(c.value)})
		got := out.Rows[0][0]
		switch {
		case c.want == "token" && kindOf(got) == "":
			t.Errorf("%s: %v", c.stmt, got)
		case c.want == "withheld" && got != Withheld:
			t.Errorf("%s: %v", c.stmt, got)
		}
		if c.want == "token" && !hasNote(out, "renamed: judged as its table's columns of this type") {
			t.Errorf("%s: notes %v", c.stmt, out.Notes)
		}
	}
	out := h.run("SELECT m.meta_key AS k, m.meta_value AS v FROM wp_usermeta m", []string{"m.k VARCHAR", "m.v LONGTEXT"},
		[]Value{text("billing_first_name"), text("Ada")})
	if out.Rows[0][0] != Withheld || out.Rows[0][1] != Withheld {
		t.Errorf("meta_key AS k, meta_value AS v: %v", out.Rows[0])
	}
}

func TestAttribution(t *testing.T) {
	orders := table("orders", "id int", "customer_id int", "status varchar")
	h := newHarness(false, nil, customers(), orders)
	cases := []struct{ stmt, col string }{
		// c is defined twice: the column can't be placed, so it's computed,
		// and customers.first_name is a candidate.
		{"SELECT c.first_name FROM customers c WHERE c.id IN (SELECT c.customer_id FROM orders c)", "c.first_name VARCHAR"},
		// A joined label matching no collected alias.
		{"SELECT first_name FROM customers", "x.first_name VARCHAR"},
		// A computed column over a table with flagged columns.
		{"SELECT CONCAT(first_name, '') AS first_name FROM customers", "first_name VARCHAR"},
	}
	for _, c := range cases {
		h.calls = map[string]int{}
		out := h.run(c.stmt, []string{c.col}, []Value{text("Ada")})
		if kindOf(out.Rows[0][0]) != "person_name" || !hasNote(out, "computed: judged by its name and values") {
			t.Errorf("%s: %v, notes %v", c.stmt, out.Rows[0], out.Notes)
		}
		if h.calls["customers"] != 1 {
			t.Errorf("%s: customers judged %d times, want once", c.stmt, h.calls["customers"])
		}
	}
}

func TestKeyValue(t *testing.T) {
	usermeta := table("wp_usermeta", "umeta_id int", "user_id int", "meta_key varchar", "meta_value longtext")
	postmeta := table("wp_postmeta", "meta_id int", "post_id int", "meta_key varchar", "meta_value longtext")
	h := newHarness(false, []model.Finding{{Table: "wp_usermeta", Column: "meta_value", MetaKey: "custom_x",
		Category: model.CatEmail, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh, Matched: 5}}, usermeta, postmeta)

	out := h.run("SELECT m.meta_key, m.meta_value FROM wp_usermeta m", []string{"m.meta_key VARCHAR", "m.meta_value LONGTEXT"},
		[]Value{text("billing_first_name"), text("Ada")}, []Value{text("session_count"), text("3")},
		[]Value{text("custom_x"), text("hello")})
	if kindOf(out.Rows[0][1]) != "person_name" || out.Rows[1][1] != "3" || kindOf(out.Rows[2][1]) != "email" {
		t.Errorf("with the key: %v", out.Rows)
	}
	if !hasNote(out, "by its row's key") {
		t.Errorf("notes: %v", out.Notes)
	}

	out = h.run("SELECT m.meta_value FROM wp_usermeta m", []string{"m.meta_value LONGTEXT"}, []Value{text("Ada")})
	if out.Rows[0][0] != Withheld || !hasNote(out, "select meta_key beside meta_value") {
		t.Errorf("without the key: %v, %v", out.Rows, out.Notes)
	}

	out = h.run("SELECT a.meta_key, a.meta_value, b.meta_key, b.meta_value FROM wp_usermeta a JOIN wp_postmeta b ON b.post_id = a.user_id",
		[]string{"a.meta_key VARCHAR", "a.meta_value LONGTEXT", "b.meta_key VARCHAR", "b.meta_value LONGTEXT"},
		[]Value{text("billing_first_name"), text("Ada"), text("_order_total"), text("12.50")})
	if kindOf(out.Rows[0][1]) != "person_name" || out.Rows[0][3] != "12.50" {
		t.Errorf("two key/value tables joined: %v", out.Rows[0])
	}
}

func TestStructured(t *testing.T) {
	h := newHarness(false, []model.Finding{
		{Table: "orders", Column: "attrs", Path: "billing.email", Category: model.CatEmail, Severity: model.SeverityHigh,
			Confidence: model.ConfidenceHigh, Matched: 5},
		{Table: "orders", Column: "attrs", Path: "total", Category: model.CatCardMeta, Severity: model.SeverityLow,
			Confidence: model.ConfidenceMedium, Matched: 5},
	}, table("orders", "id int", "attrs longtext"))
	secret := "sk_" + "live_" + strings.Repeat("Ab1", 8)
	out := h.run("SELECT o.attrs FROM orders o", []string{"o.attrs LONGTEXT"},
		[]Value{text(`{"billing":{"email":"zed@fixture-mail.gr","order_ref":"A-17"},"total":"12.50"}`)},
		[]Value{text(`{"first_name":"Ada"}`)},
		[]Value{text(`{"zed@fixture-mail.gr":1}`)},
		[]Value{text(`{"token":"` + secret + `"}`)},
		[]Value{text(`{"total":12.5}`)})
	v := func(i int) string { s, _ := out.Rows[i][0].(string); return s }
	if strings.Contains(v(0), "zed@") || !strings.Contains(v(0), `"order_ref":"A-17"`) || !strings.Contains(v(0), "[card_meta ") {
		t.Errorf("a flagged path: %s", v(0))
	}
	if strings.Contains(v(1), "Ada") || !strings.Contains(v(1), "[person_name ") {
		t.Errorf("a personal key: %s", v(1))
	}
	if strings.Contains(v(2), "zed@") {
		t.Errorf("a data key: %s", v(2))
	}
	if strings.Contains(v(3), secret) || !strings.Contains(v(3), "[secret ") {
		t.Errorf("a secret in a leaf: %s", v(3))
	}
	if v(4) != Withheld {
		t.Errorf("a flagged number the editor can't write a token into: %s", v(4))
	}
}

func TestSpans(t *testing.T) {
	h := newHarness(false, nil, table("logs", "id int", "line varchar"))
	card := fixture.Samples(3, 1)["card"][0] // Luhn-valid, not a published test card
	cases := []struct {
		line       string
		gone, kept string
	}{
		{"hash *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 end", "2470C0C0", "[password_hash "},
		{"write to zed@fixture-mail.gr", "zed@", "[email "},
		{"write to ada@example.com", "", "ada@example.com"},
		{"card " + card + " here", card, "[card "},
		{"card 4242424242424242 here", "", "4242424242424242"},
		{"ip 10.20.30.40 here", "10.20.30.40", "[ip "},
		{"ip 192.0.2.10 here", "", "192.0.2.10"},
	}
	for _, c := range cases {
		got, plain := h.amongPlain(c.line)
		if !plain || c.gone != "" && strings.Contains(got, c.gone) || !strings.Contains(got, c.kept) {
			t.Errorf("%q shows as %q (plain rows as stored: %v)", c.line, got, plain)
		}
	}

	secret := "sk_" + "live_" + strings.Repeat("Ab1", 8)
	c := newHarness(true, nil, table("logs", "id int", "line varchar"))
	got, _ := c.amongPlain("zed@fixture-mail.gr " + secret)
	if !strings.Contains(got, "zed@fixture-mail.gr") || strings.Contains(got, secret) {
		t.Errorf("--copy's set: %s", got)
	}
}

func TestAccounts(t *testing.T) {
	h := newHarness(false, nil)
	out := h.run("SHOW CREATE VIEW v", []string{"View VARCHAR", "Create View VARCHAR"},
		[]Value{text("v"), text("CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v` AS select 1")})
	if s, _ := out.Rows[0][1].(string); !strings.Contains(s, "DEFINER=[account] SQL SECURITY") || strings.Contains(s, "root") {
		t.Errorf("DEFINER=: %s", s)
	}
	out = h.run("SHOW TRIGGERS", []string{"Trigger VARCHAR", "Definer VARCHAR"}, []Value{text("tr"), text("admin@10.0.0.%")})
	if out.Rows[0][1] != "[account]" {
		t.Errorf("the Definer column: %v", out.Rows[0])
	}
	out = h.run("SHOW CREATE TABLE f", []string{"Table VARCHAR", "Create Table VARCHAR"},
		[]Value{text("f"), text("CREATE TABLE `f` (`id` int) ENGINE=FEDERATED CONNECTION='mysql://app:pw@db.internal:3306/shop/t'")})
	if s, _ := out.Rows[0][1].(string); !strings.Contains(s, "CONNECTION='[redacted]'") || strings.Contains(s, "db.internal") {
		t.Errorf("CONNECTION=: %s", s)
	}
}

func TestTokens(t *testing.T) {
	h := newHarness(false, nil, customers(), table("files", "id int", "body blob"))
	out := h.run("SELECT c.first_name FROM customers c", []string{"c.first_name VARCHAR"},
		[]Value{text("Ada")}, []Value{text("Ada")}, []Value{text("Bo")})
	if out.Rows[0][0] != out.Rows[1][0] || out.Rows[0][0] == out.Rows[2][0] || kindOf(out.Rows[0][0]) == "" {
		t.Errorf("equal values, equal tokens: %v", out.Rows)
	}
	if h.r.Token("email", []byte("x")) == h.r.Token("person_name", []byte("x")) {
		t.Error("different kinds give the same token")
	}
	other := New(Source{}, false, []byte(strings.Repeat("k", 32)))
	if other.Token("email", []byte("x")) == h.r.Token("email", []byte("x")) {
		t.Error("two keys give the same token")
	}
	out = h.run("SELECT f.body FROM files f", []string{"f.body BLOB"},
		[]Value{{Bytes: []byte{1, 2, 3}}}, []Value{{Bytes: []byte{1, 2, 3}}})
	if s, _ := out.Rows[0][0].(string); !regexp.MustCompile(`^\[binary 3 bytes [0-9a-f]{12}\]$`).MatchString(s) || out.Rows[1][0] != s {
		t.Errorf("binary values: %v", out.Rows)
	}
}

func TestWithheld(t *testing.T) {
	h := newHarness(false, []model.Finding{{Table: "logs", Column: "line", Path: "total", Category: model.CatCardMeta,
		Severity: model.SeverityLow, Confidence: model.ConfidenceMedium, Matched: 5}}, table("logs", "id int", "line varchar"))
	out := h.run("SELECT l.line FROM logs l", []string{"l.line VARCHAR"},
		[]Value{{Withheld: 2 << 20}}, []Value{{Bytes: []byte{0xff, 0xfe, 'a'}}}, []Value{text(`{"total":12.5}`)}, []Value{{Null: true}})
	for i := range 3 {
		if out.Rows[i][0] != Withheld {
			t.Errorf("row %d: %v", i, out.Rows[i][0])
		}
	}
	if out.Rows[3][0] != nil || out.Withheld != 3 {
		t.Errorf("NULL: %v; withheld %d", out.Rows[3][0], out.Withheld)
	}
	for _, want := range []string{"withheld (over 1 MiB)", "withheld (not valid UTF-8)", "withheld (a structured value prodmask couldn't edit)"} {
		if !hasNote(out, want) {
			t.Errorf("notes lack %q: %v", want, out.Notes)
		}
	}
}

func TestErrorsAndWarnings(t *testing.T) {
	cases := []struct{ got, want string }{
		{ErrorWords(1146, "42S02", "Table 'shop.secret_t' doesn't exist", "SELECT 1"),
			"MySQL error 1146: a table the statement names doesn't exist; list_tables lists the tables"},
		{ErrorWords(1064, "42000", "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'FRM t' at line 1", "SELECT * FRM t"),
			"MySQL error 1064: a syntax error near 'FRM t'"},
		{ErrorWords(1064, "42000", "You have an error in your SQL syntax; ... near 'Smith' at line 1", "SELECT 1"),
			"MySQL error 1064: a syntax error, message withheld"},
		{ErrorWords(1644, "45000", "customer Ada Lovelace is blocked", "SELECT shop.f()"), "MySQL error 1644 (45000), message withheld"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	if w, ok := WarningWords("Warning", 1292, "Truncated incorrect DOUBLE value: 'Smith'", ""); !ok || w != "warning 1292, message withheld" {
		t.Errorf("1292: %q", w)
	}
	if _, ok := WarningWords("Note", 1003, "/* select#1 */ select 'Ada' AS `first_name`", ""); ok {
		t.Error("note 1003 isn't dropped")
	}
}

func TestCaps(t *testing.T) {
	h := newHarness(false, nil, table("logs", "id int", "line varchar"))
	got, plain := h.amongPlain(strings.Repeat("a", 990) + " zed@fixture-mail.gr " + strings.Repeat("b", 100))
	if want := strings.Repeat("a", 990) + " …(121 more characters)"; got != want || !plain {
		t.Errorf("the cut at 1,000 characters: %q", got)
	}
	var rows [][]Value
	for range 400 {
		rows = append(rows, []Value{text(strings.Repeat("c", 1000))})
	}
	out := h.run("SELECT l.line FROM logs l", []string{"l.line VARCHAR"}, rows...)
	if !out.Stopped || len(out.Rows) >= 400 || len(out.Rows) < 200 || !hasNote(out, "the result stopped at 256 KB") {
		t.Errorf("the 256 KB stop: %d rows, stopped %v", len(out.Rows), out.Stopped)
	}
}

// TestProperty writes each of the fixture's invented emails, phones, cards,
// IBANs and secrets into plain words, among plain rows, in a column the name
// rules don't flag: none comes back. A secret may flag the whole column by
// the result's own values; the others must be found as spans, with the
// plain rows shown as stored.
func TestProperty(t *testing.T) {
	h := newHarness(false, nil, table("logs", "id int", "line varchar"))
	for kind, values := range fixture.Samples(42, 25) {
		for _, v := range values {
			got, plain := h.amongPlain("Please get back to me about order 42 at " + v + " today, thanks")
			if strings.Contains(got, v) {
				t.Errorf("%s %q came back: %q", kind, v, got)
			}
			if kind != "secret" && (!plain || !strings.HasPrefix(got, "Please get back to me about order 42 at [")) {
				t.Errorf("%s %q was replaced with the column, not as a span: %q", kind, v, got)
			}
		}
	}
}

// plainRows are rows of plain words, which no rule flags: a value planted
// among them is a small share of the result, as most data in free text is,
// so the result's own values don't flag the column and the spans must find
// it.
func plainRows(n int) [][]Value {
	var rows [][]Value
	for i := range n {
		rows = append(rows, []Value{text("The parcel arrived on time and the colour fits well, order " + strconv.Itoa(i))})
	}
	return rows
}

// amongPlain shows one value among plain rows, in a column the name rules
// don't flag, and returns how it shows and whether the plain rows show as
// stored.
func (h *harness) amongPlain(value string) (string, bool) {
	rows := append([][]Value{{text(value)}}, plainRows(40)...)
	out := h.run("SELECT l.line FROM logs l", []string{"l.line VARCHAR"}, rows...)
	s, _ := out.Rows[0][0].(string)
	plain, _ := out.Rows[1][0].(string)
	return s, strings.HasPrefix(plain, "The parcel arrived")
}

// TestReviewCases holds the review's cases: SHOW TRIGGERS' Definer column
// after a leading comment; a number and an array element under a key that
// says personal data; a column of a statement the alias collector can't
// read, judged as computed.
func TestReviewCases(t *testing.T) {
	h := newHarness(false, nil, customers(), table("orders", "id int", "attrs longtext"))
	for _, stmt := range []string{"-- triggers\nSHOW TRIGGERS", "/**/SHOW TRIGGERS", "(SHOW TRIGGERS)"} {
		out := h.run(stmt, []string{"Trigger VARCHAR", "Definer VARCHAR"}, []Value{text("tr"), text("root@localhost")})
		if stmt != "(SHOW TRIGGERS)" && out.Rows[0][1] != "[account]" {
			t.Errorf("%q: the Definer column shows %v", stmt, out.Rows[0][1])
		}
	}
	out := h.run("SELECT o.attrs FROM orders o", []string{"o.attrs LONGTEXT"},
		[]Value{text(`{"phone":4915123456789}`)}, []Value{text(`{"first_name":["Ada","Bo"],"total":"12.50"}`)})
	if out.Rows[0][0] != Withheld {
		t.Errorf("a number under phone: %v", out.Rows[0][0])
	}
	if s, _ := out.Rows[1][0].(string); strings.Contains(s, "Ada") || strings.Contains(s, "Bo\"") || !strings.Contains(s, "12.50") {
		t.Errorf("array elements under first_name: %s", s)
	}
	// customers' alias stands after FOR SYSTEM_TIME, where the collector
	// misses it, and the subquery's c is orders: the label is computed, not
	// tied to orders.
	out = h.run("SELECT c.first_name FROM customers FOR SYSTEM_TIME ALL c WHERE EXISTS (SELECT 1 FROM orders c)",
		[]string{"c.first_name VARCHAR"}, []Value{text("Ada")})
	if kindOf(out.Rows[0][0]) != "person_name" || !hasNote(out, "computed") {
		t.Errorf("FOR SYSTEM_TIME: %v, notes %v", out.Rows[0], out.Notes)
	}
}

// TestMetadata: a SHOW's or information_schema's result is shown with the
// span finders only, as list_tables and describe_table show names and
// comments, while an email in a comment is still replaced.
func TestMetadata(t *testing.T) {
	h := newHarness(false, nil, customers())
	out := h.run("SHOW TABLE STATUS", []string{"Name VARCHAR", "Comment VARCHAR"},
		[]Value{text("notes"), text("Notes left by the support team")}, []Value{text("customers"), text("ask ada@fixture-mail.gr")})
	if out.Rows[0][0] != "notes" || out.Rows[0][1] != "Notes left by the support team" || out.Rows[1][0] != "customers" {
		t.Errorf("SHOW TABLE STATUS: %v", out.Rows)
	}
	if s, _ := out.Rows[1][1].(string); strings.Contains(s, "ada@") {
		t.Errorf("an email in a comment: %v", out.Rows[1][1])
	}
	out = h.run("SELECT TABLE_NAME, COLUMN_NAME, COLUMN_COMMENT FROM information_schema.COLUMNS",
		[]string{"COLUMNS.TABLE_NAME VARCHAR", "COLUMNS.COLUMN_NAME VARCHAR", "COLUMNS.COLUMN_COMMENT VARCHAR"},
		[]Value{text("customers"), text("first_name"), text("Given name, as typed at sign-up")})
	if out.Rows[0][1] != "first_name" || out.Rows[0][2] != "Given name, as typed at sign-up" {
		t.Errorf("information_schema.COLUMNS: %v", out.Rows)
	}
}

// TestUnsampledNote: a table whose sample failed is named in a note.
func TestUnsampledNote(t *testing.T) {
	schema := &model.Schema{Database: "shop", Tables: []*model.Table{customers()}}
	r := New(Source{Schema: schema, Judge: func(ctx context.Context, t *model.Table) scan.TableVerdict {
		v := scan.JudgeTable(ctx, nil, nil, t, scan.Options{})
		v.SampleErr = errors.New("timed out")
		return v
	}}, false, make([]byte, 32))
	out := r.Result(context.Background(), "SELECT c.note FROM customers c", []Column{{Name: "c.note", Type: "VARCHAR"}}, [][]Value{{text("x")}})
	if !hasNote(out, "customers couldn't be sampled") {
		t.Errorf("no note for the table that couldn't be sampled: %v", out.Notes)
	}
}

// TestKeysWithoutCase: a row's key matches the scan's key, or a family's
// pattern, whatever its case, as the scan's own key matching does; and every
// family that matches counts, the worst winning.
func TestKeysWithoutCase(t *testing.T) {
	usermeta := table("wp_usermeta", "umeta_id int", "user_id int", "meta_key varchar", "meta_value longtext")
	h := newHarness(false, []model.Finding{
		{Table: "wp_usermeta", Column: "meta_value", MetaKey: "custom_x", Category: model.CatEmail, Severity: model.SeverityHigh,
			Confidence: model.ConfidenceHigh, Matched: 5},
		{Table: "wp_usermeta", Column: "meta_value", MetaKey: "acme_*", Category: model.CatCardMeta, Severity: model.SeverityLow,
			Confidence: model.ConfidenceMedium, Matched: 5},
		{Table: "wp_usermeta", Column: "meta_value", MetaKey: "*_contact", Category: model.CatPhone, Severity: model.SeverityHigh,
			Confidence: model.ConfidenceHigh, Matched: 5},
	}, usermeta)
	out := h.run("SELECT m.meta_key, m.meta_value FROM wp_usermeta m", []string{"m.meta_key VARCHAR", "m.meta_value LONGTEXT"},
		[]Value{text("Custom_X"), text("plain words")}, []Value{text("ACME_Contact"), text("more plain words")})
	if kindOf(out.Rows[0][1]) != "email" {
		t.Errorf("an exact key in another case: %v", out.Rows[0])
	}
	if kindOf(out.Rows[1][1]) != "phone" {
		t.Errorf("two families in another case, the worst winning: %v", out.Rows[1])
	}
}

// TestMetadataBackstop: a statement the alias walk takes as reading only
// information_schema, but which names one of the session's tables, isn't
// shown as metadata.
func TestMetadataBackstop(t *testing.T) {
	h := newHarness(false, nil, customers())
	for q, want := range map[string]bool{
		"SELECT TABLE_NAME, TABLE_COMMENT FROM information_schema.TABLES":     false,
		"SELECT ENGINE, customers.first_name FROM information_schema.ENGINES": true,
	} {
		if got := h.r.namesTable(dbconn.StatementAliases(q).Names); got != want {
			t.Errorf("%s: names a session table: %v, want %v", q, got, want)
		}
	}
}
