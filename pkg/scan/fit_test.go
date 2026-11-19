package scan

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"strconv"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// TestFakeWidths pins the width table prodmask Pro checks against its
// generators: a changed number must fail here first.
func TestFakeWidths(t *testing.T) {
	want := map[string]FakeWidth{
		"fake_email": {13, 15}, "fake_username": {4, 5}, "fake_name": {1, 10},
		"fake_first_name": {1, 0}, "fake_last_name": {1, 0}, "fake_company": {1, 12},
		"fake_street": {5, 12}, "fake_city": {4, 0}, "fake_postcode": {3, 0},
		"fake_user_agent": {70, 0}, "fake_phone": {1, 11}, "test_card": {1, 12},
		"fake_ip": {1, 1}, "fake_iban": {1, 1}, "fake_date": {1, 0},
	}
	got := FakeWidths()
	if !maps.Equal(got, want) {
		t.Errorf("FakeWidths() = %v, want %v", got, want)
	}
	got["fake_email"] = FakeWidth{}
	if FakeWidths()["fake_email"] != want["fake_email"] {
		t.Error("FakeWidths returns the table itself, not a copy")
	}
}

func newColumn(name, dataType string, maxLength int64) *model.Column {
	return &model.Column{Name: name, DataType: dataType, MaxLength: maxLength}
}

// TestJudge decides each column's outcome at its boundaries: a fake one
// character short of fitting, and one that fits; one width short of keeping
// 8,192 values apart in a unique column, and one that does; a fake that
// never does; a unique column of 3 and of 4 under a fake, a hash and a
// prefix, where only 3 is too short for a fake or a hash; and the columns
// and masks it leaves alone.
func TestJudge(t *testing.T) {
	noFit := func(mask, holds string, needs int) string {
		return "hash, not " + mask + ", since the column holds " + holds + " and " + mask + " needs " + strconv.Itoa(needs)
	}
	tooFew := func(mask string) string {
		return "hash, not " + mask + ", since this unique column needs more different values than " + mask + " makes"
	}
	cases := []struct {
		name        string
		col         *model.Column
		mask        string
		uniqueWidth int
		note        string
		short       bool
	}{
		{"one character short", newColumn("e", "varchar", 12), "fake_email", 0, noFit("fake_email", "12 characters", 13), false},
		{"one character", newColumn("e", "char", 1), "fake_email", 0, noFit("fake_email", "1 character", 13), false},
		{"bytes", newColumn("e", "varbinary", 2), "fake_email", 0, noFit("fake_email", "2 bytes", 13), false},
		{"one byte", newColumn("e", "binary", 1), "fake_street", 0, noFit("fake_street", "1 byte", 5), false},
		{"it fits", newColumn("e", "varchar", 13), "fake_email", 0, "", false},
		{"it fits, unique too short", newColumn("e", "varchar", 14), "fake_email", 14, tooFew("fake_email"), false},
		{"it fits, unique wide enough", newColumn("e", "varchar", 15), "fake_email", 15, "", false},
		{"a prefix too short for the fake's values", newColumn("e", "varchar", 255), "fake_email", 14, tooFew("fake_email"), false},
		{"a fake that never keeps them apart", newColumn("c", "varchar", 50), "fake_city", 50, tooFew("fake_city"), false},
		{"a card", newColumn("n", "varchar", 11), "test_card", 11, tooFew("test_card"), false},
		{"a card wide enough", newColumn("n", "varchar", 12), "test_card", 12, "", false},
		{"an IP address keeps them apart at any width", newColumn("ip", "char", 2), "fake_ip", 2, "", false},
		{"an IBAN too", newColumn("i", "char", 2), "fake_iban", 2, "", false},
		{"an IBAN in one byte", newColumn("i", "varbinary", 1), "fake_iban", 1, "", false},
		{"not unique, it fits", newColumn("c", "varchar", 50), "fake_city", 0, "", false},
		{"a short unique column under a fake, at 3", newColumn("z", "char", 3), "fake_postcode", 3, tooFew("fake_postcode"), true},
		{"a unique column under a fake, at 4", newColumn("c", "char", 4), "fake_city", 4, tooFew("fake_city"), false},
		{"a short unique column under a hash, at 3", newColumn("h", "varchar", 3), "hash", 3, "", true},
		{"a unique column under a hash, at 4", newColumn("h", "varchar", 4), "hash", 4, "", false},
		{"a unique prefix of 3 on a wide column", newColumn("e", "varchar", 255), "fake_email", 3, tooFew("fake_email"), true},
		{"a number column", newColumn("n", "int", 0), "fake_phone", 0, "", false},
		{"JSON", newColumn("j", "json", 0), "fake_name", 0, "", false},
		{"a mask that isn't a fake", newColumn("c", "char", 1), "redact", 1, "", false},
		{"fake_number isn't in the table", newColumn("c", "char", 1), "fake_number", 1, "", false},
	}
	for _, c := range cases {
		if note, short := judge(c.col, c.mask, c.uniqueWidth); note != c.note || short != c.short {
			t.Errorf("%s: judge = %q, %v; want %q, %v", c.name, note, short, c.note, c.short)
		}
	}
}

// TestUniqueWidths gives each unique column the width of its tightest
// unique prefix: the primary key's, a unique index's whole column or
// prefix, the narrowest of two, a composite index's columns; and no width
// to a column only in an ordinary index, a generated column or an
// expression's part.
func TestUniqueWidths(t *testing.T) {
	gen := newColumn("lower_code", "varchar", 10)
	gen.Extra = "VIRTUAL GENERATED"
	tbl := &model.Table{Name: "items", Columns: []*model.Column{newColumn("id", "char", 2), newColumn("slug", "varchar", 200),
		newColumn("sku", "varchar", 40), newColumn("a", "char", 5), newColumn("b", "char", 3), newColumn("plain", "char", 1), gen},
		PrimaryKey: []string{"id"},
		Indexes: []model.Index{
			{Name: "PRIMARY", Unique: true, Columns: []string{"id"}, SubParts: []int{0}},
			{Name: "slug", Unique: true, Columns: []string{"slug"}, SubParts: []int{20}},
			{Name: "slug_short", Unique: true, Columns: []string{"Slug"}, SubParts: []int{8}},
			{Name: "sku", Unique: true, Columns: []string{"sku"}, SubParts: []int{0}},
			{Name: "a_b", Unique: true, Columns: []string{"a", "b"}, SubParts: []int{0, 0}},
			{Name: "plain", Columns: []string{"plain"}, SubParts: []int{0}},
			{Name: "lower", Unique: true, Columns: []string{"lower_code", ""}, SubParts: []int{0, 0}},
		}}
	names := func(tbl *model.Table) map[string]int {
		got := map[string]int{}
		for c, w := range uniqueWidths(tbl) {
			got[c.Name] = w
		}
		return got
	}
	want := map[string]int{"id": 2, "slug": 8, "sku": 40, "a": 5, "b": 3}
	if got := names(tbl); !maps.Equal(got, want) {
		t.Errorf("uniqueWidths = %v, want %v", got, want)
	}
	// A table whose indexes don't list its primary key, as one built by hand
	// may not, still has the key's columns unique, at their full width.
	bare := &model.Table{Name: "codes", Columns: []*model.Column{newColumn("code", "char", 3), newColumn("label", "varchar", 40)},
		PrimaryKey: []string{"code"}}
	if got, want := names(bare), map[string]int{"code": 3}; !maps.Equal(got, want) {
		t.Errorf("uniqueWidths of a primary key alone = %v, want %v", got, want)
	}
}

// TestFitFakes runs the pass as the scan does, after hashUnique, on tables
// with made-up names: the three shapes of old dumps it was made for, a
// short unique column, row masks, a prefix index, bytes, a composite unique
// index and a card; and what it leaves alone.
func TestFitFakes(t *testing.T) {
	rules := &model.Table{Name: "fraud_rules", Columns: []*model.Column{newColumn("rule_email", "char", 1), newColumn("note", "varchar", 255)}}
	brokers := &model.Table{Name: "brokers", Columns: []*model.Column{newColumn("agent_code", "varchar", 255)},
		Indexes: []model.Index{{Name: "agent_code", Unique: true, Columns: []string{"agent_code"}, SubParts: []int{0}}}}
	towns := &model.Table{Name: "towns", Columns: []*model.Column{newColumn("town_name", "varchar", 50), newColumn("code", "char", 2),
		newColumn("pin", "int", 0), newColumn("token", "varchar", 4), newColumn("short_token", "char", 2),
		newColumn("raw", "varbinary", 2), newColumn("blob_email", "varbinary", 8), newColumn("zone", "char", 5), newColumn("zip", "char", 3),
		newColumn("card", "varchar", 11), newColumn("slug", "varchar", 255), newColumn("doc", "varchar", 255), newColumn("cc", "char", 2)},
		Indexes: []model.Index{
			{Name: "town_name", Unique: true, Columns: []string{"town_name"}, SubParts: []int{0}},
			{Name: "code", Unique: true, Columns: []string{"code"}, SubParts: []int{0}},
			{Name: "token", Unique: true, Columns: []string{"token"}, SubParts: []int{0}},
			{Name: "short_token", Unique: true, Columns: []string{"short_token"}, SubParts: []int{0}},
			{Name: "raw", Unique: true, Columns: []string{"raw"}, SubParts: []int{0}},
			{Name: "zone_zip", Unique: true, Columns: []string{"zone", "zip"}, SubParts: []int{0, 0}},
			{Name: "card", Unique: true, Columns: []string{"card"}, SubParts: []int{0}},
			{Name: "slug", Unique: true, Columns: []string{"slug"}, SubParts: []int{10}},
			{Name: "cc", Unique: true, Columns: []string{"cc"}, SubParts: []int{0}},
		}}
	noFit := func(mask, holds string, needs string) string {
		return "hash, not " + mask + ", since the column holds " + holds + " and " + mask + " needs " + needs
	}
	tooFew := func(mask string) string {
		return "hash, not " + mask + ", since this unique column needs more different values than " + mask + " makes"
	}
	where := "kind = 'b'"
	type fitted struct {
		mask, note string
		rows       []model.RowMask
		pro        bool
	}
	cases := []struct {
		name  string
		table *model.Table
		f     model.Finding
		want  fitted
	}{
		{"a fake that can't fit", rules, model.Finding{Column: "rule_email", Mask: "fake_email"},
			fitted{"hash", noFit("fake_email", "1 character", "13"), nil, false}},
		{"a unique column with too few fakes", brokers, model.Finding{Column: "agent_code", Mask: "fake_user_agent"},
			fitted{"hash", tooFew("fake_user_agent"), nil, false}},
		{"a unique town", towns, model.Finding{Column: "town_name", Mask: "fake_city", Note: "towns"},
			fitted{"hash", "towns; " + tooFew("fake_city"), nil, false}},
		{"a short unique column", towns, model.Finding{Column: "code", Mask: "fake_city"},
			fitted{"hash", noFit("fake_city", "2 characters", "4"), nil, true}},
		{"row masks", rules, model.Finding{Column: "rule_email", Mask: "keep", RowMasks: []model.RowMask{
			{Where: where, Mask: "fake_email", Note: "brokers"}, {Where: "kind = 'a'", Mask: "redact"}}},
			fitted{"keep", "", []model.RowMask{{Where: where, Mask: "hash", Note: "brokers; " + noFit("fake_email", "1 character", "13")},
				{Where: "kind = 'a'", Mask: "redact"}}, false}},
		{"a short unique column's row mask", towns, model.Finding{Column: "code", Mask: "keep", RowMasks: []model.RowMask{
			{Where: where, Mask: "fake_postcode"}}},
			fitted{"keep", "", []model.RowMask{{Where: where, Mask: "hash", Note: noFit("fake_postcode", "2 characters", "3")}}, true}},
		{"a prefix index", towns, model.Finding{Column: "slug", Mask: "fake_email"}, fitted{"hash", tooFew("fake_email"), nil, false}},
		{"bytes that can't fit", towns, model.Finding{Column: "blob_email", Mask: "fake_email"},
			fitted{"hash", noFit("fake_email", "8 bytes", "13"), nil, false}},
		{"short unique bytes under a hash", towns, model.Finding{Column: "raw", Mask: "hash", Note: "device IDs"},
			fitted{"hash", "device IDs", nil, true}},
		{"a composite unique index", towns, model.Finding{Column: "zip", Mask: "fake_postcode"},
			fitted{"hash", tooFew("fake_postcode"), nil, true}},
		{"a card", towns, model.Finding{Column: "card", Mask: "test_card"}, fitted{"hash", tooFew("test_card"), nil, false}},
		{"hashUnique's rewrite on a short unique column", towns, model.Finding{Column: "short_token", Mask: "null"},
			fitted{"hash", nullUniqueNote, nil, true}},

		// Left alone.
		{"a fake that fits", rules, model.Finding{Column: "note", Mask: "fake_email"}, fitted{"fake_email", "", nil, false}},
		{"a number column", towns, model.Finding{Column: "pin", Mask: "fake_phone"}, fitted{"fake_phone", "", nil, false}},
		{"a path", rules, model.Finding{Column: "rule_email", Path: "contact.email", Mask: "fake_email"},
			fitted{"fake_email", "", nil, false}},
		{"key names", rules, model.Finding{Column: "rule_email", KeyName: true, Mask: "fake_email"},
			fitted{"fake_email", "", nil, false}},
		{"hashUnique's rewrite on a column of 4 characters", towns, model.Finding{Column: "token", Mask: "null"},
			fitted{"hash", nullUniqueNote, nil, false}},
		{"a mask that isn't a fake on a short unique column", towns, model.Finding{Column: "code", Mask: "redact"},
			fitted{"redact", "", nil, false}},
		{"a country kept on a short unique column", towns, model.Finding{Column: "cc", Mask: "keep"},
			fitted{"keep", "", nil, false}},
		{"an IP address on a short unique column", towns, model.Finding{Column: "cc", Mask: "fake_ip"},
			fitted{"fake_ip", "", nil, false}},
	}
	for _, c := range cases {
		f := c.f
		f.Table, f.Category = c.table.Name, model.CatCity
		fs := []model.Finding{f}
		hashUnique(c.table, fs)
		fitFakes(c.table, fs)
		got := fitted{fs[0].Mask, fs[0].Note, fs[0].RowMasks, fs[0].ProChooses}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
		if fs[0].Category != model.CatCity {
			t.Errorf("%s: the category changed to %v", c.name, fs[0].Category)
		}
	}
}

// TestProChoosesNotInJSON checks that the mark stays in the process: a
// marked finding's JSON is byte for byte an unmarked one's.
func TestProChoosesNotInJSON(t *testing.T) {
	plain := model.Finding{Table: "t", Column: "c", Mask: "hash", Note: "n"}
	marked := plain
	marked.ProChooses = true
	a, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(marked)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("a marked finding's JSON differs:\n%s\n%s", b, a)
	}
}
