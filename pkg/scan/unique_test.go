package scan

import (
	"reflect"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// A mask that would give every row of a unique column the same value
// becomes hash, with a note that says why: null in a NOT NULL column of the
// primary key or of a unique index, prefix ones included, and empty in any
// such column, of text or bytes, row masks and findings limited by a Where
// included, and a key's finding on its value column. A nullable column's
// null, columns of other types, generated columns, index parts on
// expressions, paths and key names keep their masks.
func TestHashUnique(t *testing.T) {
	column := func(name, dataType string, nullable bool) *model.Column {
		return &model.Column{Name: name, DataType: dataType, Nullable: nullable}
	}
	gen := column("lower_token", "varchar", false)
	gen.Extra = "STORED GENERATED"
	accounts := &model.Table{Name: "accounts", Columns: []*model.Column{column("code", "varchar", false),
		column("token", "varchar", false), column("secret", "text", false), column("raw", "varbinary", false),
		column("nick", "varchar", true), column("doc", "json", false), column("pin", "int", false), column("born", "date", false),
		gen, column("note", "varchar", false), column("plain", "varchar", false)},
		PrimaryKey: []string{"code"},
		Indexes: []model.Index{
			{Name: "PRIMARY", Unique: true, Columns: []string{"code"}, SubParts: []int{0}},
			{Name: "token", Unique: true, Columns: []string{"Token"}, SubParts: []int{0}},
			{Name: "secret", Unique: true, Columns: []string{"secret"}, SubParts: []int{32}},
			{Name: "raw_nick", Unique: true, Columns: []string{"raw", "nick"}, SubParts: []int{0, 0}},
			{Name: "others", Unique: true, Columns: []string{"doc", "pin", "born", "lower_token"}, SubParts: []int{0, 0, 0, 0}},
			{Name: "by_note", Unique: true, Columns: []string{""}, SubParts: []int{0}}, // an expression that reads note
			{Name: "plain", Columns: []string{"plain"}, SubParts: []int{0}},
		}}
	settings := &model.Table{Name: "settings", Columns: []*model.Column{column("id", "int", false), column("k", "varchar", false),
		column("v", "varchar", false)}, PrimaryKey: []string{"id"},
		Indexes: []model.Index{{Name: "PRIMARY", Unique: true, Columns: []string{"id"}}, {Name: "k", Unique: true, Columns: []string{"k"}},
			{Name: "v", Unique: true, Columns: []string{"v"}}}}

	type masked struct {
		mask, note string
		rows       []model.RowMask
	}
	where := "status = 'closed'"
	cases := []struct {
		name  string
		table *model.Table
		f     model.Finding
		want  masked
	}{
		{"the primary key's null", accounts, model.Finding{Column: "code", Mask: "null"}, masked{"hash", nullUniqueNote, nil}},
		{"a unique index's null, and the note after the finding's", accounts,
			model.Finding{Column: "token", Mask: "null", Note: "API tokens"}, masked{"hash", "API tokens; " + nullUniqueNote, nil}},
		{"a prefix index's null", accounts, model.Finding{Column: "secret", Mask: "null"}, masked{"hash", nullUniqueNote, nil}},
		{"bytes", accounts, model.Finding{Column: "raw", Mask: "null"}, masked{"hash", nullUniqueNote, nil}},
		{"an empty in a nullable column", accounts, model.Finding{Column: "nick", Mask: "empty"}, masked{"hash", emptyUniqueNote, nil}},
		{"row masks", accounts, model.Finding{Column: "secret", Mask: "redact", RowMasks: []model.RowMask{
			{Where: where, Mask: "null", Note: "closed accounts"}, {Where: "status = 'open'", Mask: "empty"},
			{Where: "status = 'new'", Mask: "fake_email"}}},
			masked{"redact", "", []model.RowMask{{Where: where, Mask: "hash", Note: "closed accounts; " + nullUniqueNote},
				{Where: "status = 'open'", Mask: "hash", Note: emptyUniqueNote}, {Where: "status = 'new'", Mask: "fake_email"}}}},
		{"a finding limited by a Where", accounts, model.Finding{Column: "token", Where: where, Mask: "null"},
			masked{"hash", nullUniqueNote, nil}},
		{"a key's finding on a unique value column", settings, model.Finding{Column: "v", MetaKey: "api_token", Mask: "null"},
			masked{"hash", nullUniqueNote, nil}},

		{"a nullable column's null", accounts, model.Finding{Column: "nick", Mask: "null"}, masked{"null", "", nil}},
		{"a fake", accounts, model.Finding{Column: "token", Mask: "fake_email"}, masked{"fake_email", "", nil}},
		{"json", accounts, model.Finding{Column: "doc", Mask: "null"}, masked{"null", "", nil}},
		{"an int", accounts, model.Finding{Column: "pin", Mask: "empty"}, masked{"empty", "", nil}},
		{"a date", accounts, model.Finding{Column: "born", Mask: "null"}, masked{"null", "", nil}},
		{"a generated column", accounts, model.Finding{Column: "lower_token", Mask: "null"}, masked{"null", "", nil}},
		{"a column only an expression reads", accounts, model.Finding{Column: "note", Mask: "null"}, masked{"null", "", nil}},
		{"a column of no unique index", accounts, model.Finding{Column: "plain", Mask: "empty"}, masked{"empty", "", nil}},
		{"a path", accounts, model.Finding{Column: "secret", Path: "a.b", Mask: "null"}, masked{"null", "", nil}},
		{"a path in a key's values", settings, model.Finding{Column: "v", MetaKey: "api_token", Path: "a.b", Mask: "null"},
			masked{"null", "", nil}},
		{"a key name", settings, model.Finding{Column: "k", MetaKey: "um_*", KeyName: true, Mask: "null"}, masked{"null", "", nil}},
		{"a column the table doesn't have", accounts, model.Finding{Column: "gone", Mask: "null"}, masked{"null", "", nil}},
	}
	for _, c := range cases {
		f := c.f
		f.Table = c.table.Name
		findings := []model.Finding{f}
		hashUnique(c.table, findings)
		got := findings[0]
		if got.Mask != c.want.mask || got.Note != c.want.note || !reflect.DeepEqual(got.RowMasks, c.want.rows) {
			t.Errorf("%s: mask %q, note %q, rows %+v", c.name, got.Mask, got.Note, got.RowMasks)
		}
	}

	// The findings are rewritten in place, each by its own column.
	findings := []model.Finding{{Table: "accounts", Column: "nick", Mask: "null"}, {Table: "accounts", Column: "token", Mask: "null"}}
	hashUnique(accounts, findings)
	if findings[0].Mask != "null" || findings[1].Mask != "hash" {
		t.Errorf("got %+v", findings)
	}
}
