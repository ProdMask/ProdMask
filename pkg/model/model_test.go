package model

import "testing"

// A full-text index serves neither = nor LIKE 'prefix%', so key lookups
// can't use it.
func TestKeyIndex(t *testing.T) {
	tbl := &Table{Indexes: []Index{{Name: "ft", Type: "FULLTEXT", Columns: []string{"meta_key"}, SubParts: []int{0}}}}
	if tbl.KeyIndex("meta_key").Found {
		t.Error("full-text index used for key lookups")
	}
	tbl.Indexes = append(tbl.Indexes, Index{Name: "meta_key", Type: "BTREE", Columns: []string{"meta_key"}, SubParts: []int{191}})
	if u := tbl.KeyIndex("meta_key"); !u.Found || u.Full || u.Unique {
		t.Errorf("prefix index: %+v", u)
	}
	tbl.Indexes = append(tbl.Indexes, Index{Name: "u", Type: "BTREE", Unique: true, Columns: []string{"meta_key"}, SubParts: []int{0}})
	if u := tbl.KeyIndex("meta_key"); !u.Found || !u.Full || !u.Unique {
		t.Errorf("unique index: %+v", u)
	}
}
