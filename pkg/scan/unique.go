package scan

import (
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// The notes hashUnique adds to a mask it rewrites: the starter config's
// comment shows them, so it says why the mask isn't the category's.
const (
	nullUniqueNote  = "hash, not null, since null would give every row of this NOT NULL unique column the same value"
	emptyUniqueNote = "hash, not empty, since empty would give every row of this unique column the same value"
)

// hashUnique rewrites the masks that would give every row of a unique column
// the same value, so a copy that follows them would fail on the second row:
// null in a NOT NULL column, which writes the type's empty value there, and
// empty in any. Where the column is part of the primary key or of a unique
// index, prefix ones included, and holds text or bytes, the finding's mask
// becomes hash, which keeps the values apart, with a note that says why;
// its row masks are rewritten the same way. A key's finding is its value
// column's. Findings about a path inside a value, or about keys' names,
// are left alone, as are the parts of an index on an expression and
// generated columns, whose values the server computes.
func hashUnique(t *model.Table, findings []model.Finding) {
	widths := uniqueWidths(t)
	for i := range findings {
		f := &findings[i]
		c := t.Column(f.Column)
		_, unique := widths[c]
		if f.Path != "" || f.KeyName || c == nil || !unique || !takesHash(c) {
			continue
		}
		if note := clearingNote(c, f.Mask); note != "" {
			f.Mask, f.Note = "hash", addNote(f.Note, note)
		}
		for j := range f.RowMasks {
			rm := &f.RowMasks[j]
			if note := clearingNote(c, rm.Mask); note != "" {
				rm.Mask, rm.Note = "hash", addNote(rm.Note, note)
			}
		}
	}
}

// generated reports a column whose values the server computes.
func generated(c *model.Column) bool {
	extra := strings.ToUpper(c.Extra)
	return strings.Contains(extra, "VIRTUAL GENERATED") || strings.Contains(extra, "STORED GENERATED")
}

// takesHash reports a column a hash can fill: text, CHAR, VARCHAR and the
// TEXT types, but not JSON, and bytes, BINARY, VARBINARY and the BLOBs.
func takesHash(c *model.Column) bool {
	switch c.DataType {
	case "char", "varchar", "tinytext", "text", "mediumtext", "longtext":
		return true
	}
	return binary(c)
}

// binary reports a column of bytes, whose width counts bytes.
func binary(c *model.Column) bool {
	switch c.DataType {
	case "binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob":
		return true
	}
	return false
}

// clearingNote is the note for a mask that would give every row of a unique
// column the same value, or "" for one that doesn't.
func clearingNote(c *model.Column, mask string) string {
	switch {
	case mask == "empty":
		return emptyUniqueNote
	case mask == "null" && !c.Nullable:
		return nullUniqueNote
	}
	return ""
}

func addNote(note, more string) string {
	if note == "" {
		return more
	}
	return note + "; " + more
}
