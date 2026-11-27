package sqldump

import (
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// colDefault is a column's DEFAULT clause, kept beside the table's structure
// for the DEFAULT keyword in a row.
type colDefault struct {
	// set is true when the column has a DEFAULT clause at all.
	set bool
	// expr is true when the default is an expression, such as
	// CURRENT_TIMESTAMP or a function call; DEFAULT in a row is then NULL.
	expr bool
	// kind is how the literal was written: ValString for a quoted one,
	// ValNumber, ValHex, ValBit, or ValNull for DEFAULT NULL.
	kind ValueKind
	text string
}

// tableInfo is what the reader keeps of one table: the structure it hands to
// the visitor, and what the visitor's table has no field for.
type tableInfo struct {
	t *model.Table
	// defaults holds each column's DEFAULT clause, in the order of t.Columns.
	defaults []colDefault
	// cs and coll are the table's default character set and collation.
	cs, coll string
	// dropped is set by DROP TABLE or DROP VIEW. The structure stays, so a
	// view can take the column names of its placeholder.
	dropped bool
	// autoStart is the table's AUTO_INCREMENT= option, or 0 when it has none.
	autoStart uint64
	// implicit is set on the structure the row reader makes for rows of a
	// table the file never created. No server holds it.
	implicit bool
}

// clone copies the structure, so that what was handed to the visitor before
// an ALTER stays as it was.
func (ti *tableInfo) clone() *tableInfo {
	t := *ti.t
	t.Columns = make([]*model.Column, len(ti.t.Columns))
	for i, c := range ti.t.Columns {
		cc := *c
		t.Columns[i] = &cc
	}
	t.PrimaryKey = append([]string(nil), ti.t.PrimaryKey...)
	t.Indexes = make([]model.Index, len(ti.t.Indexes))
	for i, ix := range ti.t.Indexes {
		ix.Columns = append([]string(nil), ix.Columns...)
		ix.SubParts = append([]int(nil), ix.SubParts...)
		t.Indexes[i] = ix
	}
	t.ForeignKeys = make([]model.ForeignKey, len(ti.t.ForeignKeys))
	for i, fk := range ti.t.ForeignKeys {
		fk.Columns = append([]string(nil), fk.Columns...)
		fk.RefColumns = append([]string(nil), fk.RefColumns...)
		t.ForeignKeys[i] = fk
	}
	cp := *ti
	cp.t = &t
	cp.defaults = append([]colDefault(nil), ti.defaults...)
	return &cp
}

// column finds a column by name, without regard to case.
func (ti *tableInfo) column(name string) int {
	for i, c := range ti.t.Columns {
		if strings.EqualFold(c.Name, name) {
			return i
		}
	}
	return -1
}

// defaultOf returns the DEFAULT clause of the table's column at index i. The
// row reader uses it for DEFAULT in a row.
func (ti *tableInfo) defaultOf(i int) colDefault {
	if i < 0 || i >= len(ti.defaults) {
		return colDefault{}
	}
	return ti.defaults[i]
}

// table returns what the reader holds for a table, or nil.
func (r *reader) table(db, name string) *tableInfo {
	return r.tables[tableKey{db, name}]
}

// markRows records that rows of the table were read. The row reader calls it
// with the first row of a table.
func (r *reader) markRows(db, name string) {
	r.hasRows[tableKey{db, name}] = struct{}{}
}

// rowsOf reports whether rows of the table were read.
func (r *reader) rowsOf(db, name string) bool {
	_, ok := r.hasRows[tableKey{db, name}]
	return ok
}

// put stores a table's structure, hands it to the visitor, and lets unread
// entries name the table.
func (r *reader) put(db string, ti *tableInfo) {
	r.tables[tableKey{db, ti.t.Name}] = ti
	r.folded[tableKey{db, strings.ToLower(ti.t.Name)}] = ti.t.Name
	r.markKnown(db, ti.t.Name)
	r.v.Structure(db, ti.t)
}

// existing returns the structure the reader holds in db under name, or else,
// with variant set, under a name that differs only by letter case: the same
// one where the server folds case, so created again, whatever OR REPLACE
// says.
func (r *reader) existing(db, name string) (old *tableInfo, variant bool) {
	if old = r.table(db, name); old != nil {
		return old, false
	}
	n, ok := r.folded[tableKey{db, strings.ToLower(name)}]
	if !ok || n == name {
		return nil, false
	}
	old = r.table(db, n)
	return old, old != nil
}

// addTrigger records that a CREATE TRIGGER names the table.
func (r *reader) addTrigger(db, table string) {
	r.triggers[tableKey{r.qualify(db), strings.ToLower(table)}] = struct{}{}
}

// hasTrigger reports a table a CREATE TRIGGER has named, by any letter case.
func (r *reader) hasTrigger(db, table string) bool {
	_, ok := r.triggers[tableKey{db, strings.ToLower(table)}]
	return ok
}

// sameColumns reports whether two tables have the same column names in the
// same order.
func sameColumns(a, b []*model.Column) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i].Name, b[i].Name) {
			return false
		}
	}
	return true
}

// sameDefinition reports whether two tables have the same columns, by name
// and type, in the same order.
func sameDefinition(a, b []*model.Column) bool {
	if !sameColumns(a, b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i].ColumnType, b[i].ColumnType) {
			return false
		}
	}
	return true
}

// settle fills what follows from the table's keys: the columns' Key and
// Nullable, PrimaryKey, the positions, and the order of Indexes, PRIMARY
// first.
func (ti *tableInfo) settle() {
	t := ti.t
	for i, c := range t.Columns {
		c.Position = i + 1
		c.Key = ""
	}
	// PRIMARY comes first, as information_schema lists it.
	for i, ix := range t.Indexes {
		if ix.Name == "PRIMARY" && i > 0 {
			copy(t.Indexes[1:i+1], t.Indexes[:i])
			t.Indexes[0] = ix
		}
	}
	t.PrimaryKey = nil
	var promoted *model.Index
	for i := range t.Indexes {
		ix := &t.Indexes[i]
		if ix.Name == "PRIMARY" {
			for _, name := range ix.Columns {
				if name == "" {
					continue
				}
				t.PrimaryKey = append(t.PrimaryKey, name)
				if j := ti.column(name); j >= 0 {
					t.Columns[j].Nullable = false
				}
			}
		}
		if promoted == nil && ix.Name != "PRIMARY" && ti.promotable(ix) {
			promoted = ix
		}
	}
	hasPK := len(t.PrimaryKey) > 0
	mark := func(name, key string) {
		j := ti.column(name)
		if j < 0 || name == "" {
			return
		}
		c := t.Columns[j]
		if rank(key) > rank(c.Key) {
			c.Key = key
		}
	}
	for i := range t.Indexes {
		ix := &t.Indexes[i]
		switch {
		case ix.Name == "PRIMARY":
			for _, n := range ix.Columns {
				mark(n, "PRI")
			}
		case len(ix.Columns) == 0:
		case ix.Unique && len(ix.Columns) == 1 && ix.Type != "FULLTEXT" && ix.Type != "SPATIAL":
			if !hasPK && ix == promoted {
				mark(ix.Columns[0], "PRI")
			} else {
				mark(ix.Columns[0], "UNI")
			}
		default:
			if !hasPK && ix == promoted {
				for _, n := range ix.Columns {
					mark(n, "PRI")
				}
			} else {
				mark(ix.Columns[0], "MUL")
			}
		}
	}
}

func rank(key string) int {
	switch key {
	case "PRI":
		return 3
	case "UNI":
		return 2
	case "MUL":
		return 1
	}
	return 0
}

// promotable reports a unique index the server takes for the primary key when
// the table declares none: every part a whole column that can't be NULL.
func (ti *tableInfo) promotable(ix *model.Index) bool {
	if !ix.Unique || ix.Type == "FULLTEXT" || ix.Type == "SPATIAL" || len(ix.Columns) == 0 {
		return false
	}
	for k, name := range ix.Columns {
		j := ti.column(name)
		if name == "" || j < 0 || ti.t.Columns[j].Nullable || (k < len(ix.SubParts) && ix.SubParts[k] != 0) {
			return false
		}
	}
	return true
}
