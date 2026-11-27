package sqldump

import (
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// The fixed warnings for a statement that takes rows away after the file has
// held them. The rows stay read; the statements carry no values.
const (
	WarnDropAfterRows     = "the dump drops a table after the rows it holds for it; the rows were still read"
	WarnTruncateAfterRows = "the dump empties a table after the rows it holds for it; the rows were still read"
)

// dbOptions reads the options of CREATE DATABASE or ALTER DATABASE, after the
// database's name, and keeps the default character set and collation. Of the
// options in an uncertain version comment only MySQL's ENCRYPTION is
// accepted.
func (r *reader) dbOptions(st *stmt, name string) {
	var cs, coll string
	eq := func() {
		if st.peek().isSym('=') {
			st.next()
		}
	}
	for !st.ended || st.peeked {
		t := st.next()
		if t.unc != 0 {
			p := newSP(st)
			p.listedOption(p.conv(t), false)
			continue
		}
		if t.kind != tokWord {
			continue
		}
		switch {
		case t.is("character"):
			if st.peek().is("set") {
				st.next()
			}
			eq()
			cs, _ = st.name()
		case t.is("charset"):
			eq()
			cs, _ = st.name()
		case t.is("collate"):
			eq()
			coll, _ = st.name()
		}
	}
	if st.err != "" || st.eof || (cs == "" && coll == "") {
		return
	}
	cc := r.fl.complete(cs, coll)
	st.apply(func() { r.dbDefs[r.dbName(name)] = cc })
}

// readView reads CREATE VIEW, after the word VIEW, into a structure of type
// VIEW. The columns are named by the view's own list, or by the AS aliases of
// its select list, as mysqldump writes them in the placeholder it creates
// first. A view that names none keeps the columns of the table or placeholder
// it replaces. Over a table the reader holds, with no DROP since, it is
// ReasonRecreate, and over a view known without OR REPLACE, unless the
// columns are the same: servers keep what they have.
func (r *reader) readView(st *stmt) Reason {
	p := newSP(st)
	st.ifExists()
	db, name, ok := p.qname()
	if !ok {
		return ""
	}
	st.setTable(db, name)
	var names []string
	if p.peek().isGroupStart() {
		p.next()
		target := p.depth - 1
		for p.depth > target && !p.atEnd() {
			if t := p.next(); t.isName() {
				names = append(names, t.s)
			}
		}
	}
	if len(names) == 0 {
		names = p.selectAliases()
	}
	st.skipRest()
	if p.bad || st.err != "" || st.eof {
		return ""
	}
	ti := &tableInfo{t: &model.Table{Name: name, Type: "VIEW"}}
	old, variant := r.existing(st.tableDB, name)
	if len(names) > 0 {
		for i, n := range names {
			ti.t.Columns = append(ti.t.Columns, &model.Column{Name: n, Position: i + 1})
		}
		ti.defaults = make([]colDefault, len(names))
	} else if old != nil {
		ti.t.Columns = old.clone().t.Columns
		ti.defaults = old.defaults
		for _, c := range ti.t.Columns {
			c.Key = ""
		}
	}
	if old != nil && !old.dropped && (old.t.Type != "VIEW" || !st.orReplace || variant) {
		if old.t.Type == "VIEW" && sameColumns(old.t.Columns, ti.t.Columns) {
			return ""
		}
		return ReasonRecreate
	}
	db = st.tableDB
	st.apply(func() {
		r.put(db, ti)
		r.views[tableKey{db, strings.ToLower(name)}] = struct{}{}
	})
	return ""
}

// selectAliases reads up to the SELECT of a view and returns the names its
// select list gives with AS.
func (p *sp) selectAliases() []string {
	var names []string
	depth := -1
	for !p.atEnd() {
		t := p.next()
		if depth < 0 {
			if t.is("select") {
				depth = p.depth
			}
			continue
		}
		if p.depth < depth {
			break
		}
		if p.depth != depth {
			continue
		}
		if t.is("from") {
			break
		}
		if t.is("as") {
			if n := p.peek(); n.isName() {
				p.next()
				names = append(names, n.s)
			}
		}
	}
	return names
}

// readSequence reads MariaDB's CREATE SEQUENCE, after the word SEQUENCE, into
// a structure of type SEQUENCE with no columns.
func (r *reader) readSequence(st *stmt) {
	p := newSP(st)
	st.ifExists()
	db, name, ok := p.qname()
	if !ok {
		return
	}
	st.setTable(db, name)
	st.skipRest()
	if p.bad || st.err != "" || st.eof {
		return
	}
	db = st.tableDB
	st.apply(func() { r.put(db, &tableInfo{t: &model.Table{Name: name, Type: "SEQUENCE"}}) })
}

// dropTables reads the names of DROP TABLE and DROP VIEW, after the word that
// says which. Each removes only what it would on the server: DROP TABLE a
// table or sequence the reader holds, DROP VIEW a view, by the name's exact
// letter case. A table that has rows gets the fixed warning, once; one that
// has none is marked dropped, and its structure stays for a view to take its
// columns.
func (r *reader) dropTables(st *stmt, view bool) {
	st.ifExists()
	for {
		db, n, ok := st.qname()
		if !ok {
			return
		}
		db = r.qualify(db)
		st.apply(func() {
			ti := r.table(db, n)
			if ti == nil || (ti.t.Type == "VIEW") != view {
				return // nothing of that kind: the server drops nothing
			}
			if r.rowsOf(db, n) {
				r.warnOnce("drop", WarnDropAfterRows)
			} else {
				ti.dropped = true
			}
		})
		if !st.peek().isSym(',') {
			return
		}
		st.next()
	}
}

// truncate reads TRUNCATE [TABLE] t, after TRUNCATE.
func (r *reader) truncate(st *stmt) {
	if st.peek().is("table") {
		st.next()
	}
	db, n, ok := st.qname()
	if !ok {
		return
	}
	db = r.qualify(db)
	st.apply(func() {
		if r.rowsOf(db, n) {
			r.warnOnce("truncate", WarnTruncateAfterRows)
		}
	})
}
