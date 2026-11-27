package sqldump

import "strings"

const (
	maxSetText = 4096 // the longest mode or name a SET statement may build
	maxVars    = 256  // user variables kept
)

// sqlMode is the SQL mode of the session, as far as the file says. Only
// NO_BACKSLASH_ESCAPES and ANSI_QUOTES change how text is lexed.
type sqlMode struct {
	known   bool   // false once an assignment can't be evaluated
	text    string // the mode string
	literal bool   // the file has set the mode to a literal
}

// flags returns the two modes that matter. The combination modes ANSI, DB2,
// MAXDB, MSSQL, ORACLE and POSTGRESQL all include ANSI_QUOTES, and none
// includes NO_BACKSLASH_ESCAPES.
func (m sqlMode) flags() (noBackslash, ansiQuotes bool) {
	for _, part := range strings.Split(m.text, ",") {
		switch strings.ToUpper(strings.TrimSpace(part)) {
		case "NO_BACKSLASH_ESCAPES":
			noBackslash = true
		case "ANSI_QUOTES", "ANSI", "DB2", "MAXDB", "MSSQL", "ORACLE", "POSTGRESQL":
			ansiQuotes = true
		}
	}
	return noBackslash, ansiQuotes
}

// noAutoOnZero reports NO_AUTO_VALUE_ON_ZERO: a 0 in an auto-increment
// column is then stored as 0 and not replaced by the next key.
func (m sqlMode) noAutoOnZero() bool {
	for _, part := range strings.Split(m.text, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "NO_AUTO_VALUE_ON_ZERO") {
			return true
		}
	}
	return false
}

// textVal is the value of an expression in a SET statement.
type textVal struct {
	s   string
	ok  bool
	lit bool // a plain string literal
	def bool // DEFAULT
}

// doSet reads a SET statement: its assignments are followed, the rest is
// skipped. An assignment to sql_mode that can't be evaluated makes the mode
// unknown, and the rest of the file is one unread entry. In a SET that holds
// a version comment some servers skip, everything it assigns is unknown. A
// value that holds a := or a function call makes every user variable
// unknown (setOne).
func (r *reader) doSet(st *stmt) (Class, Reason) {
	switch p := st.peek(); {
	case p.is("statement"):
		// MariaDB's SET STATEMENT ... FOR runs a statement, which can hold rows.
		return r.unread(st, ReasonKind)
	case p.is("password"):
		st.apply(func() { r.users++ })
		return r.noRows(st)
	}
	for !st.ended || st.peeked {
		r.setOne(st)
	}
	if st.lx.vOpen >= 0 {
		for _, target := range st.targets {
			r.unknown(target)
		}
	}
	if !r.mode.known {
		r.stop = true
		st.toEnd = true
		return ClassUnread, ReasonSQLMode
	}
	return ClassKnown, ""
}

// setOne reads one assignment of a SET statement, up to the comma after it.
func (r *reader) setOne(st *stmt) {
	t := st.next()
	global := false
	for t.kind == tokWord && (t.is("global") || t.is("persist") || t.is("persist_only") || t.is("session") || t.is("local")) {
		if !t.is("session") && !t.is("local") {
			global = true
		}
		t = st.next()
	}
	if changesAutoIncrement(t) {
		r.aiShift = true
	}
	target := ""
	defer r.afterValue(st)
	switch t.kind {
	case tokWord:
		switch {
		case t.is("names"), t.is("charset"):
			st.targets = append(st.targets, "character_set_client")
			r.setNames(st)
			return
		case t.is("character"):
			if st.peek().is("set") {
				st.next()
				st.targets = append(st.targets, "character_set_client")
				r.setNames(st)
				return
			}
		case t.is("sql_mode"):
			target = "sql_mode"
		case t.is("character_set_client"):
			target = "character_set_client"
		}
	case tokVar:
		name := strings.ToLower(string(t.text))
		if strings.HasPrefix(name, "@@") {
			n := name[2:]
			switch {
			case strings.HasPrefix(n, "global.") || strings.HasPrefix(n, "persist.") || strings.HasPrefix(n, "persist_only."):
				global = true
				n = n[strings.IndexByte(n, '.')+1:]
			case strings.HasPrefix(n, "session.") || strings.HasPrefix(n, "local."):
				n = n[strings.IndexByte(n, '.')+1:]
			}
			if n == "sql_mode" || n == "character_set_client" {
				target = n
			}
		} else if len(name) > 1 {
			target = name
		}
	}
	op := st.assignOp()
	st.fxWatch, st.fx, st.fxPrev = true, false, 0
	if target == "" || global || !op {
		if target == "sql_mode" && !global {
			r.mode.known = false
		}
		st.skipToComma()
		return
	}
	st.targets = append(st.targets, target)
	v := r.evalText(st, target == "character_set_client")
	if p := st.peek(); !(p.kind == tokEnd || p.kind == tokEOF || (p.isSym(',') && st.depth == 0)) {
		v.ok = false
	}
	st.skipToComma()
	switch target {
	case "sql_mode":
		if v.ok {
			r.mode = sqlMode{known: true, text: v.s, literal: r.mode.literal || v.lit}
		} else {
			r.mode.known = false
		}
	case "character_set_client":
		if !v.ok {
			r.cs = clientCharset{unknown: true}
			r.warnOnce("cs-unknown", WarnUnknownCharset)
			return
		}
		r.setCharset(v.s, v.def)
	default: // a user variable
		if v.ok && len(v.s) <= maxSetText {
			if _, exists := r.vars[target]; exists || len(r.vars) < maxVars {
				r.vars[target] = v.s
				return
			}
		}
		delete(r.vars, target)
	}
}

// afterValue ends the watch on a SET's value: after one that holds a := or
// a function call, which may set any user variable, none is known.
func (r *reader) afterValue(st *stmt) {
	st.fxWatch = false
	if st.fx {
		clear(r.vars)
	}
}

// unknown makes what a SET assigned unknown, as if assigned an expression the
// reader doesn't evaluate.
func (r *reader) unknown(target string) {
	switch target {
	case "sql_mode":
		r.mode.known = false
	case "character_set_client":
		r.cs = clientCharset{unknown: true}
		r.warnOnce("cs-unknown", WarnUnknownCharset)
	default: // a user variable
		delete(r.vars, target)
	}
}

// assignOp consumes = or :=.
func (st *stmt) assignOp() bool {
	p := st.peek()
	switch {
	case p.isSym('='):
		st.next()
		return true
	case p.isSym(':'):
		st.next()
		if st.peek().isSym('=') {
			st.next()
			return true
		}
	}
	return false
}

// setNames reads the character set of SET NAMES, SET CHARACTER SET and SET
// CHARSET, with the COLLATE of SET NAMES.
func (r *reader) setNames(st *stmt) {
	t := st.next()
	ok, def := false, false
	name := ""
	switch {
	case t.kind == tokString && !t.cut:
		name, ok = string(t.text), true
	case t.is("default"):
		ok, def = true, true
	case t.kind == tokWord || t.kind == tokIdent:
		name, ok = string(t.text), true
	}
	if st.peek().is("collate") {
		st.next()
		st.next()
	}
	st.skipToComma()
	if !ok {
		r.cs = clientCharset{unknown: true}
		r.warnOnce("cs-unknown", WarnUnknownCharset)
		return
	}
	r.setCharset(name, def)
}

// setCharset makes name the client character set. A set that is on MySQL's
// list but isn't decoded gets one warning naming it; a name that isn't on the
// list gets one that doesn't.
func (r *reader) setCharset(name string, def bool) {
	if def {
		name = "utf8mb4"
	}
	info, n, ok := lookupCharset(name)
	switch {
	case !ok:
		r.cs = clientCharset{unknown: true}
		r.warnOnce("cs-unknown", WarnUnknownCharset)
	case !info.decoded:
		r.cs = clientCharset{name: n, info: info}
		r.warnOnce("cs-"+n, strings.Replace(warnCharsetFormat, "%s", n, 1))
	default:
		r.cs = clientCharset{name: n, info: info}
	}
}

// evalText evaluates the expressions a dump uses to set the SQL mode and the
// character set: literals, DEFAULT, @@sql_mode and @@character_set_client,
// user variables, CONCAT and REPLACE.
func (r *reader) evalText(st *stmt, bare bool) textVal {
	t := st.next()
	if bare && (t.kind == tokWord || t.kind == tokIdent) && !t.is("default") && !t.is("concat") && !t.is("replace") {
		return textVal{s: string(t.text), ok: true}
	}
	switch t.kind {
	case tokString:
		b, cut := st.joinStrings()
		if cut || len(b) > maxSetText {
			return textVal{}
		}
		return textVal{s: string(b), ok: true, lit: true}
	case tokWord:
		switch {
		case t.is("default"):
			return textVal{ok: true, def: true}
		case t.is("concat"):
			return r.evalCall(st, true)
		case t.is("replace"):
			return r.evalCall(st, false)
		}
	case tokVar:
		return r.evalVar(strings.ToLower(string(t.text)))
	case tokSym:
		if t.sym == '(' {
			v := r.evalText(st, false)
			if p := st.next(); v.ok && p.isSym(')') {
				v.lit = false
				return v
			}
		}
	}
	return textVal{}
}

func (r *reader) evalVar(name string) textVal {
	if !strings.HasPrefix(name, "@@") {
		s, ok := r.vars[name]
		return textVal{s: s, ok: ok}
	}
	n := name[2:]
	switch {
	case strings.HasPrefix(n, "session.") || strings.HasPrefix(n, "local."):
		n = n[strings.IndexByte(n, '.')+1:]
	case strings.Contains(n, "."):
		return textVal{}
	}
	switch n {
	case "sql_mode":
		if r.mode.known {
			return textVal{s: r.mode.text, ok: true}
		}
	case "character_set_client":
		if !r.cs.unknown {
			return textVal{s: r.cs.name, ok: true}
		}
	}
	return textVal{}
}

// evalCall evaluates CONCAT(a, b, ...) or REPLACE(s, from, to), after the
// function's name.
func (r *reader) evalCall(st *stmt, concat bool) textVal {
	if !st.next().isSym('(') {
		return textVal{}
	}
	var args []string
	for {
		v := r.evalText(st, false)
		if !v.ok {
			return textVal{}
		}
		args = append(args, v.s)
		if len(args) > 16 {
			return textVal{}
		}
		p := st.next()
		if p.isSym(')') {
			break
		}
		if !p.isSym(',') {
			return textVal{}
		}
	}
	var s string
	if concat {
		s = strings.Join(args, "")
	} else {
		if len(args) != 3 {
			return textVal{}
		}
		s = args[0]
		if args[1] != "" {
			s = strings.ReplaceAll(args[0], args[1], args[2])
		}
	}
	if len(s) > maxSetText {
		return textVal{}
	}
	return textVal{s: s, ok: true}
}

// joinStrings extends the string token just read with the strings that
// follow it, as the server joins adjacent literals, and returns the whole.
func (st *stmt) joinStrings() ([]byte, bool) {
	for {
		st.lx.join = true
		p := st.peek()
		st.lx.join = false
		if p.kind != tokString {
			break
		}
		st.next()
	}
	return st.lx.vb.b, st.lx.vb.cut
}

// changesAutoIncrement reports the name of auto_increment_increment or
// auto_increment_offset, as a bare word or as a system variable. A table with
// either set has keys the reader can't count.
func changesAutoIncrement(t token) bool {
	switch t.kind {
	case tokWord:
		return t.is("auto_increment_increment") || t.is("auto_increment_offset")
	case tokVar:
		name := strings.ToLower(string(t.text))
		if !strings.HasPrefix(name, "@@") {
			return false
		}
		name = name[strings.LastIndexByte(name, '.')+1:]
		return strings.HasSuffix(name, "auto_increment_increment") || strings.HasSuffix(name, "auto_increment_offset")
	}
	return false
}
