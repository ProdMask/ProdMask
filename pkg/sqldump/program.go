package sqldump

// maxNesting is how deep the compound statements of a stored program may
// nest before the reader gives up on its body.
const maxNesting = 256

// program reads CREATE TRIGGER, PROCEDURE, FUNCTION and EVENT, from the
// object's word: the header to the body's start, then the body by its
// grammar. The client sends the definition to the server as one query, and
// the semicolons inside the body are the body's own; but after the body only
// semicolons and the statement's end may follow, since the server would run
// anything else as a statement of its own, and a SET, a USE or a DELIMITER
// after a semicolon there leaves the rest of the file unread (stmt.state). A
// body the reader can't follow is unread. Nothing of the program is kept,
// and its strings are skipped.
func (r *reader) program(st *stmt) (Class, Reason) {
	st.body = true
	st.lx.discard = true
	defer func() { st.lx.discard = false }()
	st.next()
	p := &prog{st: st}
	var ok bool
	switch st.kind {
	case KindCreateTrigger:
		ok = p.triggerHead() && p.statement()
	case KindCreateEvent:
		ok = p.eventHead() && p.statement()
	case KindCreateProcedure:
		ok = p.procedureHead() && p.statement()
	default:
		ok = p.function()
	}
	if !ok {
		st.skipRest()
		return ClassUnread, ReasonKind
	}
	semi := false
	for st.peek().isSym(';') {
		st.next()
		semi = true
	}
	if t := st.peek(); t.kind != tokEnd && t.kind != tokEOF {
		for !st.ended || st.peeked {
			t := st.next()
			st.state = st.state || semi && changesSession(t)
			semi = t.isSym(';')
		}
		return ClassUnread, ReasonSeveral
	}
	return ClassKnown, ""
}

// prog reads the header and the body of a stored program. Its methods
// return false where the reader can't follow the program.
type prog struct {
	st    *stmt
	depth int // compound statements open
}

// isStop reports a token that no skip in a program may pass: a semicolon or
// the statement's end.
func isStop(t token) bool {
	return t.isSym(';') || t.kind == tokEnd || t.kind == tokEOF
}

// triggerHead reads a trigger's header up to the words FOR EACH ROW, at its
// own paren depth, and an optional FOLLOWS or PRECEDES name.
func (p *prog) triggerHead() bool {
	st := p.st
	base := st.depth
	for seen := 0; seen < 3; {
		t := st.next()
		switch {
		case isStop(t):
			return false
		case st.depth != base:
			seen = 0
		case t.is("for"):
			seen = 1
		case seen == 1 && t.is("each"), seen == 2 && t.is("row"):
			seen++
		case t.is("on"):
			// The table the trigger runs on, read in full whether or not
			// the statement is read: a server may create the trigger.
			st.lx.discard = false
			db, n, ok := st.qname()
			st.lx.discard = true
			if ok {
				st.r.addTrigger(db, n)
			}
			seen = 0
		default:
			seen = 0
		}
	}
	if t := st.peek(); t.is("follows") || t.is("precedes") {
		st.next()
		return p.dotted()
	}
	return true
}

// eventHead reads an event's header up to its first DO at its own paren
// depth.
func (p *prog) eventHead() bool {
	st := p.st
	base := st.depth
	for {
		t := st.next()
		switch {
		case isStop(t):
			return false
		case st.depth == base && t.is("do"):
			return true
		}
	}
}

// procedureHead reads [IF NOT EXISTS] name (parameters) and the
// characteristics.
func (p *prog) procedureHead() bool {
	st := p.st
	st.ifExists()
	return p.dotted() && st.next().isSym('(') && p.group() && p.characteristics()
}

// function reads a function: [IF NOT EXISTS] name, then either (parameters)
// RETURNS type, the characteristics and the body, or a loadable function's
// RETURNS word SONAME 'file', which has no body.
func (p *prog) function() bool {
	st := p.st
	st.ifExists()
	if !p.dotted() {
		return false
	}
	if st.peek().is("returns") {
		st.next()
		return st.next().kind == tokWord && st.next().is("soname") && st.next().kind == tokString
	}
	return st.next().isSym('(') && p.group() && st.next().is("returns") && p.returnType() &&
		p.characteristics() && p.statement()
}

// dotted reads a name with any number of qualifiers.
func (p *prog) dotted() bool {
	st := p.st
	for {
		if t := st.next(); t.kind != tokWord && t.kind != tokIdent && t.kind != tokNum {
			return false
		}
		if !st.peek().isSym('.') {
			return true
		}
		st.next()
	}
}

// group skips to the parenthesis that closes the one just read.
func (p *prog) group() bool {
	st := p.st
	for target := st.depth - 1; st.depth > target; {
		if isStop(st.next()) {
			return false
		}
	}
	return true
}

// returnType reads a function's type as both servers write it back: a word,
// an optional paren group, then its attributes in any order; or MariaDB's
// [ROW] TYPE OF name.
func (p *prog) returnType() bool {
	st := p.st
	t := st.next()
	if t.kind != tokWord {
		return false
	}
	typeOf := t.is("type")
	if t.is("row") && st.peek().is("type") {
		st.next()
		typeOf = true
	}
	if typeOf && st.peek().is("of") {
		st.next()
		return p.dotted()
	}
	if st.peek().isSym('(') {
		st.next()
		if !p.group() {
			return false
		}
	}
	for {
		switch t := st.peek(); {
		case t.is("unsigned"), t.is("signed"), t.is("zerofill"), t.is("binary"), t.is("ascii"), t.is("unicode"), t.is("byte"):
			st.next()
		case t.is("charset"), t.is("collate"):
			st.next()
			if !p.anyName() {
				return false
			}
		case t.is("character"):
			st.next()
			if !st.next().is("set") || !p.anyName() {
				return false
			}
		default:
			return true
		}
	}
}

// anyName reads a character set's or a collation's name.
func (p *prog) anyName() bool {
	switch p.st.next().kind {
	case tokWord, tokIdent, tokString:
		return true
	}
	return false
}

// characteristics reads a routine's characteristics, any number in any
// order.
func (p *prog) characteristics() bool {
	st := p.st
	for {
		switch t := st.peek(); {
		case t.is("comment"):
			st.next()
			if st.next().kind != tokString {
				return false
			}
			for st.peek().kind == tokString {
				st.next()
			}
		case t.is("language"), t.is("contains"), t.is("no"):
			st.next()
			if !st.next().is("sql") {
				return false
			}
		case t.is("reads"), t.is("modifies"):
			st.next()
			if !st.next().is("sql") || !st.next().is("data") {
				return false
			}
		case t.is("not"):
			st.next()
			if !st.next().is("deterministic") {
				return false
			}
		case t.is("deterministic"):
			st.next()
		case t.is("sql"):
			st.next()
			if !st.next().is("security") {
				return false
			}
			if u := st.next(); !u.is("definer") && !u.is("invoker") {
				return false
			}
		default:
			return true
		}
	}
}

// opener is the word that opens a compound statement.
type opener uint8

const (
	opNone opener = iota
	opBegin
	opIf
	opCase
	opLoop
	opWhile
	opRepeat
	opFor
	opDeclare
)

func openerOf(t token) opener {
	switch {
	case t.is("begin"):
		return opBegin
	case t.is("if"):
		return opIf
	case t.is("case"):
		return opCase
	case t.is("loop"):
		return opLoop
	case t.is("while"):
		return opWhile
	case t.is("repeat"):
		return opRepeat
	case t.is("for"):
		return opFor
	case t.is("declare"):
		return opDeclare
	}
	return opNone
}

// statement reads one statement of a body, from statement position, and
// leaves the semicolon or the end after it. The IF() and REPEAT() functions
// never stand in statement position, so IF and REPEAT there open compounds.
func (p *prog) statement() bool {
	st := p.st
	t := st.next()
	if isStop(t) {
		return false
	}
	op := openerOf(t)
	if op == opNone && (t.kind == tokWord || t.kind == tokIdent) && st.peek().isSym(':') {
		st.next() // a label, then what it names
		if t = st.next(); isStop(t) {
			return false
		}
		op = openerOf(t)
	}
	switch op {
	case opNone:
		return p.simple()
	case opDeclare:
		return p.declare()
	}
	if p.depth++; p.depth > maxNesting {
		return false
	}
	ok := p.compound(op)
	p.depth--
	return ok
}

// compound reads a compound statement after the word that opens it.
func (p *prog) compound(op opener) bool {
	st := p.st
	switch op {
	case opBegin:
		if st.peek().is("not") {
			st.next()
			if !st.next().is("atomic") {
				return false
			}
		}
		return p.list() && st.next().is("end") && p.label()
	case opIf:
		return p.branches("then", "elseif") && st.next().is("if")
	case opCase:
		if st.peek().is("when") {
			st.next()
		} else if !p.expr("when") {
			return false
		}
		return p.branches("then", "when") && st.next().is("case")
	case opLoop:
		return p.list() && st.next().is("end") && st.next().is("loop") && p.label()
	case opWhile:
		return p.expr("do") && p.list() && st.next().is("end") && st.next().is("while") && p.label()
	case opRepeat:
		return p.list() && st.next().is("until") && p.expr("end") && st.next().is("repeat") && p.label()
	default: // MariaDB's FOR loop
		return p.expr("do") && p.list() && st.next().is("end") && st.next().is("for") && p.label()
	}
}

// branches reads the branches of an IF or a CASE, after the first
// condition's opening word: expr THEN {stmt ;}, again after each word next,
// then [ELSE {stmt ;}] END.
func (p *prog) branches(then, next string) bool {
	st := p.st
	for {
		if !p.expr(then) || !p.list() {
			return false
		}
		switch t := st.next(); {
		case t.is(next):
			continue
		case t.is("else"):
			return p.list() && st.next().is("end")
		default:
			return t.is("end")
		}
	}
}

// declare reads a DECLARE: a handler, whose statement follows its
// conditions, or any other declaration, which is a simple statement.
func (p *prog) declare() bool {
	st := p.st
	if t := st.peek(); !t.is("continue") && !t.is("exit") && !t.is("undo") {
		return p.simple()
	}
	st.next()
	if !st.peek().is("handler") {
		return p.simple()
	}
	st.next()
	if !st.next().is("for") {
		return false
	}
	for {
		if !p.condition() {
			return false
		}
		if !st.peek().isSym(',') {
			break
		}
		st.next()
	}
	if p.depth++; p.depth > maxNesting {
		return false
	}
	ok := p.statement()
	p.depth--
	return ok
}

// condition reads a handler's condition: SQLSTATE [VALUE] 'code', an error
// number, NOT FOUND, or a word: SQLWARNING, SQLEXCEPTION or a condition's
// name.
func (p *prog) condition() bool {
	st := p.st
	switch t := st.next(); {
	case t.is("sqlstate"):
		if st.peek().is("value") {
			st.next()
		}
		return st.next().kind == tokString
	case t.is("not"):
		return st.next().is("found")
	default:
		return t.kind == tokNum || t.kind == tokWord || t.kind == tokIdent
	}
}

// list reads statements, each with its semicolon, up to a word that closes
// a list in statement position, which it leaves: END, ELSEIF, ELSE, WHEN or
// UNTIL. A list may be empty.
func (p *prog) list() bool {
	st := p.st
	for {
		if t := st.peek(); t.is("end") || t.is("elseif") || t.is("else") || t.is("when") || t.is("until") {
			return true
		}
		if !p.statement() || !st.next().isSym(';') {
			return false
		}
	}
}

// simple skips a statement that opens no compound, up to the semicolon or
// the end after it, which it leaves.
func (p *prog) simple() bool {
	st := p.st
	for t := st.peek(); !isStop(t); t = st.peek() {
		st.next()
	}
	return true
}

// expr skips an expression up to the word stop at its own paren depth,
// which it consumes. It steps over CASE ... END, and fails at a semicolon or
// the statement's end.
func (p *prog) expr(stop string) bool {
	st := p.st
	base, cases := st.depth, 0
	for {
		t := st.next()
		switch {
		case isStop(t):
			return false
		case t.is("case"):
			cases++
		case cases > 0 && t.is("end"):
			cases--
		case cases == 0 && st.depth == base && t.is(stop):
			return true
		}
	}
}

// label consumes the label that may follow the END of a BEGIN, a LOOP, a
// WHILE, a REPEAT or a FOR: a word or a quoted identifier.
func (p *prog) label() bool {
	if t := p.st.peek(); t.kind == tokWord || t.kind == tokIdent {
		p.st.next()
	}
	return true
}
