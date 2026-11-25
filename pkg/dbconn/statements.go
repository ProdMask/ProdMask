package dbconn

import (
	"errors"
	"fmt"
	"strings"
)

// ErrStatementRefused is returned, before anything runs, for a statement the
// read-only rules don't allow: one that could write, lock rows, end or
// change a transaction, or change the server. No statement prodmask sends
// should ever meet it, so its words ask for a report. Its text never quotes
// the statement.
var ErrStatementRefused = errors.New("prodmask stopped a statement it was about to send, because it isn't a read: this is a fault in prodmask, please report it")

// refusal is ErrStatementRefused with the rule that refused, which
// CheckAgentStatement passes on in its own words.
type refusal struct{ why string }

func (r *refusal) Error() string { return fmt.Sprintf("%v (%s)", ErrStatementRefused, r.why) }
func (r *refusal) Unwrap() error { return ErrStatementRefused }

func refuseStatement(why string) error { return &refusal{why} }

// checkStatement applies the read-only statement rules. ExecContext runs
// only session-scope SETs (exec true); the query methods run only reads. In
// every statement, INTO, locking reads and the calls that change a sequence
// are refused, and so are executable comments and optimizer hints, which the
// server runs, and control characters, which could make the server read the
// text otherwise. Strings, quoted names and plain comments are skipped when
// looking for keywords.
//
// Other functions are not vetted: a read can still call a stored function
// that writes. A read-only session refuses that on the server, and a
// Snapshot's Check still catches a statement that ends its transaction.
func checkStatement(query string, exec bool) error {
	toks, err := statementTokens(query)
	if err != nil {
		return err
	}
	if n := len(toks); n > 0 && toks[n-1].is(';') {
		toks = toks[:n-1]
	}
	if len(toks) == 0 {
		return refuseStatement("an empty statement")
	}
	for i, t := range toks {
		switch {
		case t.is(';'):
			return refuseStatement("more than one statement")
		case t.word("INTO"):
			return refuseStatement("INTO, which writes")
		case t.word("FOR") && i+1 < len(toks) && (toks[i+1].word("UPDATE") || toks[i+1].word("SHARE")),
			t.word("LOCK") && i+3 < len(toks) && toks[i+1].word("IN") && toks[i+2].word("SHARE") && toks[i+3].word("MODE"):
			return refuseStatement("a locking read")
		case sequenceCall(toks, i):
			return refuseStatement("a call that changes a sequence")
		}
	}
	if exec {
		return checkSet(toks)
	}
	return checkRead(toks)
}

// sequenceCall reports whether toks[i] starts a call that changes a MariaDB
// sequence: NEXTVAL( or SETVAL(, NEXT VALUE FOR, or seq.nextval and
// seq.setval, which MariaDB's Oracle mode reads as NEXTVAL and SETVAL with
// the name bare or quoted. A column or table named nextval written after
// another name is refused too.
func sequenceCall(toks []stmtToken, i int) bool {
	at := func(k int) stmtToken {
		if i+k < len(toks) {
			return toks[i+k]
		}
		return stmtToken{}
	}
	switch t := toks[i]; {
	case t.name("NEXTVAL"), t.name("SETVAL"):
		return at(1).is('(')
	case t.word("NEXT"):
		return at(1).word("VALUE") && at(2).word("FOR")
	case t.is('.'):
		return at(1).name("NEXTVAL") || at(1).name("SETVAL")
	}
	return false
}

// checkSet allows SET statements that change only this session: system
// variables at session scope, SET NAMES with a character set the rules read
// as the server does, and user variables. Variables that end or reshape the
// transaction, and those that change the character set the server reads
// text in, are refused.
func checkSet(toks []stmtToken) error {
	if !toks[0].word("SET") {
		return refuseStatement("only SET statements run through ExecContext")
	}
	if len(toks) == 1 {
		return refuseStatement("an empty assignment")
	}
	for i := 1; i < len(toks); {
		end := i
		for depth := 0; end < len(toks); end++ {
			switch {
			case toks[end].is('('):
				depth++
			case toks[end].is(')'):
				depth--
			}
			if depth == 0 && toks[end].is(',') {
				break
			}
		}
		if err := checkAssignment(toks[i:end]); err != nil {
			return err
		}
		i = end + 1
	}
	return nil
}

func checkAssignment(a []stmtToken) error {
	if len(a) == 0 {
		return refuseStatement("an empty assignment")
	}
	var name stmtToken
	rest := a[1:]
	switch {
	case a[0].is('@') && len(a) > 1 && a[1].is('@'):
		// @@name, or @@scope.name.
		rest = a[2:]
		if len(rest) > 2 && rest[0].kind == tokWord && rest[1].is('.') {
			switch rest[0].text {
			case "SESSION", "LOCAL":
			default:
				return refuseStatement("a variable outside the session")
			}
			rest = rest[2:]
		}
		if len(rest) == 0 {
			return refuseStatement("an incomplete assignment")
		}
		name, rest = rest[0], rest[1:]
	case a[0].is('@'):
		return nil // a user variable
	case a[0].word("NAMES"):
		return checkNames(a[1:])
	case a[0].word("CHARACTER"), a[0].word("CHARSET"):
		return refuseStatement("a character set change, which can change how the server reads text")
	case a[0].word("SESSION"), a[0].word("LOCAL"):
		if len(rest) == 0 {
			return refuseStatement("an incomplete assignment")
		}
		name, rest = rest[0], rest[1:]
	default:
		name = a[0]
	}
	if name.kind != tokWord {
		return refuseStatement("a variable name that isn't a plain word")
	}
	switch v := name.text; {
	case v == "GLOBAL", v == "PERSIST", v == "PERSIST_ONLY":
		return refuseStatement("a variable outside the session")
	case v == "TRANSACTION", v == "AUTOCOMMIT", v == "COMPLETION_TYPE",
		strings.HasPrefix(v, "TRANSACTION_"), strings.HasPrefix(v, "TX_"):
		return refuseStatement("a setting that can end or change the transaction")
	case v == "PASSWORD", v == "ROLE", v == "DEFAULT", v == "STATEMENT", v == "RESOURCE":
		return refuseStatement("a SET that isn't a session variable")
	case v == "CHARACTER_SET_CLIENT", v == "CHARACTER_SET_CONNECTION", v == "COLLATION_CONNECTION":
		// collation_connection sets character_set_connection to its own.
		return refuseStatement("a character set change, which can change how the server reads text")
	}
	if len(rest) > 0 && rest[0].is('.') {
		return refuseStatement("a structured variable")
	}
	if len(rest) > 1 && rest[0].is(':') && rest[1].is('=') || len(rest) > 0 && rest[0].is('=') {
		return nil
	}
	return refuseStatement("an assignment without =")
}

// namesCharsets are the character sets SET NAMES may choose: those in
// which the server reads a statement's bytes as these rules do.
var namesCharsets = map[string]bool{"UTF8MB4": true, "UTF8MB3": true, "UTF8": true, "BINARY": true}

// checkNames checks what follows SET NAMES: one of namesCharsets as a bare
// word, then perhaps COLLATE and a collation. A quoted name or DEFAULT is
// refused, since the rules can't tell what it names.
func checkNames(rest []stmtToken) error {
	if len(rest) == 0 || rest[0].kind != tokWord || !namesCharsets[rest[0].text] {
		return refuseStatement("a character set change, which can change how the server reads text")
	}
	if len(rest) == 1 || len(rest) == 3 && rest[1].word("COLLATE") && rest[2].kind != tokPunct {
		return nil
	}
	return refuseStatement("a SET NAMES it can't read")
}

// checkRead allows SELECT, SHOW, DESCRIBE, VALUES and TABLE, a WITH whose
// main statement is one of those, and EXPLAIN of one.
func checkRead(toks []stmtToken) error {
	i := skipOpen(toks, 0)
	if i == len(toks) {
		return refuseStatement("not a read")
	}
	switch t := toks[i]; {
	case t.word("SELECT"), t.word("SHOW"), t.word("VALUES"), t.word("TABLE"):
		return nil
	case t.word("WITH"):
		return checkWith(toks, i)
	case t.word("EXPLAIN"), t.word("DESCRIBE"), t.word("DESC"):
		return checkExplain(toks, i+1)
	}
	return refuseStatement("not a read")
}

// checkWith walks the common table expressions from toks[i], WITH, and
// checks the main statement after them.
func checkWith(toks []stmtToken, i int) error {
	i++
	if i < len(toks) && toks[i].word("RECURSIVE") {
		i++
	}
	for {
		if i >= len(toks) || toks[i].kind != tokWord && toks[i].kind != tokQuoted {
			return refuseStatement("a WITH it can't read")
		}
		i++
		if i < len(toks) && toks[i].is('(') {
			i = skipGroup(toks, i)
		}
		if i >= len(toks) || !toks[i].word("AS") {
			return refuseStatement("a WITH it can't read")
		}
		i++
		if i >= len(toks) || !toks[i].is('(') {
			return refuseStatement("a WITH it can't read")
		}
		i = skipGroup(toks, i)
		if i < len(toks) && toks[i].is(',') {
			i++
			continue
		}
		break
	}
	i = skipOpen(toks, i)
	if i < len(toks) && (toks[i].word("SELECT") || toks[i].word("TABLE") || toks[i].word("VALUES")) {
		return nil
	}
	return refuseStatement("a WITH whose statement isn't a read")
}

// checkExplain checks what follows EXPLAIN, DESCRIBE or DESC: a table's
// name, or a read. EXPLAIN ANALYZE runs its statement, so that must be a
// read too.
func checkExplain(toks []stmtToken, i int) error {
	for i < len(toks) {
		switch {
		case toks[i].word("EXTENDED"), toks[i].word("PARTITIONS"), toks[i].word("ANALYZE"):
			i++
			continue
		case toks[i].word("FORMAT") && i+2 < len(toks) && toks[i+1].is('='):
			i += 3
			continue
		}
		break
	}
	if i == len(toks) {
		return refuseStatement("an EXPLAIN of nothing")
	}
	switch t := toks[i]; {
	case t.is('('), t.word("SELECT"), t.word("TABLE"), t.word("VALUES"):
		return nil
	case t.word("WITH"):
		return checkWith(toks, i)
	case t.kind == tokQuoted:
		return nil // DESCRIBE `t`
	case t.kind == tokWord:
		switch t.text {
		case "INSERT", "UPDATE", "DELETE", "REPLACE", "FOR", "CALL", "DO", "LOAD", "SET":
			return refuseStatement("an EXPLAIN of a statement that isn't a read")
		}
		return nil // DESCRIBE t
	}
	return refuseStatement("an EXPLAIN it can't read")
}

func skipOpen(toks []stmtToken, i int) int {
	for i < len(toks) && toks[i].is('(') {
		i++
	}
	return i
}

// skipGroup returns the index after the parenthesis that closes toks[i].
func skipGroup(toks []stmtToken, i int) int {
	depth := 0
	for ; i < len(toks); i++ {
		switch {
		case toks[i].is('('):
			depth++
		case toks[i].is(')'):
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return i
}

// Statement token kinds.
const (
	tokWord   = iota + 1 // a keyword or bare name, upper-cased
	tokQuoted            // a string in single quotes, whose text is dropped, or text in backticks or double quotes, upper-cased
	tokPunct             // one punctuation character
)

type stmtToken struct {
	kind int
	text string
	// raw is a word's or quoted name's own text, as written, with a quoted
	// name's doubled quotes made one; str marks a string in single quotes.
	raw string
	str bool
	// glued marks a token that starts where the one before it ends, with
	// no space or comment between: the servers read a word glued to a dot
	// as a qualifier, and a dot after a space with a digit glued to it as
	// a number.
	glued bool
}

func (t stmtToken) word(w string) bool { return t.kind == tokWord && t.text == w }
func (t stmtToken) is(c byte) bool     { return t.kind == tokPunct && t.text[0] == c }

// name reports a bare or quoted name w. A name in double quotes counts,
// since sql_mode can make the server read one as a name.
func (t stmtToken) name(w string) bool {
	return (t.kind == tokWord || t.kind == tokQuoted) && t.text == w
}

// controlByte reports a byte the rules refuse outside a string or quoted
// name: a control character other than tab, newline or carriage return, or
// DEL. The server reads -- followed by one as the start of a comment, where
// these rules didn't, so text the server runs could hide from them.
func controlByte(c byte) bool { return c < ' ' && c != '\t' && c != '\n' && c != '\r' || c == 0x7f }

func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if controlByte(s[i]) {
			return true
		}
	}
	return false
}

// statementTokens splits a statement for the rules above. Comments are
// dropped. Executable comments and optimizer hints are refused, since the
// server runs what they hold, and so is a string holding a backslash: where
// such a string ends depends on the session's sql_mode. So is a control
// character anywhere outside a string or quoted name, comments included.
func statementTokens(q string) ([]stmtToken, error) {
	var out []stmtToken
	last := -1
	add := func(t stmtToken, start, end int) {
		t.glued = start == last
		last = end
		out = append(out, t)
	}
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case controlByte(c):
			return nil, refuseStatement("a control character outside a string or quoted name")
		case c <= ' ':
			i++
		case c == '#', c == '-' && strings.HasPrefix(q[i:], "--") && (i+2 == len(q) || q[i+2] <= ' '):
			end := strings.IndexByte(q[i:], '\n')
			if end < 0 {
				end = len(q) - i
			}
			if hasControlByte(q[i : i+end]) {
				return nil, refuseStatement("a control character outside a string or quoted name")
			}
			i += end
		case strings.HasPrefix(q[i:], "/*"):
			if strings.HasPrefix(q[i:], "/*!") || strings.HasPrefix(q[i:], "/*M!") || strings.HasPrefix(q[i:], "/*+") {
				return nil, refuseStatement("an executable comment or optimizer hint")
			}
			end := strings.Index(q[i+2:], "*/")
			if end < 0 {
				return nil, refuseStatement("an unterminated comment")
			}
			if hasControlByte(q[i+2 : i+2+end]) {
				return nil, refuseStatement("a control character outside a string or quoted name")
			}
			i += 2 + end + 2
		case c == '\'', c == '"', c == '`':
			j := i + 1
			for ; j < len(q); j++ {
				if q[j] == '\\' && c != '`' {
					return nil, refuseStatement("a string holding a backslash")
				}
				if q[j] == c {
					if j+1 < len(q) && q[j+1] == c {
						j++
						continue
					}
					break
				}
			}
			if j >= len(q) {
				return nil, refuseStatement("an unterminated string or name")
			}
			t := stmtToken{kind: tokQuoted, str: c == '\''}
			if c != '\'' {
				// A quoted name keeps its text, with a doubled quote as one.
				t.raw = strings.ReplaceAll(q[i+1:j], string([]byte{c, c}), string(c))
				t.text = strings.ToUpper(t.raw)
			}
			add(t, i, j+1)
			i = j + 1
		case wordByte(c):
			j := i
			for j < len(q) && wordByte(q[j]) {
				j++
			}
			add(stmtToken{kind: tokWord, text: strings.ToUpper(q[i:j]), raw: q[i:j]}, i, j)
			i = j
		default:
			add(stmtToken{kind: tokPunct, text: q[i : i+1]}, i, i+1)
			i++
		}
	}
	return out, nil
}

func wordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' || c >= 0x80
}
