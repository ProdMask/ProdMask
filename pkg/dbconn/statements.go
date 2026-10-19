package dbconn

import (
	"errors"
	"fmt"
	"strings"
)

// ErrStatementRefused is returned, before anything runs, for a statement a
// Snapshot doesn't allow: one that could end its transaction, write, lock
// rows or change the server. Its text never quotes the statement.
var ErrStatementRefused = errors.New("refused a statement the snapshot doesn't allow")

func refuseStatement(why string) error { return fmt.Errorf("%w: %s", ErrStatementRefused, why) }

// checkStatement applies a Snapshot's statement rules. ExecContext runs only
// session-scope SETs (exec true); the query methods run only reads. In
// every statement, INTO and locking reads are refused, and so are
// executable comments and optimizer hints, which the server runs. Strings,
// quoted names and plain comments are skipped when looking for keywords.
//
// Functions are not vetted: a read can still call one that changes
// something, such as MariaDB's NEXTVAL and SETVAL. Callers must not, and
// Check still catches a statement that ends the transaction.
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
		}
	}
	if exec {
		return checkSet(toks)
	}
	return checkRead(toks)
}

// checkSet allows SET statements that change only this session: system
// variables at session scope, SET NAMES, SET CHARACTER SET and user
// variables. Variables that end or reshape the transaction are refused.
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
	case a[0].word("NAMES"), a[0].word("CHARACTER"), a[0].word("CHARSET"):
		return nil
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
	}
	if len(rest) > 0 && rest[0].is('.') {
		return refuseStatement("a structured variable")
	}
	if len(rest) > 1 && rest[0].is(':') && rest[1].is('=') || len(rest) > 0 && rest[0].is('=') {
		return nil
	}
	return refuseStatement("an assignment without =")
}

// checkRead allows SELECT, SHOW, DESCRIBE, VALUES and TABLE, a WITH whose
// main statement is one of those, and EXPLAIN of one.
func checkRead(toks []stmtToken) error {
	i := skipOpen(toks, 0)
	if i == len(toks) {
		return refuseStatement("not a read")
	}
	switch toks[i].text {
	case "SELECT", "SHOW", "VALUES", "TABLE":
		if toks[i].kind == tokWord {
			return nil
		}
	case "WITH":
		return checkWith(toks, i)
	case "EXPLAIN", "DESCRIBE", "DESC":
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
	tokQuoted            // a string or quoted name; its contents are dropped
	tokPunct             // one punctuation character
)

type stmtToken struct {
	kind int
	text string
}

func (t stmtToken) word(w string) bool { return t.kind == tokWord && t.text == w }
func (t stmtToken) is(c byte) bool     { return t.kind == tokPunct && t.text[0] == c }

// statementTokens splits a statement for the rules above. Comments are
// dropped. Executable comments and optimizer hints are refused, since the
// server runs what they hold, and so is a string holding a backslash: where
// such a string ends depends on the session's sql_mode.
func statementTokens(q string) ([]stmtToken, error) {
	var out []stmtToken
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case c <= ' ':
			i++
		case c == '#', c == '-' && strings.HasPrefix(q[i:], "--") && (i+2 == len(q) || q[i+2] <= ' '):
			if end := strings.IndexByte(q[i:], '\n'); end >= 0 {
				i += end + 1
			} else {
				i = len(q)
			}
		case strings.HasPrefix(q[i:], "/*"):
			if strings.HasPrefix(q[i:], "/*!") || strings.HasPrefix(q[i:], "/*M!") || strings.HasPrefix(q[i:], "/*+") {
				return nil, refuseStatement("an executable comment or optimizer hint")
			}
			end := strings.Index(q[i+2:], "*/")
			if end < 0 {
				return nil, refuseStatement("an unterminated comment")
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
			out = append(out, stmtToken{kind: tokQuoted})
			i = j + 1
		case wordByte(c):
			j := i
			for j < len(q) && wordByte(q[j]) {
				j++
			}
			out = append(out, stmtToken{kind: tokWord, text: strings.ToUpper(q[i:j])})
			i = j
		default:
			out = append(out, stmtToken{kind: tokPunct, text: q[i : i+1]})
			i++
		}
	}
	return out, nil
}

func wordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' || c >= 0x80
}
