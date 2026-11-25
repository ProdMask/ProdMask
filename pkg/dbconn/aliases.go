package dbconn

import "strings"

// Aliases are the names a statement gives what it reads, for tying a result
// column's table alias, as the driver reports it, to a table. Its keys are
// lower case.
type Aliases struct {
	// Tables maps each alias, or table named without one, to the base table
	// it names as written, or to "" for a derived table or a CTE.
	Tables map[string]string
	// Twice holds the names defined more than once, as by a subquery
	// reusing an outer alias, and the names that stand bare more than once
	// (see collectAliases): a column tied to one can't be placed.
	Twice map[string]bool
	// Read lists the base tables the statement reads, each once, as
	// written, those of its subqueries and derived tables included, and a
	// name a CTE shares with a table.
	Read []string
	// InformationSchemaOnly marks a statement whose every table reference
	// is in information_schema, and which calls no function by a qualified
	// name (a stored one): its result is the schema's metadata.
	InformationSchemaOnly bool
	// Names are the statement's names outside each information_schema.x
	// pair, lower-cased, for a check against the session's tables that
	// doesn't rest on the walk having read every form.
	Names map[string]bool
}

// clauseEnds are the words that end a FROM list at its depth.
var clauseEnds = wordSet(`WHERE GROUP HAVING ORDER LIMIT WINDOW UNION INTERSECT EXCEPT INTO LOCK PROCEDURE`)

// fromFunctions take FROM between their arguments: EXTRACT(YEAR FROM d),
// TRIM(' ' FROM s), SUBSTRING(s FROM 2) and their synonyms.
var fromFunctions = wordSet(`EXTRACT TRIM SUBSTRING SUBSTR MID TRIM_ORACLE SUBSTR_ORACLE`)

// StatementAliases collects a statement's aliases from its tokens: a table
// after FROM, JOIN, a comma of a FROM list or TABLE, with an optional AS
// and an alias; a derived table's closing parenthesis and alias; a CTE's
// name. A name it can't place isn't added, so a column tied to it reads as
// computed. A statement the tokenizer refuses gives no aliases.
func StatementAliases(query string) Aliases {
	toks, err := statementTokens(query)
	if err != nil {
		return Aliases{Tables: map[string]string{}, Twice: map[string]bool{}}
	}
	al, _ := collectAliases(toks)
	return al
}

// collectAliases is StatementAliases on tokens. It also returns the tokens
// that stand as the database part of a table reference: x in FROM x.y,
// TABLE x.y and DESCRIBE x.y. The agent rules mark SHOW's own (showName).
//
// As a backstop for forms it doesn't read, a name tied to a base table that
// stands bare (neither before nor after a dot) more than once is marked
// Twice: an alias is defined bare and used before a dot, so two bare stands
// may be two definitions. A column named like an alias is marked too, which
// only makes the alias's columns read as computed. A CTE's or derived
// table's name is never tied, so it needs no mark.
func collectAliases(toks []stmtToken) (Aliases, map[int]bool) {
	al := Aliases{Tables: map[string]string{}, Twice: map[string]bool{}}
	quals := map[int]bool{}
	at := func(k int) stmtToken {
		if k < 0 || k >= len(toks) {
			return stmtToken{}
		}
		return toks[k]
	}
	define := func(name, table string) {
		key := strings.ToLower(name)
		if _, ok := al.Tables[key]; ok {
			al.Twice[key] = true
		}
		al.Tables[key] = table
	}
	aliasAt := func(j int) (string, int) {
		if at(j).word("AS") {
			j++
		}
		if n := at(j); isName(n) && !(n.kind == tokWord && notAliases[n.text]) {
			return n.raw, j + 1
		}
		return "", j
	}
	// skipHints steps past a table's index hints, such as USE INDEX FOR
	// ORDER BY (i), whose ORDER would otherwise end the FROM list.
	skipHints := func(j int) int {
		for (at(j).word("USE") || at(j).word("FORCE") || at(j).word("IGNORE")) && (at(j+1).word("INDEX") || at(j+1).word("KEY")) {
			h := j + 2
			if at(h).word("FOR") {
				if at(h+1).word("ORDER") || at(h+1).word("GROUP") {
					h++
				}
				h += 2
			}
			if !at(h).is('(') {
				break
			}
			j = skipGroup(toks, h)
		}
		return j
	}

	// CTE names first, so a FROM naming one reads it as no base table.
	ctes := map[string]bool{}
	for k := range toks {
		if !toks[k].word("WITH") || at(k+1).word("ROLLUP") {
			continue
		}
		j := k + 1
		if at(j).word("RECURSIVE") {
			j++
		}
		for isName(at(j)) {
			ctes[strings.ToLower(at(j).raw)] = true
			define(at(j).raw, "")
			j++
			if at(j).is('(') {
				j = skipGroup(toks, j)
			}
			if !at(j).word("AS") || !at(j+1).is('(') {
				break
			}
			j = skipGroup(toks, j+1)
			if !at(j).is(',') {
				break
			}
			j++
		}
	}

	read := map[string]bool{}
	infoRefs, otherRefs := 0, 0
	derived := map[int]bool{}   // a '(' opening a derived table or JSON_TABLE's columns
	fromParen := map[int]bool{} // a '(' opening a parenthesised join
	// ref reads one table reference at j and returns where the walk goes
	// on: past a table, its alias and its index hints, or at a parenthesis
	// it marked.
	ref := func(j int) int {
		if at(j).is('{') && at(j+1).word("OJ") {
			j += 2
		}
		if at(j).word("LATERAL") {
			j++
		}
		t := at(j)
		switch {
		case t.is('('):
			// A run of parentheses opens a derived table when a query
			// stands past it, and a parenthesised join otherwise.
			f := j
			for at(f).is('(') {
				f++
			}
			if first := at(f); first.word("SELECT") || first.word("WITH") || first.word("VALUES") || first.word("TABLE") {
				derived[j] = true
			} else {
				fromParen[j] = true
			}
			return j
		case t.word("JSON_TABLE") && at(j+1).is('('):
			derived[j+1] = true
			return j + 1
		case isName(t):
			name, end := t.raw, j+1
			if at(j+1).is('.') && isName(at(j+2)) {
				quals[j] = true
				name, end = at(j+2).raw, j+3
			}
			if end == j+3 && strings.EqualFold(t.raw, "information_schema") {
				infoRefs++
			} else {
				otherRefs++
			}
			key := strings.ToLower(name)
			target := name
			if ctes[key] {
				target = ""
			}
			// A CTE's name may also be a table's, read inside its own
			// definition: it stays a candidate.
			if !read[key] {
				read[key] = true
				al.Read = append(al.Read, name)
			}
			if at(end).word("PARTITION") && at(end+1).is('(') {
				end = skipGroup(toks, end+1)
			}
			alias, after := aliasAt(end)
			switch {
			case alias != "":
				define(alias, target)
			case target != "":
				define(name, target)
			}
			return skipHints(after)
		}
		return j
	}

	depth, inFrom := 0, map[int]bool{}
	var open []int
	// argFrom reports a FROM between a function's arguments: its innermost
	// parenthesis follows the function's name. A FROM clause inside such a
	// function stands in a subquery's own parentheses.
	argFrom := func() bool {
		if len(open) == 0 {
			return false
		}
		f := at(open[len(open)-1] - 1)
		return f.kind == tokWord && fromFunctions[f.text]
	}
	for k := 0; k < len(toks); {
		t := toks[k]
		switch {
		case t.is('('):
			open = append(open, k)
			depth++
			if fromParen[k] {
				inFrom[depth] = true
				k = max(ref(k+1), k+1)
				continue
			}
			k++
		case t.is(')'):
			delete(inFrom, depth)
			depth--
			opened := -1
			if len(open) > 0 {
				opened, open = open[len(open)-1], open[:len(open)-1]
			}
			k++
			if derived[opened] {
				alias, end := aliasAt(k)
				if alias != "" {
					define(alias, "")
				}
				k = end
			}
		case t.word("FROM") && !argFrom():
			inFrom[depth] = true
			k = max(ref(k+1), k+1)
		case inFrom[depth] && (t.word("JOIN") || t.word("STRAIGHT_JOIN") || t.is(',')):
			k = max(ref(k+1), k+1)
		case t.word("TABLE") && !at(k-1).word("CREATE") && !at(k-1).word("SHOW") && isName(at(k+1)):
			// The TABLE statement, or one in a union or a subquery.
			k = max(ref(k+1), k+1)
		case (t.word("DESCRIBE") || t.word("DESC") || t.word("EXPLAIN")) && isName(at(k+1)) && at(k+2).is('.') && isName(at(k+3)):
			// DESCRIBE or EXPLAIN x.y, a table's columns.
			quals[k+1] = true
			k++
		case t.kind == tokWord && clauseEnds[t.text]:
			delete(inFrom, depth)
			k++
		default:
			k++
		}
	}

	bare := map[string]int{}
	for k, t := range toks {
		if isName(t) && !at(k-1).is('.') && !at(k+1).is('.') {
			bare[strings.ToLower(t.raw)]++
		}
	}
	for key, table := range al.Tables {
		if table != "" && bare[key] > 1 {
			al.Twice[key] = true
		}
	}
	al.Names = map[string]bool{}
	qualifiedCall := false
	for k, t := range toks {
		if !isName(t) {
			continue
		}
		if !(strings.EqualFold(t.raw, "information_schema") && at(k+1).is('.') ||
			at(k-1).is('.') && strings.EqualFold(at(k-2).raw, "information_schema")) {
			al.Names[strings.ToLower(t.raw)] = true
		}
		if at(k+1).is('.') && isName(at(k+2)) && at(k+3).is('(') {
			qualifiedCall = true
		}
	}
	al.InformationSchemaOnly = infoRefs > 0 && otherRefs == 0 && !qualifiedCall
	return al, quals
}

// LeadingWord is a statement's first keyword, upper-cased, comments and
// parentheses before it skipped; "" when the statement can't be read.
func LeadingWord(query string) string {
	toks, err := statementTokens(query)
	if err != nil {
		return ""
	}
	for _, t := range toks {
		if t.kind == tokWord {
			return t.text
		}
		if !t.is('(') {
			return ""
		}
	}
	return ""
}
