package dbconn

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// ErrAgentStatement is returned by CheckAgentStatement for a statement an
// agent sent that the agent's rules don't allow. Its text names the rule
// and never quotes the statement, though it may name a function or variable
// the statement called, when the name is plain ASCII.
var ErrAgentStatement = errors.New("prodmask runs one read-only statement at a time, and refused this one")

type agentRefusal struct{ why string }

func (r *agentRefusal) Error() string { return ErrAgentStatement.Error() + ": " + r.why }
func (r *agentRefusal) Unwrap() error { return ErrAgentStatement }

func refuseAgent(why string) error { return &agentRefusal{why} }

// MaxAgentStatement is the longest statement, in bytes, an agent may send.
const MaxAgentStatement = 64 << 10

// AgentScope is what CheckAgentStatement knows of the session it checks a
// statement for.
type AgentScope struct {
	// Flavor is the server's flavour, "mysql" or "mariadb". Empty allows
	// only the functions both servers have built in.
	Flavor string
	// Database is the session's database, as the server names it.
	Database string
	// FoldCase marks a server that folds names' case (lower_case_table_names
	// 1 or 2): there the session's database in another case is still the
	// session's. Elsewhere only Database, byte for byte, is.
	FoldCase bool
	// Tables are the session database's tables and views.
	Tables []string
	// Functions are the session database's stored functions.
	Functions []string
	// Databases are the other databases the login can see, as read from
	// information_schema.SCHEMATA. Nil means the list couldn't be read, and
	// then a qualifier must be the session's database or information_schema;
	// outside a table reference it may also be one of the session's tables
	// or views, or a name the statement defines.
	Databases []string
}

// CheckAgentStatement applies the rules for a statement an agent writes,
// which is arbitrary SQL, unlike the scan's own statements: the read-only
// rules every session applies (checkStatement), then the agent's own. Those
// allow only a read, a few SHOW forms, the built-in functions that compute,
// read the session or read the clock, a short list of system variables, and
// names in the session's database and a few information_schema tables.
// Everything else is refused before anything is sent.
func CheckAgentStatement(query string, scope AgentScope) error {
	if len(query) > MaxAgentStatement {
		return refuseAgent("it's longer than 64 KB")
	}
	if err := checkStatement(query, false); err != nil {
		var r *refusal
		if errors.As(err, &r) {
			return refuseAgent(agentWords(r.why, query))
		}
		return refuseAgent("it isn't a read")
	}
	toks, err := statementTokens(query)
	if err != nil {
		return refuseAgent("it can't be read")
	}
	if n := len(toks); n > 0 && toks[n-1].is(';') {
		toks = toks[:n-1]
	}
	a := newAgentCheck(toks, scope)
	al, tablePos := collectAliases(toks)
	for name := range al.Tables {
		a.tables[name] = true
	}
	a.tablePos = tablePos
	return a.check()
}

var leadingShow = regexp.MustCompile(`(?is)^(?:\s+|/\*.*?\*/|#[^\n]*|--[^\n]*|\()*SHOW\b`)

// agentWords says why checkStatement refused, for the agent: with a way out
// for a string holding a backslash, which SHOW's LIKE can't take.
func agentWords(why, query string) string {
	if why != "a string holding a backslash" {
		return why
	}
	if leadingShow.MatchString(query) {
		return why + "; SHOW's LIKE takes no ESCAPE, so select from information_schema.TABLES with LIKE … ESCAPE '|' instead"
	}
	return why + "; write it without one, for example with LIKE … ESCAPE '|'"
}

type agentCheck struct {
	toks  []stmtToken
	scope AgentScope
	// opener[k] is the index of the innermost '(' still open at token k, or
	// -1; closer maps a '(' to its ')'.
	opener []int
	closer map[int]int
	// defined marks the tokens where a name the statement defines may stand
	// before '(': a CTE's name with a column list, a derived table's alias
	// with one. aliases holds the names the statement defines, upper-cased.
	defined map[int]bool
	aliases map[string]bool
	// tables are the names a qualifier may be: the statement's table
	// aliases, derived tables, CTEs and the tables it names, lower-cased
	// (collectAliases), never a column's alias.
	tables map[string]bool
	// tablePos marks the tokens that stand as the database part of a table
	// reference (collectAliases): a database's name to the server there,
	// whatever the statement defines.
	tablePos map[int]bool
}

func newAgentCheck(toks []stmtToken, scope AgentScope) *agentCheck {
	a := &agentCheck{toks: toks, scope: scope, opener: make([]int, len(toks)), closer: map[int]int{},
		defined: map[int]bool{}, aliases: map[string]bool{}, tables: map[string]bool{}, tablePos: map[int]bool{}}
	var stack []int
	for k, t := range toks {
		if len(stack) > 0 {
			a.opener[k] = stack[len(stack)-1]
		} else {
			a.opener[k] = -1
		}
		switch {
		case t.is('('):
			stack = append(stack, k)
		case t.is(')') && len(stack) > 0:
			a.closer[stack[len(stack)-1]] = k
			stack = stack[:len(stack)-1]
		}
	}
	return a
}

func (a *agentCheck) at(k int) stmtToken {
	if k >= 0 && k < len(a.toks) {
		return a.toks[k]
	}
	return stmtToken{}
}

// isName reports a bare word or a quoted name, not a string.
func isName(t stmtToken) bool {
	return t.kind == tokWord || t.kind == tokQuoted && !t.str
}

func (a *agentCheck) check() error {
	t := a.toks
	i := skipOpen(t, 0)
	if i == len(t) {
		return refuseAgent("not a read")
	}
	switch {
	case t[i].word("SHOW"):
		if err := a.show(i + 1); err != nil {
			return err
		}
	case t[i].word("EXPLAIN"), t[i].word("DESCRIBE"), t[i].word("DESC"):
	options:
		for j := i + 1; j < len(t); j++ {
			switch {
			case t[j].word("ANALYZE"):
				return refuseAgent("EXPLAIN ANALYZE, which runs its statement")
			case t[j].word("EXTENDED"), t[j].word("PARTITIONS"):
			case t[j].word("FORMAT") && a.at(j+1).is('='):
				// TREE and JSON print conditions with a const table's values
				// in them, as the dropped note 1003 does.
				if !a.at(j + 2).word("TRADITIONAL") {
					return refuseAgent("EXPLAIN FORMAT=TREE or JSON, which can print values from the rows it read; prodmask runs EXPLAIN's table")
				}
				j += 2
			default:
				break options
			}
		}
	}
	if err := a.collectDefinitions(); err != nil {
		return err
	}
	for k := range t {
		if err := a.token(k); err != nil {
			return err
		}
	}
	return nil
}

// token applies the rules that look at one token.
func (a *agentCheck) token(k int) error {
	t := a.toks[k]
	switch {
	case t.word("PROCEDURE"):
		return refuseAgent("PROCEDURE, which runs a procedure over the result")
	case t.word("CURRENT_USER"), t.word("CURRENT_ROLE"):
		return refuseAgent(t.text + ", which returns the login's account")
	case t.kind == tokQuoted && !t.str && strings.Contains(t.raw, "."):
		return refuseAgent("a quoted name holding a dot, which prodmask can't tell from a table's name and a column's; pick another")
	case t.is('@') && a.at(k+1).is('@') && !a.at(k-1).is('@'):
		return a.variable(k + 2)
	case t.is('.'):
		return a.qualifier(k)
	case isName(t) && a.at(k+1).is('('):
		return a.call(k)
	}
	return nil
}

// agentVariables are the system variables an agent may read with @@.
var agentVariables = wordSet(`VERSION VERSION_COMMENT SQL_MODE TIME_ZONE
	CHARACTER_SET_CLIENT CHARACTER_SET_CONNECTION CHARACTER_SET_DATABASE CHARACTER_SET_RESULTS
	CHARACTER_SET_SERVER CHARACTER_SET_SYSTEM COLLATION_CONNECTION COLLATION_DATABASE COLLATION_SERVER
	LOWER_CASE_TABLE_NAMES MAX_ALLOWED_PACKET GROUP_CONCAT_MAX_LEN MAX_EXECUTION_TIME MAX_STATEMENT_TIME
	TRANSACTION_ISOLATION TX_ISOLATION TRANSACTION_READ_ONLY TX_READ_ONLY AUTOCOMMIT SQL_SELECT_LIMIT
	LOCK_WAIT_TIMEOUT DEFAULT_STORAGE_ENGINE EXPLICIT_DEFAULTS_FOR_TIMESTAMP DIV_PRECISION_INCREMENT
	FOREIGN_KEY_CHECKS`)

// variable checks the name of @@name, @@session.name or @@global.name
// starting at token k.
func (a *agentCheck) variable(k int) error {
	if s := a.at(k); (s.word("SESSION") || s.word("GLOBAL") || s.word("LOCAL")) && a.at(k+1).is('.') {
		k += 2
	}
	if n := a.at(k); isName(n) && agentVariables[n.text] {
		return nil
	}
	return refuseAgent(fmt.Sprintf("the system variable %s, which prodmask doesn't show; it shows server settings such as @@version and @@sql_mode", shown(a.at(k))))
}

// agentInfoTables are the information_schema tables an agent may read.
var agentInfoTables = wordSet(`TABLES COLUMNS STATISTICS KEY_COLUMN_USAGE REFERENTIAL_CONSTRAINTS
	TABLE_CONSTRAINTS CHECK_CONSTRAINTS PARTITIONS CHARACTER_SETS COLLATIONS ENGINES`)

// qualifier checks the name before the '.' at token d, when it stands for a
// database: the first part of x.y or x.y.z.
func (a *agentCheck) qualifier(d int) error {
	q, next := a.at(d-1), a.at(d+1)
	switch {
	case d == 0 || !isName(q) || !(isName(next) || next.is('*')):
		return nil // not a name
	case q.kind == tokWord && allDigits(q.text):
		return nil // a number such as 1.5
	case !a.toks[d].glued && next.glued && next.kind == tokWord && next.text[0] >= '0' && next.text[0] <= '9':
		// A dot after a space, with a digit glued to it, is a number such
		// as .5. Glued to the word before, the servers read that word as
		// a qualifier and what follows as a name, digits first or not.
		return nil
	case a.at(d - 2).is('@'), a.at(d - 2).is('.'):
		return nil // @@session.x or @a.b; or y in x.y.z, a table
	}
	switch q.text {
	case "MYSQL", "PERFORMANCE_SCHEMA", "SYS":
		return refuseAgent("a name in the server's own " + strings.ToLower(q.text) + " schema")
	case "INFORMATION_SCHEMA":
		if !isASCII(q.raw) || !agentInfoTables[next.text] || !isASCII(next.raw) {
			return refuseAgent("an information_schema table prodmask doesn't read; it reads TABLES, COLUMNS, STATISTICS and the constraint tables")
		}
		return nil
	}
	if a.sessionDatabase(q.raw) {
		return nil
	}
	if a.scope.Databases != nil && a.otherDatabase(q.raw) {
		return refuseAgent("a name in another database")
	}
	// Before a table's name, a qualifier is a database's name to the
	// server, whatever the statement defines: an alias never stands for a
	// database there.
	if a.tablePos[d-1] {
		return refuseAgent("a table in another database")
	}
	if !isASCII(q.raw) {
		if slices.Contains(a.scope.Tables, q.raw) {
			return nil
		}
		return refuseAgent("a qualifier with letters outside ASCII that isn't this database or one of its tables")
	}
	if a.isTable(q.raw) || a.tables[strings.ToLower(q.raw)] {
		return nil
	}
	// A name in no list is refused too: a database created after the list
	// was read would pass a check against the list alone.
	if a.scope.Databases == nil {
		return refuseAgent("a qualifier prodmask can't place, since it couldn't read the list of databases")
	}
	return refuseAgent("a qualifier that isn't this database, one of its tables or a name the statement defines")
}

// sessionDatabase reports the session's database: its name byte for byte as
// the server gives it, or in another case on a server that folds case.
func (a *agentCheck) sessionDatabase(name string) bool {
	return name == a.scope.Database || a.scope.FoldCase && sameName(name, a.scope.Database)
}

// otherDatabase reports a name that matches a listed database, in any case,
// and isn't the session's: on a server that keeps names' case, Shop beside
// shop is another database.
func (a *agentCheck) otherDatabase(name string) bool {
	if a.sessionDatabase(name) {
		return false
	}
	for _, db := range a.scope.Databases {
		if sameName(name, db) {
			return true
		}
	}
	return false
}

func (a *agentCheck) isTable(name string) bool {
	for _, t := range a.scope.Tables {
		if sameName(name, t) {
			return true
		}
	}
	return false
}

// sameName compares a name from the statement with one from the server:
// byte for byte, or without case when both are ASCII.
func sameName(a, b string) bool {
	return a == b || isASCII(a) && isASCII(b) && strings.EqualFold(a, b)
}

// parenKeywords are the reserved words that may stand before '(' at the
// positions the grammar gives them, as bare words only: a quoted word is
// never a keyword to the server.
var parenKeywords = wordSet(`IN EXISTS VALUES OVER USING ON AS AND OR XOR NOT JOIN STRAIGHT_JOIN FROM
	SELECT WHERE HAVING BY DISTINCT UNION INTERSECT EXCEPT BETWEEN LIKE REGEXP RLIKE DIV MOD WHEN THEN
	ELSE CASE PARTITION INDEX KEY INTERVAL MATCH ALL BINARY GROUP`)

// typeNames are the types a CAST, CONVERT, JSON_TABLE column or RETURNING
// may give a length or precision in parentheses.
var typeNames = wordSet(`DECIMAL DEC NUMERIC FIXED CHAR CHARACTER NCHAR VARCHAR NVARCHAR BINARY
	VARBINARY DATETIME TIME TIMESTAMP FLOAT DOUBLE REAL INT INTEGER BIGINT SMALLINT TINYINT MEDIUMINT
	BIT YEAR VECTOR`)

// classWords say why a function of a refused class is refused.
var classWords = map[funcClass]string{
	classWait:    "waits or burns time",
	classLock:    "takes, frees or reads a user lock",
	classFile:    "reads a file on the server",
	classServer:  "reads or changes the server's own state",
	classAccount: "returns an account or a host",
}

// call checks the name before the '(' at token k+1.
func (a *agentCheck) call(k int) error {
	t := a.toks[k]
	if t.kind == tokWord && (parenKeywords[t.text] || a.nonReservedAt(k)) {
		return nil
	}
	if a.typeAt(k) || a.defined[k] {
		return nil
	}
	if a.at(k - 1).is('.') {
		if q := a.at(k - 2); isName(q) && a.sessionDatabase(q.raw) && a.storedFunction(t.raw) {
			return nil
		}
		return refuseAgent("a call to a function of another database, or by a qualified name prodmask doesn't know")
	}
	if !isASCII(t.raw) {
		return refuseAgent("a call to a function whose name has letters outside ASCII")
	}
	if t.kind == tokQuoted && !a.storedFunction(t.raw) {
		// A quoted name is never a built-in to the server: it calls a
		// loadable or stored function of that name.
		return refuseAgent(fmt.Sprintf("a call by the quoted name %s, which the server reads as a loadable or stored function", shown(t)))
	}
	if f, ok := agentFuncs[t.text]; ok && a.builtIn(f) && t.kind == tokWord {
		if f.class.allowed() {
			return nil
		}
		return refuseAgent(fmt.Sprintf("a call to %s, which %s", t.text, classWords[f.class]))
	}
	if a.storedFunction(t.raw) {
		return refuseAgent(fmt.Sprintf("a call to the stored function %s by its name alone: call it as %s.%s, since the server reads a name alone as a loadable function first",
			shown(t), shownRaw(a.scope.Database), shown(t)))
	}
	return refuseAgent(fmt.Sprintf("a call to %s, which isn't a function prodmask allows", shown(t)))
}

func (a *agentCheck) builtIn(f agentFunc) bool {
	switch a.scope.Flavor {
	case "mysql":
		return f.flavors&onMySQL != 0
	case "mariadb":
		return f.flavors&onMariaDB != 0
	}
	return f.flavors == onMySQL|onMariaDB
}

func (a *agentCheck) storedFunction(name string) bool {
	return slices.Contains(a.scope.Functions, name) || isASCII(name) && containsFold(a.scope.Functions, name)
}

// nonReservedAt reports a non-reserved keyword at the position the grammar
// gives it before '(': ANY or SOME after a comparison, AGAINST after
// MATCH's group, COLUMNS after JSON_TABLE's path, LATERAL after FROM, JOIN
// or a comma, ROW after a keyword or punctuation.
func (a *agentCheck) nonReservedAt(k int) bool {
	prev := a.at(k - 1)
	switch a.toks[k].text {
	case "ANY", "SOME":
		return prev.is('=') || prev.is('<') || prev.is('>')
	case "AGAINST":
		return prev.is(')')
	case "COLUMNS":
		return prev.kind == tokQuoted && prev.str
	// MariaDB reserves neither: OF( and LATERAL( are calls to functions
	// of those names there.
	case "LATERAL":
		return a.scope.Flavor == "mysql" && (prev.word("FROM") || prev.word("JOIN") || prev.is(','))
	case "OF":
		return a.scope.Flavor == "mysql" && prev.word("MEMBER")
	case "ROW":
		return prev.kind == tokPunct || prev.kind == tokWord && (parenKeywords[prev.text] || prev.text == "SELECT")
	}
	return false
}

// typeAt reports a type name at token k where a type may take a length:
// after AS inside CAST, after a comma inside CONVERT, after RETURNING, or
// after a column's name inside JSON_TABLE's COLUMNS.
func (a *agentCheck) typeAt(k int) bool {
	t := a.toks[k]
	if t.kind != tokWord || !typeNames[t.text] {
		return false
	}
	prev := a.at(k - 1)
	if prev.word("RETURNING") {
		return true
	}
	o := a.opener[k]
	if o < 1 {
		return false
	}
	switch fn := a.at(o - 1); {
	case fn.word("CAST"):
		return prev.word("AS")
	case fn.word("CONVERT"):
		return prev.is(',')
	case fn.word("COLUMNS"):
		return isName(prev)
	}
	return false
}

// notAliases are the words that may follow a table's name without being
// its alias.
var notAliases = wordSet(`WHERE ON USING JOIN INNER LEFT RIGHT CROSS NATURAL STRAIGHT_JOIN FULL OUTER
	GROUP ORDER LIMIT HAVING WINDOW UNION EXCEPT INTERSECT FOR LOCK PARTITION USE FORCE IGNORE AS INTO
	WITH SET TABLESAMPLE OFFSET FETCH ROWS RETURNING AND OR NOT`)

// collectDefinitions finds the names the statement defines (CTEs, derived
// tables' aliases, table and column aliases) and where a defined name may
// stand before '('. An alias named like another database is refused.
func (a *agentCheck) collectDefinitions() error {
	t := a.toks
	define := func(k int) {
		a.aliases[t[k].text] = true
		if a.at(k + 1).is('(') {
			a.defined[k] = true
		}
	}
	for k := range t {
		switch {
		case t[k].word("WITH") && !a.at(k+1).word("ROLLUP"):
			j := k + 1
			if a.at(j).word("RECURSIVE") {
				j++
			}
			for isName(a.at(j)) {
				define(j)
				j++
				if a.at(j).is('(') {
					j = skipGroup(t, j)
				}
				if !a.at(j).word("AS") || !a.at(j+1).is('(') {
					break
				}
				j = skipGroup(t, j+1)
				if !a.at(j).is(',') {
					break
				}
				j++
			}
		case t[k].is('('):
			c, ok := a.closer[k]
			if first := a.at(k + 1); !ok || !(first.word("SELECT") || first.word("WITH") || first.word("VALUES") ||
				first.word("TABLE") || first.is('(')) {
				continue
			}
			j := c + 1
			if a.at(j).word("AS") {
				j++
			}
			if n := a.at(j); isName(n) && !(n.kind == tokWord && notAliases[n.text]) {
				define(j)
			}
		case isName(t[k]) && a.at(k-1).word("AS"):
			a.aliases[t[k].text] = true
		case isName(t[k]) && !(t[k].kind == tokWord && notAliases[t[k].text]) && isName(a.at(k-1)) && a.tableBefore(k-1):
			a.aliases[t[k].text] = true
		}
	}
	if a.scope.Databases == nil {
		return nil
	}
	for name := range a.aliases {
		for _, db := range a.scope.Databases {
			if strings.EqualFold(name, db) && !sameName(db, a.scope.Database) {
				return refuseAgent("an alias that is another database's name; pick another")
			}
		}
	}
	return nil
}

// tableBefore reports a table's name at token k, by what comes before it:
// FROM, JOIN or a comma, perhaps with a database's name and a dot between.
func (a *agentCheck) tableBefore(k int) bool {
	lead := func(j int) bool { p := a.at(j); return p.word("FROM") || p.word("JOIN") || p.is(',') }
	if lead(k - 1) {
		return true
	}
	return a.at(k-1).is('.') && isName(a.at(k-2)) && lead(k-3)
}

// show checks a SHOW statement, starting at the token after SHOW.
func (a *agentCheck) show(j int) error {
	t := a.toks
	for k := j; k < len(t); k++ {
		if t[k].word("WHERE") {
			return refuseAgent("WHERE in a SHOW, whose subquery the server doesn't time-limit on MySQL; select from information_schema instead")
		}
	}
	at := func(k int, w string) bool { return a.at(k).word(w) }
	full := at(j, "FULL")
	if full {
		j++
	}
	switch {
	case at(j, "TABLES"):
		return a.showTail(j+1, true, true)
	case at(j, "COLUMNS"), at(j, "FIELDS"):
		return a.showOf(j+1, true)
	case full:
	case at(j, "TABLE") && at(j+1, "STATUS"):
		return a.showTail(j+2, true, true)
	case at(j, "INDEX"), at(j, "INDEXES"), at(j, "KEYS"):
		return a.showOf(j+1, false)
	case at(j, "CREATE") && (at(j+1, "TABLE") || at(j+1, "VIEW") || at(j+1, "TRIGGER")):
		if k := a.showName(j + 2); k == len(t) {
			return nil
		}
	case at(j, "TRIGGERS"):
		return a.showTail(j+1, true, true)
	case at(j, "CHARACTER") && at(j+1, "SET"):
		return a.showTail(j+2, false, true)
	case at(j, "CHARSET"), at(j, "COLLATION"):
		return a.showTail(j+1, false, true)
	case at(j, "ENGINES") && j+1 == len(t), at(j, "STORAGE") && at(j+1, "ENGINES") && j+2 == len(t):
		return nil
	}
	return refuseAgent("a SHOW prodmask doesn't run; it runs SHOW TABLES, COLUMNS, INDEX, TABLE STATUS, TRIGGERS, CREATE TABLE, CREATE VIEW, CREATE TRIGGER, CHARACTER SET, COLLATION and ENGINES")
}

// showOf checks FROM or IN and a table's name, then the rest.
func (a *agentCheck) showOf(j int, like bool) error {
	if !a.at(j).word("FROM") && !a.at(j).word("IN") {
		return refuseAgent("a SHOW without FROM and a table")
	}
	k := a.showName(j + 1)
	if k < 0 {
		return refuseAgent("a SHOW without a table's name")
	}
	return a.showTail(k, true, like)
}

// showName reads a name, perhaps qualified, at token j and returns the
// index after it, or -1. Its qualifier is a database's name, after FROM or
// IN as after CREATE TABLE: it's marked as standing before a table's name.
func (a *agentCheck) showName(j int) int {
	if !isName(a.at(j)) {
		return -1
	}
	if a.at(j+1).is('.') && isName(a.at(j+2)) {
		a.tablePos[j] = true
		return j + 3
	}
	return j + 1
}

// showTail checks what may end a SHOW: FROM or IN the session's database,
// then LIKE and a string, then nothing.
func (a *agentCheck) showTail(j int, db, like bool) error {
	if db && (a.at(j).word("FROM") || a.at(j).word("IN")) {
		if n := a.at(j + 1); !isName(n) || !a.sessionDatabase(n.raw) {
			return refuseAgent("a SHOW of another database")
		}
		j += 2
	}
	if like && a.at(j).word("LIKE") {
		if s := a.at(j + 1); s.kind != tokQuoted || !s.str {
			return refuseAgent("a SHOW whose LIKE isn't a string")
		}
		j += 2
	}
	if j != len(a.toks) {
		return refuseAgent("a SHOW with more than prodmask runs; it takes FROM this database and LIKE")
	}
	return nil
}

// shown is a name for a refusal's words: itself when it's plain ASCII
// letters, digits and underscores, else a placeholder.
func shown(t stmtToken) string { return shownRaw(t.raw) }

func shownRaw(s string) string {
	if !plainName(s) || len(s) > 64 {
		return "a name it doesn't show"
	}
	return s
}

func wordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if isASCII(v) && strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
