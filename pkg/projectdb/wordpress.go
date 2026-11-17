package projectdb

import (
	"bytes"
	"net"
	"strconv"
	"strings"
)

// The keys wp-config.php's refusals name, and the reasons they give.
var (
	wordpressKeys    = []string{"DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"}
	wordpressReasons = []string{
		reasonMissing, reasonEmpty, reasonTwice, reasonNotPlain, reasonForm,
		wpInBlock, wpConst, wpSilenced, wpThirdArg, reasonLines,
	}
	wordpressFileReasons = []string{
		wpInclude, wpEval, wpGoto, wpComputed, wpUnended, wpShortTag, wpAttribute, wpDynamic, wpNamespace,
	}
)

// The reasons wp-config.php gives for refusing one key, after its name.
const (
	wpInBlock  = "is set inside a block or a condition"
	wpConst    = "is set with const"
	wpSilenced = "is set with @define"
	wpThirdArg = "has a third argument"
)

// The reasons wp-config.php gives for refusing the whole file.
const (
	wpInclude   = "it includes another file before its database settings"
	wpEval      = "it runs eval before its database settings"
	wpGoto      = "it uses goto before its database settings"
	wpComputed  = "it calls a function through a variable or call_user_func before its database settings"
	wpUnended   = "it ends inside a comment, a string or a heredoc"
	wpShortTag  = "it has a short open tag, which PHP reads as code only with short_open_tag on"
	wpAttribute = "it has #[, which PHP 7 reads as a comment and PHP 8 as an attribute"
	wpDynamic   = "it calls define with a name prodmask can't read"
	wpNamespace = "it declares a namespace or imports a function, so its define may not be PHP's"
)

// clientFlags refuses wp-config.php wherever it's set, in any shape: it can
// ask for TLS or compression, which prodmask doesn't read.
const clientFlags = "MYSQL_CLIENT_FLAGS"

// wpSet is one place wp-config.php sets a database key.
type wpSet struct {
	pos    int    // the define's token
	value  string // the value, when it's read
	reason string // why it isn't, or ""
}

// readWordPress reads wp-config.php's database settings from its top-level
// define('KEY', 'value'); statements, without running PHP. It refuses
// whatever it can't be sure PHP reads the same way.
func readWordPress(data []byte) (*settings, error) {
	toks, reason := lexPHP(data)
	if reason != "" {
		return nil, fileError(WordPress, reason)
	}
	w := &walker{toks: toks, top: make([]bool, len(toks))}
	w.statements(true)

	sets := map[string][]wpSet{}
	flags, dynamic, namespaced := false, false, false
	// The first include, eval, goto or call through a variable, which before
	// the last database define could set a key first or skip the defines.
	first, firstReason := -1, ""
	note := func(i int, reason string) {
		if first < 0 {
			first, firstReason = i, reason
		}
	}
	inConst := -1 // the bracket depth inside a const statement, or -1
	for i, t := range toks {
		if inConst >= 0 && t.kind == tPunct {
			switch {
			case opens(t.text):
				inConst++
			case closes(t.text):
				inConst--
			case t.text == ";" && inConst == 0:
				inConst = -1
			}
		} else if inConst == 0 && t.kind == tName && punct(at(toks, i+1), "=") {
			// A constant the const statement declares.
			switch key, _ := checkedKey(t.text); key {
			case "":
			case clientFlags:
				flags = true
			default:
				sets[key] = append(sets[key], wpSet{pos: i, reason: wpConst})
			}
		}
		switch {
		case t.kind == tStr:
			// A callback, as in array_map('define', …), can define any key.
			dynamic = dynamic || t.plain && lastName(t.text, "define")
		case t.kind == tVar || punct(t, "]") || punct(t, "}"):
			// A call through a variable or what an expression gives, as in
			// $f(…), $a['f'](…) or ${'f'}(…). A ( that starts a statement
			// isn't one.
			if punct(at(toks, i+1), "(") && !w.top[i+1] {
				note(i, wpComputed)
			}
		case t.kind != tName || member(toks, i):
		case isWord(t.text, "include", "include_once", "require", "require_once"):
			note(i, wpInclude)
		case isWord(t.text, "eval"):
			note(i, wpEval)
		case isWord(t.text, "goto"):
			note(i, wpGoto)
		case lastName(t.text, "call_user_func", "call_user_func_array", "forward_static_call", "forward_static_call_array") &&
			punct(at(toks, i+1), "("):
			note(i, wpComputed)
		case isWord(t.text, "namespace"), isWord(t.text, "use") && w.top[i] && importsFunction(toks, i):
			// Either makes an unqualified define call a function of the
			// file's own, such as Site\define.
			namespaced = true
		case isWord(t.text, "const"):
			inConst = 0
		case lastName(t.text, "define") && punct(at(toks, i+1), "("):
			key, s, unknown := w.define(i)
			dynamic = dynamic || unknown
			switch key {
			case "":
			case clientFlags:
				flags = true
			default:
				sets[key] = append(sets[key], s)
			}
		}
	}

	switch {
	case flags:
		return nil, refuse(WordPress, textClientFlags)
	case dynamic:
		return nil, fileError(WordPress, wpDynamic)
	case namespaced:
		return nil, fileError(WordPress, wpNamespace)
	}
	values := map[string]string{}
	last := -1 // the last database define, or past the end when one is missing
	for _, key := range wordpressKeys {
		for _, s := range sets[key] {
			if s.reason != "" {
				return nil, keyError(WordPress, key, s.reason)
			}
		}
		switch len(sets[key]) {
		case 0:
			last = len(toks) // an included file could set it
		case 1:
			values[key] = sets[key][0].value
			last = max(last, sets[key][0].pos)
		default:
			return nil, keyError(WordPress, key, reasonTwice)
		}
	}
	// PHP keeps a constant's first definition, so an included file, eval or a
	// call through a variable before the defines could set any of them
	// first, and a goto could skip them.
	if first >= 0 && first < last {
		return nil, fileError(WordPress, firstReason)
	}
	for _, key := range wordpressKeys {
		if _, ok := values[key]; !ok {
			return nil, keyError(WordPress, key, reasonMissing)
		}
	}
	for _, key := range []string{"DB_NAME", "DB_USER"} {
		if values[key] == "" {
			return nil, keyError(WordPress, key, reasonEmpty)
		}
	}
	s := &settings{user: values["DB_USER"], password: values["DB_PASSWORD"], database: values["DB_NAME"]}
	var ok bool
	if s.host, s.port, s.socket, ok = wordpressHost(values["DB_HOST"]); !ok {
		return nil, keyError(WordPress, "DB_HOST", reasonForm)
	}
	return s, nil
}

// define reads the define call at toks[i]: the checked key it sets, if any,
// and its value or why it can't be read. unknown reports a name that isn't
// one plain string, which could be any key.
func (w *walker) define(i int) (key string, s wpSet, unknown bool) {
	name, after := at(w.toks, i+2), at(w.toks, i+3)
	if name.kind != tStr || !name.plain || !punct(after, ",") && !punct(after, ")") {
		return "", s, true
	}
	key, exact := checkedKey(name.text)
	s.pos = i
	switch {
	case key == "" || key == clientFlags:
	case !exact || strings.Contains(strings.TrimPrefix(w.toks[i].text, `\`), `\`):
		// A lookalike name, or a namespaced function such as Foo\define.
		s.reason = reasonForm
	case punct(at(w.toks, i-1), "@"):
		s.reason = wpSilenced
	case !w.top[i]:
		s.reason = wpInBlock
	default:
		s.value, s.reason = defineValue(w.toks, i+3)
	}
	return key, s, false
}

// defineValue reads the rest of define('KEY', 'value'); from the token after
// the key: one plain string, then ); or ?>. A trailing comma is fine.
func defineValue(toks []token, j int) (value, reason string) {
	if !punct(toks[j], ",") {
		return "", reasonForm // no value
	}
	v, end := at(toks, j+1), j+2
	if v.kind != tStr || !v.plain || !punct(at(toks, end), ")") && !punct(at(toks, end), ",") {
		return "", reasonNotPlain
	}
	if punct(at(toks, end), ",") {
		if !punct(at(toks, end+1), ")") {
			return "", wpThirdArg
		}
		end++
	}
	switch {
	case !punct(at(toks, end+1), ";"):
		return "", reasonForm
	case strings.Contains(v.text, "\n"):
		// The file's CRLF line ends were made LF, so a value over several
		// lines may not be the one PHP reads.
		return "", reasonLines
	}
	return v.text, ""
}

// checkedKey names the database key or MYSQL_CLIENT_FLAGS that a constant's
// name sets, and whether it's that name exactly. A lookalike, in another case
// or after a backslash, still names its key, to be refused.
func checkedKey(name string) (key string, exact bool) {
	bare := strings.TrimPrefix(name, `\`)
	for _, k := range append([]string{clientFlags}, wordpressKeys...) {
		if strings.EqualFold(bare, k) {
			return k, name == k
		}
	}
	return "", false
}

// member reports a name that is neither a keyword nor called as a function
// of its own: a method, property or class constant after ->, ?-> or ::, a
// declared function's name, a class after new, or a named argument's label,
// which PHP 8 lets be a keyword, as in f(namespace: 1).
func member(toks []token, i int) bool {
	prev := at(toks, i-1)
	switch {
	case punct(prev, "->"), punct(prev, "?->"), punct(prev, "::"), word(prev, "function", "new"):
		return true
	case punct(prev, "&"):
		return word(at(toks, i-2), "function")
	}
	return punct(at(toks, i+1), ":")
}

func at(toks []token, i int) token {
	if i < 0 || i >= len(toks) {
		return token{}
	}
	return toks[i]
}

func punct(t token, s string) bool { return t.kind == tPunct && t.text == s }

// word reports a name that is one of words, in any case, as PHP's keywords
// are.
func word(t token, words ...string) bool { return t.kind == tName && isWord(t.text, words...) }

func isWord(s string, words ...string) bool {
	for _, w := range words {
		if strings.EqualFold(s, w) {
			return true
		}
	}
	return false
}

// lastName reports whether a name's last part, after any backslash, is one of
// names, in any case.
func lastName(s string, names ...string) bool {
	return isWord(s[strings.LastIndexByte(s, '\\')+1:], names...)
}

// importsFunction reports whether the use statement at toks[i] imports a
// function, as use function Site\define; and use Site\{function define}; do.
func importsFunction(toks []token, i int) bool {
	for j := i + 1; j < len(toks) && !punct(toks[j], ";"); j++ {
		if word(toks[j], "function") {
			return true
		}
	}
	return false
}

func opens(s string) bool  { return s == "(" || s == "[" || s == "{" }
func closes(s string) bool { return s == ")" || s == "]" || s == "}" }

// A token is one piece of PHP code. Comments, whitespace and the text outside
// the PHP tags make none.
type token struct {
	kind tokKind
	// text is a name or punctuation as written, ";" for ?>, or a plain
	// string's value.
	text string
	// plain marks a string that is one plain value: single-quoted, or
	// double-quoted with no \ or $.
	plain bool
}

type tokKind uint8

const (
	tNone  tokKind = iota
	tName          // a name or keyword, maybe qualified: define, \define, Foo\bar
	tVar           // a variable
	tNum           // a number
	tStr           // a quoted string, a heredoc or a nowdoc
	tPunct         // punctuation or an operator
)

// lexer splits PHP into tokens as PHP's own scanner does, for the parts that
// decide where code, comments and strings are.
type lexer struct {
	src    []byte
	pos    int
	toks   []token
	reason string // why the file can't be read, or ""
	halted bool   // after __halt_compiler, PHP reads nothing
}

// lexPHP returns the tokens of data's PHP code, or why it can't split it.
func lexPHP(data []byte) ([]token, string) {
	l := &lexer{src: data}
	for !l.stopped() {
		i := bytes.Index(l.src[l.pos:], []byte("<?"))
		if i < 0 {
			break
		}
		l.pos += i + 2
		rest := l.src[l.pos:]
		switch {
		case len(rest) >= 3 && strings.EqualFold(string(rest[:3]), "php") && (len(rest) == 3 || isSpace(rest[3])):
			l.pos += 3
		case len(rest) > 0 && rest[0] == '=':
			l.pos++
			l.emit(tName, "echo")
		default:
			// <? alone, or <?php run into more letters, is code only when
			// short_open_tag is on, which a config file can't show.
			l.reason = wpShortTag
			return nil, l.reason
		}
		l.code(false)
	}
	return l.toks, l.reason
}

func (l *lexer) stopped() bool { return l.reason != "" || l.halted }

func (l *lexer) emit(k tokKind, text string) { l.toks = append(l.toks, token{kind: k, text: text}) }

func (l *lexer) peek(n int) byte {
	if l.pos+n < len(l.src) {
		return l.src[l.pos+n]
	}
	return 0
}

// code reads PHP code through ?>, or, inside a string, through the } that
// ends an interpolation.
func (l *lexer) code(inner bool) {
	depth := 0
	for !l.stopped() {
		if l.pos >= len(l.src) {
			if inner {
				l.reason = wpUnended
			}
			return
		}
		c, next := l.src[l.pos], l.peek(1)
		switch {
		case isSpace(c):
			l.pos++
		case c == '?' && next == '>':
			if inner {
				l.reason = wpUnended
				return
			}
			l.pos += 2
			l.emit(tPunct, ";") // PHP reads ?> as the end of a statement
			return
		case c == '#' && next == '[':
			l.reason = wpAttribute
		case c == '#' || c == '/' && next == '/':
			l.lineComment()
		case c == '/' && next == '*':
			l.blockComment()
		case c == '\'':
			l.single()
		case c == '"' || c == '`':
			l.interpolated(c)
		case c == '<' && l.heredoc():
		case c == '$' && isLabelStart(next):
			start := l.pos
			l.pos++
			l.skipLabel()
			l.emit(tVar, string(l.src[start:l.pos]))
		case isLabelStart(c) || c == '\\' && isLabelStart(next):
			l.name()
		case c >= '0' && c <= '9':
			l.number()
		case c == '{':
			depth++
			l.pos++
			l.emit(tPunct, "{")
		case c == '}':
			l.pos++
			l.emit(tPunct, "}")
			if inner && depth == 0 {
				return
			}
			depth--
		default:
			l.punct()
		}
	}
}

// lineComment skips a // or # comment, which ends at a newline (a lone CR
// too) or before ?>.
func (l *lexer) lineComment() {
	for ; l.pos < len(l.src); l.pos++ {
		if c := l.src[l.pos]; c == '\n' || c == '\r' || c == '?' && l.peek(1) == '>' {
			return
		}
	}
}

func (l *lexer) blockComment() {
	end := bytes.Index(l.src[l.pos+2:], []byte("*/"))
	if end < 0 {
		l.reason = wpUnended
		return
	}
	l.pos += 2 + end + 2
}

// single reads a single-quoted string, whose value decodes only \\ and \'.
func (l *lexer) single() {
	var b []byte
	for i := l.pos + 1; i < len(l.src); i++ {
		c := l.src[i]
		if c == '\'' {
			l.pos = i + 1
			l.toks = append(l.toks, token{kind: tStr, text: string(b), plain: true})
			return
		}
		if c == '\\' && i+1 < len(l.src) && (l.src[i+1] == '\\' || l.src[i+1] == '\'') {
			i++
			c = l.src[i]
		}
		b = append(b, c)
	}
	l.reason = wpUnended
}

// interpolated reads a double-quoted or backtick string. A backslash skips
// the next byte, and {$ or ${ opens code up to its }, whose tokens follow the
// string's own. Only a double-quoted string with no \ or $ is plain.
func (l *lexer) interpolated(quote byte) {
	idx := len(l.toks)
	l.emit(tStr, "")
	l.pos++
	start, plain := l.pos, quote == '"'
	for !l.stopped() {
		if l.pos >= len(l.src) {
			l.reason = wpUnended
			return
		}
		switch c := l.src[l.pos]; {
		case c == quote:
			if plain {
				l.toks[idx] = token{kind: tStr, text: string(l.src[start:l.pos]), plain: true}
			}
			l.pos++
			return
		case c == '\\':
			plain = false
			l.pos += 2
		case c == '$' || c == '{':
			plain = plain && c != '$'
			l.interpolation()
		default:
			l.pos++
		}
	}
}

// interpolation reads what starts at a $ or { inside a string: {$ and ${
// open code up to the matching }, and anything else is text.
func (l *lexer) interpolation() {
	switch c, next := l.src[l.pos], l.peek(1); {
	case c == '{' && next == '$':
		l.pos++ // the code starts at the $
	case c == '$' && next == '{':
		l.pos += 2
	default:
		l.pos++
		return
	}
	l.emit(tPunct, "{")
	l.code(true)
}

// heredoc reads a heredoc or nowdoc at <<<, and reports whether there was
// one. Its closing name may be indented, and needs a byte after it, as in
// PHP 7.3 and later.
func (l *lexer) heredoc() bool {
	if !bytes.HasPrefix(l.src[l.pos:], []byte("<<<")) {
		return false
	}
	i := l.pos + 3
	for i < len(l.src) && (l.src[i] == ' ' || l.src[i] == '\t') {
		i++
	}
	quote := byte(0)
	if i < len(l.src) && (l.src[i] == '\'' || l.src[i] == '"') {
		quote = l.src[i]
		i++
	}
	start := i
	if i >= len(l.src) || !isLabelStart(l.src[i]) {
		return false
	}
	for i < len(l.src) && isLabelChar(l.src[i]) {
		i++
	}
	label := l.src[start:i]
	if quote != 0 {
		if i >= len(l.src) || l.src[i] != quote {
			return false
		}
		i++
	}
	if i >= len(l.src) || l.src[i] != '\n' && l.src[i] != '\r' {
		return false
	}
	l.pos = i + 1
	l.emit(tStr, "") // never plain
	for !l.stopped() {
		j := l.pos
		for j < len(l.src) && (l.src[j] == ' ' || l.src[j] == '\t') {
			j++
		}
		if end := j + len(label); end < len(l.src) && bytes.HasPrefix(l.src[j:], label) && !isLabelChar(l.src[end]) {
			l.pos = end
			return true
		}
		l.line(quote != '\'')
	}
	return true
}

// line reads one line of a heredoc's body through its newline. In a heredoc,
// not a nowdoc, a backslash skips the next byte unless it ends the line, and
// {$ or ${ opens code.
func (l *lexer) line(interp bool) {
	for !l.stopped() {
		if l.pos >= len(l.src) {
			l.reason = wpUnended
			return
		}
		switch c := l.src[l.pos]; {
		case c == '\n' || c == '\r':
			l.pos++
			return
		case interp && c == '\\':
			l.pos++
			if next := l.peek(0); next != 0 && next != '\n' && next != '\r' {
				l.pos++
			}
		case interp && (c == '$' || c == '{'):
			l.interpolation()
		default:
			l.pos++
		}
	}
}

// name reads a name, maybe qualified with backslashes. PHP reads nothing
// after __halt_compiler.
func (l *lexer) name() {
	start := l.pos
	if l.src[l.pos] == '\\' {
		l.pos++
	}
	l.skipLabel()
	for l.peek(0) == '\\' && isLabelStart(l.peek(1)) {
		l.pos++
		l.skipLabel()
	}
	text := string(l.src[start:l.pos])
	l.emit(tName, text)
	l.halted = strings.EqualFold(text, "__halt_compiler")
}

func (l *lexer) skipLabel() {
	for l.pos < len(l.src) && isLabelChar(l.src[l.pos]) {
		l.pos++
	}
}

func (l *lexer) number() {
	start := l.pos
	for l.pos < len(l.src) && (isLabelChar(l.src[l.pos]) || l.src[l.pos] == '.' && l.peek(1) >= '0' && l.peek(1) <= '9') {
		l.pos++
	}
	l.emit(tNum, string(l.src[start:l.pos]))
}

// puncts are the operators of more than one byte that tell the statements
// apart: ?-> and :: from ? and :, and = from == and =>.
var puncts = []string{
	"?->", "===", "!==", "<=>", "**=", "...", "<<=", ">>=", "??=",
	"->", "::", "=>", "==", "!=", "<>", "<=", ">=", "&&", "||", "??", "++", "--",
	"+=", "-=", "*=", "/=", ".=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
}

func (l *lexer) punct() {
	rest := l.src[l.pos:]
	for _, p := range puncts {
		if len(rest) >= len(p) && string(rest[:len(p)]) == p {
			l.pos += len(p)
			l.emit(tPunct, p)
			return
		}
	}
	l.pos++
	l.emit(tPunct, string(rest[:1]))
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isLabelStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isLabelChar(c byte) bool { return isLabelStart(c) || c >= '0' && c <= '9' }

// walker marks the tokens that start a statement at the top level: at brace
// depth 0, outside an alternative-syntax block such as if (…): … endif;, and
// not in the condition or the braceless body of a control structure. What it
// can't place stays unmarked, so a define there is refused, never read.
type walker struct {
	toks []token
	i    int
	top  []bool
}

// endWords close each alternative-syntax block.
var endWords = map[string]string{
	"else": "endif", "while": "endwhile", "for": "endfor", "foreach": "endforeach",
	"switch": "endswitch", "declare": "enddeclare",
}

func (w *walker) cur() token { return at(w.toks, w.i) }

// statements reads statements up to a } or one of the words in stops, or to
// the end.
func (w *walker) statements(top bool, stops ...string) {
	for w.i < len(w.toks) {
		switch t := w.toks[w.i]; {
		case punct(t, "}") && top:
			w.i++ // a stray brace, which PHP wouldn't parse
		case punct(t, "}"), word(t, stops...):
			return
		default:
			w.statement(top)
		}
	}
}

// statement reads one statement.
func (w *walker) statement(top bool) {
	t := w.toks[w.i]
	if top {
		w.top[w.i] = true
	}
	kw := ""
	if t.kind == tName {
		kw = strings.ToLower(t.text)
	}
	switch {
	case punct(t, ";"):
		w.i++
	case punct(t, "{"):
		w.skipGroup()
	case kw == "if" || kw == "elseif":
		w.i++
		w.ifRest()
	case endWords[kw] != "":
		w.i++
		if kw != "else" {
			w.parens()
		}
		w.body(endWords[kw])
	case kw == "do":
		w.i++
		if w.i < len(w.toks) {
			w.statement(false)
		}
		if word(w.cur(), "while") {
			w.i++
			w.parens()
		}
	case kw == "try" || kw == "catch" || kw == "finally":
		w.i++
		w.parens()
		if punct(w.cur(), "{") {
			w.skipGroup()
		}
	case isWord(kw, "function", "class", "interface", "trait", "enum", "namespace", "abstract", "final", "readonly"):
		w.declaration()
	case kw == "case" || kw == "default":
		w.until(":")
	case kw != "" && !strings.Contains(kw, `\`) && punct(at(w.toks, w.i+1), ":"):
		w.i += 2 // a goto label
	default:
		w.until(";")
	}
}

// ifRest reads an if's condition and body, then its elseif and else parts.
func (w *walker) ifRest() {
	for {
		w.parens()
		alt := w.body("endif", "elseif", "else")
		switch {
		case word(w.cur(), "elseif"):
			w.i++
		case word(w.cur(), "else") && !alt && word(at(w.toks, w.i+1), "if"):
			w.i += 2
		case word(w.cur(), "else"):
			w.i++
			w.body("endif")
			return
		default:
			return
		}
	}
}

// body reads a control structure's body: one statement, or, after a colon,
// an alternative-syntax block's statements through ends[0] and its ;. It
// reports the alternative syntax.
func (w *walker) body(ends ...string) bool {
	if !punct(w.cur(), ":") {
		if w.i < len(w.toks) {
			w.statement(false)
		}
		return false
	}
	w.i++
	w.statements(false, ends...)
	if word(w.cur(), ends[0]) {
		w.i++
		if punct(w.cur(), ";") {
			w.i++
		}
	}
	return true
}

func (w *walker) parens() {
	if punct(w.cur(), "(") {
		w.skipGroup()
	}
}

// skipGroup skips from an opening bracket past its match.
func (w *walker) skipGroup() {
	depth := 0
	for ; w.i < len(w.toks); w.i++ {
		t := w.toks[w.i]
		switch {
		case t.kind != tPunct:
		case opens(t.text):
			depth++
		case closes(t.text):
			if depth--; depth <= 0 {
				w.i++
				return
			}
		}
	}
}

// declaration skips a function, class or namespace declaration: through a ;
// or through the block that is its body.
func (w *walker) declaration() {
	for w.i < len(w.toks) {
		t := w.toks[w.i]
		switch {
		case punct(t, "{"):
			w.skipGroup()
			return
		case punct(t, ";"):
			w.i++
			return
		case t.kind == tPunct && closes(t.text):
			return
		case t.kind == tPunct && opens(t.text):
			w.skipGroup()
		default:
			w.i++
		}
	}
}

// until skips a statement through end, a ; or a : for a switch's case label,
// with brackets matched. It stops before a } that closes the block around it.
func (w *walker) until(end string) {
	for w.i < len(w.toks) {
		t := w.toks[w.i]
		switch {
		case punct(t, end), punct(t, ";"):
			w.i++
			return
		case punct(t, "}"):
			return
		case t.kind == tPunct && opens(t.text):
			w.skipGroup()
		default:
			w.i++
		}
	}
}

// wordpressHost reads DB_HOST as wpdb::parse_db_host does. A socket follows
// the first ":/". What's left is an IPv6 address, bracketed with an optional
// port or bare, when it holds two colons, and otherwise a host with an
// optional port. PHP's empty() makes a host of "0" empty and a port of 0 the
// default. Only the whole value in one of those forms is read: a p: prefix,
// which asks mysqli for a persistent connection, or anything after a valid
// form, isn't. As mysqli does, the socket is used only for an empty host or
// localhost, and dropped for TCP to any other.
func wordpressHost(v string) (host string, port int, socket string, ok bool) {
	if len(v) >= 2 && v[1] == ':' && (v[0] == 'p' || v[0] == 'P') {
		return "", 0, "", false
	}
	if i := strings.Index(v, ":/"); i >= 0 {
		v, socket = v[:i], v[i+1:]
	}
	host, digits, hasPort := v, "", false
	if strings.Count(v, ":") > 1 {
		if v[0] == '[' {
			end := strings.IndexByte(v, ']')
			if end < 0 {
				return "", 0, "", false
			}
			host = v[1:end]
			if rest := v[end+1:]; rest != "" {
				if rest[0] != ':' {
					return "", 0, "", false
				}
				digits, hasPort = rest[1:], true
			}
		}
		if strings.Trim(host, "0123456789abcdefABCDEF:") != "" || net.ParseIP(host) == nil {
			return "", 0, "", false
		}
	} else {
		if i := strings.IndexByte(v, ':'); i >= 0 {
			host, digits, hasPort = v[:i], v[i+1:], true
		}
		if strings.ContainsAny(host, "/[]") {
			return "", 0, "", false
		}
		if host == "0" {
			host = ""
		}
	}
	if hasPort {
		if port, ok = wordpressPort(digits); !ok {
			return "", 0, "", false
		}
	}
	if socket != "" && (host == "" || strings.EqualFold(host, "localhost")) {
		return "", 0, socket, true
	}
	return host, port, "", true
}

// wordpressPort reads a port of ASCII digits as absint does, up to 65535.
func wordpressPort(digits string) (int, bool) {
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}
	digits = strings.TrimLeft(digits, "0")
	if len(digits) > 5 {
		return 0, false
	}
	n, _ := strconv.Atoi(digits) // "" after the zeros is 0, the default
	return n, n <= 65535
}
