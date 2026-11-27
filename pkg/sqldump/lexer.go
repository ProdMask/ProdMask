package sqldump

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"unicode/utf8"
)

const (
	readBufSize    = 64 << 10
	maxIdent       = 256
	maxDelim       = 15 // the clients keep 15 bytes of a delimiter
	shortWord      = 16
	maxCommentLine = 256
)

var bom = []byte{0xEF, 0xBB, 0xBF}

type tokKind uint8

const (
	tokEOF    tokKind = iota
	tokEnd            // the statement delimiter
	tokWord           // an unquoted name or keyword
	tokNum            // a number
	tokString         // a quoted string, decoded
	tokHex            // 0x41 or X'41', as bytes
	tokBit            // 0b01 or b'01', as digits
	tokIdent          // a quoted identifier
	tokVar            // @name or @@name.name
	tokSym            // one punctuation byte
	tokErr            // a lexing fault, with a reason
	tokClient         // a command of the mysql client's own, which ends the statement
)

// token is one lexical item. Its text is valid until the lexer reads the
// next token of the same family.
type token struct {
	kind tokKind
	text []byte
	sym  byte
	cut  bool // a string or hex literal longer than the cap
	bad  bool // a hex or bit literal that is malformed or of odd length
	err  Reason
	line int
	unc  int // the uncertain version comment it was lexed in, from 1, or 0
}

// is reports whether the token is the keyword kw, which must be lower case.
func (t token) is(kw string) bool {
	if t.kind != tokWord || len(t.text) != len(kw) {
		return false
	}
	for i := 0; i < len(kw); i++ {
		c := t.text[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != kw[i] {
			return false
		}
	}
	return true
}

func (t token) isSym(c byte) bool { return t.kind == tokSym && t.sym == c }

// valBuf collects a decoded literal up to a cap in characters.
type valBuf struct {
	b       []byte
	chars   int
	cap     int
	cut     bool
	discard bool
	cs      csKind
	one     [1]byte
}

func (v *valBuf) reset(cs csKind, limit int, discard bool) {
	v.b = v.b[:0]
	v.chars = 0
	v.cap = limit
	v.cut = false
	v.discard = discard
	v.cs = cs
}

func (v *valBuf) addByte(c byte) {
	v.one[0] = c
	v.add(v.one[:])
}

// add appends decoded text. Once the cap is reached the rest is dropped and
// the value is flagged as cut; a character is never cut in the middle.
func (v *valBuf) add(p []byte) {
	if v.cut || v.discard || len(p) == 0 {
		return
	}
	switch v.cs {
	case csBinary:
		room := v.cap - v.chars
		if len(p) > room {
			v.b = append(v.b, p[:room]...)
			v.chars += room
			v.cut = true
			return
		}
		v.b = append(v.b, p...)
		v.chars += len(p)
	case csLatin1:
		for _, c := range p {
			if v.chars >= v.cap {
				v.cut = true
				return
			}
			v.chars++
			if c < 0x80 {
				v.b = append(v.b, c)
			} else {
				v.b = utf8.AppendRune(v.b, latin1Rune(c))
			}
		}
	default:
		chars := v.chars
		for i, c := range p {
			if c&0xC0 != 0x80 {
				if chars >= v.cap {
					v.b = append(v.b, p[:i]...)
					v.chars = chars
					v.cut = true
					return
				}
				chars++
			}
		}
		v.b = append(v.b, p...)
		v.chars = chars
	}
}

// lexer splits a dump into tokens the way the mysql client splits it into
// statements. It reads through a bufio.Reader and never holds a statement.
type lexer struct {
	br  *bufio.Reader
	ctx context.Context

	line  int
	delim []byte

	atStart  bool // no token yet in this statement
	blank    bool // nothing yet on this line but spaces: no token or comment
	inExec   bool // inside an executable comment
	exec     bool // an executable comment opened in this statement
	prevName bool // the last token was a name, so a dot is punctuation

	noBackslash bool
	ansiQuotes  bool
	cs          csKind
	override    csKind
	mb          mbKind
	maxChars    int

	discard bool // skipping: strings and long words aren't kept
	join    bool // the next string token extends the last one

	// hexWide lets a hex literal keep four bytes for each character of the
	// cap, for the row reader to cut by the column's own measure.
	hexWide bool

	vb, hb, ib valBuf // strings, hex and bit literals, quoted identifiers
	wb         []byte // words and variables
	wlong      bool

	onComment func(text []byte, line int)
	cbuf      []byte

	// What the statement in progress holds of uncertain version comments,
	// which some supported server may skip: every /*M!, a /*! of one to four
	// or six digits, or of five from 50700. MySQL skips every /*M! and
	// versions above its own; MariaDB skips 50700 to 99999. startStatement
	// clears it.
	ntok        int  // tokens lexed in the statement
	vOutside    int  // tokens lexed outside uncertain comments
	vOpen       int  // ntok where the first uncertain comment opened, or -1
	vLine       int  // the line it opened on
	vFault      bool // one is broken: see blockComment
	inUncertain bool // inside an uncertain comment
	vDepth      int  // parentheses opened inside it
	star        bool // the last byte watched inside it was *
	vNonLit     bool // one holds a token other than a string or a number
	vCom        []vComment

	err error
	eof bool
}

// vComment is an uncertain comment of the statement in progress: how many
// tokens it holds, and how many a parser found to be a listed form in its
// place (approve), or -1 for more than one form.
type vComment struct {
	tokens int
	form   int
}

func newLexer(ctx context.Context, r io.Reader, maxChars int) *lexer {
	if maxChars <= 0 {
		maxChars = defaultMaxChars
	}
	lx := &lexer{
		br:       bufio.NewReaderSize(r, readBufSize),
		ctx:      ctx,
		line:     1,
		delim:    []byte{';'},
		atStart:  true,
		blank:    true,
		override: csNone,
		maxChars: maxChars,
		vOpen:    -1,
	}
	if b, _ := lx.br.Peek(3); bytes.Equal(b, bom) {
		lx.br.Discard(3)
	}
	return lx
}

// fill returns the buffered bytes, reading more when there are none. It
// returns nil at the end of the input or on a read error, which it keeps.
func (lx *lexer) fill() []byte {
	if lx.br.Buffered() == 0 {
		if lx.eof {
			return nil
		}
		if err := lx.ctx.Err(); err != nil {
			lx.err = err
			lx.eof = true
			return nil
		}
		if _, err := lx.br.Peek(1); err != nil {
			if err != io.EOF && lx.err == nil {
				lx.err = err
			}
			lx.eof = true
			return nil
		}
	}
	b, _ := lx.br.Peek(lx.br.Buffered())
	return b
}

// peek looks at up to n bytes without consuming them.
func (lx *lexer) peek(n int) []byte {
	b, err := lx.br.Peek(n)
	if err != nil && err != io.EOF && lx.err == nil {
		lx.err = err
	}
	return b
}

func (lx *lexer) skip(n int) { lx.br.Discard(n) }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool {
	return isDigit(c) || (c|0x20 >= 'a' && c|0x20 <= 'f')
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || isDigit(c) || (c|0x20 >= 'a' && c|0x20 <= 'z') || c >= 0x80
}

func isWordStart(c byte) bool { return isWordByte(c) && !isDigit(c) }

// atDelim reports whether the delimiter starts at the next byte.
func (lx *lexer) atDelim() bool {
	if len(lx.delim) == 1 {
		return true
	}
	return bytes.HasPrefix(lx.peek(len(lx.delim)), lx.delim)
}

// next returns the next token.
func (lx *lexer) next() token {
	for {
		b := lx.fill()
		if b == nil {
			lx.leaveUncertain() // the file ends inside it
			return token{kind: tokEOF, line: lx.line}
		}
		c := b[0]
		switch c {
		case ' ', '\t', '\r', '\v', '\f', '\n':
			lx.skipSpace(b)
			continue
		}
		if c == lx.delim[0] && lx.atDelim() {
			line := lx.line
			lx.skip(len(lx.delim))
			lx.atStart, lx.blank = true, false
			lx.leaveUncertain() // the delimiter cuts it
			lx.inExec = false
			lx.prevName = false
			return token{kind: tokEnd, line: line}
		}
		if lx.atStart && lx.blank && (c == '?' || (c|0x20 >= 'a' && c|0x20 <= 'z')) {
			switch lx.command() {
			case cmdDelimiter:
				continue
			case cmdClient:
				return token{kind: tokClient, line: lx.line}
			}
		}
		switch c {
		case '\\':
			// The client runs a backslash command anywhere outside strings,
			// identifiers and plain comments.
			return token{kind: tokClient, line: lx.line}
		case '#':
			lx.lineComment()
			continue
		case '-':
			p := lx.peek(3)
			if len(p) >= 2 && p[1] == '-' && (len(p) == 2 || p[2] <= ' ' || p[2] == 0x7f) {
				lx.lineComment()
				continue
			}
		case '/':
			if lx.blockComment() {
				lx.blank = false
				continue
			}
		case '*':
			if lx.inExec {
				if p := lx.peek(2); len(p) == 2 && p[1] == '/' {
					lx.skip(2)
					lx.inExec, lx.blank = false, false
					if lx.inUncertain {
						lx.inUncertain = false
						lx.vFault = lx.vFault || lx.vDepth != 0
					}
					continue
				}
			}
		}
		return lx.token(c)
	}
}

// startStatement clears what is kept about the statement in progress.
func (lx *lexer) startStatement() {
	lx.ntok, lx.vOutside, lx.vOpen, lx.vFault, lx.exec = 0, 0, -1, false, false
	lx.vNonLit, lx.vCom = false, lx.vCom[:0]
}

// approve notes that uncertain comment id holds a form MySQL writes in a
// version comment, of n tokens all lexed in it. The parser that knows where
// the form belongs calls it; approved checks, once the statement is read,
// that the form is all the comment holds.
func (lx *lexer) approve(id, n int) {
	if id <= 0 || id > len(lx.vCom) {
		return
	}
	if c := &lx.vCom[id-1]; c.form == 0 {
		c.form = n
	} else {
		c.form = -1
	}
}

// approved reports whether every uncertain comment of the statement holds a
// listed form, in its place, and nothing else.
func (lx *lexer) approved() bool {
	for _, c := range lx.vCom {
		if c.form != c.tokens {
			return false
		}
	}
	return true
}

// leaveUncertain ends an uncertain comment that its */ didn't close: one the
// delimiter or the end of the file cuts is broken.
func (lx *lexer) leaveUncertain() {
	if lx.inUncertain {
		lx.inUncertain = false
		lx.vFault = true
	}
}

// watch looks at the raw bytes the lexer consumes in a quoted text or a line
// comment. Inside an uncertain comment a */ among them is where a server that
// skips the comment ends it, though the reader doesn't: the comment is broken.
func (lx *lexer) watch(p []byte) {
	if !lx.inUncertain {
		return
	}
	for _, c := range p {
		lx.vFault = lx.vFault || lx.star && c == '/'
		lx.star = c == '*'
	}
}

func (lx *lexer) token(c byte) token {
	line := lx.line
	lx.atStart, lx.blank = false, false
	var t token
	switch {
	case c == '\'':
		t = lx.stringTok('\'')
	case c == '"':
		if lx.ansiQuotes {
			t = lx.identTok('"')
		} else {
			t = lx.stringTok('"')
		}
	case c == '`':
		t = lx.identTok('`')
	case isDigit(c):
		t = lx.numberTok(false)
	case c == '@':
		t = lx.varTok()
	case isWordStart(c):
		t = lx.wordTok()
	default:
		if c == '.' && !lx.prevName {
			if p := lx.peek(2); len(p) == 2 && isDigit(p[1]) {
				t = lx.numberTok(true)
				break
			}
		}
		lx.skip(1)
		t = token{kind: tokSym, sym: c}
	}
	t.line = line
	lx.prevName = t.kind == tokWord || t.kind == tokIdent || t.kind == tokVar
	lx.ntok++
	if lx.inUncertain {
		t.unc = len(lx.vCom)
		lx.vCom[t.unc-1].tokens++
		lx.vNonLit = lx.vNonLit || t.kind != tokString && t.kind != tokNum
	}
	switch {
	case !lx.inUncertain:
		lx.vOutside++
	case t.isSym('('):
		lx.vDepth++
	case t.isSym(')'):
		lx.vDepth--
		lx.vFault = lx.vFault || lx.vDepth < 0
	case t.isSym(';'):
		lx.vFault = true
	}
	return t
}

func (lx *lexer) skipSpace(b []byte) {
	i := 0
	for i < len(b) {
		c := b[i]
		if c == '\n' {
			lx.line++
			lx.blank = true
		} else if c != ' ' && c != '\t' && c != '\r' && c != '\v' && c != '\f' {
			break
		}
		i++
	}
	lx.skip(i)
}

// readLine consumes the rest of the line, newline included, and returns up
// to limit of its bytes.
func (lx *lexer) readLine(limit int) []byte {
	lx.cbuf = lx.cbuf[:0]
	for {
		b := lx.fill()
		if b == nil {
			return lx.cbuf
		}
		i := bytes.IndexByte(b, '\n')
		chunk := b
		if i >= 0 {
			chunk = b[:i]
		}
		if room := limit - len(lx.cbuf); room > 0 {
			if len(chunk) < room {
				room = len(chunk)
			}
			lx.cbuf = append(lx.cbuf, chunk[:room]...)
		}
		lx.watch(chunk)
		lx.skip(len(chunk))
		if i >= 0 {
			lx.skip(1)
			lx.line++
			lx.blank = true
			return lx.cbuf
		}
	}
}

// lineComment skips a "-- " or "#" comment, offering its start to the
// header reader when one is listening.
func (lx *lexer) lineComment() {
	line := lx.line
	lx.star = false
	if lx.onComment == nil {
		lx.readLine(0)
		return
	}
	text := lx.readLine(maxCommentLine)
	lx.onComment(text, line)
}

// blockComment handles a comment that starts at the next byte, and reports
// whether there was one. An executable comment only sets the state: its
// content is lexed as SQL.
//
// An uncertain one is broken when a server that skips it would end it
// elsewhere than the reader: at a */ inside a string, a quoted identifier or a
// line comment (watch), or at the end of a comment nested in it. It is broken
// too when its parentheses don't balance or it holds a ; (token), or when the
// delimiter or the end of the file cuts it (leaveUncertain).
func (lx *lexer) blockComment() bool {
	p := lx.peek(4)
	if len(p) < 2 || p[1] != '*' {
		return false
	}
	lx.vFault = lx.vFault || lx.inUncertain
	n := 0
	switch {
	case len(p) >= 3 && p[2] == '!':
		n = 3
	case len(p) >= 4 && p[2] == 'M' && p[3] == '!':
		n = 4
		if bytes.HasPrefix(lx.peek(12), []byte(`/*M!999999\-`)) {
			n = 0 // mariadb-dump's marker for the client, a plain comment
		}
	case len(p) >= 3 && p[2] == '+':
		// An optimizer hint is a comment to the reader, but MySQL's client
		// runs a backslash command inside one: the skip stops at it.
		lx.skip(3)
		lx.skipBlock(true)
		return true
	}
	if n == 0 {
		lx.skip(2)
		lx.skipBlock(false)
		return true
	}
	lx.skip(n)
	digits, version := 0, 0
	for ; digits < 6; digits++ {
		d := lx.peek(1)
		if len(d) == 0 || !isDigit(d[0]) {
			break
		}
		version = version*10 + int(d[0]-'0')
		lx.skip(1)
	}
	// Certain: /*! with no version, or with five digits below 50700, which
	// MySQL 5.7 and later and MariaDB 10 and later all run.
	if n == 4 || (digits != 0 && digits != 5) || version >= 50700 {
		lx.vFault = lx.vFault || lx.inExec
		lx.inUncertain, lx.vDepth = true, 0
		lx.vCom = append(lx.vCom, vComment{})
		if lx.vOpen < 0 {
			lx.vOpen, lx.vLine = lx.ntok, lx.line
		}
	}
	lx.inExec, lx.exec = true, true
	return true
}

// skipBlock skips to the end of a plain comment, without buffering it. In a
// hint it stops at a backslash, which next reads as a client command.
func (lx *lexer) skipBlock(hint bool) {
	for {
		b := lx.fill()
		if b == nil {
			return
		}
		i := bytes.IndexByte(b, '*')
		if hint {
			i = bytes.IndexAny(b, `*\`)
		}
		if i < 0 {
			lx.line += bytes.Count(b, []byte{'\n'})
			lx.skip(len(b))
			continue
		}
		lx.line += bytes.Count(b[:i], []byte{'\n'})
		stop := b[i] == '\\'
		lx.skip(i)
		if stop {
			return
		}
		p := lx.peek(2)
		if len(p) < 2 {
			lx.skip(len(p))
			return
		}
		if p[1] == '/' {
			lx.skip(2)
			return
		}
		lx.skip(1)
	}
}

// cmdKind says what command, if any, starts a statement.
type cmdKind uint8

const (
	cmdNone      cmdKind = iota
	cmdDelimiter         // DELIMITER, read
	cmdClient            // a command the client runs itself
)

const (
	maxCommandName = len("ssl_session_data_print")
	maxCommandLine = 4 << 10 // how far a command's line is searched for the delimiter
)

// command handles a command of the client's own at the start of a
// statement: DELIMITER, as delimiterCommand reads it, or one of the other
// long-form commands of the mysql and mariadb clients. The client looks for
// one only as the first word of a line, with nothing but spaces before it
// (a comment there is text), and only while no statement has begun: next
// checks both. It runs one when the word is followed by a space, a tab, the
// line's end or the file's end, and its line holds no delimiter, in its raw
// bytes. A line with no end within 4 KiB is taken for a command.
func (lx *lexer) command() cmdKind {
	if lx.inExec {
		// The client keeps an executable comment's text as the statement's,
		// so on a later line of one the statement has begun: no command,
		// DELIMITER included, is run inside one.
		return cmdNone
	}
	p, ok := lx.ahead(maxCommandName+1, func(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' })
	if !ok || len(p) > maxCommandName {
		return cmdNone
	}
	var w [maxCommandName]byte
	for i, c := range p {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		w[i] = c
	}
	switch string(w[:len(p)]) {
	case "delimiter":
		return lx.delimiterCommand()
	case "?", "charset", "clear", "connect", "costs", "edit", "ego", "exit", "go", "help",
		"nopager", "notee", "nowarning", "pager", "print", "prompt", "query_attributes", "quit", "rehash",
		"resetconnection", "sandbox", "source", "ssl_session_data_print", "status", "system", "tee", "use", "warnings":
	default:
		return cmdNone
	}
	line, ok := lx.ahead(maxCommandLine, func(c byte) bool { return c == '\n' })
	if ok && bytes.Contains(line, lx.delim) {
		return cmdNone
	}
	return cmdClient
}

// ahead looks at the coming bytes, without consuming them, up to the first
// that stop accepts, which it leaves out. It reads more only while none has
// come, so a slow source isn't waited on past it. It reports false when limit
// bytes came with none, and the file goes on.
func (lx *lexer) ahead(limit int, stop func(byte) bool) ([]byte, bool) {
	for want := 1; ; {
		b := lx.peek(min(limit, max(want, lx.br.Buffered())))
		for i, c := range b {
			if stop(c) {
				return b[:i], true
			}
		}
		switch {
		case len(b) >= limit:
			return b, false
		case len(b) < want:
			return b, true // the end of the file
		}
		want = len(b) + 1
	}
}

// delimiterCommand handles DELIMITER at the start of a statement and its
// line: cmdDelimiter once it has read the line, or cmdClient, with the line
// left for the unread entry, for an argument the clients reject or read their
// own way (delimiterArg). It returns cmdNone when the word isn't followed by
// a space or a tab.
func (lx *lexer) delimiterCommand() cmdKind {
	p := lx.peek(10)
	if len(p) < 10 || !bytes.EqualFold(p[:9], []byte("delimiter")) || (p[9] != ' ' && p[9] != '\t') {
		return cmdNone
	}
	line, ok := lx.ahead(maxCommandLine, func(c byte) bool { return c == '\n' })
	arg, good := delimiterArg(line[10:])
	if !ok || !good {
		return cmdClient
	}
	if len(arg) > 0 {
		lx.delim = append(lx.delim[:0], arg...)
	}
	lx.skip(10)
	lx.readLine(0)
	return cmdDelimiter
}

// delimiterArg reads DELIMITER's argument from the rest of its line as the
// clients do: a quoted string, or a word up to the first space, with what
// follows a space after it ignored. It reports false for one they reject or
// read their own way: over 15 bytes, a backslash or a control byte such as a
// tab in it, a quoted one holding a space or its own quote, an unclosed
// quote, or text right after the closing quote.
func delimiterArg(rest []byte) ([]byte, bool) {
	rest = bytes.TrimLeft(bytes.TrimRight(rest, " \r"), " \t")
	if len(rest) == 0 {
		return nil, true // no argument: the clients change nothing
	}
	arg := rest
	switch q := rest[0]; q {
	case '\'', '"', '`':
		end := bytes.IndexByte(rest[1:], q)
		if end < 0 {
			return nil, false
		}
		arg = rest[1 : 1+end]
		if after := rest[2+end:]; len(after) > 0 && after[0] != ' ' || bytes.IndexByte(arg, ' ') >= 0 {
			return nil, false
		}
	default:
		if i := bytes.IndexByte(rest, ' '); i >= 0 {
			arg = rest[:i]
		}
	}
	if len(arg) > maxDelim || bytes.IndexByte(arg, '\\') >= 0 {
		return nil, false
	}
	for _, c := range arg {
		if c < 0x20 || c == 0x7f {
			return nil, false
		}
	}
	return arg, true
}

// special finds the first byte of b that ends a plain run of a quoted text.
func (lx *lexer) special(b []byte, q byte, escapes bool) int {
	if lx.mb != mbNone && escapes {
		for i, c := range b {
			if c == q || c == '\\' || lx.mb.lead(c) {
				return i
			}
		}
		return len(b)
	}
	i := bytes.IndexByte(b, q)
	if i < 0 {
		i = len(b)
	}
	if escapes {
		if j := bytes.IndexByte(b[:i], '\\'); j >= 0 {
			i = j
		}
	}
	return i
}

// quoted reads a quoted text into vb, after its opening quote, and reports
// whether it ended.
func (lx *lexer) quoted(vb *valBuf, q byte, escapes bool) bool {
	lx.star = false
	for {
		b := lx.fill()
		if b == nil {
			return false
		}
		i := lx.special(b, q, escapes)
		if i > 0 {
			lx.line += bytes.Count(b[:i], []byte{'\n'})
			vb.add(b[:i])
			lx.watch(b[:i])
			lx.skip(i)
		}
		if i == len(b) {
			continue
		}
		c := b[i]
		lx.star = false // a quote, a backslash or a lead byte
		switch {
		case c == q:
			lx.skip(1)
			if p := lx.peek(1); len(p) == 1 && p[0] == q {
				vb.addByte(q)
				lx.skip(1)
				continue
			}
			return true
		case c == '\\':
			lx.skip(1)
			e := lx.fill()
			if e == nil {
				return false
			}
			lx.watch(e[:1])
			lx.skip(1)
			switch e0 := e[0]; e0 {
			case '0':
				vb.addByte(0)
			case 'b':
				vb.addByte('\b')
			case 'n':
				vb.addByte('\n')
			case 'r':
				vb.addByte('\r')
			case 't':
				vb.addByte('\t')
			case 'Z':
				vb.addByte(26)
			case '%', '_':
				vb.addByte('\\')
				vb.addByte(e0)
			case '\n':
				lx.line++
				vb.addByte(e0)
			default:
				vb.addByte(e0)
			}
		default:
			// a lead byte of a multi-byte set: its trail byte is taken whole
			vb.addByte(c)
			lx.skip(1)
			e := lx.fill()
			if e == nil {
				return false
			}
			if e[0] == '\n' {
				lx.line++
			}
			vb.addByte(e[0])
			lx.watch(e[:1])
			lx.skip(1)
		}
	}
}

func (lx *lexer) effectiveCS() csKind {
	if lx.override != csNone {
		return lx.override
	}
	return lx.cs
}

func (lx *lexer) stringTok(q byte) token {
	if !lx.join {
		lx.vb.reset(lx.effectiveCS(), lx.maxChars, lx.discard)
	}
	lx.skip(1)
	if !lx.quoted(&lx.vb, q, !lx.noBackslash) {
		return token{kind: tokErr, err: ReasonString}
	}
	return token{kind: tokString, text: lx.vb.b, cut: lx.vb.cut}
}

func (lx *lexer) identTok(q byte) token {
	lx.ib.reset(csBinary, maxIdent, lx.discard)
	lx.skip(1)
	if !lx.quoted(&lx.ib, q, false) {
		return token{kind: tokErr, err: ReasonString}
	}
	if lx.ib.cut {
		return token{kind: tokErr, err: ReasonIdentLength}
	}
	return token{kind: tokIdent, text: lx.ib.b}
}

// wadd appends to the word buffer up to its cap.
func (lx *lexer) wadd(p []byte) {
	limit := maxIdent
	if lx.discard {
		limit = shortWord
	}
	room := limit - len(lx.wb)
	if len(p) > room {
		if room > 0 {
			lx.wb = append(lx.wb, p[:room]...)
		}
		lx.wlong = true
		return
	}
	lx.wb = append(lx.wb, p...)
}

// wordRun reads word bytes, and dots too when dots is set, stopping where the
// delimiter starts.
func (lx *lexer) wordRun(dots bool) {
	for {
		b := lx.fill()
		if b == nil {
			return
		}
		d0 := lx.delim[0]
		i := 0
		for i < len(b) {
			c := b[i]
			if !(isWordByte(c) || (dots && c == '.')) || c == d0 {
				break
			}
			i++
		}
		lx.wadd(b[:i])
		lx.skip(i)
		if i == len(b) {
			continue
		}
		c := b[i]
		if (isWordByte(c) || (dots && c == '.')) && c == d0 {
			if lx.atDelim() {
				return
			}
			lx.wadd([]byte{c})
			lx.skip(1)
			continue
		}
		return
	}
}

func (lx *lexer) wordResult(kind tokKind) token {
	if lx.wlong && !lx.discard {
		return token{kind: tokErr, err: ReasonIdentLength}
	}
	return token{kind: kind, text: lx.wb}
}

func (lx *lexer) wordTok() token {
	lx.wb = lx.wb[:0]
	lx.wlong = false
	lx.wordRun(false)
	if len(lx.wb) == 1 {
		if p := lx.peek(1); len(p) == 1 && p[0] == '\'' {
			switch lx.wb[0] | 0x20 {
			case 'x':
				return lx.hexLit(true, false)
			case 'b':
				return lx.hexLit(true, true)
			case 'n':
				return lx.stringTok('\'')
			}
		}
	}
	return lx.wordResult(tokWord)
}

func (lx *lexer) varTok() token {
	p := lx.peek(3)
	n := 1
	if len(p) >= 2 && p[1] == '@' {
		n = 2
	}
	if len(p) <= n || !(isWordByte(p[n]) || p[n] == '.') {
		lx.skip(1)
		return token{kind: tokSym, sym: '@'}
	}
	lx.skip(n)
	lx.wb = append(lx.wb[:0], p[:n]...)
	lx.wlong = false
	lx.wordRun(true)
	return lx.wordResult(tokVar)
}

func allDigits(b []byte) bool {
	for _, c := range b {
		if !isDigit(c) {
			return false
		}
	}
	return len(b) > 0
}

// numericPrefix reports whether b is digits with at most one dot and a digit.
func numericPrefix(b []byte) bool {
	dots, digits := 0, 0
	for _, c := range b {
		switch {
		case isDigit(c):
			digits++
		case c == '.':
			dots++
		default:
			return false
		}
	}
	return dots <= 1 && digits > 0
}

// isNumberText reports whether b is a number: digits with an optional
// fraction and an optional exponent.
func isNumberText(b []byte) bool {
	i, digits := 0, 0
	for i < len(b) && isDigit(b[i]) {
		i++
		digits++
	}
	if i < len(b) && b[i] == '.' {
		i++
		for i < len(b) && isDigit(b[i]) {
			i++
			digits++
		}
	}
	if digits == 0 {
		return false
	}
	if i < len(b) && b[i]|0x20 == 'e' {
		i++
		if i < len(b) && (b[i] == '+' || b[i] == '-') {
			i++
		}
		ed := 0
		for i < len(b) && isDigit(b[i]) {
			i++
			ed++
		}
		if ed == 0 {
			return false
		}
	}
	return i == len(b)
}

func (lx *lexer) numberTok(dot bool) token {
	if !dot {
		if p := lx.peek(3); len(p) == 3 && p[0] == '0' {
			if p[1]|0x20 == 'x' && isHexDigit(p[2]) {
				lx.skip(2)
				return lx.hexLit(false, false)
			}
			if p[1]|0x20 == 'b' && (p[2] == '0' || p[2] == '1') {
				lx.skip(2)
				return lx.hexLit(false, true)
			}
		}
	}
	lx.wb = lx.wb[:0]
	lx.wlong = false
	if dot {
		lx.wb = append(lx.wb, '.')
		lx.skip(1)
	}
	lx.wordRun(false)
	if !dot && allDigits(lx.wb) {
		if p := lx.peek(1); len(p) == 1 && p[0] == '.' && lx.delim[0] != '.' {
			lx.skip(1)
			lx.wb = append(lx.wb, '.')
			lx.wordRun(false)
		}
	}
	if n := len(lx.wb); n > 1 && lx.wb[n-1]|0x20 == 'e' && numericPrefix(lx.wb[:n-1]) {
		if p := lx.peek(2); len(p) == 2 && (p[0] == '+' || p[0] == '-') && isDigit(p[1]) {
			lx.wb = append(lx.wb, p[0])
			lx.skip(1)
			lx.wordRun(false)
		}
	}
	if !lx.wlong && isNumberText(lx.wb) {
		return token{kind: tokNum, text: lx.wb}
	}
	return lx.wordResult(tokWord)
}

// hexLit reads a hex or bit literal. A quoted one (X'41', b'01') is at its
// opening quote; an unquoted one (0x41, 0b01) is past its prefix. Hex digits
// become bytes and bit digits are kept as '0' and '1'.
func (lx *lexer) hexLit(quoted, bit bool) token {
	limit := lx.maxChars
	if lx.hexWide {
		if bit {
			limit *= 8 // eight digits a byte: a byte for each character of the cap
		} else {
			limit *= 4 // a text column counts characters, which take up to 4 bytes
		}
	}
	lx.hb.reset(csBinary, limit, lx.discard)
	if quoted {
		lx.skip(1)
		lx.star = false
	}
	hi, digits := -1, 0
	bad := false
	for {
		b := lx.fill()
		if b == nil {
			if quoted {
				return token{kind: tokErr, err: ReasonString}
			}
			break
		}
		i := 0
		done := false
		for i < len(b) && !done {
			c := b[i]
			switch {
			case quoted && c == '\'':
				done = true
				continue
			case !quoted && !isWordByte(c):
				done = true
				continue
			}
			i++
			switch {
			case bit && (c == '0' || c == '1'):
				digits++
				lx.hb.addByte(c)
			case !bit && isHexDigit(c):
				digits++
				var n int
				if isDigit(c) {
					n = int(c - '0')
				} else {
					n = int(c|0x20-'a') + 10
				}
				if hi < 0 {
					hi = n
				} else {
					lx.hb.addByte(byte(hi<<4 | n))
					hi = -1
				}
			default:
				bad = true
				if c == '\n' {
					lx.line++
				}
			}
		}
		if quoted {
			lx.watch(b[:i])
		}
		lx.skip(i)
		if done {
			break
		}
	}
	if quoted {
		lx.skip(1)
	}
	kind := tokHex
	if bit {
		kind = tokBit
	}
	return token{kind: kind, text: lx.hb.b, cut: lx.hb.cut, bad: bad || (!bit && digits%2 == 1)}
}
