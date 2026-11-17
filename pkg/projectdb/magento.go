package projectdb

import (
	"bytes"
	"slices"
	"strings"
)

// The keys app/etc/env.php's refusals name, and the reasons they give.
var (
	magentoKeys = []string{
		"db", "db.connection", "db.connection.default",
		"host", "dbname", "username", "password", "port", "unix_socket", "driver_options",
	}
	magentoReasons = []string{
		reasonMissing, reasonEmpty, reasonTwice, reasonNotPlain, reasonForm, reasonSemicolon, reasonLines,
		magentoPortSet, magentoNotRead, magentoServer,
	}
	magentoFileReasons = []string{magentoNotArray}
)

const (
	// magentoPortSet refuses a port key, which Magento's adapter throws on:
	// "Port must be configured within host parameter".
	magentoPortSet = "is set, which Magento itself refuses"
	// magentoNotRead refuses a unix_socket key. Magento's adapter passes
	// every key it doesn't use itself into PDO's DSN, so PHP would connect
	// through that socket where prodmask would read host.
	magentoNotRead = "is set, which prodmask doesn't read"
	// magentoServer refuses db.connection.default when an entry that goes
	// into PDO's DSN could name another server there.
	magentoServer = "has a setting Magento passes to PDO that could name another server"
	// magentoNotArray refuses a file that isn't <?php, comments, and return
	// with one array literal whose keys are literals.
	magentoNotArray = "it doesn't return an array of plain values"
)

// readMagento reads app/etc/env.php's database settings: the host, dbname,
// username and password of db.connection.default, as Magento's adapter reads
// them. Nothing in the file runs. prodmask follows the literals on the path
// to those keys, checks that the connection's other entries can't name
// another server in PDO's DSN, and skips every other value by its brackets.
func readMagento(data []byte) (*settings, error) {
	p, top, ok := magentoParse(data)
	if !ok {
		return nil, fileError(Magento, magentoNotArray)
	}
	entries, err := p.defaultEntries(top)
	if err != nil {
		return nil, err
	}
	return p.connection(entries)
}

// magentoParse checks the file's shape: <?php and whitespace, comments,
// return, an array literal whose keys are literals, and ;, with nothing after
// it but comments and a closing ?>. It returns the array's entries.
func magentoParse(data []byte) (*magentoParser, []magentoEntry, bool) {
	if len(data) < 6 || !magentoFold(string(data[:5]), "<?php") || !magentoSpace(data[5]) {
		return nil, nil, false
	}
	toks, ok := magentoLex(data[5:])
	if !ok {
		return nil, nil, false
	}
	p := &magentoParser{toks: toks}
	if !p.pair() || !p.word(0, "return") {
		return nil, nil, false
	}
	from, to, ok := p.array(1)
	if !ok || !p.mark(to+1, ";") {
		return nil, nil, false
	}
	if rest := toks[to+2:]; len(rest) > 1 || len(rest) == 1 && rest[0].kind != magentoCloseTag {
		return nil, nil, false
	}
	top, ok := p.entries(from, to)
	if !ok || !p.literalKeys(top) {
		return nil, nil, false
	}
	return p, top, true
}

// defaultEntries follows db, connection and default to the entries of
// db.connection.default. Each must be set once, to an array literal whose
// keys are literals.
func (p *magentoParser) defaultEntries(entries []magentoEntry) ([]magentoEntry, error) {
	for _, step := range [...]struct{ key, path string }{
		{"db", "db"}, {"connection", "db.connection"}, {"default", "db.connection.default"},
	} {
		found := p.find(entries, step.key)
		switch {
		case len(found) == 0:
			return nil, keyError(Magento, "db.connection.default", reasonMissing)
		case len(found) > 1:
			return nil, keyError(Magento, step.path, reasonTwice)
		}
		from, to, ok := p.arrayValue(found[0].value)
		if !ok {
			return nil, keyError(Magento, step.path, reasonForm)
		}
		if entries, ok = p.entries(from, to); !ok || !p.literalKeys(entries) {
			return nil, keyError(Magento, step.path, reasonForm)
		}
	}
	return entries, nil
}

// connection reads db.connection.default's entries.
func (p *magentoParser) connection(entries []magentoEntry) (*settings, error) {
	host, err := p.plain(entries, "host", true)
	if err != nil {
		return nil, err
	}
	if strings.Contains(host, ";") {
		return nil, keyError(Magento, "host", reasonSemicolon)
	}
	s, ok := magentoHost(host)
	if !ok {
		return nil, keyError(Magento, "host", reasonForm)
	}
	if s.database, err = p.plain(entries, "dbname", true); err != nil {
		return nil, err
	}
	if strings.Contains(s.database, ";") {
		return nil, keyError(Magento, "dbname", reasonSemicolon)
	}
	if s.user, err = p.plain(entries, "username", true); err != nil {
		return nil, err
	}
	if s.password, err = p.plain(entries, "password", false); err != nil {
		return nil, err
	}
	if len(p.find(entries, "port")) > 0 {
		return nil, keyError(Magento, "port", magentoPortSet)
	}
	if len(p.find(entries, "unix_socket")) > 0 {
		return nil, keyError(Magento, "unix_socket", magentoNotRead)
	}
	if err := p.driverOptions(entries); err != nil {
		return nil, err
	}
	if !p.dsnSafe(entries) {
		return nil, keyError(Magento, "db.connection.default", magentoServer)
	}
	return s, nil
}

// magentoOwn are the keys of db.connection.default that Zend's adapter keeps
// out of PDO's DSN, with host and dbname, which connection checks itself.
// charset isn't one: the adapter adds it to the DSN's end.
var magentoOwn = []string{"host", "dbname", "username", "password", "options", "persistent", "driver_options"}

// dsnSafe reports whether every other entry of db.connection.default is known
// to name no server in PDO's DSN. Magento's adapter writes each into the DSN
// as key=value, joined by ;, and PDO takes the last of each key, so an
// initStatements of "SET NAMES utf8;host=other", or a key of " host", would
// move the connection. A plain string with no server key after a ;, a number,
// true, false, null or an array, which PHP writes as Array, is safe; anything
// else could name one.
func (p *magentoParser) dsnSafe(entries []magentoEntry) bool {
	for _, e := range entries {
		key, _ := p.str(e.key)
		if slices.Contains(magentoOwn, key) {
			continue
		}
		value, ok := p.str(e.value)
		// Each entry follows a ; in the DSN, so its key's own start counts.
		if !ok && !p.namesNothing(e.value) || magentoNamesServer(";"+key+"="+value) {
			return false
		}
	}
	return true
}

// namesNothing reports a value PHP writes into the DSN as a text holding no
// key: a number, true, false, null, or an array, which it writes as Array.
func (p *magentoParser) namesNothing(v magentoSpan) bool {
	if v.to-v.from == 1 {
		return p.toks[v.from].kind == magentoNumber || p.word(v.from, "true") || p.word(v.from, "false") || p.word(v.from, "null")
	}
	_, _, ok := p.arrayValue(v)
	return ok
}

// magentoNamesServer reports whether s, written into PDO's DSN, sets a key
// that names the server: one after a ;, past the whitespace PDO skips there.
// A ; doubled, which some PHP versions read as a ; in the value, counts too.
func magentoNamesServer(s string) bool {
	for i := strings.IndexByte(s, ';'); i >= 0; i = strings.IndexByte(s, ';') {
		s = strings.TrimLeft(s[i+1:], "; \t\n\v\f\r")
		for _, k := range []string{"host=", "port=", "dbname=", "unix_socket="} {
			if strings.HasPrefix(s, k) {
				return true
			}
		}
	}
	return false
}

// magentoHost reads host as Magento's adapter does: a / anywhere makes it a
// unix socket's path; otherwise a : splits it, with explode(':', ...), into a
// host and a port. prodmask takes exactly one :, between a host and a port
// from 1 to 65535, and refuses any other split.
func magentoHost(host string) (*settings, bool) {
	if strings.Contains(host, "/") {
		// PHP would resolve a relative path from its own folder, prodmask
		// from the user's, so only an absolute one is read.
		if !absolute(host) {
			return nil, false
		}
		return &settings{socket: host}, true
	}
	name, port, found := strings.Cut(host, ":")
	if !found {
		return &settings{host: host}, true
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if !magentoDigit(port[i]) {
			return nil, false
		}
		if n = n*10 + int(port[i]-'0'); n > 65535 {
			return nil, false
		}
	}
	if name == "" || n == 0 {
		return nil, false
	}
	return &settings{host: name, port: n}, true
}

// plain returns key's value, which must be one plain string on one line, set
// once. A required key must be set, and not empty.
func (p *magentoParser) plain(entries []magentoEntry, key string, required bool) (string, error) {
	found := p.find(entries, key)
	switch {
	case len(found) > 1:
		return "", keyError(Magento, key, reasonTwice)
	case len(found) == 0 && required:
		return "", keyError(Magento, key, reasonMissing)
	case len(found) == 0:
		return "", nil
	}
	value, ok := p.str(found[0].value)
	switch {
	case !ok:
		return "", keyError(Magento, key, reasonNotPlain)
	case value == "" && required:
		return "", keyError(Magento, key, reasonEmpty)
	case strings.Contains(value, "\n"):
		return "", keyError(Magento, key, reasonLines)
	}
	return value, nil
}

// driverOptions refuses driver_options unless it's an array literal whose
// every value is false, however its key is written. Magento's installer
// writes [1014 => false], which turns off PDO's check of the server's
// certificate; any other option, such as a certificate, could change the
// connection.
func (p *magentoParser) driverOptions(entries []magentoEntry) error {
	found := p.find(entries, "driver_options")
	switch {
	case len(found) == 0:
		return nil
	case len(found) > 1:
		return keyError(Magento, "driver_options", reasonTwice)
	}
	from, to, ok := p.arrayValue(found[0].value)
	if !ok {
		return refuse(Magento, textDriverOptions)
	}
	options, ok := p.entries(from, to)
	if !ok {
		return refuse(Magento, textDriverOptions)
	}
	for _, o := range options {
		if o.value.to-o.value.from != 1 || !p.word(o.value.from, "false") {
			return refuse(Magento, textDriverOptions)
		}
	}
	return nil
}

// magentoParser reads the tokens of env.php.
type magentoParser struct {
	toks []magentoToken
	// partner holds each bracket's matching bracket.
	partner []int
}

// magentoEntry is one array element: the tokens of its key, none for a bare
// value, and of its value.
type magentoEntry struct{ key, value magentoSpan }

// magentoSpan is a run of tokens, toks[from:to].
type magentoSpan struct{ from, to int }

// magentoClosers pairs each opening bracket with its closing one.
var magentoClosers = map[string]string{"[": "]", "(": ")", "{": "}"}

// pair matches every bracket with its partner, and fails on one left open or
// closed by another kind.
func (p *magentoParser) pair() bool {
	p.partner = make([]int, len(p.toks))
	var open []int
	for i, t := range p.toks {
		switch {
		case t.kind != magentoMark:
		case p.opens(i):
			open = append(open, i)
		case t.text == "]" || t.text == ")" || t.text == "}":
			if len(open) == 0 || magentoClosers[p.toks[open[len(open)-1]].text] != t.text {
				return false
			}
			o := open[len(open)-1]
			open = open[:len(open)-1]
			p.partner[o], p.partner[i] = i, o
		}
	}
	return len(open) == 0
}

// array returns the bounds of the array literal at toks[i], [...] or
// array(...): its first inner token and its closing bracket.
func (p *magentoParser) array(i int) (from, to int, ok bool) {
	switch {
	case p.mark(i, "["):
		return i + 1, p.partner[i], true
	case p.word(i, "array") && p.mark(i+1, "("):
		return i + 2, p.partner[i+1], true
	}
	return 0, 0, false
}

// arrayValue is array for a value that must be one array literal and nothing
// more, so that [...] + [] isn't taken for one.
func (p *magentoParser) arrayValue(v magentoSpan) (from, to int, ok bool) {
	from, to, ok = p.array(v.from)
	return from, to, ok && to == v.to-1
}

// entries splits the inner tokens of an array, toks[from:to], where toks[to]
// is its closing bracket: at each comma outside brackets into entries, and
// each entry at its first => outside brackets into key and value. Only the
// last entry may end in a comma, and no key or value may be empty.
func (p *magentoParser) entries(from, to int) ([]magentoEntry, bool) {
	var out []magentoEntry
	start, arrow := from, -1
	for i := from; i <= to; i++ {
		if i < to && !p.mark(i, ",") {
			if p.opens(i) {
				i = p.partner[i]
			} else if arrow < 0 && p.mark(i, "=>") {
				arrow = i
			}
			continue
		}
		// toks[i] ends an entry: a comma, or the closing bracket.
		switch {
		case i == start:
			if i < to {
				return nil, false
			}
		case arrow < 0:
			out = append(out, magentoEntry{value: magentoSpan{start, i}})
		case arrow == start || arrow == i-1:
			return nil, false
		default:
			out = append(out, magentoEntry{key: magentoSpan{start, arrow}, value: magentoSpan{arrow + 1, i}})
		}
		start, arrow = i+1, -1
	}
	return out, true
}

// literalKeys reports whether every entry's key is a plain string, a number,
// or none, which PHP numbers. PHP would let any other key, or a spread (...),
// stand for a key prodmask reads, and set it over the one prodmask found.
func (p *magentoParser) literalKeys(entries []magentoEntry) bool {
	for _, e := range entries {
		switch {
		case e.key.from == e.key.to:
			if p.mark(e.value.from, "...") {
				return false
			}
		case e.key.to-e.key.from == 1 && p.toks[e.key.from].kind == magentoNumber:
		default:
			if _, ok := p.str(e.key); !ok {
				return false
			}
		}
	}
	return true
}

// find returns the entries whose key is the plain string key.
func (p *magentoParser) find(entries []magentoEntry, key string) []magentoEntry {
	var found []magentoEntry
	for _, e := range entries {
		if k, ok := p.str(e.key); ok && k == key {
			found = append(found, e)
		}
	}
	return found
}

// str returns the value of tokens that are one plain string.
func (p *magentoParser) str(s magentoSpan) (string, bool) {
	if s.to-s.from != 1 {
		return "", false
	}
	t := p.toks[s.from]
	return t.text, t.kind == magentoString && t.plain
}

func (p *magentoParser) mark(i int, text string) bool {
	return i < len(p.toks) && p.toks[i].kind == magentoMark && p.toks[i].text == text
}

func (p *magentoParser) opens(i int) bool {
	return i < len(p.toks) && p.toks[i].kind == magentoMark && magentoClosers[p.toks[i].text] != ""
}

// word reports whether toks[i] is the name word, in any case, as PHP reads
// keywords and false.
func (p *magentoParser) word(i int, word string) bool {
	return i < len(p.toks) && p.toks[i].kind == magentoName && magentoFold(p.toks[i].text, word)
}

// magentoToken is one PHP token. Whitespace and comments make none.
type magentoToken struct {
	kind magentoKind
	// text is a name's or a mark's text, or a plain string's value.
	text string
	// plain marks a string whose value prodmask knows: single-quoted, or
	// double-quoted with no \ or $.
	plain bool
}

type magentoKind uint8

const (
	magentoName     magentoKind = iota // a keyword or a name: return, false, PDO
	magentoNumber                      // a number literal
	magentoString                      // a quoted string, a heredoc or a nowdoc
	magentoMark                        // a punctuation mark, such as [ or =>
	magentoCloseTag                    // ?>
)

// magentoLex splits the code after <?php into tokens. It fails on what it
// can't follow: a comment, string or heredoc left open; a string that runs
// code, with {$ or ${; #[, which PHP 7 reads as a comment and PHP 8 as an
// attribute; and anything but whitespace after ?>.
func magentoLex(src []byte) ([]magentoToken, bool) {
	var toks []magentoToken
	for i := 0; i < len(src); {
		c, next := src[i], byte(0)
		if i+1 < len(src) {
			next = src[i+1]
		}
		switch {
		case magentoSpace(c):
			i++
		case c == '#' && next == '[':
			return nil, false
		case c == '#' || c == '/' && next == '/':
			i = magentoCommentEnd(src, i)
		case c == '/' && next == '*':
			n := bytes.Index(src[i+2:], []byte("*/"))
			if n < 0 {
				return nil, false
			}
			i += n + 4
		case c == '?' && next == '>':
			if len(bytes.TrimLeft(src[i+2:], " \t\n\r")) > 0 {
				return nil, false
			}
			return append(toks, magentoToken{kind: magentoCloseTag}), true
		case c == '\'' || c == '"' || c == '`':
			t, end, ok := magentoQuoted(src, i)
			if !ok {
				return nil, false
			}
			toks, i = append(toks, t), end
		case c == '<' && bytes.HasPrefix(src[i:], []byte("<<<")):
			end, ok := magentoHeredoc(src, i+3)
			if !ok {
				return nil, false
			}
			toks, i = append(toks, magentoToken{kind: magentoString}), end
		case magentoLabel(c) && !magentoDigit(c):
			j := i + 1
			for j < len(src) && magentoLabel(src[j]) {
				j++
			}
			toks, i = append(toks, magentoToken{kind: magentoName, text: string(src[i:j])}), j
		case magentoDigit(c) || c == '.' && magentoDigit(next):
			j := i + 1
			for j < len(src) && (src[j] < 0x80 && magentoLabel(src[j]) || src[j] == '.') {
				j++
			}
			toks, i = append(toks, magentoToken{kind: magentoNumber}), j
		default:
			n := 1
			for _, m := range []string{"<=>", "=>", "..."} {
				if bytes.HasPrefix(src[i:], []byte(m)) {
					n = len(m)
					break
				}
			}
			toks, i = append(toks, magentoToken{kind: magentoMark, text: string(src[i : i+n])}), i+n
		}
	}
	return toks, true
}

// magentoCommentEnd returns where the // or # comment at src[i] ends: at a
// line end, or before ?>, which ends PHP code even inside such a comment.
func magentoCommentEnd(src []byte, i int) int {
	for ; i < len(src); i++ {
		if src[i] == '\n' || src[i] == '\r' || src[i] == '?' && i+1 < len(src) && src[i+1] == '>' {
			break
		}
	}
	return i
}

// magentoQuoted reads the quoted string at src[i] and returns where it ends.
// In single quotes only \\ and \' are escapes, so the value is always known.
// In double quotes and backquotes a \ escapes the byte after it; the value is
// known only for double quotes with no \ or $, and {$ or ${ starts code,
// which prodmask doesn't follow.
func magentoQuoted(src []byte, i int) (magentoToken, int, bool) {
	quote := src[i]
	t := magentoToken{kind: magentoString, plain: quote != '`'}
	var value []byte
	for j := i + 1; j < len(src); j++ {
		c := src[j]
		switch {
		case c == quote:
			if t.plain {
				t.text = string(value)
			}
			return t, j + 1, true
		case quote == '\'':
			if c == '\\' && j+1 < len(src) && (src[j+1] == '\\' || src[j+1] == '\'') {
				j++
				c = src[j]
			}
		case c == '\\':
			t.plain = false
			j++
		case magentoCode(src, j):
			return magentoToken{}, 0, false
		case c == '$':
			t.plain = false
		}
		value = append(value, c)
	}
	return magentoToken{}, 0, false
}

// magentoHeredoc skips the heredoc or nowdoc whose <<< ends at src[i], and
// returns where it ends: after the first line that starts, past spaces and
// tabs, with its label and then a byte that can't extend the label, as PHP
// 7.3 and later read it.
func magentoHeredoc(src []byte, i int) (int, bool) {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	var quote byte
	if i < len(src) && (src[i] == '\'' || src[i] == '"') {
		quote = src[i]
		i++
	}
	start := i
	if i >= len(src) || !magentoLabel(src[i]) || magentoDigit(src[i]) {
		return 0, false
	}
	for i < len(src) && magentoLabel(src[i]) {
		i++
	}
	label := src[start:i]
	if quote != 0 {
		if i >= len(src) || src[i] != quote {
			return 0, false
		}
		i++
	}
	i, ok := magentoNewline(src, i)
	for ok {
		j := i
		for j < len(src) && (src[j] == ' ' || src[j] == '\t') {
			j++
		}
		if end := j + len(label); end < len(src) && bytes.Equal(src[j:end], label) && !magentoLabel(src[end]) {
			return end, true
		}
		for ; j < len(src) && src[j] != '\n' && src[j] != '\r'; j++ {
			switch {
			case quote == '\'':
			case src[j] == '\\' && j+1 < len(src) && src[j+1] != '\n' && src[j+1] != '\r':
				j++
			case magentoCode(src, j):
				return 0, false
			}
		}
		i, ok = magentoNewline(src, j)
	}
	return 0, false
}

// magentoNewline returns where the line end at src[i] ends: \n, \r or \r\n.
func magentoNewline(src []byte, i int) (int, bool) {
	switch {
	case i >= len(src):
		return 0, false
	case src[i] == '\r' && i+1 < len(src) && src[i+1] == '\n':
		return i + 2, true
	case src[i] == '\n' || src[i] == '\r':
		return i + 1, true
	}
	return 0, false
}

// magentoCode reports {$ or ${ at src[j], which starts code inside a string.
func magentoCode(src []byte, j int) bool {
	return j+1 < len(src) && (src[j] == '{' && src[j+1] == '$' || src[j] == '$' && src[j+1] == '{')
}

func magentoSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func magentoDigit(c byte) bool { return '0' <= c && c <= '9' }

// magentoLabel reports a byte PHP allows in a name: a letter, a digit, _, or
// any byte from 0x80.
func magentoLabel(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || magentoDigit(c) || c == '_' || c >= 0x80
}

// magentoFold reports whether s is word, which is in lower case, with ASCII
// letters in any case: PHP folds no others.
func magentoFold(s, word string) bool {
	if len(s) != len(word) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != word[i] {
			return false
		}
	}
	return true
}
