package sqldump

import (
	"strings"
	"unicode/utf8"
)

// csKind is how a string literal's bytes are turned into the bytes handed on.
type csKind uint8

const (
	csKeep   csKind = iota // the bytes are UTF-8 or ASCII already
	csLatin1               // latin1 to UTF-8, by MySQL's mapping
	csBinary               // raw bytes
	csNone   csKind = 255  // no override
)

// mbKind is a multi-byte character set whose trail bytes can be a backslash
// or a quote, so the lexer must step over them.
type mbKind uint8

const (
	mbNone mbKind = iota
	mbSJIS
	mbGBK
)

func (m mbKind) lead(c byte) bool {
	switch m {
	case mbSJIS:
		return (c >= 0x81 && c <= 0x9f) || (c >= 0xe0 && c <= 0xfc)
	case mbGBK:
		return c >= 0x81 && c <= 0xfe
	}
	return false
}

type charsetInfo struct {
	decoded bool
	kind    csKind
	mb      mbKind
}

// charsets is MySQL's and MariaDB's list of character sets, with what the
// reader does with each. Only the first six are decoded.
var charsets = func() map[string]charsetInfo {
	m := map[string]charsetInfo{
		"utf8mb4": {decoded: true, kind: csKeep},
		"utf8mb3": {decoded: true, kind: csKeep},
		"utf8":    {decoded: true, kind: csKeep},
		"ascii":   {decoded: true, kind: csKeep},
		"latin1":  {decoded: true, kind: csLatin1},
		"binary":  {decoded: true, kind: csBinary},
	}
	for _, n := range strings.Fields(`armscii8 cp1250 cp1251 cp1256 cp1257 cp850
		cp852 cp866 dec8 eucjpms euckr gb2312 geostd8 greek hebrew hp8 keybcs2
		koi8r koi8u latin2 latin5 latin7 macce macroman swe7 tis620 ucs2 ujis
		utf16 utf16le utf32`) {
		m[n] = charsetInfo{}
	}
	for _, n := range []string{"big5", "gbk", "gb18030"} {
		m[n] = charsetInfo{mb: mbGBK}
	}
	for _, n := range []string{"sjis", "cp932"} {
		m[n] = charsetInfo{mb: mbSJIS}
	}
	return m
}()

// lookupCharset finds a character set by name, without regard to case.
func lookupCharset(name string) (charsetInfo, string, bool) {
	n := strings.ToLower(name)
	info, ok := charsets[n]
	return info, n, ok
}

// clientCharset is the state of the client character set.
type clientCharset struct {
	name    string // from the list; empty when the set isn't on it
	info    charsetInfo
	unknown bool // the name isn't on the list, or can't be told
}

// usable reports whether string literals can be decoded.
func (c clientCharset) usable() bool { return !c.unknown && c.info.decoded }

// latin1High is MySQL's latin1 for bytes 0x80 to 0x9F: Windows-1252, with the
// five bytes it leaves undefined mapped to the C1 controls. Bytes from 0xA0
// map to the same code point.
var latin1High = [32]rune{
	0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
	0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
	0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
}

func latin1Rune(c byte) rune {
	if c >= 0x80 && c < 0xA0 {
		return latin1High[c-0x80]
	}
	return rune(c)
}

// appendLatin1 appends latin1 bytes to dst as UTF-8, by MySQL's mapping.
func appendLatin1(dst, src []byte) []byte {
	for _, c := range src {
		if c < 0x80 {
			dst = append(dst, c)
		} else {
			dst = utf8.AppendRune(dst, latin1Rune(c))
		}
	}
	return dst
}
