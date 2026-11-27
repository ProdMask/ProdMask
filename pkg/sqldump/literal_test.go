package sqldump

import (
	"context"
	"strings"
	"testing"
)

func TestLiteralTable(t *testing.T) {
	const nb = "SET sql_mode='NO_BACKSLASH_ESCAPES';"
	const ansi = "SET sql_mode='ANSI_QUOTES';"
	tests := []struct {
		name, prelude, expr string
		want                val
		why                 Reason
	}{
		// each escape on its own
		{"escape 0", "", `'a\0b'`, val{ValString, "a\x00b", false}, ""},
		{"escape quote", "", `'a\'b'`, val{ValString, "a'b", false}, ""},
		{"escape double", "", `'a\"b'`, val{ValString, `a"b`, false}, ""},
		{"escape b", "", `'a\bb'`, val{ValString, "a\bb", false}, ""},
		{"escape n", "", `'a\nb'`, val{ValString, "a\nb", false}, ""},
		{"escape r", "", `'a\rb'`, val{ValString, "a\rb", false}, ""},
		{"escape t", "", `'a\tb'`, val{ValString, "a\tb", false}, ""},
		{"escape Z", "", `'a\Zb'`, val{ValString, "a\x1ab", false}, ""},
		{"escape backslash", "", `'a\\b'`, val{ValString, `a\b`, false}, ""},
		{"percent keeps its backslash", "", `'a\%b'`, val{ValString, `a\%b`, false}, ""},
		{"underscore keeps its backslash", "", `'a\_b'`, val{ValString, `a\_b`, false}, ""},
		{"other escape is the letter", "", `'a\qb\xc'`, val{ValString, "aqbxc", false}, ""},
		{"escaped newline", "", "'a\\\nb'", val{ValString, "a\nb", false}, ""},
		{"empty", "", `''`, val{ValString, "", false}, ""},
		// quotes
		{"doubled single", "", `'it''s'`, val{ValString, "it's", false}, ""},
		{"doubled double", "", `"say ""hi"""`, val{ValString, `say "hi"`, false}, ""},
		{"double quotes read as a string", "", `"abc"`, val{ValString, "abc", false}, ""},
		{"single inside double", "", `"it's"`, val{ValString, "it's", false}, ""},
		{"double inside single", "", `'say "hi"'`, val{ValString, `say "hi"`, false}, ""},
		// the SQL mode
		{"no backslash escapes: backslash is plain", nb, `'a\b'`, val{ValString, `a\b`, false}, ""},
		{"no backslash escapes: trailing backslash", nb, `'a\'`, val{ValString, `a\`, false}, ""},
		{"no backslash escapes: n stays", nb, `'a\n'`, val{ValString, `a\n`, false}, ""},
		{"no backslash escapes: doubled quote", nb, `'it''s'`, val{ValString, "it's", false}, ""},
		{"ansi quotes: double is an identifier", ansi, `"abc"`, val{}, ReasonExpression},
		{"ansi quotes: single is a string", ansi, `'abc'`, val{ValString, "abc", false}, ""},
		{"ansi mode name", "SET sql_mode='ANSI';", `"abc"`, val{}, ReasonExpression},
		// adjacent strings
		{"adjacent", "", `'a' 'b'`, val{ValString, "ab", false}, ""},
		{"adjacent mixed quotes", "", `'a' "b" 'c'`, val{ValString, "abc", false}, ""},
		{"adjacent over a comment", "", "'a' /* x */ 'b'", val{ValString, "ab", false}, ""},
		{"adjacent over lines", "", "'a'\n'b'", val{ValString, "ab", false}, ""},
		// introducers
		{"binary", "", `_binary 'x\0y'`, val{ValBinary, "x\x00y", false}, ""},
		{"binary hex", "", `_binary X'00FF'`, val{ValBinary, "\x00\xff", false}, ""},
		{"utf8mb4", "", `_utf8mb4 'abc'`, val{ValString, "abc", false}, ""},
		{"introducer with collate", "", `_utf8mb4 'abc' COLLATE utf8mb4_bin`, val{ValString, "abc", false}, ""},
		{"latin1 introducer", "", "_latin1 'caf\xe9'", val{ValString, "caf\xc3\xa9", false}, ""},
		{"latin1 hex", "", `_latin1 X'E9'`, val{ValString, "\xc3\xa9", false}, ""},
		{"utf8 hex", "", `_utf8 0x41`, val{ValString, "A", false}, ""},
		{"introducer joins strings", "", `_binary 'a' 'b'`, val{ValBinary, "ab", false}, ""},
		{"introducer with an uppercase name", "", `_UTF8MB4 'a'`, val{ValString, "a", false}, ""},
		{"introducer of a set not decoded", "", `_sjis 'a'`, val{}, ReasonCharset},
		{"introducer of no set", "", `_nonesuch 'a'`, val{}, ReasonExpression},
		{"introducer then a name", "", `_binary foo`, val{}, ReasonExpression},
		// hex
		{"0x", "", `0x41`, val{ValHex, "A", false}, ""},
		{"0X upper", "", `0X4a4B`, val{ValHex, "JK", false}, ""},
		{"X quoted", "", `X'4142'`, val{ValHex, "AB", false}, ""},
		{"x quoted lower", "", `x'41'`, val{ValHex, "A", false}, ""},
		{"x empty", "", `X''`, val{ValHex, "", false}, ""},
		{"0x binary bytes", "", `0x00ff80`, val{ValHex, "\x00\xff\x80", false}, ""},
		{"odd 0x", "", `0x414`, val{}, ReasonExpression},
		{"odd X quoted", "", `X'414'`, val{}, ReasonExpression},
		{"bad digit in X", "", `X'4G'`, val{}, ReasonExpression},
		{"bad 0x tail", "", `0x41zz`, val{}, ReasonExpression},
		// bits
		{"b quoted", "", `b'0101'`, val{ValBit, "0101", false}, ""},
		{"B quoted", "", `B'1'`, val{ValBit, "1", false}, ""},
		{"0b", "", `0b0101`, val{ValBit, "0101", false}, ""},
		{"bad bit digit", "", `b'012'`, val{}, ReasonExpression},
		// numbers
		{"integer", "", `42`, val{ValNumber, "42", false}, ""},
		{"zero", "", `0`, val{ValNumber, "0", false}, ""},
		{"leading zeros", "", `007`, val{ValNumber, "007", false}, ""},
		{"negative", "", `-17`, val{ValNumber, "-17", false}, ""},
		{"plus", "", `+17`, val{ValNumber, "17", false}, ""},
		{"fraction", "", `1.5`, val{ValNumber, "1.5", false}, ""},
		{"negative fraction", "", `-0.25`, val{ValNumber, "-0.25", false}, ""},
		{"dot first", "", `.5`, val{ValNumber, ".5", false}, ""},
		{"negative dot first", "", `-.5`, val{ValNumber, "-.5", false}, ""},
		{"exponent", "", `1e3`, val{ValNumber, "1e3", false}, ""},
		{"negative exponent", "", `1.5e-3`, val{ValNumber, "1.5e-3", false}, ""},
		{"upper exponent plus", "", `-1.5E+10`, val{ValNumber, "-1.5E+10", false}, ""},
		{"long number", "", `123456789012345678901234567890`, val{ValNumber, "123456789012345678901234567890", false}, ""},
		{"number then name", "", `1abc`, val{}, ReasonExpression},
		{"minus a name", "", `-x`, val{}, ReasonExpression},
		// keywords
		{"NULL", "", `NULL`, val{ValNull, "", false}, ""},
		{"null lower", "", `null`, val{ValNull, "", false}, ""},
		{"TRUE", "", `TRUE`, val{ValNumber, "1", false}, ""},
		{"FALSE", "", `false`, val{ValNumber, "0", false}, ""},
		{"DEFAULT", "", `DEFAULT`, val{ValDefault, "", false}, ""},
		// anything else
		{"function", "", `NOW()`, val{}, ReasonExpression},
		{"function with arguments", "", `CONCAT('a', 'b')`, val{}, ReasonExpression},
		{"name", "", `somecolumn`, val{}, ReasonExpression},
		{"quoted name", "", "`col`", val{}, ReasonExpression},
		{"expression", "", `1+2`, val{}, ReasonExpression},
		{"string expression", "", `'a' + 'b'`, val{}, ReasonExpression},
		{"parenthesis", "", `(1)`, val{}, ReasonExpression},
		{"subquery", "", `(SELECT 1)`, val{}, ReasonExpression},
		{"default of a column", "", `DEFAULT(a)`, val{}, ReasonExpression},
		{"variable", "", `@x`, val{}, ReasonExpression},
		{"unterminated string", "", `'abc`, val{}, ReasonExpression},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, why := literal(t, tc.prelude, tc.expr)
			if why != tc.why {
				t.Fatalf("reason = %q, want %q", why, tc.why)
			}
			if why == "" && got != tc.want {
				t.Fatalf("value = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLiteralCut(t *testing.T) {
	opts := testOpts()
	opts.MaxChars = 4
	tests := []struct {
		name, expr string
		want       val
	}{
		{"exactly the cap", `'abcd'`, val{ValString, "abcd", false}},
		{"one over", `'abcde'`, val{ValString, "abcd", true}},
		{"multi-byte characters count once", "'\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9'", val{ValString, "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", true}},
		{"four-byte characters", "'\xf0\x9f\x98\x80\xf0\x9f\x98\x80x'", val{ValString, "\xf0\x9f\x98\x80\xf0\x9f\x98\x80x", false}},
		{"escapes count as the character", `'a\nb\tcd\0'`, val{ValString, "a\nb\t", true}},
		{"joined strings share the cap", `'ab' 'cdef'`, val{ValString, "abcd", true}},
		{"hex counts bytes", `0x4142434445`, val{ValHex, "ABCD", true}},
		{"binary", `_binary 'abcdef'`, val{ValBinary, "abcd", true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, why := literalWith(t, opts, "", tc.expr)
			if why != "" || got != tc.want {
				t.Fatalf("got %+v (%q), want %+v", got, why, tc.want)
			}
		})
	}
}

func TestLiteralCutThenNextValue(t *testing.T) {
	opts := testOpts()
	opts.MaxChars = 16
	big := strings.Repeat("x", 10<<20)
	rd := newReader(context.Background(), strings.NewReader("("+"'"+big+"', 'next', 7)"), &rec{}, opts)
	st := rd.begin()
	if !st.next().isSym('(') {
		t.Fatal("no parenthesis")
	}
	v, why := st.readValue()
	if why != "" || !v.Cut || len(v.Bytes) != 16 {
		t.Fatalf("big value: cut=%v len=%d why=%q", v.Cut, len(v.Bytes), why)
	}
	st.next() // the comma
	v, why = st.readValue()
	if why != "" || v.Cut || string(v.Bytes) != "next" {
		t.Fatalf("next value: %q cut=%v why=%q", v.Bytes, v.Cut, why)
	}
	st.next()
	v, _ = st.readValue()
	if string(v.Bytes) != "7" {
		t.Fatalf("third value %q", v.Bytes)
	}
}

func TestLiteralBackslashModeAfterTrigger(t *testing.T) {
	// A trigger written as mysqldump writes it, with NO_BACKSLASH_ESCAPES in
	// its own mode, then the mode restored; the value after it reads with
	// backslash escapes again.
	prelude := "SET sql_mode='';\nDELIMITER ;;\n" +
		"/*!50003 SET @saved_sql_mode = @@sql_mode */ ;;\n" +
		"/*!50003 SET sql_mode = 'NO_BACKSLASH_ESCAPES' */ ;;\n" +
		"/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER t BEFORE INSERT ON x FOR EACH ROW BEGIN SET NEW.a = 'p\\'; END */;;\n" +
		"/*!50003 SET sql_mode = @saved_sql_mode */ ;;\n" +
		"DELIMITER ;\n"
	got, why := literal(t, prelude, `'it\'s'`)
	if why != "" || got.Bytes != "it's" {
		t.Fatalf("got %+v %q, want it's", got, why)
	}
	// and while the trigger's mode holds, the backslash is plain
	prelude = "SET sql_mode='';\nDELIMITER ;;\n/*!50003 SET sql_mode = 'NO_BACKSLASH_ESCAPES' */ ;;\n"
	got, why = literal(t, prelude, `'a\'`)
	if why != "" || got.Bytes != `a\` {
		t.Fatalf("got %+v %q, want a\\", got, why)
	}
}

func TestLiteralLatin1(t *testing.T) {
	want := []rune{
		0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
		0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
		0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
		0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
	}
	for i := 0; i < 256; i++ {
		got, why := literal(t, "SET NAMES latin1;", "'"+string([]byte{byte(i)})+"'")
		if i == '\'' || i == '\\' {
			continue
		}
		var w string
		switch {
		case i >= 0x80 && i < 0xA0:
			w = string(want[i-0x80])
		default:
			w = string(rune(i))
		}
		if why != "" || got.Bytes != w || got.Kind != ValString {
			t.Fatalf("byte %#x: got %q (%q), want %q", i, got.Bytes, why, w)
		}
	}
}

func TestLiteralCharsets(t *testing.T) {
	// four-byte UTF-8 is kept as it is
	emoji := "\xf0\x9f\x98\x80"
	got, why := literal(t, "SET NAMES utf8mb4;", "'a"+emoji+"b'")
	if why != "" || got.Bytes != "a"+emoji+"b" {
		t.Fatalf("utf8mb4: %q %q", got.Bytes, why)
	}
	// binary stays raw
	got, why = literal(t, "SET NAMES binary;", "'\xff\xfe\x80'")
	if why != "" || got.Kind != ValBinary || got.Bytes != "\xff\xfe\x80" {
		t.Fatalf("binary: %+v %q", got, why)
	}
	// utf8, utf8mb3, ascii keep the bytes
	for _, cs := range []string{"utf8", "utf8mb3", "ascii", "UTF8MB4"} {
		got, why = literal(t, "SET NAMES "+cs+";", "'caf\xc3\xa9'")
		if why != "" || got.Bytes != "caf\xc3\xa9" {
			t.Fatalf("%s: %+v %q", cs, got, why)
		}
	}
}

func FuzzLiteral(f *testing.F) {
	f.Add([]byte("plain"))
	f.Add([]byte("it's \"quoted\" \\ back\nline\r\x00 \x1a"))
	f.Add([]byte("\xff\xfe\x80"))
	f.Add([]byte("100%_done"))
	f.Fuzz(func(t *testing.T, b []byte) {
		// Escaped as mysql_real_escape_string escapes, read in the binary
		// character set so no byte is changed, the value reads back equal.
		got, why := literalWith(t, testOpts(), "SET NAMES binary;", escapeValue(b))
		if why != "" || got.Kind != ValBinary || got.Bytes != string(b) {
			t.Fatalf("binary: %q read back as %+v %q", b, got, why)
		}
		// Read as utf8mb4 the bytes are kept too.
		got, why = literal(t, "", escapeValue(b))
		if why != "" || got.Bytes != string(b) {
			t.Fatalf("utf8mb4: %q read back as %+v %q", b, got, why)
		}
		// With NO_BACKSLASH_ESCAPES, only quotes are doubled.
		plain := "'" + strings.ReplaceAll(string(b), "'", "''") + "'"
		got, why = literal(t, "SET sql_mode='NO_BACKSLASH_ESCAPES';", plain)
		if why != "" || got.Bytes != string(b) {
			t.Fatalf("no backslash escapes: %q read back as %+v %q", b, got, why)
		}
	})
}
