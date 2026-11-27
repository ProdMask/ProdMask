package sqldump

import (
	"strings"
	"testing"
)

func TestComments(t *testing.T) {
	tests := []struct {
		name, sql string
		drops     int
		others    int
	}{
		{"dash dash space", "DROP TABLE a; -- DROP TABLE b;\nDROP TABLE c;", 2, 0},
		{"dash dash tab", "DROP TABLE a; --\tDROP TABLE b;\nDROP TABLE c;", 2, 0},
		{"dash dash newline", "DROP TABLE a; --\nDROP TABLE c;", 2, 0},
		{"dash dash at the end", "DROP TABLE a; --", 1, 0},
		{"dash dash without its space is not a comment", "DROP TABLE a; --DROP TABLE b;\nDROP TABLE c;", 2, 1},
		{"dash dash then a digit is not a comment", "DROP TABLE a; --1;\nDROP TABLE c;", 2, 1},
		{"hash", "DROP TABLE a; # DROP TABLE b;\nDROP TABLE c;", 2, 0},
		{"hash with no space", "DROP TABLE a; #DROP TABLE b;\nDROP TABLE c;", 2, 0},
		{"block", "DROP TABLE a; /* DROP TABLE b; */ DROP TABLE c;", 2, 0},
		{"block with stars", "DROP TABLE a; /** DROP TABLE b; **/ DROP TABLE c;", 2, 0},
		{"block over lines", "DROP TABLE a; /* x\n;\ny */ DROP TABLE c;", 2, 0},
		{"block is not nested", "DROP TABLE a; /* /* */ DROP TABLE c; */ DROP TABLE d;", 2, 1},
		{"comment inside a statement", "DROP /* ; */ TABLE a; DROP TABLE -- ;\n b;", 2, 0},
		{"semicolon in a string", "INSERT INTO t VALUES ('a;b'); DROP TABLE c;", 1, 0},
		{"semicolon in a double-quoted string", `INSERT INTO t VALUES ("a;b"); DROP TABLE c;`, 1, 0},
		{"semicolon in an identifier", "DROP TABLE `a;b`; DROP TABLE c;", 2, 0},
		{"comment marks in strings", "INSERT INTO t VALUES ('-- x', '/* y', '#'); DROP TABLE c;", 1, 0},
		{"quote in a comment", "DROP TABLE a; -- it's\nDROP TABLE c; /* it's */ DROP TABLE d;", 3, 0},
		{"executable, five digits", "/*!40101 DROP TABLE a */; DROP TABLE b;", 2, 0},
		{"executable, six digits", "/*!100100 DROP TABLE a */; DROP TABLE b;", 2, 0},
		{"executable, no digits", "/*! DROP TABLE a */; DROP TABLE b;", 2, 0},
		{"executable, mariadb", "/*M!100100 DROP TABLE a */; DROP TABLE b;", 2, 0},
		{"executable, mariadb, six digits", "/*M!100100 DROP TABLE a */;", 1, 0},
		{"sandbox line", "/*M!999999\\- enable the sandbox mode */ DROP TABLE a;", 1, 0},
		{"sandbox line on its own", "/*M!999999\\- enable the sandbox mode */\n/*!40101 SET @a=1 */;\nDROP TABLE a;", 1, 0},
		{"executable comment with a string holding the end", "/*!40101 SET @a='*/' */; DROP TABLE b;", 1, 0},
		{"delimiter inside an executable comment ends the statement", "/*!40101 DROP TABLE a; DROP TABLE b */; DROP TABLE c;", 3, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, st := readSQL(t, "SET sql_mode='';\n"+tc.sql)
			if count(st, KindDrop) != tc.drops || count(st, KindOther) != tc.others {
				t.Fatalf("drops=%d (want %d), others=%d (want %d): %v", count(st, KindDrop), tc.drops, count(st, KindOther), tc.others, st.ByKind)
			}
		})
	}
}

func TestDelimiter(t *testing.T) {
	trigger := "DELIMITER ;;\n" +
		"/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER t BEFORE INSERT ON x FOR EACH ROW BEGIN\n" +
		"  SET NEW.a = 1;\n  SET NEW.b = ';;';\n  -- a comment ;;\n  /* another ;; */\nEND */;;\n" +
		"DELIMITER ;\n"
	_, st := readSQL(t, "SET sql_mode='';\n"+trigger+"DROP TABLE a;")
	if count(st, KindCreateTrigger) != 1 || count(st, KindDrop) != 1 || st.Unread != 0 || st.Statements() != 3 {
		t.Fatalf("trigger: %v unread=%d", st.ByKind, st.Unread)
	}
	// a delimiter that is inside a string, an identifier and a comment doesn't end anything
	_, st = readSQL(t, "SET sql_mode='';\nDELIMITER $$\nDROP TABLE `a$$b`$$\nINSERT INTO t VALUES ('x$$y')$$\n/* $$ */ DROP TABLE c -- $$\n$$\nDELIMITER ;\nDROP TABLE d;")
	if count(st, KindDrop) != 3 || count(st, KindInsert) != 1 || st.Statements() != 5 {
		t.Fatalf("dollar delimiter: %v", st.ByKind)
	}
	// the delimiter ends a statement in the middle of a word
	_, st = readSQL(t, "SET sql_mode='';\nDELIMITER $$\nDROP TABLE a$$DROP TABLE b$$\nDELIMITER ;")
	if count(st, KindDrop) != 2 {
		t.Fatalf("delimiter after a word: %v", st.ByKind)
	}
	// DELIMITER is a command only at the start of a statement
	_, st = readSQL(t, "SET sql_mode='';\nDROP TABLE a DELIMITER x; DROP TABLE b;")
	if count(st, KindDrop) != 2 {
		t.Fatalf("delimiter in a statement: %v", st.ByKind)
	}
	// a command in lower case, with quotes
	_, st = readSQL(t, "SET sql_mode='';\ndelimiter '//'\nDROP TABLE a; DROP TABLE b//\ndelimiter ;\nDROP TABLE c;")
	if count(st, KindDrop) != 2 {
		t.Fatalf("quoted delimiter: %v", st.ByKind)
	}
	// the command itself is not a statement
	_, st = readSQL(t, "DELIMITER ;;\nDELIMITER ;\n")
	if st.Statements() != 0 {
		t.Fatalf("DELIMITER counted: %v", st.ByKind)
	}
}

func TestCRLFAndBOM(t *testing.T) {
	_, st := readSQL(t, "\xEF\xBB\xBFSET sql_mode='';\r\nDROP TABLE a;\r\nINSERT INTO t VALUES ('a\r\nb');\r\n")
	if st.Statements() != 3 || count(st, KindOther) != 0 || st.Unread != 0 {
		t.Fatalf("BOM or CR LF: %v", st.ByKind)
	}
	// a BOM is no part of the first statement's kind
	_, st = readSQL(t, "\xEF\xBB\xBFDROP TABLE a;")
	if count(st, KindDrop) != 1 {
		t.Fatalf("BOM: %v", st.ByKind)
	}
}

func TestIdentifierLength(t *testing.T) {
	at := strings.Repeat("a", 256)
	at2 := strings.Repeat("b", 256)
	over := strings.Repeat("a", 257)
	v, st := readSQL(t, "SET sql_mode='';\nCREATE TABLE `"+at+"` (a int);\nCREATE TABLE `"+over+"` (a int);\nCREATE TABLE "+over+" (a int);\nCREATE TABLE "+at2+" (a int);")
	if st.Structure != 2 || st.Unread != 2 {
		t.Fatalf("structure=%d unread=%d", st.Structure, st.Unread)
	}
	for _, u := range v.unread {
		if u.Reason != ReasonIdentLength {
			t.Fatalf("reason %q", u.Reason)
		}
	}
}

func TestTokens(t *testing.T) {
	lx := newLexer(t.Context(), strings.NewReader("a.b `c`.d @x @@session.sql_mode 1.5e-3 .5 'x' 0x41 b'1' (,) 12abc"), 100)
	want := []struct {
		kind tokKind
		text string
	}{
		{tokWord, "a"}, {tokSym, ""}, {tokWord, "b"}, {tokIdent, "c"}, {tokSym, ""}, {tokWord, "d"},
		{tokVar, "@x"}, {tokVar, "@@session.sql_mode"}, {tokNum, "1.5e-3"}, {tokNum, ".5"},
		{tokString, "x"}, {tokHex, "A"}, {tokBit, "1"}, {tokSym, ""}, {tokSym, ""}, {tokSym, ""}, {tokWord, "12abc"}, {tokEOF, ""},
	}
	for i, w := range want {
		tok := lx.next()
		if tok.kind != w.kind || (w.text != "" && string(tok.text) != w.text) {
			t.Fatalf("token %d = kind %d %q, want kind %d %q", i, tok.kind, tok.text, w.kind, w.text)
		}
	}
}

func TestReadErrorKeepsStats(t *testing.T) {
	// a stream that fails after some statements gives the fixed error and what
	// was read
	r := &failingReader{data: "SET sql_mode='';DROP TABLE a;DROP TABLE b;DR"}
	st, err := Read(t.Context(), r, nil, testOpts())
	if err != ErrRead {
		t.Fatalf("error = %v", err)
	}
	if count(st, KindDrop) != 2 {
		t.Fatalf("stats %v", st.ByKind)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("the error holds the reader's text")
	}
}

type failingReader struct {
	data string
	done bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.done {
		return 0, errSecret
	}
	f.done = true
	return copy(p, f.data), nil
}

type secretError struct{}

func (secretError) Error() string { return "secret path /home/x/dump.sql" }

var errSecret = secretError{}
