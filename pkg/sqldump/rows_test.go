package sqldump

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// rowCopy is a Row copied while the visitor holds it.
type rowCopy struct {
	DB, Table   string
	Kind        Kind
	Line        int64
	Ordinal     int64
	Struct      *model.Table
	Values      []val
	KeyCounted  bool
	KeysUnknown bool
}

// rrec records the rows of a read, with what srec records.
type rrec struct {
	srec
	rows []rowCopy
}

func (v *rrec) Row(r *Row) {
	c := rowCopy{DB: r.DB, Table: r.Table, Kind: r.Kind, Line: r.Line, Ordinal: r.Ordinal,
		Struct: r.Structure, KeyCounted: r.KeyCounted, KeysUnknown: r.KeysUnknown}
	if len(r.Values) != len(r.Structure.Columns) {
		panic("the values don't match the columns")
	}
	for _, x := range r.Values {
		c.Values = append(c.Values, val{x.Kind, string(x.Bytes), x.Cut})
	}
	v.rows = append(v.rows, c)
}

// render writes a value as a short string: n: for a number, s: for text, b:
// for bytes, h: for hex, t: for bits.
func (x val) render() string {
	switch x.Kind {
	case ValNull:
		return "NULL"
	case ValString:
		return "s:" + x.Bytes + cutMark(x)
	case ValBinary:
		return "b:" + x.Bytes + cutMark(x)
	case ValHex:
		return "h:" + x.Bytes + cutMark(x)
	case ValNumber:
		return "n:" + x.Bytes
	case ValBit:
		return "t:" + x.Bytes
	}
	return fmt.Sprintf("kind%d", x.Kind)
}

func cutMark(x val) string {
	if x.Cut {
		return "~"
	}
	return ""
}

func (c rowCopy) render() string {
	parts := make([]string, len(c.Values))
	for i, x := range c.Values {
		parts[i] = x.render()
	}
	return strings.Join(parts, "|")
}

func (v *rrec) rendered() []string {
	var out []string
	for _, r := range v.rows {
		out = append(out, r.render())
	}
	return out
}

const rowsPrelude = "SET sql_mode='';\nSET NAMES utf8mb4;\n"

func readRowsOpts(t testing.TB, sql string, opts Options) (*rrec, Stats) {
	t.Helper()
	v := &rrec{}
	st, err := Read(t.Context(), strings.NewReader(sql), v, opts)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return v, st
}

func readRows(t testing.TB, sql string) (*rrec, Stats) {
	t.Helper()
	return readRowsOpts(t, rowsPrelude+sql, testOpts())
}

func sameList(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %q, want %q", what, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: row %d is %q, want %q", what, i+1, got[i], want[i])
		}
	}
}

const abcTable = "CREATE TABLE t (a int, b varchar(10), c text);\n"

func TestInsertForms(t *testing.T) {
	tests := []struct {
		name, sql string
		kind      Kind
		rows      []string
	}{
		{"plain", "INSERT INTO t VALUES (1,'x','y');", KindInsert, []string{"n:1|s:x|s:y"}},
		{"several rows", "INSERT INTO t VALUES (1,'x','y'),(2,'p','q');", KindInsert, []string{"n:1|s:x|s:y", "n:2|s:p|s:q"}},
		{"VALUE", "INSERT INTO t VALUE (1,'x','y');", KindInsert, []string{"n:1|s:x|s:y"}},
		{"qualified", "INSERT INTO d.t VALUES (1,'x','y');", KindInsert, nil},
		{"partition", "INSERT INTO t PARTITION (p0, p1) VALUES (1,'x','y');", KindInsert, []string{"n:1|s:x|s:y"}},
		{"column list", "INSERT INTO t (c, a) VALUES ('y', 1);", KindInsert, []string{"n:1|NULL|s:y"}},
		{"partition and list", "INSERT INTO t PARTITION (p0) (b) VALUES ('x');", KindInsert, []string{"NULL|s:x|NULL"}},
		{"qualified column", "INSERT INTO t (t.a, `b`) VALUES (1, 'x');", KindInsert, []string{"n:1|s:x|NULL"}},
		{"alias", "INSERT INTO t VALUES (1,'x','y') AS new;", KindInsert, []string{"n:1|s:x|s:y"}},
		{"alias with columns", "INSERT INTO t VALUES (1,'x','y'),(2,'x','y') AS new (p, q, r);", KindInsert, []string{"n:1|s:x|s:y", "n:2|s:x|s:y"}},
		{"ignore", "INSERT IGNORE INTO t VALUES (1,'x','y');", KindInsertIgnore, []string{"n:1|s:x|s:y"}},
		{"low priority", "INSERT LOW_PRIORITY INTO t VALUES (1,'x','y');", KindInsert, []string{"n:1|s:x|s:y"}},
		{"replace", "REPLACE INTO t VALUES (1,'x','y');", KindReplace, []string{"n:1|s:x|s:y"}},
		{"empty row", "INSERT INTO t VALUES ();", KindInsert, []string{"NULL|NULL|NULL"}},
		{"empty list and row", "INSERT INTO t () VALUES (), ();", KindInsert, []string{"NULL|NULL|NULL", "NULL|NULL|NULL"}},
		{"names in any case", "INSERT INTO t (A) VALUES (7);", KindInsert, []string{"n:7|NULL|NULL"}},
		{"line breaks", "INSERT INTO t VALUES\n(1,'x','y'),\n(2,'p','q');", KindInsert, []string{"n:1|s:x|s:y", "n:2|s:p|s:q"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, st := readRows(t, abcTable+tc.sql)
			if tc.name == "qualified" {
				// d.t is another table, which the file never created
				if len(v.rows) != 1 || v.rows[0].DB != "d" || v.rows[0].Table != "t" || len(v.rows[0].Values) != 3 {
					t.Fatalf("rows: %+v", v.rows)
				}
				return
			}
			sameList(t, "rows", v.rendered(), tc.rows)
			if len(v.unread) != 0 || st.Unread != 0 {
				t.Fatalf("unread: %+v", v.unread)
			}
			for i, r := range v.rows {
				if r.Kind != tc.kind || r.Table != "t" || r.Line != 4 || r.Ordinal != int64(i+1) {
					t.Errorf("row %d: %+v", i+1, r)
				}
			}
			if st.Rows != int64(len(tc.rows)) || st.Read != 1 {
				t.Errorf("stats: rows %d, read %d", st.Rows, st.Read)
			}
		})
	}
}

func TestInsertUnreadForms(t *testing.T) {
	tests := []struct {
		name, sql string
		reason    Reason
		rows      []string
	}{
		{"on duplicate", "INSERT INTO t VALUES (1,'x','y'), (2,'x','y') ON DUPLICATE KEY UPDATE b = 'z';", ReasonInsertForm, []string{"n:1|s:x|s:y", "n:2|s:x|s:y"}},
		{"on duplicate after alias", "INSERT INTO t VALUES (1,'x','y') AS n ON DUPLICATE KEY UPDATE b = n.b;", ReasonInsertForm, []string{"n:1|s:x|s:y"}},
		{"select", "INSERT INTO t SELECT * FROM s;", ReasonInsertForm, nil},
		{"list and select", "INSERT INTO t (a) SELECT 1;", ReasonInsertForm, nil},
		{"parenthesised select", "INSERT INTO t (SELECT * FROM s);", ReasonInsertForm, nil},
		{"set", "INSERT INTO t SET a = 1;", ReasonInsertForm, nil},
		{"table", "INSERT INTO t TABLE s;", ReasonInsertForm, nil},
		{"replace set", "REPLACE INTO t SET a = 1;", ReasonInsertForm, nil},
		{"row constructor", "INSERT INTO t VALUES ROW(1,'x','y');", ReasonInsertForm, nil},
		{"no list", "INSERT INTO t VALUES;", ReasonInsertForm, nil},
		{"too few values", "INSERT INTO t VALUES (1,'x','y'), (2,'x');", ReasonColumns, []string{"n:1|s:x|s:y"}},
		{"too many values", "INSERT INTO t VALUES (1,'x','y'), (2,'x','y', 4);", ReasonColumns, []string{"n:1|s:x|s:y"}},
		{"too few for the list", "INSERT INTO t (a, b) VALUES (1);", ReasonColumns, nil},
		{"unknown column", "INSERT INTO t (a, z) VALUES (1, 2);", ReasonColumns, nil},
		{"repeated column", "INSERT INTO t (a, A) VALUES (1, 2);", ReasonColumns, nil},
		{"expression", "INSERT INTO t VALUES (1,'x','y'), (2, NOW(), 'y');", ReasonExpression, []string{"n:1|s:x|s:y"}},
		{"arithmetic", "INSERT INTO t VALUES (1+1,'x','y');", ReasonExpression, nil},
		{"hex of odd length", "INSERT INTO t VALUES (1,0x414,'y');", ReasonExpression, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, st := readRows(t, abcTable+tc.sql+"\nINSERT INTO t VALUES (9,'after','x');")
			if len(v.unread) != 1 {
				t.Fatalf("unread: %+v", v.unread)
			}
			u := v.unread[0]
			if u.Reason != tc.reason || u.Line != 4 || u.Table != "t" {
				t.Errorf("unread %+v, want %q at line 4 naming t", u, tc.reason)
			}
			// the statement after it is read whatever happened to this one
			want := append(append([]string(nil), tc.rows...), "n:9|s:after|s:x")
			sameList(t, "rows", v.rendered(), want)
			if st.Unread != 1 || st.Read != 1 {
				t.Errorf("stats: %+v", st)
			}
		})
	}
}

func TestRowsOrdinalsPerTable(t *testing.T) {
	v, _ := readRows(t, "CREATE TABLE a (x int);CREATE TABLE b (x int);\n"+
		"INSERT INTO a VALUES (1),(2);INSERT INTO b VALUES (1);INSERT INTO a VALUES (3);REPLACE INTO b VALUES (1),(1);")
	var got []string
	for _, r := range v.rows {
		got = append(got, fmt.Sprintf("%s%d", r.Table, r.Ordinal))
	}
	sameList(t, "ordinals", got, []string{"a1", "a2", "b1", "a3", "b2", "b3"})
}

func TestRowsStructureAndKnown(t *testing.T) {
	v, st := readRows(t, abcTable+"INSERT INTO t VALUES (1,'x','y');")
	if st.Rows != 1 || len(v.rows) != 1 {
		t.Fatal("no row")
	}
	if v.rows[0].Struct != v.last("t") {
		t.Error("the row's structure is not the one handed on")
	}
	// a table with rows is known, and so is named when an ALTER the reader
	// can't follow is refused
	v, _ = readRows(t, abcTable+"INSERT INTO t VALUES (1,'x','y');ALTER TABLE t ADD COLUMN z int;")
	if len(v.unread) != 1 || v.unread[0].Table != "t" {
		t.Errorf("unread: %+v", v.unread)
	}
	// an ALTER changes the structure in force for the next statement
	v, _ = readRows(t, abcTable+"INSERT INTO t VALUES (1,'x','y');ALTER TABLE t MODIFY a int DEFAULT 5 FIRST;INSERT INTO t (b) VALUES ('q');")
	sameList(t, "after alter", v.rendered(), []string{"n:1|s:x|s:y", "n:5|s:q|NULL"})
}

func TestLiteralsIntoColumns(t *testing.T) {
	const uuidHex = "0x00112233445566778899aabbccddeeff"
	tests := []struct {
		name, prelude, col, lit string
		want                    string
	}{
		{"string into varchar", "", "varchar(9)", `'a\nb'`, "s:a\nb"},
		{"string into int", "", "int", `'12'`, "s:12"},
		{"number into varchar", "", "varchar(9)", `12`, "n:12"},
		{"negative decimal", "", "decimal(5,2)", `-3.50`, "n:-3.50"},
		{"exponent", "", "double", `1.5e3`, "n:1.5e3"},
		{"NULL", "", "int", `NULL`, "NULL"},
		{"TRUE", "", "tinyint(1)", `TRUE`, "n:1"},
		{"FALSE", "", "tinyint(1)", `FALSE`, "n:0"},
		{"bit", "", "bit(3)", `b'101'`, "t:101"},
		{"0b bit", "", "bit(3)", `0b101`, "t:101"},
		{"hex into int", "", "int", `0x10`, "h:\x10"},
		{"adjacent strings", "", "varchar(9)", `'ab' 'cd'`, "s:abcd"},
		{"4 byte utf8 into text", "", "varchar(9)", "'\U0001F600'", "s:\U0001F600"},
		{"hex into varchar", "", "varchar(9)", `0x41C3A9`, "s:A\u00e9"},
		{"hex into utf8mb3 varchar", "", "varchar(9) CHARACTER SET utf8mb3", `X'41C3A9'`, "s:A\u00e9"},
		{"hex into ascii varchar", "", "varchar(9) CHARACTER SET ascii", `0x4142`, "s:AB"},
		{"hex into text", "", "text", `0x4142`, "s:AB"},
		{"hex into enum", "", "enum('a','b')", `0x61`, "s:a"},
		{"hex into json", "", "json", `0x7B7D`, "s:{}"},
		{"hex into latin1 varchar", "", "varchar(9) CHARACTER SET latin1", `0x80E9FF`, "s:\u20ac\u00e9\u00ff"},
		{"latin1 C1 holes", "", "varchar(9) CHARACTER SET latin1", `0x819D`, "s:\u0081\u009d"},
		{"hex into varbinary", "", "varbinary(9)", `0x00FF80`, "b:\x00\xff\x80"},
		{"hex into blob", "", "blob", `X'4142'`, "b:AB"},
		{"hex into binary", "", "binary(3)", `0x414243`, "b:ABC"},
		{"string into varbinary", "", "varbinary(9)", `'a\0b'`, "b:a\x00b"},
		{"utf8 string into varbinary", "", "varbinary(9)", "'\u00e9'", "b:\xc3\xa9"},
		{"binary client into varbinary", "SET NAMES binary;", "varbinary(9)", "'\xff\x00'", "b:\xff\x00"},
		{"binary client into varchar", "SET NAMES binary;", "varchar(9)", "'abc'", "s:abc"},
		{"_binary into varbinary", "", "varbinary(9)", `_binary 'xy'`, "b:xy"},
		{"_binary hex into varchar utf8", "", "varchar(9)", `_binary X'41C3A9'`, "s:A\u00e9"},
		{"_binary hex into varchar latin1", "", "varchar(9) CHARACTER SET latin1", `_binary X'E9'`, "s:\u00e9"},
		{"_utf8mb4 into varchar", "", "varchar(9)", `_utf8mb4 'x' COLLATE utf8mb4_bin`, "s:x"},
		{"_latin1 string into varchar", "", "varchar(9)", "_latin1 'caf\xe9'", "s:caf\u00e9"},
		{"latin1 client into latin1 varchar", "SET NAMES latin1;", "varchar(9) CHARACTER SET latin1", "'caf\xe9\x80'", "s:caf\u00e9\u20ac"},
		{"latin1 client into varbinary", "SET NAMES latin1;", "varbinary(9)", "'caf\xe9\x80\x81'", "b:caf\xe9\x80\x81"},
		{"latin1 client into utf8 varchar", "SET NAMES latin1;", "varchar(9)", "'\xe9'", "s:\u00e9"},
		{"uuid from hex", "", "uuid", uuidHex, "s:00112233-4455-6677-8899-aabbccddeeff"},
		{"uuid from _binary", "", "uuid", "_binary X'00112233445566778899AABBCCDDEEFF'", "s:00112233-4455-6677-8899-aabbccddeeff"},
		{"uuid from raw bytes", "SET NAMES binary;", "uuid", "'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'", "s:00112233-4455-6677-8899-aabbccddeeff"},
		{"uuid from text", "", "uuid", `'00112233-4455-6677-8899-aabbccddeeff'`, "s:00112233-4455-6677-8899-aabbccddeeff"},
		{"inet6 loopback", "", "inet6", `0x00000000000000000000000000000001`, "s:::1"},
		{"inet6", "", "inet6", `0x20010db8000000000000000000000001`, "s:2001:db8::1"},
		{"inet6 from _binary", "", "inet6", `_binary X'20010DB8000000000000000000000001'`, "s:2001:db8::1"},
		{"inet6 compatible", "", "inet6", `0x00000000000000000000000001020304`, "s:::1.2.3.4"},
		{"inet6 low", "", "inet6", `0x00000000000000000000000000000102`, "s:::102"},
		{"inet6 mapped", "", "inet6", `0x00000000000000000000ffff01020304`, "s:::ffff:1.2.3.4"},
		{"inet6 compressed in the middle", "", "inet6", `0x20010db8000000000001000000000001`, "s:2001:db8::1:0:0:1"},
		{"inet4", "", "inet4", `0x7f000001`, "s:127.0.0.1"},
		{"inet4 from text", "", "inet4", `'10.0.0.1'`, "s:10.0.0.1"},
		{"inet4 of the wrong length", "", "inet4", `0x7f0000`, "h:\x7f\x00\x00"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := readRows(t, tc.prelude+"\nCREATE TABLE t (c "+tc.col+");\nINSERT INTO t VALUES ("+tc.lit+");")
			if len(v.unread) != 0 || len(v.rows) != 1 {
				t.Fatalf("unread %+v, rows %+v", v.unread, v.rows)
			}
			if got := v.rows[0].render(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHexIntoUndecodedCharset(t *testing.T) {
	v, st := readRows(t, "CREATE TABLE t (a int, b varchar(9) CHARACTER SET cp1251, c varchar(9));\n"+
		"INSERT INTO t VALUES (1,'ok','x'),(2,'caf\u00e9','y'),(3,0xE9,'z'),(4,'late','w');\n"+
		"INSERT INTO t VALUES (5,'next','v');")
	// a string is already decoded; only raw bytes need the column's set
	sameList(t, "rows", v.rendered(), []string{"n:1|s:ok|s:x", "n:2|s:caf\u00e9|s:y", "n:5|s:next|s:v"})
	if len(v.unread) != 1 || v.unread[0].Reason != ReasonCharset || v.unread[0].Table != "t" || st.Rows != 3 {
		t.Errorf("unread %+v, rows %d", v.unread, st.Rows)
	}
}

func TestCutByCharacters(t *testing.T) {
	opts := testOpts()
	opts.MaxChars = 5
	e5 := strings.Repeat("\u00e9", 5)
	e5hex := strings.Repeat("C3A9", 7)
	sql := rowsPrelude + "CREATE TABLE t (a varchar(99), b varbinary(99), c varchar(99) CHARACTER SET latin1, d text);\n" +
		"INSERT INTO t VALUES ('abcdefgh', 0x41424344454647, 0x4142434445464748, 0x" + e5hex + "),\n" +
		"('abcde', 'ab\u00e9\u00e9\u00e9', 0x41, '" + e5 + "x');"
	v, _ := readRowsOpts(t, sql, opts)
	sameList(t, "rows", v.rendered(), []string{
		"s:abcde~|b:ABCDE~|s:ABCDE~|s:" + e5 + "~",
		"s:abcde|b:ab\xc3\xa9\xc3~|s:A|s:" + e5 + "~",
	})
	// binary counts bytes: ab + three two-byte characters is 8 bytes
}

func TestDefaultsInRows(t *testing.T) {
	ddl := "CREATE TABLE t (id int NOT NULL, a varchar(9) DEFAULT 'dv', b int DEFAULT 7, c datetime DEFAULT CURRENT_TIMESTAMP, " +
		"d int, e varbinary(4) DEFAULT 'xy', f varchar(5) DEFAULT NULL, g varchar(9) CHARACTER SET latin1 DEFAULT 'q', h bit(3) DEFAULT b'101');\n"
	tests := []struct {
		name, sql string
		want      string
		noLit     int64
	}{
		// c's CURRENT_TIMESTAMP is an expression the server fills.
		{"left out", "INSERT INTO t (id) VALUES (1);", "n:1|s:dv|n:7|NULL|NULL|b:xy|NULL|s:q|t:101", 1},
		{"DEFAULT", "INSERT INTO t VALUES (1,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT);", "n:1|s:dv|n:7|NULL|NULL|b:xy|NULL|s:q|t:101", 2},
		{"given", "INSERT INTO t VALUES (1,'z',8,'2020-01-01',3,'k','f','m',b'1');", "n:1|s:z|n:8|s:2020-01-01|n:3|b:k|s:f|s:m|t:1", 0},
		{"empty row", "INSERT INTO t VALUES ();", "NULL|s:dv|n:7|NULL|NULL|b:xy|NULL|s:q|t:101", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, st := readRows(t, ddl+tc.sql)
			if len(v.unread) != 0 || len(v.rows) != 1 {
				t.Fatalf("unread %+v rows %d", v.unread, len(v.rows))
			}
			if got := v.rows[0].render(); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
			if st.DefaultsNoLiteral != tc.noLit {
				t.Errorf("DEFAULTs without a literal: %d, want %d", st.DefaultsNoLiteral, tc.noLit)
			}
		})
	}
}

// keyCase is a dump of one table with an auto-increment key and the keys the
// reader should hold for its rows, "x" for a row that isn't counted.
type keyCase struct {
	name string
	sql  string
	keys []string // each row's first value
	// counted is each row's KeyCounted, as a string of c and . characters.
	counted string
	unknown bool // the table's keys are unknown at its last row
	warns   int  // key warnings
}

func keyTable(opt string) string {
	return "CREATE TABLE t (id bigint unsigned NOT NULL AUTO_INCREMENT, v varchar(9), PRIMARY KEY (id)) ENGINE=InnoDB" + opt + ";\n"
}

func TestCountedKeys(t *testing.T) {
	tests := []keyCase{
		{name: "left out", sql: keyTable("") + "INSERT INTO t (v) VALUES ('a'),('b'),('c');",
			keys: []string{"n:1", "n:2", "n:3"}, counted: "ccc"},
		{name: "NULL", sql: keyTable("") + "INSERT INTO t VALUES (NULL,'a'),(NULL,'b');",
			keys: []string{"n:1", "n:2"}, counted: "cc"},
		{name: "DEFAULT", sql: keyTable("") + "INSERT INTO t VALUES (DEFAULT,'a'),(DEFAULT,'b');",
			keys: []string{"n:1", "n:2"}, counted: "cc"},
		{name: "zero", sql: keyTable("") + "INSERT INTO t VALUES (0,'a'),(0,'b');",
			keys: []string{"n:1", "n:2"}, counted: "cc"},
		{name: "zero string", sql: keyTable("") + "INSERT INTO t VALUES ('0','a'),(0,'b');",
			keys: []string{"n:1", "n:2"}, counted: "cc"},
		{name: "zero with NO_AUTO_VALUE_ON_ZERO", sql: "SET sql_mode='NO_AUTO_VALUE_ON_ZERO';\n" + keyTable("") + "INSERT INTO t VALUES (0,'a'),(NULL,'b'),(0,'c');",
			keys: []string{"n:0", "n:1", "n:0"}, counted: ".c."},
		{name: "mode added with CONCAT", sql: "SET SESSION sql_mode = CONCAT(@@sql_mode, ',NO_AUTO_VALUE_ON_ZERO');\n" + keyTable("") + "INSERT INTO t VALUES (0,'a'),(NULL,'b');",
			keys: []string{"n:0", "n:1"}, counted: ".c"},
		{name: "mode taken away again", sql: "SET sql_mode='NO_AUTO_VALUE_ON_ZERO';\n" + keyTable("") + "INSERT INTO t VALUES (0,'a');SET sql_mode='';INSERT INTO t VALUES (0,'b');",
			keys: []string{"n:0", "n:1"}, counted: ".c"},
		{name: "explicit keys in between", sql: keyTable("") + "INSERT INTO t VALUES (NULL,'a'),(10,'b'),(NULL,'c'),(5,'d'),(NULL,'e');",
			keys: []string{"n:1", "n:10", "n:11", "n:5", "n:12"}, counted: "c.c.c"},
		{name: "explicit key as a string", sql: keyTable("") + "INSERT INTO t VALUES ('7','a'),(NULL,'b');",
			keys: []string{"s:7", "n:8"}, counted: ".c"},
		{name: "explicit key as hex", sql: keyTable("") + "INSERT INTO t VALUES (0x20,'a'),(NULL,'b');",
			keys: []string{"h:\x20", "n:33"}, counted: ".c"},
		{name: "negative key", sql: keyTable("") + "INSERT INTO t VALUES (-4,'a'),(NULL,'b');",
			keys: []string{"n:-4", "n:1"}, counted: ".c"},
		{name: "AUTO_INCREMENT option", sql: keyTable(" AUTO_INCREMENT=100") + "INSERT INTO t (v) VALUES ('a'),('b');",
			keys: []string{"n:100", "n:101"}, counted: "cc"},
		{name: "AUTO_INCREMENT option and a lower key", sql: keyTable(" AUTO_INCREMENT=100") + "INSERT INTO t VALUES (7,'a'),(NULL,'b');",
			keys: []string{"n:7", "n:100"}, counted: ".c"},
		{name: "ALTER AUTO_INCREMENT before rows", sql: keyTable("") + "ALTER TABLE t AUTO_INCREMENT = 50;INSERT INTO t (v) VALUES ('a');",
			keys: []string{"n:50"}, counted: "c"},
		{name: "ALTER AUTO_INCREMENT between rows", sql: keyTable("") + "INSERT INTO t (v) VALUES ('a'),('b');ALTER TABLE t AUTO_INCREMENT=40;INSERT INTO t (v) VALUES ('c');ALTER TABLE t AUTO_INCREMENT=3;INSERT INTO t (v) VALUES ('d');",
			keys: []string{"n:1", "n:2", "n:40", "n:41"}, counted: "cccc"},
		{name: "all keys explicit", sql: keyTable("") + "INSERT INTO t VALUES (3,'a'),(4,'b');",
			keys: []string{"n:3", "n:4"}, counted: ".."},
		{name: "huge key", sql: keyTable("") + "INSERT INTO t VALUES (18446744073709551614,'a'),(NULL,'b');",
			keys: []string{"n:18446744073709551614", "n:18446744073709551615"}, counted: ".c"},
		{name: "counter at the end", sql: keyTable("") + "INSERT INTO t VALUES (18446744073709551615,'a'),(NULL,'b');",
			keys: []string{"n:18446744073709551615", "NULL"}, counted: "..", unknown: true, warns: 1},
		{name: "explicit key after the counter ends", sql: keyTable("") + "INSERT INTO t VALUES (18446744073709551615,'a'),(5,'b'),(NULL,'c');",
			keys: []string{"n:18446744073709551615", "n:5", "NULL"}, counted: "...", unknown: true, warns: 1},
		{name: "counter reaches the end", sql: keyTable("") + "INSERT INTO t VALUES (18446744073709551614,'a'),(NULL,'b'),(NULL,'c');",
			keys: []string{"n:18446744073709551614", "n:18446744073709551615", "NULL"}, counted: ".c.", unknown: true, warns: 1},
		{name: "second statement continues", sql: keyTable("") + "INSERT INTO t (v) VALUES ('a');INSERT INTO t VALUES (NULL,'b'),(9,'c');INSERT INTO t (v) VALUES ('d');",
			keys: []string{"n:1", "n:2", "n:9", "n:10"}, counted: "cc.c"},
		// unknown keys
		{name: "auto_increment_increment", sql: "SET @@session.auto_increment_increment=2;\n" + keyTable("") + "INSERT INTO t (v) VALUES ('a'),('b');",
			keys: []string{"NULL", "NULL"}, counted: "..", unknown: true, warns: 1},
		{name: "auto_increment_offset", sql: "SET auto_increment_offset = 3;\n" + keyTable("") + "INSERT INTO t VALUES (NULL,'a'),(8,'b');",
			keys: []string{"NULL", "n:8"}, counted: "..", unknown: true, warns: 1},
		{name: "global auto_increment_increment", sql: "SET GLOBAL auto_increment_increment=2;\n" + keyTable("") + "INSERT INTO t (v) VALUES ('a');",
			keys: []string{"NULL"}, counted: ".", unknown: true, warns: 1},
		{name: "INSERT IGNORE leaving the key", sql: keyTable("") + "INSERT IGNORE INTO t (v) VALUES ('a'),('b');",
			keys: []string{"NULL", "NULL"}, counted: "..", unknown: true, warns: 1},
		{name: "REPLACE leaving the key", sql: keyTable("") + "INSERT INTO t (v) VALUES ('a');REPLACE INTO t VALUES (NULL,'b');INSERT INTO t (v) VALUES ('c');",
			keys: []string{"n:1", "NULL", "NULL"}, counted: "c..", unknown: true, warns: 1},
		{name: "INSERT IGNORE with keys", sql: keyTable("") + "INSERT IGNORE INTO t VALUES (1,'a'),(1,'b');REPLACE INTO t VALUES (2,'c');",
			keys: []string{"n:1", "n:1", "n:2"}, counted: "...", warns: 0},
		{name: "REPLACE with a zero", sql: keyTable("") + "REPLACE INTO t VALUES (4,'a'),(0,'b');",
			keys: []string{"n:4", "n:0"}, counted: "..", unknown: true, warns: 1},
		{name: "REPLACE with a zero under the mode", sql: "SET sql_mode='NO_AUTO_VALUE_ON_ZERO';\n" + keyTable("") + "REPLACE INTO t VALUES (4,'a'),(0,'b');",
			keys: []string{"n:4", "n:0"}, counted: "..", warns: 0},
		{name: "key that can't be read", sql: keyTable("") + "INSERT INTO t VALUES (1.5,'a'),(NULL,'b');",
			keys: []string{"n:1.5", "NULL"}, counted: "..", unknown: true, warns: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, st := readRows(t, tc.sql)
			if len(v.unread) != 0 {
				t.Fatalf("unread: %+v", v.unread)
			}
			var keys []string
			counted := ""
			for _, r := range v.rows {
				keys = append(keys, r.Values[0].render())
				if r.KeyCounted {
					counted += "c"
				} else {
					counted += "."
				}
			}
			sameList(t, "keys", keys, tc.keys)
			if counted != tc.counted {
				t.Errorf("counted = %q, want %q", counted, tc.counted)
			}
			if last := v.rows[len(v.rows)-1]; last.KeysUnknown != tc.unknown {
				t.Errorf("KeysUnknown = %v, want %v", last.KeysUnknown, tc.unknown)
			}
			n := 0
			for _, w := range v.warns {
				if strings.HasPrefix(w, "the keys of the table ") {
					n++
					if w != fmt.Sprintf(warnKeysFormat, "t") {
						t.Errorf("warning %q", w)
					}
				}
			}
			if n != tc.warns {
				t.Errorf("%d key warnings, want %d: %q", n, tc.warns, v.warns)
			}
			// a table whose keys are unknown never counts one again
			seenUnknown := false
			for _, r := range v.rows {
				if seenUnknown && (r.KeyCounted || !r.KeysUnknown) {
					t.Errorf("row %d: the keys were unknown before it: %+v", r.Ordinal, r)
				}
				seenUnknown = seenUnknown || r.KeysUnknown
			}
			_ = st
		})
	}
}

func TestUnknownKeysPrimaryKeyMissing(t *testing.T) {
	// a primary key that isn't auto-increment, with a value missing
	ddl := "CREATE TABLE t (a int NOT NULL, b int NOT NULL DEFAULT 4, c varchar(9), PRIMARY KEY (a, b));\n"
	v, _ := readRows(t, ddl+"INSERT INTO t VALUES (1,1,'x');INSERT INTO t (a, c) VALUES (2,'y');INSERT INTO t (c) VALUES ('z');INSERT INTO t VALUES (3,3,'w');")
	var unknown []bool
	for _, r := range v.rows {
		unknown = append(unknown, r.KeysUnknown)
	}
	// the default of b is a literal, so it isn't missing; a is
	want := []bool{false, false, true, true}
	for i := range want {
		if unknown[i] != want[i] {
			t.Errorf("row %d: KeysUnknown = %v, want %v", i+1, unknown[i], want[i])
		}
	}
	n := 0
	for _, w := range v.warns {
		if strings.HasPrefix(w, "the keys of the table ") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d warnings: %q", n, v.warns)
	}
	// NULL and DEFAULT without a literal default are missing too
	v, _ = readRows(t, "CREATE TABLE t (a int NOT NULL PRIMARY KEY, c int);INSERT INTO t VALUES (1,1),(NULL,2);")
	if !v.rows[1].KeysUnknown || v.rows[0].KeysUnknown {
		t.Errorf("rows: %+v", v.rows)
	}
	// the warning is per table
	v, _ = readRows(t, "CREATE TABLE p (a int NOT NULL PRIMARY KEY);CREATE TABLE q (a int NOT NULL PRIMARY KEY);INSERT INTO p VALUES (NULL);INSERT INTO q VALUES (NULL);INSERT INTO p VALUES (NULL);")
	n = 0
	for _, w := range v.warns {
		if strings.HasPrefix(w, "the keys of the table ") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d warnings: %q", n, v.warns)
	}
}

func TestAutoIncrementShiftIsPerFile(t *testing.T) {
	// a table with no auto-increment column is not affected
	v, _ := readRows(t, "SET auto_increment_increment=2;CREATE TABLE t (a int, b int);INSERT INTO t VALUES (1,2);")
	if v.rows[0].KeysUnknown {
		t.Error("a table with no auto-increment key has unknown keys")
	}
}

func TestRepeatedKeysAreBothHandedOn(t *testing.T) {
	v, st := readRows(t, keyTable("")+"REPLACE INTO t VALUES (1,'a'),(1,'b');INSERT IGNORE INTO t VALUES (1,'c');")
	sameList(t, "rows", v.rendered(), []string{"n:1|s:a", "n:1|s:b", "n:1|s:c"})
	if st.Rows != 3 || v.rows[0].Ordinal != 1 || v.rows[1].Ordinal != 2 || v.rows[2].Ordinal != 3 {
		t.Errorf("rows %d, ordinals %d %d %d", st.Rows, v.rows[0].Ordinal, v.rows[1].Ordinal, v.rows[2].Ordinal)
	}
	if v.rows[0].Kind != KindReplace || v.rows[2].Kind != KindInsertIgnore {
		t.Errorf("kinds %s, %s", v.rows[0].Kind, v.rows[2].Kind)
	}
}

func TestTableWithoutStructure(t *testing.T) {
	t.Run("no column list", func(t *testing.T) {
		v, st := readRows(t, "INSERT INTO `lost` VALUES (1,'a',NULL),(2,0x4142,'c');INSERT INTO lost VALUES (3,'x','y');")
		sameList(t, "rows", v.rendered(), []string{"n:1|s:a|NULL", "n:2|s:AB|s:c", "n:3|s:x|s:y"})
		if len(v.calls) != 1 {
			t.Fatalf("%d structures", len(v.calls))
		}
		tb := v.calls[0].t
		if tb.Name != "lost" || len(tb.Columns) != 3 || tb.Columns[0].Name != "column_1" || tb.Columns[2].Name != "column_3" {
			t.Errorf("structure: %+v", tb)
		}
		for _, c := range tb.Columns {
			if c.DataType != "longtext" || c.Charset != "utf8mb4" || !c.Nullable {
				t.Errorf("column %+v", c)
			}
		}
		warned := 0
		for _, w := range v.warns {
			if w == fmt.Sprintf(warnNoTableFormat, "lost") {
				warned++
			}
		}
		if warned != 1 {
			t.Errorf("warnings %q", v.warns)
		}
		if st.Rows != 3 || v.rows[2].Ordinal != 3 || v.rows[0].Struct != tb {
			t.Errorf("rows %d", st.Rows)
		}
	})
	t.Run("column list", func(t *testing.T) {
		v, _ := readRows(t, "INSERT INTO lost (id, Name) VALUES (1,'a');INSERT INTO lost (name, id) VALUES ('b', 2);")
		sameList(t, "rows", v.rendered(), []string{"n:1|s:a", "n:2|s:b"})
		if tb := v.calls[0].t; tb.Columns[0].Name != "id" || tb.Columns[1].Name != "Name" || len(v.calls) != 1 {
			t.Errorf("structure: %+v", tb.Columns)
		}
	})
	t.Run("count disagrees with the first row", func(t *testing.T) {
		v, st := readRows(t, "INSERT INTO lost (a, b) VALUES (1);INSERT INTO lost (a, a) VALUES (1, 2);INSERT INTO lost VALUES ();")
		if len(v.rows) != 0 || len(v.calls) != 0 || st.Unread != 3 {
			t.Errorf("rows %d, structures %d, unread %d", len(v.rows), len(v.calls), st.Unread)
		}
		for _, u := range v.unread {
			if u.Reason != ReasonColumns || u.Table != "" {
				t.Errorf("unread %+v", u)
			}
		}
	})
	t.Run("a later row of another size", func(t *testing.T) {
		v, st := readRows(t, "INSERT INTO lost VALUES (1,2);INSERT INTO lost VALUES (1,2,3);")
		if len(v.rows) != 1 || st.Unread != 1 || v.unread[0].Reason != ReasonColumns {
			t.Errorf("rows %d, unread %+v", len(v.rows), v.unread)
		}
	})
	t.Run("two tables and a database", func(t *testing.T) {
		v, _ := readRows(t, "USE d1;INSERT INTO a VALUES (1);USE d2;INSERT INTO a VALUES (2,3);INSERT INTO d1.a VALUES (4);")
		var got []string
		for _, r := range v.rows {
			got = append(got, r.DB+"."+r.Table+fmt.Sprint(len(r.Values)))
		}
		sameList(t, "rows", got, []string{"d1.a1", "d2.a2", "d1.a1"})
		if len(v.calls) != 2 {
			t.Errorf("%d structures", len(v.calls))
		}
	})
	t.Run("created later with the same columns", func(t *testing.T) {
		v, st := readRows(t, "INSERT INTO t VALUES (1,'a');CREATE TABLE t (column_1 int, column_2 varchar(3));INSERT INTO t VALUES (2,'b');")
		if len(v.rows) != 2 || st.Unread != 0 {
			t.Errorf("rows %d unread %+v", len(v.rows), v.unread)
		}
	})
	t.Run("created later with other columns", func(t *testing.T) {
		v, _ := readRows(t, "INSERT INTO t VALUES (1,'a');CREATE TABLE t (x int, y varchar(3));")
		if len(v.unread) != 1 || v.unread[0].Reason != ReasonRecreate {
			t.Errorf("unread %+v", v.unread)
		}
	})
}

func TestRowsMarkRows(t *testing.T) {
	rd, _ := readerFor(abcTable + "INSERT INTO t VALUES (1,'x','y');INSERT INTO u VALUES (1);CREATE TABLE w (a int);")
	if err := rd.run(); err != nil {
		t.Fatal(err)
	}
	if !rd.rowsOf("", "t") || !rd.rowsOf("", "u") || rd.rowsOf("", "w") || !rd.isKnown("", "u") {
		t.Errorf("has-rows set: %v, known: %v", rd.hasRows, rd.known)
	}
	// the second CREATE TABLE of a table with rows is known when the columns
	// are the same
	_, st := readRows(t, abcTable+"INSERT INTO t VALUES (1,'x','y');"+abcTable)
	if st.Structure != 1 || st.Known < 1 {
		t.Errorf("stats %+v", st)
	}
	// and, with other columns, is unread and keeps the structure when no row
	// has been read too
	v, st := readRows(t, abcTable+"CREATE TABLE t (a int);INSERT INTO t VALUES (1,'x','y');")
	if st.Structure != 1 || len(v.unread) != 1 || v.unread[0].Reason != ReasonRecreate || len(v.rows[0].Values) != 3 {
		t.Errorf("stats %+v", st)
	}
	// DROP TABLE after rows warns, as the rows are kept
	v, _ = readRows(t, abcTable+"INSERT INTO t VALUES (1,'x','y');DROP TABLE t;")
	if !v.hasWarning(WarnDropAfterRows) {
		t.Errorf("warnings %q", v.warns)
	}
}

func TestRowValuesAreReusedSafely(t *testing.T) {
	// each value is copied out of the lexer's buffer before the next is read
	v, _ := readRows(t, "CREATE TABLE t (a varchar(9), b varchar(9), c varchar(9));INSERT INTO t VALUES ('one','two','three'),('four','five','six');")
	sameList(t, "rows", v.rendered(), []string{"s:one|s:two|s:three", "s:four|s:five|s:six"})
}

func TestShopFileReadsWhole(t *testing.T) {
	data, err := os.ReadFile("../../examples/shop.sql")
	if err != nil {
		t.Skip("the example isn't here")
	}
	tuples := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "(") {
			tuples++
		}
	}
	v := &rrec{}
	st, err := Read(t.Context(), strings.NewReader(string(data)), v, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if st.Unread != 0 || len(v.unread) != 0 {
		t.Fatalf("%d unread statements: %+v", st.Unread, v.unread)
	}
	if st.Rows != int64(tuples) || int64(len(v.rows)) != st.Rows {
		t.Fatalf("rows read %d, VALUES tuples in the file %d", st.Rows, tuples)
	}
	for _, w := range v.warns {
		if strings.HasPrefix(w, "the keys of the table ") || strings.HasPrefix(w, "the dump holds rows for the table ") {
			t.Errorf("warning: %q", w)
		}
	}
	// every key is explicit, and the file sets NO_AUTO_VALUE_ON_ZERO
	for _, r := range v.rows {
		if r.KeyCounted || r.KeysUnknown {
			t.Fatalf("%s row %d: counted %v, unknown %v", r.Table, r.Ordinal, r.KeyCounted, r.KeysUnknown)
		}
	}
	// the key-shaped values written as adjacent literals are joined
	joined := 0
	for _, r := range v.rows {
		if r.Table != "wp_options" {
			continue
		}
		for _, x := range r.Values {
			if strings.Contains(x.Bytes, "sk_live_") && !strings.Contains(x.Bytes, "' '") {
				joined++
			}
		}
	}
	if joined == 0 {
		t.Error("no joined key-shaped value found")
	}
	perTable := map[string]int{}
	for _, r := range v.rows {
		perTable[r.Table]++
	}
	t.Logf("%d rows in %d tables", st.Rows, len(perTable))
}
