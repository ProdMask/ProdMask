package sqldump

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

const (
	mysql8   = "-- Server version\t8.4.3\n"
	mysql57  = "-- Server version\t5.7.44-log\n"
	maria11  = "-- Server version\t11.8.2-MariaDB\n"
	maria10  = "-- Server version\t5.5.5-10.11.6-MariaDB-1:10.11.6+maria~ubu2204\n"
	noMode   = "SET sql_mode='';\n"
	mysqlHdr = mysql8 + noMode
)

// srec records the structures a read hands over, as well as what rec does.
type srec struct {
	rec
	calls []structCall
	// onStructure runs when a structure arrives, for a test that marks rows.
	onStructure func(db string, t *model.Table)
}

type structCall struct {
	db string
	t  *model.Table
}

func (s *srec) Structure(db string, t *model.Table) {
	s.calls = append(s.calls, structCall{db, t})
	if s.onStructure != nil {
		s.onStructure(db, t)
	}
}

// last is the last structure given for a table.
func (s *srec) last(name string) *model.Table {
	for i := len(s.calls) - 1; i >= 0; i-- {
		if s.calls[i].t.Name == name {
			return s.calls[i].t
		}
	}
	return nil
}

// readTables reads a dump and returns what the visitor was given and the
// reader's state. mark makes the first structure of each table count as
// having rows, as the row reader will.
func readTables(t testing.TB, sql string, mark bool) (*srec, *reader, Stats) {
	t.Helper()
	v := &srec{}
	rd := newReader(context.Background(), strings.NewReader(sql), v, testOpts())
	if mark {
		v.onStructure = func(db string, tb *model.Table) { rd.markRows(db, tb.Name) }
	}
	if err := rd.run(); err != nil {
		t.Fatalf("read: %v", err)
	}
	return v, rd, rd.snapshot()
}

// tableOf reads a dump and returns the last structure of the named table.
func tableOf(t testing.TB, sql, name string) *model.Table {
	t.Helper()
	v, _, _ := readTables(t, sql, false)
	tb := v.last(name)
	if tb == nil {
		t.Fatalf("no structure for %s; unread: %+v", name, v.unread)
	}
	return tb
}

// colOf reads CREATE TABLE t (c <def>) <opts> after a prelude and returns the
// column c.
func colOf(t testing.TB, prelude, def, opts string) *model.Column {
	t.Helper()
	return tableOf(t, prelude+"CREATE TABLE t (c "+def+") "+opts+";", "t").Column("c")
}

func TestColumnTypes(t *testing.T) {
	type want struct {
		dt, ct             string
		null               bool
		max, octet         int64
		charset, collation string
		comment, extra     string
	}
	const cs, co = "utf8mb4", "utf8mb4_0900_ai_ci"
	cases := []struct {
		name, def string
		w         want
	}{
		{"varchar", "varchar(255) NOT NULL", want{"varchar", "varchar(255)", false, 255, 1020, cs, co, "", ""}},
		{"varchar nullable", "varchar(10) DEFAULT NULL", want{"varchar", "varchar(10)", true, 10, 40, cs, co, "", ""}},
		{"char", "char(3)", want{"char", "char(3)", true, 3, 12, cs, co, "", ""}},
		{"char without a length", "char", want{"char", "char(1)", true, 1, 4, cs, co, "", ""}},
		{"character varying", "character varying(5)", want{"varchar", "varchar(5)", true, 5, 20, cs, co, "", ""}},
		{"binary", "binary(16)", want{"binary", "binary(16)", true, 16, 16, "", "", "", ""}},
		{"char byte", "char(4) byte", want{"binary", "binary(4)", true, 4, 4, "", "", "", ""}},
		{"varbinary", "varbinary(20) NOT NULL", want{"varbinary", "varbinary(20)", false, 20, 20, "", "", "", ""}},
		{"tinytext", "tinytext", want{"tinytext", "tinytext", true, 255, 255, cs, co, "", ""}},
		{"text", "text", want{"text", "text", true, 65535, 65535, cs, co, "", ""}},
		{"mediumtext", "mediumtext", want{"mediumtext", "mediumtext", true, 16777215, 16777215, cs, co, "", ""}},
		{"longtext", "longtext", want{"longtext", "longtext", true, 4294967295, 4294967295, cs, co, "", ""}},
		{"long varchar", "long varchar", want{"mediumtext", "mediumtext", true, 16777215, 16777215, cs, co, "", ""}},
		{"text with a length", "text(100)", want{"tinytext", "tinytext", true, 255, 255, cs, co, "", ""}},
		{"tinyblob", "tinyblob", want{"tinyblob", "tinyblob", true, 255, 255, "", "", "", ""}},
		{"blob", "blob", want{"blob", "blob", true, 65535, 65535, "", "", "", ""}},
		{"mediumblob", "mediumblob", want{"mediumblob", "mediumblob", true, 16777215, 16777215, "", "", "", ""}},
		{"longblob", "longblob", want{"longblob", "longblob", true, 4294967295, 4294967295, "", "", "", ""}},
		{"enum", "enum('a','bb','ccc') NOT NULL", want{"enum", "enum('a','bb','ccc')", false, 3, 12, cs, co, "", ""}},
		{"enum with a quote", "enum('it''s','x')", want{"enum", "enum('it''s','x')", true, 4, 16, cs, co, "", ""}},
		{"enum with multibyte members", "enum('ab','ééé')", want{"enum", "enum('ab','ééé')", true, 3, 12, cs, co, "", ""}},
		{"set, as long as its members joined", "set('x','yy')", want{"set", "set('x','yy')", true, 4, 16, cs, co, "", ""}},
		{"int", "int NOT NULL", want{"int", "int", false, 0, 0, "", "", "", ""}},
		{"integer with a width", "INTEGER(11) UNSIGNED", want{"int", "int(11) unsigned", true, 0, 0, "", "", "", ""}},
		{"zerofill", "int(4) unsigned zerofill", want{"int", "int(4) unsigned zerofill", true, 0, 0, "", "", "", ""}},
		{"bigint", "bigint(20) unsigned NOT NULL", want{"bigint", "bigint(20) unsigned", false, 0, 0, "", "", "", ""}},
		{"bool", "bool", want{"tinyint", "tinyint(1)", true, 0, 0, "", "", "", ""}},
		{"decimal", "decimal(10,2) NOT NULL", want{"decimal", "decimal(10,2)", false, 0, 0, "", "", "", ""}},
		{"numeric with one argument", "numeric(8)", want{"decimal", "decimal(8,0)", true, 0, 0, "", "", "", ""}},
		{"double precision", "double precision", want{"double", "double", true, 0, 0, "", "", "", ""}},
		{"datetime", "datetime(3)", want{"datetime", "datetime(3)", true, 0, 0, "", "", "", ""}},
		{"json", "json", want{"json", "json", true, 0, 0, "", "", "", ""}},
		{"bit", "bit(3)", want{"bit", "bit(3)", true, 0, 0, "", "", "", ""}},
		{"year", "year", want{"year", "year", true, 0, 0, "", "", "", ""}},
		{"comment", "int COMMENT 'it''s here'", want{"int", "int", true, 0, 0, "", "", "it's here", ""}},
		{"upper case", "VARCHAR(7) NOT NULL", want{"varchar", "varchar(7)", false, 7, 28, cs, co, "", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := colOf(t, mysqlHdr, tc.def, "")
			got := want{c.DataType, c.ColumnType, c.Nullable, c.MaxLength, c.OctetLength, c.Charset, c.Collation, c.Comment, c.Extra}
			if got != tc.w {
				t.Fatalf("got  %+v\nwant %+v", got, tc.w)
			}
			if c.Name != "c" || c.Position != 1 || c.Key != "" {
				t.Fatalf("name %q position %d key %q", c.Name, c.Position, c.Key)
			}
		})
	}
}

func TestOctetLengthByCharset(t *testing.T) {
	for _, tc := range []struct {
		cs     string
		octets int64
	}{
		{"utf8mb4", 40}, {"utf8mb3", 30}, {"utf8", 30}, {"latin1", 10}, {"ascii", 10},
		{"ucs2", 20}, {"utf16", 40}, {"utf32", 40}, {"big5", 20}, {"gbk", 20}, {"gb18030", 40},
		{"sjis", 20}, {"ujis", 30}, {"euckr", 20}, {"cp1251", 10}, {"koi8r", 10},
	} {
		c := colOf(t, mysqlHdr, "varchar(10) CHARACTER SET "+tc.cs, "")
		if c.MaxLength != 10 || c.OctetLength != tc.octets {
			t.Errorf("%s: max %d octet %d, want 10 and %d", tc.cs, c.MaxLength, c.OctetLength, tc.octets)
		}
	}
	// text types count bytes whatever the set; an enum counts its members.
	if c := colOf(t, mysqlHdr, "text CHARACTER SET utf8mb3", ""); c.MaxLength != 65535 || c.OctetLength != 65535 {
		t.Errorf("text: %d %d", c.MaxLength, c.OctetLength)
	}
	if c := colOf(t, mysqlHdr, "enum('ab','cde') CHARACTER SET latin1", ""); c.MaxLength != 3 || c.OctetLength != 3 {
		t.Errorf("enum: %d %d", c.MaxLength, c.OctetLength)
	}
}

func TestCharsetResolution(t *testing.T) {
	for _, tc := range []struct {
		name, prelude, def, opts string
		charset, collation       string
	}{
		{"the column's own set and collation", mysqlHdr, "varchar(9) CHARACTER SET latin1 COLLATE latin1_general_ci", "DEFAULT CHARSET=utf8mb4", "latin1", "latin1_general_ci"},
		{"the column's own collation names the set", mysqlHdr, "varchar(9) COLLATE utf8mb4_bin", "DEFAULT CHARSET=latin1", "utf8mb4", "utf8mb4_bin"},
		{"a collation with a long name", mysqlHdr, "varchar(9) COLLATE utf8mb4_unicode_520_ci", "", "utf8mb4", "utf8mb4_unicode_520_ci"},
		{"the column's own set takes its default collation", mysqlHdr, "varchar(9) CHARACTER SET latin1", "DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin", "latin1", "latin1_swedish_ci"},
		{"CHARSET is CHARACTER SET", mysqlHdr, "varchar(9) CHARSET ascii", "", "ascii", "ascii_general_ci"},
		{"the table's set and collation", mysqlHdr, "varchar(9)", "DEFAULT CHARSET=latin1 COLLATE=latin1_german1_ci", "latin1", "latin1_german1_ci"},
		{"the table's set alone", mysqlHdr, "varchar(9)", "DEFAULT CHARSET=latin1", "latin1", "latin1_swedish_ci"},
		{"the table's collation alone", mysqlHdr, "varchar(9)", "COLLATE=latin1_bin", "latin1", "latin1_bin"},
		{"CHARACTER SET in the table's options", mysqlHdr, "varchar(9)", "CHARACTER SET=gbk", "gbk", "gbk_chinese_ci"},
		{"the database's set and collation", mysqlHdr + "CREATE DATABASE d DEFAULT CHARACTER SET latin1 COLLATE latin1_bin;\n", "varchar(9)", "", "latin1", "latin1_bin"},
		{"the database's set alone", mysqlHdr + "CREATE DATABASE d /*!40100 DEFAULT CHARACTER SET latin2 */;\n", "varchar(9)", "", "latin2", "latin2_general_ci"},
		{"the database's set after ALTER DATABASE", mysqlHdr + "CREATE DATABASE d DEFAULT CHARACTER SET latin1;\nALTER DATABASE d CHARACTER SET = ascii;\n", "varchar(9)", "", "ascii", "ascii_general_ci"},
		{"the table beats the database", mysqlHdr + "CREATE DATABASE d DEFAULT CHARACTER SET latin1;\n", "varchar(9)", "DEFAULT CHARSET=ascii", "ascii", "ascii_general_ci"},
		{"MySQL 8 with nothing said", mysql8 + noMode, "varchar(9)", "", "utf8mb4", "utf8mb4_0900_ai_ci"},
		{"no header with nothing said", noMode, "varchar(9)", "", "utf8mb4", "utf8mb4_0900_ai_ci"},
		{"MySQL 5.7 with nothing said", mysql57 + noMode, "varchar(9)", "", "utf8mb4", "utf8mb4_general_ci"},
		{"MariaDB 11 with nothing said", maria11 + noMode, "varchar(9)", "", "utf8mb4", "utf8mb4_uca1400_ai_ci"},
		{"MariaDB 11.4 with nothing said", "-- Server version\t11.4.2-MariaDB\n" + noMode, "varchar(9)", "", "utf8mb4", "utf8mb4_general_ci"},
		{"utf8mb3 on MariaDB 11.8", maria11 + noMode, "varchar(9) CHARACTER SET utf8mb3", "", "utf8mb3", "utf8mb3_uca1400_ai_ci"},
		{"latin1 on MariaDB 11.8", maria11 + noMode, "varchar(9) CHARACTER SET latin1", "", "latin1", "latin1_swedish_ci"},
		{"MariaDB 10 with nothing said", maria10 + noMode, "varchar(9)", "", "utf8mb4", "utf8mb4_general_ci"},
		{"the database's utf8mb4 on MariaDB 11", maria11 + noMode + "CREATE DATABASE d DEFAULT CHARACTER SET utf8mb4;\n", "varchar(9)", "", "utf8mb4", "utf8mb4_uca1400_ai_ci"},
		{"the BINARY attribute", mysqlHdr, "varchar(9) BINARY", "DEFAULT CHARSET=latin1", "latin1", "latin1_bin"},
		{"the BINARY attribute with a set", mysqlHdr, "char(2) CHARACTER SET utf8mb3 BINARY", "", "utf8mb3", "utf8mb3_bin"},
		{"utf8 is utf8mb3", mysqlHdr, "varchar(9) CHARACTER SET utf8", "", "utf8mb3", "utf8mb3_general_ci"},
		{"a utf8 collation is a utf8mb3 one", mysqlHdr, "varchar(9) COLLATE utf8_unicode_ci", "", "utf8mb3", "utf8mb3_unicode_ci"},
		{"utf8mb3 on MySQL 5.7 is utf8", mysql57 + noMode, "varchar(9) CHARACTER SET utf8mb3", "", "utf8", "utf8_general_ci"},
		{"upper case names", mysqlHdr, "varchar(9) CHARACTER SET LATIN1 COLLATE LATIN1_BIN", "", "latin1", "latin1_bin"},
		{"an enum has them too", mysqlHdr, "enum('a') CHARACTER SET latin1", "", "latin1", "latin1_swedish_ci"},
		{"a text column", mysqlHdr, "text", "DEFAULT CHARSET=latin1", "latin1", "latin1_swedish_ci"},
		{"national char is utf8mb3", mysqlHdr, "national char(3)", "", "utf8mb3", "utf8mb3_general_ci"},
		{"ASCII is latin1", mysqlHdr, "char(3) ASCII", "", "latin1", "latin1_swedish_ci"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := colOf(t, tc.prelude+"USE d;\n", tc.def, tc.opts)
			if c.Charset != tc.charset || c.Collation != tc.collation {
				t.Fatalf("charset %q collation %q, want %q %q", c.Charset, c.Collation, tc.charset, tc.collation)
			}
		})
	}
	// Non-string types have none, whatever the table says.
	for _, def := range []string{"int", "decimal(5,2)", "datetime", "json", "blob", "binary(3)", "varbinary(3)", "bit(2)"} {
		c := colOf(t, mysqlHdr, def, "DEFAULT CHARSET=latin1")
		if c.Charset != "" || c.Collation != "" {
			t.Errorf("%s: charset %q collation %q", def, c.Charset, c.Collation)
		}
	}
}

func TestKeyDerivation(t *testing.T) {
	keys := func(sql string) map[string]string {
		tb := tableOf(t, mysqlHdr+sql, "t")
		m := map[string]string{}
		for _, c := range tb.Columns {
			m[c.Name] = c.Key
		}
		return m
	}
	for _, tc := range []struct {
		name, sql string
		want      map[string]string
	}{
		{"primary key", "CREATE TABLE t (a int NOT NULL, b int, PRIMARY KEY (a));", map[string]string{"a": "PRI", "b": ""}},
		{"composite primary key", "CREATE TABLE t (a int NOT NULL, b int NOT NULL, c int, PRIMARY KEY (a, b));", map[string]string{"a": "PRI", "b": "PRI", "c": ""}},
		{"unique, plain and composite", "CREATE TABLE t (a int, b int, c int, d int, e int, PRIMARY KEY (e), UNIQUE KEY u1 (a), UNIQUE KEY u2 (b, c), KEY k (d));", map[string]string{"a": "UNI", "b": "MUL", "c": "", "d": "MUL", "e": "PRI"}},
		{"only the first column of a key", "CREATE TABLE t (a int, b int, c int, KEY k (a, b, c));", map[string]string{"a": "MUL", "b": "", "c": ""}},
		{"unique wins over a plain key", "CREATE TABLE t (a int, UNIQUE KEY u (a), KEY k (a));", map[string]string{"a": "UNI"}},
		{"primary wins over unique", "CREATE TABLE t (a int NOT NULL, PRIMARY KEY (a), UNIQUE KEY u (a));", map[string]string{"a": "PRI"}},
		{"a unique key with a prefix", "CREATE TABLE t (a varchar(255) NOT NULL, PRIMARY KEY (a), b varchar(255), UNIQUE KEY u (b(10)));", map[string]string{"a": "PRI", "b": "UNI"}},
		{"a unique not-null key stands in for the primary key", "CREATE TABLE t (a int NOT NULL, b int, UNIQUE KEY u (a), KEY k (b));", map[string]string{"a": "PRI", "b": "MUL"}},
		{"only the first such key", "CREATE TABLE t (a int NOT NULL, b int NOT NULL, UNIQUE KEY u1 (a), UNIQUE KEY u2 (b));", map[string]string{"a": "PRI", "b": "UNI"}},
		{"a nullable unique key is no primary key", "CREATE TABLE t (a int, UNIQUE KEY u (a));", map[string]string{"a": "UNI"}},
		{"a composite unique not-null key", "CREATE TABLE t (a int NOT NULL, b int NOT NULL, UNIQUE KEY u (a, b));", map[string]string{"a": "PRI", "b": "PRI"}},
		{"inline keys", "CREATE TABLE t (a int NOT NULL AUTO_INCREMENT PRIMARY KEY, b int UNIQUE KEY, c int);", map[string]string{"a": "PRI", "b": "UNI", "c": ""}},
		{"KEY in a column is the primary key", "CREATE TABLE t (a int KEY, b int);", map[string]string{"a": "PRI", "b": ""}},
		{"fulltext and spatial", "CREATE TABLE t (a int, b text, g geometry NOT NULL, FULLTEXT KEY f (b), SPATIAL KEY s (g));", map[string]string{"a": "", "b": "MUL", "g": "MUL"}},
		{"a functional key part names no column", "CREATE TABLE t (a int, b int, KEY k ((a + 1), b));", map[string]string{"a": "", "b": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := keys(tc.sql); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	tb := tableOf(t, mysqlHdr+"CREATE TABLE t (a int, PRIMARY KEY (a));", "t")
	if tb.Column("a").Nullable {
		t.Error("a primary key column is nullable")
	}
}

func TestExtra(t *testing.T) {
	for _, tc := range []struct {
		name, prelude, def, extra string
	}{
		{"auto_increment", mysqlHdr, "int NOT NULL AUTO_INCREMENT", "auto_increment"},
		{"virtual", mysqlHdr, "int GENERATED ALWAYS AS ((`a` + 1)) VIRTUAL", "VIRTUAL GENERATED"},
		{"generated with no keyword is virtual", mysqlHdr, "int AS (a + 1)", "VIRTUAL GENERATED"},
		{"stored", mysqlHdr, "int GENERATED ALWAYS AS (a * 2) STORED", "STORED GENERATED"},
		{"persistent", maria11 + noMode, "int AS (a * 2) PERSISTENT", "STORED GENERATED"},
		{"a nested expression with commas", mysqlHdr, "varchar(9) GENERATED ALWAYS AS (concat(a, ',', (b))) STORED", "STORED GENERATED"},
		{"invisible, in a version comment", mysqlHdr, "int DEFAULT NULL /*!80023 INVISIBLE */", "INVISIBLE"},
		{"invisible, bare", mysqlHdr, "int INVISIBLE", "INVISIBLE"},
		{"a generated invisible column", mysqlHdr, "int GENERATED ALWAYS AS (a) VIRTUAL INVISIBLE", "VIRTUAL GENERATED INVISIBLE"},
		{"a function default on MySQL 8", mysqlHdr, "datetime DEFAULT CURRENT_TIMESTAMP", "DEFAULT_GENERATED"},
		{"an expression default on MySQL 8", mysqlHdr, "varchar(36) DEFAULT (uuid())", "DEFAULT_GENERATED"},
		{"a literal default has none", mysqlHdr, "varchar(36) DEFAULT 'x'", ""},
		{"a null default has none", mysqlHdr, "int DEFAULT NULL", ""},
		{"a function default on MySQL 5.7", mysql57 + noMode, "datetime DEFAULT CURRENT_TIMESTAMP", ""},
		{"a function default on MariaDB", maria11 + noMode, "datetime DEFAULT current_timestamp()", ""},
		{"on update on MySQL", mysqlHdr, "timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP", "DEFAULT_GENERATED on update CURRENT_TIMESTAMP"},
		{"on update with a precision on MySQL", mysqlHdr, "timestamp(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6)", "on update CURRENT_TIMESTAMP(6)"},
		{"on update written as now()", mysqlHdr, "timestamp NULL ON UPDATE now()", "on update CURRENT_TIMESTAMP"},
		{"on update on MariaDB", maria11 + noMode, "timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()", "on update current_timestamp()"},
		{"on update with a precision on MariaDB", maria11 + noMode, "datetime(3) NULL ON UPDATE CURRENT_TIMESTAMP(3)", "on update current_timestamp(3)"},
		{"auto_increment and invisible", mysqlHdr, "int NOT NULL AUTO_INCREMENT INVISIBLE", "auto_increment INVISIBLE"},
		{"a system versioning column", maria11 + noMode, "timestamp(6) GENERATED ALWAYS AS ROW START INVISIBLE", "STORED GENERATED INVISIBLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := colOf(t, tc.prelude, tc.def, "")
			if c.Extra != tc.extra {
				t.Fatalf("Extra = %q, want %q", c.Extra, tc.extra)
			}
		})
	}
}

func TestDefaultsKept(t *testing.T) {
	_, rd, _ := readTables(t, mysqlHdr+"CREATE TABLE t (\n"+
		"a int NOT NULL,\n"+
		"b varchar(9) DEFAULT 'x''y',\n"+
		"c int NOT NULL DEFAULT '7',\n"+
		"d int DEFAULT NULL,\n"+
		"e decimal(5,2) DEFAULT -1.50,\n"+
		"f datetime DEFAULT CURRENT_TIMESTAMP,\n"+
		"g varchar(36) DEFAULT (uuid()),\n"+
		"h varchar(9) DEFAULT 'a' 'b',\n"+
		"i bit(3) DEFAULT b'101',\n"+
		"j int DEFAULT 0 COMMENT 'k',\n"+
		"k bool DEFAULT TRUE);", false)
	ti := rd.table("", "t")
	if ti == nil {
		t.Fatal("no table")
	}
	want := []colDefault{
		{},
		{set: true, kind: ValString, text: "x'y"},
		{set: true, kind: ValString, text: "7"},
		{set: true, kind: ValNull},
		{set: true, kind: ValNumber, text: "-1.50"},
		{set: true, expr: true},
		{set: true, expr: true},
		{set: true, kind: ValString, text: "ab"},
		{set: true, kind: ValBit, text: "101"},
		{set: true, kind: ValNumber, text: "0"},
		{set: true, kind: ValNumber, text: "1"},
	}
	if len(ti.defaults) != len(want) {
		t.Fatalf("%d defaults for %d columns", len(ti.defaults), len(want))
	}
	for i, w := range want {
		if got := ti.defaultOf(i); got != w {
			t.Errorf("column %s: default %+v, want %+v", ti.t.Columns[i].Name, got, w)
		}
	}
	if (ti.defaultOf(99) != colDefault{}) {
		t.Error("a column out of range has a default")
	}
	// ALTER keeps the default of a column's new definition, and of the others.
	_, rd, _ = readTables(t, mysqlHdr+"CREATE TABLE t (a int DEFAULT 1, b int DEFAULT 2);\nALTER TABLE t MODIFY a int DEFAULT 5;", false)
	if d := rd.table("", "t").defaultOf(0); d.text != "5" {
		t.Errorf("after MODIFY: %+v", d)
	}
	if d := rd.table("", "t").defaultOf(1); d.text != "2" {
		t.Errorf("the other column: %+v", d)
	}
}
