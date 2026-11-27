package sqldump

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
)

var fuzzSeeds = []string{
	"",
	";",
	"SET sql_mode='NO_BACKSLASH_ESCAPES';INSERT INTO t VALUES ('a\\');DROP TABLE x;",
	"/*!40101 SET sql_mode='ANSI_QUOTES' */;INSERT INTO t VALUES (\"a\\\");",
	"/*M!999999\\- enable the sandbox mode */\n-- MariaDB dump 10.19  Distrib 11.8.2-MariaDB\nSET @a=@@sql_mode;",
	"DELIMITER ;;\nCREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW BEGIN SET @a = ';'; END;;\nDELIMITER ;\n",
	"DELIMITER $$\nDROP TABLE `a$$b`$$\nDELIMITER ;\n",
	"INSERT INTO t VALUES (1, 'a' 'b', _binary 'x', 0x41, X'4142', b'01', -1.5e3, NULL, DEFAULT, TRUE);",
	"INSERT INTO t VALUES (X'414', NOW(), 1+2",
	"SET NAMES latin1;INSERT INTO t VALUES ('caf\xe9');SET NAMES sjis;INSERT INTO t VALUES ('\x83\x5c');",
	"SET @saved_cs_client = @@character_set_client;SET character_set_client = @saved_cs_client;",
	"SET sql_mode=CONCAT(@@sql_mode, ',ANSI_QUOTES');SET sql_mode=REPLACE(@@sql_mode,'ANSI_QUOTES','');",
	"SET sql_mode=@x;DROP TABLE a;",
	"CREATE USER 'a'@'%' IDENTIFIED BY 'x';GRANT ALL ON *.* TO 'b'@'%';",
	"'unterminated",
	"`unterminated",
	"/* unterminated",
	"-- comment\r\n# comment\r\nDROP TABLE a;\r\n",
	"\xEF\xBB\xBFDROP TABLE a;",
	"INSERT INTO t VALUES (0x" + strings.Repeat("4", 300) + ");",
	"CREATE TABLE `" + strings.Repeat("a", 300) + "` (a int);",
	"CREATE TABLE t (id int NOT NULL AUTO_INCREMENT, a varchar(9) DEFAULT 'x', b varbinary(9), c varchar(9) CHARACTER SET latin1, u uuid, PRIMARY KEY (id)) AUTO_INCREMENT=5;" +
		"INSERT INTO t VALUES (NULL,DEFAULT,0x00ff,0xe9e8,0x00112233445566778899aabbccddeeff),(0,'a\\'b',_binary 'x',X'',NULL),(9,'aaaaaaaaaaaaaaaa',0x4142434445464748494a,'zz',_binary 'abc');" +
		"INSERT INTO t (a, id) VALUES ('q',DEFAULT);REPLACE INTO t (b) VALUES (1);INSERT IGNORE INTO t () VALUES ();SET auto_increment_increment=2;INSERT INTO t (a) VALUES ('r');",
	"INSERT INTO lost VALUES (1,'a');INSERT INTO lost (x, y) VALUES (1,2);INSERT INTO lost VALUES (1);INSERT INTO lost2 (a, a) VALUES (1,2);",
	"CREATE TABLE t (a int, PRIMARY KEY (a));INSERT INTO t VALUES (NULL),(1) ON DUPLICATE KEY UPDATE a = 1;INSERT INTO t (SELECT 1);INSERT INTO t VALUES ROW(1);",
	"\x00\x01\xff\xfe(((()))),,,;;;'''\"\"\"```\\\\\\",
}

func FuzzRead(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	kinds := map[Kind]bool{}
	for _, k := range Kinds {
		kinds[k] = true
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		v := &rrec{}
		opts := testOpts()
		opts.MaxChars = 64
		st, err := Read(ctx, strings.NewReader(string(data)), v, opts)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if st.Bytes != int64(len(data)) {
			t.Fatalf("bytes = %d, want %d", st.Bytes, len(data))
		}
		named := map[[2]string]bool{}
		for _, c := range v.calls {
			named[[2]string{c.db, c.t.Name}] = true
		}
		for _, u := range v.unread {
			if !slices.Contains(Reasons, u.Reason) {
				t.Fatalf("a reason outside the list: %q", u.Reason)
			}
			if !kinds[u.Kind] {
				t.Fatalf("a kind outside the list: %q", u.Kind)
			}
			if u.Line < 1 {
				t.Fatalf("line %d", u.Line)
			}
			if u.Table != "" && !named[[2]string{u.Database, u.Table}] {
				t.Fatalf("a table named with none known: %+v", u)
			}
			if (u.Table == "") != (u.Database == "" && u.Table == "") {
				t.Fatalf("a database without a table: %+v", u)
			}
		}
		for _, c := range v.calls {
			checkStructure(t, c.t)
		}
		checkRows(t, v, st, opts.MaxChars)
		for k := range st.ByKind {
			if !kinds[k] {
				t.Fatalf("a kind outside the list: %q", k)
			}
		}
		if st.Read+st.Known+st.Structure+st.Unread != st.Statements() || len(v.unread) != st.Unread {
			t.Fatalf("counts disagree: %+v", st)
		}
		for _, w := range v.warns {
			ok := w == WarnNoSQLMode || w == WarnUnknownCharset ||
				w == WarnDropAfterRows || w == WarnTruncateAfterRows ||
				strings.HasPrefix(w, "the dump creates ") ||
				strings.HasPrefix(w, "the keys of the table ") ||
				strings.HasPrefix(w, "the dump holds rows for the table ") ||
				strings.HasPrefix(w, "the dump uses the character set ")
			if !ok {
				t.Fatalf("a warning outside the fixed set: %q", w)
			}
			if strings.HasPrefix(w, "the dump uses the character set ") {
				name := strings.TrimSuffix(strings.Fields(w)[6], ",")
				if _, _, listed := lookupCharset(name); !listed {
					t.Fatalf("a warning names %q, which is not on the list", name)
				}
			}
		}
	})
}

// checkStructure checks what every structure the reader hands on must hold.
func checkStructure(t *testing.T, tb *model.Table) {
	t.Helper()
	switch tb.Type {
	case "BASE TABLE", "SYSTEM VERSIONED", "VIEW", "SEQUENCE":
	default:
		t.Fatalf("type %q", tb.Type)
	}
	for i, c := range tb.Columns {
		if c.Position != i+1 && tb.Type != "VIEW" {
			t.Fatalf("column %q at %d has position %d", c.Name, i+1, c.Position)
		}
		switch c.Key {
		case "", "PRI", "UNI", "MUL":
		default:
			t.Fatalf("key %q", c.Key)
		}
	}
	for i, ix := range tb.Indexes {
		if len(ix.SubParts) != len(ix.Columns) || len(ix.Columns) == 0 {
			t.Fatalf("index %q: %d columns, %d sub parts", ix.Name, len(ix.Columns), len(ix.SubParts))
		}
		if ix.Name == "PRIMARY" && i != 0 {
			t.Fatalf("PRIMARY at %d", i)
		}
	}
}

// checkRows checks what every row the reader hands on must hold.
func checkRows(t *testing.T, v *rrec, st Stats, maxChars int) {
	t.Helper()
	if st.Rows != int64(len(v.rows)) {
		t.Fatalf("Stats.Rows = %d, %d rows handed on", st.Rows, len(v.rows))
	}
	ord := map[[2]string]int64{}
	unknown := map[[2]string]bool{}
	for _, r := range v.rows {
		k := [2]string{r.DB, r.Table}
		ord[k]++
		if r.Ordinal != ord[k] {
			t.Fatalf("%s: ordinal %d, want %d", r.Table, r.Ordinal, ord[k])
		}
		switch r.Kind {
		case KindInsert, KindInsertIgnore, KindReplace:
		default:
			t.Fatalf("row of kind %q", r.Kind)
		}
		if r.Line < 1 {
			t.Fatalf("line %d", r.Line)
		}
		if len(r.Values) != len(r.Struct.Columns) {
			t.Fatalf("%d values for %d columns", len(r.Values), len(r.Struct.Columns))
		}
		for _, x := range r.Values {
			if x.Kind >= ValDefault {
				t.Fatalf("value of kind %d", x.Kind)
			}
			if x.Kind == ValNull && x.Bytes != "" {
				t.Fatalf("a NULL with bytes")
			}
			switch x.Kind {
			case ValString:
				chars := 0
				for i := 0; i < len(x.Bytes); i++ {
					if x.Bytes[i]&0xC0 != 0x80 {
						chars++
					}
				}
				if chars > maxChars {
					t.Fatalf("a string of %d characters", chars)
				}
			case ValBinary, ValHex:
				if len(x.Bytes) > maxChars {
					t.Fatalf("%d bytes", len(x.Bytes))
				}
			}
		}
		if r.KeyCounted {
			ai := -1
			for i, c := range r.Struct.Columns {
				if c.AutoIncrement() {
					ai = i
				}
			}
			if ai < 0 || r.Values[ai].Kind != ValNumber || r.KeysUnknown || unknown[k] {
				t.Fatalf("a counted key with no counter: %+v", r)
			}
		}
		if unknown[k] && !r.KeysUnknown {
			t.Fatalf("%s: the keys were unknown, then known", r.Table)
		}
		unknown[k] = unknown[k] || r.KeysUnknown
	}
}
