package sqldump

import (
	"strings"
	"testing"
)

func TestCharsetNotDecoded(t *testing.T) {
	sql := "SET sql_mode='';\nSET NAMES sjis;\nINSERT INTO t VALUES ('a');\nCREATE TABLE t (a int);\nDROP TABLE x;\nSET NAMES sjis;\nINSERT INTO t VALUES ('b');\nSET NAMES utf8mb4;\nINSERT INTO t VALUES ('c');\n"
	v, st := readSQL(t, sql)
	if st.Unread != 3 || st.Read != 1 || st.Known != 5 {
		t.Fatalf("read=%d known=%d unread=%d", st.Read, st.Known, st.Unread)
	}
	for _, u := range v.unread {
		if u.Reason != ReasonCharset {
			t.Fatalf("reason %q", u.Reason)
		}
	}
	// one warning, naming the set
	n := 0
	for _, w := range v.warns {
		if strings.Contains(w, "sjis") {
			n++
			if !strings.Contains(w, "--default-character-set=utf8mb4") {
				t.Fatalf("warning without its advice: %q", w)
			}
		}
	}
	if n != 1 {
		t.Fatalf("warnings = %q", v.warns)
	}
}

func TestCharsetUnlistedNameIsNeverPrinted(t *testing.T) {
	const name = "zq_secret_cs"
	for _, set := range []string{
		"SET NAMES " + name + ";",
		"SET NAMES '" + name + "' COLLATE " + name + "_ci;",
		"SET CHARACTER SET " + name + ";",
		"SET character_set_client = '" + name + "';",
		"SET @x = '" + name + "'; SET character_set_client = @x;",
		"SET NAMES `" + name + "`;",
	} {
		t.Run(set, func(t *testing.T) {
			v, st := readSQL(t, "SET sql_mode='';\n"+set+"\nINSERT INTO t VALUES ('"+name+"');\n")
			if st.Unread != 1 || v.unread[0].Reason != ReasonCharset || v.unread[0].Kind != KindInsert {
				t.Fatalf("unread = %+v", v.unread)
			}
			if !v.hasWarning(WarnUnknownCharset) || len(v.warns) < 1 {
				t.Fatalf("warnings = %q", v.warns)
			}
			for _, w := range v.warns {
				if strings.Contains(w, name) || strings.Contains(w, "secret") {
					t.Fatalf("a warning holds the name: %q", w)
				}
			}
			for _, u := range v.unread {
				if strings.Contains(string(u.Reason), "secret") || strings.Contains(u.Table, name) {
					t.Fatalf("an entry holds the name: %+v", u)
				}
			}
		})
	}
}

func TestCharsetSaveAndRestore(t *testing.T) {
	// as mysqldump writes it around each table
	sql := "SET sql_mode='';\nSET NAMES latin1;\n" +
		"/*!40101 SET @saved_cs_client     = @@character_set_client */;\n" +
		"/*!50503 SET character_set_client = utf8mb4 */;\n" +
		"CREATE TABLE t (a int);\n" +
		"/*!40101 SET character_set_client = @saved_cs_client */;\n"
	rd, _ := readerFor(sql)
	if err := rd.run(); err != nil {
		t.Fatal(err)
	}
	if rd.cs.name != "latin1" || rd.lx.cs != csLatin1 {
		t.Fatalf("after the restore: %+v", rd.cs)
	}
	// restoring a set the reader doesn't decode brings its warning back
	sql = "SET sql_mode='';\nSET NAMES big5;\nSET @s = @@character_set_client;\nSET character_set_client = utf8mb4;\nINSERT INTO t VALUES (1);\nSET character_set_client = @s;\nINSERT INTO t VALUES (1);\n"
	v, st := readSQL(t, sql)
	if st.Read != 1 || st.Unread != 1 || v.unread[0].Line != 7 {
		t.Fatalf("read=%d unread=%+v", st.Read, v.unread)
	}
}

func TestCharsetSetNamesForms(t *testing.T) {
	for set, want := range map[string]string{
		"SET NAMES utf8mb4;":                       "utf8mb4",
		"SET NAMES 'latin1';":                      "latin1",
		"SET NAMES latin1 COLLATE latin1_bin;":     "latin1",
		"SET NAMES DEFAULT;":                       "utf8mb4",
		"SET CHARACTER SET latin1;":                "latin1",
		"SET CHARSET latin1;":                      "latin1",
		"SET character_set_client = latin1;":       "latin1",
		"SET @@character_set_client = latin1;":     "latin1",
		"SET SESSION character_set_client=BINARY;": "binary",
		"/*!40101 SET NAMES utf8 */;":              "utf8",
		"SET NAMES UTF8MB4, @a = 1;":               "utf8mb4",
	} {
		rd, _ := readerFor("SET sql_mode='';" + set)
		if err := rd.run(); err != nil {
			t.Fatal(err)
		}
		if rd.cs.name != want || rd.cs.unknown {
			t.Errorf("%s: set = %+v, want %s", set, rd.cs, want)
		}
	}
}

func TestCharsetMultiByteBackslash(t *testing.T) {
	// In sjis, 0x83 0x5C is one character whose second byte looks like a
	// backslash; it must not escape the quote after it.
	sql := "SET sql_mode='';\nSET NAMES sjis;\nINSERT INTO t VALUES ('\x83\x5c');\nDROP TABLE x;\n"
	_, st := readSQL(t, sql)
	if count(st, KindDrop) != 1 || st.Statements() != 4 {
		t.Fatalf("sjis: %v", st.ByKind)
	}
	sql = strings.Replace(sql, "sjis", "gbk", 1)
	_, st = readSQL(t, sql)
	if count(st, KindDrop) != 1 || st.Statements() != 4 {
		t.Fatalf("gbk: %v", st.ByKind)
	}
}

func TestCharsetList(t *testing.T) {
	for _, n := range []string{"utf8mb4", "utf8mb3", "utf8", "ascii", "latin1", "binary"} {
		if info, _, ok := lookupCharset(n); !ok || !info.decoded {
			t.Errorf("%s should be decoded", n)
		}
	}
	for _, n := range []string{"sjis", "cp1251", "utf16", "ucs2", "gb18030", "koi8r", "swe7", "eucjpms"} {
		if info, _, ok := lookupCharset(n); !ok || info.decoded {
			t.Errorf("%s should be listed and not decoded", n)
		}
	}
	for _, n := range []string{"", "utf-8", "latin", "nonesuch"} {
		if _, _, ok := lookupCharset(n); ok {
			t.Errorf("%q should not be listed", n)
		}
	}
}
