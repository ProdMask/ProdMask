package sqldump

import (
	"slices"
	"testing"
)

// A version comment some supported server skips (every /*M!, a /*! of six
// digits, or of five from 50700) is read only where skipping it can't change
// what loads: as a whole SET or ANALYZE TABLE of a histogram, as a form MySQL
// writes in its place in CREATE TABLE or CREATE and ALTER DATABASE, or as
// literals after SET. The probes loaded rows on one server or both while the
// reader read every statement.
func TestUncertainVersionComments(t *testing.T) {
	for _, c := range []struct {
		name, sql string
		why       Reason
		toEnd     bool
		line      int
		rows      int64
	}{
		{"a string past the end", "/*!99999 SET @x=' */ " + clientRow + "; /*!99999 ' */;\n", ReasonVersion, true, 6, 1},
		{"a trigger's body", "DELIMITER $$\nCREATE TRIGGER tg BEFORE INSERT ON t FOR EACH ROW /*!99999 BEGIN */ SET @a=1; " +
			clientRow + " /*!99999 ; END */ $$\nDELIMITER ;\n", ReasonVersion, false, 7, 1},
		{"LOCK TABLES", "/*!99999 LOCK TABLES */ " + clientRow + ";\n", ReasonVersion, false, 6, 1},
		{"SET", "/*!99999 SET @a = */ " + clientRow + ";\n", ReasonVersion, true, 6, 1},
		{"CREATE DATABASE", "/*!99999 CREATE DATABASE IF NOT EXISTS x */ " + clientRow + ";\n", ReasonVersion, true, 6, 1},
		{"a whole CREATE DATABASE", "/*!99999 CREATE DATABASE zzx */;\n" + clientRow + ";\n", ReasonVersion, true, 6, 1},
		{"a database option", "CREATE DATABASE e /*!80016 CHARACTER SET latin1 */;\n" + clientRow + ";\n", ReasonVersion, true, 6, 1},
		{"MariaDB's", "/*M!100100 LOCK TABLES */ " + clientRow + ";\n", ReasonVersion, false, 6, 1},
		{"50701", "/*!50701 LOCK TABLES */ " + clientRow + ";\n", ReasonVersion, false, 6, 1},
		{"a line comment", "/*!99999 -- */ " + clientRow + ";\n*/;\n", ReasonVersion, false, 6, 1},
		{"a nested block comment", "/*!99999 SET @a = /* x */ 1 */;\n", ReasonVersion, true, 6, 1},
		{"a string holding the end", "SET @@GLOBAL.GTID_PURGED=/*!80000 '*/' */ 'x';\n", ReasonVersion, true, 6, 1},
		{"a quoted identifier holding the end", "CREATE TABLE u (a int /*!80023 , `b*/c` int */);\n", ReasonVersion, false, 6, 1},
		{"unbalanced parentheses", "CREATE TABLE u (a int /*!80023 ) */, b int);\n", ReasonVersion, false, 6, 1},
		{"a semicolon", "DELIMITER ;;\nCREATE TABLE u (a int) /*!80023 ; */;;\nDELIMITER ;\n", ReasonVersion, false, 7, 1},
		{"cut by the delimiter", "/*!99999 SET @a = 1;\n", ReasonVersion, true, 6, 1},
		{"before the object word", "CREATE /*!99999 TEMPORARY */ TABLE u (a int);\n", ReasonVersion, false, 6, 1},
		{"inside a view", "CREATE /*!80000 OR REPLACE */ VIEW v AS SELECT 1;\n", ReasonVersion, false, 6, 1},
		{"inside an INSERT", "INSERT INTO t VALUES (1, /*!80000 'a' */ 'b');\n", ReasonVersion, false, 6, 1},
		{"six digits, whole", "/*!100100 DROP TABLE IF EXISTS x */;\n" + clientRow + ";\n", ReasonVersion, false, 6, 2},
		{"MariaDB's, whole", "/*M!100100 DROP TABLE IF EXISTS x */ ;\n" + clientRow + ";\n", ReasonVersion, false, 6, 2},
		{"inside a program's header", "DELIMITER ;;\nCREATE PROCEDURE p() /*!80000 DETERMINISTIC */ SELECT 1;;\nDELIMITER ;\n", ReasonVersion, false, 7, 1},
		// What a server that skips the comment wouldn't share: the database
		// and the SQL mode leave the rest of the file unread.
		{"USE", "/*!99999 USE other */;\n" + clientRow + ";\n", ReasonVersion, true, 6, 1},
		{"inside USE", "USE /*!99999 other */;\n" + clientRow + ";\n", ReasonVersion, true, 6, 1},
		{"the SQL mode", "/*!80000 SET sql_mode='NO_BACKSLASH_ESCAPES' */;\n" + clientRow + ";\n", ReasonSQLMode, true, 6, 1},
		{"the SQL mode inside SET", "SET @@SESSION.sql_mode = /*!80000 'ANSI_QUOTES' */ '';\n" + clientRow + ";\n", ReasonSQLMode, true, 6, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			u, st := readOneUnread(t, c.sql, c.why, c.toEnd)
			if u.Line != c.line || st.Rows != c.rows {
				t.Fatalf("line %d, %d rows; want line %d, %d rows", u.Line, st.Rows, c.line, c.rows)
			}
		})
	}
	// A character set or a user variable a skipping server wouldn't share is
	// unknown: the row statements under it are unread.
	for name, sql := range map[string]string{
		"SET NAMES":       "/*!80000 SET NAMES latin1 */;\n" + clientRow + ";\n",
		"a user variable": "/*M!100100 SET @saved_cs_client = 'latin1' */;\nSET character_set_client = @saved_cs_client;\n" + clientRow + ";\n",
	} {
		t.Run(name, func(t *testing.T) {
			v, st := readSQL(t, clientHead+sql)
			if st.Unread != 1 || len(v.unread) != 1 || v.unread[0].Reason != ReasonCharset || st.Rows != 1 || !v.hasWarning(WarnUnknownCharset) {
				t.Fatalf("unread %+v, %d rows, warnings %q", v.unread, st.Rows, v.warns)
			}
		})
	}
	// What the dump tools write, and what reads the same either way, stays
	// read, and so does the rest of the file.
	for name, sql := range map[string]string{
		"INVISIBLE":           "CREATE TABLE u (`id` int NOT NULL, `a` int DEFAULT NULL /*!80023 INVISIBLE */, PRIMARY KEY (`id`));\n",
		"INVISIBLE, ANSI":     "SET sql_mode='ANSI_QUOTES';\nCREATE TABLE u (\"id\" int NOT NULL, \"a\" int DEFAULT NULL /*!80023 INVISIBLE */, PRIMARY KEY (\"id\"));\n",
		"NOTE_VERBOSITY":      "/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;\n/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;\n",
		"CREATE DATABASE":     "CREATE DATABASE /*!32312 IF NOT EXISTS*/ `e` /*!40100 DEFAULT CHARACTER SET utf8mb4 */ /*!80016 DEFAULT ENCRYPTION='N' */;\nUSE `d`;\n",
		"ALTER DATABASE":      "ALTER DATABASE `d` /*!80016 DEFAULT ENCRYPTION='N' */;\n",
		"GTID_PURGED":         "SET @@GLOBAL.GTID_PURGED=/*!80000 '+'*/ 'uuid:1-5';\n",
		"a histogram":         "/*!80002 ANALYZE TABLE `t` UPDATE HISTOGRAM ON `email` WITH 4 BUCKETS */;\n",
		"certain, inside":     "INSERT /*!40000 IGNORE */ INTO t VALUES (2,'b@example.test');\n",
		"no version, inside":  "LOCK TABLES /*! t WRITE */;\n",
		"an empty one, alone": "/*!99999 */;\n",
	} {
		t.Run(name, func(t *testing.T) {
			v, st := readSQL(t, clientHead+sql+clientRow+";\n")
			if st.Unread != 0 || st.Rows < 2 {
				t.Fatalf("unread %+v, %d rows", v.unread, st.Rows)
			}
		})
	}
}

// Several statements before the delimiter, where one after a semicolon is a
// SET, a USE or a DELIMITER, leave the rest of the file unread: the server
// may have changed what the reader follows.
func TestSeveralStatementsThatChangeState(t *testing.T) {
	const after = "INSERT INTO t VALUES (3,'c@example.test');\n"
	for _, c := range []struct {
		name, sql string
		rows      int64
	}{
		{"SET NAMES", "DELIMITER ;;\n" + clientRow + "; SET NAMES latin1;;\nDELIMITER ;\n", 2},
		{"USE", "DELIMITER ;;\n" + clientRow + "; USE x;;\nDELIMITER ;\n", 2},
		{"DELIMITER", "DELIMITER ;;\n" + clientRow + "; DELIMITER $$;;\nDELIMITER ;\n", 2},
		{"SET after another statement", "DELIMITER ;;\n" + clientRow + "; INSERT INTO t VALUES (2,'b@example.test'); ; SET @a = 1;;\nDELIMITER ;\n", 2},
		{"SET after a program's body", "DELIMITER ;;\nCREATE PROCEDURE p() BEGIN SELECT 1; END; SET sql_mode='ANSI_QUOTES';;\nDELIMITER ;\n", 1},
		{"SET later after a body", "DELIMITER ;;\nCREATE PROCEDURE p() BEGIN SELECT 1; END; " + clientRow + "; SET @a = 1;;\nDELIMITER ;\n", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			u, st := readOneUnread(t, c.sql+after, ReasonSeveral, true)
			if u.Line != 7 || st.Rows != c.rows {
				t.Fatalf("line %d, %d rows; want line 7, %d rows", u.Line, st.Rows, c.rows)
			}
		})
	}
	// Without one, only the statement is unread.
	u, st := readOneUnread(t, "DELIMITER ;;\n"+clientRow+"; INSERT INTO t VALUES (2,'b@example.test');;\nDELIMITER ;\n"+after, ReasonSeveral, false)
	if u.Line != 7 || st.Rows != 3 {
		t.Fatalf("line %d, %d rows", u.Line, st.Rows)
	}
}

// DELIMITER inside an executable comment is no command: the clients don't
// run it there, so its words are tokens and the delimiter stays ;.
func TestDelimiterInsideComments(t *testing.T) {
	const commit = "CREATE TABLE `commit` (id int NOT NULL, note varchar(100));\n"
	for _, c := range []struct {
		name, sql string
		why       Reason
		rows      int64
	}{
		{"in an uncertain comment", "/*!99999 DELIMITER INSERT\n */ INSERT commit VALUES (2,'a@example.test') ; INSERT commit VALUES (3,'b@example.test') ; INSERT", ReasonVersion, 2},
		{"in MariaDB's comment", "/*M!100100 DELIMITER INSERT\n */ INSERT commit VALUES (2,'a@example.test') ; INSERT", ReasonVersion, 1},
		{"in a certain comment", "/*!40000 DELIMITER INSERT\n */ INSERT commit VALUES (2,'a@example.test') ; INSERT", ReasonKind, 1},
		{"in a comment with no version", "/*! DELIMITER INSERT\n */ INSERT commit VALUES (2,'a@example.test') ; INSERT", ReasonKind, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, st := readSQL(t, clientHead+commit+c.sql)
			if len(v.unread) == 0 || v.unread[0].Reason != c.why || v.unread[0].Line != 7 || st.Rows != c.rows {
				t.Fatalf("unread %+v, %d rows", v.unread, st.Rows)
			}
			for _, u := range v.unread {
				if u.Table != "" || u.Database != "" {
					t.Fatalf("an entry names a table: %+v", u)
				}
			}
		})
	}
}

// Inside CREATE TABLE an uncertain comment may hold only a form MySQL's SHOW
// CREATE TABLE writes in one, in its place: skipping it can't change a
// column's type, count or order.
func TestCreateTableVersionForms(t *testing.T) {
	// mysqldump 8.4's own table with every form.
	read := map[string]string{
		"every form": "CREATE TABLE `f` (\n  `id` int NOT NULL,\n  `a` int DEFAULT '5' /*!80023 INVISIBLE */ COMMENT 'c',\n" +
			"  `g` point NOT NULL /*!80003 SRID 4326 */,\n  `g2` geometry /*!80003 SRID 0 */ DEFAULT NULL /*!80023 INVISIBLE */ COMMENT 'x',\n" +
			"  `b` varchar(10) CHARACTER SET latin1 COLLATE latin1_bin DEFAULT 'x' /*!80023 INVISIBLE */,\n" +
			"  `v` int GENERATED ALWAYS AS ((`id` + 1)) VIRTUAL /*!80023 INVISIBLE */,\n  PRIMARY KEY (`id`),\n" +
			"  KEY `k` (`a`) /*!80000 INVISIBLE */,\n  KEY `k2` (`b`) COMMENT 'kc' /*!80000 INVISIBLE */,\n  SPATIAL KEY `sk` (`g`),\n" +
			"  CONSTRAINT `ck` CHECK ((`id` > 0)) /*!80016 NOT ENFORCED */,\n  CONSTRAINT `ck2` CHECK ((`a` < 100))\n" +
			") /*!80023 AUTOEXTEND_SIZE=4194304 */ ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;\n",
		"a bare CHECK":        "CREATE TABLE u (a int, CHECK (a > 0) /*!80016 NOT ENFORCED */);\n",
		"a size":              "CREATE TABLE u (a int) /*!80023 AUTOEXTEND_SIZE 4M */;\n",
		"table encryption":    "CREATE TABLE u (a int) ENGINE=InnoDB /*!80016 DEFAULT ENCRYPTION='N' */;\n",
		"under ANSI quotes":   "SET sql_mode='ANSI_QUOTES';\nCREATE TABLE \"u\" (\"a\" int /*!80023 INVISIBLE */, KEY \"k\" (\"a\") /*!80000 INVISIBLE */);\n",
		"database encryption": "ALTER DATABASE `d` /*!80016 ENCRYPTION = 'N' */;\n",
	}
	for name, sql := range read {
		t.Run(name, func(t *testing.T) {
			if v, st := readSQL(t, clientHead+sql+clientRow+";\n"); st.Unread != 0 || st.Rows != 2 {
				t.Fatalf("unread %+v, %d rows", v.unread, st.Rows)
			}
		})
	}
	for name, sql := range map[string]string{
		"a type swapped":                 "CREATE TABLE people (id int NOT NULL, email /*!99999 blob, zz */ varchar(100), PRIMARY KEY (id));\n",
		"a collation swapped":            "CREATE TABLE people (id int NOT NULL, email /*!99999 blob COLLATE */ text, PRIMARY KEY (id));\n",
		"INVISIBLE before the type":      "CREATE TABLE u (a /*!80023 INVISIBLE */ int);\n",
		"an unlisted word":               "CREATE TABLE u (a int /*!80023 VISIBLE */);\n",
		"a listed word and another":      "CREATE TABLE u (a int /*!80023 INVISIBLE NOT NULL */);\n",
		"SRID on a column not spatial":   "CREATE TABLE u (a int /*!80003 SRID 4326 */);\n",
		"INVISIBLE among the options":    "CREATE TABLE u (a int) /*!80023 INVISIBLE */;\n",
		"NOT ENFORCED on a column":       "CREATE TABLE u (a int /*!80016 NOT ENFORCED */);\n",
		"another table option":           "CREATE TABLE u (a int) /*!80000 ENGINE=MEMORY */;\n",
		"a key's name":                   "CREATE TABLE u (a int, KEY /*!80000 k */ (a));\n",
		"INVISIBLE before a key's parts": "CREATE TABLE u (a int, KEY k /*!80000 INVISIBLE */ (a));\n",
	} {
		t.Run(name, func(t *testing.T) {
			if u, _ := readOneUnread(t, sql, ReasonVersion, false); u.Line != 6 || u.Kind != KindCreateTable {
				t.Fatalf("unread %+v", u)
			}
		})
	}
}

// In a SET, an uncertain comment that isn't the whole statement may hold
// only string and number literals; anything else may have changed the
// server's SQL mode or character set, so the rest of the file is unread.
func TestSetVersionComments(t *testing.T) {
	for name, sql := range map[string]string{
		"the mode hidden":           "SET /*!99999 @x = */ sql_mode = 'NO_BACKSLASH_ESCAPES';\n",
		"the character set":         "SET /*!99999 @x = */ character_set_client = gbk;\n",
		"SET NAMES swapped":         "SET NAMES /*!99999 utf8mb4 COLLATE */ gbk;\n",
		"a variable among literals": "SET @a = /*!80000 'x', @b = */ 'y';\n",
	} {
		t.Run(name, func(t *testing.T) {
			if u, st := readOneUnread(t, sql+clientRow+";\n", ReasonVersion, true); u.Line != 6 || st.Rows != 1 {
				t.Fatalf("line %d, %d rows", u.Line, st.Rows)
			}
		})
	}
	// Literals only: a user variable it assigns is unknown, nothing more.
	if v, st := readSQL(t, clientHead+"SET @a = /*!80000 1 */ 2;\n"+clientRow+";\n"); st.Unread != 0 || st.Rows != 2 {
		t.Fatalf("literals: unread %+v, %d rows", v.unread, st.Rows)
	}
}

// A USE, CREATE DATABASE or ALTER DATABASE the version rule leaves unread
// switches no database: a server that skips the comment never switched.
func TestVersionUnreadSwitchesNoDatabase(t *testing.T) {
	for name, sql := range map[string]string{
		"a whole CREATE DATABASE": "/*!99999 CREATE DATABASE zz */;\n",
		"USE":                     "/*!99999 USE zz */;\n",
		"MariaDB's":               "/*M!100100 CREATE DATABASE zz */;\n",
		"inside":                  "CREATE DATABASE /*!99999 zz */;\n",
		"ALTER DATABASE":          "ALTER DATABASE /*!99999 zz */ CHARACTER SET latin1;\n",
	} {
		t.Run(name, func(t *testing.T) {
			v, st := readSQL(t, clientHead+sql)
			if st.Unread != 1 || len(v.dbs) != 1 || v.dbs[0] != "d" {
				t.Fatalf("unread %d, databases %q", st.Unread, v.dbs)
			}
		})
	}
	// A plain one names its database, once; only USE switches.
	if v, _ := readSQL(t, clientHead+"CREATE DATABASE e;\nUSE d;\nALTER DATABASE f CHARACTER SET latin1;\n"); !slices.Equal(v.dbs, []string{"d", "e", "f"}) {
		t.Fatalf("databases %q", v.dbs)
	}
}
