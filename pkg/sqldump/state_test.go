package sqldump

import (
	"slices"
	"strings"
	"testing"
)

// reasons lists the reasons of the unread entries, in order.
func reasons(v *rrec) []Reason {
	var out []Reason
	for _, u := range v.unread {
		out = append(out, u.Reason)
	}
	return out
}

const peopleBlob = "CREATE TABLE IF NOT EXISTS people (id int NOT NULL, email blob, PRIMARY KEY (id));\n"

// A DROP removes only what it would on the server: DROP TABLE a table, DROP
// VIEW a view. A temporary table is unread. So the CREATE after a DROP that
// removed nothing keeps the first structure, or the rows are unread.
func TestDropRemovesOnlyItsKind(t *testing.T) {
	const view = "SET sql_mode='';\nCREATE TABLE base (id int NOT NULL, email varchar(100), PRIMARY KEY (id));\n" +
		"CREATE VIEW people AS SELECT id AS id, email AS email FROM base;\n"
	for name, c := range map[string]struct {
		sql   string
		why   []Reason
		types []string
	}{
		"DROP TABLE on a view": {view + "DROP TABLE IF EXISTS people;\n" + peopleBlob + peopleRows, []Reason{ReasonRecreate, ReasonInsertForm}, nil},
		"DROP VIEW on a table": {peopleTable + "DROP VIEW IF EXISTS people;\n" + peopleBlob + peopleRows, []Reason{ReasonRecreate}, []string{"varchar", "varchar"}},
		"DROP TEMPORARY":       {peopleTable + "DROP TEMPORARY TABLE IF EXISTS people;\n" + peopleBlob + peopleRows, []Reason{ReasonKind, ReasonRecreate}, []string{"varchar", "varchar"}},
		"CREATE TEMPORARY": {peopleTable + "CREATE TEMPORARY TABLE people (id int NOT NULL, email varchar(100), PRIMARY KEY (id));\n" +
			"DROP TABLE people;\n" + peopleBlob + peopleRows, []Reason{ReasonKind}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			v, _ := readRowsOpts(t, c.sql, testOpts())
			if !slices.Equal(reasons(v), c.why) || (c.types != nil && !slices.Equal(emailTypes(v), c.types)) {
				t.Fatalf("unread %+v, rows %q", v.unread, emailTypes(v))
			}
			for _, u := range v.unread {
				if u.Reason != ReasonRecreate && u.Table != "" {
					t.Fatalf("names a table: %+v", u)
				}
			}
		})
	}
	// The tools' view sequences drop what they created and stay read.
	for name, sql := range map[string]string{
		"mysqldump 8.4": "DROP TABLE IF EXISTS v;\n/*!50001 DROP VIEW IF EXISTS v*/;\n/*!50001 CREATE VIEW v AS SELECT 1 AS id, 1 AS email*/;\n" +
			"/*!50001 DROP VIEW IF EXISTS v*/;\n/*!50001 CREATE ALGORITHM=UNDEFINED */ /*!50001 VIEW v AS select id, email from people */;\n",
		"old mysqldump": "DROP TABLE IF EXISTS `v`;\n/*!50001 DROP VIEW IF EXISTS `v`*/;\n/*!50001 CREATE TABLE `v` (`id` int, `email` varchar(100)) ENGINE=MyISAM */;\n" +
			"/*!50001 DROP TABLE IF EXISTS `v`*/;\n/*!50001 DROP VIEW IF EXISTS `v`*/;\n/*!50001 CREATE ALGORITHM=UNDEFINED */ /*!50001 VIEW `v` AS select `id`, `email` from `people` */;\n",
		"phpMyAdmin": "CREATE TABLE `v` (`id` int, `email` varchar(100));\nDROP TABLE IF EXISTS `v`;\n" +
			"CREATE ALGORITHM=UNDEFINED SQL SECURITY DEFINER VIEW `v` AS SELECT `id` AS `id`, `email` AS `email` FROM `people`;\n",
	} {
		t.Run(name, func(t *testing.T) {
			if v, st := readRowsOpts(t, peopleTable+sql+peopleRows, testOpts()); st.Unread != 0 || v.last("v").Type != "VIEW" {
				t.Fatalf("unread %+v", v.unread)
			}
		})
	}
}

// An INSERT or REPLACE into a view the reader holds is unread, naming no
// table: its rows go into a table behind the view.
func TestInsertIntoAView(t *testing.T) {
	for name, verb := range map[string]string{"insert": "INSERT", "replace": "REPLACE"} {
		v, st := readRowsOpts(t, "SET sql_mode='';\nCREATE TABLE base (id int NOT NULL, email varchar(100), PRIMARY KEY (id));\n"+
			"CREATE VIEW people AS SELECT id AS id, email AS email FROM base;\n"+verb+" INTO people VALUES (1,'a@example.test');\n", testOpts())
		if st.Unread != 1 || v.unread[0].Reason != ReasonInsertForm || v.unread[0].Table != "" || len(v.rows) != 0 {
			t.Fatalf("%s: unread %+v, %d rows", name, v.unread, len(v.rows))
		}
	}
}

// A name that differs from a held one only by letter case is the same table
// on a server that folds case: a CREATE of it is created again, kept by the first, and a
// DROP of it drops nothing, as on a server that doesn't.
func TestNamesThatDifferByCase(t *testing.T) {
	for name, c := range map[string]struct {
		sql   string
		why   []Reason
		types []string
	}{
		"other columns": {peopleTable + "CREATE TABLE IF NOT EXISTS People (id int NOT NULL, email blob, PRIMARY KEY (id));\n" + peopleRows,
			[]Reason{ReasonRecreate}, []string{"varchar", "varchar"}},
		"the same columns": {peopleTable + "CREATE TABLE People (id int NOT NULL, email varchar(100), PRIMARY KEY (id));\n" + peopleRows,
			nil, []string{"varchar", "varchar"}},
		"OR REPLACE": {peopleTable + "CREATE OR REPLACE TABLE PEOPLE (id int NOT NULL, email blob, PRIMARY KEY (id));\n" + peopleRows,
			[]Reason{ReasonRecreate}, []string{"varchar", "varchar"}},
		"a view": {peopleTable + "CREATE OR REPLACE VIEW People AS SELECT 1 AS id, 2 AS email;\n" + peopleRows,
			[]Reason{ReasonRecreate}, []string{"varchar", "varchar"}},
		"a DROP by another case": {peopleTable + "DROP TABLE IF EXISTS `People`;\n" + peopleBlob + peopleRows,
			[]Reason{ReasonRecreate}, []string{"varchar", "varchar"}},
		"one spelling, as the tools write": {peopleTable + "DROP TABLE IF EXISTS people;\n" + peopleBlob + peopleRows,
			nil, []string{"blob", "blob"}},
	} {
		t.Run(name, func(t *testing.T) {
			v, _ := readRowsOpts(t, c.sql, testOpts())
			if !slices.Equal(reasons(v), c.why) || !slices.Equal(emailTypes(v), c.types) {
				t.Fatalf("unread %+v, rows %q", v.unread, emailTypes(v))
			}
		})
	}
}

// Only USE switches the current database: CREATE and ALTER DATABASE name
// theirs for the report and leave it.
func TestOnlyUseSwitches(t *testing.T) {
	for name, stmt := range map[string]string{
		"CREATE DATABASE": "CREATE DATABASE IF NOT EXISTS other;\n",
		"ALTER DATABASE":  "ALTER DATABASE other CHARACTER SET latin1;\n",
	} {
		t.Run(name, func(t *testing.T) {
			v, _ := readRowsOpts(t, "SET sql_mode='';\nCREATE DATABASE IF NOT EXISTS shop;\nUSE shop;\n"+stmt+
				"CREATE TABLE people (id int NOT NULL, email varchar(100), PRIMARY KEY (id));\n"+peopleRows, testOpts())
			if len(v.calls) != 1 || v.calls[0].db != "shop" || len(v.rows) != 2 || v.rows[0].DB != "shop" ||
				!slices.Equal(v.dbs, []string{"shop", "other"}) {
				t.Fatalf("calls %+v, databases %q", v.calls, v.dbs)
			}
		})
	}
}

// A DELIMITER argument the clients reject or read their own way leaves the
// rest of the file unread, as their own command; one they read as the reader
// does is read.
func TestDelimiterArguments(t *testing.T) {
	a15 := strings.Repeat("A", 15)
	for name, line := range map[string]string{
		"17 bytes":                "DELIMITER " + a15 + "AB\n",
		"16 bytes (they keep 15)": "DELIMITER " + a15 + "A\n",
		"quoted with a space":     "DELIMITER \"x y\"\n",
		"a backslash":             "DELIMITER $\\$\n",
		"a tab in the word":       "DELIMITER $$\tzz yy\n",
		"text after the quote":    "DELIMITER \"$$\"zz\n",
		"a doubled quote":         "DELIMITER 'a''b'\n",
		"an unclosed quote":       "DELIMITER '$$\n",
	} {
		t.Run(name, func(t *testing.T) {
			if u, st := readOneUnread(t, line+clientRow+"$$\nDELIMITER ;\n", ReasonClient, true); u.Line != 6 || st.Rows != 1 {
				t.Fatalf("line %d, %d rows", u.Line, st.Rows)
			}
		})
	}
	for name, c := range map[string]struct{ line, delim string }{
		"15 bytes":            {"DELIMITER " + a15, a15},
		"two words":           {"DELIMITER $$ zz", "$$"},
		"quoted, then a word": {"DELIMITER \"$$\" zz", "$$"},
		"quoted":              {"DELIMITER '$$'", "$$"},
		"CR LF":               {"DELIMITER $$\r", "$$"},
	} {
		t.Run(name, func(t *testing.T) {
			v, st := readSQL(t, clientHead+c.line+"\n"+clientRow+c.delim+"\nDELIMITER ;\nINSERT INTO t VALUES (3,'c@example.test');\n")
			if st.Unread != 0 || st.Rows != 3 {
				t.Fatalf("unread %+v, %d rows", v.unread, st.Rows)
			}
		})
	}
}

// A := or a function call in a SET's value, or an INSERT into a table with a
// trigger, may set any user variable: none is known after it, so a mode or a
// character set taken from one is unknown.
func TestVariablesSetBehindTheReader(t *testing.T) {
	const mode = "SET sql_mode = @m;\n" + clientRow + ";\n"
	for name, sql := range map[string]string{
		":=":               "SET @m = '';\nSET @x = (@m := 'NO_BACKSLASH_ESCAPES');\n" + mode,
		":= with no space": "SET @m = '';\nSET @x = (@m:='NO_BACKSLASH_ESCAPES');\n" + mode,
		"a function":       "SET @m = '';\nSET @x = f(1);\n" + mode,
		"a qualified one":  "SET @m = '';\nSET @x = db.concat('a');\n" + mode,
		"a system target":  "SET @m = '';\nSET @@session.time_zone = f();\n" + mode,
		"a trigger": "SET @m = '';\nCREATE TABLE tg (id int NOT NULL);\n" +
			"CREATE TRIGGER t1 BEFORE INSERT ON tg FOR EACH ROW SET @m = 'NO_BACKSLASH_ESCAPES';\nINSERT INTO tg VALUES (1);\n" + mode,
		"a trigger, other case": "SET @m = '';\nCREATE TABLE tg (id int NOT NULL);\n" +
			"CREATE TRIGGER t1 BEFORE INSERT ON `d`.`TG` FOR EACH ROW SET @m = 'NO_BACKSLASH_ESCAPES';\nREPLACE INTO tg VALUES (1);\n" + mode,
	} {
		t.Run(name, func(t *testing.T) {
			v, _ := readSQL(t, clientHead+sql)
			if n := len(v.unread); n == 0 || v.unread[n-1].Reason != ReasonSQLMode || !v.unread[n-1].ToEnd {
				t.Fatalf("unread %+v", v.unread)
			}
		})
	}
	// A character set from such a variable is unknown too.
	v, st := readSQL(t, clientHead+"SET @c = 'utf8mb4';\nSET @x = f();\nSET character_set_client = @c;\n"+clientRow+";\n")
	if st.Unread != 1 || v.unread[0].Reason != ReasonCharset {
		t.Fatalf("charset: unread %+v", v.unread)
	}
	// What the tools write keeps its variables: system variables, CONCAT and
	// REPLACE set nothing, and the rows of a table come before its triggers.
	for name, sql := range map[string]string{
		"mysqldump's header and footer": "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n" +
			"/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;\n/*!50503 SET NAMES utf8mb4 */;\n" +
			"/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;\n/*!40103 SET TIME_ZONE='+00:00' */;\n" +
			"/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;\n/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;\n" +
			"SET @MYSQLDUMP_TEMP_LOG_BIN = @@SESSION.SQL_LOG_BIN;\nSET @@SESSION.SQL_LOG_BIN= 0;\n" + clientRow + ";\n" +
			"SET @@SESSION.SQL_LOG_BIN = @MYSQLDUMP_TEMP_LOG_BIN;\n/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;\n/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\n" +
			"/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;\n",
		"CONCAT and REPLACE": "SET @m = 'ANSI_QUOTES';\nSET @x = CONCAT(@m, REPLACE('a', 'a', 'b'));\nSET sql_mode = @m;\n",
		"rows before the trigger": "SET @m = '';\nCREATE TABLE tg (id int NOT NULL);\nINSERT INTO tg VALUES (1);\n" +
			"CREATE TRIGGER t1 BEFORE INSERT ON tg FOR EACH ROW SET @m = 'x';\nSET sql_mode = @m;\n",
		"a trigger on another table": "SET @m = '';\nCREATE TABLE tg (id int NOT NULL);\n" +
			"CREATE TRIGGER t1 BEFORE INSERT ON tg FOR EACH ROW SET @m = 'x';\n" + clientRow + ";\nSET sql_mode = @m;\n",
	} {
		t.Run(name, func(t *testing.T) {
			if v, st := readSQL(t, clientHead+sql); st.Unread != 0 || v.hasWarning(WarnUnknownCharset) {
				t.Fatalf("unread %+v, warnings %q", v.unread, v.warns)
			}
		})
	}
}
