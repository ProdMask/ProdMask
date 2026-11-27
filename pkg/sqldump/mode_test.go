package sqldump

import (
	"strings"
	"testing"
)

// modeAfter reads the statements and returns the mode flags that hold at the end.
func modeAfter(t *testing.T, sql string) (noBackslash, ansi, known bool) {
	t.Helper()
	rd, _ := readerFor(sql)
	if err := rd.run(); err != nil {
		t.Fatal(err)
	}
	nb, aq := rd.mode.flags()
	return nb, aq, rd.mode.known
}

func TestSQLModeTracking(t *testing.T) {
	tests := []struct {
		name, sql string
		nb, ansi  bool
	}{
		{"nothing", "", false, false},
		{"literal", "SET sql_mode='NO_BACKSLASH_ESCAPES';", true, false},
		{"literal, lower case", "set sql_mode='no_backslash_escapes';", true, false},
		{"several modes", "SET sql_mode='STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES,ANSI_QUOTES';", true, true},
		{"with spaces", "SET sql_mode='STRICT_TRANS_TABLES, NO_BACKSLASH_ESCAPES';", true, false},
		{"session", "SET SESSION sql_mode='NO_BACKSLASH_ESCAPES';", true, false},
		{"local", "SET LOCAL sql_mode='NO_BACKSLASH_ESCAPES';", true, false},
		{"@@session", "SET @@SESSION.sql_mode='NO_BACKSLASH_ESCAPES';", true, false},
		{"@@sql_mode", "SET @@sql_mode='NO_BACKSLASH_ESCAPES';", true, false},
		{"colon equals", "SET sql_mode:='NO_BACKSLASH_ESCAPES';", true, false},
		{"in an executable comment", "/*!40101 SET sql_mode='NO_BACKSLASH_ESCAPES' */;", true, false},
		{"set to empty", "SET sql_mode='NO_BACKSLASH_ESCAPES'; SET sql_mode='';", false, false},
		{"after other assignments", "SET @a=1, sql_mode='NO_BACKSLASH_ESCAPES', @b=2;", true, false},
		{"ANSI", "SET sql_mode='ANSI';", false, true},
		{"DB2", "SET sql_mode='DB2';", false, true},
		{"MAXDB", "SET sql_mode='MAXDB';", false, true},
		{"MSSQL", "SET sql_mode='MSSQL';", false, true},
		{"ORACLE", "SET sql_mode='ORACLE';", false, true},
		{"POSTGRESQL", "SET sql_mode='POSTGRESQL';", false, true},
		{"TRADITIONAL is neither", "SET sql_mode='TRADITIONAL';", false, false},
		{"ANSI_QUOTES alone", "SET sql_mode='ANSI_QUOTES';", false, true},
		{"CONCAT adds", "SET sql_mode=''; SET SESSION sql_mode = CONCAT(@@sql_mode, ',NO_BACKSLASH_ESCAPES');", true, false},
		{"CONCAT adds to the start", "SET SESSION sql_mode = CONCAT(@@sql_mode, ',NO_BACKSLASH_ESCAPES');", true, false},
		{"CONCAT with a session name", "SET sql_mode = CONCAT(@@session.sql_mode, ',ANSI_QUOTES');", false, true},
		{"CONCAT of two literals", "SET sql_mode = CONCAT('NO_BACKSLASH_ESCAPES', ',ANSI_QUOTES');", true, true},
		{"REPLACE removes", "SET sql_mode='NO_BACKSLASH_ESCAPES,ANSI'; SET sql_mode=REPLACE(@@sql_mode,'NO_BACKSLASH_ESCAPES','');", false, true},
		{"REPLACE of a combination", "SET sql_mode='ANSI,NO_BACKSLASH_ESCAPES'; SET sql_mode=REPLACE(@@sql_mode,'ANSI','');", true, false},
		{"REPLACE inside CONCAT", "SET sql_mode='NO_BACKSLASH_ESCAPES'; SET sql_mode=CONCAT(REPLACE(@@sql_mode,'NO_BACKSLASH_ESCAPES',''), ',ANSI_QUOTES');", false, true},
		{"DEFAULT", "SET sql_mode='NO_BACKSLASH_ESCAPES,ANSI_QUOTES'; SET sql_mode=DEFAULT;", false, false},
		{"GLOBAL", "SET GLOBAL sql_mode='NO_BACKSLASH_ESCAPES,ANSI_QUOTES';", false, false},
		{"@@GLOBAL", "SET @@GLOBAL.sql_mode='NO_BACKSLASH_ESCAPES';", false, false},
		{"PERSIST", "SET PERSIST sql_mode='NO_BACKSLASH_ESCAPES';", false, false},
		{"saved and restored", "SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_BACKSLASH_ESCAPES'; SET SQL_MODE=@OLD_SQL_MODE;", false, false},
		{"saved with a lower-case name", "SET sql_mode='ANSI_QUOTES'; SET @saved_sql_mode = @@sql_mode; SET sql_mode='NO_BACKSLASH_ESCAPES'; SET sql_mode = @SAVED_SQL_MODE;", false, true},
		{"saved in an executable comment", "SET sql_mode='ANSI_QUOTES';\n/*!50003 SET @saved_sql_mode = @@sql_mode */ ;\n/*!50003 SET sql_mode = 'NO_BACKSLASH_ESCAPES' */ ;\n/*!50003 SET sql_mode = @saved_sql_mode */ ;", false, true},
		{"restored twice", "SET @s=@@sql_mode; SET sql_mode='NO_BACKSLASH_ESCAPES'; SET sql_mode=@s; SET sql_mode='ANSI_QUOTES'; SET sql_mode=@s;", false, false},
		{"parenthesised", "SET sql_mode=('NO_BACKSLASH_ESCAPES');", true, false},
		{"joined literals", "SET sql_mode='NO_BACKSLASH' '_ESCAPES';", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nb, ansi, known := modeAfter(t, tc.sql)
			if !known || nb != tc.nb || ansi != tc.ansi {
				t.Fatalf("known=%v noBackslash=%v ansiQuotes=%v, want known noBackslash=%v ansiQuotes=%v", known, nb, ansi, tc.nb, tc.ansi)
			}
		})
	}
	// MySQL skips every /*M! comment, so a mode set in one is unknown.
	if _, _, known := modeAfter(t, "/*M!100100 SET sql_mode='NO_BACKSLASH_ESCAPES' */;"); known {
		t.Error("a mode set in a MariaDB executable comment is known")
	}
}

// A mode's effect is seen in where the next statement ends.
func TestSQLModeChangesSplitting(t *testing.T) {
	nbProbe := `INSERT INTO t VALUES ('a\'); DROP TABLE z; -- ');` + "\n"
	ansiProbe := `INSERT INTO t VALUES ("a\"); DROP TABLE z; -- ");` + "\n"
	tests := []struct {
		name, set string
		nbDrops   int
		ansiDrops int
	}{
		{"default", "SET sql_mode='';", 0, 0},
		{"no backslash escapes", "SET sql_mode='NO_BACKSLASH_ESCAPES';", 1, 1},
		{"ansi", "SET sql_mode='ANSI';", 0, 1},
		{"concat", "SET sql_mode=CONCAT(@@sql_mode,',NO_BACKSLASH_ESCAPES,ANSI_QUOTES');", 1, 1},
		{"back to default", "SET sql_mode='ANSI,NO_BACKSLASH_ESCAPES'; SET sql_mode=DEFAULT;", 0, 0},
	}
	for _, tc := range tests {
		_, st := readSQL(t, tc.set+"\n"+nbProbe)
		if got := count(st, KindDrop); got != tc.nbDrops {
			t.Errorf("%s: no-backslash probe gave %d drops, want %d", tc.name, got, tc.nbDrops)
		}
		_, st = readSQL(t, tc.set+"\n"+ansiProbe)
		if got := count(st, KindDrop); got != tc.ansiDrops {
			t.Errorf("%s: ansi probe gave %d drops, want %d", tc.name, got, tc.ansiDrops)
		}
	}
}

func TestSQLModeAfterTrigger(t *testing.T) {
	// as mysqldump wraps a trigger: the trigger's mode, then the restore, then
	// an INSERT with \' that must be read under the restored mode
	sql := "SET sql_mode='';\n" +
		"DELIMITER ;;\n" +
		"/*!50003 SET @saved_sql_mode = @@sql_mode */ ;;\n" +
		"/*!50003 SET sql_mode = 'NO_BACKSLASH_ESCAPES' */ ;;\n" +
		"/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER t BEFORE INSERT ON x FOR EACH ROW BEGIN SET NEW.a = 'p\\'; END */;;\n" +
		"/*!50003 SET sql_mode = @saved_sql_mode */ ;;\n" +
		"DELIMITER ;\n" +
		"INSERT INTO x VALUES ('it\\'s; DROP TABLE y;');\n"
	_, st := readSQL(t, sql)
	if count(st, KindDrop) != 0 || count(st, KindInsert) != 1 || count(st, KindCreateTrigger) != 1 || st.Unread != 0 {
		t.Fatalf("after the trigger: %v unread=%d", st.ByKind, st.Unread)
	}
	// the same without the restore: the INSERT is read in the trigger's mode
	_, st = readSQL(t, strings.Replace(sql, "/*!50003 SET sql_mode = @saved_sql_mode */ ;;\n", "", 1))
	if count(st, KindDrop) != 1 {
		t.Fatalf("without the restore: %v", st.ByKind)
	}
}

func TestSQLModeUnknown(t *testing.T) {
	for _, assign := range []string{
		"SET sql_mode = 5;",
		"SET sql_mode = NOW();",
		"SET sql_mode = @never_set;",
		"SET sql_mode = NULL;",
		"SET sql_mode = CONCAT(@@sql_mode, @never_set);",
		"SET sql_mode = 'A' 'B' + 1;",
		"SET sql_mode = @@global.sql_mode;",
		"SET sql_mode;",
		"SET @@sql_mode = (SELECT 1);",
	} {
		t.Run(assign, func(t *testing.T) {
			sql := "SET sql_mode='';\nDROP TABLE a;\n" + assign + "\nINSERT INTO t VALUES (1);\nDROP TABLE b;\nUPDATE t SET a=1;\n"
			v, st := readSQL(t, sql)
			if st.Statements() != 3 || count(st, KindDrop) != 1 || count(st, KindInsert) != 0 {
				t.Fatalf("statements: %v", st.ByKind)
			}
			if st.Unread != 1 || len(v.unread) != 1 {
				t.Fatalf("unread = %+v", v.unread)
			}
			u := v.unread[0]
			if u.Reason != ReasonSQLMode || !u.ToEnd || u.Line != 3 || u.Kind != KindSet {
				t.Fatalf("entry = %+v", u)
			}
			if st.Bytes != int64(len(sql)) {
				t.Fatalf("bytes = %d, want %d", st.Bytes, len(sql))
			}
		})
	}
}

func TestSQLModeWarning(t *testing.T) {
	tests := []struct {
		name, sql string
		warns     bool
	}{
		{"never set", "INSERT INTO t VALUES (1);", true},
		{"set to a literal", "SET sql_mode='NO_AUTO_VALUE_ON_ZERO';INSERT INTO t VALUES (1);", false},
		{"set to an empty literal", "SET sql_mode='';INSERT INTO t VALUES (1);", false},
		{"only added to, as examples/shop.sql does", "SET SESSION sql_mode = CONCAT(@@sql_mode, ',NO_AUTO_VALUE_ON_ZERO');INSERT INTO t VALUES (1);", true},
		{"only DEFAULT", "SET sql_mode = DEFAULT;INSERT INTO t VALUES (1);", true},
		{"only GLOBAL", "SET GLOBAL sql_mode = 'ANSI';INSERT INTO t VALUES (1);", true},
		{"a literal inside an executable comment", "/*!40101 SET sql_mode='NO_AUTO_VALUE_ON_ZERO' */;INSERT INTO t VALUES (1);", false},
		{"no statements", "-- nothing\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := readSQL(t, tc.sql)
			if got := v.hasWarning(WarnNoSQLMode); got != tc.warns {
				t.Fatalf("warning = %v, want %v (%q)", got, tc.warns, v.warns)
			}
		})
	}
	if WarnNoSQLMode != "the dump doesn't set its SQL mode, so it was read as a server with default settings reads it" {
		t.Fatal("the fixed warning changed")
	}
}

// SET PASSWORD counts with the statements that create users.
func TestSetPasswordIsCountedWithUsers(t *testing.T) {
	v, _ := readSQL(t, "SET sql_mode='';SET PASSWORD FOR 'a'@'%' = 'x';\nCREATE USER 'b'@'%' IDENTIFIED BY 'y';")
	if !v.hasWarning("the dump creates 2 database users; an IDENTIFIED BY clause can hold a password") {
		t.Fatalf("warnings = %q", v.warns)
	}
	v, _ = readSQL(t, "SET sql_mode='';CREATE USER 'b'@'%' IDENTIFIED BY 'y';")
	if !v.hasWarning("the dump creates 1 database user; an IDENTIFIED BY clause can hold a password") {
		t.Fatalf("warnings = %q", v.warns)
	}
}
