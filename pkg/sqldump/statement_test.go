package sqldump

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestStatementKinds(t *testing.T) {
	long := strings.Repeat("a", 300)
	tests := []struct {
		sql   string
		kind  Kind
		class Class
		why   Reason
	}{
		{"INSERT INTO t VALUES (1);", KindInsert, ClassRead, ""},
		{"INSERT t VALUES (1);", KindInsert, ClassRead, ""},
		{"INSERT INTO t (a, b) VALUES (1, 2), (3, 4);", KindInsert, ClassRead, ""},
		{"INSERT INTO db.t VALUE (1);", KindInsert, ClassRead, ""},
		{"INSERT INTO t PARTITION (p0) (a) VALUES (1);", KindInsert, ClassRead, ""},
		{"INSERT /*!40000 IGNORE */ INTO t VALUES (1);", KindInsertIgnore, ClassRead, ""},
		{"INSERT IGNORE INTO t VALUES (1);", KindInsertIgnore, ClassRead, ""},
		{"INSERT LOW_PRIORITY IGNORE t VALUES (1);", KindInsertIgnore, ClassRead, ""},
		{"INSERT HIGH_PRIORITY INTO t VALUES (1);", KindInsert, ClassRead, ""},
		{"REPLACE INTO t VALUES (1);", KindReplace, ClassRead, ""},
		{"REPLACE DELAYED t VALUES (1);", KindReplace, ClassRead, ""},
		{"INSERT INTO t VALUES (1) ON DUPLICATE KEY UPDATE a = 2;", KindInsert, ClassUnread, ReasonInsertForm},
		{"INSERT INTO t SELECT * FROM s;", KindInsert, ClassUnread, ReasonInsertForm},
		{"INSERT INTO t (SELECT * FROM s);", KindInsert, ClassUnread, ReasonInsertForm},
		{"INSERT INTO t SET a = 1;", KindInsert, ClassUnread, ReasonInsertForm},
		{"INSERT INTO t TABLE s;", KindInsert, ClassUnread, ReasonInsertForm},
		{"REPLACE INTO t SET a = 1;", KindReplace, ClassUnread, ReasonInsertForm},
		{"CREATE TABLE t (a int);", KindCreateTable, ClassStructure, ""},
		{"CREATE TABLE IF NOT EXISTS `db`.`t` (a int) ENGINE=InnoDB;", KindCreateTable, ClassStructure, ""},
		{"CREATE TEMPORARY TABLE t (a int);", KindCreateTable, ClassUnread, ReasonKind},
		{"CREATE TABLE t LIKE s;", KindCreateTable, ClassUnread, ReasonKind},
		{"CREATE TABLE t (LIKE s);", KindCreateTable, ClassUnread, ReasonKind},
		{"CREATE TABLE t AS SELECT 1;", KindCreateTable, ClassUnread, ReasonKind},
		{"CREATE TABLE t (a int) SELECT 1;", KindCreateTable, ClassUnread, ReasonInsertForm},
		{"ALTER TABLE t ADD KEY (a);", KindAlterTable, ClassUnread, ReasonAlter},
		{"ALTER TABLE t DISABLE KEYS;", KindAlterTable, ClassStructure, ""},
		{"CREATE INDEX i ON t (a);", KindCreateIndex, ClassUnread, ReasonAlter},
		{"CREATE UNIQUE INDEX i ON t (a);", KindCreateIndex, ClassUnread, ReasonAlter},
		{"CREATE VIEW v AS SELECT 1;", KindCreateView, ClassKnown, ""},
		{"CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW v AS select 1;", KindCreateView, ClassKnown, ""},
		{"CREATE OR REPLACE DEFINER=root@localhost VIEW v AS select 1;", KindCreateView, ClassKnown, ""},
		{"CREATE DEFINER='root'@'%' TRIGGER x BEFORE INSERT ON t FOR EACH ROW SET NEW.a = ';';", KindCreateTrigger, ClassKnown, ""},
		{"CREATE DEFINER=CURRENT_USER() PROCEDURE p() SELECT 1;", KindCreateProcedure, ClassKnown, ""},
		{"CREATE FUNCTION f() RETURNS int RETURN 1;", KindCreateFunction, ClassKnown, ""},
		{"CREATE AGGREGATE FUNCTION f RETURNS int SONAME 'x.so';", KindCreateFunction, ClassKnown, ""},
		{"CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO SELECT 1;", KindCreateEvent, ClassKnown, ""},
		{"CREATE SEQUENCE s START WITH 1;", KindCreateSequence, ClassKnown, ""},
		{"SELECT SETVAL(`s`, 5, 0);", KindSetval, ClassKnown, ""},
		{"DO SETVAL(`s`, 5, 0);", KindSetval, ClassKnown, ""},
		{"ANALYZE TABLE t UPDATE HISTOGRAM ON a, b;", KindAnalyzeTable, ClassKnown, ""},
		{"ANALYZE TABLE t;", KindOther, ClassUnread, ReasonKind},
		{"DROP TABLE IF EXISTS t;", KindDrop, ClassKnown, ""},
		{"DROP VIEW v;", KindDrop, ClassKnown, ""},
		{"DROP DATABASE d;", KindDrop, ClassKnown, ""},
		{"DROP TRIGGER t;", KindDrop, ClassKnown, ""},
		{"DROP PROCEDURE IF EXISTS p;", KindDrop, ClassKnown, ""},
		{"DROP FUNCTION f;", KindDrop, ClassKnown, ""},
		{"DROP EVENT e;", KindDrop, ClassKnown, ""},
		{"DROP SEQUENCE s;", KindDrop, ClassKnown, ""},
		{"DROP TEMPORARY TABLE t;", KindDrop, ClassUnread, ReasonKind},
		{"DROP INDEX i ON t;", KindOther, ClassUnread, ReasonKind},
		{"TRUNCATE TABLE t;", KindTruncate, ClassKnown, ""},
		{"TRUNCATE t;", KindTruncate, ClassKnown, ""},
		{"CREATE DATABASE IF NOT EXISTS d;", KindCreateDatabase, ClassKnown, ""},
		{"CREATE SCHEMA d;", KindCreateDatabase, ClassKnown, ""},
		{"ALTER DATABASE d CHARACTER SET utf8mb4;", KindAlterDatabase, ClassKnown, ""},
		{"USE `d`;", KindUse, ClassKnown, ""},
		{"SET NAMES utf8mb4;", KindSet, ClassKnown, ""},
		{"SET TIME_ZONE='+00:00', @a = 1;", KindSet, ClassKnown, ""},
		{"SET @@GLOBAL.GTID_PURGED=/*!80000 '+'*/ 'uuid:1-5';", KindSet, ClassKnown, ""},
		{"LOCK TABLES t WRITE;", KindLockTables, ClassKnown, ""},
		{"LOCK TABLE t READ;", KindLockTables, ClassKnown, ""},
		{"UNLOCK TABLES;", KindUnlockTables, ClassKnown, ""},
		{"START TRANSACTION;", KindTransaction, ClassKnown, ""},
		{"BEGIN;", KindTransaction, ClassKnown, ""},
		{"COMMIT;", KindTransaction, ClassKnown, ""},
		{"ROLLBACK;", KindTransaction, ClassKnown, ""},
		{"FLUSH TABLES;", KindFlush, ClassKnown, ""},
		{"CHANGE MASTER TO MASTER_LOG_FILE='x', MASTER_LOG_POS=4;", KindChangeSource, ClassKnown, ""},
		{"CHANGE REPLICATION SOURCE TO SOURCE_LOG_FILE='x';", KindChangeSource, ClassKnown, ""},
		{"CREATE USER 'u'@'%' IDENTIFIED BY 'x';", KindUser, ClassKnown, ""},
		{"ALTER USER 'u'@'%' IDENTIFIED BY 'x';", KindUser, ClassKnown, ""},
		{"GRANT SELECT ON *.* TO 'u'@'%';", KindGrant, ClassKnown, ""},
		{"REVOKE SELECT ON *.* FROM 'u'@'%';", KindGrant, ClassKnown, ""},
		{"UPDATE t SET a = 1;", KindUpdate, ClassUnread, ReasonKind},
		{"DELETE FROM t WHERE a = 1;", KindDelete, ClassUnread, ReasonKind},
		{"LOAD DATA INFILE 'f' INTO TABLE t;", KindLoadData, ClassUnread, ReasonKind},
		{"CALL p();", KindCall, ClassUnread, ReasonKind},
		{"SOURCE f.sql;", KindSource, ClassUnread, ReasonKind},
		{"SELECT 1;", KindOther, ClassUnread, ReasonKind},
		{"SHOW TABLES;", KindOther, ClassUnread, ReasonKind},
		{"CREATE ROLE r;", KindOther, ClassUnread, ReasonKind},
		{"ALTER VIEW v AS SELECT 1;", KindOther, ClassUnread, ReasonKind},
		{"START SLAVE;", KindOther, ClassUnread, ReasonKind},
		{"1 + 2;", KindOther, ClassUnread, ReasonKind},
		{"'text';", KindOther, ClassUnread, ReasonKind},
		// faults
		{"INSERT INTO t VALUES ('abc", KindInsert, ClassUnread, ReasonString},
		{"CREATE TABLE `abc (a int);", KindCreateTable, ClassUnread, ReasonString},
		{"DROP TABLE t", KindDrop, ClassUnread, ReasonEOF},
		{"INSERT INTO t VALUES (1)", KindInsert, ClassUnread, ReasonEOF},
		{"CREATE TABLE `" + long + "` (a int);", KindCreateTable, ClassUnread, ReasonIdentLength},
		{"INSERT INTO " + long + " VALUES (1);", KindInsert, ClassUnread, ReasonIdentLength},
		{"UPDATE `" + long + "` SET a = 1;", KindUpdate, ClassUnread, ReasonKind},
	}
	seen := map[Kind]bool{}
	for _, tc := range tests {
		name := tc.sql
		if len(name) > 50 {
			name = name[:50]
		}
		t.Run(name, func(t *testing.T) {
			v, st := readSQL(t, "SET sql_mode='';\n"+tc.sql)
			// the leading SET is counted too
			wantKind := 1
			if tc.kind == KindSet {
				wantKind = 2
			}
			if got := count(st, tc.kind); got != wantKind || st.Statements() != 2 {
				t.Fatalf("kind %s counted %d times, %d statements: %v", tc.kind, got, st.Statements(), st.ByKind)
			}
			want := [4]int{0, 1, 0, 0}
			want[tc.class]++
			if got := [4]int{st.Read, st.Known, st.Structure, st.Unread}; got != want {
				t.Fatalf("counts read/known/structure/unread = %v, want %v", got, want)
			}
			if tc.class == ClassUnread {
				if len(v.unread) != 1 {
					t.Fatalf("unread entries: %+v", v.unread)
				}
				u := v.unread[0]
				// rows read before the fault make the table known
				table := ""
				if tc.sql == "INSERT INTO t VALUES (1)" || strings.Contains(tc.sql, "ON DUPLICATE") {
					table = "t"
				}
				if u.Kind != tc.kind || u.Reason != tc.why || u.Line != 2 || u.Table != table || u.ToEnd {
					t.Fatalf("unread = %+v, want kind %s reason %q line 2", u, tc.kind, tc.why)
				}
			} else if len(v.unread) != 0 {
				t.Fatalf("unexpected unread: %+v", v.unread)
			}
		})
		seen[tc.kind] = true
	}
	for _, k := range Kinds {
		if !seen[k] {
			t.Errorf("no test statement of kind %s", k)
		}
	}
}

func TestClosedLists(t *testing.T) {
	if len(slices.Compact(slices.Sorted(slices.Values(Kinds)))) != len(Kinds) {
		t.Error("a kind is listed twice")
	}
	if len(slices.Compact(slices.Sorted(slices.Values(Reasons)))) != len(Reasons) {
		t.Error("a reason is listed twice")
	}
	want := []Reason{
		"a string or identifier doesn't end",
		"an expression the reader doesn't evaluate",
		"this form of INSERT isn't read",
		"this statement kind isn't read",
		"the row's values don't match the table's columns",
		"the file ended inside the statement",
		"a character set the reader doesn't decode",
		"the SQL mode is unknown",
		"an identifier longer than 256 bytes",
		"the ALTER TABLE changes the structure in a way the reader doesn't follow",
		"the table is created again with other columns",
		"more than one statement before the delimiter",
		"a mysql client command the reader doesn't follow",
		"a version comment some servers skip, where skipping it changes the statement",
	}
	if !slices.Equal(Reasons, want) {
		t.Errorf("reasons = %q", Reasons)
	}
}

func TestUnreadLineNumbers(t *testing.T) {
	sql := "SET sql_mode='';\r\n-- a comment\r\n\r\nINSERT INTO t VALUES\r\n  (1),\r\n  (2);\r\nUPDATE t\r\n  SET a = 1;\r\n/* two\r\nlines */ CALL p();\r\n"
	v, _ := readSQL(t, sql)
	if len(v.unread) != 2 || v.unread[0].Line != 7 || v.unread[0].Kind != KindUpdate || v.unread[1].Line != 10 || v.unread[1].Kind != KindCall {
		t.Fatalf("unread = %+v", v.unread)
	}
}

func TestUnreadTableOnlyWhenKnown(t *testing.T) {
	rd, v := readerFor("SET sql_mode='';\nUPDATE known SET a=1;\nUPDATE other SET a=1;\nDELETE FROM db.known WHERE 1;\nUSE db;\nDELETE FROM known WHERE 1;\nUPDATE known SET b=1")
	rd.markKnown("", "known")
	rd.markKnown("db", "known")
	if err := rd.run(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, u := range v.unread {
		got = append(got, fmt.Sprintf("%d:%s.%s", u.Line, u.Database, u.Table))
	}
	// line 2 names a known table in no database; line 3 an unknown table;
	// line 4 and 6 are in db, where the table is known; line 7 ends in the
	// file, in db, and is known there too
	want := []string{"2:.known", "3:.", "4:db.known", "6:db.known", "7:db.known"}
	if !slices.Equal(got, want) {
		t.Fatalf("unread tables = %v, want %v", got, want)
	}
}

func TestUnreadListCapped(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("SET sql_mode='';\n")
	for i := 0; i < 150; i++ {
		sb.WriteString("CALL p();\n")
	}
	v, st := readSQL(t, sb.String())
	if st.Unread != 150 || len(st.UnreadList) != 100 || len(v.unread) != 150 {
		t.Fatalf("unread = %d, listed %d, visited %d", st.Unread, len(st.UnreadList), len(v.unread))
	}
	if st.UnreadList[99].Line != 101 {
		t.Fatalf("last listed line %d", st.UnreadList[99].Line)
	}
}

func TestEmptyStatementsAreNotCounted(t *testing.T) {
	_, st := readSQL(t, ";;; ;\n/* c */;\n-- c\nDROP TABLE a;;\n")
	if st.Statements() != 1 || count(st, KindDrop) != 1 {
		t.Fatalf("statements %d %v", st.Statements(), st.ByKind)
	}
}

func TestUsersWarning(t *testing.T) {
	v, _ := readSQL(t, "SET sql_mode='';CREATE USER 'a'@'%' IDENTIFIED BY 'x';\nALTER USER 'b'@'%' IDENTIFIED BY 'y';\nGRANT ALL ON *.* TO 'c'@'%' IDENTIFIED BY 'z';\nGRANT SELECT ON *.* TO 'd'@'%';")
	want := "the dump creates 3 database users; an IDENTIFIED BY clause can hold a password"
	if !v.hasWarning(want) {
		t.Fatalf("warnings = %q", v.warns)
	}
	for _, w := range v.warns {
		for _, secret := range []string{"x", "'y", "z'"} {
			if strings.Contains(w, "'"+secret) {
				t.Fatalf("warning holds a value: %q", w)
			}
		}
	}
	v, _ = readSQL(t, "SET sql_mode='';GRANT SELECT ON *.* TO 'd'@'%';")
	for _, w := range v.warns {
		if strings.Contains(w, "database users") {
			t.Fatalf("a GRANT without IDENTIFIED warned: %q", w)
		}
	}
}

func TestDatabases(t *testing.T) {
	v, _ := readSQL(t, "SET sql_mode='';USE a;USE a;CREATE DATABASE IF NOT EXISTS `b c`;USE `b c`;ALTER DATABASE d CHARACTER SET x;USE e;")
	want := []string{"a", "b c", "d", "e"}
	if !slices.Equal(v.dbs, want) {
		t.Fatalf("databases = %q", v.dbs)
	}
}

func TestPanicBecomesAFixedError(t *testing.T) {
	canary := "CANARY-VALUE-1234"
	sql := "SET sql_mode='';\nINSERT INTO t VALUES ('" + canary + "');\nDROP TABLE t;\n"
	opts := Options{test: testHooks{panicAtLine: 2}}
	v := &rec{}
	st, err := Read(t.Context(), strings.NewReader(sql), v, opts)
	if err == nil {
		t.Fatal("no error")
	}
	var pe *PanicError
	if !asPanicError(err, &pe) || pe.Line != 2 {
		t.Fatalf("error = %#v", err)
	}
	if err.Error() != "the dump reader stopped at line 2" {
		t.Fatalf("message = %q", err.Error())
	}
	if strings.Contains(err.Error(), "test panic") || strings.Contains(err.Error(), canary) {
		t.Fatal("the message holds the panic's value or the file's")
	}
	if st.Statements() != 1 {
		t.Fatalf("statements before the panic: %d", st.Statements())
	}
	// with the hook on, the panic escapes
	defer func() {
		if recover() == nil {
			t.Fatal("the panic didn't escape with repanic on")
		}
	}()
	opts.test.repanic = true
	Read(t.Context(), strings.NewReader(sql), v, opts)
}

func asPanicError(err error, target **PanicError) bool {
	pe, ok := err.(*PanicError)
	if ok {
		*target = pe
	}
	return ok
}

func TestShopExample(t *testing.T) {
	// examples/shop.sql adds to the mode and never sets it to a literal, so it
	// gets the fixed warning; it holds statements of every kind the reader
	// follows, and none that is unread.
	v, st := readSQLFile(t, "../../examples/shop.sql")
	if !v.hasWarning(WarnNoSQLMode) {
		t.Fatalf("warnings = %q", v.warns)
	}
	if st.Unread != 0 {
		t.Fatalf("unread: %+v", v.unread[:min(3, len(v.unread))])
	}
	if count(st, KindCreateTable) < 10 || count(st, KindInsert) < 10 {
		t.Fatalf("kinds: %v", st.ByKind)
	}
}

// A statement that holds rows inside a form the reader doesn't open is
// unread, not known.
func TestRowsInsideWrapperStatementsAreUnread(t *testing.T) {
	const head = "SET sql_mode='';\nCREATE TABLE t (id int, note varchar(100));\n"
	for name, stmt := range map[string]string{
		"set statement":    "SET STATEMENT sql_mode='' FOR INSERT INTO t VALUES (2,'x');",
		"begin not atomic": "BEGIN NOT ATOMIC INSERT INTO t VALUES (4,'x');",
		"histogram data":   `ANALYZE TABLE t UPDATE HISTOGRAM ON note USING DATA '{"buckets": [["x", 1.0]]}';`,
	} {
		t.Run(name, func(t *testing.T) {
			v, st := readSQL(t, head+stmt+"\n")
			if st.Unread != 1 || len(v.unread) != 1 || v.unread[0].Reason != ReasonKind {
				t.Fatalf("unread %d, list %+v", st.Unread, v.unread)
			}
		})
	}
	// The forms that hold no rows stay known.
	for _, stmt := range []string{
		"BEGIN;", "BEGIN WORK;", "COMMIT;", "ANALYZE TABLE t UPDATE HISTOGRAM ON note;",
		"ANALYZE TABLE t DROP HISTOGRAM ON note;",
	} {
		_, st := readSQL(t, head+stmt+"\n")
		if st.Unread != 0 {
			t.Errorf("%q was left unread", stmt)
		}
	}
}
