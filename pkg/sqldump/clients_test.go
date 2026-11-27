package sqldump

import (
	"strings"
	"testing"
)

// clientHead makes the table t known in the database d, so that an unread
// entry that named a table it can't tell would show. The next line is 6.
const clientHead = "SET sql_mode='';\nCREATE DATABASE d;\nUSE d;\n" +
	"CREATE TABLE t (id int NOT NULL, email varchar(100) NOT NULL, PRIMARY KEY (id));\n" +
	"INSERT INTO t VALUES (9,'known@example.test');\n"

const clientRow = "INSERT INTO t VALUES (1,'a@example.test')"

// readOneUnread reads clientHead and sql, and checks that exactly one
// statement is unread, for the reason why, and that its entry names no table.
func readOneUnread(t *testing.T, sql string, why Reason, toEnd bool) (Unread, Stats) {
	t.Helper()
	v, st := readSQL(t, clientHead+sql)
	if st.Unread != 1 || len(v.unread) != 1 {
		t.Fatalf("unread %d: %+v", st.Unread, v.unread)
	}
	u := v.unread[0]
	if u.Reason != why || u.Database != "" || u.Table != "" || u.ToEnd != toEnd {
		t.Fatalf("unread = %+v, want reason %q, to the end %v, no table", u, why, toEnd)
	}
	return u, st
}

// The shapes of the client probes: the mysql and mariadb clients loaded rows
// from each of them. Each is unread, for its own reason, and names no table.
func TestClientProbeShapes(t *testing.T) {
	for _, c := range []struct {
		name, sql string
		why       Reason
		toEnd     bool
		line      int
		rows      int64
	}{
		{"lock tables", "DELIMITER ;;\nLOCK TABLES t WRITE; " + clientRow + ";;\nDELIMITER ;\n", ReasonSeveral, false, 7, 1},
		{"begin work", "DELIMITER ;;\nBEGIN WORK; " + clientRow + ";;\nDELIMITER ;\n", ReasonSeveral, false, 7, 1},
		{"set names", "DELIMITER ;;\nSET NAMES utf8mb4; " + clientRow + ";;\nDELIMITER ;\n", ReasonSeveral, false, 7, 1},
		{"trigger", "DELIMITER ;;\nCREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.id = NEW.id; " + clientRow + ";;\nDELIMITER ;\n", ReasonSeveral, false, 7, 1},
		{"two inserts", "DELIMITER ;;\nINSERT INTO t VALUES (2,'b@example.test'); " + clientRow + ";;\nDELIMITER ;\n", ReasonSeveral, false, 7, 2},
		{"two tables", "DELIMITER ;;\nINSERT INTO t VALUES (2,'b@example.test'); INSERT INTO u VALUES (3,'c');;\nDELIMITER ;\n", ReasonSeveral, false, 7, 2},
		{"disable keys", "DELIMITER ;;\n/*!40000 ALTER TABLE t DISABLE KEYS */; " + clientRow + ";;\nDELIMITER ;\n", ReasonSeveral, false, 7, 1},
		{"drop", "DELIMITER ;;\nDROP TABLE IF EXISTS t2; " + clientRow + ";;\nDELIMITER ;\n", ReasonSeveral, false, 7, 1},
		{"dollar delimiter", "DELIMITER $$\nSET NAMES utf8mb4; " + clientRow + "$$\nDELIMITER ;\n", ReasonSeveral, false, 7, 1},
		{"backslash g", "SET NAMES utf8mb4 \\g " + clientRow + ";\n", ReasonClient, true, 6, 1},
		{"backslash G", "SET NAMES utf8mb4 \\G " + clientRow + ";\n", ReasonClient, true, 6, 1},
		{"backslash c", "SET NAMES utf8mb4 \\c\n" + clientRow + ";\n", ReasonClient, true, 6, 1},
		{"source", "\\. other.sql\n" + clientRow + ";\n", ReasonClient, true, 6, 1},
		{"use", "use other\n" + clientRow + ";\n", ReasonClient, true, 6, 1},
		{"charset", "charset utf8mb4\n" + clientRow + ";\n", ReasonClient, true, 6, 1},
		// The clients take the word after DELIMITER and drop the rest up to
		// the ;, the row of 7 included.
		{"a statement, then DELIMITER on its line", clientRow + "; DELIMITER $$\nINSERT INTO t VALUES (7,'c@example.test')$$\nDELIMITER ;\n", ReasonClient, true, 6, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			u, st := readOneUnread(t, c.sql, c.why, c.toEnd)
			if u.Line != c.line || st.Rows != c.rows {
				t.Fatalf("line %d, %d rows; want line %d, %d rows", u.Line, st.Rows, c.line, c.rows)
			}
		})
	}
	// The control, and the shapes the clients load nothing from: go and ego
	// are commands only at the start of a statement, and the reader takes
	// DELIMITER only at the start of a line too. After a statement on its
	// line, the statement DELIMITER starts leaves the rest of the file unread.
	for _, c := range []struct {
		name, sql string
		unread    int
		rows      int64
	}{
		{"control", "DELIMITER ;;\n" + clientRow + ";;\nDELIMITER ;\n", 0, 2},
		{"go inside a statement", "SET NAMES utf8mb4\ngo\n" + clientRow + ";\n", 0, 1},
		{"ego inside a statement", "SET NAMES utf8mb4\nego\n" + clientRow + ";\n", 0, 1},
		{"delimiter after a statement", "SELECT 1; DELIMITER $$\nINSERT INTO t VALUES (7,'c@example.test')$$\nDELIMITER ;\n", 2, 1},
		{"delimiter inside a statement", clientRow + " delimiter $$\nINSERT INTO t VALUES (7,'c@example.test')$$\nDELIMITER ;\n", 0, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, st := readSQL(t, clientHead+c.sql)
			if st.Unread != c.unread || st.Rows != c.rows {
				t.Fatalf("unread %+v, %d rows; want %d unread, %d rows", v.unread, st.Rows, c.unread, c.rows)
			}
		})
	}
}

// Semicolons right before a custom delimiter end no second statement.
func TestTrailingSemicolonsStayRead(t *testing.T) {
	for _, c := range []struct {
		name, sql string
		kind      Kind
		rows      int64
	}{
		{"insert", "DELIMITER $$\n" + clientRow + ";$$\nDELIMITER ;\n", KindInsert, 2},
		{"insert, two", "DELIMITER $$\n" + clientRow + "; ;$$\nDELIMITER ;\n", KindInsert, 2},
		{"insert under ;;", "DELIMITER ;;\n" + clientRow + "; ;;\nDELIMITER ;\n", KindInsert, 2},
		{"set", "DELIMITER $$\nSET NAMES utf8mb4;$$\nDELIMITER ;\n", KindSet, 1},
		{"trigger", "DELIMITER $$\nCREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.id = NEW.id;$$\nDELIMITER ;\n", KindCreateTrigger, 1},
		{"trigger with a body", "DELIMITER $$\nCREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.id = NEW.id; END;$$\nDELIMITER ;\n", KindCreateTrigger, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, st := readSQL(t, clientHead+c.sql)
			if st.Unread != 0 || st.Rows != c.rows || count(st, c.kind) < 1 {
				t.Fatalf("unread %+v, %d rows, kinds %v", v.unread, st.Rows, st.ByKind)
			}
		})
	}
}

// A backslash outside strings, identifiers and plain comments is a command of
// the client's own: the rest of the file is one unread entry.
func TestBackslashCommands(t *testing.T) {
	for _, c := range []struct {
		name, sql string
		line      int
		rows      int64
	}{
		{"u", "\\u other\n" + clientRow + ";\n", 6, 1},
		{"C", "\\C latin1\n" + clientRow + ";\n", 6, 1},
		{"d", "\\d $$\n" + clientRow + "$$\n", 6, 1},
		{"r", "\\r\n" + clientRow + ";\n", 6, 1},
		{"x", "\\x\n" + clientRow + ";\n", 6, 1},
		{"q after a statement", clientRow + ";\n\\q\n", 7, 2},
		{"g after a row", clientRow + " \\g INSERT INTO t VALUES (2,'b@example.test');\n", 6, 2},
		{"in an executable comment", "/*!40101 SET NAMES utf8mb4 \\g */ " + clientRow + ";\n", 6, 1},
		{"in a hint", "INSERT /*+ SET_VAR(sort_buffer_size = 16M) \\g */ INTO t VALUES (1,'a@example.test');\n", 6, 1},
		// The clients pass \N on as NULL; the reader doesn't tell it apart.
		{"N outside a string", "INSERT INTO t VALUES (1,\\N);\n", 6, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			u, st := readOneUnread(t, c.sql, ReasonClient, true)
			if u.Line != c.line || st.Rows != c.rows {
				t.Fatalf("line %d, %d rows; want line %d, %d rows", u.Line, st.Rows, c.line, c.rows)
			}
		})
	}
	// Backslashes the clients don't run.
	for name, sql := range map[string]string{
		"in a string":            "INSERT INTO t VALUES (1,'a\\\\g \\'q\\' \\c');\n",
		"in a quoted string":     "INSERT INTO t VALUES (1,\"a\\\\g\");\n",
		"in an identifier":       "CREATE TABLE `a\\g` (id int);\n",
		"in a block comment":     "/* \\g */ DROP TABLE x;\n",
		"in line comments":       "DROP TABLE x; -- \\g\n# \\c\nDROP TABLE y;\n",
		"no backslash escapes":   "SET sql_mode='NO_BACKSLASH_ESCAPES';\nINSERT INTO t VALUES (1,'a\\');\n",
		"a hint with no command": "INSERT /*+ SET_VAR(sort_buffer_size = 16M) */ INTO t VALUES (1,'a@example.test');\n",
	} {
		t.Run(name, func(t *testing.T) {
			if v, st := readSQL(t, clientHead+sql); st.Unread != 0 {
				t.Fatalf("unread %+v", v.unread)
			}
		})
	}
	// mariadb-dump's first line stays a plain comment.
	v, st := readSQL(t, "/*M!999999\\- enable the sandbox mode */ \n"+clientHead+clientRow+";\n")
	if st.Unread != 0 || st.Rows != 2 {
		t.Fatalf("sandbox line: unread %+v, %d rows", v.unread, st.Rows)
	}
}

// The clients run a line as their own command at the start of a statement
// when its first word is a command's name, followed by a space, a tab or the
// line's end, and the line holds no delimiter.
func TestLongClientCommands(t *testing.T) {
	names := []string{"?", "charset", "clear", "connect", "costs", "edit", "ego", "exit", "go", "help",
		"nopager", "notee", "nowarning", "pager", "print", "prompt", "query_attributes", "quit", "rehash",
		"resetconnection", "sandbox", "source", "ssl_session_data_print", "status", "system", "tee", "use", "warnings"}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			for _, line := range []string{n + " x\n", n + "\tx\n", n + "\n", n + "\r\n", strings.ToUpper(n) + " x y\n"} {
				u, st := readOneUnread(t, line+clientRow+";\n", ReasonClient, true)
				if u.Line != 6 || st.Rows != 1 {
					t.Fatalf("%q: line %d, %d rows", line, u.Line, st.Rows)
				}
			}
			// at the end of the file
			if u, _ := readOneUnread(t, clientRow+";\n"+n, ReasonClient, true); u.Line != 7 {
				t.Fatalf("at the end: line %d", u.Line)
			}
		})
	}
	// With the delimiter on its line, anywhere in it, the line is SQL, as
	// every dump tool writes USE; and so is a name inside a statement. A USE
	// with more than its name before the delimiter is one the server rejects:
	// unread, and nothing switches.
	for _, c := range []struct {
		name, sql string
		kind      Kind
		unread    int
		rows      int64
	}{
		{"use with its delimiter", "use other;\n" + clientRow + ";\n", KindUse, 0, 2},
		{"USE as the tools write it", "USE `other`;\n" + clientRow + ";\n", KindUse, 0, 2},
		{"a delimiter in a comment", "use other -- ;\n" + clientRow + ";\n", KindUse, 1, 1},
		{"a delimiter in a string", "use other ';'\n" + clientRow + ";\n", KindUse, 1, 1},
		{"a delimiter far along the line", "use other /* " + strings.Repeat("x", 3000) + " */;\n" + clientRow + ";\n", KindUse, 0, 2},
		{"status with its delimiter", "status;\n" + clientRow + ";\n", KindOther, 1, 2},
		{"a longer word", "gopher x\n" + clientRow + ";\n", KindOther, 1, 1},
		{"a name inside a statement", "DROP TABLE IF EXISTS x\nstatus\n;\n" + clientRow + ";\n", KindDrop, 0, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, st := readSQL(t, clientHead+c.sql)
			if st.Unread != c.unread || st.Rows != c.rows || count(st, c.kind) < 1 {
				t.Fatalf("unread %+v, %d rows, kinds %v", v.unread, st.Rows, st.ByKind)
			}
			for _, u := range v.unread {
				if u.Reason == ReasonClient {
					t.Fatalf("a client command: %+v", u)
				}
			}
		})
	}
	// A line with no end within 4 KiB is taken for a command.
	readOneUnread(t, "use "+strings.Repeat("x", 5000)+";\n"+clientRow+";\n", ReasonClient, true)
	// DELIMITER keeps its own handling, with the delimiter on its line.
	if v, st := readSQL(t, clientHead+"DELIMITER ;\n"+clientRow+";\n"); st.Unread != 0 || st.Rows != 2 {
		t.Fatalf("DELIMITER: unread %+v, %d rows", v.unread, st.Rows)
	}
}

// The clients run a long-form command only as the first word of its line:
// nothing but spaces and tabs before it, and a comment there counts as text.
func TestCommandsOnlyAtALineStart(t *testing.T) {
	// A version comment before DELIMITER on its line.
	v, st := readSQL(t, clientHead+"CREATE TABLE `commit` (id int NOT NULL, note varchar(100));\n"+
		"/*!99999 */ DELIMITER INSERT\n INSERT commit VALUES (2,'a@example.test') ; INSERT")
	if len(v.unread) == 0 || v.unread[0].Line != 7 || st.Rows != 1 {
		t.Fatalf("a version comment before DELIMITER: unread %+v, %d rows", v.unread, st.Rows)
	}
	// A plain comment before DELIMITER on its line: the reader takes no
	// command, but the clients run the statement DELIMITER starts as theirs,
	// so the rest of the file is unread.
	if u, st := readOneUnread(t, "/* c */ DELIMITER ;;\n"+clientRow+";\nINSERT INTO t VALUES (2,'b@example.test');\n", ReasonClient, true); u.Line != 6 || st.Rows != 1 {
		t.Fatalf("a comment first: %+v, %d rows", u, st.Rows)
	}
	// Indented, it is a command.
	if v, st := readSQL(t, clientHead+"  DELIMITER ;;\n"+clientRow+";;\n\tDELIMITER ;\n"+clientRow+";\n"); st.Unread != 0 || st.Rows != 3 {
		t.Fatalf("indented: unread %+v, %d rows", v.unread, st.Rows)
	}
	// After a statement on the same line, use is no command: the USE
	// with more after its name is unread, and the file goes on.
	u, st := readOneUnread(t, clientRow+"; use other\nINSERT INTO t VALUES (2,'b@example.test');\nINSERT INTO t VALUES (3,'c@example.test');\n", ReasonKind, false)
	if u.Line != 6 || u.Kind != KindUse || st.Rows != 3 {
		t.Fatalf("use after a statement: %+v, %d rows", u, st.Rows)
	}
	// A USE with a word after its name switches nothing.
	v, _ = readSQL(t, clientHead+"USE other x;\n")
	if len(v.dbs) != 1 || len(v.unread) != 1 || v.unread[0].Reason != ReasonKind {
		t.Fatalf("USE other x: %q %+v", v.dbs, v.unread)
	}
}
