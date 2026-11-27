package cli

import (
	"fmt"
	"strings"
	"testing"
)

// Rows held inside a statement the reader doesn't open make the gate fail, in
// every form.
func TestScanDumpWrappedRowsFailTheGate(t *testing.T) {
	const head = dumpHead + "CREATE TABLE `things` (`id` int NOT NULL AUTO_INCREMENT, `note` varchar(100), PRIMARY KEY (`id`));\n" +
		"INSERT INTO `things` VALUES (1,'x');\n"
	for name, stmt := range map[string]string{
		"set statement":  "SET STATEMENT sql_mode='' FOR INSERT INTO `things` VALUES (2,'zq7canary.one@example.test'),(3,'zq7canary.two@example.test');\n",
		"begin":          "BEGIN NOT ATOMIC INSERT INTO `things` VALUES (4,'zq7canary.three@example.test');\n",
		"histogram data": "ANALYZE TABLE `things` UPDATE HISTOGRAM ON `note` USING DATA '{\"buckets\": [[\"zq7canary.four@example.test\", 1.0]]}';\n",
	} {
		code, stdout, stderr := scanDump(t, "--dump", writeDump(t, head+stmt), "--fail-on", "high")
		if code != ExitError || !strings.Contains(stderr, "the gate fails") || !strings.Contains(stdout, "wasn't read") {
			t.Errorf("%s: status %d, stderr %q\n%s", name, code, stderr, stdout)
		}
		if hasCanary(stdout) || hasCanary(stderr) {
			t.Errorf("%s: a canary is in the output", name)
		}
	}
}

// Rows the mysql clients load from what the reader would have read as one
// statement, or after a command of the client's own, make the gate fail.
func TestScanDumpClientShapesFailTheGate(t *testing.T) {
	const head = dumpHead + "CREATE TABLE `things` (`id` int NOT NULL AUTO_INCREMENT, `note` varchar(100), PRIMARY KEY (`id`));\n" +
		"INSERT INTO `things` VALUES (1,'x');\n"
	for name, c := range map[string]struct{ sql, why string }{
		"trigger": {"DELIMITER ;;\nCREATE TRIGGER `trg` BEFORE INSERT ON `things` FOR EACH ROW SET NEW.id = NEW.id; " +
			"INSERT INTO `things` VALUES (2,'zq7canary.one@example.test');;\nDELIMITER ;\n", "more than one statement before the delimiter"},
		"two inserts": {"DELIMITER ;;\nINSERT INTO `things` VALUES (3,'y'); INSERT INTO `things` VALUES (4,'zq7canary.two@example.test');;\nDELIMITER ;\n",
			"more than one statement before the delimiter"},
		"backslash g": {"SET NAMES utf8mb4 \\g INSERT INTO `things` VALUES (5,'zq7canary.three@example.test');\n", "a mysql client command the reader doesn't follow"},
		"use":         {"use zq7canary_db\nINSERT INTO `things` VALUES (6,'zq7canary.four@example.test');\n", "a mysql client command the reader doesn't follow"},
	} {
		code, stdout, stderr := scanDump(t, "--dump", writeDump(t, head+c.sql), "--fail-on", "high")
		if code != ExitError || !strings.Contains(stderr, "the gate fails") || !strings.Contains(stdout, c.why) {
			t.Errorf("%s: status %d, stderr %q\n%s", name, code, stderr, stdout)
		}
		if hasCanary(stdout) || hasCanary(stderr) {
			t.Errorf("%s: a canary is in the output", name)
		}
	}
}

// Rows a server loads after skipping a version comment the reader read as SQL
// make the gate fail.
func TestScanDumpVersionCommentsFailTheGate(t *testing.T) {
	const head = dumpHead + "CREATE TABLE `things` (`id` int NOT NULL AUTO_INCREMENT, `note` varchar(100), PRIMARY KEY (`id`));\n" +
		"INSERT INTO `things` VALUES (1,'x');\n"
	for name, sql := range map[string]string{
		"LOCK TABLES":           "/*!99999 LOCK TABLES */ INSERT INTO `things` VALUES (2,'zq7canary.one@example.test');\n",
		"a string past the end": "/*!99999 SET @x=' */ INSERT INTO `things` VALUES (3,'zq7canary.two@example.test'); /*!99999 ' */;\n",
		"a trigger's body": "DELIMITER $$\nCREATE TRIGGER `tg` BEFORE INSERT ON `things` FOR EACH ROW /*!99999 BEGIN */ SET @a=1; " +
			"INSERT INTO `things` VALUES (4,'zq7canary.three@example.test') /*!99999 ; END */ $$\nDELIMITER ;\n",
		// Not refused for several databases: the rest of the file is unread.
		"a whole CREATE DATABASE": "/*!99999 CREATE DATABASE other_db */;\nINSERT INTO `things` VALUES (5,'zq7canary.four@example.test');\n",
	} {
		code, stdout, stderr := scanDump(t, "--dump", writeDump(t, head+sql), "--fail-on", "high")
		if code != ExitError || !strings.Contains(stderr, "the gate fails") ||
			!strings.Contains(joined(stdout), "a version comment some servers skip, where skipping it changes the statement") {
			t.Errorf("%s: status %d, stderr %q\n%s", name, code, stderr, stdout)
		}
		if hasCanary(stdout) || hasCanary(stderr) {
			t.Errorf("%s: a canary is in the output", name)
		}
	}
}

// The report never names a database from a statement the version rule leaves
// unread: a server that skips the comment never switched to it.
func TestScanDumpVersionCommentNamesNoDatabase(t *testing.T) {
	const table = "CREATE TABLE `things` (`id` int NOT NULL, `note` varchar(100), PRIMARY KEY (`id`));\nINSERT INTO `things` VALUES (1,'x');\n"
	for name, sql := range map[string]string{
		"CREATE DATABASE": "/*!99999 CREATE DATABASE zq7canarydb */;\n",
		"USE":             "/*!99999 USE zq7canarydb */;\n",
		"MariaDB's":       "/*M!100100 CREATE DATABASE zq7canarydb */;\n",
	} {
		path := writeDump(t, dumpHead+table+sql+"INSERT INTO `things` VALUES (2,'y');\n")
		for _, format := range []string{"text", "json"} {
			code, stdout, stderr := scanDump(t, "--dump", path, "--format", format)
			if code != ExitOK || hasCanary(stdout) || hasCanary(stderr) {
				t.Errorf("%s %s: status %d\n%s%s", name, format, code, stdout, stderr)
			}
		}
	}
	// A plain CREATE DATABASE and USE still name it.
	path := writeDump(t, dumpHead+"CREATE DATABASE `d`;\nUSE `d`;\n"+table)
	if _, stdout, _ := scanDump(t, "--dump", path); !strings.Contains(stdout, "prodmask scan · d · dump file") {
		t.Errorf("text:\n%s", stdout)
	}
	if _, stdout, _ := scanDump(t, "--dump", path, "--format", "json"); !strings.Contains(stdout, `"database": "d"`) {
		t.Errorf("json:\n%s", stdout)
	}
}

// A whole statement in a version comment that some servers skip changes
// nothing the reader holds: the table keeps its first structure, so the rows
// after it are judged as varchar and the email is found.
func TestScanDumpWholeVersionCommentsKeepTheTable(t *testing.T) {
	const people = dumpHead + "CREATE TABLE `people` (`id` int NOT NULL, `email` varchar(100), PRIMARY KEY (`id`));\n"
	const rows = "INSERT INTO `people` VALUES (1,'zq7canary.a@fixture-store.gr'),(2,'zq7canary.b@fixture-store.gr'),(3,'zq7canary.c@fixture-store.gr');\n"
	for name, sql := range map[string]string{
		"ALTER TABLE":                    "/*!99999 ALTER TABLE people MODIFY email blob */;\n",
		"CREATE TABLE IF NOT EXISTS":     "/*M!100100 CREATE TABLE IF NOT EXISTS people (id int NOT NULL, email blob, PRIMARY KEY (id)) */;\n",
		"CREATE OR REPLACE TABLE":        "/*!99999 CREATE OR REPLACE TABLE people (id int NOT NULL, email blob, PRIMARY KEY (id)) */;\n",
		"DROP TABLE":                     "/*!99999 DROP TABLE people */;\n",
		"CREATE OR REPLACE VIEW":         "/*!99999 CREATE OR REPLACE VIEW people AS SELECT 1 AS id, 2 AS email */;\n",
		"INSERT":                         "/*!99999 INSERT INTO people VALUES (9,'zq7canary.d@fixture-store.gr') */;\n",
		"AUTO_INCREMENT":                 "/*!99999 ALTER TABLE people AUTO_INCREMENT=5 */;\n",
		"CREATE INDEX":                   "/*!99999 CREATE UNIQUE INDEX u ON people (email) */;\n",
		"a second CREATE, IF NOT EXISTS": "CREATE TABLE IF NOT EXISTS people (id int NOT NULL, email blob, PRIMARY KEY (id));\n",
	} {
		// --verbose prints each finding's whole evidence, which the report
		// otherwise cuts to the width.
		code, stdout, stderr := scanDump(t, "--dump", writeDump(t, people+sql+rows), "--fail-on", "high", "--verbose")
		if code != ExitFindings || !strings.Contains(stdout, "3 of 3 sampled values match the email address") {
			t.Errorf("%s: status %d\n%s%s", name, code, stdout, stderr)
		}
		if hasCanary(stdout) || hasCanary(stderr) {
			t.Errorf("%s: a canary is in the output", name)
		}
	}
}

// What a server keeps after a DROP that removes nothing, a CREATE by another
// letter case, an INSERT through a view, a DELIMITER the clients reject or a
// variable set behind the reader's back is never judged other than it loads:
// the email is found, or the gate fails. Only USE switches the database.
func TestScanDumpStateSweep(t *testing.T) {
	const things = "CREATE TABLE `things` (`id` int NOT NULL, `note` varchar(100), PRIMARY KEY (`id`));\n"
	const blob = "CREATE TABLE IF NOT EXISTS things (id int NOT NULL, note blob, PRIMARY KEY (id));\n"
	const values = " VALUES (1,'zq7canary.a@fixture-store.gr'),(2,'zq7canary.b@fixture-store.gr'),(3,'zq7canary.c@fixture-store.gr');\n"
	const rows = "INSERT INTO things" + values
	const view = "CREATE TABLE base (id int NOT NULL, note varchar(100), PRIMARY KEY (id));\n" +
		"CREATE VIEW things AS SELECT id AS id, note AS note FROM base;\n"
	// CREATE DATABASE switches nothing: the rows are in shop, with or without --database.
	createDB := writeDump(t, dumpHead+"CREATE DATABASE IF NOT EXISTS shop;\nUSE shop;\nCREATE TABLE first (id int NOT NULL, PRIMARY KEY (id));\n"+
		"CREATE DATABASE IF NOT EXISTS other;\n"+things+rows)
	for _, extra := range [][]string{nil, {"--database", "shop"}} {
		code, stdout, stderr := scanDump(t, append([]string{"--dump", createDB, "--fail-on", "high"}, extra...)...)
		if code != ExitFindings || !strings.Contains(stdout, "3 of 3 sampled values look like email addresses") {
			t.Errorf("CREATE DATABASE %v: status %d\n%s%s", extra, code, stdout, stderr)
		}
		if hasCanary(stdout) || hasCanary(stderr) {
			t.Errorf("CREATE DATABASE %v: a canary is in the output", extra)
		}
	}
	for name, sql := range map[string]string{
		"DROP TABLE on a view":   view + "DROP TABLE IF EXISTS things;\n" + blob + rows,
		"INSERT through a view":  view + rows,
		"DROP TEMPORARY":         things + "DROP TEMPORARY TABLE IF EXISTS things;\n" + blob + rows,
		"CREATE TEMPORARY":       things + "CREATE TEMPORARY TABLE things (id int NOT NULL, note varchar(100), PRIMARY KEY (id));\nDROP TABLE things;\n" + blob + rows,
		"a name by another case": things + "CREATE TABLE IF NOT EXISTS Things (id int NOT NULL, note blob, PRIMARY KEY (id));\nINSERT INTO Things" + values,
		"a 17-byte DELIMITER": things + "DELIMITER AAAAAAAAAAAAAAAAB\nINSERT INTO things VALUES (1,'zq7canary.a@fixture-store.gr') AAAAAAAAAAAAAAAA\n" +
			"DELIMITER ;\n",
		"a variable set in an expression": things + "SET @m = '';\nSET @x = (@m := 'NO_BACKSLASH_ESCAPES');\nSET sql_mode = @m;\n" + rows,
		"DROP VIEW on a table":            things + "DROP VIEW IF EXISTS things;\n" + blob + rows,
		"a DROP by another case":          things + "DROP TABLE IF EXISTS `Things`;\n" + blob + rows,
	} {
		code, stdout, stderr := scanDump(t, "--dump", writeDump(t, dumpHead+sql), "--fail-on", "high")
		if code == ExitOK || !strings.Contains(stdout, "3 of 3 sampled values look like email addresses") && !strings.Contains(stdout, "wasn't read") {
			t.Errorf("%s: status %d\n%s%s", name, code, stdout, stderr)
		}
		if hasCanary(stdout) || hasCanary(stderr) {
			t.Errorf("%s: a canary is in the output", name)
		}
	}
}

// A table filled from a query fails the gate; bit literals into text are
// judged as their bytes; database names that differ only by case are one,
// with or without --database in either spelling; values an expression fills
// are counted.
func TestScanDumpFilledValues(t *testing.T) {
	const cols = "CREATE TABLE things (id int NOT NULL, note varchar(100), PRIMARY KEY (id))"
	const sel = "SELECT 1 AS id, 'zq7canary.a@fixture-store.gr' AS note UNION ALL SELECT 2, 'zq7canary.b@fixture-store.gr' UNION ALL SELECT 3, 'zq7canary.c@fixture-store.gr'"
	const values = " VALUES (1,'zq7canary.a@fixture-store.gr'),(2,'zq7canary.b@fixture-store.gr'),(3,'zq7canary.c@fixture-store.gr');\n"
	bits := func(s string) string {
		var b strings.Builder
		for _, c := range []byte(s) {
			fmt.Fprintf(&b, "%08b", c)
		}
		return b.String()
	}
	check := func(name string, code int, stdout, stderr string, want int) {
		t.Helper()
		if code != want || hasCanary(stdout) || hasCanary(stderr) {
			t.Errorf("%s: status %d\n%s%s", name, code, stdout, stderr)
		}
	}
	for name, sql := range map[string]string{
		"a query in parentheses":    cols + " (" + sel + ");\n",
		"a query after a PARTITION": cols + " PARTITION BY HASH(id) PARTITIONS 2 " + sel + ";\n",
		"IGNORE and a query":        cols + " IGNORE (" + sel + ");\n",
	} {
		code, stdout, stderr := scanDump(t, "--dump", writeDump(t, dumpHead+sql), "--fail-on", "high")
		check(name, code, stdout, stderr, ExitError)
		if !strings.Contains(stdout, "this form of INSERT isn't read") {
			t.Errorf("%s: no unread entry\n%s", name, stdout)
		}
	}
	for name, lit := range map[string]string{"b'...'": "b'%s'", "0b...": "0b%s"} {
		rows := ""
		for i, e := range []string{"zq7canary.a@fixture-store.gr", "zq7canary.b@fixture-store.gr", "zq7canary.c@fixture-store.gr"} {
			if i > 0 {
				rows += ","
			}
			rows += fmt.Sprintf("(%d,"+lit+")", i+1, bits(e))
		}
		code, stdout, stderr := scanDump(t, "--dump", writeDump(t, dumpHead+cols+";\nINSERT INTO things VALUES "+rows+";\n"), "--fail-on", "high")
		check(name, code, stdout, stderr, ExitFindings)
		if !strings.Contains(stdout, "3 of 3 sampled values look like email addresses") {
			t.Errorf("%s: not judged\n%s", name, stdout)
		}
	}
	useCase := writeDump(t, dumpHead+"CREATE DATABASE IF NOT EXISTS shop;\nUSE shop;\nCREATE TABLE first (id int NOT NULL, PRIMARY KEY (id));\nUSE Shop;\n"+cols+";\nINSERT INTO things"+values)
	qualified := writeDump(t, dumpHead+"CREATE DATABASE IF NOT EXISTS shop;\nUSE shop;\n"+cols+";\nINSERT INTO Shop.things"+values)
	for name, path := range map[string]string{"USE by another case": useCase, "a qualified name": qualified} {
		for _, extra := range [][]string{nil, {"--database", "shop"}, {"--database", "Shop"}} {
			code, stdout, stderr := scanDump(t, append([]string{"--dump", path, "--fail-on", "high"}, extra...)...)
			check(fmt.Sprint(name, extra), code, stdout, stderr, ExitFindings)
			if !strings.Contains(stdout, "3 of 3 sampled values look like email addresses") || !strings.Contains(stdout, "prodmask scan · shop · dump file") {
				t.Errorf("%s %v: not judged in shop\n%s", name, extra, stdout)
			}
		}
	}
	// Numbers into ENUM and SET are the members they pick, and strings read as before.
	const members = "'zq7canary.a@fixture-store.gr','zq7canary.b@fixture-store.gr','zq7canary.c@fixture-store.gr'"
	for name, sql := range map[string]string{
		"an ENUM index":           "CREATE TABLE things (id int NOT NULL, note enum('x'," + members + "), PRIMARY KEY (id));\nINSERT INTO things VALUES (1,2),(2,3),(3,4);\n",
		"a SET mask":              "CREATE TABLE things (id int NOT NULL, note set(" + members + "), PRIMARY KEY (id));\nINSERT INTO things VALUES (1,1),(2,2),(3,4);\n",
		"ENUM members as strings": "CREATE TABLE things (id int NOT NULL, note enum('x'," + members + "), PRIMARY KEY (id));\nINSERT INTO things" + values,
	} {
		code, stdout, stderr := scanDump(t, "--dump", writeDump(t, dumpHead+sql), "--fail-on", "high")
		check(name, code, stdout, stderr, ExitFindings)
		if !strings.Contains(stdout, "3 of 3 sampled values look like email addresses") {
			t.Errorf("%s: not judged\n%s", name, stdout)
		}
	}
	exprDefault := writeDump(t, dumpHead+"CREATE TABLE things (id int NOT NULL, note varchar(100) DEFAULT (CONCAT('zq7canary.a','@fixture-store.gr')), PRIMARY KEY (id));\n"+
		"INSERT INTO things (id) VALUES (1),(2),(3);\n")
	code, stdout, stderr := scanDump(t, "--dump", exprDefault, "--fail-on", "high", "--format", "json")
	check("an expression default", code, stdout, stderr, ExitOK)
	if !strings.Contains(stdout, `"defaults_without_literal": 3`) {
		t.Errorf("an expression default: not counted\n%s", stdout)
	}
}

// A gzip file that is damaged after its SQL mode became unknown is an error
// whatever --fail-on says.
func TestScanDumpCutAfterUnknownMode(t *testing.T) {
	var sql strings.Builder
	sql.WriteString(dumpHead + "CREATE TABLE `things` (`id` int, `note` varchar(100));\nSET sql_mode=CONCAT(@@sql_mode, func());\n")
	for i := range 20000 {
		sql.WriteString("INSERT INTO `things` VALUES (" + string(rune('0'+i%10)) + ",'row " + strings.Repeat("y", i%37) + "');\n")
	}
	whole := gzipped(t, sql.String())
	path := writeDump(t, string(whole[:len(whole)/2]))
	for _, failOn := range []string{"none", "high"} {
		code, _, stderr := scanDump(t, "--dump", path, "--fail-on", failOn)
		if code != ExitError {
			t.Errorf("--fail-on %s: status %d, stderr %q", failOn, code, stderr)
		}
	}
}
