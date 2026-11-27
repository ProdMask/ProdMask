package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/report"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/dump")

const shopDump = "../../examples/shop.sql"

// dumpHead is what a dump starts with, so that the reader knows its mode.
const dumpHead = "-- Server version\t8.4.3\n\nSET sql_mode='NO_AUTO_VALUE_ON_ZERO';\nSET NAMES utf8mb4;\n"

func writeDump(t *testing.T, sql string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "masked.sql")
	if err := os.WriteFile(path, []byte(sql), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func scanDump(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	return run(New("1.2.3"), append([]string{"scan"}, args...)...)
}

// volatile hides what changes from one run to the next: the date and how long
// the scan took.
var volatile = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`in \d+(\.\d+)? ?m?s \(`), "in <time> ("},
	{regexp.MustCompile(`on \d{4}-\d\d-\d\d \d\d:\d\d [A-Z]+`), "on <date>"},
	{regexp.MustCompile(`"generated_at": "[^"]*"`), `"generated_at": "<date>"`},
	{regexp.MustCompile(`"duration_ms": \d+`), `"duration_ms": 0`},
}

func normalise(s string) string {
	for _, v := range volatile {
		s = v.re.ReplaceAllString(s, v.with)
	}
	return s
}

// wrapped is a line break and the indent of the line after it.
var wrapped = regexp.MustCompile(`\n +`)

// joined is a text report with each indented line put on the end of the line
// before it, after one space, so a check finds a sentence the report wrapped
// to its width.
func joined(s string) string { return wrapped.ReplaceAllString(s, " ") }

// The reports on examples/shop.sql, as text, Markdown and JSON, are in
// testdata/dump. With -update the test rewrites them instead, and every line
// that changes must be a change the release means to make.
func TestScanDumpGoldens(t *testing.T) {
	for _, g := range []struct{ file, format string }{
		{"shop.txt", "text"}, {"shop.md", "markdown"}, {"shop.json", "json"},
	} {
		code, stdout, stderr := scanDump(t, "--dump", shopDump, "--format", g.format)
		if code != ExitOK || stderr != "" {
			t.Fatalf("%s: status %d, stderr %q", g.format, code, stderr)
		}
		got := normalise(stdout)
		path := filepath.Join("testdata", "dump", g.file)
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run with -update to write it)", err)
		}
		if got != string(want) {
			t.Errorf("the %s report differs from %s; check each change, then run with -update:\n%s", g.format, path, lineDiff(string(want), got))
		}
	}
	text, _ := os.ReadFile(filepath.Join("testdata", "dump", "shop.txt"))
	if !strings.Contains(joined(string(text)), "orders in HPOS tables") {
		t.Error("the golden doesn't say \"orders in HPOS tables\"")
	}
}

// The closing lines, what a finding is and which rows were judged, are in
// every report on a dump, in every format.
func TestScanDumpClosingLines(t *testing.T) {
	const (
		judged = "Judged up to 300 rows of each table, the ones scan reads on a database, and every key of its key/value tables."
		names  = "Judged names only; no values were read."
		shape  = "A finding is a shape: a masked value can look the same. leak-check compare --dump counts the real production values a dump holds."
		pro    = "prodmask Pro makes masked copies and checks every value of them: https://prodmask.com"
	)
	for _, c := range []struct {
		args   []string
		judged string
	}{
		{nil, judged},
		{[]string{"--sample-rows", "50"}, strings.Replace(judged, "300", "50", 1)},
		{[]string{"--no-samples"}, names},
	} {
		for _, format := range []string{"text", "markdown", "json"} {
			code, stdout, _ := scanDump(t, append([]string{"--dump", shopDump, "--format", format}, c.args...)...)
			if code != ExitOK {
				t.Fatalf("%v %s: status %d", c.args, format, code)
			}
			if format == "text" {
				stdout = joined(stdout)
			}
			if !strings.Contains(stdout, c.judged) {
				t.Errorf("%v %s: no line %q", c.args, format, c.judged)
			}
			if format == "json" {
				// The JSON carries the judged line, which is a fact of the dump, not the others.
				continue
			}
			for _, l := range []string{shape, pro} {
				if !strings.Contains(stdout, l) {
					t.Errorf("%v %s: no line %q", c.args, format, l)
				}
			}
			other := names
			if c.judged == names {
				other = judged
			}
			if strings.Contains(stdout, other) {
				t.Errorf("%v %s: holds the other judged line", c.args, format)
			}
		}
	}
	// A build with an edition has its own line, and none of this one.
	app := New("1.2.3")
	app.Edition = "Pro"
	var out, errOut bytes.Buffer
	app.Run(context.Background(), []string{"scan", "--dump", shopDump}, &out, &errOut)
	if strings.Contains(joined(out.String()), "prodmask Pro makes masked copies") || !strings.Contains(joined(out.String()), shape) {
		t.Errorf("the report of a build with an edition:\n%s", out.String()[max(0, out.Len()-400):])
	}
	// The scan of a database has none of the dump's lines.
	for _, l := range []string{"dump file", "A finding is a shape"} {
		if strings.Contains(report.Headline, l) {
			t.Errorf("%q", l)
		}
	}
}

// A dump with a statement the reader can't read, for each kind of reason, and
// the line the report gives it.
func TestScanDumpUnreadLines(t *testing.T) {
	const tbl = "CREATE TABLE `t` (`id` int NOT NULL, `note` varchar(20) DEFAULT NULL, PRIMARY KEY (`id`));\n"
	for _, c := range []struct{ name, sql, line string }{
		{"expression", tbl + "INSERT INTO `t` VALUES (1,CONCAT('a','b'));\n", "an INSERT into t wasn't read: an expression the reader doesn't evaluate"},
		{"form", tbl + "INSERT INTO `t` SELECT 1,'a';\n", "an INSERT into t wasn't read: this form of INSERT isn't read"},
		{"columns", tbl + "INSERT INTO `t` VALUES (1,'a','b');\n", "an INSERT into t wasn't read: the row's values don't match the table's columns"},
		{"alter", tbl + "ALTER TABLE `t` DROP COLUMN `note`;\n", "an ALTER TABLE of t wasn't read: the ALTER TABLE changes the structure in a way the reader doesn't follow"},
		{"kind", tbl + "OPTIMIZE TABLE `t`;\n", "line 6: a statement wasn't read: this statement kind isn't read"},
		{"end of file", tbl + "INSERT INTO `t` VALUES (1,'a'", "an INSERT into t wasn't read: the file ended inside the statement"},
		{"sql mode", tbl + "SET sql_mode = @mode;\nINSERT INTO `t` VALUES (1,'a');\n", "to the end of the file weren't read: the SQL mode is unknown"},
	} {
		path := writeDump(t, dumpHead+c.sql)
		code, stdout, stderr := scanDump(t, "--dump", path, "--fail-on", "high")
		stdout = joined(stdout)
		if code != ExitError || !strings.Contains(stdout, c.line) || !strings.Contains(stdout, "wasn't read, see Warnings") && !strings.Contains(stdout, "weren't read, see Warnings") {
			t.Errorf("%s: status %d, stdout:\n%s\nstderr: %q", c.name, code, stdout, stderr)
		}
		if !strings.Contains(stderr, "of the dump weren't read, so the check at --fail-on high is incomplete and the gate fails: see the report.") &&
			!strings.Contains(stderr, "statement of the dump wasn't read, so the check at --fail-on high is incomplete and the gate fails: see the report.") {
			t.Errorf("%s: stderr %q", c.name, stderr)
		}
	}
}

// The gate, case by case, through the command line.
func TestScanDumpGate(t *testing.T) {
	const (
		quiet  = "CREATE TABLE `t` (`id` int NOT NULL, `note` varchar(20) DEFAULT NULL, PRIMARY KEY (`id`));\n"
		people = "CREATE TABLE `people` (`id` int NOT NULL, `email` varchar(100) DEFAULT NULL, PRIMARY KEY (`id`));\n" +
			"INSERT INTO `people` VALUES (1,'customer.one@fixture-store.gr'),(2,'customer.two@fixture-store.gr');\n"
		unread = "INSERT INTO `t` VALUES (1,CONCAT('a','b'));\n"
	)
	two := func(inA, inB string) string {
		return "CREATE DATABASE `a`;\nUSE `a`;\n" + inA + "CREATE DATABASE `b`;\nUSE `b`;\n" +
			strings.ReplaceAll(strings.ReplaceAll(inB, "`t`", "`u`"), "`people`", "`people2`")
	}
	cases := []struct {
		name   string
		sql    string
		args   []string
		code   int
		stdout string // a part the report must hold
		stderr string // a part standard error must hold
	}{
		{"unread fails the gate", quiet + unread, []string{"--fail-on", "high"}, ExitError, "wasn't read", "the gate fails"},
		{"findings first", people + quiet + unread, []string{"--fail-on", "high"}, ExitFindings, "wasn't read", "found high-severity items"},
		{"no fail-on", people + quiet + unread, nil, ExitOK, "wasn't read", ""},
		{"fail-on none", quiet + unread, []string{"--fail-on", "none"}, ExitOK, "wasn't read", ""},
		{"nothing unread", quiet + "INSERT INTO `t` VALUES (1,'a');\n", []string{"--fail-on", "low"}, ExitOK, "every statement was read", ""},
		{"no rows", quiet, []string{"--fail-on", "low"}, ExitOK, "the dump holds no rows, so no values were judged", ""},
		{"another database", two(quiet, quiet+unread), []string{"--database", "a", "--fail-on", "high"}, ExitOK, "wasn't read", ""},
		{"the database checked", two(quiet, quiet+unread), []string{"--database", "b", "--fail-on", "high"}, ExitError, "wasn't read", "the gate fails"},
		{"an unknown database", two(quiet, quiet+"UPDATE `zz` SET `a` = 1;\n"), []string{"--database", "a", "--fail-on", "high"}, ExitError, "an UPDATE statement wasn't read", "the gate fails"},
		{"several databases", two(quiet, quiet), nil, ExitUsage, "", "name one with --database"},
		{"a database it doesn't hold", two(quiet, quiet), []string{"--database", "c"}, ExitUsage, "", "holds no tables of the database"},
	}
	for _, c := range cases {
		code, stdout, stderr := scanDump(t, append([]string{"--dump", writeDump(t, dumpHead+c.sql)}, c.args...)...)
		if code != c.code || !strings.Contains(stdout, c.stdout) || !strings.Contains(stderr, c.stderr) {
			t.Errorf("%s: status %d, want %d\nstdout:\n%s\nstderr: %q", c.name, code, c.code, stdout, stderr)
		}
		if c.code == ExitUsage && stdout != "" {
			t.Errorf("%s: a report on a usage mistake", c.name)
		}
	}
}

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(s))
	zw.Close()
	return b.Bytes()
}

func TestScanDumpFiles(t *testing.T) {
	var sql strings.Builder
	sql.WriteString(dumpHead)
	sql.WriteString("CREATE TABLE `people` (`id` int NOT NULL, `email` varchar(100) DEFAULT NULL, PRIMARY KEY (`id`));\n")
	for i := range 3000 {
		sql.WriteString("INSERT INTO `people` VALUES (" + string(rune('0'+i%10)) + ",'" + strings.Repeat("x", 40) + "@fixture-store.gr');\n")
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	whole := gzipped(t, sql.String())

	// A gzip file reads like a plain one.
	code, stdout, stderr := scanDump(t, "--dump", write("whole.sql.gz", whole), "--fail-on", "high")
	if code != ExitFindings || !strings.Contains(stdout, "dump file whole.sql.gz (MySQL 8.4.3)") {
		t.Errorf("a gzip dump: status %d, stderr %q\n%s", code, stderr, stdout)
	}

	// A cut one gives its report, judged by names in one pass, then exit 1,
	// whatever --fail-on says.
	cut := write("cut.sql.gz", whole[:len(whole)*2/3])
	for _, failOn := range []string{"none", "high"} {
		code, stdout, stderr = scanDump(t, "--dump", cut, "--fail-on", failOn)
		if code != ExitError || !strings.Contains(stdout, "dump file cut.sql.gz") || !strings.Contains(stdout, "Judged names only") ||
			!strings.Contains(stdout, "(one pass)") || !strings.Contains(stderr, "the dump could not be read to its end") {
			t.Errorf("a cut gzip dump (--fail-on %s): status %d, stderr %q\n%s", failOn, code, stderr, stdout)
		}
	}

	// A file that isn't SQL gives no report.
	bin := make([]byte, 4096)
	for i := range bin {
		bin[i] = byte(i*7 + i>>3)
	}
	code, stdout, stderr = scanDump(t, "--dump", write("image.png", append([]byte("\x89PNG\r\n\x1a\n"), bin...)))
	if code != ExitError || stdout != "" || !strings.Contains(stderr, "isn't a dump") {
		t.Errorf("a binary file: status %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	// Errors on opening are fixed texts, with no path.
	for name, want := range map[string]string{
		"missing.sql": "the dump file doesn't exist",
		"":            "the dump is a directory",
	} {
		p := filepath.Join(dir, name)
		code, stdout, stderr = scanDump(t, "--dump", p)
		if code != ExitError || stdout != "" || !strings.Contains(stderr, want) || strings.Contains(stderr, dir) {
			t.Errorf("%q: status %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
	}
	code, _, stderr = scanDump(t, "--dump", write("a.zst", []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0, 0, 0}))
	if code != ExitError || !strings.Contains(stderr, "zstd") || strings.Contains(stderr, dir) {
		t.Errorf("zstd: status %d, stderr %q", code, stderr)
	}
}

// Each combination of flags with --dump, and the refusals.
func TestScanDumpFlags(t *testing.T) {
	path := writeDump(t, dumpHead+"CREATE TABLE `t` (`id` int);\nINSERT INTO `t` VALUES (1);\n")
	existing := filepath.Join(t.TempDir(), "report.txt")
	os.WriteFile(existing, []byte("x"), 0o600)
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--dsn", "root@tcp(db:3306)/x"}, ExitUsage, "--dsn doesn't go with --dump"},
		{[]string{"--project", "."}, ExitUsage, "--project doesn't go with --dump"},
		{[]string{"--timeout", "20s"}, ExitUsage, "--timeout doesn't go with --dump"},
		{[]string{"--meta-sample-rows", "20"}, ExitUsage, "--meta-sample-rows doesn't go with --dump"},
		{[]string{"--config-out", filepath.Join(t.TempDir(), "c.yml")}, ExitUsage, "--config-out doesn't go with --dump"},
		{[]string{"--dsn", ""}, ExitUsage, "--dsn doesn't go with --dump"},
		{[]string{"--sample-rows", "0"}, ExitUsage, "--sample-rows"},
		{[]string{"--out", existing}, ExitUsage, "already exists"},
		{[]string{"--out", existing, "--force"}, ExitOK, ""},
		{[]string{"--sample-rows", "5", "--preset", "none", "--no-color", "--verbose", "--format", "md"}, ExitOK, ""},
		{[]string{"--no-samples", "--database", "x"}, ExitOK, ""},
	} {
		code, _, stderr := scanDump(t, append([]string{"--dump", path}, c.args...)...)
		if code != c.code || !strings.Contains(stderr, c.want) {
			t.Errorf("%q: status %d, want %d, stderr %q", c.args, code, c.code, stderr)
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--dump", "-"}, "--dump needs a file's path"},
		{[]string{"--dump", ""}, "--dump is empty"},
		{[]string{"--database", "x"}, "--database goes with --dump"},
	} {
		code, stdout, stderr := scanDump(t, c.args...)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%q: status %d, stdout %q, stderr %q", c.args, code, stdout, stderr)
		}
	}

	// $PRODMASK_DSN isn't read, and a line says so, only when it's set.
	t.Setenv("PRODMASK_DSN", "root:zq7canary-pw@tcp(db.example.test:3306)/x")
	code, _, stderr := run(New("1.2.3"), "scan", "--dump", path)
	if code != ExitOK || !strings.Contains(stderr, "$PRODMASK_DSN isn't used with --dump.") || strings.Contains(stderr, "zq7canary") {
		t.Errorf("with $PRODMASK_DSN: status %d, stderr %q", code, stderr)
	}
	code, _, stderr = scanDump(t, "--dump", path)
	if code != ExitOK || stderr != "" {
		t.Errorf("without it: status %d, stderr %q", code, stderr)
	}

	// The usage text says what --dump reads and what it doesn't check.
	_, _, help := run(New("1.2.3"), "scan", "-h")
	for _, s := range []string{"-dump string", "-database string", "reads the file twice", "side effects", "IDENTIFIED BY"} {
		if !strings.Contains(help, s) {
			t.Errorf("scan -h has no %q", s)
		}
	}
}

// A path typed in the wrong place may be a secret, so no error repeats it.
func TestScanDumpNeverEchoesArguments(t *testing.T) {
	for _, v := range []string{"mysql://ro:zq7canary-pw@db.example.test:3306/shop", "zq7canarykey0123456789abcdef"} {
		for _, args := range [][]string{{"--dump", v}, {"--dump=" + v}, {"--dump", v, "--database", v}} {
			code, stdout, stderr := scanDump(t, args...)
			if code != ExitError || stdout != "" || strings.Contains(stderr, "zq7canary") {
				t.Errorf("%q: status %d, stdout %q, stderr %q", args, code, stdout, stderr)
			}
		}
	}
	code, _, stderr := scanDump(t, "--dump", "x.sql", "zq7canary-arg")
	if code != ExitUsage || strings.Contains(stderr, "zq7canary") {
		t.Errorf("an argument of its own: status %d, stderr %q", code, stderr)
	}
}

// What the canary dump holds, in each kind of place. No output may hold any
// of them.
const canaryDump = "-- zq7canary_hdr: a header comment\n" + dumpHead + `
/* zq7canary_cmt */
CREATE TABLE ` + "`ct`" + ` (
  ` + "`id`" + ` int NOT NULL AUTO_INCREMENT,
  ` + "`email`" + ` varchar(100) DEFAULT NULL,
  ` + "`c`" + ` char(40) DEFAULT NULL,
  ` + "`txt`" + ` text,
  ` + "`mtxt`" + ` mediumtext,
  ` + "`b`" + ` blob,
  ` + "`vb`" + ` varbinary(60) DEFAULT NULL,
  ` + "`j`" + ` json DEFAULT NULL,
  ` + "`e`" + ` enum('a','b') DEFAULT NULL,
  ` + "`s`" + ` set('a','b') DEFAULT NULL,
  ` + "`dt`" + ` datetime DEFAULT NULL,
  ` + "`d`" + ` decimal(10,2) DEFAULT NULL,
  ` + "`n`" + ` int DEFAULT NULL,
  ` + "`ser`" + ` longtext,
  ` + "`sqltext`" + ` text,
  PRIMARY KEY (` + "`id`" + `)
);
INSERT INTO ` + "`ct`" + ` VALUES
(1,'zq7canary_em@example.test','zq7canary_char','zq7canary_text','zq7canary_mtext',X'7a713763616e6172795f626c6f62',
 'zq7canary_vb','{"email":"zq7canary_json@example.test","k":"zq7canary_jv"}','a','b','zq7canary_dt',1.5,7,
 'a:2:{s:5:"email";s:26:"zq7canary_php@example.test";s:4:"name";s:15:"zq7canary_pname";}',
 'x''); CREATE TABLE zq7canary_inj (a int); INSERT INTO zq7canary_inj VALUES (''zq7canary_injv'''),
(2,'zq7canary_em2@example.test','a','b','c',X'00ff','d','{}','b','a','2024-01-02 03:04:05',2.5,8,'zq7canary_ser','y');
CREATE TABLE ` + "`wp_options`" + ` (
  ` + "`option_id`" + ` bigint unsigned NOT NULL AUTO_INCREMENT,
  ` + "`option_name`" + ` varchar(191) NOT NULL DEFAULT '',
  ` + "`option_value`" + ` longtext NOT NULL,
  ` + "`autoload`" + ` varchar(20) NOT NULL DEFAULT 'yes',
  PRIMARY KEY (` + "`option_id`" + `),
  UNIQUE KEY ` + "`option_name`" + ` (` + "`option_name`" + `)
);
INSERT INTO ` + "`wp_options`" + ` VALUES
(1,'zq7canary_key','zq7canary_value','yes'),
(2,'admin_email','zq7canary_admin@example.test','yes'),
(3,'zq7canary_serial','a:1:{s:5:"email";s:28:"zq7canary_optphp@example.test";}','no');
INSERT INTO ` + "`ct`" + ` VALUES (3,CONCAT('zq7canary_unread','x'),'a','b','c',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO ` + "`ct`" + ` (id, email) SELECT 9, 'zq7canary_select';
UPDATE ` + "`ct`" + ` SET email = 'zq7canary_update';
INSERT INTO nostruct VALUES (1,'zq7canary_nostruct@example.test','zq7canary_nostruct2');
CREATE VIEW vw AS SELECT 'zq7canary_view' AS x;
DELIMITER ;;
CREATE TRIGGER trg BEFORE INSERT ON ` + "`ct`" + ` FOR EACH ROW BEGIN SET NEW.c = 'zq7canary_trigger'; END ;;
DELIMITER ;
SET NAMES zq7canary_cs;
INSERT INTO ` + "`ct`" + ` (id, c) VALUES (10, 'zq7canary_charset');
CREATE USER 'u'@'h' IDENTIFIED BY 'zq7canary_createpw';
GRANT ALL ON *.* TO 'u2'@'h' IDENTIFIED BY 'zq7canary_grantpw';
`

// A statement after a lost position: a string that never ends.
const canaryLost = dumpHead + "CREATE TABLE `t` (`id` int, `email` varchar(60));\n" +
	"INSERT INTO `t` VALUES (1,'zq7canary_lost@example.test);\n" +
	"INSERT INTO zq7canary_late VALUES ('zq7canary_after');\nINSERT INTO `t` VALUES (2,'zq7canary_end);\n"

// A client's own commands, and a version comment some servers skip, with a
// canary in them and after them: nothing of either is shown.
const canaryClientHead = dumpHead + "CREATE TABLE `t` (`id` int, `email` varchar(60));\nINSERT INTO `t` VALUES (1,'zq7canary_before@example.test');\n"

var canaryClients = map[string]string{
	"use":     canaryClientHead + "use zq7canary_usedb\nINSERT INTO `t` VALUES (2,'zq7canary_afteruse@example.test');\n",
	"bsu":     canaryClientHead + "\\u zq7canary_bsudb\nINSERT INTO `t` VALUES (3,'zq7canary_afterbsu@example.test');\n",
	"afterg":  canaryClientHead + "SET NAMES utf8mb4 \\g INSERT INTO `t` VALUES (4,'zq7canary_afterg@example.test');\n",
	"version": canaryClientHead + "/*!99999 SET @v = 'zq7canary_inside' */ INSERT INTO `t` VALUES (5,'zq7canary_afterversion@example.test');\n",
}

func hasCanary(s string) bool {
	return strings.Contains(s, "zq7canary") || strings.Contains(strings.NewReplacer("\n", "", "\r", "").Replace(s), "zq7canary")
}

// No output of any format holds a value from the file.
func TestScanDumpNeverPrintsValues(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var cutBody strings.Builder
	cutBody.WriteString(dumpHead + "CREATE TABLE `t` (`id` int, `email` varchar(60));\n")
	for i := range 4000 {
		cutBody.WriteString("INSERT INTO `t` VALUES (" + string(rune('0'+i%10)) + ",'zq7canary_cut" + strings.Repeat("a", i%50) + "@example.test');\n")
	}
	whole := gzipped(t, cutBody.String())
	files := map[string]string{
		"main": write("main.sql", []byte(canaryDump)),
		"lost": write("lost.sql", []byte(canaryLost)),
		// An unread statement of a table the dump never created: its name is a value.
		"nostruct": write("nostruct.sql", []byte(canaryLost+"INSERT INTO zq7canary_sel SELECT 1;"+"\n")),
		"cut":      write("cut.sql.gz", whole[:len(whole)/2]),
		"gz":       write("whole.sql.gz", gzipped(t, canaryDump)),
		"short":    write("short.sql", []byte(canaryDump[:len(canaryDump)/2])),
	}
	for name, text := range canaryClients {
		files[name] = write(name+".sql", []byte(text))
	}
	found := map[string]int{}
	for name, path := range files {
		for _, extra := range [][]string{
			nil, {"--verbose"}, {"--no-samples"}, {"--preset", "none", "--verbose"}, {"--fail-on", "low"}, {"--sample-rows", "1"},
		} {
			for _, format := range []string{"text", "markdown", "json"} {
				args := append([]string{"--dump", path, "--format", format}, extra...)
				code, stdout, stderr := scanDump(t, args...)
				if code == ExitUsage {
					t.Errorf("%s %q: status %d, stderr %q", name, args[2:], code, stderr)
				}
				if hasCanary(stdout) || hasCanary(stderr) {
					t.Errorf("%s %q: a canary is in the output (status %d)", name, args[2:], code)
				}
				found[name] += len(stdout)
			}
		}
	}
	for name, n := range found {
		if n == 0 {
			t.Errorf("%s: no report was written", name)
		}
	}

	// A report written to a file.
	for _, p := range []string{files["main"], files["lost"]} {
		for _, f := range []string{"--verbose"} {
			_, stdout, _ := scanDump(t, "--dump", p, f, "--out", filepath.Join(dir, "out-"+filepath.Base(p)+".txt"), "--force")
			if stdout != "" {
				t.Errorf("--out wrote the report to standard output")
			}
			b, err := os.ReadFile(filepath.Join(dir, "out-"+filepath.Base(p)+".txt"))
			if err != nil || hasCanary(string(b)) {
				t.Errorf("the file given to --out: %v", err)
			}
		}
	}
	// The main file's findings are there: the canaries sat in values the scan judged.
	_, stdout, _ := scanDump(t, "--dump", files["main"], "--verbose")
	for _, want := range []string{"email address", "wp_options", "nostruct", "wasn't read", "the dump creates 2 database users"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the canary dump's report has no %q:\n%s", want, stdout)
		}
	}
}

// lineDiff lists the lines only in want (-) and only in got (+), as pkg/scan's
// golden tests print them.
func lineDiff(want, got string) string {
	count := map[string]int{}
	for _, l := range strings.Split(strings.TrimSuffix(want, "\n"), "\n") {
		count[l]++
	}
	for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		count[l]--
	}
	var out []string
	for l, n := range count {
		for ; n > 0; n-- {
			out = append(out, "- "+l)
		}
		for ; n < 0; n++ {
			out = append(out, "+ "+l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][2:] < out[j][2:] || (out[i][2:] == out[j][2:] && out[i] < out[j]) })
	return strings.Join(out, "\n")
}

// The bodies a dump holds are counted, each view once: the real tools'
// snippets hold one trigger and one view, which they write twice, as a
// placeholder and as itself. The JSON report counts them too, with the
// statements that can set a password, and names what a dump scan doesn't
// check.
func TestScanDumpBodies(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "sqldump", "testdata", "real", "*.sql"))
	if err != nil || len(files) != 2 {
		t.Fatalf("snippets: %v, %v", files, err)
	}
	for _, f := range files {
		_, stdout, _ := scanDump(t, "--dump", f)
		if !strings.Contains(stdout, "The bodies of 1 trigger and 1 view aren't judged.") {
			t.Errorf("%s:\n%s", filepath.Base(f), stdout)
		}
		_, stdout, _ = scanDump(t, "--dump", f, "--format", "json")
		for _, w := range []string{`"not_checked": [`, `"side_effects"`, `"triggers": 1`, `"routines": 0`, `"views": 1`, `"user_statements": 0`} {
			if !strings.Contains(stdout, w) {
				t.Errorf("%s: the JSON report has no %s", filepath.Base(f), w)
			}
		}
	}
}
