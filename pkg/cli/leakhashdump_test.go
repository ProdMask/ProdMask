package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hashDumpHead = "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\nCREATE DATABASE `shop`;\nUSE `shop`;\n"

const hashDumpTable = "CREATE TABLE `customers` (`id` bigint NOT NULL, `email` varchar(190) DEFAULT NULL, PRIMARY KEY (`id`)) ENGINE=InnoDB;\n"

const hashDumpMembers = "CREATE TABLE `members` (`id` bigint NOT NULL, `email` varchar(190)) ENGINE=InnoDB;\n"

func hashDumpRows(table, domain string, n int) string {
	var rows []string
	for i := 1; i <= n; i++ {
		rows = append(rows, fmt.Sprintf("(%d,'customer.%d@%s')", i, i, domain))
	}
	return "INSERT INTO `" + table + "` VALUES " + strings.Join(rows, ",") + ";\n"
}

func TestLeakHashDumpFlagErrors(t *testing.T) {
	t.Setenv(keyEnv, "")
	dir := t.TempDir()
	out := filepath.Join(dir, "h.json")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--out", out, "--dsn", "mysql://u@x/d", "--dump", "d.sql"}, "--dsn doesn't go with --dump"},
		{[]string{"--out", out, "--dump", "d.sql", "--timeout", "5s"}, "--timeout doesn't go with --dump"},
		{[]string{"--out", out, "--database", "shop"}, "--database goes with --dump"},
		{[]string{"--out", out, "--dump", ""}, "--dump is empty"},
		{[]string{"--out", out, "--dump", "-"}, "--dump needs a file's path, not standard input: it reads the file three times"},
	} {
		code, stdout, stderr := run(New("1.2.3"), append([]string{"leak-check", "hash"}, c.args...)...)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%q: status %d\n%s%s", c.args, code, stdout, stderr)
		}
	}
	_, _, stderr := run(New("1.2.3"), "leak-check", "hash", "-h")
	for _, w := range []string{"prodmask leak-check hash --dump FILE --out FILE [flags]", "-dump", "-database", "read three times", "not - for standard input"} {
		if !strings.Contains(stderr, w) {
			t.Errorf("hash -h has no %q:\n%s", w, stderr)
		}
	}
	if _, _, stderr := run(New("1.2.3"), "leak-check", "-h"); !strings.Contains(stderr, "prodmask leak-check hash --dump FILE") {
		t.Errorf("leak-check -h:\n%s", stderr)
	}
}

// TestLeakHashDump runs hash --dump and compare --dump as a user would, with no
// server: what each one exits with, and what no output shows.
func TestLeakHashDump(t *testing.T) {
	t.Setenv(keyEnv, "")
	t.Setenv("PRODMASK_DSN", "")
	const domain = "mailbox.prodmask-fixture.dev"
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	app := New("1.2.3")
	keyPath := filepath.Join(dir, "leak.key")
	if code, _, stderr := run(app, "leak-check", "key", "--out", keyPath); code != ExitOK {
		t.Fatalf("key: %d\n%s", code, stderr)
	}
	hash := func(name string, args ...string) (int, string, string, string) {
		out := filepath.Join(dir, name+".json")
		code, stdout, stderr := run(app, append([]string{"leak-check", "hash", "--key-file", keyPath, "--out", out}, args...)...)
		return code, stdout, stderr, out
	}
	compare := func(hashes string, args ...string) (int, string, string) {
		return run(app, append([]string{"leak-check", "compare", "--key-file", keyPath, "--hashes", hashes, "--no-color"}, args...)...)
	}
	noValues := func(name, text string) {
		t.Helper()
		if strings.Contains(text, "customer.") || strings.Contains(text, dir) {
			t.Errorf("%s: a value or the path is shown:\n%s", name, text)
		}
	}

	prod := write("prod.sql", hashDumpHead+hashDumpTable+hashDumpRows("customers", domain, 80))
	code, stdout, stderr, hashes := hash("ok", "--dump", prod)
	if code != ExitOK || !strings.Contains(stdout, "Hash file written: 80 values sampled from 1 columns of shop.") || !strings.Contains(stdout, "customers.email") ||
		!strings.Contains(stderr, "Sampled up to 3,000 rows of each flagged table in the dump.") {
		t.Fatalf("hash: status %d\n%s%s", code, stdout, stderr)
	}
	noValues("hash", stdout+stderr)

	t.Run("the same dump finds every sampled value", func(t *testing.T) {
		code, stdout, stderr := compare(hashes, "--dump", prod, "--fail-on", "high")
		if code != ExitFindings || !strings.Contains(stderr, "80 of 80 sampled production values found in the dump.") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
		noValues("compare", stdout+stderr)
	})

	t.Run("a masked dump", func(t *testing.T) {
		masked := write("masked.sql", hashDumpHead+hashDumpTable+hashDumpRows("customers", "elsewhere.invalid", 80))
		if code, stdout, stderr := compare(hashes, "--dump", masked, "--fail-on", "high"); code != ExitOK || !strings.Contains(stderr, "0 of 80 sampled") ||
			!strings.Contains(stdout, "Read every value of the 1 column or key in the dump;") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
	})

	t.Run("a statement of the table that wasn't read", func(t *testing.T) {
		unread := write("unread.sql", hashDumpHead+hashDumpTable+hashDumpRows("customers", domain, 80)+
			hashDumpMembers+hashDumpRows("members", domain, 30)+
			"INSERT INTO `customers` SELECT * FROM `customers`;\n")
		code, stdout, stderr, h := hash("unread", "--dump", unread)
		if code != ExitOK || !strings.Contains(stdout, "customers.email  a statement of this table in the dump wasn't read: compare will count it as not read") ||
			!strings.Contains(stdout, "members.email") {
			t.Fatalf("hash: status %d\n%s%s", code, stdout, stderr)
		}
		masked := write("masked2.sql", hashDumpHead+hashDumpTable+hashDumpRows("customers", "elsewhere.invalid", 10)+
			hashDumpMembers+hashDumpRows("members", "elsewhere.invalid", 10))
		code, stdout, stderr = compare(h, "--dump", masked, "--fail-on", "high")
		if code != ExitError || !strings.Contains(stderr, "couldn't be checked in full, so the gate fails") {
			t.Errorf("compare --fail-on high: status %d\n%s%s", code, stdout, stderr)
		}
		if code, _, _ := compare(h, "--dump", masked); code != ExitOK {
			t.Errorf("without --fail-on: status %d", code)
		}
	})

	// Two INSERTs before the delimiter, the second into another table, which
	// the clients both load: the second's table can't be told.
	several := func(domain string) string {
		return hashDumpHead + hashDumpTable + hashDumpMembers + "DELIMITER ;;\n" +
			strings.TrimSuffix(hashDumpRows("customers", domain, 80), "\n") + " " + strings.TrimSuffix(hashDumpRows("members", domain, 30), ";\n") + ";;\nDELIMITER ;\n"
	}

	t.Run("two statements before the delimiter", func(t *testing.T) {
		code, stdout, stderr := compare(hashes, "--dump", write("several.sql", several("elsewhere.invalid")), "--fail-on", "high")
		if code != ExitError || !strings.Contains(stdout, "its table can't be told") || !strings.Contains(stderr, "so the gate fails") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
		noValues("compare several", stdout+stderr)
	})

	t.Run("no file is written", func(t *testing.T) {
		for name, text := range map[string]string{
			"tableless": hashDumpHead + hashDumpTable + hashDumpRows("customers", domain, 80) + "CALL cleanup();\n",
			"mode":      hashDumpHead + hashDumpTable + hashDumpRows("customers", domain, 80) + "SET sql_mode = @unknown;\n",
			"several":   several(domain),
			"version":   hashDumpHead + hashDumpTable + hashDumpRows("customers", domain, 80) + "/*!99999 LOCK TABLES */ " + hashDumpRows("customers", "late.invalid", 1),
		} {
			code, stdout, stderr, h := hash(name, "--dump", write(name+".sql", text))
			if code != ExitError || stdout != "" || !strings.Contains(stderr, "no sample of the dump can be trusted") {
				t.Errorf("%s: status %d\n%s%s", name, code, stdout, stderr)
			}
			if _, err := os.Stat(h); err == nil {
				t.Errorf("%s: a file was written", name)
			}
			noValues(name, stderr)
		}
	})

	t.Run("opening errors name no path", func(t *testing.T) {
		code, stdout, stderr, _ := hash("missing", "--dump", filepath.Join(dir, "no-such-"+keyShaped()+".sql"))
		if code != ExitError || stdout != "" || !strings.Contains(stderr, "the dump file doesn't exist") || strings.Contains(stderr, "no-such") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
		code, _, stderr, _ = hash("dir", "--dump", dir)
		if code != ExitError || !strings.Contains(stderr, "the dump is a directory") || strings.Contains(stderr, dir) {
			t.Errorf("a directory: status %d\n%s", code, stderr)
		}
		code, stdout, stderr, _ = hash("png", "--dump", write("image.png", "\x89PNG\r\n\x1a\n"+strings.Repeat("\x01\x02\x03", 2000)))
		if code != ExitError || stdout != "" || !strings.Contains(stderr, "isn't a dump") {
			t.Errorf("a binary file: status %d\n%s%s", code, stdout, stderr)
		}
	})
}

// A dump that never names its database, as mysqldump writes one database
// without --databases: hash and compare show its name as "an unnamed
// database", and compare with --database reads it as the file's one database,
// as scan --dump does, without repeating what --database holds.
func TestLeakDumpUnnamedDatabase(t *testing.T) {
	t.Setenv(keyEnv, "")
	t.Setenv("PRODMASK_DSN", "")
	dir := t.TempDir()
	app := New("1.2.3")
	keyPath := filepath.Join(dir, "leak.key")
	if code, _, stderr := run(app, "leak-check", "key", "--out", keyPath); code != ExitOK {
		t.Fatalf("key: %d\n%s", code, stderr)
	}
	path := filepath.Join(dir, "unnamed.sql")
	body := "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n" + hashDumpTable + hashDumpRows("customers", "mailbox.prodmask-fixture.dev", 20)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	hashes := filepath.Join(dir, "h.json")
	code, stdout, stderr := run(app, "leak-check", "hash", "--key-file", keyPath, "--dump", path, "--out", hashes)
	if code != ExitOK || !strings.Contains(stdout, "Hash file written: 20 values sampled from 1 columns of an unnamed database.") {
		t.Fatalf("hash: status %d\n%s%s", code, stdout, stderr)
	}
	const given = "zq7canary-db"
	for _, args := range [][]string{nil, {"--database", given}} {
		code, stdout, stderr := run(app, append([]string{"leak-check", "compare", "--key-file", keyPath, "--hashes", hashes, "--no-color",
			"--dump", path, "--fail-on", "high"}, args...)...)
		if code != ExitFindings || !strings.Contains(stdout, "Compared with values sampled from an unnamed database on ") ||
			!strings.Contains(stdout, " 1 of 1 columns read ") || !strings.Contains(stderr, "20 of 20 sampled production values found in the dump.") {
			t.Errorf("compare %q: status %d\n%s%s", args, code, stdout, stderr)
		}
		if strings.Contains(stdout+stderr, given) {
			t.Errorf("compare %q repeats what --database holds", args)
		}
	}
}

// A dump of several databases, with no --database, ends as scan --dump's
// does: a usage error, with status 2.
func TestLeakHashDumpSeveralDatabases(t *testing.T) {
	t.Setenv(keyEnv, "")
	dir := t.TempDir()
	app := New("1.2.3")
	keyPath := filepath.Join(dir, "leak.key")
	if code, _, stderr := run(app, "leak-check", "key", "--out", keyPath); code != ExitOK {
		t.Fatalf("key: %d\n%s", code, stderr)
	}
	table := "CREATE TABLE `ct` (`id` int NOT NULL, `email` varchar(100), PRIMARY KEY (`id`));\n" +
		"INSERT INTO `ct` VALUES (1,'customer.1@mailbox.prodmask-fixture.dev');\n"
	path := filepath.Join(dir, "two.sql")
	body := dumpHead + "CREATE DATABASE `a`;\nUSE `a`;\n" + table + "CREATE DATABASE `b`;\nUSE `b`;\n" + table
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(app, "leak-check", "hash", "--key-file", keyPath, "--dump", path, "--out", filepath.Join(dir, "h.json"))
	if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "several databases") {
		t.Errorf("status %d\n%s%s", code, stdout, stderr)
	}
}
