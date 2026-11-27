package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What --database holds may be a DSN with a password, or a key: neither scan
// --dump nor leak-check's hash --dump and compare --dump repeats it, in an
// error, a report or a hash file, whether it names no database of the dump or
// the dump names none.
func TestDumpCommandsNeverEchoTheDatabase(t *testing.T) {
	t.Setenv(keyEnv, "")
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	const given = "mysql://ro:zq7canary-pw@db.fixture-store.gr:3306/shop"
	dir := t.TempDir()
	app := New("1.2.3")
	keyPath := filepath.Join(dir, "leak.key")
	if code, _, stderr := run(app, "leak-check", "key", "--out", keyPath); code != ExitOK {
		t.Fatalf("key: %d\n%s", code, stderr)
	}
	var rows []string
	for i := 1; i <= 40; i++ {
		rows = append(rows, fmt.Sprintf("(%d,'customer.%d@mailbox.prodmask-fixture.dev')", i, i))
	}
	table := "CREATE TABLE `ct` (`id` int NOT NULL, `email` varchar(100) DEFAULT NULL, PRIMARY KEY (`id`));\n" +
		"INSERT INTO `ct` VALUES " + strings.Join(rows, ",") + ";\n"
	paths := map[string]string{}
	for name, body := range map[string]string{
		"named":   dumpHead + "CREATE DATABASE `shop_one`;\nUSE `shop_one`;\n" + table,
		"unnamed": dumpHead + table,
	} {
		paths[name] = filepath.Join(dir, name+".sql")
		if err := os.WriteFile(paths[name], []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(what, text string) {
		t.Helper()
		if strings.Contains(text, "zq7canary") {
			t.Errorf("%s holds what --database holds:\n%s", what, text)
		}
	}
	hashes := filepath.Join(dir, "hashes.json")
	if code, _, stderr := run(app, "leak-check", "hash", "--key-file", keyPath, "--dump", paths["unnamed"], "--out", hashes); code != ExitOK {
		t.Fatalf("hash: %d\n%s", code, stderr)
	}
	for name, path := range paths {
		for _, format := range []string{"text", "json", "markdown"} {
			_, stdout, stderr := run(app, "scan", "--dump", path, "--database", given, "--format", format)
			check("scan "+name+" "+format+" output", stdout)
			check("scan "+name+" "+format+" error", stderr)
			_, stdout, stderr = run(app, "leak-check", "compare", "--key-file", keyPath, "--hashes", hashes, "--dump", path, "--database", given, "--format", format)
			check("compare "+name+" "+format+" output", stdout)
			check("compare "+name+" "+format+" error", stderr)
		}
		out := filepath.Join(dir, "hashes-"+name+".json")
		_, stdout, stderr := run(app, "leak-check", "hash", "--key-file", keyPath, "--dump", path, "--database", given, "--out", out)
		check("hash "+name+" output", stdout)
		check("hash "+name+" error", stderr)
		if _, err := os.Stat(out); err == nil {
			check("hash "+name+" file", hashFileText(t, out))
		}
	}
}
