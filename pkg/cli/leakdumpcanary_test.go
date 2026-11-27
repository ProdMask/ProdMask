package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hashFileText is a hash file as text, with its hashes, salt and key check
// left out, so that a canary can be looked for in what is left.
func hashFileText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "salt")
	delete(doc, "key_check")
	if cols, ok := doc["columns"].([]any); ok {
		for _, c := range cols {
			if m, ok := c.(map[string]any); ok {
				delete(m, "hashes")
			}
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestLeakDumpNeverPrintsValues puts the scan's canaries in dumps that
// leak-check compare --dump and hash --dump read, and looks for them in
// everything either one writes.
func TestLeakDumpNeverPrintsValues(t *testing.T) {
	t.Setenv(keyEnv, "")
	t.Setenv("PRODMASK_DSN", "")
	t.Setenv("PRODMASK_PASSWORD", "")
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	app := New("1.2.3")
	keyPath := filepath.Join(dir, "leak.key")
	if code, _, stderr := run(app, "leak-check", "key", "--out", keyPath); code != ExitOK {
		t.Fatalf("key: %d\n%s", code, stderr)
	}

	// Production's dump: the canaries sit in its header, a comment, the
	// values of the flagged column and another column.
	var rows []string
	for i := 1; i <= 80; i++ {
		rows = append(rows, fmt.Sprintf("(%d,'zq7canary_em%d@mailbox.prodmask-fixture.dev')", i, i))
	}
	prodBody := dumpHead + "/* zq7canary_cmt */\nCREATE TABLE `ct` (`id` int NOT NULL, `email` varchar(100) DEFAULT NULL, PRIMARY KEY (`id`));\n" +
		"INSERT INTO `ct` VALUES " + strings.Join(rows, ",") + ";\n"
	prod := "-- zq7canary_hdr: a header comment\n" + prodBody
	files := map[string][]byte{
		"prod.sql":    []byte(prod),
		"prod.sql.gz": gzipped(t, prod),
	}
	check := func(name, what, text string) {
		t.Helper()
		if hasCanary(text) {
			t.Errorf("%s: a canary is in %s", name, what)
		}
	}

	hashes := ""
	for name, b := range files {
		out := filepath.Join(dir, "hashes-"+name+".json")
		code, stdout, stderr := run(app, "leak-check", "hash", "--key-file", keyPath, "--dump", write(name, b), "--out", out)
		if code != ExitOK {
			t.Fatalf("hash %s: status %d\n%s%s", name, code, stdout, stderr)
		}
		check("hash "+name, "standard output", stdout)
		if strings.Contains(stderr, name) {
			t.Errorf("hash %s: the file's name is on standard error", name)
		}
		check("hash "+name, "standard error", stderr)
		check("hash "+name, "the hash file", hashFileText(t, out))
		hashes = out
	}
	// Dumps hash can't use end in an error that holds no value.
	bad := map[string]string{"main": canaryDump, "lost": canaryLost, "short": canaryDump[:len(canaryDump)/2]}
	for name, body := range canaryClients {
		bad[name] = body
	}
	for name, body := range bad {
		out := filepath.Join(dir, "hashes-bad-"+name+".json")
		_, stdout, stderr := run(app, "leak-check", "hash", "--key-file", keyPath, "--dump", write("bad-"+name+".sql", []byte(body)), "--out", out)
		check("hash "+name, "standard output", stdout)
		check("hash "+name, "standard error", stderr)
		if _, err := os.Stat(out); err == nil {
			check("hash "+name, "the hash file", hashFileText(t, out))
		}
	}

	whole := gzipped(t, prod)
	compared := map[string][]byte{
		"main":  []byte(canaryDump),
		"lost":  []byte(canaryLost),
		"short": []byte(canaryDump[:len(canaryDump)/2]),
		"gz":    gzipped(t, canaryDump),
		"match": []byte(prod),
		"cut":   whole[:len(whole)/2],
		// An unread statement of a table the dump never created.
		"nostruct": []byte(canaryLost + "INSERT INTO zq7canary_sel SELECT 1;\n"),
	}
	for name, body := range canaryClients {
		compared[name] = []byte(body)
	}
	for name, b := range compared {
		path := write("cmp-"+name+".sql", b)
		for _, extra := range [][]string{nil, {"--fail-on", "high"}, {"--format", "json"}} {
			args := append([]string{"leak-check", "compare", "--key-file", keyPath, "--hashes", hashes, "--no-color", "--dump", path}, extra...)
			code, stdout, stderr := run(app, args...)
			if code == ExitUsage {
				t.Errorf("%s %q: status %d, stderr %q", name, extra, code, stderr)
			}
			if name == "match" && len(extra) == 2 && extra[0] == "--fail-on" && code != ExitFindings {
				t.Errorf("match: status %d, want the findings status: %.300s %.300s", code, stdout, stderr)
			}
			check(name+" "+strings.Join(extra, " "), "standard output", stdout)
			if strings.Contains(stderr, "cmp-"+name) {
				t.Errorf("%s: the file's name is on standard error", name)
			}
			check(name+" "+strings.Join(extra, " "), "standard error", stderr)
		}
		// The same dump on standard input.
		for _, format := range []string{"text", "json"} {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			saved := os.Stdin
			os.Stdin = f
			code, stdout, stderr := run(app, "leak-check", "compare", "--key-file", keyPath, "--hashes", hashes, "--no-color", "--dump", "-", "--format", format)
			os.Stdin = saved
			f.Close()
			if code == ExitUsage {
				t.Errorf("%s stdin %s: status %d, stderr %q", name, format, code, stderr)
			}
			check(name+" stdin "+format, "standard output", stdout)
			check(name+" stdin "+format, "standard error", stderr)
		}
	}
}
