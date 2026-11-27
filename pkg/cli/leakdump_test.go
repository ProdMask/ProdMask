package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
)

func TestLeakCompareDumpFlagErrors(t *testing.T) {
	t.Setenv(keyEnv, "")
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"compare", "--hashes", "x", "--dsn", "mysql://u@x/d", "--dump", "d.sql"}, "--dsn doesn't go with --dump"},
		{[]string{"compare", "--hashes", "x", "--dump", "d.sql", "--timeout", "5s"}, "--timeout doesn't go with --dump"},
		{[]string{"compare", "--hashes", "x", "--database", "shop"}, "--database goes with --dump"},
		{[]string{"compare", "--hashes", "x", "--dump", ""}, "--dump is empty"},
	}
	for _, c := range cases {
		code, stdout, stderr := run(New("1.2.3"), append([]string{"leak-check"}, c.args...)...)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%q: status %d\n%s%s", c.args, code, stdout, stderr)
		}
	}
	_, _, stderr := run(New("1.2.3"), "leak-check", "compare", "-h")
	for _, w := range []string{"prodmask leak-check compare --dump FILE --hashes FILE [flags]", "-dump", "-database", "--timeout doesn't apply"} {
		if !strings.Contains(stderr, w) {
			t.Errorf("compare -h has no %q:\n%s", w, stderr)
		}
	}
	if _, _, stderr := run(New("1.2.3"), "leak-check", "-h"); !strings.Contains(stderr, "prodmask leak-check compare --dump FILE") {
		t.Errorf("leak-check -h:\n%s", stderr)
	}
}

// TestLeakCompareDumpGate runs compare --dump as a user would, on dumps made
// of a fixture's invented customers, and checks what each one exits with. It
// needs PRODMASK_TEST_DSN.
func TestLeakCompareDumpGate(t *testing.T) {
	dsn := testdb.DSN(t)
	t.Setenv(keyEnv, "")
	t.Setenv("PRODMASK_PASSWORD", "")
	adminCfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("PRODMASK_TEST_DSN doesn't parse")
	}
	adminCfg.DBName = ""
	adminCfg.MultiStatements = true
	connector, err := mysql.NewConnector(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const prod = "prodmask_s8_cli_prod"
	const domain = "mailbox.prodmask-fixture.dev"
	for _, q := range []string{
		"DROP DATABASE IF EXISTS `" + prod + "`",
		"CREATE DATABASE `" + prod + "` CHARACTER SET utf8mb4",
		"CREATE TABLE `" + prod + "`.customers (id bigint NOT NULL PRIMARY KEY, email varchar(190), phone varchar(32)) ENGINE=InnoDB",
	} {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	defer admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS `"+prod+"`")
	var real, masked []string
	for i := 1; i <= 80; i++ {
		real = append(real, fmt.Sprintf("(%d,'customer.%d@%s','+30 69 %d')", i, i, domain, 10000000+i))
		masked = append(masked, fmt.Sprintf("(%d,'someone.%d@elsewhere.%s','+1 202 555 %04d')", i, i, domain, i))
	}
	if _, err := admin.ExecContext(ctx, "INSERT INTO `"+prod+"`.customers VALUES "+strings.Join(real, ",")); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, "ANALYZE TABLE `"+prod+"`.customers"); err != nil {
		t.Fatal(err)
	}
	prodCfg := adminCfg.Clone()
	prodCfg.DBName, prodCfg.MultiStatements = prod, false

	dir := t.TempDir()
	keyPath, hashes := filepath.Join(dir, "leak.key"), filepath.Join(dir, "hashes.json")
	app := New("1.2.3")
	if code, _, stderr := run(app, "leak-check", "key", "--out", keyPath); code != ExitOK {
		t.Fatalf("key: %d\n%s", code, stderr)
	}
	if code, stdout, stderr := run(app, "leak-check", "hash", "--dsn", prodCfg.FormatDSN(), "--key-file", keyPath, "--out", hashes); code != ExitOK ||
		!strings.Contains(stdout, "customers.email") || !strings.Contains(stdout, "customers.phone") {
		t.Fatalf("hash: status %d\n%s%s", code, stdout, stderr)
	}

	const create = "CREATE TABLE `customers` (`id` bigint NOT NULL, `email` varchar(190) DEFAULT NULL, `phone` varchar(32) DEFAULT NULL, PRIMARY KEY (`id`)) ENGINE=InnoDB;\n"
	const top = "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n"
	dump := func(rows []string) string {
		return top + "CREATE DATABASE `shop`;\nUSE `shop`;\n" + create + "INSERT INTO `customers` VALUES " + strings.Join(rows, ",") + ";\n"
	}
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	compare := func(args ...string) (int, string, string) {
		return run(app, append([]string{"leak-check", "compare", "--key-file", keyPath, "--hashes", hashes, "--no-color"}, args...)...)
	}
	noValues := func(name, out string) {
		t.Helper()
		if strings.Contains(out, "customer.") || strings.Contains(out, "+30 69") || strings.Contains(out, "someone.") {
			t.Errorf("%s: a value from the dump is shown:\n%s", name, out)
		}
	}

	t.Run("a masked dump", func(t *testing.T) {
		p := write("masked.sql", dump(masked))
		code, stdout, stderr := compare("--dump", p, "--fail-on", "high")
		if code != ExitOK || !strings.Contains(stdout, "dump file masked.sql") || !strings.Contains(stdout, "Sampled production values found in this dump") ||
			!strings.Contains(stdout, "Read every value of the 2 columns and keys in the dump; production's hashes are a sample of up to 3,000 values of each, so a zero isn't proof.") ||
			!strings.Contains(stderr, "0 of ") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
		noValues("masked", stdout+stderr)
		if strings.Contains(stdout+stderr, p) || strings.Contains(stdout+stderr, dir) {
			t.Errorf("the path is shown:\n%s%s", stdout, stderr)
		}
	})

	t.Run("a dump holding real values", func(t *testing.T) {
		p := write("match.sql", dump(real))
		code, stdout, stderr := compare("--dump", p, "--fail-on", "high")
		if code != ExitFindings || !strings.Contains(stdout, "customers.email") || !strings.Contains(stderr, "sampled production values found in the dump.") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
		noValues("match", stdout+stderr)
		code, stdout, _ = compare("--dump", p, "--format", "json")
		if code != ExitOK || !strings.Contains(stdout, `"dump": {`) || !strings.Contains(stdout, `"file": "match.sql"`) ||
			!strings.Contains(stdout, "so a zero isn't proof.") {
			t.Errorf("json: status %d\n%.400s", code, stdout)
		}
		noValues("match json", stdout)
	})

	t.Run("a gzip dump", func(t *testing.T) {
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		w.Write([]byte(dump(real)))
		w.Close()
		p := write("match.sql.gz", gz.String())
		if code, stdout, _ := compare("--dump", p, "--fail-on", "high"); code != ExitFindings || !strings.Contains(stdout, "dump file match.sql.gz") {
			t.Errorf("status %d\n%s", code, stdout)
		}
	})

	t.Run("a statement of the table that wasn't read", func(t *testing.T) {
		p := write("unread.sql", dump(masked)+"INSERT INTO `customers` SELECT * FROM `customers`;\n")
		code, stdout, stderr := compare("--dump", p, "--fail-on", "high")
		if code != ExitError || !strings.Contains(stdout, "stopped after 80 rows (a statement of this table in the dump wasn't read)") ||
			!strings.Contains(stderr, "couldn't be checked in full, so the gate fails") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
		if code, _, _ := compare("--dump", p); code != ExitOK {
			t.Errorf("without --fail-on: status %d", code)
		}
	})

	t.Run("a statement with no table", func(t *testing.T) {
		p := write("tableless.sql", dump(masked)+"CALL cleanup();\n")
		code, stdout, stderr := compare("--dump", p, "--fail-on", "high")
		if code != ExitError || !strings.Contains(stdout, "its table can't be told") || !strings.Contains(stderr, "so the gate fails") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
		// A hit still comes first.
		p = write("tableless-hit.sql", dump(real)+"CALL cleanup();\n")
		if code, _, _ := compare("--dump", p, "--fail-on", "high"); code != ExitFindings {
			t.Errorf("with a hit: status %d", code)
		}
	})

	t.Run("a column that isn't in the dump", func(t *testing.T) {
		p := write("nocolumn.sql", top+"CREATE TABLE `customers` (`id` bigint, `email` varchar(190));\nINSERT INTO `customers` VALUES (1,'x@elsewhere.prodmask-fixture.dev');\n")
		code, stdout, _ := compare("--dump", p, "--fail-on", "high")
		if code != ExitError || !strings.Contains(stdout, "customers.phone") || !strings.Contains(stdout, "not in the dump") || strings.Contains(stdout, "not on staging") {
			t.Errorf("status %d\n%s", code, stdout)
		}
	})

	t.Run("two databases on standard input", func(t *testing.T) {
		text := top + "CREATE DATABASE `a`;\nUSE `a`;\n" + create + "INSERT INTO `customers` VALUES " + strings.Join(masked, ",") + ";\n" +
			"CREATE DATABASE `b`;\nUSE `b`;\n" + create + "INSERT INTO `customers` VALUES " + strings.Join(real, ",") + ";\n"
		f, err := os.Open(write("two.sql", text))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		saved := os.Stdin
		os.Stdin = f
		defer func() { os.Stdin = saved }()
		code, stdout, stderr := compare("--dump", "-", "--fail-on", "high")
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "--database") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
		noValues("two databases", stdout+stderr)

		// With --database, the one chosen is read.
		for db, want := range map[string]int{"a": ExitOK, "b": ExitFindings} {
			if _, err := f.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := compare("--dump", "-", "--database", db, "--fail-on", "high")
			if code != want || !strings.Contains(stdout, "dump file standard input") {
				t.Errorf("database %s: status %d, want %d\n%s%s", db, code, want, stdout, stderr)
			}
		}
	})

	t.Run("opening errors name no path", func(t *testing.T) {
		secret := filepath.Join(dir, "no-such-"+keyShaped()+".sql")
		code, stdout, stderr := compare("--dump", secret)
		if code != ExitError || stdout != "" || !strings.Contains(stderr, "the dump file doesn't exist") || strings.Contains(stderr, "no-such") {
			t.Errorf("status %d\n%s%s", code, stdout, stderr)
		}
		code, _, stderr = compare("--dump", dir)
		if code != ExitError || !strings.Contains(stderr, "the dump is a directory") || strings.Contains(stderr, dir) {
			t.Errorf("a directory: status %d\n%s", code, stderr)
		}
		p := write("cut.sql.gz", "\x1f\x8b\x08\x00not really gzip")
		code, stdout, stderr = compare("--dump", p)
		if code != ExitError || stdout != "" || strings.Contains(stderr, "not really") || !strings.Contains(stderr, "no SQL statement") {
			t.Errorf("bad gzip: status %d\n%s%s", code, stdout, stderr)
		}
	})

	t.Run("--max-time", func(t *testing.T) {
		p := write("masked2.sql", dump(masked))
		if code, _, stderr := compare("--dump", p, "--max-time", "-1s"); code != ExitUsage || !strings.Contains(stderr, "--max-time can't be negative") {
			t.Errorf("status %d\n%s", code, stderr)
		}
		if code, _, stderr := compare("--dump", p, "--max-time", "1h", "--fail-on", "high"); code != ExitOK {
			t.Errorf("status %d\n%s", code, stderr)
		}
	})
}
