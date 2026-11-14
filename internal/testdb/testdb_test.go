package testdb

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestOnlyDSNReadsTheVariable keeps every server test on DSN: a test that
// read PRODMASK_TEST_DSN itself would skip without it, whatever
// PRODMASK_TEST_REQUIRE_ALL says. It looks for the variable's name written
// into Getenv or LookupEnv, so it's a tripwire, not a proof.
func TestOnlyDSNReadsTheVariable(t *testing.T) {
	read := regexp.MustCompile(`(Getenv|LookupEnv)\("PRODMASK_TEST_DSN"\)`)
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata"):
			return filepath.SkipDir
		case d.IsDir() || !strings.HasSuffix(path, ".go"):
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if read.Match(data) {
			t.Errorf("%s reads PRODMASK_TEST_DSN itself; call testdb.DSN", filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestLookup checks that a missing DSN skips a server test, and fails it when
// PRODMASK_TEST_REQUIRE_ALL is set to anything but 0.
func TestLookup(t *testing.T) {
	const (
		skipped = "PRODMASK_TEST_DSN is not set"
		failed  = "PRODMASK_TEST_DSN is not set, and PRODMASK_TEST_REQUIRE_ALL asks every server test to run"
	)
	for _, c := range []struct {
		dsn, required    string
		want, skip, fail string
	}{
		{"", "", "", skipped, ""},
		{"", "0", "", skipped, ""},
		{"", "1", "", "", failed},
		{"", "true", "", "", failed},
		{"root@tcp(127.0.0.1:3306)/", "", "root@tcp(127.0.0.1:3306)/", "", ""},
		{"root@tcp(127.0.0.1:3306)/", "1", "root@tcp(127.0.0.1:3306)/", "", ""},
	} {
		env := map[string]string{"PRODMASK_TEST_DSN": c.dsn, "PRODMASK_TEST_REQUIRE_ALL": c.required}
		dsn, skip, fail := lookup(func(name string) string { return env[name] })
		if dsn != c.want || skip != c.skip || fail != c.fail {
			t.Errorf("DSN %q, REQUIRE_ALL %q: got %q, skip %q, fail %q", c.dsn, c.required, dsn, skip, fail)
		}
	}
}
