// Package testdb gives the tests that need a database server its address.
package testdb

import (
	"os"
	"testing"
)

// DSN returns PRODMASK_TEST_DSN, a server where the tests may create
// databases. Without it a server test is skipped, so that a plain
// go test ./... passes with no database. With PRODMASK_TEST_REQUIRE_ALL set,
// to anything but 0, the test fails instead, so that a run meant to test
// against a server can't pass by skipping.
func DSN(t testing.TB) string {
	t.Helper()
	dsn, skip, fail := lookup(os.Getenv)
	switch {
	case fail != "":
		t.Fatal(fail)
	case skip != "":
		t.Skip(skip)
	}
	return dsn
}

// lookup reads the environment through getenv, and returns the DSN, or why
// the test is skipped or fails.
func lookup(getenv func(string) string) (dsn, skip, fail string) {
	if dsn = getenv("PRODMASK_TEST_DSN"); dsn != "" {
		return dsn, "", ""
	}
	if required := getenv("PRODMASK_TEST_REQUIRE_ALL"); required != "" && required != "0" {
		return "", "", "PRODMASK_TEST_DSN is not set, and PRODMASK_TEST_REQUIRE_ALL asks every server test to run"
	}
	return "", "PRODMASK_TEST_DSN is not set", ""
}
