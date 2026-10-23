package introspect

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// TestLoadColumns builds prodmask_fixture_introspect on the server in
// PRODMASK_TEST_DSN, as the scan's integration tests do, and checks the
// lengths, character sets and collations Load reads.
func TestLoadColumns(t *testing.T) {
	dsn := os.Getenv("PRODMASK_TEST_DSN")
	if dsn == "" {
		t.Skip("PRODMASK_TEST_DSN is not set")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName = ""
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	const database = "prodmask_fixture_introspect"
	for _, q := range []string{
		"DROP DATABASE IF EXISTS " + database,
		"CREATE DATABASE " + database + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		"CREATE TABLE " + database + `.t (
			id INT NOT NULL PRIMARY KEY,
			name VARCHAR(10) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL,
			email VARCHAR(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
			code CHAR(4) CHARACTER SET utf16 COLLATE utf16_general_ci NULL,
			note TEXT,
			ip VARBINARY(16) NULL
		)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	s, err := Load(ctx, db, database)
	if err != nil {
		t.Fatal(err)
	}
	tab := s.Table("t")
	if tab == nil {
		t.Fatal("table t not loaded")
	}
	want := map[string]struct {
		charset, collation string
		maxLen, octetLen   int64
	}{
		"id":    {"", "", 0, 0},
		"name":  {"latin1", "latin1_swedish_ci", 10, 10},
		"email": {"utf8mb4", "utf8mb4_bin", 20, 80},
		"code":  {"utf16", "utf16_general_ci", 4, 16},
		"ip":    {"", "", 16, 16},
	}
	for name, w := range want {
		c := tab.Column(name)
		if c == nil {
			t.Errorf("column %s not loaded", name)
			continue
		}
		if c.Charset != w.charset || c.Collation != w.collation || c.MaxLength != w.maxLen || c.OctetLength != w.octetLen {
			t.Errorf("%s: charset %q, collation %q, lengths %d and %d; want %q, %q, %d and %d", name,
				c.Charset, c.Collation, c.MaxLength, c.OctetLength, w.charset, w.collation, w.maxLen, w.octetLen)
		}
	}
	// TEXT's limit is in bytes; servers differ in the characters they report.
	if c := tab.Column("note"); c == nil || c.Charset != "utf8mb4" || c.Collation != "utf8mb4_unicode_ci" ||
		c.OctetLength != 65535 || c.MaxLength <= 0 {
		t.Errorf("note: %+v", c)
	}
}
