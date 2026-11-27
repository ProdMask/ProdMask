package sqldump

import (
	"strings"
	"testing"
)

// TestCharsetTablesMatchServer checks the reader's default collation and
// widest character of every character set the server has.
func TestCharsetTablesMatchServer(t *testing.T) {
	admin, version, mariadb := openAdmin(t)
	rows, err := admin.Query("SELECT CHARACTER_SET_NAME, DEFAULT_COLLATE_NAME, MAXLEN FROM information_schema.CHARACTER_SETS ORDER BY 1")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	f, _ := flavourOfLine("-- Server version	" + version)
	if f.mariadb != mariadb || !strings.Contains(version, ".") {
		t.Fatal("the flavour of the server was not read")
	}
	n := 0
	for rows.Next() {
		var cs, co string
		var maxLen int64
		if err := rows.Scan(&cs, &co, &maxLen); err != nil {
			t.Fatal(err)
		}
		n++
		if got := f.defaultCollation(cs); got != co {
			t.Errorf("%s: the server's default collation is %s, the reader's is %s", cs, co, got)
		}
		if got := bytesPerChar(cs); got != maxLen {
			t.Errorf("%s: the server's widest character is %d bytes, the reader's is %d", cs, maxLen, got)
		}
	}
	t.Logf("%s: %d character sets", version, n)
}
