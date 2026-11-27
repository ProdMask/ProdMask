package sqldump

import (
	"context"
	"path/filepath"
	"testing"
)

// The files in testdata/handwritten are hand-written in the formats the
// dump tools write, from their documented output, with invented values:
// mysqldump 5.7, 8.0 and 9.x, mariadb-dump 10.11, mysqldump-php and
// phpMyAdmin. None is a capture of a real tool's run. Each holds a header,
// one table and three rows, and every statement of it is read.
func TestHandwrittenFormats(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "handwritten", "*.sql"))
	if err != nil || len(files) != 6 {
		t.Fatalf("snippets: %v, %v", files, err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			r, _, err := Open(f, false)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			v := &snippetVisitor{tables: map[string]bool{}, rows: map[string]int{}}
			st, err := Read(context.Background(), r, v, testOpts())
			if err != nil {
				t.Fatal(err)
			}
			if st.Unread != 0 || len(v.unread) != 0 {
				t.Errorf("%d unread statements: %+v", st.Unread, v.unread)
			}
			if !v.tables["customers"] || v.rows["customers"] != 3 || st.Rows != 3 {
				t.Errorf("tables %v, rows %v", v.tables, v.rows)
			}
		})
	}
}
