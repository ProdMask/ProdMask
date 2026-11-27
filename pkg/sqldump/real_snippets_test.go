package sqldump

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// The files in testdata/real are what the real dump tools wrote for the
// dump-shapes fixture at their default settings: mysqldump 8.4.13 against
// MySQL 8.4.13 and mariadb-dump 11.8.9 against MariaDB 11.8.9. The data is
// invented. The header's Host line was set to localhost.

type snippetVisitor struct {
	BaseVisitor
	header Header
	tables map[string]bool
	rows   map[string]int
	unread []Unread
}

func (v *snippetVisitor) Header(h Header)                     { v.header = h }
func (v *snippetVisitor) Structure(db string, t *model.Table) { v.tables[t.Name] = true }
func (v *snippetVisitor) Row(r *Row)                          { v.rows[r.Table]++ }
func (v *snippetVisitor) Unread(u Unread)                     { v.unread = append(v.unread, u) }

func TestRealToolSnippets(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "real", "*.sql"))
	if err != nil || len(files) != 2 {
		t.Fatalf("snippets: %v, %v", files, err)
	}
	wantRows := map[string]int{
		"shape_latin1": 3, "shape_nopk": 4, "shape_keys": 3, "shape_types": 2, "shape_fk_parent": 2,
		"shape_fk_child": 2, "shape_charsets": 1, "shape_memory": 2, "shape_myisam": 2,
	}
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
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
			if st.Statements() < 100 || st.Structure < 20 {
				t.Errorf("too few statements: %d, %d structure", st.Statements(), st.Structure)
			}
			wantProducer := "mysqldump 8.4.13"
			if strings.HasPrefix(name, "mariadb") {
				wantProducer = "mariadb-dump 11.8.9"
			}
			if v.header.Producer != wantProducer {
				t.Errorf("producer %q, want %q", v.header.Producer, wantProducer)
			}
			for _, tbl := range []string{"shape_latin1", "shape_types", "shape_view", "shape_fk_child"} {
				if !v.tables[tbl] {
					t.Errorf("no structure for %s", tbl)
				}
			}
			for tbl, n := range wantRows {
				if v.rows[tbl] != n {
					t.Errorf("%s: %d rows, want %d", tbl, v.rows[tbl], n)
				}
			}
			if _, err := os.Stat(f); err != nil {
				t.Fatal(err)
			}
		})
	}
}
