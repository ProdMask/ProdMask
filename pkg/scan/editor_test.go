package scan_test

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/detect"
)

// checkEditorPaths reads every value of a fixture database and checks that
// the structured editor hands out the leaves Walk gives, with the same
// paths, so rules written for the scan's paths reach the leaves a copy
// edits.
func checkEditorPaths(ctx context.Context, t *testing.T, sess *dbconn.Session) {
	t.Helper()
	tables, err := sess.DB.QueryContext(ctx,
		"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for tables.Next() {
		var n string
		if err := tables.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	tables.Close()
	checked := 0
	for _, name := range names {
		rows, err := sess.DB.QueryContext(ctx, "SELECT * FROM `"+name+"`")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cols, _ := rows.Columns()
		vals := make([]sql.RawBytes, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			for i, v := range vals {
				ok, same := compareEditorPaths(string(v))
				if !same {
					t.Errorf("%s.%s: the editor's leaves differ from Walk's", name, cols[i])
				}
				if ok {
					checked++
				}
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rows.Close()
	}
	if checked == 0 {
		t.Error("no structured values checked")
	}
	t.Logf("%d structured values read alike by the editor and Walk", checked)
}

// compareEditorPaths compares Walk's leaves with the editor's, for a value
// Walk opens and the editor reads whole. ok reports whether both did.
func compareEditorPaths(v string) (ok, same bool) {
	var walked []string
	if !detect.Walk(v, func(path []string, leaf string) { walked = append(walked, detect.JoinPath(path)+"="+leaf) }) {
		return false, true
	}
	var edited []string
	_, _, err := detect.EditStructured(v, func(l detect.Leaf) (string, bool) {
		switch l.Kind {
		case detect.LeafKey:
			if l.DataKey {
				edited = append(edited, detect.JoinPath(append(slices.Clone(l.Path), "{}"))+"="+l.Key)
			}
		case detect.LeafNull:
		default:
			edited = append(edited, detect.JoinPath(l.Path)+"="+l.Value)
		}
		return "", false
	})
	if err != nil {
		return false, true // cut off or over the editor's limits: a copy falls back
	}
	return true, slices.Equal(walked, edited)
}
