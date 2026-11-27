package leak

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/model"
)

// dumpOf writes a database as a dump file: SHOW CREATE TABLE for each base
// table, and its rows as INSERTs of the server's own QUOTE, or X'..' for a
// column of bytes, as mysqldump writes them.
func dumpOf(ctx context.Context, t *testing.T, admin *sql.DB, db string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("/*!40101 SET NAMES utf8mb4 */;\nSET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\nCREATE DATABASE `" + db + "`;\nUSE `" + db + "`;\n")
	var tables []string
	rows, err := admin.QueryContext(ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_type = 'BASE TABLE' ORDER BY 1", db)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	for _, tbl := range tables {
		var name, ddl string
		if err := admin.QueryRowContext(ctx, "SHOW CREATE TABLE `"+db+"`.`"+tbl+"`").Scan(&name, &ddl); err != nil {
			t.Fatal(err)
		}
		b.WriteString(ddl + ";\n")
		var exprs []string
		cols, err := admin.QueryContext(ctx, "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position", db, tbl)
		if err != nil {
			t.Fatal(err)
		}
		for cols.Next() {
			var c, typ string
			if err := cols.Scan(&c, &typ); err != nil {
				t.Fatal(err)
			}
			q := "`" + strings.ReplaceAll(c, "`", "``") + "`"
			switch typ {
			case "binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob":
				exprs = append(exprs, "IFNULL(CONCAT('X''', HEX("+q+"), ''''), 'NULL')")
			default:
				exprs = append(exprs, "QUOTE("+q+")")
			}
		}
		cols.Close()
		data, err := admin.QueryContext(ctx, "SELECT CONCAT('(', "+strings.Join(exprs, ", ',', ")+", ')') FROM `"+db+"`.`"+tbl+"`")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for data.Next() {
			var tuple string
			if err := data.Scan(&tuple); err != nil {
				t.Fatal(err)
			}
			switch {
			case n%200 == 0:
				if n > 0 {
					b.WriteString(";\n")
				}
				b.WriteString("INSERT INTO `" + tbl + "` VALUES " + tuple)
			default:
				b.WriteString("," + tuple)
			}
			n++
		}
		data.Close()
		if n > 0 {
			b.WriteString(";\n")
		}
	}
	return b.String()
}

// sameColumns fails the test where two results differ in a column's state or
// counts.
func sameColumns(t *testing.T, live, dump *model.LeakResult) {
	t.Helper()
	if len(live.Columns) != len(dump.Columns) {
		t.Fatalf("%d columns on the database, %d in the dump", len(live.Columns), len(dump.Columns))
	}
	for i, a := range live.Columns {
		b := dump.Columns[i]
		type counts struct {
			loc, kind, state, stopped       string
			sampled, found                  int
			rows, values, skipped, rowsRead int64
		}
		ca := counts{a.Location(), string(a.Kind), a.State, a.StoppedBy, a.Sampled, a.Found, a.Rows, a.Values, a.ValuesSkipped, a.RowsRead}
		cb := counts{b.Location(), string(b.Kind), b.State, b.StoppedBy, b.Sampled, b.Found, b.Rows, b.Values, b.ValuesSkipped, b.RowsRead}
		if ca != cb {
			t.Errorf("column %d: the database gives %+v, the dump %+v", i, ca, cb)
		}
		if a.State != model.LeakRead && a.State == b.State && b.Found == 0 && b.Line == a.Line && a.State != model.LeakNotOnStaging {
			t.Errorf("%s: a dump's line says %q", b.Location(), b.Line)
		}
	}
	ls, ds := live.Summary, dump.Summary
	ls.DurationMillis, ds.DurationMillis = 0, 0
	if ls != ds {
		t.Errorf("summary: the database gives %+v, the dump %+v", ls, ds)
	}
}

// TestCompareDumpMatchesCompare: a masked copy of production read on its
// server, and the same copy written as a dump, give the same columns, states
// and counts.
func TestCompareDumpMatchesCompare(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	key := testKey(t)
	const prod, stag = "prodmask_s8_prod", "prodmask_s8_stag"
	for _, db := range []string{prod, stag} {
		if err := fixture.Build(ctx, admin, "wordpress", db, fixture.Options{}); err != nil {
			t.Fatalf("build %s: %v", db, err)
		}
		t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS `"+db+"`") })
	}
	f := hashDB(ctx, t, cfg, prod, key, HashOptions{})
	if len(f.Columns) < 3 {
		t.Fatalf("%d columns in the hash file", len(f.Columns))
	}

	// What the copy keeps: half the users' addresses, every phone masked, and
	// two flagged columns gone, one with its table.
	exec(ctx, t, admin, "UPDATE `"+stag+"`.wp_users SET user_email = CONCAT('user.', ID, '@elsewhere.prodmask-fixture.dev') WHERE ID MOD 2 = 0")
	exec(ctx, t, admin, "UPDATE `"+stag+"`.wp_usermeta SET meta_value = CONCAT('+1 202 555 ', LPAD(umeta_id MOD 10000, 4, '0')) WHERE meta_key = 'billing_phone'")
	exec(ctx, t, admin, "ALTER TABLE `"+stag+"`.wp_users DROP COLUMN user_url")
	dropped := ""
	for _, c := range f.Columns {
		if c.Table != "wp_users" && c.Table != "wp_usermeta" {
			dropped = c.Table
			break
		}
	}
	if dropped != "" {
		exec(ctx, t, admin, "DROP TABLE `"+stag+"`.`"+dropped+"`")
	}

	live := compareDB(ctx, t, cfg, stag, f, key, CompareOptions{})
	dump, err := CompareDump(ctx, strings.NewReader(dumpOf(ctx, t, admin, stag)), f, key, CompareDumpOptions{Version: "test", File: "stag.sql"})
	if err != nil {
		t.Fatal(err)
	}
	sameColumns(t, live, dump)

	read, hits := 0, 0
	for _, c := range dump.Columns {
		if c.State == model.LeakRead {
			read++
		}
		if c.Found > 0 {
			hits++
		}
	}
	if read == 0 || hits == 0 || (dropped != "" && read == len(dump.Columns)) {
		t.Errorf("%d of %d columns read, %d with hits: the copy doesn't test what it should (dropped %q)", read, len(dump.Columns), hits, dropped)
	}
	if dump.Dump.Unread != 0 {
		t.Errorf("%d statements unread: %+v", dump.Dump.Unread, dump.Dump.UnreadList)
	}
	if testing.Verbose() {
		t.Log(fmt.Sprintf("%d columns, %d read, %d with hits, %d rows", len(dump.Columns), read, hits, dump.Dump.Rows))
	}

	// And the full copy, whole.
	exec(ctx, t, admin, "DROP DATABASE `"+stag+"`")
	if err := fixture.Build(ctx, admin, "wordpress", stag, fixture.Options{}); err != nil {
		t.Fatal(err)
	}
	live = compareDB(ctx, t, cfg, stag, f, key, CompareOptions{})
	dump, err = CompareDump(ctx, strings.NewReader(dumpOf(ctx, t, admin, stag)), f, key, CompareDumpOptions{File: "stag.sql"})
	if err != nil {
		t.Fatal(err)
	}
	sameColumns(t, live, dump)
	for _, c := range dump.Columns {
		if c.State != model.LeakRead || c.Found != c.Sampled {
			t.Errorf("%s: %s, found %d of %d on a full copy", c.Location(), c.State, c.Found, c.Sampled)
		}
	}
}
