package sqldump

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/fixture"
)

// roundTable is what the server holds for a table, as the driver returns it,
// by primary key.
type roundTable struct {
	pk   []int
	rows map[string][]sql.NullString
	seen int
}

// roundCheck compares each row the reader gives with the server's.
type roundCheck struct {
	BaseVisitor
	t      *testing.T
	db     string
	tables map[string]*roundTable
	cols   map[string][]string
	failed int
}

func (c *roundCheck) Row(r *Row) {
	rt := c.tables[r.Table]
	if rt == nil {
		c.fail("%s: a row of a table the server doesn't have", r.Table)
		return
	}
	rt.seen++
	var key string
	if len(rt.pk) == 0 {
		key = fmt.Sprint(r.Ordinal)
	} else {
		parts := make([]string, len(rt.pk))
		for i, j := range rt.pk {
			parts[i] = string(r.Values[j].Bytes)
		}
		key = strings.Join(parts, "\x00")
	}
	want, ok := rt.rows[key]
	if !ok {
		c.fail("%s: no row on the server with the key %q", r.Table, key)
		return
	}
	for i, v := range r.Values {
		w := want[i]
		isNull := v.Kind == ValNull
		if isNull != !w.Valid || (!isNull && string(v.Bytes) != w.String) || v.Cut {
			c.fail("%s.%s, key %q: the reader has %s %q, the server has %v %q", r.Table, c.cols[r.Table][i], key, kindName(v.Kind), v.Bytes, w.Valid, w.String)
		}
	}
}

func (c *roundCheck) fail(format string, args ...any) {
	c.failed++
	if c.failed <= 20 {
		c.t.Errorf(format, args...)
	}
}

func kindName(k ValueKind) string {
	return [...]string{"NULL", "string", "binary", "hex", "number", "bit", "default"}[k]
}

// valueExpr is the expression that makes the server write a column's literal:
// QUOTE for text and numbers, an X'..' literal from HEX for bytes.
func valueExpr(t *testing.T, table, col, dataType string) string {
	c := quoteIdent(col)
	switch dataType {
	case "binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "uuid", "inet6", "inet4":
		return "IFNULL(CONCAT('X''',HEX(" + c + "),''''),'NULL')"
	case "tinyint", "smallint", "mediumint", "int", "bigint", "decimal", "float", "double", "year",
		"char", "varchar", "tinytext", "text", "mediumtext", "longtext", "enum", "set", "json",
		"date", "datetime", "timestamp", "time":
		return "QUOTE(" + c + ")"
	}
	t.Fatalf("%s.%s: the round trip has no literal for the type %s", table, col, dataType)
	return ""
}

// roundTripDatabase writes each table of the database as a dump whose
// literals the server wrote, reads it, and compares every value with what
// the driver returns for the same row. It returns how many rows it compared.
func roundTripDatabase(ctx context.Context, t *testing.T, admin *sql.DB, db, version string) (tables, rows int) {
	t.Helper()
	trows, err := admin.QueryContext(ctx, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE' ORDER BY 1", db)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for trows.Next() {
		var n string
		if err := trows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	trows.Close()

	check := &roundCheck{t: t, db: db, tables: map[string]*roundTable{}, cols: map[string][]string{}}
	var dump strings.Builder
	fmt.Fprintf(&dump, "-- Server version\t%s\n\nSET sql_mode='NO_AUTO_VALUE_ON_ZERO';\nSET NAMES utf8mb4;\n", version)
	want := map[string]int{}
	for _, name := range names {
		n := buildRoundTable(ctx, t, admin, db, name, check, &dump)
		want[name] = n
	}
	v := &roundSink{roundCheck: check}
	st, err := Read(ctx, strings.NewReader(dump.String()), v, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if st.Unread != 0 {
		t.Errorf("%s: %d statements unread: %+v", db, st.Unread, v.unread)
	}
	for _, name := range names {
		if got := check.tables[name].seen; got != want[name] {
			t.Errorf("%s.%s: the reader gave %d rows, the server has %d", db, name, got, want[name])
		}
		rows += want[name]
	}
	if check.failed > 20 {
		t.Errorf("%d more differences", check.failed-20)
	}
	return len(names), rows
}

// roundSink adds what the unread entries need to the check.
type roundSink struct {
	*roundCheck
	unread []Unread
}

func (s *roundSink) Unread(u Unread) { s.unread = append(s.unread, u) }

// buildRoundTable writes one table's CREATE TABLE and INSERTs, built from the
// server's own quoting, to dump, and keeps what the driver returns for it.
func buildRoundTable(ctx context.Context, t *testing.T, admin *sql.DB, db, table string, check *roundCheck, dump *strings.Builder) int {
	t.Helper()
	qt := quoteIdent(db) + "." + quoteIdent(table)
	crows, err := admin.QueryContext(ctx, "SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION", db, table)
	if err != nil {
		t.Fatal(err)
	}
	var cols, exprs, plain []string
	for crows.Next() {
		var c, dt string
		if err := crows.Scan(&c, &dt); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
		exprs = append(exprs, valueExpr(t, table, c, strings.ToLower(dt)))
		plain = append(plain, quoteIdent(c))
	}
	crows.Close()
	check.cols[table] = cols
	rt := &roundTable{rows: map[string][]sql.NullString{}}
	check.tables[table] = rt

	prows, err := admin.QueryContext(ctx, "SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND INDEX_NAME = 'PRIMARY' ORDER BY SEQ_IN_INDEX", db, table)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for prows.Next() {
		var c string
		if err := prows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		for i, n := range cols {
			if n == c {
				rt.pk = append(rt.pk, i)
			}
		}
		order = append(order, quoteIdent(c))
	}
	prows.Close()
	orderBy := ""
	if len(order) > 0 {
		orderBy = " ORDER BY " + strings.Join(order, ", ")
	}

	// what the driver returns
	n := 0
	drows, err := admin.QueryContext(ctx, "SELECT "+strings.Join(plain, ", ")+" FROM "+qt+orderBy)
	if err != nil {
		t.Fatal(err)
	}
	for drows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := drows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		n++
		var key string
		if len(rt.pk) == 0 {
			key = fmt.Sprint(n)
		} else {
			parts := make([]string, len(rt.pk))
			for i, j := range rt.pk {
				parts[i] = vals[j].String
			}
			key = strings.Join(parts, "\x00")
		}
		rt.rows[key] = vals
	}
	drows.Close()

	// what the server writes
	var create, ignore string
	if err := admin.QueryRowContext(ctx, "SHOW CREATE TABLE "+qt).Scan(&ignore, &create); err != nil {
		t.Fatal(err)
	}
	dump.WriteString(create + ";\n")
	lrows, err := admin.QueryContext(ctx, "SELECT "+strings.Join(exprs, ", ")+" FROM "+qt+orderBy)
	if err != nil {
		t.Fatal(err)
	}
	defer lrows.Close()
	inBatch := 0
	for lrows.Next() {
		vals := make([]sql.RawBytes, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := lrows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		if inBatch == 0 {
			dump.WriteString("INSERT INTO " + quoteIdent(table) + " VALUES\n")
		} else {
			dump.WriteString(",\n")
		}
		dump.WriteByte('(')
		for i, v := range vals {
			if i > 0 {
				dump.WriteByte(',')
			}
			dump.Write(v)
		}
		dump.WriteByte(')')
		if inBatch++; inBatch == 100 {
			dump.WriteString(";\n")
			inBatch = 0
		}
	}
	if inBatch > 0 {
		dump.WriteString(";\n")
	}
	if err := lrows.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}

// tortureStatements makes a table that holds every byte, every escaped
// character, 4-byte UTF-8, latin1, JSON, an empty string and NULL.
func tortureStatements() []string {
	all := make([]byte, 256)
	rev := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
		rev[i] = byte(255 - i)
	}
	h := func(b []byte) string { return "X'" + strings.ToUpper(hex.EncodeToString(b)) + "'" }
	u8 := func(s string) string { return "CONVERT(" + h([]byte(s)) + " USING utf8mb4)" }
	special := "\x00'\"\b\n\r\t\x1a\\%_\\'\\\"\\0 \u00e9\u20ac\U0001F600\U0001D11E ' OR 1=1; -- \x00"
	json := `{"a":"q\"\\n\u00e9\ud83d\ude00","b":[1,2.5,null,true,-0.5e2],"c":{"d":"` + "\U0001F600" + `"},"e":""}`
	stmts := []string{
		"CREATE TABLE torture (id int NOT NULL, vb varbinary(300), bl blob, u8 varchar(300) CHARACTER SET utf8mb4, " +
			"l1 varchar(300) CHARACTER SET latin1, j json, e varchar(10) CHARACTER SET utf8mb4, n varchar(10) CHARACTER SET utf8mb4, PRIMARY KEY (id)) ENGINE=InnoDB",
		"INSERT INTO torture VALUES (1, " + h(all) + ", " + h(rev) + ", " + u8(special) + ", CONVERT(" + h(all) + " USING latin1), '{\"k\": \"v\"}', '', NULL)",
		"INSERT INTO torture VALUES (2, X'', X'', '', '', '\"\"', '', '')",
		"INSERT INTO torture VALUES (3, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
		"INSERT INTO torture VALUES (4, X'5C27', X'0027', " + u8(strings.Repeat("\U0001F600", 50)) + ", CONVERT(" + h([]byte(`\'"`)) + " USING latin1), " + u8(json) + ", '\\\\', '''')",
		"INSERT INTO torture VALUES (5, X'00', X'FF', " + u8(strings.Repeat(`\'""`, 20)) + ", CONVERT(X'E9E8E0' USING latin1), '[]', ' ', '0')",
	}
	for i := 6; i <= 40; i++ { // a run of rows, each with its own bytes
		b := make([]byte, 0, 32)
		for j := 0; j < 32; j++ {
			b = append(b, byte(i*7+j*13))
		}
		stmts = append(stmts, fmt.Sprintf("INSERT INTO torture VALUES (%d, %s, %s, %s, CONVERT(%s USING latin1), '1', 'x', NULL)", i, h(b), h(b), u8(fmt.Sprintf("row %d \\ ' \" \u00e9", i)), h(b)))
	}
	return stmts
}

// TestRowsMatchServer is the round trip: for every table of the fixtures and
// a torture table, the server writes the literals (QUOTE and HEX), the reader
// reads them, and each value must equal what the driver returns.
func TestRowsMatchServer(t *testing.T) {
	admin, version, mariadb := openAdmin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	totalTables, totalRows := 0, 0
	for _, platform := range fixture.Platforms {
		t.Run(platform, func(t *testing.T) {
			db := "prodmask_s3_" + platform
			t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+quoteIdent(db)) })
			if err := fixture.Build(ctx, admin, platform, db, fixture.Options{}); err != nil {
				t.Fatalf("build the fixture: %v", err)
			}
			n, r := roundTripDatabase(ctx, t, admin, db, version)
			totalTables += n
			totalRows += r
		})
	}
	t.Run("torture", func(t *testing.T) {
		db := "prodmask_s3_torture"
		buildTables(ctx, t, admin, db, tortureStatements(), "", "")
		n, r := roundTripDatabase(ctx, t, admin, db, version)
		if n != 1 || r < 40 {
			t.Errorf("%d tables, %d rows", n, r)
		}
		totalTables += n
		totalRows += r
	})
	t.Run("typed", func(t *testing.T) {
		if !mariadb {
			t.Skip("uuid, inet4 and inet6 columns are MariaDB's")
		}
		db := "prodmask_s3_typed"
		stmts := []string{"CREATE TABLE typed (id int NOT NULL PRIMARY KEY, u uuid, a inet6, b inet4)"}
		addrs := []string{"::", "::1", "::2", "::102", "::1:2", "::0.1.0.0", "::1.2.3.4", "::10.0.0.1", "::ffff:1.2.3.4", "::ffff:0:1",
			"2001:db8::1", "2001:db8:0:0:1:0:0:1", "2001:0:0:1:0:0:0:1", "1::", "1:0:2:0:3:0:4:5", "abcd::ef", "64:ff9b::1.2.3.4",
			"fe80::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1:2:3:4:5:6:7:8", "0:0:0:1:0:0:0:0",
			"0:1:2:3:4:5:6:7", "1:2:3:4:5:6:7:0", "1:2:3:0:4:5:6:7", "1:0:0:2:0:0:3:4", "1:0:2:0:0:3:4:5", "0:0:1:0:0:0:2:0"}
		for i, a := range addrs {
			stmts = append(stmts, fmt.Sprintf("INSERT INTO typed VALUES (%d, UUID(), '%s', '10.%d.0.255')", i+1, a, i))
		}
		stmts = append(stmts,
			"INSERT INTO typed VALUES (100, '00000000-0000-0000-0000-000000000000', '::', '0.0.0.0')",
			"INSERT INTO typed VALUES (101, 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'ffff::', '255.255.255.255')",
			"INSERT INTO typed VALUES (102, NULL, NULL, NULL)")
		buildTables(ctx, t, admin, db, stmts, "", "")
		n, r := roundTripDatabase(ctx, t, admin, db, version)
		totalTables += n
		totalRows += r
	})
	t.Logf("%s: %d tables, %d rows compared", version, totalTables, totalRows)
}

// serverKeyCase is a run of statements on one table with an auto-increment
// key; the server and the reader must agree on the keys.
type serverKeyCase struct {
	name string
	opt  string // table options
	pre  []string
	sql  []string
	post []string
	// unknown is set when the reader must call the keys unknown.
	unknown bool
}

const keyRows = "(id bigint unsigned NOT NULL AUTO_INCREMENT, n int NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB"

func serverKeyCases() []serverKeyCase {
	return []serverKeyCase{
		{name: "left_out", sql: []string{"INSERT INTO %s (n) VALUES (1),(2),(3)"}},
		{name: "null", sql: []string{"INSERT INTO %s VALUES (NULL,1),(NULL,2)"}},
		{name: "default", sql: []string{"INSERT INTO %s VALUES (DEFAULT,1),(DEFAULT,2)"}},
		{name: "zero", sql: []string{"INSERT INTO %s VALUES (0,1),(0,2),(0,3)"}},
		{name: "zero_string", sql: []string{"INSERT INTO %s VALUES ('0',1),(0,2)"}},
		{name: "zero_with_mode", pre: []string{"SET SESSION sql_mode='NO_AUTO_VALUE_ON_ZERO'"},
			sql:  []string{"INSERT INTO %s VALUES (0,1),(NULL,2),(5,3),(NULL,4)"},
			post: []string{"SET SESSION sql_mode=''"}},
		{name: "zero_with_concat", pre: []string{"SET SESSION sql_mode = CONCAT(@@sql_mode, ',NO_AUTO_VALUE_ON_ZERO')"},
			sql:  []string{"INSERT INTO %s VALUES (0,1),(NULL,2)"},
			post: []string{"SET SESSION sql_mode=''"}},
		{name: "explicit_between", sql: []string{"INSERT INTO %s VALUES (NULL,1),(10,2),(NULL,3),(5,4),(NULL,5)"}},
		{name: "option", opt: " AUTO_INCREMENT=100", sql: []string{"INSERT INTO %s (n) VALUES (1),(2)", "INSERT INTO %s VALUES (7,3),(NULL,4)"}},
		{name: "option_and_lower_key", opt: " AUTO_INCREMENT=100", sql: []string{"INSERT INTO %s VALUES (7,1),(NULL,2),(150,3),(NULL,4)"}},
		{name: "several_statements", sql: []string{"INSERT INTO %s (n) VALUES (1)", "INSERT INTO %s VALUES (NULL,2),(20,3)", "INSERT INTO %s (n) VALUES (4)"}},
		{name: "string_key", sql: []string{"INSERT INTO %s VALUES ('7',1),(NULL,2)"}},
		{name: "alter", sql: []string{"INSERT INTO %s (n) VALUES (1),(2)", "ALTER TABLE %s AUTO_INCREMENT=40", "INSERT INTO %s (n) VALUES (3)", "ALTER TABLE %s AUTO_INCREMENT=3", "INSERT INTO %s (n) VALUES (4)"}},
		{name: "ignore_and_replace_with_keys", sql: []string{"INSERT IGNORE INTO %s VALUES (1,1),(2,2)", "REPLACE INTO %s VALUES (3,3)", "INSERT INTO %s (n) VALUES (4)"}},
		{name: "big_key", sql: []string{"INSERT INTO %s VALUES (4294967290,1),(NULL,2),(NULL,3)"}},
		{name: "insert_ignore_leaving_key", unknown: true, sql: []string{"INSERT IGNORE INTO %s (n) VALUES (1),(2)"}},
		{name: "replace_leaving_key", unknown: true, sql: []string{"INSERT INTO %s (n) VALUES (1)", "REPLACE INTO %s VALUES (NULL,2),(NULL,3)"}},
	}
}

// TestCountedKeysMatchServer runs the statements of each case on the server,
// one by one, and compares the keys it gave with the keys the reader counted
// from the same text.
func TestCountedKeysMatchServer(t *testing.T) {
	admin, version, _ := openAdmin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db := "prodmask_s3_keys"
	q := quoteIdent(db)
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+q) })
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+q); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+q+" CHARACTER SET utf8mb4"); err != nil {
		t.Fatal(err)
	}
	conn, err := admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "USE "+q); err != nil {
		t.Fatal(err)
	}

	var all []string
	run := func(s string) {
		t.Helper()
		all = append(all, s)
		if _, err := conn.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	run("SET SESSION sql_mode=''")
	cases := serverKeyCases()
	for _, c := range cases {
		table := "k_" + c.name
		run("CREATE TABLE " + table + " " + keyRows + c.opt)
		for _, s := range c.pre {
			run(s)
		}
		for _, s := range c.sql {
			run(strings.ReplaceAll(s, "%s", table))
		}
		for _, s := range c.post {
			run(s)
		}
	}
	run("SET SESSION sql_mode=DEFAULT")

	dump := "-- Server version\t" + version + "\n" + strings.Join(all, ";\n") + ";\n"
	v := &rrec{}
	st, err := Read(ctx, strings.NewReader(dump), v, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if st.Unread != 0 {
		t.Fatalf("unread: %+v", v.unread)
	}
	compared, counted := 0, 0
	for _, c := range cases {
		table := "k_" + c.name
		var theirs []string
		krows, err := conn.QueryContext(ctx, "SELECT id FROM "+table+" ORDER BY n")
		if err != nil {
			t.Fatal(err)
		}
		for krows.Next() {
			var id string
			if err := krows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			theirs = append(theirs, id)
		}
		krows.Close()
		var mine []rowCopy
		for _, r := range v.rows {
			if r.Table == table {
				mine = append(mine, r)
			}
		}
		if len(mine) != len(theirs) {
			t.Errorf("%s: the reader gave %d rows, the server has %d", c.name, len(mine), len(theirs))
			continue
		}
		unknown := false
		for i, r := range mine {
			unknown = unknown || r.KeysUnknown
			if r.Values[0].Kind == ValNull {
				if r.KeyCounted {
					t.Errorf("%s row %d: counted a NULL key", c.name, i+1)
				}
				continue
			}
			compared++
			if r.KeyCounted {
				counted++
			}
			// the key, read as a number, is the server's
			got := string(r.Values[0].Bytes)
			if r.Values[0].Kind == ValString {
				got = strings.TrimLeft(got, "+")
			}
			if got != theirs[i] {
				t.Errorf("%s row %d: the reader has key %s (counted %v), the server gave %s", c.name, i+1, got, r.KeyCounted, theirs[i])
			}
		}
		if unknown != c.unknown {
			t.Errorf("%s: keys unknown = %v, want %v", c.name, unknown, c.unknown)
		}
		after := false
		for i, r := range mine {
			if after && (r.KeyCounted || !r.KeysUnknown) {
				t.Errorf("%s row %d: counted after the keys were unknown: %+v", c.name, i+1, r)
			}
			after = after || r.KeysUnknown
		}
	}
	if counted == 0 {
		t.Error("no counted key was compared")
	}
	t.Logf("%s: %d keys compared, %d of them counted", version, compared, counted)
}
