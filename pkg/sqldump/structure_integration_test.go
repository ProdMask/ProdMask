package sqldump

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/introspect"
	"github.com/ProdMask/ProdMask/pkg/model"
)

// structures collects the last structure the reader gave for each table.
type structures struct {
	BaseVisitor
	db     string
	tables map[string]*model.Table
	calls  int
}

func (s *structures) Structure(db string, t *model.Table) {
	if db == s.db {
		s.tables[t.Name] = t
		s.calls++
	}
}

func openAdmin(t *testing.T) (*sql.DB, string, bool) {
	t.Helper()
	cfg, err := mysql.ParseDSN(testdb.DSN(t))
	if err != nil {
		t.Fatal("the test DSN doesn't parse")
	}
	cfg.MultiStatements = true
	cfg.DBName = ""
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	t.Cleanup(func() { admin.Close() })
	var version string
	if err := admin.QueryRow("SELECT VERSION()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	return admin, version, strings.Contains(strings.ToLower(version), "mariadb")
}

// buildTables drops and creates a database, with the statements run in a
// session that has the SQL mode given.
func buildTables(ctx context.Context, t *testing.T, admin *sql.DB, db string, stmts []string, mode, trigger string) {
	t.Helper()
	q := quoteIdent(db)
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+q) })
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+q); err != nil {
		t.Fatalf("drop %s: %v", db, err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+q+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatalf("create %s: %v", db, err)
	}
	conn, err := admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "USE "+q); err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if trigger != "" {
		if _, err := conn.ExecContext(ctx, "SET SESSION sql_mode = '"+mode+"'"); err != nil {
			t.Fatal(err)
		}
		_, err := conn.ExecContext(ctx, trigger)
		// the connection goes back to the pool, so its mode must too
		if _, e := conn.ExecContext(ctx, "SET SESSION sql_mode = DEFAULT"); e != nil {
			t.Fatal(e)
		}
		if err != nil {
			t.Fatalf("%s: %v", trigger, err)
		}
	}
}

// dumpStructure writes what a dump of the database's structure holds: the
// header's server version, CREATE DATABASE, and each object's SHOW CREATE.
func dumpStructure(ctx context.Context, t *testing.T, admin *sql.DB, db, version string) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "-- Server version\t%s\n\nSET sql_mode='';\nSET NAMES utf8mb4;\n", version)
	var name, create string
	if err := admin.QueryRowContext(ctx, "SHOW CREATE DATABASE "+quoteIdent(db)).Scan(&name, &create); err != nil {
		t.Fatal(err)
	}
	b.WriteString(create + ";\nUSE " + quoteIdent(db) + ";\n")
	rows, err := admin.QueryContext(ctx, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME", db)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		r, err := admin.QueryContext(ctx, "SHOW CREATE TABLE "+quoteIdent(db)+"."+quoteIdent(n))
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := r.Columns()
		vals := make([]sql.RawBytes, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if !r.Next() {
			t.Fatalf("SHOW CREATE TABLE %s gave nothing", n)
		}
		if err := r.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		b.WriteString(string(vals[1]) + ";\n")
		r.Close()
	}
	return b.String()
}

// compareDatabase reads the dump of a database and compares each table with
// introspect's, field by field. It returns how many tables it compared.
func compareDatabase(ctx context.Context, t *testing.T, admin *sql.DB, db, version string) int {
	t.Helper()
	dump := dumpStructure(ctx, t, admin, db, version)
	v := &structures{db: db, tables: map[string]*model.Table{}}
	if _, err := Read(ctx, strings.NewReader(dump), v, testOpts()); err != nil {
		t.Fatalf("read the dump of %s: %v", db, err)
	}
	schema, err := introspect.Load(ctx, admin, db)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range schema.Tables {
		got := v.tables[want.Name]
		if got == nil {
			t.Errorf("%s.%s: the reader gave no structure", db, want.Name)
			continue
		}
		for _, d := range diffTables(got, want) {
			t.Errorf("%s.%s", db, d)
		}
	}
	for name := range v.tables {
		if schema.Table(name) == nil {
			t.Errorf("%s.%s: the reader gave a table the server doesn't have", db, name)
		}
	}
	return len(schema.Tables)
}

// diffTables compares a table read from a dump with the one introspect
// loaded, in every field but RowsEstimate and DataBytes, and names each
// difference by its table, column and field. Views and sequences are compared
// by name and type only. The order of the indexes and of the foreign keys is
// not compared: information_schema lists them by name.
func diffTables(got, want *model.Table) []string {
	var out []string
	add := func(where, field string, g, w any) {
		if !reflect.DeepEqual(g, w) {
			out = append(out, fmt.Sprintf("%s: %s = %#v, introspect has %#v", where, field, g, w))
		}
	}
	tn := want.Name
	add(tn, "Name", got.Name, want.Name)
	add(tn, "Type", got.Type, want.Type)
	if want.Type == "VIEW" || want.Type == "SEQUENCE" {
		return out
	}
	add(tn, "Engine", got.Engine, want.Engine)
	add(tn, "Comment", got.Comment, want.Comment)
	add(tn, "PrimaryKey", got.PrimaryKey, want.PrimaryKey)
	if len(got.Columns) != len(want.Columns) {
		out = append(out, fmt.Sprintf("%s: has %d columns, introspect has %d", tn, len(got.Columns), len(want.Columns)))
	} else {
		for i, w := range want.Columns {
			g := got.Columns[i]
			c := tn + "." + w.Name
			add(c, "Name", g.Name, w.Name)
			add(c, "Position", g.Position, w.Position)
			add(c, "DataType", g.DataType, w.DataType)
			add(c, "ColumnType", g.ColumnType, w.ColumnType)
			add(c, "Nullable", g.Nullable, w.Nullable)
			add(c, "MaxLength", g.MaxLength, w.MaxLength)
			add(c, "OctetLength", g.OctetLength, w.OctetLength)
			add(c, "Charset", g.Charset, w.Charset)
			add(c, "Collation", g.Collation, w.Collation)
			add(c, "Key", g.Key, w.Key)
			add(c, "Extra", g.Extra, w.Extra)
			add(c, "Comment", g.Comment, w.Comment)
		}
	}
	gi, wi := sortedIndexes(got.Indexes), sortedIndexes(want.Indexes)
	if len(gi) != len(wi) {
		out = append(out, fmt.Sprintf("%s: has %d indexes, introspect has %d (%v and %v)", tn, len(gi), len(wi), indexNames(gi), indexNames(wi)))
	} else {
		for i, w := range wi {
			g := gi[i]
			c := tn + ".index " + w.Name
			add(c, "Name", g.Name, w.Name)
			add(c, "Unique", g.Unique, w.Unique)
			add(c, "Type", g.Type, w.Type)
			add(c, "Columns", g.Columns, w.Columns)
			add(c, "SubParts", g.SubParts, w.SubParts)
		}
	}
	if len(got.Indexes) > 0 && got.Indexes[0].Name != "PRIMARY" && hasIndex(got.Indexes, "PRIMARY") {
		out = append(out, tn+": PRIMARY is not the first index")
	}
	gf, wf := sortedFKs(got.ForeignKeys), sortedFKs(want.ForeignKeys)
	if len(gf) != len(wf) {
		out = append(out, fmt.Sprintf("%s: has %d foreign keys, introspect has %d", tn, len(gf), len(wf)))
	} else {
		for i, w := range wf {
			g := gf[i]
			c := tn + ".foreign key " + w.Name
			add(c, "Name", g.Name, w.Name)
			add(c, "Columns", g.Columns, w.Columns)
			add(c, "RefSchema", g.RefSchema, w.RefSchema)
			add(c, "RefTable", g.RefTable, w.RefTable)
			add(c, "RefColumns", g.RefColumns, w.RefColumns)
		}
	}
	return out
}

func hasIndex(ix []model.Index, name string) bool {
	for _, x := range ix {
		if x.Name == name {
			return true
		}
	}
	return false
}

func indexNames(ix []model.Index) []string {
	var n []string
	for _, x := range ix {
		n = append(n, x.Name)
	}
	return n
}

func sortedIndexes(ix []model.Index) []model.Index {
	out := append([]model.Index(nil), ix...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sortedFKs(fk []model.ForeignKey) []model.ForeignKey {
	out := append([]model.ForeignKey(nil), fk...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// TestStructureMatchesIntrospect parses SHOW CREATE TABLE of every table of
// the fixtures and compares the structure with the one introspect reads from
// information_schema.
func TestStructureMatchesIntrospect(t *testing.T) {
	admin, version, mariadb := openAdmin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	total := 0
	for _, platform := range fixture.Platforms {
		t.Run(platform, func(t *testing.T) {
			db := "prodmask_s2_" + platform
			t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+quoteIdent(db)) })
			if err := fixture.Build(ctx, admin, platform, db, fixture.Options{}); err != nil {
				t.Fatalf("build the fixture: %v", err)
			}
			total += compareDatabase(ctx, t, admin, db, version)
		})
	}
	fixtures := []struct {
		name, trigger string
		ddl           []string
	}{
		{"multisite", "", multisiteDDL()},
		{"fits", "", fitsDDL()},
		{"shapes", "trigger", shapesDDL(mariadb)},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			db := "prodmask_s2_" + f.name
			mode, trigger := "", ""
			if f.trigger != "" {
				mode, trigger = shapesTrigger()
			}
			buildTables(ctx, t, admin, db, f.ddl, mode, trigger)
			total += compareDatabase(ctx, t, admin, db, version)
		})
	}
	t.Logf("%s: %d tables compared", version, total)
}
