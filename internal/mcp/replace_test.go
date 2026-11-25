package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// naive is a query an agent might send, and, for a renamed column, the
// table column each label stands for.
type naive struct {
	sql     string
	renamed map[string]string
}

// flags are what the scan reports at medium confidence or higher: columns,
// and key/value tables' keys.
type flags struct {
	columns map[string]map[string]bool // table → lower-case column
	// paths are a column's flagged paths inside JSON or serialized values,
	// where step 5 replaces only those leaves: there, the leaves are the
	// cells compared.
	paths map[string]map[string]map[string]bool // table → lower-case column → path
	keys  map[string][]string                   // table → keys and key patterns
	kv    map[string]model.TableSummary
	metas map[string]*preset.MetaTable // how the scan reads each key/value table's keys
}

func readFlags(res *model.Result) flags {
	f := flags{columns: map[string]map[string]bool{}, paths: map[string]map[string]map[string]bool{}, keys: map[string][]string{},
		kv: map[string]model.TableSummary{}}
	for _, ts := range res.Tables {
		if ts.Kind == "key/value" {
			f.kv[ts.Name] = ts
		}
	}
	for _, fd := range res.Findings {
		if fd.Confidence < model.ConfidenceMedium || fd.KeyName {
			continue
		}
		if fd.MetaKey != "" {
			f.keys[fd.Table] = append(f.keys[fd.Table], fd.MetaKey)
			continue
		}
		if fd.Path != "" {
			col := strings.ToLower(fd.Column)
			if f.paths[fd.Table] == nil {
				f.paths[fd.Table] = map[string]map[string]bool{}
			}
			if f.paths[fd.Table][col] == nil {
				f.paths[fd.Table][col] = map[string]bool{}
			}
			f.paths[fd.Table][col][fd.Path] = true
			continue
		}
		if f.columns[fd.Table] == nil {
			f.columns[fd.Table] = map[string]bool{}
		}
		f.columns[fd.Table][strings.ToLower(fd.Column)] = true
	}
	return f
}

// keyFlagged reports whether a key/value row's key is one the scan flags,
// read as the scan reads it: by its label's shown form, a family's pattern,
// or as a hidden key when its name may hold data.
func (f flags) keyFlagged(table, key string) bool {
	label, shown := key, detect.ShowKey(key)
	if m := f.metas[table]; m != nil {
		if m.Label != nil {
			label = m.Label(key)
			shown = detect.ShowKey(label)
		}
		if m.Guard && detect.FreeTextKey(key) {
			shown = detect.HiddenKey
		}
	}
	for _, k := range f.keys[table] {
		if k == shown || k != detect.HiddenKey && strings.Contains(k, "*") && glob(k, label) {
			return true
		}
	}
	return false
}

func glob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) || !strings.HasSuffix(s, parts[len(parts)-1]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return true
}

// naiveQueries are an agent's naive queries for a fixture: SELECT * on each
// table with findings, a read by primary key, a renamed column, key/value
// reads with and without the key, the joins the scan found, SHOW CREATE
// TABLE, and a GROUP BY on each email column.
func naiveQueries(ctx context.Context, t *testing.T, admin *sql.DB, schema *model.Schema, res *model.Result, f flags) []naive {
	var out []naive
	for _, tbl := range schema.Tables {
		if !tbl.IsData() || (len(f.columns[tbl.Name]) == 0 && len(f.keys[tbl.Name]) == 0 && len(f.paths[tbl.Name]) == 0) {
			continue
		}
		q := func(s string, a ...any) string { return fmt.Sprintf(s, a...) }
		out = append(out, naive{sql: q("SELECT * FROM `%s`", tbl.Name)}, naive{sql: q("SHOW CREATE TABLE `%s`", tbl.Name)})
		if pk := tbl.SinglePK(); pk != nil {
			var first sql.NullString
			if admin.QueryRowContext(ctx, q("SELECT `%s` FROM `%s` LIMIT 1", pk.Name, tbl.Name)).Scan(&first) == nil && first.Valid {
				out = append(out, naive{sql: q("SELECT * FROM `%s` WHERE `%s` = '%s'", tbl.Name, pk.Name, strings.ReplaceAll(first.String, "'", "''"))})
			}
		}
		if ts, ok := f.kv[tbl.Name]; ok {
			out = append(out, naive{sql: q("SELECT `%s`, `%s` FROM `%s`", ts.KeyColumn, ts.ValueColumn, tbl.Name)},
				naive{sql: q("SELECT `%s` FROM `%s`", ts.ValueColumn, tbl.Name)})
		}
		renamed := false
		for _, c := range tbl.Columns {
			if !f.columns[tbl.Name][strings.ToLower(c.Name)] {
				continue
			}
			if !renamed && (c.DataType == "varchar" || c.DataType == "text" || c.DataType == "char") {
				renamed = true
				out = append(out, naive{sql: q("SELECT `%s` AS label FROM `%s`", c.Name, tbl.Name), renamed: map[string]string{"label": c.Name}})
			}
		}
	}
	for _, fd := range res.Findings {
		if fd.Category == model.CatEmail && fd.MetaKey == "" && fd.Path == "" && fd.Confidence >= model.ConfidenceMedium {
			out = append(out, naive{sql: fmt.Sprintf("SELECT `%s`, COUNT(*) FROM `%s` GROUP BY `%s`", fd.Column, fd.Table, fd.Column)})
		}
	}
	seen := map[string]bool{}
	for _, r := range res.Relationships {
		key := r.ChildTable + ">" + r.ParentTable
		if seen[key] || r.ChildTable == r.ParentTable || len(r.ChildColumns) != 1 || len(r.ParentColumns) != 1 {
			continue
		}
		seen[key] = true
		out = append(out, naive{sql: fmt.Sprintf("SELECT * FROM `%s` c JOIN `%s` p ON p.`%s` = c.`%s`",
			r.ChildTable, r.ParentTable, r.ParentColumns[0], r.ChildColumns[0])})
	}
	return out
}

// strings collects every JSON string in a tool's answer.
func answerStrings(text string) []string {
	var v any
	if json.Unmarshal([]byte(text), &v) != nil {
		return []string{text}
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// TestReplacementOnFixtures: for each naive query on each fixture,
// every cell of the admin's result for the same statement whose column or
// key the scan reports at medium confidence or higher isn't in any JSON
// string of the answer, compared whole under 8 characters and as a
// substring from 8 up, skipping values also in an unflagged column of the
// same result; and no planted secret appears anywhere.
func TestReplacementOnFixtures(t *testing.T) {
	cfg, err := mysql.ParseDSN(testdb.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName, cfg.MultiStatements = "", true
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	builder := sql.OpenDB(connector)
	defer builder.Close()
	for _, platform := range fixture.Platforms {
		t.Run(platform, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			database := "prodmask_fixture_kit_" + platform
			var planted fixture.Planted
			if err := fixture.Build(ctx, builder, platform, database, fixture.Options{Canary: "kitcanary7q", Planted: &planted}); err != nil {
				t.Fatalf("build: %v", err)
			}
			defer builder.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+database)
			dbCfg := cfg.Clone()
			dbCfg.MultiStatements, dbCfg.DBName = false, database
			sess, err := dbconn.Open(ctx, dbCfg, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			res, err := scan.Run(ctx, sess, scan.Options{SampleRows: scan.DefaultSampleRows, MetaSampleRows: scan.DefaultMetaSampleRows,
				Samples: true, Preset: "auto"})
			if err != nil {
				t.Fatal(err)
			}
			f := readFlags(res)

			readerCfg := dbCfg.Clone()
			readerCfg.ColumnsWithAlias = true
			rc, err := mysql.NewConnector(readerCfg)
			if err != nil {
				t.Fatal(err)
			}
			admin := sql.OpenDB(rc)
			defer admin.Close()
			schemaSess := sess

			c := startClient(t, Options{Config: dbCfg, AllowWrite: true, MaxRows: 1000})
			conn, failure := c.server.connection(ctx)
			if conn == nil || conn.refusal != "" {
				t.Fatalf("not served: %s %v", failure, conn)
			}
			f.metas = map[string]*preset.MetaTable{}
			for name := range f.kv {
				if tbl := conn.schema.Table(name); tbl != nil {
					f.metas[name] = scan.KeyValueTable(tbl, conn.presets)
				}
			}
			queries := naiveQueries(ctx, t, admin, conn.schema, res, f)
			_ = schemaSess
			var all []string
			checked := 0
			for _, q := range queries {
				text, isErr := c.tool("query", map[string]any{"sql": q.sql})
				if isErr {
					t.Logf("%s: %s", q.sql, text)
					continue
				}
				out := answerStrings(text)
				all = append(all, out...)
				checked += checkCells(ctx, t, admin, q, f, out)
			}
			for _, v := range planted.Values {
				for _, s := range all {
					if strings.Contains(s, v) {
						t.Errorf("a planted secret appears in an answer")
						break
					}
				}
			}
			t.Logf("%d naive queries, %d flagged cells checked, %d planted secrets", len(queries), checked, len(planted.Values))
			if checked == 0 {
				t.Error("no flagged cell was checked, so the test shows nothing")
			}
		})
	}
}

// checkCells runs the statement as the admin and checks each flagged cell
// against the answer's strings. It returns how many cells it checked.
func checkCells(ctx context.Context, t *testing.T, admin *sql.DB, q naive, f flags, out []string) int {
	rows, err := admin.QueryContext(ctx, q.sql)
	if err != nil {
		t.Errorf("the admin's %s: %v", q.sql, err)
		return 0
	}
	defer rows.Close()
	names, _ := rows.Columns()
	al := dbconn.StatementAliases(q.sql)
	type source struct{ table, column string }
	src := make([]source, len(names))
	for i, n := range names {
		alias, label, ok := strings.Cut(n, ".")
		if !ok {
			continue
		}
		table := al.Tables[strings.ToLower(alias)]
		if col, ok := q.renamed[label]; ok {
			label = col
		}
		src[i] = source{table, label}
	}
	var cells [][]sql.NullString
	for rows.Next() {
		row := make([]sql.NullString, len(names))
		dest := make([]any, len(names))
		for i := range row {
			dest[i] = &row[i]
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		cells = append(cells, row)
	}
	flagged := func(row []sql.NullString, i int) bool {
		s := src[i]
		if s.table == "" {
			return false
		}
		if f.columns[s.table][strings.ToLower(s.column)] {
			return true
		}
		ts, ok := f.kv[s.table]
		if !ok || !strings.EqualFold(s.column, ts.ValueColumn) {
			return false
		}
		for j, o := range src {
			if o.table == s.table && strings.EqualFold(o.column, ts.KeyColumn) && row[j].Valid {
				return f.keyFlagged(s.table, row[j].String)
			}
		}
		return len(f.keys[s.table]) > 0 // the key isn't in the result: any key could be flagged
	}
	// A value that also appears in an unflagged cell, whole or inside its
	// text, is skipped: the answer may show it there.
	var plain []string
	exact := map[string]bool{}
	for _, row := range cells {
		for i, v := range row {
			if v.Valid && !flagged(row, i) {
				plain = append(plain, v.String)
				exact[v.String] = true
			}
		}
	}
	inPlain := func(v string) bool {
		if exact[v] {
			return true
		}
		if len(v) < 8 {
			return false
		}
		for _, p := range plain {
			if strings.Contains(p, v) {
				return true
			}
		}
		return false
	}
	// A column flagged at paths is compared by the values at those paths.
	values := func(row []sql.NullString, i int) []string {
		v := row[i]
		if !v.Valid || v.String == "" {
			return nil
		}
		if flagged(row, i) {
			return []string{v.String}
		}
		paths := f.paths[src[i].table][strings.ToLower(src[i].column)]
		if len(paths) == 0 {
			return nil
		}
		var out []string
		detect.Walk(v.String, func(path []string, leaf string) {
			if paths[detect.JoinPath(path)] && leaf != "" {
				out = append(out, leaf)
			}
		})
		return out
	}
	n := 0
	for _, row := range cells {
		for i := range row {
			for _, v := range values(row, i) {
				if inPlain(v) {
					continue
				}
				n++
				for _, s := range out {
					if len(v) < 8 && s == v || len(v) >= 8 && strings.Contains(s, v) {
						key := ""
						for j, o := range src {
							if ts, ok := f.kv[o.table]; ok && o.table == src[i].table && strings.EqualFold(o.column, ts.KeyColumn) {
								key = detect.ShowKey(row[j].String)
							}
						}
						t.Errorf("%s: a flagged value of %s.%s (%d characters, key %q) is in the answer", q.sql, src[i].table, src[i].column, len(v), key)
						break
					}
				}
			}
		}
	}
	return n
}
