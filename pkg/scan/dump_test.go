package scan

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
	"github.com/ProdMask/ProdMask/pkg/sqldump"
)

// --- windows ---

// refWindow is the live sampler's three reads, written from its SQL: the
// ordinals of the rows it returns, in order. keys[i] belongs to ordinal i+1.
func refWindow(limit int, keys []*big.Int) []int64 {
	n := len(keys)
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return keys[idx[a]].Cmp(keys[idx[b]]) < 0 })
	var out []int64
	seen := map[int]bool{}
	take := func(i int) {
		if !seen[i] {
			seen[i] = true
			out = append(out, int64(i+1))
		}
	}
	lo, hi := keys[idx[0]], keys[idx[n-1]]
	span := new(big.Int).Sub(hi, lo)
	if span.Cmp(big.NewInt(int64(limit)*2)) <= 0 {
		for _, i := range idx[:min(limit, n)] {
			take(i)
		}
		return out
	}
	k := max(limit/3, 1)
	mid := new(big.Int).Add(lo, new(big.Int).Div(span, big.NewInt(2)))
	for _, i := range idx[:min(k, n)] {
		take(i)
	}
	got := 0
	for _, i := range idx {
		if got == limit-2*k {
			break
		}
		if keys[i].Cmp(mid) >= 0 {
			take(i)
			got++
		}
	}
	for j := 0; j < k && j < n; j++ {
		take(idx[n-1-j])
	}
	return out
}

func TestWindowMatchesLiveSampler(t *testing.T) {
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	gen := map[string]func(n int) []*big.Int{
		"contiguous": func(n int) []*big.Int { return seq(n, 1, 1) },
		"sparse":     func(n int) []*big.Int { return seq(n, 3, 7) },
		"negative":   func(n int) []*big.Int { return seq(n, -int64(n)/3, 1) },
		"unsigned 64-bit": func(n int) []*big.Int {
			out := seq(n, 0, 1)
			for _, k := range out {
				k.Sub(two64, k).Sub(k, big.NewInt(1)) // 2^64 - 1 downwards
			}
			return out
		},
		"signed to unsigned": func(n int) []*big.Int {
			out := seq(n, 0, 1<<40)
			out[0] = big.NewInt(math.MinInt64)
			out[n-1] = new(big.Int).Sub(two64, big.NewInt(1))
			return out
		},
		"repeated keys": func(n int) []*big.Int {
			out := seq(n, 1, 1)
			for i := 0; i < n; i += 5 {
				out[i] = new(big.Int).Set(out[(i+1)%n])
			}
			return out
		},
	}
	rng := rand.New(rand.NewPCG(7, 11))
	for _, limit := range []int{300, 3000, 100} {
		for _, n := range []int{1, 2, limit, 2*limit - 1, 2 * limit, 2*limit + 1, 2*limit + 2, 2*limit + 3, 3*limit + 5, 20000} {
			for name, g := range gen {
				keys := g(n)
				rng.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
				var r intRange
				for _, k := range keys {
					r.add(valueOf(k))
				}
				w := newWindow(limit, &r, int64(n))
				for i, k := range keys {
					w.offer(ikeyOf(k), true, int64(i+1), func() []sql.NullString { return nil })
				}
				_, got := w.result()
				if want := refWindow(limit, keys); !equalInts(got, want) {
					t.Errorf("limit %d, %d rows, %s keys: ordinals differ\n got %v\nwant %v", limit, n, name, head(got), head(want))
				}
			}
		}
	}
}

func seq(n int, start, step int64) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = big.NewInt(start + int64(i)*step)
	}
	return out
}

func head(v []int64) []int64 {
	if len(v) > 12 {
		return v[:12]
	}
	return v
}

func equalInts(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestWindowMethods(t *testing.T) {
	r := &intRange{any: true, min: ikeyInt(1), max: ikeyInt(600)}
	for _, c := range []struct {
		name  string
		limit int
		rng   *intRange
		rows  int64
		want  string
	}{
		{"no key", 300, nil, 10, methodFirst},
		{"no rows", 300, &intRange{}, 0, methodEmpty},
		{"limit 0", 0, r, 600, methodNone},
		{"span at twice the limit", 300, r, 600, methodAll},
		{"span past it", 299, r, 600, methodWindow},
	} {
		if got := newWindow(c.limit, c.rng, c.rows).method; got != c.want {
			t.Errorf("%s: method %q, want %q", c.name, got, c.want)
		}
	}
	// At 100 rows: 33, 34 and 33.
	w := newWindow(100, &intRange{any: true, min: ikeyInt(1), max: ikeyInt(100000)}, 100000)
	if w.small.cap != 33 || w.mid.cap != 34 || w.large.cap != 33 {
		t.Errorf("windows of %d, %d and %d rows, want 33, 34 and 33", w.small.cap, w.mid.cap, w.large.cap)
	}
}

func TestParseKey(t *testing.T) {
	for _, c := range []struct {
		in   string
		kind sqldumpKind
		want string
		ok   bool
	}{
		{"42", numKind, "42", true},
		{"-42", numKind, "-42", true},
		{" 7 ", strKind, "7", true},
		{"18446744073709551615", numKind, "18446744073709551615", true},
		{"18446744073709551616", numKind, "", false},
		{"-9223372036854775808", numKind, "-9223372036854775808", true},
		{"-9223372036854775809", numKind, "", false},
		{"1.5", numKind, "", false},
		{"", strKind, "", false},
		{"12a", strKind, "", false},
	} {
		k, ok := parseKey(valueText(c.kind, c.in))
		if ok != c.ok || (ok && k.big().String() != c.want) {
			t.Errorf("%q: got %v %v, want %v %v", c.in, k.big(), ok, c.want, c.ok)
		}
	}
	if k, ok := parseKey(hexValue(0x01, 0x00)); !ok || k.big().String() != "256" {
		t.Errorf("hex 0x0100: got %v %v", k.big(), ok)
	}
	if _, ok := parseKey(hexValue(1, 2, 3, 4, 5, 6, 7, 8, 9)); ok {
		t.Error("nine bytes of hex read as a key")
	}
}

func TestCollEqual(t *testing.T) {
	col := func(coll string) *model.Column { return &model.Column{Collation: coll} }
	for _, c := range []struct {
		coll string
		a, b string
		want bool
	}{
		{"utf8mb4_unicode_ci", "User_Request", "user_request", true},
		{"utf8mb4_unicode_ci", "user_request  ", "user_request", true},
		{"utf8mb4_0900_ai_ci", "user_request  ", "user_request", false},
		{"utf8mb4_0900_ai_ci", "USER_REQUEST", "user_request", true},
		{"utf8mb4_bin", "USER", "user", false},
		{"utf8mb4_bin", "user ", "user", true},
		{"utf8mb4_0900_bin", "user ", "user", false},
		{"utf8mb4_nopad_bin", "user ", "user", false},
		{"", "x", "x", true},
	} {
		if got := collEqual(col(c.coll), c.a, c.b); got != c.want {
			t.Errorf("%s: %q and %q: %v, want %v", c.coll, c.a, c.b, got, c.want)
		}
	}
}

func TestParseCond(t *testing.T) {
	for _, c := range []struct {
		where string
		want  rowCond
		ok    bool
	}{
		{"post_type = 'user_request'", rowCond{"post_type", []string{"user_request"}}, true},
		{"post_type='a'", rowCond{"post_type", []string{"a"}}, true},
		{"post_type IN ('shop_order', 'shop_order_refund')", rowCond{"post_type", []string{"shop_order", "shop_order_refund"}}, true},
		{"`post_type` in ('x')", rowCond{"post_type", []string{"x"}}, true},
		{"post_type LIKE 'x%'", rowCond{}, false},
		{"post_type = 'a' OR post_type = 'b'", rowCond{}, false},
		{"post_type IN ('a', 'b'", rowCond{}, false},
		{"post_type = 'it\\'s'", rowCond{}, false},
	} {
		got, ok := parseCond(c.where)
		if ok != c.ok || (ok && (got.col != c.want.col || strings.Join(got.vals, "|") != strings.Join(c.want.vals, "|"))) {
			t.Errorf("%s: %+v %v, want %+v %v", c.where, got, ok, c.want, c.ok)
		}
	}
}

// The row subjects a preset writes are all forms a dump scan can check.
func TestPresetRowSubjectsAreChecked(t *testing.T) {
	var tables []*model.Table
	add := func(name string, cols ...string) {
		tb := &model.Table{Name: name, Type: "BASE TABLE"}
		for i, c := range cols {
			tb.Columns = append(tb.Columns, &model.Column{Name: c, Position: i + 1, DataType: "varchar"})
		}
		tables = append(tables, tb)
	}
	for _, p := range []string{"wp_", "wp_2_"} {
		add(p+"options", "option_id", "option_name", "option_value")
		add(p+"posts", "ID", "post_type", "post_title", "post_password")
		add(p+"postmeta", "meta_id", "post_id", "meta_key", "meta_value")
	}
	add("wp_users", "ID", "user_email")
	add("wp_usermeta", "umeta_id", "user_id", "meta_key", "meta_value")
	add("customer_entity", "entity_id", "email")
	add("migrations", "id", "migration", "batch")
	s := &model.Schema{Tables: tables}
	pr := preset.DetectOffline(s, "auto", preset.Offline{
		Options: func(string, string, string, []string) map[string]string { return nil },
		Rows:    func(string, []string) [][]string { return nil },
	})
	if len(pr.RowSubjects) == 0 {
		t.Fatal("no row subjects found to check")
	}
	for _, rs := range pr.RowSubjects {
		c, ok := parseCond(rs.Where)
		if !ok {
			t.Errorf("the row subject %s.%s has a condition of another form: %s", rs.Table, rs.Column, rs.Where)
			continue
		}
		tb := s.Table(rs.Table)
		if tb.Column(c.col) == nil {
			t.Errorf("the row subject %s.%s tests %s, which the table lacks", rs.Table, rs.Column, c.col)
		}
	}
}

// --- scanning a dump ---

const dumpHead = "-- Server version\t8.4.3\n\nSET sql_mode='NO_AUTO_VALUE_ON_ZERO';\nSET NAMES utf8mb4;\n"

func openText(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
}

// tapped is what a table collected.
type tapped struct {
	wins map[int]*sample.Sample
	kv   *kvRead
}

func dumpOpts() DumpOptions {
	return DumpOptions{Options: Options{SampleRows: DefaultSampleRows, MetaSampleRows: DefaultMetaSampleRows,
		KeySampleRows: DefaultKeySampleRows, Samples: true, Preset: "auto", Version: "test"}, File: "test.sql"}
}

// scanDump scans SQL text and returns the result and what each table
// collected.
func scanDump(t *testing.T, sql string, mod func(*DumpOptions)) (*model.Result, map[string]*tapped) {
	t.Helper()
	got := map[string]*tapped{}
	opts := dumpOpts()
	opts.limits.repanic = true
	opts.limits.tap = func(table string, wins map[int]*sample.Sample, kv *kvRead) { got[table] = &tapped{wins, kv} }
	if mod != nil {
		mod(&opts)
	}
	res, err := RunDump(context.Background(), openText(dumpHead+sql), opts)
	if err != nil {
		t.Fatal(err)
	}
	return res, got
}

func insertAll(b *strings.Builder, table, cols string, rows []string) {
	for i := 0; i < len(rows); i += 100 {
		fmt.Fprintf(b, "INSERT INTO `%s` (%s) VALUES %s;\n", table, cols, strings.Join(rows[i:min(i+100, len(rows))], ","))
	}
}

func keysOf(s *sample.Sample, col string) []string {
	i := s.Index(col)
	var out []string
	for _, r := range s.Rows {
		out = append(out, r[i].String)
	}
	return out
}

func tableOf(res *model.Result, name string) model.TableSummary {
	for _, ts := range res.Tables {
		if ts.Name == name {
			return ts
		}
	}
	return model.TableSummary{}
}

func TestDumpPlainTableWindows(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `t` (`id` int NOT NULL, `name` varchar(20) DEFAULT NULL, PRIMARY KEY (`id`));\n")
	const n = 6100
	rng := rand.New(rand.NewPCG(3, 4))
	ids := rng.Perm(n) // keys out of order
	var rows, keys []string
	var bigs []*big.Int
	for _, i := range ids {
		rows = append(rows, fmt.Sprintf("(%d,'n%d')", i*3, i))
		bigs = append(bigs, big.NewInt(int64(i*3)))
	}
	insertAll(&b, "t", "`id`,`name`", rows)
	res, got := scanDump(t, b.String(), nil)
	for _, limit := range []int{300, 3000} {
		keys = nil
		for _, o := range refWindow(limit, bigs) {
			keys = append(keys, fmt.Sprint(bigs[o-1]))
		}
		s := got["t"].wins[limit]
		if limit == 3000 && s != nil {
			t.Errorf("a plain table kept the window of %d rows", limit)
		}
		if limit == 300 {
			if s.Method != methodWindow {
				t.Errorf("method %q", s.Method)
			}
			if g := keysOf(s, "id"); strings.Join(g, ",") != strings.Join(keys, ",") {
				t.Errorf("limit %d: keys %v, want %v", limit, g[:10], keys[:10])
			}
		}
	}
	if ts := tableOf(res, "t"); ts.RowsSampled != 300 || ts.RowsEstimate != n {
		t.Errorf("table: %+v", ts)
	}
}

func TestDumpFirstRows(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `log` (`msg` varchar(20) DEFAULT NULL);\n")
	b.WriteString("CREATE TABLE `auto` (`id` int NOT NULL AUTO_INCREMENT, `msg` varchar(20) DEFAULT NULL, PRIMARY KEY (`id`));\n")
	b.WriteString("SET @@auto_increment_increment=2;\n")
	var rows, auto []string
	for i := range 700 {
		rows = append(rows, fmt.Sprintf("('m%d')", i))
		auto = append(auto, fmt.Sprintf("('m%d')", i))
	}
	insertAll(&b, "log", "`msg`", rows)
	insertAll(&b, "auto", "`msg`", auto)
	res, got := scanDump(t, b.String(), nil)
	for _, name := range []string{"log", "auto"} {
		s := got[name].wins[300]
		if s.Method != methodFirst || len(s.Rows) != 300 {
			t.Errorf("%s: %q with %d rows", name, s.Method, len(s.Rows))
		}
		if m := keysOf(s, "msg"); m[0] != "m0" || m[299] != "m299" {
			t.Errorf("%s: first rows %v ... %v", name, m[0], m[299])
		}
	}
	found := false
	for _, w := range res.Warnings {
		found = found || strings.Contains(w, "the keys of the table auto can't be counted")
	}
	if !found {
		t.Errorf("no warning for the table whose keys can't be counted: %v", res.Warnings)
	}
}

func TestDumpCountedKeys(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `t` (`id` bigint NOT NULL AUTO_INCREMENT, `name` varchar(20) DEFAULT NULL, PRIMARY KEY (`id`)) AUTO_INCREMENT=1000;\n")
	var rows []string
	for i := range 900 {
		rows = append(rows, fmt.Sprintf("('n%d')", i))
	}
	insertAll(&b, "t", "`name`", rows)
	_, got := scanDump(t, b.String(), nil)
	s := got["t"].wins[300]
	ids := keysOf(s, "id")
	if s.Method != methodWindow || ids[0] != "1000" || !slices.Contains(ids, "1899") || slices.Contains(ids, "999") {
		t.Errorf("method %q, keys %v ...: want the counted keys 1000 to 1899", s.Method, ids[:3])
	}
}

func TestDumpKeyAfterRows(t *testing.T) {
	// phpMyAdmin declares the key after the rows.
	var b strings.Builder
	b.WriteString("CREATE TABLE `t` (`id` int NOT NULL, `name` varchar(20) DEFAULT NULL);\n")
	var rows []string
	for i := 700; i > 0; i-- {
		rows = append(rows, fmt.Sprintf("(%d,'n%d')", i, i))
	}
	insertAll(&b, "t", "`id`,`name`", rows)
	b.WriteString("ALTER TABLE `t` ADD PRIMARY KEY (`id`);\n")
	_, got := scanDump(t, b.String(), nil)
	s := got["t"].wins[300]
	ids := keysOf(s, "id")
	if s.Method != methodWindow || ids[0] != "1" || !slices.Contains(ids, "700") {
		t.Errorf("method %q, keys %v ...", s.Method, ids[:3])
	}
}

func TestDumpEmptyAndNoSamples(t *testing.T) {
	sql := "CREATE TABLE `t` (`id` int NOT NULL, `email` varchar(60) DEFAULT NULL, PRIMARY KEY (`id`));\n"
	_, got := scanDump(t, sql, nil)
	if m := got["t"].wins[300].Method; m != methodEmpty {
		t.Errorf("an empty table's method is %q", m)
	}
	opens := 0
	opts := dumpOpts()
	opts.Samples = false
	open := func() (io.ReadCloser, error) {
		opens++
		return io.NopCloser(strings.NewReader(dumpHead + sql + "INSERT INTO `t` VALUES (1,'a@b.example');\n")), nil
	}
	res, err := RunDump(context.Background(), open, opts)
	if err != nil {
		t.Fatal(err)
	}
	if opens != 1 {
		t.Errorf("--no-samples opened the file %d times", opens)
	}
	if res.Dump.Judged != "Judged names only; no values were read." {
		t.Errorf("judged line: %q", res.Dump.Judged)
	}
	if ts := tableOf(res, "t"); ts.RowsEstimate != 1 || ts.RowsSampled != 0 {
		t.Errorf("table: %+v", ts)
	}
	if len(res.Findings) == 0 || res.Findings[0].Column != "email" || res.Findings[0].Sampled != 0 {
		t.Errorf("findings by name: %+v", res.Findings)
	}
}

func TestDumpFindings(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `customers` (`id` int NOT NULL AUTO_INCREMENT, `email` varchar(80) DEFAULT NULL, `note` text, PRIMARY KEY (`id`));\n")
	var rows []string
	for i := range 40 {
		rows = append(rows, fmt.Sprintf("(NULL,'user%d@shop.example','n')", i))
	}
	insertAll(&b, "customers", "`id`,`email`,`note`", rows)
	res, _ := scanDump(t, b.String(), nil)
	var f *model.Finding
	for i := range res.Findings {
		if res.Findings[i].Column == "email" {
			f = &res.Findings[i]
		}
	}
	if f == nil || f.Category != model.CatEmail || f.Sampled != 40 || f.Matched != 40 {
		t.Errorf("email finding: %+v", f)
	}
	d := res.Dump
	if d == nil || d.File != "test.sql" || d.Rows != 40 || d.Statements == 0 || d.Unread != 0 || d.SampleRows != 300 ||
		!strings.HasPrefix(d.Judged, "Judged up to 300 rows of each table") || d.ByKind["INSERT"] != 1 {
		t.Errorf("dump info: %+v", d)
	}
	if res.Server.Flavor != "mysql" || res.Server.Version != "8.4.3" || res.Database != "" {
		t.Errorf("server %+v, database %q", res.Server, res.Database)
	}
}

func TestDumpTextCutAndHex(t *testing.T) {
	var b strings.Builder
	long := strings.Repeat("é", 5000)
	b.WriteString("CREATE TABLE `members` (`id` int NOT NULL, `note` text, `regip` binary(4) DEFAULT NULL, `blobs` blob, PRIMARY KEY (`id`));\n")
	fmt.Fprintf(&b, "INSERT INTO `members` VALUES (1,'%s',0x7F000001,'x'),(2,'short',NULL,'y');\n", long)
	_, got := scanDump(t, b.String(), nil)
	s := got["members"].wins[300]
	if len(s.Columns) != 3 || s.Columns[2].Name != "regip" || !s.Hex[2] {
		t.Fatalf("columns %v hex %v", s.Columns, s.Hex)
	}
	if v := s.Rows[0][1].String; len([]rune(v)) != 4096 {
		t.Errorf("the text kept is %d characters, want 4096", len([]rune(v)))
	}
	if s.Rows[0][2].String != "7F000001" || s.Rows[1][2].Valid {
		t.Errorf("hex column: %+v %+v", s.Rows[0][2], s.Rows[1][2])
	}
}

// --- key/value tables ---

const usermeta = "CREATE TABLE `usermeta` (`umeta_id` bigint unsigned NOT NULL AUTO_INCREMENT, `user_id` bigint NOT NULL DEFAULT 0, " +
	"`meta_key` varchar(255) DEFAULT NULL, `meta_value` longtext, PRIMARY KEY (`umeta_id`), KEY `meta_key` (`meta_key`(191)));\n"

func metaRows(keys []string, per int) []string {
	var rows []string
	for _, k := range keys {
		for j := range per {
			rows = append(rows, fmt.Sprintf("(1,'%s','v%s%d')", k, k, j))
		}
	}
	return rows
}

func TestDumpKVWholeHoldsRowsOnce(t *testing.T) {
	var b strings.Builder
	b.WriteString(usermeta)
	insertAll(&b, "usermeta", "`user_id`,`meta_key`,`meta_value`", append(metaRows([]string{"nick"}, 30), metaRows([]string{"other"}, 3)...))
	_, got := scanDump(t, b.String(), nil)
	c := got["usermeta"]
	if c.kvMode() != int(modeWhole) {
		t.Fatalf("mode %d, want a whole read", c.kvMode())
	}
	if n := len(c.kv.values["nick"]); n != 20 {
		t.Errorf("nick holds %d values, want its first 10 and last 10", n)
	}
	held, rows := 0, len(c.wins[300].Rows)
	for _, h := range c.kv.heldRows {
		if h {
			held++
		}
	}
	if rows != 33 || held != 23 || len(c.kv.pks) != 0 {
		t.Errorf("window of %d rows with %d held, %d primary keys kept; want 33, 23 and none", rows, held, len(c.kv.pks))
	}
	// The first and the last ten by key.
	vals := c.kv.values["nick"]
	if vals[0].Value != "vnick0" || vals[9].Value != "vnick9" {
		t.Errorf("first values: %v %v", vals[0], vals[9])
	}
	tail := map[string]bool{}
	for _, v := range vals[10:] {
		tail[v.Value] = true
	}
	for j := 20; j < 30; j++ {
		if !tail[fmt.Sprintf("vnick%d", j)] {
			t.Errorf("the value of row %d isn't among the last ten", j)
		}
	}
}

func (c *tapped) kvMode() int {
	if c.kv == nil {
		return 0
	}
	return int(c.kv.mode)
}

func TestDumpKVEnvelopeEdges(t *testing.T) {
	for _, c := range []struct {
		rows  int
		bytes int64
		mode  kvMode
	}{
		{10, 1 << 20, modeWhole}, {11, 1 << 20, modeList}, {5, 50, modeWhole}, {5, 49, modeList},
	} {
		var b strings.Builder
		b.WriteString(usermeta)
		var keys []string
		for i := range c.rows {
			keys = append(keys, fmt.Sprintf("k%02d", i))
		}
		insertAll(&b, "usermeta", "`user_id`,`meta_key`,`meta_value`", metaRows(keys, 1))
		_, got := scanDump(t, b.String(), func(o *DumpOptions) {
			o.limits.wholeRows, o.limits.wholeBytes = 10, c.bytes
		})
		// Each row is 10 bytes of values: its counted key, user_id, key and value.
		if m := got["usermeta"].kvMode(); m != int(c.mode) {
			t.Errorf("%d rows, %d bytes of limit: mode %d, want %d", c.rows, c.bytes, m, c.mode)
		}
	}
}

func TestDumpKVListedOutsideEnvelope(t *testing.T) {
	var b strings.Builder
	b.WriteString(usermeta)
	var keys []string
	for i := range 12 {
		keys = append(keys, fmt.Sprintf("k%02d", i))
	}
	insertAll(&b, "usermeta", "`user_id`,`meta_key`,`meta_value`", metaRows(keys, 25))
	res, got := scanDump(t, b.String(), func(o *DumpOptions) { o.limits.wholeRows = 10 })
	c := got["usermeta"]
	if c.kvMode() != int(modeList) || len(c.kv.keys) != 12 {
		t.Fatalf("mode %d with %d keys", c.kvMode(), len(c.kv.keys))
	}
	// Twenty rows a key, by primary key: the first twenty of each key.
	for _, k := range keys {
		vals := c.kv.values[k]
		if len(vals) != 20 || vals[0].Value != "v"+k+"0" || vals[19].Value != "v"+k+"19" {
			t.Errorf("%s: %d values, first %q", k, len(vals), vals[0].Value)
		}
	}
	// A window of 3,000 rows holds the other five of each key too.
	if n := len(c.wins[3000].Rows); n != 300 {
		t.Errorf("window of %d rows", n)
	}
	if ts := tableOf(res, "usermeta"); ts.Keys != 12 || ts.RowsSampled != 300+12*20 {
		t.Errorf("table: %+v", ts)
	}
}

func TestDumpKVCapsKeepPresetKeys(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `wp_options` (`option_id` bigint unsigned NOT NULL AUTO_INCREMENT, `option_name` varchar(191) NOT NULL DEFAULT '', " +
		"`option_value` longtext NOT NULL, PRIMARY KEY (`option_id`), UNIQUE KEY `option_name` (`option_name`));\n")
	b.WriteString("CREATE TABLE `wp_posts` (`ID` bigint unsigned NOT NULL AUTO_INCREMENT, `post_type` varchar(20) NOT NULL DEFAULT 'post', " +
		"`post_title` text, PRIMARY KEY (`ID`));\n")
	b.WriteString("CREATE TABLE `wp_postmeta` (`meta_id` bigint unsigned NOT NULL AUTO_INCREMENT, `post_id` bigint NOT NULL DEFAULT 0, " +
		"`meta_key` varchar(255) DEFAULT NULL, `meta_value` longtext, PRIMARY KEY (`meta_id`), KEY `meta_key` (`meta_key`(191)));\n")
	var keys []string
	for i := range 30 {
		keys = append(keys, fmt.Sprintf("A%02d", i))
	}
	keys = append(keys, "_order_key", "_bbp_author_ip")
	insertAll(&b, "wp_postmeta", "`post_id`,`meta_key`,`meta_value`", metaRows(keys, 2))
	res, got := scanDump(t, b.String(), func(o *DumpOptions) { o.limits.wholeRows, o.limits.maxKeys = 10, 5 })
	c := got["wp_postmeta"]
	if c.kvMode() != int(modeList) {
		t.Fatalf("mode %d", c.kvMode())
	}
	want := "A00 A01 A02 A03 A04 _bbp_author_ip _order_key"
	if g := strings.Join(c.kv.keys, " "); g != want {
		t.Errorf("keys kept: %s, want %s", g, want)
	}
	if len(c.kv.values["_order_key"]) != 2 || len(c.kv.values["A31"]) != 0 {
		t.Errorf("values: %v", c.kv.values)
	}
	if !c.kv.truncated {
		t.Error("the listing isn't marked as cut")
	}
	if ts := tableOf(res, "wp_postmeta"); ts.Keys != 7 {
		t.Errorf("keys %d", ts.Keys)
	}
	cut := false
	for _, w := range res.Warnings {
		cut = cut || strings.Contains(w, "wp_postmeta has more than 5 keys")
	}
	if !cut {
		t.Errorf("no warning for the cut: %v", res.Warnings)
	}
}

func TestDumpKVByteCapsJudgeKeysByName(t *testing.T) {
	var b strings.Builder
	b.WriteString(usermeta)
	keys := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet"}
	insertAll(&b, "usermeta", "`user_id`,`meta_key`,`meta_value`", metaRows(keys, 1))
	res, got := scanDump(t, b.String(), func(o *DumpOptions) {
		// Each row counts for its text and kvRowOverhead: three rows fit.
		o.limits.wholeRows, o.limits.valueBytes = 5, 400
		o.SampleRows, o.MetaSampleRows = 1, 1
	})
	c := got["usermeta"]
	read := 0
	for _, k := range c.kv.keys {
		if len(c.kv.values[k]) > 0 {
			read++
		}
	}
	if len(c.kv.keys) != 10 || read == 0 || read >= 10 {
		t.Errorf("%d keys, %d with values", len(c.kv.keys), read)
	}
	warned := false
	for _, w := range res.Warnings {
		// The limits a dump has, per table: none for the whole scan.
		warned = warned || strings.Contains(w, "were not sampled (limits: 200000 keys and 0 MB per table);")
	}
	if !warned {
		t.Errorf("no warning with the dump's limits: %v", res.Warnings)
	}
}

func TestDumpDemotedKeyValueGetsSmallWindow(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `entries` (`id` int NOT NULL AUTO_INCREMENT, `meta_key` varchar(60) DEFAULT NULL, `meta_value` text, PRIMARY KEY (`id`), KEY `k` (`meta_key`));\n")
	first := []string{"Ama", "Brisa", "Cato", "Dren", "Elio", "Faye", "Garo", "Hesper"}
	last := []string{"Vexley", "Quillon", "Marrow", "Tamsk", "Orrin", "Pellow", "Strand", "Ivel"}
	var rows []string
	for i := range 400 {
		rows = append(rows, fmt.Sprintf("('%s %s%d','x')", first[i%8], last[(i/8)%8], i))
	}
	insertAll(&b, "entries", "`meta_key`,`meta_value`", rows)
	res, got := scanDump(t, b.String(), func(o *DumpOptions) { o.limits.wholeRows = 10 })
	if got["entries"].kvMode() != int(modeList) {
		t.Fatalf("mode %d", got["entries"].kvMode())
	}
	ts := tableOf(res, "entries")
	if ts.Kind != "table" || ts.RowsSampled != 300 {
		t.Errorf("demoted table: %+v, want a plain table with the 300-row window", ts)
	}
}

func TestDumpKVWithoutUsableColumns(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `config` (`id` int NOT NULL, `config_key` varchar(40) DEFAULT NULL, `config_value` blob, PRIMARY KEY (`id`));\n")
	b.WriteString("INSERT INTO `config` VALUES (1,'a','x');\n")
	res, got := scanDump(t, b.String(), nil)
	// A binary value isn't a key/value table at all, so the table stays plain.
	if got["config"].kvMode() != 0 {
		t.Errorf("mode %d", got["config"].kvMode())
	}
	if ts := tableOf(res, "config"); ts.Kind != "table" {
		t.Errorf("table: %+v", ts)
	}
}

// --- row subjects ---

func wpPosts(index string) string {
	return "CREATE TABLE `wp_options` (`option_id` bigint unsigned NOT NULL AUTO_INCREMENT, `option_name` varchar(191) NOT NULL DEFAULT '', " +
		"`option_value` longtext NOT NULL, PRIMARY KEY (`option_id`), UNIQUE KEY `option_name` (`option_name`));\n" +
		"CREATE TABLE `wp_postmeta` (`meta_id` bigint unsigned NOT NULL AUTO_INCREMENT, `post_id` bigint NOT NULL DEFAULT 0, " +
		"`meta_key` varchar(255) DEFAULT NULL, `meta_value` longtext, PRIMARY KEY (`meta_id`), KEY `meta_key` (`meta_key`(191)));\n" +
		"CREATE TABLE `wp_posts` (`ID` bigint unsigned NOT NULL AUTO_INCREMENT, `post_type` varchar(20) NOT NULL DEFAULT 'post', " +
		"`post_title` text, PRIMARY KEY (`ID`)" + index + ");\n"
}

func TestDumpRowSubjects(t *testing.T) {
	for _, c := range []struct {
		matches, want int
	}{{30, 30}, {50, 50}, {60, 50}} {
		var b strings.Builder
		b.WriteString(wpPosts(", KEY `post_type` (`post_type`)"))
		var rows []string
		// Keys out of order, and one in capitals, which the collation reads as equal.
		for i := c.matches; i >= 1; i-- {
			typ := "user_request"
			if i == 7 {
				typ = "USER_REQUEST"
			}
			rows = append(rows, fmt.Sprintf("(%d,'%s','req%d@shop.example')", i, typ, i))
		}
		rows = append(rows, "(1000,'post','a title')")
		insertAll(&b, "wp_posts", "`ID`,`post_type`,`post_title`", rows)
		res, _ := scanDump(t, b.String(), nil)
		var f *model.Finding
		for i := range res.Findings {
			if res.Findings[i].Table == "wp_posts" && res.Findings[i].Column == "post_title" && res.Findings[i].Where != "" {
				f = &res.Findings[i]
			}
		}
		if f == nil || f.Category != model.CatEmail || f.Sampled != c.want {
			t.Errorf("%d requests: finding %+v, want %d values read", c.matches, f, c.want)
		}
	}
}

func TestDumpRowSubjectWithoutIndex(t *testing.T) {
	var b strings.Builder
	b.WriteString(wpPosts(""))
	b.WriteString("INSERT INTO `wp_posts` VALUES (1,'user_request','req@shop.example');\n")
	res, _ := scanDump(t, b.String(), nil)
	want := "skipped the rows where post_type = 'user_request' in wp_posts: no index on post_type"
	if !strings.Contains(strings.Join(res.Warnings, "\n"), want) {
		t.Errorf("warnings %v, want %q", res.Warnings, want)
	}
	for _, f := range res.Findings {
		if f.Table == "wp_posts" && f.Where != "" && f.Sampled > 0 {
			t.Errorf("a row subject was read without an index: %+v", f)
		}
	}
}

// --- platform settings, relationships, the end of the result ---

func TestDumpPresetFromFirstPass(t *testing.T) {
	var b strings.Builder
	b.WriteString(wpPosts(", KEY `post_type` (`post_type`)"))
	b.WriteString("INSERT INTO `wp_options` (`option_name`,`option_value`) VALUES ('siteurl','x'),('woocommerce_version','9.3.3');\n")
	res, _ := scanDump(t, b.String(), nil)
	names := map[string]bool{}
	for _, p := range res.Platforms {
		names[p.Name] = true
	}
	if !names["wordpress"] || !names["woocommerce"] {
		t.Errorf("platforms %+v: WooCommerce's version is a row of wp_options the first pass keeps", res.Platforms)
	}
	if len(res.SideEffects) != 0 {
		t.Errorf("side effects %v", res.SideEffects)
	}
	for _, r := range res.Relationships {
		if r.Source != "declared" && (r.Status != model.RelUnverified || r.Note != "not checked in a dump file") {
			t.Errorf("relationship %+v", r)
		}
	}
}

func TestDumpRelationships(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `parent` (`id` int NOT NULL, PRIMARY KEY (`id`));\n")
	b.WriteString("CREATE TABLE `child` (`id` int NOT NULL, `parent_id` int DEFAULT NULL, `other_id` int DEFAULT NULL, PRIMARY KEY (`id`), " +
		"KEY `p` (`parent_id`), CONSTRAINT `fk` FOREIGN KEY (`parent_id`) REFERENCES `parent` (`id`));\n")
	b.WriteString("CREATE TABLE `other` (`id` int NOT NULL, PRIMARY KEY (`id`));\n")
	res, _ := scanDump(t, b.String(), nil)
	if len(res.Relationships) != 1 || res.Relationships[0].Status != model.RelDeclared || res.Relationships[0].ChildColumns[0] != "parent_id" {
		t.Errorf("relationships %+v: want the declared key alone, no guess from a name", res.Relationships)
	}
}

func TestDumpUnreadAndDatabases(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `t` (`id` int NOT NULL, `a` int, PRIMARY KEY (`id`));\n")
	b.WriteString("INSERT INTO `t` VALUES (1,1),(2,2);\n")
	b.WriteString("INSERT INTO `t` VALUES (3,CONCAT('x','y'));\n")
	b.WriteString("INSERT INTO `t` VALUES (4,5,6);\n")
	res, _ := scanDump(t, b.String(), nil)
	if res.Dump.Unread != 2 || len(res.Dump.UnreadList) != 2 || res.Dump.UnreadList[0].Table != "t" || res.Dump.UnreadList[0].Line == 0 {
		t.Errorf("dump info: %+v", res.Dump)
	}
	if ts := tableOf(res, "t"); ts.Error != "2 statements of this table weren't read" || ts.RowsEstimate != 2 {
		t.Errorf("table %+v", ts)
	}

	two := "CREATE DATABASE `one`;\nUSE `one`;\nCREATE TABLE `a` (`id` int);\nCREATE DATABASE `two`;\nUSE `two`;\nCREATE TABLE `b` (`id` int);\nINSERT INTO `b` VALUES (1);\n"
	_, err := RunDump(context.Background(), openText(dumpHead+two), dumpOpts())
	if err == nil || !strings.Contains(err.Error(), `"one", "two"`) {
		t.Errorf("several databases: %v", err)
	}
	opts := dumpOpts()
	opts.Database = "two"
	res, err = RunDump(context.Background(), openText(dumpHead+two), opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Database != "two" || len(res.Tables) != 1 || res.Tables[0].Name != "b" || len(res.Dump.Databases) != 2 {
		t.Errorf("database %q, tables %+v, databases %v", res.Database, res.Tables, res.Dump.Databases)
	}
	opts.Database = "three"
	if _, err = RunDump(context.Background(), openText(dumpHead+two), opts); err == nil {
		t.Error("a database the file holds no tables of was accepted")
	}
	// The error holds the names the reader parsed, quoted, and nothing else.
	many := dumpHead
	for i := range 14 {
		many += fmt.Sprintf("USE `d%02d`;\nCREATE TABLE `t` (`id` int);\n", i)
	}
	_, err = RunDump(context.Background(), openText(many), dumpOpts())
	if err == nil || !strings.Contains(err.Error(), `"d09", and 4 more`) || strings.Contains(err.Error(), "d10") {
		t.Errorf("fourteen databases: %v", err)
	}
}

func TestDumpDatabaseFromUse(t *testing.T) {
	res, _ := scanDump(t, "USE `shop`;\nCREATE TABLE `t` (`id` int);\n", nil)
	if res.Database != "shop" {
		t.Errorf("database %q", res.Database)
	}
}

// --- the file between passes ---

func TestDumpFileChanged(t *testing.T) {
	text := dumpHead + "CREATE TABLE `t` (`id` int NOT NULL, `a` varchar(9), PRIMARY KEY (`id`));\nINSERT INTO `t` VALUES (1,'x'),(2,'y');\n"
	changes := map[string]string{
		"a row added":       text + "INSERT INTO `t` VALUES (3,'z');\n",
		"a row removed":     strings.Replace(text, ",(2,'y')", "", 1),
		"a column added":    strings.Replace(text, "`a` varchar(9),", "`a` varchar(9), `b` int,", 1),
		"a structure added": text + "CREATE TABLE `u` (`id` int);\n",
	}
	for name, second := range changes {
		calls := 0
		open := func() (io.ReadCloser, error) {
			calls++
			if calls == 1 {
				return io.NopCloser(strings.NewReader(text)), nil
			}
			return io.NopCloser(strings.NewReader(second)), nil
		}
		res, err := RunDump(context.Background(), open, dumpOpts())
		if !errors.Is(err, ErrDumpChanged) || res != nil {
			t.Errorf("%s: %v, %v", name, res, err)
		}
	}
	// The same content with another size or time.
	for name, c := range map[string]struct {
		size int64
		mod  time.Time
	}{"size": {11, time.Unix(100, 0)}, "time": {10, time.Unix(101, 0)}} {
		calls := 0
		opts := dumpOpts()
		opts.Stat = func() (int64, time.Time, error) {
			calls++
			if calls == 1 {
				return 10, time.Unix(100, 0), nil
			}
			return c.size, c.mod, nil
		}
		res, err := RunDump(context.Background(), openText(text), opts)
		if !errors.Is(err, ErrDumpChanged) || res != nil {
			t.Errorf("a changed %s: %v, %v", name, res, err)
		}
	}
	opts := dumpOpts()
	opts.Stat = func() (int64, time.Time, error) { return 10, time.Unix(100, 0), nil }
	if _, err := RunDump(context.Background(), openText(text), opts); err != nil {
		t.Errorf("a file that stayed the same: %v", err)
	}
	if !strings.Contains(ErrDumpChanged.Error(), "the file changed while it was read") {
		t.Error(ErrDumpChanged)
	}
}

func TestDumpProgressAndCut(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `t` (`id` int NOT NULL, `a` varchar(60), PRIMARY KEY (`id`));\n")
	var rows []string
	for i := range 60000 {
		rows = append(rows, fmt.Sprintf("(%d,'%040d')", i, i))
	}
	insertAll(&b, "t", "`id`,`a`", rows)
	opts := dumpOpts()
	var passes = map[int]int{}
	var last string
	opts.ReadProgress = func(pass int, done, total int64, table string) { passes[pass]++; last = table }
	if _, err := RunDump(context.Background(), openText(dumpHead+b.String()), opts); err != nil {
		t.Fatal(err)
	}
	if passes[1] == 0 || passes[2] == 0 || last != "t" {
		t.Errorf("progress calls %v, last table %q", passes, last)
	}

	// A file that ends early gives what was read, with the error.
	opts = dumpOpts()
	open := func() (io.ReadCloser, error) {
		return io.NopCloser(io.MultiReader(strings.NewReader(dumpHead+"CREATE TABLE `t` (`id` int);\n"), errReader{})), nil
	}
	res, err := RunDump(context.Background(), open, opts)
	if res == nil || err == nil || !strings.Contains(err.Error(), "could not be read to its end") || len(res.Tables) != 1 {
		t.Errorf("a cut file: %v, %v", res, err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestDumpKeyCounts(t *testing.T) {
	var b strings.Builder
	b.WriteString(usermeta)
	insertAll(&b, "usermeta", "`user_id`,`meta_key`,`meta_value`", append(metaRows([]string{"nick"}, 30), metaRows([]string{"other"}, 3)...))
	var counts map[string]int64
	scanDump(t, b.String(), func(o *DumpOptions) {
		o.KeyCounts = func(table string, c map[string]int64) {
			if table == "usermeta" {
				counts = c
			}
		}
	})
	if counts["nick"] != 30 || counts["other"] != 3 || len(counts) != 2 {
		t.Errorf("counts %v", counts)
	}
}

func TestDumpPanicIsFixed(t *testing.T) {
	opts := dumpOpts()
	opts.Preset = "none"
	opts.limits.tap = func(string, map[int]*sample.Sample, *kvRead) { panic("the value zq7canary") }
	_, err := RunDump(context.Background(), openText(dumpHead+"CREATE TABLE `t` (`id` int);\nINSERT INTO `t` VALUES (1);\n"), opts)
	if err == nil || strings.Contains(err.Error(), "canary") || !strings.Contains(err.Error(), "the dump reader stopped at line") {
		t.Errorf("error %v", err)
	}
}

// --- values ---

type sqldumpKind = sqldump.ValueKind

const (
	numKind = sqldump.ValNumber
	strKind = sqldump.ValString
)

func valueText(kind sqldumpKind, s string) *sqldump.Value {
	return &sqldump.Value{Kind: kind, Bytes: []byte(s)}
}

func hexValue(b ...byte) *sqldump.Value { return &sqldump.Value{Kind: sqldump.ValHex, Bytes: b} }

func valueOf(k *big.Int) *sqldump.Value { return valueText(numKind, k.String()) }

func ikeyOf(k *big.Int) ikey {
	key, ok := parseKey(valueOf(k))
	if !ok {
		panic("a key the tests built doesn't parse: " + k.String())
	}
	return key
}
