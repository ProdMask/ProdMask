package scan

import (
	"database/sql"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sqldump"
)

// The bounds of a dump scan, each hit through limits
// shrunk for the test, or at its real size where that is cheap:
//
//	a statement, an identifier        pkg/sqldump: TestStreamHugeStatements and the Statements tests
//	a value                           TestDumpValueCutAndNextRead (and sqldump's literal tests)
//	pass 1's whole tables             TestDumpWholeTableRowsCap
//	one table's plain sample          TestDumpWideSampleThinned, TestDumpSampleFloor, TestDumpRowHeapThin
//	key/value keys, names, values     TestDumpKVKeyCapAtDefault, TestDumpKVNameBytesCap, TestDumpKVCapsKeepPresetKeys
//	                                  and TestDumpKVByteCapsJudgeKeysByName (dump_test.go)
//	tables open at once               TestDumpOpenTablesThinned, TestDumpOpenTablesNamesAtMostTen
//	unread statements listed          TestDumpUnreadListCap
//	the accounting                    TestDumpHeldBytesTrackHeap

func wideCreate(table string) string {
	return "CREATE TABLE `" + table + "` (`id` int NOT NULL AUTO_INCREMENT, `body` text, PRIMARY KEY (`id`));\n"
}

// wideInsert is an INSERT of the rows from..to-1 of a table, each holding
// width bytes of text.
func wideInsert(b *strings.Builder, table string, from, to, width int) {
	fmt.Fprintf(b, "INSERT INTO `%s` VALUES ", table)
	for i := from; i < to; i++ {
		if i > from {
			b.WriteByte(',')
		}
		fmt.Fprintf(b, "(%d,'row %d %s')", i, i, strings.Repeat("w", max(width-len(strconv.Itoa(i))-5, 0)))
	}
	b.WriteString(";\n")
}

func wideTable(table string, rows, width int) string {
	var b strings.Builder
	b.WriteString(wideCreate(table))
	for i := 1; i <= rows; i += 10 {
		wideInsert(&b, table, i, min(i+10, rows+1), width)
	}
	return b.String()
}

// interleaved is tables whose statements alternate: batch after batch of
// each, so all of them are open until the end.
func interleaved(tables []string, rows, width int) string {
	var b strings.Builder
	for _, t := range tables {
		b.WriteString(wideCreate(t))
	}
	for i := 1; i <= rows; i += 10 {
		for _, t := range tables {
			wideInsert(&b, t, i, min(i+10, rows+1), width)
		}
	}
	return b.String()
}

func hasWarning(res *model.Result, parts ...string) bool {
	for _, w := range res.Warnings {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(w, p)
		}
		if ok {
			return true
		}
	}
	return false
}

func countWarnings(res *model.Result, part string) int {
	n := 0
	for _, w := range res.Warnings {
		if strings.Contains(w, part) {
			n++
		}
	}
	return n
}

func sampledIDs(t *testing.T, c *tapped, limit int) []int {
	t.Helper()
	var ids []int
	for _, s := range keysOf(c.wins[limit], "id") {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, n)
	}
	slices.Sort(ids)
	return ids
}

const thinWarning = "has very wide rows, so its sample was thinned"

func TestDumpWideSampleThinned(t *testing.T) {
	sql := wideTable("notes", 1000, 800)

	// With the real limits nothing is thinned.
	res, got := scanDump(t, sql, nil)
	if ts := tableOf(res, "notes"); ts.RowsSampled != 300 || hasWarning(res, thinWarning) {
		t.Errorf("default limits: %d rows sampled, warnings %v", ts.RowsSampled, res.Warnings)
	}
	if n := len(got["notes"].wins[300].Rows); n != 300 {
		t.Errorf("default limits: window of %d rows", n)
	}

	// Past its bytes, the sample is thinned: the three reads halve, evenly, and
	// the warning names the table once.
	res, got = scanDump(t, sql, func(o *DumpOptions) { o.limits.sampleBytes = 150000 })
	ts := tableOf(res, "notes")
	if ts.RowsSampled <= 30 || ts.RowsSampled >= 150 || countWarnings(res, "notes "+thinWarning) != 1 {
		t.Errorf("thinned: %d rows sampled, warnings %v", ts.RowsSampled, res.Warnings)
	}
	ids := sampledIDs(t, got["notes"], 300)
	var low []int
	for _, id := range ids {
		if id <= 100 {
			low = append(low, id)
		}
	}
	if len(low) < 20 || low[0] != 1 || low[len(low)-1] != 100 {
		t.Errorf("the oldest rows kept: %v, want an even spread from 1 to 100", low)
	}
	for i := 1; i < len(low); i++ {
		if low[i]-low[i-1] > 4 {
			t.Errorf("the oldest rows kept have a gap: %v", low)
			break
		}
	}
	if ids[len(ids)-1] != 1000 {
		t.Errorf("the newest row isn't kept: %v", ids[len(ids)-5:])
	}
}

func TestDumpSampleFloor(t *testing.T) {
	// A limit no row fits under: the sample stops at the floor, 30 rows, the
	// three reads of it ten each, and the warning is there.
	res, got := scanDump(t, wideTable("notes", 1000, 800), func(o *DumpOptions) { o.limits.sampleBytes = 10000 })
	ts := tableOf(res, "notes")
	if ts.RowsSampled != 30 || countWarnings(res, "notes "+thinWarning) != 1 {
		t.Errorf("%d rows sampled, warnings %v; want the floor, 30, and one warning", ts.RowsSampled, res.Warnings)
	}
	ids := sampledIDs(t, got["notes"], 300)
	if len(ids) != 30 || ids[0] != 1 || ids[9] != 10 || ids[len(ids)-1] != 1000 {
		t.Errorf("rows kept: %v", ids)
	}

	// A table of fewer rows than the floor loses nothing, so says nothing.
	res, _ = scanDump(t, wideTable("small", 20, 800), func(o *DumpOptions) { o.limits.sampleBytes = 1000 })
	if ts := tableOf(res, "small"); ts.RowsSampled != 20 || hasWarning(res, thinWarning) {
		t.Errorf("small table: %d rows sampled, warnings %v", ts.RowsSampled, res.Warnings)
	}

	// The floor is a limit of the code, not only of the test: 30 rows is what a
	// real limit leaves.
	if d := (DumpOptions{}).lim(); d.sampleFloor != 30 || d.sampleBytes != 64<<20 || d.openBytes != 256<<20 {
		t.Errorf("defaults: floor %d, sample %d, open %d", d.sampleFloor, d.sampleBytes, d.openBytes)
	}
}

func TestDumpOpenTablesThinned(t *testing.T) {
	names := []string{"a_notes", "b_notes"}
	// Each table alone holds about 270 KB; the limit is 400 KB for all.
	shrink := func(o *DumpOptions) { o.limits.openBytes = 400000 }

	// One after the other, only one is open at a time: nothing is thinned.
	var seq strings.Builder
	for _, n := range names {
		seq.WriteString(wideTable(n, 400, 800))
	}
	res, _ := scanDump(t, seq.String(), shrink)
	for _, n := range names {
		if ts := tableOf(res, n); ts.RowsSampled != 300 {
			t.Errorf("%s in sequence: %d rows sampled", n, ts.RowsSampled)
		}
	}
	if hasWarning(res, "interleaved") {
		t.Errorf("in sequence: %v", res.Warnings)
	}

	// Interleaved, both are open at once and are thinned, with one warning
	// naming both.
	res, _ = scanDump(t, interleaved(names, 400, 800), shrink)
	for _, n := range names {
		if ts := tableOf(res, n); ts.RowsSampled < 30 || ts.RowsSampled >= 300 {
			t.Errorf("%s interleaved: %d rows sampled", n, ts.RowsSampled)
		}
	}
	if countWarnings(res, "interleaved") != 1 || !hasWarning(res, "samples of a_notes, b_notes were thinned") {
		t.Errorf("warnings: %v", res.Warnings)
	}

	// With the real limit, the same file is whole.
	res, _ = scanDump(t, interleaved(names, 400, 800), nil)
	if ts := tableOf(res, "a_notes"); ts.RowsSampled != 300 || hasWarning(res, "interleaved") {
		t.Errorf("default limits: %d rows sampled, warnings %v", ts.RowsSampled, res.Warnings)
	}
}

func TestDumpOpenTablesNamesAtMostTen(t *testing.T) {
	var names []string
	for i := 1; i <= 14; i++ {
		names = append(names, fmt.Sprintf("t%02d", i))
	}
	res, _ := scanDump(t, interleaved(names, 100, 300), func(o *DumpOptions) { o.limits.openBytes = 5000 })
	var w string
	for _, x := range res.Warnings {
		if strings.Contains(x, "interleaved") {
			w = x
		}
	}
	if countWarnings(res, "interleaved") != 1 || !strings.Contains(w, "t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, and 4 more") ||
		strings.Contains(w, "t11") {
		t.Errorf("warnings: %v", res.Warnings)
	}
	for _, n := range names {
		if ts := tableOf(res, n); ts.RowsSampled != 30 {
			t.Errorf("%s: %d rows sampled, want the floor", n, ts.RowsSampled)
		}
	}
}

func TestDumpRowHeapThin(t *testing.T) {
	var held int64
	h := &rowHeap{cap: 100, held: &held}
	for i := int64(1); i <= 100; i++ {
		h.offer(ikeyInt(i), i, func() []sql.NullString { return []sql.NullString{{String: strings.Repeat("x", 100), Valid: true}} })
	}
	one := rowSize([]sql.NullString{{String: strings.Repeat("x", 100)}})
	if held != 100*one {
		t.Fatalf("held %d, want %d", held, 100*one)
	}
	if !h.thin(30) || len(h.rows) != 50 || h.cap != 50 || held != 50*one {
		t.Fatalf("after thin: %d rows, cap %d, held %d (one row %d)", len(h.rows), h.cap, held, one)
	}
	got := h.sorted()
	if got[0].ord != 1 || got[49].ord != 100 {
		t.Errorf("ends: %d and %d", got[0].ord, got[49].ord)
	}
	// It doesn't fill again: a worse row isn't taken, a better one replaces the worst.
	h.offer(ikeyInt(500), 500, func() []sql.NullString { return nil })
	if len(h.rows) != 50 {
		t.Errorf("a worse row was taken: %d rows", len(h.rows))
	}
	// The floor: 30 rows aren't thinned.
	h2 := &rowHeap{cap: 100}
	for i := int64(1); i <= 30; i++ {
		h2.offer(ikeyInt(i), i, func() []sql.NullString { return nil })
	}
	if h2.thin(30) || len(h2.rows) != 30 || h2.cap != 30 {
		t.Errorf("at the floor: %d rows, cap %d", len(h2.rows), h2.cap)
	}
}

func TestDumpUnreadListCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `t` (`id` int NOT NULL, PRIMARY KEY (`id`));\n")
	for range 150 {
		b.WriteString("ANALYZE TABLE `t`;\n")
	}
	res, _ := scanDump(t, b.String(), nil)
	if res.Dump.Unread != 150 || len(res.Dump.UnreadList) != 100 {
		t.Errorf("%d unread statements, %d listed; want 150 and 100", res.Dump.Unread, len(res.Dump.UnreadList))
	}
	if res.Dump.UnreadList[99].Line <= res.Dump.UnreadList[0].Line {
		t.Errorf("the list isn't in the file's order")
	}
}

func TestDumpValueCutAndNextRead(t *testing.T) {
	var b strings.Builder
	b.WriteString("CREATE TABLE `notes` (`id` int NOT NULL, `body` longtext, `tail` varchar(20), PRIMARY KEY (`id`));\n")
	b.WriteString("INSERT INTO `notes` VALUES (1,'" + strings.Repeat("ab", 5<<20) + "','after'),(2,'x','second');\n")
	res, got := scanDump(t, b.String(), nil)
	s := got["notes"].wins[300]
	if res.Dump.Unread != 0 || len(s.Rows) != 2 {
		t.Fatalf("%d unread, %d rows", res.Dump.Unread, len(s.Rows))
	}
	bi, ti := s.Index("body"), s.Index("tail")
	if n := len(s.Rows[0][bi].String); n != DefaultMaxValueLen {
		t.Errorf("a value of 10 MiB is kept as %d bytes, want %d", n, DefaultMaxValueLen)
	}
	if s.Rows[0][ti].String != "after" || s.Rows[1][bi].String != "x" || s.Rows[1][ti].String != "second" {
		t.Errorf("the values after it: %v %v", s.Rows[0], s.Rows[1])
	}
}

func eavDump(n int) string {
	var b strings.Builder
	b.WriteString("CREATE TABLE `eav_attribute` (`attribute_id` int unsigned NOT NULL AUTO_INCREMENT, `entity_type_id` smallint unsigned NOT NULL DEFAULT 0, " +
		"`attribute_code` varchar(255) DEFAULT NULL, PRIMARY KEY (`attribute_id`));\n")
	var rows []string
	for i := 1; i <= n; i++ {
		rows = append(rows, fmt.Sprintf("(%d,1,'attr_%d')", i, i))
	}
	insertAll(&b, "eav_attribute", "`attribute_id`,`entity_type_id`,`attribute_code`", rows)
	return b.String()
}

func TestDumpWholeTableRowsCap(t *testing.T) {
	// The real limit: 150,000 rows stop at 100,000, with the warning.
	res, _ := scanDump(t, eavDump(150000), nil)
	if !hasWarning(res, "only the first 100000 rows of eav_attribute were kept for the platform checks") {
		t.Errorf("warnings: %v", res.Warnings)
	}
	// Under it, no warning.
	res, _ = scanDump(t, eavDump(99999), nil)
	if hasWarning(res, "were kept for the platform checks") {
		t.Errorf("warnings: %v", res.Warnings)
	}
	// Shrunk.
	res, _ = scanDump(t, eavDump(80), func(o *DumpOptions) { o.limits.wholeTableRows = 50 })
	if !hasWarning(res, "only the first 50 rows of eav_attribute") {
		t.Errorf("shrunk: %v", res.Warnings)
	}
}

func TestDumpKVKeyCapAtDefault(t *testing.T) {
	var b strings.Builder
	b.WriteString(wpPosts(""))
	keys := make([]string, 0, 200600)
	for i := range 200500 {
		keys = append(keys, fmt.Sprintf("k%06d", i))
	}
	keys = append(keys, "_order_key", "_bbp_author_ip")
	insertAll(&b, "wp_postmeta", "`post_id`,`meta_key`,`meta_value`", metaRows(keys, 1))
	res, got := scanDump(t, b.String(), nil)
	c := got["wp_postmeta"]
	if c.kvMode() != int(modeList) || !c.kv.truncated {
		t.Fatalf("mode %d, truncated %v", c.kvMode(), c.kv.truncated)
	}
	// The smallest 200,000 by name, and the preset's two.
	if n := len(c.kv.keys); n != 200002 {
		t.Errorf("%d keys kept, want 200,002", n)
	}
	if len(c.kv.values["_order_key"]) != 1 || len(c.kv.values["_bbp_author_ip"]) != 1 {
		t.Errorf("the preset's keys have no values")
	}
	if !slices.Contains(c.kv.keys, "k199999") || slices.Contains(c.kv.keys, "k200000") {
		t.Errorf("the keys kept aren't the smallest by name")
	}
	if !hasWarning(res, "wp_postmeta has more than 200000 keys; the smallest 200000 by name were judged") {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

func TestDumpKVNameBytesCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(usermeta)
	var keys []string
	for i := range 100 {
		keys = append(keys, fmt.Sprintf("key%03d", i))
	}
	keys = append(keys, "wp_capabilities")
	insertAll(&b, "usermeta", "`user_id`,`meta_key`,`meta_value`", metaRows(keys, 1))
	// Each name counts for its text and kvKeyOverhead: ten names fit.
	res, got := scanDump(t, b.String(), func(o *DumpOptions) {
		o.limits.wholeRows, o.limits.keyBytes = 10, 10*(kvKeyOverhead+6)
	})
	c := got["usermeta"]
	if c.kvMode() != int(modeList) || !c.kv.truncated {
		t.Fatalf("mode %d, truncated %v", c.kvMode(), c.kv.truncated)
	}
	kept := 0
	for _, k := range c.kv.keys {
		if strings.HasPrefix(k, "key") {
			kept++
		}
	}
	if kept != 10 || !slices.Contains(c.kv.keys, "key009") || slices.Contains(c.kv.keys, "key010") {
		t.Errorf("%d names kept: %v", kept, c.kv.keys)
	}
	if !hasWarning(res, "usermeta has more key names than the scan holds") {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

// --- the accounting ---

func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func TestDumpHeldBytesTrackHeap(t *testing.T) {
	// What the collectors count themselves as holding must cover what they
	// take of the heap, for rows of few small values and of wide ones, and for
	// key/value rows; and not be several times it.
	check := func(name string, held int64, real uint64) {
		t.Helper()
		t.Logf("%s: counted %d, heap %d (%.2f)", name, held, real, float64(held)/float64(real))
		if held < int64(real) || held > 2*int64(real) {
			t.Errorf("%s: counted %d bytes, but the heap grew by %d", name, held, real)
		}
	}
	for _, c := range []struct {
		name        string
		rows, cells int
		width       int
	}{{"narrow rows", 40000, 4, 10}, {"wide rows", 400, 6, 20000}} {
		var held int64
		base := liveHeap()
		h := &rowHeap{cap: 1 << 30, held: &held}
		for i := range c.rows {
			vals := make([]sql.NullString, c.cells)
			for j := range vals {
				vals[j] = sql.NullString{String: string(slices.Repeat([]byte{byte('a' + (i+j)%26)}, c.width)), Valid: true}
			}
			h.offer(ikeyInt(int64(i)), int64(i), func() []sql.NullString { return vals })
		}
		now := liveHeap()
		check(c.name, held, now-base)
		runtime.KeepAlive(h)
	}

	// Key/value rows: 40,000 keys of 8 rows.
	lim := (DumpOptions{}).lim()
	col := &model.Column{DataType: "varchar", ColumnType: "varchar(255)"}
	kc := &kvCollect{keyCol: col, valCol: col, keyI: 0, valI: 1, pkI: -1, valueLen: 4096, perKey: 8,
		keys: map[string]*kvKey{}, protected: map[string]bool{}}
	base := liveHeap()
	acc := &fakeRow{vals: make([]sqldump.Value, 2)}
	for i := range 40000 {
		acc.vals[0] = sqldump.Value{Kind: sqldump.ValString, Bytes: []byte(fmt.Sprintf("meta_key_%06d", i))}
		for j := range 8 {
			acc.vals[1] = sqldump.Value{Kind: sqldump.ValString, Bytes: []byte(fmt.Sprintf("a value of some length %d", i*8+j))}
			kc.add(acc, int64(i*8+j+1), lim)
		}
	}
	check("key/value rows", kc.held(), liveHeap()-base)
	runtime.KeepAlive(kc)
}

type fakeRow struct{ vals []sqldump.Value }

func (f *fakeRow) val(j int) *sqldump.Value { return &f.vals[j] }

// --- the ascending read ---

func TestWindowAscendingDecodesOnlyWhatCanEnter(t *testing.T) {
	for _, repeat := range []bool{false, true} {
		n := 5000
		keys := seq(n, 1, 3)
		if repeat {
			for i := 0; i < n; i += 4 {
				keys[i+1].Set(keys[i])
			}
		}
		var r intRange
		for _, k := range keys {
			r.add(valueOf(k))
		}
		if r.unsorted || r.n != int64(n) {
			t.Fatalf("range of an ascending file: %+v", r)
		}
		w := newWindow(300, &r, int64(n))
		built := 0
		for i, k := range keys {
			w.offer(ikeyOf(k), true, int64(i+1), func() []sql.NullString { built++; return nil })
		}
		_, got := w.result()
		if want := refWindow(300, keys); !equalInts(got, want) {
			t.Errorf("repeat %v: ordinals differ\n got %v\nwant %v", repeat, head(got), head(want))
		}
		// The first 100, the first 100 from the middle, and the last 100.
		if built > 300 {
			t.Errorf("repeat %v: %d rows decoded, want at most 300", repeat, built)
		}
	}
	// A file out of order is read as before.
	keys := seq(2000, 1, 1)
	keys[10], keys[1500] = keys[1500], keys[10]
	var r intRange
	for _, k := range keys {
		r.add(valueOf(k))
	}
	if !r.unsorted {
		t.Fatal("a swapped pair isn't seen")
	}
	w := newWindow(300, &r, 2000)
	for i, k := range keys {
		w.offer(ikeyOf(k), true, int64(i+1), func() []sql.NullString { return nil })
	}
	_, ords := w.result()
	if want := refWindow(300, keys); !equalInts(ords, want) {
		t.Errorf("out of order: ordinals differ\n got %v\nwant %v", head(ords), head(want))
	}
}
