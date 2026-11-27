package leak

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// All values here are invented, at a domain that doesn't exist.

const prodHead = "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\nCREATE DATABASE `shop`;\nUSE `shop`;\n"

func tableOf(name string) string {
	return "CREATE TABLE `" + name + "` (`id` int NOT NULL, `email` varchar(100) DEFAULT NULL, PRIMARY KEY (`id`)) ENGINE=InnoDB;\n"
}

// mailRows is the rows from..to of a table of people: row i holds person i.
func mailRows(table string, from, to int) string {
	var b strings.Builder
	for i := from; i <= to; i += 200 {
		b.WriteString("INSERT INTO `" + table + "` VALUES ")
		for j := i; j <= min(i+199, to); j++ {
			if j > i {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "(%d,'person.%d@%s')", j, j, fakeDomain)
		}
		b.WriteString(";\n")
	}
	return b.String()
}

func openOf(text string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(text)), nil }
}

func hashDump(t *testing.T, text string, opts HashDumpOptions) (*File, []string, error) {
	t.Helper()
	opts.Version = "test"
	if opts.Preset == "" {
		opts.Preset = "auto"
	}
	return HashDump(context.Background(), openOf(text), testKey(t), opts)
}

func mustHashDump(t *testing.T, text string, opts HashDumpOptions) *File {
	t.Helper()
	f, _, err := hashDump(t, text, opts)
	if err != nil {
		t.Fatalf("HashDump: %v", err)
	}
	return f
}

func dumpColumn(t *testing.T, f *File, table, column, metaKey string) FileColumn {
	t.Helper()
	for _, c := range f.Columns {
		if c.Table == table && c.Column == column && c.MetaKey == metaKey {
			return c
		}
	}
	t.Fatalf("no column %s.%s[%s] in the file: %+v", table, column, metaKey, f.Columns)
	return FileColumn{}
}

func TestEverySpread(t *testing.T) {
	for _, c := range []struct {
		rows int64
		want int64
	}{{0, 1}, {1, 1}, {2999, 1}, {3000, 1}, {3001, 2}, {6000, 2}, {6001, 3}, {10000, 4}} {
		if got := every(c.rows, 3000); got != c.want {
			t.Errorf("every(%d) = %d, want %d", c.rows, got, c.want)
		}
	}
}

// A table of 3,000 rows is hashed whole; one of 3,001 is spread, every second
// row from the first.
func TestHashDumpSpreadSizes(t *testing.T) {
	text := prodHead + tableOf("small") + mailRows("small", 1, 3000) + tableOf("big") + mailRows("big", 1, 3001)
	f := mustHashDump(t, text, HashDumpOptions{})
	small, big := dumpColumn(t, f, "small", "email", ""), dumpColumn(t, f, "big", "email", "")
	if small.Sample != model.SampleAllRows || !small.Exact || small.Values != 3000 || small.RowsRead != 3000 || small.EstimatedValues != 3000 || small.RowsEstimate != 3000 {
		t.Errorf("3,000 rows: %+v", withoutHashes(small))
	}
	// Rows 1, 3, 5, ..., 3001.
	if big.Sample != model.SampleSpread || big.Exact || big.Values != 1501 || big.RowsRead != 1501 || big.RowsEstimate != 3001 {
		t.Errorf("3,001 rows: %+v", withoutHashes(big))
	}
	// 3,001 rows, 1,501 distinct values among 1,501 picked: the estimate is the table.
	if big.EstimatedValues != 3001 {
		t.Errorf("estimate %d, want 3001", big.EstimatedValues)
	}
	if f.Database != "shop" || f.SampleRows != DefaultSampleRows {
		t.Errorf("database %q, sample rows %d", f.Database, f.SampleRows)
	}
}

func withoutHashes(c FileColumn) FileColumn {
	c.Hashes = nil
	return c
}

// Hashing a dump and comparing a dump of the rows it kept finds all of them,
// and a dump of the rows it passed over finds none: the spread is every k-th
// row in file order.
func TestHashDumpSpreadPicksEveryKthRow(t *testing.T) {
	key := testKey(t)
	const n = 10
	text := prodHead + tableOf("people") + mailRows("people", 1, 95)
	f := mustHashDump(t, text, HashDumpOptions{SampleRows: n})
	c := dumpColumn(t, f, "people", "email", "")
	// k = 10: rows 1, 11, ..., 91.
	if c.Sample != model.SampleSpread || c.Exact || c.Values != 10 || c.RowsRead != 10 || c.EstimatedValues != 95 {
		t.Fatalf("%+v", withoutHashes(c))
	}
	var kept, passed strings.Builder
	kept.WriteString(prodHead + tableOf("people"))
	passed.WriteString(prodHead + tableOf("people"))
	for i := 1; i <= 95; i++ {
		row := fmt.Sprintf("INSERT INTO `people` VALUES (%d,'person.%d@%s');\n", i, i, fakeDomain)
		if (i-1)%10 == 0 {
			kept.WriteString(row)
		} else {
			passed.WriteString(row)
		}
	}
	if got := columnOf(t, compareDump(t, kept.String(), f, key, CompareDumpOptions{}), "people.email", model.LeakEmail); got.Found != 10 || got.Sampled != 10 {
		t.Errorf("the kept rows: found %d of %d", got.Found, got.Sampled)
	}
	if got := columnOf(t, compareDump(t, passed.String(), f, key, CompareDumpOptions{}), "people.email", model.LeakEmail); got.Found != 0 {
		t.Errorf("the rows passed over: found %d", got.Found)
	}
}

const dumpMetaTable = "CREATE TABLE `wp_usermeta` (`umeta_id` bigint unsigned NOT NULL AUTO_INCREMENT, `user_id` bigint NOT NULL DEFAULT 0, " +
	"`meta_key` varchar(255) DEFAULT NULL, `meta_value` longtext, PRIMARY KEY (`umeta_id`), KEY `meta_key` (`meta_key`(191)));\n"

// metaDump holds a key/value table: billing_email with 25 rows, billing_phone
// with 8 and 'note' with 40 that hold nothing to count.
func metaDump() string {
	var b strings.Builder
	b.WriteString(prodHead + dumpMetaTable)
	var rows []string
	add := func(key string, n int, value func(i int) string) {
		for i := 1; i <= n; i++ {
			rows = append(rows, fmt.Sprintf("(%d,'%s','%s')", 1+i%3, key, value(i)))
		}
	}
	add("billing_email", 25, func(i int) string { return fmt.Sprintf("buyer.%d@%s", i, fakeDomain) })
	add("note", 40, func(i int) string { return fmt.Sprintf("note %d", i) })
	add("billing_phone", 8, func(i int) string { return fmt.Sprintf("+30 69%08d", 10000000+i) })
	b.WriteString("INSERT INTO `wp_usermeta` (`user_id`,`meta_key`,`meta_value`) VALUES " + strings.Join(rows, ",") + ";\n")
	return b.String()
}

func TestHashDumpKeyValueSpread(t *testing.T) {
	key := testKey(t)
	text := metaDump()
	f := mustHashDump(t, text, HashDumpOptions{SampleRows: 10})
	em := dumpColumn(t, f, "wp_usermeta", "meta_value", "billing_email")
	ph := dumpColumn(t, f, "wp_usermeta", "meta_value", "billing_phone")
	// 25 rows at 10 values: k = 3, rows 1, 4, ..., 25, which is 9 of them.
	if em.Sample != model.SampleSpread || em.Exact || em.Values != 9 || em.RowsRead != 9 || em.EstimatedValues != 25 {
		t.Errorf("billing_email: %+v", withoutHashes(em))
	}
	// 8 rows are under it: all of them.
	if ph.Sample != model.SampleAllRows || !ph.Exact || ph.Values != 8 || ph.RowsRead != 8 || ph.EstimatedValues != 8 {
		t.Errorf("billing_phone: %+v", withoutHashes(ph))
	}
	if em.RowsEstimate != 73 {
		t.Errorf("rows estimate %d", em.RowsEstimate)
	}
	if got := columnOf(t, compareDump(t, text, f, key, CompareDumpOptions{}), "wp_usermeta.meta_value[billing_email]", model.LeakEmail); got.Found != 9 || got.Sampled != 9 {
		t.Errorf("compare: found %d of %d", got.Found, got.Sampled)
	}
}

// The counters are the live sampling's, so the estimate and the odds follow:
// a key hashed whole gives its distinct count, a spread key its rows' share.
func TestHashDumpCountersFeedTheEstimate(t *testing.T) {
	s := &source{rowsRead: 73, keyRows: 25, picked: 9}
	if got := estimateValues(73, s, 9, 9, false); got != 25 {
		t.Errorf("a spread key: %d", got)
	}
	if got := estimateValues(73, s, 9, 9, true); got != 9 {
		t.Errorf("a key read whole: %d", got)
	}
}

func TestHashDumpUnreadStatementOfAPlannedTable(t *testing.T) {
	key := testKey(t)
	text := prodHead + tableOf("users") + mailRows("users", 1, 20) +
		tableOf("members") + mailRows("members", 1, 20) +
		"INSERT INTO `users` SELECT * FROM `users`;\n"
	f, _, err := hashDump(t, text, HashDumpOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Columns {
		if c.Table == "users" {
			t.Errorf("users is hashed: %+v", withoutHashes(c))
		}
	}
	dumpColumn(t, f, "members", "email", "")
	var out []model.LeakLeftOut
	for _, l := range f.LeftOut {
		if strings.HasPrefix(l.Location, "users") {
			out = append(out, l)
		}
	}
	want := []model.LeakLeftOut{{Location: "users.email", Why: "a statement of this table in the dump wasn't read", NotRead: true}}
	if !slices.Equal(out, want) {
		t.Errorf("left out %+v, want %+v", out, want)
	}
	// compare counts it as unchecked, so the gate fails.
	res := compareDump(t, prodHead+tableOf("members")+mailRows("members", 100, 110), f, key, CompareDumpOptions{})
	if hits, unchecked := Gate(res, model.SeverityHigh); hits != 0 || unchecked != 1 {
		t.Errorf("gate: %d hits, %d unchecked", hits, unchecked)
	}
}

func TestHashDumpFailsClosed(t *testing.T) {
	base := prodHead + tableOf("users") + mailRows("users", 1, 20)
	for _, c := range []struct {
		name string
		text string
		want error
	}{
		{"a statement whose table can't be told", base + "CALL cleanup();\n", ErrDumpUnreadNoTable},
		{"an SQL mode that became unknown", base + "SET sql_mode = @unknown;\n" + mailRows("users", 21, 30), ErrDumpSQLMode},
		{"two statements before the delimiter", base + tableOf("other") + "DELIMITER ;;\n" +
			strings.TrimSuffix(mailRows("users", 21, 30), "\n") + " " + strings.TrimSuffix(mailRows("other", 1, 10), ";\n") + ";;\nDELIMITER ;\n", ErrDumpUnreadNoTable},
		{"a command of the client's own", base + "use other\n" + mailRows("users", 21, 30), ErrDumpUnreadNoTable},
		{"a chunk that changes the session", base + tableOf("other") + "DELIMITER ;;\n" +
			strings.TrimSuffix(mailRows("other", 1, 10), "\n") + " SET NAMES latin1;;\nDELIMITER ;\n" + mailRows("users", 21, 30), ErrDumpUnreadNoTable},
		{"a USE in a version comment", base + "/*!99999 USE other */;\n" + mailRows("users", 21, 30), ErrDumpUnreadNoTable},
	} {
		f, _, err := hashDump(t, c.text, HashDumpOptions{})
		if f != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: file %v, error %v", c.name, f != nil, err)
		}
	}
	// An unread statement of a table that isn't sampled, or of another database, costs nothing.
	for _, text := range []string{
		base + tableOf("other") + "INSERT INTO `other` SELECT * FROM `other`;\n",
	} {
		if _, _, err := hashDump(t, text, HashDumpOptions{}); err != nil {
			t.Errorf("%v", err)
		}
	}
}

func TestHashDumpFileChanged(t *testing.T) {
	text := prodHead + tableOf("users") + mailRows("users", 1, 20)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	opts := HashDumpOptions{Size: int64(len(text)), ModTime: t0}
	for _, c := range []struct {
		name string
		stat func() (int64, time.Time, error)
		want bool
	}{
		{"the same", func() (int64, time.Time, error) { return int64(len(text)), t0, nil }, false},
		{"a new size", func() (int64, time.Time, error) { return int64(len(text)) + 1, t0, nil }, true},
		{"a new time", func() (int64, time.Time, error) { return int64(len(text)), t0.Add(time.Second), nil }, true},
	} {
		opts.Stat = c.stat
		_, _, err := hashDump(t, text, opts)
		if c.want != errors.Is(err, scan.ErrDumpChanged) || (!c.want && err != nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// The third pass reads other rows than the first two.
	calls := 0
	open := func() (io.ReadCloser, error) {
		calls++
		if calls == 3 {
			return io.NopCloser(strings.NewReader(prodHead + tableOf("users") + mailRows("users", 1, 19))), nil
		}
		return io.NopCloser(strings.NewReader(text)), nil
	}
	_, _, err := HashDump(context.Background(), open, testKey(t), HashDumpOptions{Version: "test", Preset: "auto"})
	if !errors.Is(err, scan.ErrDumpChanged) {
		t.Errorf("a changed third pass: %v", err)
	}
	if calls != 3 {
		t.Errorf("%d reads of the file, want 3", calls)
	}
}

func TestHashDumpTableBytes(t *testing.T) {
	text := prodHead + tableOf("users") + mailRows("users", 1, 100)
	f, warnings, err := hashDump(t, text, HashDumpOptions{tableBytes: 500})
	if err != nil {
		t.Fatal(err)
	}
	c := dumpColumn(t, f, "users", "email", "")
	if c.Sample != model.SampleFirstRows || c.Exact || c.Values == 0 || c.Values >= 100 {
		t.Errorf("%+v", withoutHashes(c))
	}
	if !slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, "the sample of users stopped") }) {
		t.Errorf("warnings %q", warnings)
	}
}

func TestHashDumpNothingToHash(t *testing.T) {
	f, _, err := hashDump(t, prodHead+tableOf("users")+"INSERT INTO `users` VALUES (1,'x');\n", HashDumpOptions{})
	if f != nil || !errors.Is(err, ErrNothingToHash) {
		t.Errorf("file %v, error %v", f != nil, err)
	}
}
