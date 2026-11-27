package leak

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
)

// All values here are invented, at a domain that doesn't exist.

const (
	mailA = "alice@" + fakeDomain
	mailB = "bob@" + fakeDomain
	mailC = "carol@" + fakeDomain
)

// hcol is a column of a hash file made in a test: its location, and the
// values production's sample held.
type hcol struct {
	table, column, keyColumn, metaKey string
	kind                              model.LeakKind
	maxChars                          int
	values                            []string
}

// hashFile makes a hash file without a server, the way Hash writes one.
func hashFile(t *testing.T, key Key, cols ...hcol) *File {
	t.Helper()
	salt := bytes.Repeat([]byte{7}, saltLen)
	f := &File{Format: fileFormat, Version: fileVersion, Salt: salt, KeyCheck: key.keyCheck(salt), Database: "prod",
		SampleRows: DefaultSampleRows, CreatedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	hs, ex := key.hasher(salt), newExtractor(&Allowlist{})
	for _, c := range cols {
		fc := FileColumn{Table: c.table, Column: c.column, KeyColumn: c.keyColumn, MetaKey: c.metaKey, Kind: c.kind,
			MaxChars: c.maxChars, Sample: model.SampleAllRows, Exact: true}
		if fc.MaxChars == 0 {
			fc.MaxChars = 200
		}
		prefix := hs.prefix(c.table, c.column, c.metaKey, c.kind)
		var sums [][hashLen]byte
		for _, v := range c.values {
			ex.values(v, &wants{}, func(k model.LeakKind, norm string) {
				if k == c.kind {
					sums = append(sums, hs.of(prefix, norm))
				}
			})
		}
		sort.Slice(sums, func(i, j int) bool { return bytes.Compare(sums[i][:], sums[j][:]) < 0 })
		for _, s := range sums {
			fc.Hashes = append(fc.Hashes, s[:]...)
		}
		fc.Values, fc.EstimatedValues = len(sums), int64(len(sums))
		f.Columns = append(f.Columns, fc)
	}
	return f
}

func email(table, column string, values ...string) hcol {
	return hcol{table: table, column: column, kind: model.LeakEmail, values: values}
}

const dumpTop = "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\nCREATE DATABASE `shop`;\nUSE `shop`;\n"

const usersTable = "CREATE TABLE `users` (`id` int NOT NULL, `email` varchar(100) DEFAULT NULL, PRIMARY KEY (`id`)) ENGINE=InnoDB;\n"

func compareDump(t *testing.T, sql string, f *File, key Key, opts CompareDumpOptions) *model.LeakResult {
	t.Helper()
	res, err := CompareDump(context.Background(), strings.NewReader(sql), f, key, opts)
	if err != nil {
		t.Fatalf("CompareDump: %v", err)
	}
	return res
}

// maskedRows is a row of users with no sampled address, then a statement that
// isn't read.
const maskedRows = "INSERT INTO `users` VALUES (1,'x@elsewhere.prodmask-fixture.dev');\nINSERT INTO `users` SELECT * FROM `users`;\n"

func TestCompareDumpCountsAndStates(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key,
		email("users", "email", mailA, mailB, mailC),
		email("users", "nickname", mailA),
		email("gone", "email", mailA),
		email("blobs", "data", mailA),
		email("v", "email", mailA),
		email("loose", "email", mailA),
	)
	sql := dumpTop + usersTable +
		"INSERT INTO `users` VALUES (1,'" + mailA + "'),(2,'" + mailB + "'),(3,'someone@elsewhere.prodmask-fixture.dev'),(4,NULL);\n" +
		"CREATE TABLE `blobs` (`id` int, `data` blob) ENGINE=InnoDB;\n" +
		"INSERT INTO `blobs` VALUES (1,0x" + "616161" + ");\n" +
		"CREATE TABLE `base` (`id` int, `email` text);\n" +
		"CREATE VIEW `v` AS SELECT 1 AS `email`;\n" +
		"INSERT INTO `loose` VALUES ('x');\n"
	res := compareDump(t, sql, f, key, CompareDumpOptions{Version: "test", File: "shop.sql"})

	want := map[string]string{
		"users.email": model.LeakRead, "users.nickname": model.LeakNotOnStaging, "gone.email": model.LeakNotOnStaging,
		"blobs.data": model.LeakUnreadable, "v.email": model.LeakUnreadable, "loose.email": model.LeakUnreadable,
	}
	for _, c := range res.Columns {
		if c.State != want[c.Location()] {
			t.Errorf("%s: state %s, want %s", c.Location(), c.State, want[c.Location()])
		}
	}
	c := columnOf(t, res, "users.email", model.LeakEmail)
	if c.Found != 2 || c.Sampled != 3 || c.Rows != 2 || c.Values != 3 || c.RowsRead != 4 {
		t.Errorf("users.email: found %d of %d on %d rows, %d values, %d rows read", c.Found, c.Sampled, c.Rows, c.Values, c.RowsRead)
	}
	if hits, unchecked := Gate(res, model.SeverityHigh); hits != 1 || unchecked != 5 {
		t.Errorf("gate: %d hits, %d unchecked", hits, unchecked)
	}
	if res.Dump == nil || res.Dump.File != "shop.sql" || res.Dump.Rows != 6 || res.Database != "shop" {
		t.Errorf("dump %+v, database %q", res.Dump, res.Database)
	}
	if !strings.Contains(columnOf(t, res, "gone.email", model.LeakEmail).Line, "not in the dump") {
		t.Errorf("line %q", columnOf(t, res, "gone.email", model.LeakEmail).Line)
	}
	want1 := "Read every value of the 1 column or key in the dump; production's hashes are a sample of up to 3,000 values of each, so a zero isn't proof."
	if res.Dump.Judged != want1 {
		t.Errorf("judged %q", res.Dump.Judged)
	}
	var out bytes.Buffer
	if err := report.LeakText(&out, res, false); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"dump file shop.sql", "not in the dump", want1} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("report has no %q:\n%s", s, out.String())
		}
	}
	for _, s := range []string{"found on this", "not on staging", mailA, "alice@"} {
		if strings.Contains(out.String(), s) {
			t.Errorf("report has %q:\n%s", s, out.String())
		}
	}
	var js bytes.Buffer
	report.LeakJSON(&js, res)
	if !strings.Contains(js.String(), `"dump": {`) || !strings.Contains(js.String(), "so a zero isn't proof.") || strings.Contains(js.String(), "alice@") {
		t.Errorf("json:\n%s", js.String())
	}
}

func TestCompareDumpNamesTheServer(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA))
	sql := "-- MariaDB dump 10.19  Distrib 11.8.2-MariaDB, for Linux (x86_64)\n--\n-- Host: localhost    Database: shop\n" +
		"-- Server version\t11.8.2-MariaDB\n\n" + dumpTop + usersTable + "INSERT INTO `users` VALUES (1,'" + mailA + "');\n"
	res := compareDump(t, sql, f, key, CompareDumpOptions{File: "shop.sql.gz"})
	var out bytes.Buffer
	report.LeakText(&out, res, false)
	if first := strings.SplitN(out.String(), "\n", 2)[0]; first != "prodmask leak-check · shop · dump file shop.sql.gz (MariaDB 11.8.2)" {
		t.Errorf("header %q", first)
	}
}

func TestCompareDumpKeyedAndPlain(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key,
		email("users", "email", mailA),
		hcol{table: "meta", column: "meta_value", keyColumn: "meta_key", metaKey: "billing_email", kind: model.LeakEmail, values: []string{mailB}},
		hcol{table: "meta", column: "meta_value", keyColumn: "meta_key", metaKey: "alt_*", kind: model.LeakEmail, values: []string{mailC}},
	)
	sql := dumpTop + usersTable +
		"INSERT INTO `users` VALUES (1,'" + mailA + "');\n" +
		"CREATE TABLE `meta` (`id` int NOT NULL, `meta_key` varchar(50), `meta_value` longtext, PRIMARY KEY (`id`));\n" +
		"INSERT INTO `meta` VALUES (1,'billing_email','" + mailB + "'),(2,'note','" + mailB + "'),(3,'ALT_one','" + mailC + "')," +
		"(4,'alt_two','" + mailB + "'),(5,'billing_email',NULL);\n"
	res := compareDump(t, sql, f, key, CompareDumpOptions{})
	if c := columnOf(t, res, "users.email", model.LeakEmail); c.Found != 1 || c.State != model.LeakRead {
		t.Errorf("plain: %+v", c)
	}
	if c := columnOf(t, res, "meta.meta_value[billing_email]", model.LeakEmail); c.Found != 1 || c.Values != 1 || c.RowsRead != 5 {
		t.Errorf("keyed: found %d, %d values, %d rows read", c.Found, c.Values, c.RowsRead)
	}
	// The pattern takes its keys' values, and only those: bob's address under
	// alt_two isn't among its sample.
	if c := columnOf(t, res, "meta.meta_value[alt_*]", model.LeakEmail); c.Found != 1 || c.Values != 2 {
		t.Errorf("pattern: found %d, %d values", c.Found, c.Values)
	}
}

func TestCompareDumpTableNamesIgnoreCase(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("Users", "EMAIL", mailA))
	for _, name := range []string{"users", "USERS", "Users"} {
		sql := dumpTop + strings.Replace(usersTable, "`users`", "`"+name+"`", 1) +
			"INSERT INTO `" + name + "` VALUES (1,'" + mailA + "');\n"
		c := columnOf(t, compareDump(t, sql, f, key, CompareDumpOptions{}), "Users.EMAIL", model.LeakEmail)
		if c.State != model.LeakRead || c.Found != 1 {
			t.Errorf("%s: state %s, found %d", name, c.State, c.Found)
		}
	}
}

// A value is cut at the file column's MaxChars, in characters as LEFT counts
// them, so an address that ends past the cut isn't found.
func TestCompareDumpCutsAtMaxChars(t *testing.T) {
	key := testKey(t)
	value := "éééééé " + mailA
	chars := len([]rune(value))
	sql := dumpTop + usersTable + "INSERT INTO `users` VALUES (1,'" + value + "');\n"
	for _, c := range []struct {
		maxChars int
		found    int
	}{{chars, 1}, {chars + 40, 1}, {chars - 1, 0}, {chars - 5, 0}} {
		h := email("users", "email", value)
		h.maxChars = c.maxChars
		// The hashes are of the whole address, as production's are.
		f := hashFile(t, key, h)
		got := columnOf(t, compareDump(t, sql, f, key, CompareDumpOptions{}), "users.email", model.LeakEmail)
		if got.Found != c.found {
			t.Errorf("a cut at %d of %d characters: found %d, want %d", c.maxChars, chars, got.Found, c.found)
		}
	}
}

func TestCompareDumpUnreadStatements(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA, mailB), email("other", "email", mailC))
	other := "CREATE TABLE `other` (`id` int, `email` varchar(100));\nINSERT INTO `other` VALUES (1,'" + mailC + "');\n"
	base := dumpTop + usersTable + "INSERT INTO `users` VALUES (1,'" + mailA + "');\n" + other

	t.Run("a table's own statement stops its columns", func(t *testing.T) {
		sql := base + "INSERT INTO `users` SELECT * FROM `users`;\nINSERT INTO `users` VALUES (2,'" + mailB + "');\n"
		res := compareDump(t, sql, f, key, CompareDumpOptions{})
		u, o := columnOf(t, res, "users.email", model.LeakEmail), columnOf(t, res, "other.email", model.LeakEmail)
		if u.State != model.LeakStopped || u.StoppedBy != stoppedTableUnread || u.Found != 2 || u.RowsRead != 2 {
			t.Errorf("users: %+v", u)
		}
		if o.State != model.LeakRead || o.Found != 1 {
			t.Errorf("other: %+v", o)
		}
		if hits, unchecked := Gate(res, model.SeverityHigh); hits != 2 || unchecked != 0 {
			t.Errorf("gate: %d hits, %d unchecked", hits, unchecked)
		}
		masked := dumpTop + usersTable + maskedRows + other
		if hits, unchecked := Gate(compareDump(t, masked, f, key, CompareDumpOptions{}), model.SeverityHigh); hits != 1 || unchecked != 1 {
			t.Errorf("gate with no hit in the stopped table: %d hits, %d unchecked", hits, unchecked)
		}
		if res.Dump.Unread != 1 || len(res.Dump.UnreadList) != 1 || res.Dump.UnreadList[0].Table != "users" {
			t.Errorf("unread %d: %+v", res.Dump.Unread, res.Dump.UnreadList)
		}
		var out bytes.Buffer
		report.LeakText(&out, res, false)
		if !strings.Contains(out.String(), "stopped after 2 rows (a statement of this table in the dump wasn't read)") {
			t.Errorf("report:\n%s", out.String())
		}
	})

	t.Run("a statement of another table, or not in the file, costs nothing", func(t *testing.T) {
		sql := base + "CREATE TABLE `third` (`id` int);\nINSERT INTO `third` SELECT 1;\n"
		res := compareDump(t, sql, f, key, CompareDumpOptions{})
		if res.Dump.Unread != 1 {
			t.Fatalf("unread %d", res.Dump.Unread)
		}
		for _, c := range res.Columns {
			if c.State != model.LeakRead {
				t.Errorf("%s: %s", c.Location(), c.State)
			}
		}
	})

	t.Run("a statement with no table stops every column", func(t *testing.T) {
		res := compareDump(t, base+"CALL cleanup();\n", f, key, CompareDumpOptions{})
		if res.Dump.Unread != 1 || res.Dump.UnreadList[0].Table != "" {
			t.Fatalf("unread %d: %+v", res.Dump.Unread, res.Dump.UnreadList)
		}
		for _, c := range res.Columns {
			if c.State != model.LeakStopped || c.StoppedBy != stoppedAnyUnread {
				t.Errorf("%s: %s %q", c.Location(), c.State, c.StoppedBy)
			}
		}
		if _, unchecked := Gate(res, model.SeverityHigh); unchecked != 0 {
			// Both columns hold hits, which count first.
			t.Logf("unchecked %d", unchecked)
		}
	})

	t.Run("an unread statement of another database doesn't count", func(t *testing.T) {
		sql := base + "CREATE DATABASE `b`;\nUSE `b`;\nCREATE TABLE `zzz` (`id` int);\nINSERT INTO `zzz` SELECT 1;\n"
		res := compareDump(t, sql, f, key, CompareDumpOptions{Database: "shop"})
		for _, c := range res.Columns {
			if c.State != model.LeakRead {
				t.Errorf("%s: %s", c.Location(), c.State)
			}
		}
	})
}

func TestCompareDumpDatabases(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA, mailB))
	rows := func(mail string) string {
		return usersTable + "INSERT INTO `users` VALUES (1,'" + mail + "');\n"
	}
	two := "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\nCREATE DATABASE `a`;\nUSE `a`;\n" + rows(mailA) +
		"CREATE DATABASE `b`;\nUSE `b`;\n" + rows(mailB)

	if res, err := CompareDump(context.Background(), strings.NewReader(two), f, key, CompareDumpOptions{}); !errors.Is(err, ErrSecondDatabase) || res != nil {
		t.Errorf("two databases, none chosen: %v, %v", res, err)
	}
	if strings.Contains(ErrSecondDatabase.Error(), "alice") || !strings.Contains(ErrSecondDatabase.Error(), "--database") {
		t.Errorf("error %q", ErrSecondDatabase)
	}
	for _, c := range []struct {
		db     string
		rows   int64
		hit    int
		dbName string
	}{{"a", 1, 1, "a"}, {"b", 1, 1, "b"}, {"c", 0, 0, ""}} { // never what --database holds, unless the file names it
		res := compareDump(t, two, f, key, CompareDumpOptions{Database: c.db})
		col := columnOf(t, res, "users.email", model.LeakEmail)
		if col.RowsRead != c.rows || col.Found != c.hit || res.Database != c.dbName {
			t.Errorf("database %s: %d rows, found %d, database %q, state %s", c.db, col.RowsRead, col.Found, res.Database, col.State)
		}
	}
	// A second database with no table of the file is no trouble.
	oneOfTwo := "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\nCREATE DATABASE `a`;\nUSE `a`;\n" + rows(mailA) +
		"CREATE DATABASE `b`;\nUSE `b`;\nCREATE TABLE `logs` (`id` int);\n"
	if c := columnOf(t, compareDump(t, oneOfTwo, f, key, CompareDumpOptions{}), "users.email", model.LeakEmail); c.Found != 1 {
		t.Errorf("found %d", c.Found)
	}
}

// A dump that never names its database, as mysqldump writes one database
// without --databases, holds its tables in the unnamed one. With a database
// chosen, that is the file's one database, as scan --dump takes it, and the
// report doesn't repeat the choice. Beside a named database that holds a table
// of the hash file, it isn't: the read stops, unless the named one is the
// choice and comes first, which scan --dump would read too.
func TestCompareDumpUnnamedDatabase(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA, mailB))
	const head = "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n"
	unnamed := usersTable + "INSERT INTO `users` VALUES (1,'" + mailA + "');\n"
	named := strings.ReplaceAll(usersTable, "`users`", "`b`.`users`") + "INSERT INTO `b`.`users` VALUES (1,'" + mailB + "');\n"

	for _, db := range []string{"", "shop"} {
		res := compareDump(t, head+unnamed, f, key, CompareDumpOptions{Database: db})
		if c := columnOf(t, res, "users.email", model.LeakEmail); c.RowsRead != 1 || c.Found != 1 || res.Database != "" {
			t.Errorf("--database %q: %d rows, found %d, database %q, state %s", db, c.RowsRead, c.Found, res.Database, c.State)
		}
	}
	for _, c := range []struct{ name, sql, db string }{
		{"the unnamed first, the choice after", head + unnamed + named, "b"},
		{"the unnamed first, another after", head + unnamed + named, "c"},
		{"another first, the unnamed after", head + named + unnamed, "c"},
	} {
		if res, err := CompareDump(context.Background(), strings.NewReader(c.sql), f, key, CompareDumpOptions{Database: c.db}); !errors.Is(err, ErrUnnamedDatabase) || res != nil {
			t.Errorf("%s: %v, %v", c.name, res, err)
		}
	}
	res := compareDump(t, head+named+unnamed, f, key, CompareDumpOptions{Database: "B"})
	if c := columnOf(t, res, "users.email", model.LeakEmail); c.RowsRead != 1 || c.Found != 1 || res.Database != "b" {
		t.Errorf("the choice first: %d rows, found %d, database %q", c.RowsRead, c.Found, res.Database)
	}

	if s := (&File{}).String(); s != "hash file of an unnamed database: 0 columns" {
		t.Errorf("a hash file of a dump that names no database: %q", s)
	}
}

// slowReader gives its first part at once, and each later one only when
// release is closed.
type slowReader struct {
	parts   []string
	release chan struct{}
	at      int
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.at >= len(s.parts) {
		return 0, io.EOF
	}
	if s.at > 0 {
		<-s.release
	}
	n := copy(p, s.parts[s.at])
	s.parts[s.at] = s.parts[s.at][n:]
	if s.parts[s.at] == "" {
		s.at++
	}
	return n, nil
}

// The first part is given at once, and its row counts if it is read within
// the 100 ms limit, which takes a few milliseconds. The second is held until
// a second after the limit has passed (the release's timer starts before the
// read does), so the read stops before any of its rows.
func TestCompareDumpMaxTime(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA), email("other", "email", mailC))
	const limit = 100 * time.Millisecond
	r := &slowReader{release: make(chan struct{}), parts: []string{
		dumpTop + usersTable + "INSERT INTO `users` VALUES (1,'" + mailA + "');\n",
		"CREATE TABLE `other` (`id` int, `email` varchar(100));\nINSERT INTO `other` VALUES (1,'" + mailC + "');\nINSERT INTO `other` VALUES (2,'x');\n",
	}}
	time.AfterFunc(limit+time.Second, func() { close(r.release) })
	res, err := CompareDump(context.Background(), r, f, key, CompareDumpOptions{MaxTime: limit})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Columns {
		if c.State != model.LeakStopped || c.StoppedBy != "--max-time" {
			t.Errorf("%s: %s %q", c.Location(), c.State, c.StoppedBy)
		}
	}
	u := columnOf(t, res, "users.email", model.LeakEmail)
	if u.Found != 1 || u.RowsRead != 1 {
		t.Errorf("what was read before the limit still counts: found %d, %d rows", u.Found, u.RowsRead)
	}
	if hits, unchecked := Gate(res, model.SeverityHigh); hits != 1 || unchecked != 1 {
		t.Errorf("gate: %d hits, %d unchecked", hits, unchecked)
	}
	var out bytes.Buffer
	report.LeakText(&out, res, false)
	if !strings.Contains(out.String(), "stopped by --max-time after 1 rows") {
		t.Errorf("report:\n%s", out.String())
	}
	// The caller's own cancellation is an error, not a result.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if res, err := CompareDump(ctx, strings.NewReader(dumpTop), f, key, CompareDumpOptions{}); err == nil || res != nil {
		t.Errorf("cancelled: %v, %v", res, err)
	}
}

func TestCompareDumpCutShort(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA))
	sql := dumpTop + usersTable + "INSERT INTO `users` VALUES (1,'" + mailA + "');\n"
	r := io.MultiReader(strings.NewReader(sql), errReader{})
	res, err := CompareDump(context.Background(), r, f, key, CompareDumpOptions{})
	if err == nil || res == nil {
		t.Fatalf("a read error gives the result and the error: %v, %v", res, err)
	}
	c := columnOf(t, res, "users.email", model.LeakEmail)
	if c.State != model.LeakStopped || c.Found != 1 || strings.Contains(c.StoppedBy, "boom") {
		t.Errorf("%+v", c)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom: " + mailA) }

func TestCompareDumpWrongKey(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA))
	other, err := ParseKey([]byte(hex.EncodeToString(bytes.Repeat([]byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18}, 4))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompareDump(context.Background(), strings.NewReader(dumpTop), f, other, CompareDumpOptions{}); !errors.Is(err, ErrWrongKey) {
		t.Errorf("%v", err)
	}
}

func TestCompareDumpExceptAndAllow(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA))
	sql := dumpTop + usersTable + "INSERT INTO `users` VALUES (1,'" + mailA + "');\n"
	res := compareDump(t, sql, f, key, CompareDumpOptions{FailExcept: []string{"users.email", "nope"}})
	if c := columnOf(t, res, "users.email", model.LeakEmail); !c.Excepted {
		t.Error("not excepted")
	}
	if hits, _ := Gate(res, model.SeverityHigh); hits != 0 {
		t.Errorf("%d hits", hits)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "--fail-except value 2 matches no column") {
		t.Errorf("warnings %q", res.Warnings)
	}
	allow, err := NewAllowlist([]string{fakeDomain})
	if err != nil {
		t.Fatal(err)
	}
	res = compareDump(t, sql, f, key, CompareDumpOptions{Allow: allow})
	if c := columnOf(t, res, "users.email", model.LeakEmail); c.Found != 0 || c.ValuesSkipped != 1 {
		t.Errorf("found %d, %d skipped", c.Found, c.ValuesSkipped)
	}
}

func TestCompareDumpNotADump(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA))
	for _, text := range []string{"", "\x89PNG\r\n\x1a\n not sql at all", "hello world " + mailA} {
		res, err := CompareDump(context.Background(), strings.NewReader(text), f, key, CompareDumpOptions{})
		if !errors.Is(err, ErrNotADump) || res != nil {
			t.Errorf("%.12q: %v, %v", text, res, err)
		}
	}
	if strings.Contains(ErrNotADump.Error(), "alice") {
		t.Error("the error holds a value")
	}
}

// CompareDump tells ReadProgress about the bytes read, once at the start and
// about once a megabyte after, with the file's size and the table the last
// row went into.
func TestCompareDumpProgress(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA))
	var b strings.Builder
	b.WriteString(dumpTop + usersTable)
	for i := 1; i <= 30000; i += 500 {
		b.WriteString("INSERT INTO `users` VALUES ")
		for j := i; j < i+500; j++ {
			if j > i {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "(%d,'customer.%06d@%s')", j, j, fakeDomain)
		}
		b.WriteString(";\n")
	}
	size := int64(b.Len())
	calls, last := 0, ""
	_, err := CompareDump(context.Background(), strings.NewReader(b.String()), f, key, CompareDumpOptions{
		Size: size,
		ReadProgress: func(done, total int64, table string) {
			calls, last = calls+1, table
			if total != size || done > size {
				t.Errorf("%d of %d bytes", done, total)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls < 2 || last != "users" {
		t.Errorf("%d calls, the last at %q", calls, last)
	}
}
