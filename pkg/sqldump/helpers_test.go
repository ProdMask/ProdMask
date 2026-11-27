package sqldump

import (
	"context"
	"os"
	"strings"
	"testing"
)

// rec records what a read reports.
type rec struct {
	BaseVisitor
	header Header
	hdrs   int
	dbs    []string
	unread []Unread
	warns  []string
}

func (r *rec) Header(h Header)   { r.header = h; r.hdrs++ }
func (r *rec) Database(n string) { r.dbs = append(r.dbs, n) }
func (r *rec) Unread(u Unread)   { r.unread = append(r.unread, u) }
func (r *rec) Warning(w Warning) { r.warns = append(r.warns, w.Text) }
func (r *rec) hasWarning(s string) bool {
	for _, w := range r.warns {
		if w == s {
			return true
		}
	}
	return false
}

// testOpts makes a panic fail the test, as it should.
func testOpts() Options { return Options{test: testHooks{repanic: true}} }

// readSQL reads a dump held in a string.
func readSQL(t testing.TB, sql string) (*rec, Stats) {
	t.Helper()
	return readSQLOpts(t, sql, testOpts())
}

func readSQLOpts(t testing.TB, sql string, opts Options) (*rec, Stats) {
	t.Helper()
	v := &rec{}
	st, err := Read(context.Background(), strings.NewReader(sql), v, opts)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return v, st
}

// readerFor makes a reader over a string, for tests that look at its state.
func readerFor(sql string) (*reader, *rec) {
	v := &rec{}
	return newReader(context.Background(), strings.NewReader(sql), v, testOpts()), v
}

// val is a copy of a Value, which is valid only until the next read.
type val struct {
	Kind  ValueKind
	Bytes string
	Cut   bool
}

// literalWith reads the first value of "(expr, 1)", after the statements of
// prelude have been read, with the options given.
func literalWith(t testing.TB, opts Options, prelude, expr string) (val, Reason) {
	t.Helper()
	rd := newReader(context.Background(), strings.NewReader(prelude+"\n("+expr+", 1)"), &rec{}, opts)
	for {
		st := rd.begin()
		first := st.next()
		if first.isSym('(') {
			v, why := st.readValue()
			return val{v.Kind, string(v.Bytes), v.Cut}, why
		}
		if first.kind == tokEOF {
			t.Fatalf("prelude %q ended before the value", prelude)
		}
		class, why := rd.dispatch(st, first)
		rd.finish(st, class, why)
	}
}

func literal(t testing.TB, prelude, expr string) (val, Reason) {
	return literalWith(t, testOpts(), prelude, expr)
}

func count(st Stats, k Kind) int { return st.ByKind[k] }

func readSQLFile(t testing.TB, path string) (*rec, Stats) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Skip("the file isn't here")
	}
	defer f.Close()
	v := &rec{}
	st, err := Read(context.Background(), f, v, testOpts())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return v, st
}
