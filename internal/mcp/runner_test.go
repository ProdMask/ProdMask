package mcp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/model"
)

// fakeServer is the runner's seam: a driver whose connections answer the
// runner's own statements as the test sets, and the agent's through agent.
type fakeServer struct {
	mu       sync.Mutex
	nextID   int64
	sent     []string
	args     []int // the agent's statements' argument counts
	prepares int
	closed   []int64
	// readOnly, when set, is what the read-back gives for the read-only
	// variable.
	readOnly string
	release  func(id int64) (int64, error)
	running  func(id int64) bool
	warnings [][]driver.Value
	agent    func(ctx context.Context, q string) (driver.Rows, error)
}

var fakeSettings = map[string]string{"autocommit": "1", "lock_wait_timeout": "5", "transaction_read_only": "1",
	"max_execution_time": "1000", "sql_select_limit": "4"}

func (s *fakeServer) Connect(context.Context) (driver.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	return &fakeConn{s: s, id: s.nextID}, nil
}

func (s *fakeServer) Driver() driver.Driver { return nil }

func (s *fakeServer) sentCopy() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.sent)
}

type fakeConn struct {
	s  *fakeServer
	id int64
}

func (c *fakeConn) Prepare(string) (driver.Stmt, error) {
	c.s.mu.Lock()
	c.s.prepares++
	c.s.mu.Unlock()
	return nil, errors.New("fake: nothing is prepared")
}

func (c *fakeConn) Close() error {
	c.s.mu.Lock()
	c.s.closed = append(c.s.closed, c.id)
	c.s.mu.Unlock()
	return nil
}

func (c *fakeConn) Begin() (driver.Tx, error) { return nil, errors.New("fake: no transactions") }

func (c *fakeConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	s.mu.Lock()
	s.sent = append(s.sent, q)
	s.mu.Unlock()
	switch {
	case strings.HasPrefix(q, "SELECT CONNECTION_ID(), @@SESSION."):
		names := strings.Split(strings.TrimPrefix(q, "SELECT CONNECTION_ID(), @@SESSION."), ", @@SESSION.")
		row := []driver.Value{c.id}
		for _, n := range names {
			v := fakeSettings[n]
			if n == "transaction_read_only" && s.readOnly != "" {
				v = s.readOnly
			}
			row = append(row, []byte(v))
		}
		return &fakeRows{cols: append([]string{"id"}, names...), rows: [][]driver.Value{row}}, nil
	case q == "SELECT RELEASE_ALL_LOCKS(), CONNECTION_ID()":
		id, err := c.id, error(nil)
		if s.release != nil {
			id, err = s.release(c.id)
		}
		if err != nil {
			return nil, err
		}
		return &fakeRows{cols: []string{"freed", "id"}, rows: [][]driver.Value{{int64(1), id}}}, nil
	case strings.HasPrefix(q, "SHOW WARNINGS"):
		return &fakeRows{cols: []string{"Level", "Code", "Message"}, rows: s.warnings}, nil
	case strings.Contains(q, "information_schema.PROCESSLIST"):
		n := int64(0)
		if s.running != nil && s.running(args[0].Value.(int64)) {
			n = 1
		}
		return &fakeRows{cols: []string{"n"}, rows: [][]driver.Value{{n}}}, nil
	}
	s.mu.Lock()
	s.args = append(s.args, len(args))
	s.mu.Unlock()
	return s.agent(ctx, q)
}

// fakeRows gives its rows; with wait set, it then waits for the context to
// end, as a slow statement would.
type fakeRows struct {
	cols []string
	rows [][]driver.Value
	i    int
	wait context.Context
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.i >= len(r.rows) {
		if r.wait != nil {
			<-r.wait.Done()
			return r.wait.Err()
		}
		return io.EOF
	}
	copy(dest, r.rows[r.i])
	r.i++
	return nil
}

func numbers(n int) [][]driver.Value {
	var out [][]driver.Value
	for i := range n {
		out = append(out, []driver.Value{int64(i)})
	}
	return out
}

// newFake returns a runner over a fake server with a ceiling of 3 rows, a
// 200 ms limit, and no grace.
func newFake(t *testing.T, s *fakeServer) *Runner {
	t.Helper()
	if s.agent == nil {
		s.agent = func(context.Context, string) (driver.Rows, error) {
			return &fakeRows{cols: []string{"i"}, rows: numbers(2)}, nil
		}
	}
	db := sql.OpenDB(s)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	sess := &dbconn.Session{DB: db, Server: model.ServerInfo{Flavor: "mysql"}, Timeout: 200 * time.Millisecond,
		ServerTimeout: true, Settings: fakeSettings}
	r, err := NewRunner(sess, sess, 3, func() dbconn.AgentScope {
		return dbconn.AgentScope{Flavor: "mysql", Database: "shop", Tables: []string{"t"}}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.grace = 0
	return r
}

func TestRunnerReadBack(t *testing.T) {
	s := &fakeServer{readOnly: "0"}
	r := newFake(t, s)
	if _, err := r.Query(context.Background(), "SELECT i FROM t", 0); !errors.Is(err, ErrSettings) {
		t.Fatalf("a read-back with transaction_read_only 0: %v", err)
	}
	if slices.Contains(s.sentCopy(), "SELECT i FROM t") {
		t.Error("the statement was sent on a connection that isn't read-only")
	}
	if !slices.Contains(s.closed, 1) {
		t.Errorf("the connection wasn't closed: closed %v", s.closed)
	}
	s.readOnly = ""
	res, err := r.Query(context.Background(), "SELECT i FROM t", 0)
	if err != nil || len(res.Rows) != 2 {
		t.Fatalf("the next call: %v, %+v", err, res)
	}
	if r.lastID != 2 {
		t.Errorf("the next call ran on connection %d, want a new one, 2", r.lastID)
	}
}

func TestRunnerProxy(t *testing.T) {
	s := &fakeServer{release: func(id int64) (int64, error) { return id + 100, nil }}
	r := newFake(t, s)
	if _, err := r.Query(context.Background(), "SELECT i FROM t", 0); !errors.Is(err, ErrSessionNotKept) {
		t.Fatalf("a release from another connection: %v", err)
	}
	before := len(s.sentCopy())
	if _, err := r.Query(context.Background(), "SELECT i FROM t", 0); !errors.Is(err, ErrSessionNotKept) {
		t.Fatalf("the next call: %v", err)
	}
	if len(s.sentCopy()) != before {
		t.Errorf("the next call sent %q", s.sentCopy()[before:])
	}
}

func TestRunnerNoReleaseAllLocks(t *testing.T) {
	s := &fakeServer{release: func(int64) (int64, error) {
		return 0, &mysql.MySQLError{Number: 1305, Message: "FUNCTION RELEASE_ALL_LOCKS does not exist"}
	}}
	r := newFake(t, s)
	res, err := r.Query(context.Background(), "SELECT i FROM t", 0)
	if err != nil || len(res.Rows) != 2 {
		t.Fatalf("a call on a server without RELEASE_ALL_LOCKS: %v, %+v", err, res)
	}
	if !slices.Contains(s.closed, 1) {
		t.Errorf("the connection wasn't closed: closed %v", s.closed)
	}
}

func TestRunnerWaitRunsOut(t *testing.T) {
	s := &fakeServer{running: func(int64) bool { return true }}
	s.agent = func(ctx context.Context, q string) (driver.Rows, error) {
		return &fakeRows{cols: []string{"i"}, rows: numbers(1), wait: ctx}, nil
	}
	r := newFake(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	res, err := r.Query(ctx, "SELECT i FROM t", 0)
	if !errors.Is(err, context.Canceled) || res == nil || !slices.Contains(res.Notes, "warnings weren't read") {
		t.Fatalf("a call cancelled mid-read: %v, %+v", err, res)
	}
	if slices.ContainsFunc(s.sentCopy(), func(q string) bool { return strings.HasPrefix(q, "SHOW WARNINGS") }) {
		t.Error("warnings were read on a connection cut short")
	}
	if r.cutShort == 0 {
		t.Fatal("the cut-short connection isn't kept for the next call")
	}
	if _, err := r.Query(context.Background(), "SELECT i + 1 FROM t", 0); !errors.Is(err, ErrStillRunning) {
		t.Fatalf("the next call, while the statement runs on: %v", err)
	}
	if slices.Contains(s.sentCopy(), "SELECT i + 1 FROM t") {
		t.Error("the next call's statement was sent")
	}
	s.running = func(int64) bool { return false }
	s.agent = func(context.Context, string) (driver.Rows, error) {
		return &fakeRows{cols: []string{"i"}, rows: numbers(1)}, nil
	}
	if _, err := r.Query(context.Background(), "SELECT i + 1 FROM t", 0); err != nil {
		t.Fatalf("the call after the statement ended: %v", err)
	}
}

func TestRunnerUnboundedRead(t *testing.T) {
	s := &fakeServer{}
	s.agent = func(context.Context, string) (driver.Rows, error) {
		return &fakeRows{cols: []string{"i"}, rows: numbers(50)}, nil
	}
	r := newFake(t, s)
	res, err := r.Query(context.Background(), "SELECT i FROM t LIMIT 50", 0)
	if err != nil || len(res.Rows) != 3 || !res.MoreRows || !slices.Contains(res.Notes, "warnings weren't read") {
		t.Fatalf("a statement past the server's bound: %v, %+v", err, res)
	}
	if r.cutShort == 0 {
		t.Error("the statement stopped by cancelling isn't waited for")
	}
	if slices.ContainsFunc(s.sentCopy(), func(q string) bool { return strings.HasPrefix(q, "SHOW WARNINGS") }) {
		t.Error("warnings were read on a connection cut short")
	}
}

func TestRunnerBoundedRead(t *testing.T) {
	s := &fakeServer{warnings: [][]driver.Value{{[]byte("Warning"), int64(1292), []byte("Truncated incorrect DOUBLE value")}}}
	s.agent = func(context.Context, string) (driver.Rows, error) {
		rows := numbers(4) // the server's bound: sql_select_limit 4
		rows = append(rows, []driver.Value{nil}, []driver.Value{[]byte{}})
		return &fakeRows{cols: []string{"i"}, rows: rows[2:]}, nil
	}
	r := newFake(t, s)
	res, err := r.Query(context.Background(), "SELECT i FROM t", 0)
	if err != nil || len(res.Rows) != 3 || !res.MoreRows || r.cutShort != 0 {
		t.Fatalf("a statement the server bounded: %v, %+v", err, res)
	}
	if res.Rows[1][0].Null || !res.Rows[2][0].Null {
		t.Errorf("values: %+v", res.Rows)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Code != 1292 {
		t.Errorf("warnings: %+v", res.Warnings)
	}
	sent := s.sentCopy()
	at := slices.Index(sent, "SELECT i FROM t")
	if at < 0 || at+2 >= len(sent) || !strings.HasPrefix(sent[at+1], "SHOW WARNINGS") || sent[at+2] != "SELECT RELEASE_ALL_LOCKS(), CONNECTION_ID()" {
		t.Errorf("the order of statements: %q", sent)
	}
	if s.prepares != 0 || !slices.Equal(s.args, []int{0}) {
		t.Errorf("the statement was prepared (%d) or sent with arguments (%v)", s.prepares, s.args)
	}
}

func TestRunnerNullAndEmpty(t *testing.T) {
	s := &fakeServer{}
	s.agent = func(context.Context, string) (driver.Rows, error) {
		return &fakeRows{cols: []string{"a", "b"}, rows: [][]driver.Value{{nil, []byte{}}}}, nil
	}
	r := newFake(t, s)
	res, err := r.Query(context.Background(), "SELECT a, b FROM t", 0)
	if err != nil || len(res.Rows) != 1 {
		t.Fatalf("%v, %+v", err, res)
	}
	if v := res.Rows[0]; !v[0].Null || v[1].Null || v[1].Bytes == nil {
		t.Errorf("NULL and the empty string read as %+v", v)
	}
}

func TestRunnerWithheldValue(t *testing.T) {
	s := &fakeServer{}
	s.agent = func(context.Context, string) (driver.Rows, error) {
		return &fakeRows{cols: []string{"v"}, rows: [][]driver.Value{{make([]byte, 2<<20)}}}, nil
	}
	r := newFake(t, s)
	res, err := r.Query(context.Background(), "SELECT a FROM t", 0)
	if err != nil || len(res.Rows) != 1 || res.Rows[0][0].Withheld != 2<<20 || res.Rows[0][0].Bytes != nil {
		t.Fatalf("a 2 MiB value: %v, %+v", err, res)
	}
}

func TestRunnerBusy(t *testing.T) {
	r := newFake(t, &fakeServer{})
	done, err := r.Turn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if _, err := r.Query(context.Background(), "SELECT i FROM t", 0); !errors.Is(err, ErrBusy) {
		t.Fatalf("a call while another runs: %v", err)
	}
}

func TestRunnerRefusesServer(t *testing.T) {
	for name, sess := range map[string]*dbconn.Session{
		"no time limit": {ServerTimeout: false, Settings: fakeSettings},
		"no read-only":  {ServerTimeout: true, Settings: map[string]string{"autocommit": "1"}},
	} {
		if _, err := NewRunner(sess, sess, 3, nil, nil); err == nil || !strings.HasPrefix(err.Error(), "prodmask mcp won't serve this server") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRunnerRefusesStatement(t *testing.T) {
	s := &fakeServer{}
	r := newFake(t, s)
	if _, err := r.Query(context.Background(), "SELECT SLEEP(10)", 0); !errors.Is(err, dbconn.ErrAgentStatement) {
		t.Fatalf("a refused statement: %v", err)
	}
	if len(s.sentCopy()) != 0 {
		t.Errorf("a refused statement sent %q", s.sentCopy())
	}
}

func TestSameSetting(t *testing.T) {
	for _, c := range []struct {
		got, set string
		same     bool
	}{
		{"10.000000", "10", true}, {"1", "1", true}, {"ON", "1", true}, {"0", "1", false},
		{"OFF", "1", false}, {"101", "100", false}, {"", "1", false},
	} {
		if sameSetting(c.got, c.set) != c.same {
			t.Errorf("sameSetting(%q, %q) = %v", c.got, c.set, !c.same)
		}
	}
}
