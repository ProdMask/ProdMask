package mcp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/login"
	"github.com/ProdMask/ProdMask/internal/redact"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// reassuring are words prodmask mcp never prints: it replaces what it
// recognises, and says what it doesn't catch.
var reassuring = []string{"anonymised", "anonymized", "anonymise", "anonymize", "pii-free", "compliant", "compliance",
	"safe", "guarantee"}

func checkWords(t *testing.T, texts []string) {
	t.Helper()
	for _, text := range texts {
		lower := strings.ToLower(text)
		for _, w := range reassuring {
			if strings.Contains(lower, w) {
				t.Errorf("%q in:\n%.400s", w, text)
			}
		}
	}
}

// TestWordingNeverReassures checks what the agent reads: the instructions,
// every tool's description, about's answer, the standing lines and what the
// replacement doesn't catch, the refusals and the copy status, what a login
// can do, the notes, and the words for errors and warnings.
func TestWordingNeverReassures(t *testing.T) {
	texts := []string{instructions, standingNotCopy, standingCopy, dataNotInstructions}
	texts = append(texts, notCaught...)
	for _, tool := range toolDefs() {
		texts = append(texts, tool.Title, tool.Description, string(tool.InputSchema))
	}

	// about, with nothing listening.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	cfg := mysql.NewConfig()
	cfg.Net, cfg.Addr, cfg.User, cfg.DBName = "tcp", addr, "u", "shop"
	s := NewServer(Options{Config: cfg, Timeout: time.Second, MaxRows: 100, Copy: true})
	s.Start(context.Background())
	about, _ := s.about(context.Background())
	if !strings.Contains(about.Text, "couldn't reach the database server") || !strings.Contains(about.Text, "not_caught") {
		t.Fatalf("about, with nothing listening: %s", about.Text)
	}
	texts = append(texts, about.Text)

	writer := &model.Login{ChangeData: []string{"INSERT"}, ChangeSchema: []string{"ALTER"}, Drop: []string{"DROP"}, Files: "anywhere",
		Admin: []string{"SUPER"}, Process: true, OtherDatabases: 2, SystemTables: true, RolesNotActive: 1,
		Routes: []model.LoginRoute{{Kind: "view", Name: "v", DefinerRights: true}}, NotRead: []string{"a privilege prodmask doesn't know"}}
	texts = append(texts, login.Refusal(writer, "shop"))
	texts = append(texts, LoginLines(writer)...)
	for _, m := range []login.Marker{{}, {Found: true}, {Found: true, State: "incomplete"}, {Found: true, State: "complete", Masking: "none"},
		{Found: true, Holds: true, State: "complete", Masking: "stable", Tool: "prodmask Pro 1.0.0", Finished: "2026-11-18 10:00:00"},
		{Found: true, Holds: true, State: "complete", Masking: "per-run"}} {
		texts = append(texts, m.Words(), copyRefusal(m))
	}
	for _, err := range []error{ErrBusy, ErrStillRunning, ErrSettings, ErrSessionNotKept, ErrTimeLimit,
		refusalError("prodmask mcp won't serve this server: it has no statement time limit")} {
		w, _ := errorWords(err, "SELECT 1")
		texts = append(texts, w)
	}
	for _, code := range []int{1054, 1146, 1142, 1143, 1792, 3024, 1969, 1317, 1222, 1241, 1242, 1248, 1064, 1644, 9999} {
		texts = append(texts, redact.ErrorWords(code, "HY000", "near 'x' at line 1", "SELECT x"))
		w, _ := redact.WarningWords("Warning", code, "near 'x' at line 1", "SELECT x")
		texts = append(texts, w)
	}

	// The notes of a result that replaces, withholds and cuts.
	customers := &model.Table{Name: "customers", Type: "BASE TABLE", Columns: []*model.Column{
		{Name: "id", DataType: "int"}, {Name: "first_name", DataType: "varchar"}, {Name: "note", DataType: "varchar"}}}
	meta := &model.Table{Name: "wp_usermeta", Type: "BASE TABLE", Columns: []*model.Column{
		{Name: "umeta_id", DataType: "int"}, {Name: "meta_key", DataType: "varchar"}, {Name: "meta_value", DataType: "longtext"}}}
	r := redact.New(redact.Source{Schema: &model.Schema{Tables: []*model.Table{customers, meta}},
		Judge: func(ctx context.Context, t *model.Table) scan.TableVerdict {
			return scan.JudgeTable(ctx, nil, nil, t, scan.Options{})
		}},
		false, make([]byte, 32))
	for _, q := range []struct {
		sql  string
		cols []redact.Column
		row  []redact.Value
	}{
		{"SELECT c.first_name, c.note FROM customers c", []redact.Column{{Name: "c.first_name", Type: "VARCHAR"}, {Name: "c.note", Type: "VARCHAR"}},
			[]redact.Value{{Bytes: []byte("Ada")}, {Withheld: 2 << 20}}},
		{"SELECT c.first_name AS label FROM customers c", []redact.Column{{Name: "c.label", Type: "VARCHAR"}}, []redact.Value{{Bytes: []byte("Ada")}}},
		{"SELECT CONCAT(first_name) AS first_name FROM customers", []redact.Column{{Name: "first_name", Type: "VARCHAR"}}, []redact.Value{{Bytes: []byte("Ada")}}},
		{"SELECT m.meta_value FROM wp_usermeta m", []redact.Column{{Name: "m.meta_value", Type: "TEXT"}}, []redact.Value{{Bytes: []byte("x")}}},
		{"SELECT m.meta_key, m.meta_value FROM wp_usermeta m", []redact.Column{{Name: "m.meta_key", Type: "VARCHAR"}, {Name: "m.meta_value", Type: "TEXT"}},
			[]redact.Value{{Bytes: []byte("billing_first_name")}, {Bytes: []byte("Ada")}}},
	} {
		out := r.Result(context.Background(), q.sql, q.cols, [][]redact.Value{q.row})
		texts = append(texts, out.Notes...)
	}
	checkWords(t, texts)
}

// TestRefusalWords: a refusal reaches the agent in its own words, whatever
// they start with, as one the connection hook returns after a reconnect.
func TestRefusalWords(t *testing.T) {
	const words = "prodmask couldn't read the database's tables (timed out); try again"
	got, outcome := errorWords(fmt.Errorf("the new connection: %w", refusalError(words)), "SELECT 1")
	if got != words || outcome != "refused" {
		t.Errorf("a wrapped refusal: %q, %q", got, outcome)
	}
}
