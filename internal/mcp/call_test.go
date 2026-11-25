package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// TestCallArguments: a tool call's arguments are checked before anything
// connects, and a bad one is an invalid-params error.
func TestCallArguments(t *testing.T) {
	cfg := mysql.NewConfig()
	cfg.Addr, cfg.DBName = "127.0.0.1:1", "shop"
	s := NewServer(Options{Config: cfg, Timeout: time.Second, MaxRows: 100})
	s.Start(context.Background())
	defer s.Close()
	for _, c := range []struct {
		tool string
		args map[string]json.RawMessage
	}{
		{"query", map[string]json.RawMessage{"sql": json.RawMessage(`"SELECT 1"`), "max_rows": json.RawMessage(`0`)}},
		{"query", map[string]json.RawMessage{"sql": json.RawMessage(`"SELECT 1"`), "max_rows": json.RawMessage(`"ten"`)}},
		{"query", map[string]json.RawMessage{"sql": json.RawMessage(`""`)}},
		{"query", nil},
		{"describe_table", nil},
		{"no_such_tool", nil},
	} {
		var invalid InvalidParamsError
		if _, err := s.call(context.Background(), c.tool, c.args); !errors.As(err, &invalid) {
			t.Errorf("%s %v: %v, want invalid params", c.tool, c.args, err)
		}
	}
}
