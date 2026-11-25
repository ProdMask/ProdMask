package mcp

import (
	"context"

	"github.com/ProdMask/ProdMask/internal/redact"
)

// shownResult is query's answer.
type shownResult struct {
	Columns  []redact.ShownColumn `json:"columns"`
	Rows     [][]any              `json:"rows"`
	MoreRows bool                 `json:"more_rows"`
	Warnings []string             `json:"warnings,omitempty"`
	Notes    []string             `json:"notes"`
	TimeMS   int64                `json:"time_ms"`
}

// show turns a result into what the agent sees .
func (s *Server) show(ctx context.Context, c *connection, statement string, res *Result) (shownResult, int, int) {
	cols := make([]redact.Column, len(res.Columns))
	for i, col := range res.Columns {
		cols[i] = redact.Column{Name: col.Name, Type: col.Type}
	}
	rows := make([][]redact.Value, len(res.Rows))
	for i, row := range res.Rows {
		rows[i] = make([]redact.Value, len(row))
		for j, v := range row {
			rows[i][j] = redact.Value{Bytes: v.Bytes, Null: v.Null, Withheld: v.Withheld}
		}
	}
	shown := s.redactor(c).Result(ctx, statement, cols, rows)
	out := shownResult{Columns: shown.Columns, Rows: shown.Rows, MoreRows: res.MoreRows || shown.Stopped, Notes: shown.Notes}
	for _, w := range res.Warnings {
		if words, ok := redact.WarningWords(w.Level, w.Code, w.Message, statement); ok {
			out.Warnings = append(out.Warnings, words)
		}
	}
	out.Notes = append(out.Notes, res.Notes...)
	standing := standingNotCopy
	if c.copyShown {
		standing = standingCopy
	}
	out.Notes = append(out.Notes, standing)
	return out, shown.Replaced, shown.Withheld
}

// showText shows a comment from the schema.
func (s *Server) showText(c *connection, text string) string {
	if text == "" {
		return ""
	}
	return s.redactor(c).Text(text)
}
