// Package preset knows the schemas of common platforms: where they keep
// personal data, how their tables link up, and which settings would let a
// staging copy act on real customers.
package preset

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// Names lists the presets that can be asked for by name.
var Names = []string{"wordpress", "woocommerce", "magento2", "laravel"}

// Querier is the part of *sql.DB the presets need.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// MetaTable describes a key/value table such as wp_postmeta. Each key is
// judged on its own, as if it were a column.
type MetaTable struct {
	Key, Value string
	Platform   string
	Keys       map[string]*detect.Hint       // known keys
	Probe      []string                      // keys worth reading directly if the sample misses them
	HintFor    func(key string) *detect.Hint // pattern-based hints
	Label      func(key string) string       // maps raw keys to names, e.g. Magento attribute IDs
}

// Hint returns what the preset knows about one key.
func (m *MetaTable) Hint(key string) *detect.Hint {
	if h := m.Keys[key]; h != nil {
		return h
	}
	if m.HintFor != nil {
		return m.HintFor(key)
	}
	return nil
}

// TableAction is advice for a whole table, e.g. to empty it in the copy.
type TableAction struct {
	Action string // "truncate"
	Reason string
}

// Result is everything the presets found.
type Result struct {
	Platforms     []model.Platform
	Columns       map[string]map[string]*detect.Hint // table → lower-case column → hint
	Meta          map[string]*MetaTable
	Actions       map[string]TableAction
	Relationships []model.Relationship
	Prefixes      []string
	SideEffects   []model.SideEffect
	Warnings      []string
}

// ColumnHint returns the preset hint for a column, if any.
func (r *Result) ColumnHint(table, column string) *detect.Hint {
	return r.Columns[table][strings.ToLower(column)]
}

type env struct {
	ctx     context.Context
	q       Querier
	schema  *model.Schema
	res     *Result
	timeout time.Duration
}

// Detect recognises platforms and collects their hints and side effects.
// which is "auto", "none" or one of Names.
func Detect(ctx context.Context, q Querier, schema *model.Schema, which string, timeout time.Duration) *Result {
	e := &env{ctx: ctx, q: q, schema: schema, timeout: timeout, res: &Result{
		Columns: map[string]map[string]*detect.Hint{},
		Meta:    map[string]*MetaTable{},
		Actions: map[string]TableAction{},
	}}
	run := func(name string) bool { return which == "auto" || which == name }
	found := map[string]bool{}
	if run("wordpress") || run("woocommerce") {
		found["wordpress"], found["woocommerce"] = e.wordpress(which == "auto" || which == "woocommerce")
	}
	if run("magento2") {
		found["magento2"] = e.magento()
	}
	if run("laravel") {
		found["laravel"] = e.laravel()
	}
	if which != "auto" && which != "none" && !found[which] {
		e.warn(fmt.Sprintf("the %s preset was requested, but its tables were not found", which))
	}
	sort.SliceStable(e.res.SideEffects, func(i, j int) bool {
		return e.res.SideEffects[i].Severity > e.res.SideEffects[j].Severity
	})
	return e.res
}

func (e *env) warn(msg string) { e.res.Warnings = append(e.res.Warnings, msg) }

func (e *env) table(name string) *model.Table { return e.schema.Table(name) }

func (e *env) has(name string, columns ...string) bool {
	t := e.table(name)
	if t == nil {
		return false
	}
	for _, c := range columns {
		if t.Column(c) == nil {
			return false
		}
	}
	return true
}

func hint(platform string, cat model.Category, note string) *detect.Hint {
	return &detect.Hint{Category: cat, Note: note, Source: "preset:" + platform}
}

func (e *env) column(table, column string, h *detect.Hint) {
	if !e.has(table, column) {
		return
	}
	cols := e.res.Columns[table]
	if cols == nil {
		cols = map[string]*detect.Hint{}
		e.res.Columns[table] = cols
	}
	cols[strings.ToLower(column)] = h
}

func (e *env) meta(table string, m *MetaTable) {
	if e.has(table, m.Key, m.Value) {
		e.res.Meta[table] = m
	}
}

func (e *env) action(table, action, reason string) {
	if e.has(table) {
		e.res.Actions[table] = TableAction{Action: action, Reason: reason}
	}
}

func (e *env) rel(platform, child, childCol, parent, parentCol string) {
	if !e.has(child, childCol) || !e.has(parent, parentCol) {
		return
	}
	e.res.Relationships = append(e.res.Relationships, model.Relationship{
		ChildTable: child, ChildColumns: []string{childCol},
		ParentTable: parent, ParentColumns: []string{parentCol},
		Source: "preset:" + platform,
	})
}

func (e *env) sideEffect(s model.SideEffect) { e.res.SideEffects = append(e.res.SideEffects, s) }

// rows runs a small query and returns its rows as strings.
func (e *env) rows(query string, args ...any) ([][]string, error) {
	ctx, cancel := context.WithTimeout(e.ctx, e.timeout)
	defer cancel()
	rows, err := e.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out [][]string
	raw := make([]sql.RawBytes, len(cols))
	dest := make([]any, len(cols))
	for i := range raw {
		dest[i] = &raw[i]
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return out, err
		}
		row := make([]string, len(cols))
		for i, b := range raw {
			row[i] = string(b)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// count runs a COUNT query.
func (e *env) count(query string, args ...any) (int64, error) {
	ctx, cancel := context.WithTimeout(e.ctx, e.timeout)
	defer cancel()
	var n int64
	err := e.q.QueryRowContext(ctx, query, args...).Scan(&n)
	return n, err
}

// options reads selected rows of a key/value settings table.
func (e *env) options(table, keyCol, valueCol string, keys []string) map[string]string {
	out := map[string]string{}
	if len(keys) == 0 || !e.has(table, keyCol, valueCol) {
		return out
	}
	q := fmt.Sprintf("SELECT %s, LEFT(%s, 65535) FROM %s WHERE %s IN (%s)",
		sample.QuoteIdent(keyCol), sample.QuoteIdent(valueCol), sample.QuoteIdent(table),
		sample.QuoteIdent(keyCol), strings.TrimSuffix(strings.Repeat("?,", len(keys)), ","))
	args := make([]any, len(keys))
	for i, k := range keys {
		args[i] = k
	}
	rows, err := e.rows(q, args...)
	if err != nil {
		e.warn(fmt.Sprintf("could not read settings from %s: %v", table, err))
		return out
	}
	for _, r := range rows {
		if _, ok := out[r[0]]; !ok {
			out[r[0]] = r[1]
		}
	}
	return out
}

var reSafe = regexp.MustCompile(`^[A-Za-z0-9_.:/\\ -]{1,80}$`)

// Safe returns s if it looks like an identifier (a hook, job or gateway
// name) and a placeholder otherwise, so no stored value can slip into a
// report through a label.
func Safe(s string) string {
	if reSafe.MatchString(s) && !strings.Contains(s, "@") {
		return s
	}
	return "(unnamed)"
}

// liveMode reads the usual payment gateway settings. known is false when
// none of them is present.
func liveMode(kv map[string]string) (live, known bool) {
	for _, k := range []string{"testmode", "test_mode", "sandbox", "sandbox_on", "sandbox_flag", "is_sandbox",
		"sandbox_mode", "is_test_mode", "demo_mode"} {
		if v, ok := kv[k]; ok {
			return !yes(v), true
		}
	}
	for _, k := range []string{"environment", "mode", "account_mode", "api_mode", "stripe_mode"} {
		if v, ok := kv[k]; ok {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "live", "production", "prod":
				return true, true
			case "test", "sandbox", "staging", "development", "dev":
				return false, true
			}
		}
	}
	return false, false
}

// topCounts renders "hook (12), other (3)" from rows of (name, count).
func topCounts(rows [][]string, n int) string {
	var parts []string
	for i, r := range rows {
		if i == n {
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", Safe(r[0]), r[1]))
	}
	return strings.Join(parts, ", ")
}
