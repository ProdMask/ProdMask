// Package sample reads small, bounded samples of rows. Every query is a plain
// SELECT with a LIMIT, ordered by the primary key where there is one, so the
// server reads only a few index pages per query.
package sample

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// Querier is the part of *sql.DB the package needs.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Sampler reads samples from one database.
type Sampler struct {
	DB          Querier
	MaxValueLen int           // longer text values are cut on the server
	Timeout     time.Duration // client-side limit per query
	// Hex, when set, picks short binary columns (see ShortBinary) that Table
	// reads as HEX(column), such as IP addresses stored as bytes. No other
	// read selects a binary column.
	Hex func(t *model.Table, c *model.Column) bool
}

// Sample is the set of rows read from one table.
type Sample struct {
	Columns []*model.Column
	Rows    [][]sql.NullString
	Method  string
	// Hex marks the columns read as HEX(column), in the order of Columns.
	Hex []bool
}

// ShortBinary reports whether a column is binary or varbinary of at most 16
// bytes, the size of a stored IPv4 or IPv6 address.
func ShortBinary(c *model.Column) bool {
	return (c.DataType == "binary" || c.DataType == "varbinary") && c.MaxLength > 0 && c.MaxLength <= 16
}

// Index returns the position of a column in the sample, or -1.
func (s *Sample) Index(column string) int {
	for i, c := range s.Columns {
		if strings.EqualFold(c.Name, column) {
			return i
		}
	}
	return -1
}

// Values returns the non-NULL values of one sampled column.
func (s *Sample) Values(i int) []string {
	out := make([]string, 0, len(s.Rows))
	for _, r := range s.Rows {
		if r[i].Valid {
			out = append(out, r[i].String)
		}
	}
	return out
}

// Sampleable reports whether the scanner reads a column's values. Binary,
// spatial and vector columns are skipped.
func Sampleable(c *model.Column) bool {
	switch c.DataType {
	case "binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "bit",
		"geometry", "point", "linestring", "polygon", "multipoint", "multilinestring",
		"multipolygon", "geometrycollection", "geomcollection", "vector":
		return false
	}
	return true
}

// IsText reports whether a column holds text, which the server can cut.
func IsText(c *model.Column) bool {
	switch c.DataType {
	case "char", "varchar", "tinytext", "text", "mediumtext", "longtext", "json":
		return true
	}
	return false
}

// IsInteger reports whether a column holds whole numbers.
func IsInteger(c *model.Column) bool {
	switch c.DataType {
	case "tinyint", "smallint", "mediumint", "int", "integer", "bigint":
		return true
	}
	return false
}

// QuoteIdent quotes a table or column name for MySQL.
func QuoteIdent(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// ValueExpr is the select expression for a column: text is cut to n
// characters on the server so huge values never cross the network.
func ValueExpr(c *model.Column, n int) string {
	q := QuoteIdent(c.Name)
	if IsText(c) && n > 0 {
		return fmt.Sprintf("LEFT(%s, %d)", q, n)
	}
	return q
}

// Table samples up to limit rows. With a single integer primary key the
// rows come from three windows: the oldest, the middle and the newest
// rows, since old and new data often differ in shape. Otherwise the first
// rows the server returns are used.
func (sm *Sampler) Table(ctx context.Context, t *model.Table, limit int) (*Sample, error) {
	s, exprs := sm.selectList(t)
	if len(s.Columns) == 0 || limit <= 0 {
		s.Method = "none"
		return s, nil
	}
	sel := "SELECT " + strings.Join(exprs, ", ") + " FROM " + QuoteIdent(t.Name)

	pk := t.SinglePK()
	pkIdx := -1
	if pk != nil && IsInteger(pk) {
		pkIdx = s.Index(pk.Name)
	}
	if pkIdx < 0 {
		s.Method = "first rows"
		rows, err := sm.rows(ctx, fmt.Sprintf("%s LIMIT %d", sel, limit), len(s.Columns))
		s.Rows = rows
		return s, err
	}

	pkq := QuoteIdent(pk.Name)
	var lo, hi sql.NullString
	err := sm.row(ctx, fmt.Sprintf("SELECT MIN(%s), MAX(%s) FROM %s", pkq, pkq, QuoteIdent(t.Name)), &lo, &hi)
	if err != nil {
		return s, err
	}
	if !lo.Valid || !hi.Valid {
		s.Method = "empty"
		return s, nil
	}
	first, ok1 := new(big.Int).SetString(lo.String, 10)
	last, ok2 := new(big.Int).SetString(hi.String, 10)
	var span *big.Int
	if ok1 && ok2 {
		span = new(big.Int).Sub(last, first)
	}
	if span == nil || span.Cmp(big.NewInt(int64(limit)*2)) <= 0 {
		s.Method = "all rows by key"
		rows, err := sm.rows(ctx, fmt.Sprintf("%s ORDER BY %s LIMIT %d", sel, pkq, limit), len(s.Columns))
		s.Rows = rows
		return s, err
	}

	k := limit / 3
	if k == 0 {
		k = 1
	}
	middle := limit - 2*k
	mid := new(big.Int).Add(first, new(big.Int).Div(span, big.NewInt(2)))
	queries := []string{
		fmt.Sprintf("%s ORDER BY %s ASC LIMIT %d", sel, pkq, k),
		// mid is a number computed here, never text from the database.
		fmt.Sprintf("%s WHERE %s >= %s ORDER BY %s ASC LIMIT %d", sel, pkq, mid.String(), pkq, middle),
		fmt.Sprintf("%s ORDER BY %s DESC LIMIT %d", sel, pkq, k),
	}
	s.Method = "oldest, middle and newest rows by key"
	seen := map[string]bool{}
	for _, q := range queries {
		rows, err := sm.rows(ctx, q, len(s.Columns))
		for _, r := range rows {
			id := r[pkIdx].String
			if !seen[id] {
				seen[id] = true
				s.Rows = append(s.Rows, r)
			}
		}
		if err != nil {
			return s, err
		}
	}
	return s, nil
}

// selectList picks the columns Table reads, and the expression for each:
// the readable columns, plus the short binary columns Hex picks, as hex.
func (sm *Sampler) selectList(t *model.Table) (*Sample, []string) {
	s := &Sample{}
	var exprs []string
	for _, c := range t.Columns {
		switch {
		case Sampleable(c):
			s.Columns, s.Hex = append(s.Columns, c), append(s.Hex, false)
			exprs = append(exprs, sm.valueExpr(c))
		case sm.Hex != nil && ShortBinary(c) && sm.Hex(t, c):
			s.Columns, s.Hex = append(s.Columns, c), append(s.Hex, true)
			exprs = append(exprs, "HEX("+QuoteIdent(c.Name)+")")
		}
	}
	return s, exprs
}

// KeyValues reads up to limit values of valueCol from rows where keyCol
// equals key. It is used to look at a known meta key directly when the
// window sample happened to miss it.
func (sm *Sampler) KeyValues(ctx context.Context, t *model.Table, keyCol, valueCol *model.Column, key string, limit int) ([]string, error) {
	q := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? LIMIT %d",
		sm.valueExpr(valueCol), QuoteIdent(t.Name), QuoteIdent(keyCol.Name), limit)
	ctx, cancel := context.WithTimeout(ctx, sm.Timeout)
	defer cancel()
	rows, err := sm.DB.QueryContext(ctx, q, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v sql.RawBytes
		if err := rows.Scan(&v); err != nil {
			return out, err
		}
		if v != nil {
			out = append(out, string(v))
		}
	}
	return out, rows.Err()
}

func (sm *Sampler) valueExpr(c *model.Column) string { return ValueExpr(c, sm.MaxValueLen) }

func (sm *Sampler) row(ctx context.Context, q string, dest ...any) error {
	ctx, cancel := context.WithTimeout(ctx, sm.Timeout)
	defer cancel()
	return sm.DB.QueryRowContext(ctx, q).Scan(dest...)
}

func (sm *Sampler) rows(ctx context.Context, q string, n int) ([][]sql.NullString, error) {
	ctx, cancel := context.WithTimeout(ctx, sm.Timeout)
	defer cancel()
	rows, err := sm.DB.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	raw := make([]sql.RawBytes, n)
	dest := make([]any, n)
	for i := range raw {
		dest[i] = &raw[i]
	}
	var out [][]sql.NullString
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return out, err
		}
		row := make([]sql.NullString, n)
		for i, b := range raw {
			if b != nil {
				row[i] = sql.NullString{String: string(b), Valid: true}
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
