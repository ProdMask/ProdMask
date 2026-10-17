package sample

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// KV is one row of a key/value table: its key, its primary key (empty
// without a single-column one) and its value, cut on the server.
type KV struct {
	Key   string
	PK    string
	Value string
	Null  bool
}

// errByteCap stops a read that reached its byte budget.
var errByteCap = errors.New("byte budget reached")

// singlePK returns the single-column primary key, or nil.
func singlePK(t *model.Table) *model.Column {
	if pk := t.SinglePK(); pk != nil && Sampleable(pk) {
		return pk
	}
	return nil
}

func pkExpr(t *model.Table) string {
	if pk := singlePK(t); pk != nil {
		return QuoteIdent(pk.Name)
	}
	return "''"
}

// WholeTable reads the key and value of up to maxRows rows, in primary key
// order. It reports whether it read the whole table: false when there are
// more rows than maxRows, or when maxBytes of values were read first. At
// the byte cap it cancels the statement, since closing the rows would make
// the server send the rest anyway.
func (sm *Sampler) WholeTable(ctx context.Context, t *model.Table, keyCol, valueCol *model.Column, valueLen, maxRows int, maxBytes int64) (rows []KV, complete bool, read int64, err error) {
	q := fmt.Sprintf("SELECT %s, %s, %s FROM %s", QuoteIdent(keyCol.Name), pkExpr(t), ValueExpr(valueCol, valueLen), QuoteIdent(t.Name))
	if pk := singlePK(t); pk != nil {
		q += " ORDER BY " + QuoteIdent(pk.Name)
	}
	q += fmt.Sprintf(" LIMIT %d", maxRows+1)
	more := false
	err = sm.stream(ctx, q, nil, func(r []sql.RawBytes) error {
		if len(rows) == maxRows {
			more = true // the one row past maxRows: the LIMIT ends the result after it
			return nil
		}
		kv := KV{Key: string(r[0]), PK: string(r[1]), Value: string(r[2]), Null: r[2] == nil}
		read += int64(len(r[0]) + len(r[2]))
		rows = append(rows, kv)
		if read > maxBytes {
			return errByteCap
		}
		return nil
	})
	if errors.Is(err, errByteCap) {
		return rows, false, read, nil
	}
	return rows, err == nil && !more, read, err
}

// Keys lists the distinct keys of a key/value table in key order, up to
// max. more reports that there were more.
func (sm *Sampler) Keys(ctx context.Context, t *model.Table, keyCol *model.Column, max int) (keys []string, more bool, err error) {
	k := QuoteIdent(keyCol.Name)
	q := fmt.Sprintf("SELECT DISTINCT %s FROM %s WHERE %s IS NOT NULL ORDER BY %s LIMIT %d", k, QuoteIdent(t.Name), k, k, max+1)
	err = sm.stream(ctx, q, nil, func(r []sql.RawBytes) error {
		if len(keys) == max {
			more = true // the one key past max: the LIMIT ends the result after it
			return nil
		}
		keys = append(keys, string(r[0]))
		return nil
	})
	return keys, more, err
}

// Lookup asks for the rows of one key, or of every key with a prefix.
type Lookup struct {
	Key    string
	Prefix bool // Key is a prefix: rows whose key starts with it
	Limit  int
}

// Batch is what KeyValuesBatch or ProbeScan read for a list of lookups.
type Batch struct {
	Rows map[int][]KV // the rows of each lookup, by its index
	// Complete marks the lookups that ran to their end. The others were
	// cut short by the byte budget or an error, or never ran, and may have
	// some rows or none.
	Complete []bool
	Bytes    int64 // keys and values read
}

func newBatch(n int) Batch { return Batch{Rows: map[int][]KV{}, Complete: make([]bool, n)} }

// likePrefix escapes a prefix for LIKE ... ESCAPE '!'.
func likePrefix(p string) string {
	r := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")
	return r.Replace(p) + "%"
}

// lookupBatch is how many lookups one UNION ALL statement holds.
const lookupBatch = 50

// KeyValuesBatch runs lookups in UNION ALL batches, each part an indexed
// read with its own LIMIT. It stops at maxBytes of keys and values, and at
// the first failed batch.
func (sm *Sampler) KeyValuesBatch(ctx context.Context, t *model.Table, keyCol, valueCol *model.Column, lookups []Lookup, valueLen int, maxBytes int64) (Batch, error) {
	b := newBatch(len(lookups))
	k := QuoteIdent(keyCol.Name)
	sel := fmt.Sprintf("%s, %s, %s FROM %s WHERE ", k, pkExpr(t), ValueExpr(valueCol, valueLen), QuoteIdent(t.Name))
	for start := 0; start < len(lookups); start += lookupBatch {
		end := min(start+lookupBatch, len(lookups))
		var parts []string
		var args []any
		for i := start; i < end; i++ {
			l := lookups[i]
			cond, arg := k+" = ?", any(l.Key)
			if l.Prefix {
				cond, arg = k+" LIKE ? ESCAPE '!'", any(likePrefix(l.Key))
			}
			// i is a number computed here, never text from the database.
			parts = append(parts, fmt.Sprintf("(SELECT %d, %s%s LIMIT %d)", i, sel, cond, max(l.Limit, 1)))
			args = append(args, arg)
		}
		last := start // the lookup of the last row read
		err := sm.stream(ctx, strings.Join(parts, " UNION ALL "), args, func(r []sql.RawBytes) error {
			var i int
			fmt.Sscan(string(r[0]), &i)
			b.Rows[i] = append(b.Rows[i], KV{Key: string(r[1]), PK: string(r[2]), Value: string(r[3]), Null: r[3] == nil})
			b.Bytes += int64(len(r[1]) + len(r[3]))
			last = i
			if b.Bytes > maxBytes {
				return errByteCap
			}
			return nil
		})
		if err != nil {
			// UNION ALL returns its parts in order: those before the part
			// that was cut ran to their end.
			for i := start; i < last; i++ {
				b.Complete[i] = true
			}
			if errors.Is(err, errByteCap) {
				err = nil
			}
			return b, err
		}
		for i := start; i < end; i++ {
			b.Complete[i] = true
		}
	}
	return b, nil
}

// probeQuery builds the statement of ProbeScan: the prefix conditions,
// then one IN list of the exact keys, with the arguments in the same order.
func probeQuery(t *model.Table, keyCol, valueCol *model.Column, lookups []Lookup, valueLen int) (string, []any) {
	k := QuoteIdent(keyCol.Name)
	var conds []string
	var args, exact []any
	for _, l := range lookups {
		if l.Prefix {
			conds = append(conds, k+" LIKE ? ESCAPE '!'")
			args = append(args, likePrefix(l.Key))
		} else {
			exact = append(exact, l.Key)
		}
	}
	if len(exact) > 0 {
		conds = append(conds, k+" IN ("+strings.TrimSuffix(strings.Repeat("?, ", len(exact)), ", ")+")")
		args = append(args, exact...)
	}
	cols := k + ", " + pkExpr(t)
	if singlePK(t) == nil {
		cols += ", " + ValueExpr(valueCol, valueLen)
	}
	return fmt.Sprintf("SELECT %s FROM %s WHERE %s", cols, QuoteIdent(t.Name), strings.Join(conds, " OR ")), args
}

// ProbeScan reads, in one pass over a table whose key column has no index,
// up to Limit rows for each lookup. The pass reads keys and primary keys
// only and is cancelled once every lookup has its rows; the values are
// then read by primary key, in lookup order. Without a single-column
// primary key the pass reads the values itself. Only the rows kept count
// against maxBytes, so a busy family can't crowd out a rare key, and rows
// whose values weren't read are dropped.
func (sm *Sampler) ProbeScan(ctx context.Context, t *model.Table, keyCol, valueCol *model.Column, lookups []Lookup, valueLen int, maxBytes int64) (Batch, error) {
	b := newBatch(len(lookups))
	if len(lookups) == 0 {
		return b, nil
	}
	q, args := probeQuery(t, keyCol, valueCol, lookups, valueLen)
	pk := singlePK(t)
	lower := make([]string, len(lookups))
	for i, l := range lookups {
		lower[i] = strings.ToLower(l.Key)
	}
	left := len(lookups)
	got := make([]int, len(lookups))
	err := sm.stream(ctx, q, args, func(r []sql.RawBytes) error {
		key := string(r[0])
		lk := strings.ToLower(key)
		for i, l := range lookups {
			limit := max(l.Limit, 1)
			if got[i] >= limit {
				continue
			}
			// As the usual case-insensitive collations compare.
			if (l.Prefix && strings.HasPrefix(lk, lower[i])) ||
				(!l.Prefix && strings.TrimRight(lk, " ") == strings.TrimRight(lower[i], " ")) {
				kv := KV{Key: key, PK: string(r[1])}
				b.Bytes += int64(len(r[0]))
				if pk == nil {
					kv.Value, kv.Null = string(r[2]), r[2] == nil
					b.Bytes += int64(len(r[2]))
				}
				b.Rows[i] = append(b.Rows[i], kv)
				if got[i]++; got[i] == limit {
					left--
				}
				break
			}
		}
		if left == 0 {
			return errStop
		}
		if b.Bytes > maxBytes {
			return errByteCap
		}
		return nil
	})
	// A pass that saw the whole table, or filled every lookup, leaves each
	// lookup complete; a cut one only those that got all their rows.
	cut := err != nil && !errors.Is(err, errStop)
	for i, l := range lookups {
		b.Complete[i] = !cut || got[i] >= max(l.Limit, 1)
	}
	if errors.Is(err, errStop) || errors.Is(err, errByteCap) {
		err = nil
	}
	if pk == nil {
		return b, err
	}

	// Values by primary key, one lookup at a time in lookup order, so a cut
	// keeps the first lookups whole. A pass that failed still has its rows'
	// values read.
	answered := map[string]bool{}
values:
	for i := range lookups {
		rows := b.Rows[i]
		for start := 0; start < len(rows); start += 500 {
			end := min(start+500, len(rows))
			byPK := map[string]*KV{}
			pks := make([]any, 0, end-start)
			for j := start; j < end; j++ {
				byPK[rows[j].PK] = &rows[j]
				pks = append(pks, rows[j].PK)
			}
			q := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s IN (%s)", QuoteIdent(pk.Name), ValueExpr(valueCol, valueLen),
				QuoteIdent(t.Name), QuoteIdent(pk.Name), strings.TrimSuffix(strings.Repeat("?,", end-start), ","))
			verr := sm.stream(ctx, q, pks, func(r []sql.RawBytes) error {
				if kv := byPK[string(r[0])]; kv != nil {
					kv.Value, kv.Null = string(r[1]), r[1] == nil
					answered[kv.PK] = true
					b.Bytes += int64(len(r[1]))
				}
				if b.Bytes > maxBytes {
					return errByteCap
				}
				return nil
			})
			if verr != nil {
				if !errors.Is(verr, errByteCap) && err == nil {
					err = verr
				}
				break values
			}
		}
	}
	for i := range lookups {
		rows := b.Rows[i][:0]
		for _, kv := range b.Rows[i] {
			if answered[kv.PK] {
				rows = append(rows, kv)
			}
		}
		if len(rows) < len(b.Rows[i]) {
			b.Complete[i] = false
		}
		if len(rows) == 0 {
			delete(b.Rows, i)
		} else {
			b.Rows[i] = rows
		}
	}
	return b, err
}

// Where reads up to limit values of one column from the rows that match
// a condition. The condition comes from a preset, never from the database.
func (sm *Sampler) Where(ctx context.Context, t *model.Table, c *model.Column, where string, limit int) ([]string, error) {
	q := fmt.Sprintf("SELECT %s FROM %s WHERE %s LIMIT %d", sm.valueExpr(c), QuoteIdent(t.Name), where, limit)
	var out []string
	err := sm.stream(ctx, q, nil, func(r []sql.RawBytes) error {
		if r[0] != nil {
			out = append(out, string(r[0]))
		}
		return nil
	})
	return out, err
}

// errStop ends a stream early on purpose.
var errStop = errors.New("stop")

// stream runs a query and hands each row to fn. When fn returns an error
// the statement is cancelled at once, so the server stops sending rows.
func (sm *Sampler) stream(ctx context.Context, q string, args []any, fn func([]sql.RawBytes) error) error {
	ctx, cancel := context.WithTimeout(ctx, sm.Timeout)
	defer cancel()
	rows, err := sm.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	cols, err := rows.Columns()
	if err != nil {
		rows.Close()
		return err
	}
	raw := make([]sql.RawBytes, len(cols))
	dest := make([]any, len(cols))
	for i := range raw {
		dest[i] = &raw[i]
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			rows.Close()
			return err
		}
		if err := fn(raw); err != nil {
			cancel() // before Close: Close would read the rest of the result
			rows.Close()
			return err
		}
	}
	err = rows.Err()
	rows.Close()
	return err
}
