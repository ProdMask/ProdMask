package sample

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"slices"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// spreadBatch is how many points one UNION ALL statement holds.
const spreadBatch = 50

// SpreadRow is one row a Spread read: the point it came from, its primary
// key (empty without a single integer one) and the values of the expressions
// asked for.
type SpreadRow struct {
	Point  int
	PK     string
	Values []sql.NullString
}

// SpreadResult is what a Spread read.
type SpreadResult struct {
	Rows   []SpreadRow
	Method string // model.SampleSpread, SampleThin, SampleAllRows or SampleFirstRows
}

// IntegerPK returns the single integer primary key, or nil.
func IntegerPK(t *model.Table) *model.Column {
	if pk := t.SinglePK(); pk != nil && IsInteger(pk) {
		return pk
	}
	return nil
}

// Spread reads a sample of a table's rows, with one read per point over the
// integer primary key's range. The range is cut into points equal slices, and
// each gets a random spot in it and the perPoint rows from there, so a row is
// about as likely as any other to be read, and any unbroken run of rows that
// covers two slices is certain to be. Each point is one indexed seek, and no
// statement reads more than its LIMITs say.
//
// A table that fits in points*perPoint rows is read whole instead, in key
// order; one with no single integer primary key gets its first rows. Gaps in
// the key make points land on the same rows, which are dropped, and on the rows
// right after each gap. So under half the points with a row of their own makes
// the method model.SampleThin, and so do rows far from their points, as with
// keys in tight clusters, where every point can have a row and all of them be
// first in their cluster.
//
// args are the arguments of exprs, and are only allowed without an integer
// key or with a table read whole: a statement of many points would repeat
// them for each. On an error, the rows read so far come back with it. pick
// picks a number below n; nil picks at random. Reports must never print what
// comes back.
func (sm *Sampler) Spread(ctx context.Context, t *model.Table, exprs []string, args []any, points, perPoint int, pick func(n uint64) uint64) (*SpreadResult, error) {
	limit := points * perPoint
	res := &SpreadResult{Method: model.SampleSpread}
	pk := IntegerPK(t)
	if pk == nil {
		rows, whole, err := sm.inOrder(ctx, t, nil, exprs, args, limit)
		res.Rows = rows
		res.Method = model.SampleFirstRows
		if whole && err == nil {
			res.Method = model.SampleAllRows
		}
		return res, err
	}
	pkq := QuoteIdent(pk.Name)
	var lo, hi sql.NullString
	if err := sm.row(ctx, fmt.Sprintf("SELECT MIN(%s), MAX(%s) FROM %s", pkq, pkq, QuoteIdent(t.Name)), &lo, &hi); err != nil {
		return res, err
	}
	if !lo.Valid || !hi.Valid {
		res.Method = model.SampleAllRows
		return res, nil
	}
	first, ok1 := new(big.Int).SetString(lo.String, 10)
	last, ok2 := new(big.Int).SetString(hi.String, 10)
	if !ok1 || !ok2 {
		return res, errors.New("the primary key isn't a whole number")
	}
	span := new(big.Int).Add(new(big.Int).Sub(last, first), big.NewInt(1))
	if t.RowsEstimate <= int64(limit) || span.Cmp(big.NewInt(int64(limit)*2)) <= 0 {
		rows, whole, err := sm.inOrder(ctx, t, pk, exprs, args, limit)
		if err != nil {
			res.Rows = rows
			return res, err
		}
		if whole {
			res.Rows = rows
			res.Method = model.SampleAllRows
			return res, nil
		}
		// More rows than the sample: its oldest rows wouldn't do.
	}
	if len(args) > 0 {
		return res, errors.New("a spread read takes no arguments")
	}
	if pick == nil {
		pick = rand.Uint64N
	}
	sel := strings.Join(append([]string{pkq}, exprs...), ", ")
	seen := map[string]bool{}
	back := 0
	spots := make([]string, points)
	var distances []float64
	for start := 0; start < points; start += spreadBatch {
		end := min(start+spreadBatch, points)
		parts := make([]string, 0, end-start)
		for i := start; i < end; i++ {
			// i and the point are numbers computed here, never text from the
			// database.
			spots[i] = slicePoint(first, span, i, points, pick)
			parts = append(parts, fmt.Sprintf("(SELECT %d, %s FROM %s WHERE %s >= %s ORDER BY %s LIMIT %d)",
				i, sel, QuoteIdent(t.Name), pkq, spots[i], pkq, perPoint))
		}
		rows, err := sm.rows(ctx, strings.Join(parts, " UNION ALL "), len(exprs)+2)
		fresh := map[string]bool{}
		firsts := map[string]bool{}
		for _, r := range rows {
			id := r[1].String
			var point int
			fmt.Sscan(r[0].String, &point)
			if !firsts[r[0].String] {
				firsts[r[0].String] = true
				distances = append(distances, keyDistance(id, spots[point]))
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			if !fresh[r[0].String] {
				fresh[r[0].String] = true
				back++
			}
			res.Rows = append(res.Rows, SpreadRow{Point: point, PK: id, Values: r[2:]})
		}
		if err != nil {
			return res, err
		}
	}
	if back*2 < points || clustered(distances, span, t.RowsEstimate) {
		res.Method = model.SampleThin
	}
	return res, nil
}

// clusterFactor is how many times the keys' average spacing a row can usually
// be from its point before the sample reads as first-in-cluster rows. Evenly
// spread keys give about 0.7 times it, whatever their gaps' sizes.
const clusterFactor = 5

// keyDistance is how far a row's key is from its point.
func keyDistance(key, spot string) float64 {
	k, ok1 := new(big.Int).SetString(key, 10)
	p, ok2 := new(big.Int).SetString(spot, 10)
	if !ok1 || !ok2 {
		return 0
	}
	d, _ := new(big.Float).SetInt(k.Sub(k, p)).Float64()
	return d
}

// clustered reports whether rows are usually much further from their points
// than the table's size and key range explain. A table's row estimate can be
// off, but not by that much in that direction; with no estimate, it can't tell.
func clustered(distances []float64, span *big.Int, rowsEstimate int64) bool {
	if len(distances) == 0 || rowsEstimate <= 0 {
		return false
	}
	slices.Sort(distances)
	s, _ := new(big.Float).SetInt(span).Float64()
	return distances[len(distances)/2] > clusterFactor*s/float64(rowsEstimate)
}

// slicePoint picks a random spot in slice i of a key range starting at first.
func slicePoint(first, span *big.Int, i, points int, pick func(n uint64) uint64) string {
	n := big.NewInt(int64(points))
	from := new(big.Int).Mul(span, big.NewInt(int64(i)))
	from.Div(from, n)
	to := new(big.Int).Mul(span, big.NewInt(int64(i)+1))
	to.Div(to, n)
	at := new(big.Int).Add(first, from)
	if width := new(big.Int).Sub(to, from); width.IsUint64() && width.Uint64() > 0 {
		at.Add(at, new(big.Int).SetUint64(pick(width.Uint64())))
	}
	return at.String()
}

// inOrder reads up to limit rows, by primary key if there is one, and reports
// whether that was all of them. The primary key comes first, or empty without
// one, so the rows have the shape of a spread read's.
func (sm *Sampler) inOrder(ctx context.Context, t *model.Table, pk *model.Column, exprs []string, args []any, limit int) ([]SpreadRow, bool, error) {
	key := "''"
	order := ""
	if pk != nil {
		key = QuoteIdent(pk.Name)
		order = " ORDER BY " + key
	}
	q := fmt.Sprintf("SELECT %s FROM %s%s LIMIT %d", strings.Join(append([]string{key}, exprs...), ", "), QuoteIdent(t.Name), order, limit+1)
	var rows []SpreadRow
	whole := true
	err := sm.stream(ctx, q, args, func(r []sql.RawBytes) error {
		if len(rows) == limit {
			whole = false // the one row past the sample: the LIMIT ends the result after it
			return nil
		}
		row := SpreadRow{Point: len(rows), PK: string(r[0]), Values: make([]sql.NullString, len(r)-1)}
		for i, b := range r[1:] {
			if b != nil {
				row.Values[i] = sql.NullString{String: string(b), Valid: true}
			}
		}
		rows = append(rows, row)
		return nil
	})
	return rows, whole, err
}

// PKValue is one value read by primary key.
type PKValue struct {
	PK    string
	Value string
	Valid bool
}

// ValuesByPK reads one column of the rows with these integer primary keys. An
// id that isn't a whole number is refused, as the ids go into the statement's
// text.
func (sm *Sampler) ValuesByPK(ctx context.Context, t *model.Table, pk, c *model.Column, chars int, ids []string) ([]PKValue, error) {
	for _, id := range ids {
		if _, ok := new(big.Int).SetString(id, 10); !ok {
			return nil, errors.New("the primary key isn't a whole number")
		}
	}
	q := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s IN (%s)", QuoteIdent(pk.Name), ValueExpr(c, chars), QuoteIdent(t.Name),
		QuoteIdent(pk.Name), strings.Join(ids, ","))
	var out []PKValue
	err := sm.stream(ctx, q, nil, func(r []sql.RawBytes) error {
		out = append(out, PKValue{PK: string(r[0]), Value: string(r[1]), Valid: r[1] != nil})
		return nil
	})
	return out, err
}

// Whole hands every row of a table to fn, without its primary key. A table
// with a single integer primary key is read in chunks, each a statement of its
// own, so no statement runs long and no snapshot or lock outlives one; the
// first has no lower bound, so negative keys aren't skipped. Any other table
// is one statement, which a time limit may stop. Whole returns the rows it
// handed over, with the error that stopped it, if any.
func (sm *Sampler) Whole(ctx context.Context, t *model.Table, exprs []string, args []any, chunk int, fn func([]sql.RawBytes) error) (int64, error) {
	list := strings.Join(exprs, ", ")
	table := QuoteIdent(t.Name)
	pk := IntegerPK(t)
	var read int64
	if pk == nil {
		err := sm.stream(ctx, fmt.Sprintf("SELECT %s FROM %s", list, table), args, func(r []sql.RawBytes) error {
			read++
			return fn(r)
		})
		return read, err
	}
	pkq := QuoteIdent(pk.Name)
	after := ""
	for {
		q := fmt.Sprintf("SELECT %s, %s FROM %s%s ORDER BY %s LIMIT %d", pkq, list, table, after, pkq, chunk)
		n := 0
		var last *big.Int
		err := sm.stream(ctx, q, args, func(r []sql.RawBytes) error {
			n++
			read++
			if n == chunk {
				var ok bool
				if last, ok = new(big.Int).SetString(string(r[0]), 10); !ok {
					return errors.New("the primary key isn't a whole number")
				}
			}
			return fn(r[1:])
		})
		if err != nil || n < chunk {
			return read, err
		}
		// A number parsed here, never text from the database.
		after = " WHERE " + pkq + " > " + last.String()
	}
}
