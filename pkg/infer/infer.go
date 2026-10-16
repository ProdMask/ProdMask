// Package infer finds relationships between tables that the schema does not
// declare, and checks them against sampled values.
package infer

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// maxIDs is how many distinct values per column are kept for checks.
const maxIDs = 100

// IDValues keeps a few distinct sampled values of the columns that may
// point at other tables.
type IDValues struct {
	cols  map[string]map[string]*valueSet            // table → column
	morph map[string]map[string]map[string]*valueSet // table → id column → type value
}

type valueSet struct {
	seen  map[string]bool
	order []string
}

func (s *valueSet) add(v string) {
	if len(s.order) >= maxIDs || s.seen[v] {
		return
	}
	s.seen[v] = true
	s.order = append(s.order, v)
}

// NewIDValues returns an empty store.
func NewIDValues() *IDValues {
	return &IDValues{cols: map[string]map[string]*valueSet{}, morph: map[string]map[string]map[string]*valueSet{}}
}

func newSet() *valueSet { return &valueSet{seen: map[string]bool{}} }

// Collect keeps candidate key values from one table's sample: integer and
// short text columns other than a single-column primary key, and
// polymorphic (x_type, x_id) pairs.
func (v *IDValues) Collect(t *model.Table, s *sample.Sample) {
	for i, c := range s.Columns {
		if !keyLike(c) {
			continue
		}
		cols := v.cols[t.Name]
		if cols == nil {
			cols = map[string]*valueSet{}
			v.cols[t.Name] = cols
		}
		set := cols[c.Name]
		if set == nil {
			set = newSet()
			cols[c.Name] = set
		}
		for _, row := range s.Rows {
			if row[i].Valid && usableID(row[i].String) {
				set.add(row[i].String)
			}
		}
	}
	for _, pair := range morphPairs(t) {
		ti, ii := s.Index(pair[0]), s.Index(pair[1])
		if ti < 0 || ii < 0 {
			continue
		}
		for _, row := range s.Rows {
			if !row[ti].Valid || !row[ii].Valid || !usableID(row[ii].String) {
				continue
			}
			byID := v.morph[t.Name]
			if byID == nil {
				byID = map[string]map[string]*valueSet{}
				v.morph[t.Name] = byID
			}
			byType := byID[pair[1]]
			if byType == nil {
				byType = map[string]*valueSet{}
				byID[pair[1]] = byType
			}
			set := byType[row[ti].String]
			if set == nil {
				if len(byType) >= 20 {
					continue
				}
				set = newSet()
				byType[row[ti].String] = set
			}
			set.add(row[ii].String)
		}
	}
}

func usableID(s string) bool { return s != "" && s != "0" }

// Get returns the kept values of a column.
func (v *IDValues) Get(table, column string) []string {
	if s := v.cols[table][column]; s != nil {
		return s.order
	}
	return nil
}

// morphTypes returns the type values seen for a polymorphic id column.
func (v *IDValues) morphTypes(table, idColumn string) []string {
	var out []string
	for t := range v.morph[table][idColumn] {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func keyLike(c *model.Column) bool {
	if sample.IsInteger(c) {
		return true
	}
	switch c.DataType {
	case "char", "varchar":
		return c.MaxLength > 0 && c.MaxLength <= 64
	case "uuid":
		return true
	}
	return false
}

func compatible(a, b *model.Column) bool {
	ai, bi := sample.IsInteger(a), sample.IsInteger(b)
	if ai || bi {
		return ai && bi
	}
	return keyLike(a) && keyLike(b)
}

// morphPairs finds Laravel-style polymorphic columns: commentable_type and
// commentable_id.
func morphPairs(t *model.Table) [][2]string {
	var out [][2]string
	for _, c := range t.Columns {
		name := strings.ToLower(c.Name)
		if !strings.HasSuffix(name, "_type") {
			continue
		}
		base := strings.TrimSuffix(c.Name, c.Name[len(c.Name)-5:])
		id := t.Column(base + "_id")
		if id == nil || inPrimaryKey(t, id.Name) {
			continue // e.g. wp_comments.comment_type next to its own key comment_ID
		}
		out = append(out, [2]string{c.Name, id.Name})
	}
	return out
}

// Inferrer proposes relationships for one schema.
type Inferrer struct {
	Schema   *model.Schema
	IDs      *IDValues
	Prefixes []string             // table prefixes such as "wp_"
	Known    []model.Relationship // from presets
}

var userAliases = map[string]bool{
	"author": true, "owner": true, "creator": true, "editor": true, "assignee": true, "reporter": true,
	"uploader": true, "approver": true, "reviewer": true, "causer": true, "created": true, "updated": true,
	"modified": true, "deleted": true,
}

// Relationships returns the declared foreign keys, the preset relationships
// and those guessed from naming. Only declared ones are marked as such; the
// rest still need Verify.
func (in *Inferrer) Relationships() []model.Relationship {
	var out []model.Relationship
	seen := map[string]bool{}
	covered := map[string]bool{} // table.column already linked
	add := func(r model.Relationship) {
		k := r.Key()
		if seen[k] {
			return
		}
		seen[k] = true
		if len(r.ChildColumns) == 1 && r.TypeValue == "" {
			covered[r.ChildTable+"."+strings.ToLower(r.ChildColumns[0])] = true
		}
		out = append(out, r)
	}

	for _, t := range in.Schema.Tables {
		for _, fk := range t.ForeignKeys {
			r := model.Relationship{
				ChildTable: t.Name, ChildColumns: fk.Columns,
				ParentTable: fk.RefTable, ParentColumns: fk.RefColumns,
				Source: "declared", Status: model.RelDeclared,
			}
			if !strings.EqualFold(fk.RefSchema, in.Schema.Database) {
				r.ParentTable = fk.RefSchema + "." + fk.RefTable
				r.Note = "points at another database"
			}
			add(r)
		}
	}
	for _, r := range in.Known {
		child, parent := in.Schema.Table(r.ChildTable), in.Schema.Table(r.ParentTable)
		if child == nil || parent == nil || !hasColumns(child, r.ChildColumns) || !hasColumns(parent, r.ParentColumns) {
			continue
		}
		if covered[r.ChildTable+"."+strings.ToLower(r.ChildColumns[0])] {
			continue
		}
		r.Status = model.RelUnverified
		add(r)
	}

	for _, t := range in.Schema.Tables {
		if !t.IsData() {
			continue
		}
		pk := t.SinglePK()
		for _, c := range t.Columns {
			if (pk != nil && c == pk) || !keyLike(c) || covered[t.Name+"."+strings.ToLower(c.Name)] {
				continue
			}
			if parent := in.parentByName(t, c); parent != nil {
				add(model.Relationship{
					ChildTable: t.Name, ChildColumns: []string{c.Name},
					ParentTable: parent.Name, ParentColumns: []string{parent.SinglePK().Name},
					Source: "naming", Status: model.RelUnverified,
				})
			}
		}
		for _, pair := range morphPairs(t) {
			for _, typ := range in.IDs.morphTypes(t.Name, pair[1]) {
				parent := in.tableForClass(typ)
				if parent == nil {
					continue
				}
				add(model.Relationship{
					ChildTable: t.Name, ChildColumns: []string{pair[1]},
					ParentTable: parent.Name, ParentColumns: []string{parent.SinglePK().Name},
					Source: "polymorphic", Status: model.RelUnverified,
					TypeColumn: pair[0], TypeValue: typ,
				})
			}
		}
	}
	return out
}

func inPrimaryKey(t *model.Table, column string) bool {
	for _, c := range t.PrimaryKey {
		if strings.EqualFold(c, column) {
			return true
		}
	}
	return false
}

func hasColumns(t *model.Table, cols []string) bool {
	for _, c := range cols {
		if t.Column(c) == nil {
			return false
		}
	}
	return len(cols) > 0
}

// parentByName guesses the table a column points at: customer_id points at
// customer(s) or customer_entity, parent_id at its own table, author_id at
// users. The parent needs a single-column primary key of a compatible type.
func (in *Inferrer) parentByName(t *model.Table, c *model.Column) *model.Table {
	tokens := detect.Tokens(c.Name)
	if n := len(tokens); n >= 2 && (tokens[n-1] == "id" || tokens[n-1] == "uuid") {
		base := tokens[:n-1]
		if len(base) == 1 && base[0] == "parent" {
			if pk := t.SinglePK(); pk != nil && compatible(c, pk) {
				return t
			}
			return nil
		}
		var names []string
		for i := 0; i < len(base); i++ { // billing_address → billing_address, address
			names = append(names, strings.Join(base[i:], "_"))
		}
		if userAliases[base[len(base)-1]] || (len(base) >= 2 && base[len(base)-1] == "by") {
			names = append(names, "user")
		}
		for _, name := range names {
			for _, candidate := range []string{name, plural(name), name + "_entity"} {
				if p := in.table(candidate); p != nil && p != t {
					if pk := p.SinglePK(); pk != nil && compatible(c, pk) {
						return p
					}
				}
			}
		}
	}
	// Magento EAV: customer_entity_varchar.entity_id → customer_entity.
	for _, p := range in.Schema.Tables {
		if p == t || !strings.HasPrefix(t.Name, p.Name+"_") {
			continue
		}
		if pk := p.SinglePK(); pk != nil && strings.EqualFold(pk.Name, c.Name) && compatible(c, pk) && !strings.EqualFold(c.Name, "id") {
			return p
		}
	}
	return nil
}

// table finds a table by name, trying the known prefixes.
func (in *Inferrer) table(name string) *model.Table {
	if t := in.Schema.Table(name); t != nil {
		return t
	}
	for _, p := range in.Prefixes {
		if t := in.Schema.Table(p + name); t != nil {
			return t
		}
	}
	return nil
}

// tableForClass maps a morph type such as App\Models\OrderItem or
// order_item to the order_items table.
func (in *Inferrer) tableForClass(typ string) *model.Table {
	name := typ
	if i := strings.LastIndexAny(name, `\/.`); i >= 0 {
		name = name[i+1:]
	}
	snake := strings.Join(detect.Tokens(name), "_")
	if snake == "" {
		return nil
	}
	for _, candidate := range []string{plural(snake), snake} {
		if t := in.table(candidate); t != nil && t.SinglePK() != nil {
			return t
		}
	}
	return nil
}

func plural(s string) string {
	switch {
	case strings.HasSuffix(s, "y") && len(s) > 1 && !strings.ContainsRune("aeiou", rune(s[len(s)-2])):
		return s[:len(s)-1] + "ies"
	case strings.HasSuffix(s, "s"), strings.HasSuffix(s, "x"), strings.HasSuffix(s, "z"),
		strings.HasSuffix(s, "ch"), strings.HasSuffix(s, "sh"):
		return s + "es"
	}
	return s + "s"
}

// Querier is the part of *sql.DB Verify needs.
type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Verify looks the sampled child values up in the parent table and grades
// every unverified relationship: confirmed when at least 90% exist, likely
// from 50%, weak below. Weak naming guesses are dropped.
func Verify(ctx context.Context, q Querier, ids *IDValues, schema *model.Schema, rels []model.Relationship, timeout time.Duration) ([]model.Relationship, []string) {
	var (
		out      []model.Relationship
		warnings []string
	)
	for _, r := range rels {
		if r.Status != model.RelUnverified || len(r.ChildColumns) != 1 || len(r.ParentColumns) != 1 {
			out = append(out, r)
			continue
		}
		var values []string
		if r.TypeValue != "" {
			if s := ids.morph[r.ChildTable][r.ChildColumns[0]][r.TypeValue]; s != nil {
				values = s.order
			}
		} else {
			values = ids.Get(r.ChildTable, r.ChildColumns[0])
		}
		if len(values) == 0 {
			r.Note = "no sampled values to check"
			if r.Source != "naming" {
				out = append(out, r)
			}
			continue
		}
		parent := schema.Table(r.ParentTable)
		pk := parent.Column(r.ParentColumns[0])
		found, err := lookup(ctx, q, parent, pk, values, timeout)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("could not check %s.%s → %s: %v",
				r.ChildTable, r.ChildColumns[0], r.ParentTable, err))
			out = append(out, r)
			continue
		}
		r.Checked, r.Found = len(values), found
		switch ratio := float64(found) / float64(len(values)); {
		case ratio >= 0.9:
			r.Status = model.RelConfirmed
		case ratio >= 0.5:
			r.Status = model.RelLikely
		default:
			r.Status = model.RelWeak
		}
		if r.Status == model.RelWeak && r.Source == "naming" {
			continue
		}
		out = append(out, r)
	}
	return out, warnings
}

func lookup(ctx context.Context, q Querier, parent *model.Table, pk *model.Column, values []string, timeout time.Duration) (int, error) {
	args := make([]any, len(values))
	for i, v := range values {
		args[i] = v
		if sample.IsInteger(pk) {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				args[i] = n
			}
		}
	}
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s IN (%s)",
		sample.QuoteIdent(parent.Name), sample.QuoteIdent(pk.Name), strings.TrimSuffix(strings.Repeat("?,", len(values)), ","))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var n int
	err := q.QueryRowContext(ctx, query, args...).Scan(&n)
	return n, err
}
