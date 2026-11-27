package preset

import (
	"context"
	"errors"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// Offline answers the reads the presets make that settings and attribute
// data need, from a dump file instead of a server. Both funcs are required.
type Offline struct {
	// Options answers env.options as its SQL does: for the key/value table
	// with this name, the value of each of keys that it holds, the first one
	// in the table where a key repeats, with values cut at 65,535
	// characters. A key it holds nothing for is left out.
	Options func(table, keyCol, valueCol string, keys []string) map[string]string
	// Rows returns the kept rows of the whole table with this name, as
	// strings, with the named columns in the order given. Rows of a table
	// it holds nothing for are left out.
	Rows func(table string, columns []string) [][]string
}

// SettingsKeys returns the option names the detection reads through
// siteOptions. They're read from `*options` tables, with the columns
// option_name and option_value, at any table prefix.
func SettingsKeys() []string {
	return []string{"db_version", "woocommerce_version", "woocommerce_custom_orders_table_enabled"}
}

// WholeTables names the tables a dump reader must keep whole for
// DetectOffline, at any table prefix, with the columns it reads.
func WholeTables() map[string][]string {
	return map[string][]string{
		"eav_attribute":   {"attribute_id", "attribute_code", "entity_type_id"},
		"eav_entity_type": {"entity_type_id", "entity_type_code"},
	}
}

// DetectOffline is Detect for a schema read from a dump file, with no
// server. It runs the same code, with settings and attribute rows from src.
// The reads that only side effects and platform details use are skipped, so
// it lists no side effects, and the platform details that come from reading
// the database (the db_version excepted, which src gives) are missing:
// Magento's store views and Laravel's migration count.
func DetectOffline(schema *model.Schema, which string, src Offline) *Result {
	e := newEnv(context.Background(), nil, schema, 0)
	e.off = &src
	return e.detect(which)
}

// errOffline is what a read that needs a server gives without one.
var errOffline = errors.New("no server to read from")

// online runs f only with a server. The side-effect checks run through it,
// so without one they're skipped whole; it keeps each call on one line, so
// the calls after it keep their places in the file. Two reads are guarded
// inline with e.off == nil instead, inside a condition that was already
// there: Laravel's count of queued jobs (laravel.go) and Magento's count of
// store views (magento.go). Laravel's migration count goes through
// countOnline.
func (e *env) online(f func()) {
	if e.off == nil {
		f()
	}
}

// countOnline runs a count that only a platform detail uses; without a
// server it gives errOffline and the detail is left out.
func (e *env) countOnline(query string, args ...any) (int64, error) {
	if e.off != nil {
		return 0, errOffline
	}
	return e.count(query, args...)
}

// eavRows runs eavLabels' query, or without a server does its join in Go
// over the dump's rows.
func (e *env) eavRows(attrs, types, query string) ([][]string, error) {
	if e.off != nil {
		return e.offlineEAV(attrs, types), nil
	}
	return e.rows(query)
}

// offlineEAV is eavLabels' join, done in Go over the dump's rows: the
// (attribute_id, attribute_code) of each attribute whose entity type is
// customer or customer_address.
func (e *env) offlineEAV(attrs, types string) [][]string {
	codes := map[string]bool{}
	for _, t := range e.off.Rows(types, []string{"entity_type_id", "entity_type_code"}) {
		if strings.EqualFold(t[1], "customer") || strings.EqualFold(t[1], "customer_address") {
			codes[t[0]] = true
		}
	}
	var out [][]string
	for _, a := range e.off.Rows(attrs, []string{"attribute_id", "attribute_code", "entity_type_id"}) {
		if codes[a[2]] {
			out = append(out, a[:2])
		}
	}
	return out
}
