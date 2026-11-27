package preset

import (
	"context"
	"database/sql"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// noQuerier fails the test when a preset reads the database.
type noQuerier struct{ t *testing.T }

func (n noQuerier) QueryContext(_ context.Context, query string, _ ...any) (*sql.Rows, error) {
	n.t.Fatalf("offline detection ran a query: %s", query)
	return nil, nil
}

func (n noQuerier) QueryRowContext(_ context.Context, query string, _ ...any) *sql.Row {
	n.t.Fatalf("offline detection ran a query: %s", query)
	return nil
}

func schemaOf(tables map[string][]string) *model.Schema {
	s := &model.Schema{}
	names := make([]string, 0, len(tables))
	for n := range tables {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := &model.Table{Name: n, Type: "BASE TABLE"}
		for i, c := range tables[n] {
			t.Columns = append(t.Columns, &model.Column{Name: c, Position: i + 1, DataType: "varchar"})
		}
		s.Tables = append(s.Tables, t)
	}
	return s
}

func wpTables(prefix string, into map[string][]string) {
	into[prefix+"options"] = []string{"option_id", "option_name", "option_value"}
	into[prefix+"posts"] = []string{"ID", "post_author", "post_type", "post_title", "post_password"}
	into[prefix+"postmeta"] = []string{"meta_id", "post_id", "meta_key", "meta_value"}
}

// offlineEnv is DetectOffline's env with a querier that fails the test if
// any read reaches it, which proves no read is left unguarded.
func offlineEnv(t *testing.T, s *model.Schema, src Offline) *env {
	e := newEnv(context.Background(), noQuerier{t}, s, 0)
	e.off = &src
	return e
}

func settings(kv map[string]string) Offline {
	return Offline{
		Options: func(table, keyCol, valueCol string, keys []string) map[string]string {
			out := map[string]string{}
			for _, k := range keys {
				if v, ok := kv[table+"/"+k]; ok {
					out[k] = v
				}
			}
			return out
		},
		Rows: func(string, []string) [][]string { return nil },
	}
}

func TestDetectOfflineNeverReads(t *testing.T) {
	wp := map[string][]string{}
	wpTables("wp_", wp)
	wp["wp_users"] = []string{"ID", "user_email", "user_pass"}

	multi := map[string][]string{}
	wpTables("wp_", multi)
	wpTables("wp_2_", multi)
	multi["wp_users"] = []string{"ID", "user_email"}

	woo := map[string][]string{}
	wpTables("wp_", woo)
	woo["wp_users"] = []string{"ID", "user_email"}
	woo["wp_wc_orders"] = []string{"id", "customer_id", "billing_email"}
	woo["wp_wc_webhooks"] = []string{"webhook_id", "status", "delivery_url", "user_id"}
	woo["wp_actionscheduler_actions"] = []string{"action_id", "hook", "status", "group_id"}
	woo["wp_actionscheduler_groups"] = []string{"group_id", "slug"}

	mg := map[string][]string{
		"core_config_data":    {"config_id", "scope", "path", "value"},
		"eav_attribute":       {"attribute_id", "attribute_code", "entity_type_id"},
		"eav_entity_type":     {"entity_type_id", "entity_type_code"},
		"customer_entity":     {"entity_id", "email"},
		"sales_order":         {"entity_id", "customer_id", "send_email", "email_sent"},
		"store":               {"store_id", "code"},
		"cron_schedule":       {"schedule_id", "job_code", "status"},
		"customer_entity_int": {"value_id", "attribute_id", "entity_id", "value"},
	}
	lv := map[string][]string{
		"migrations": {"id", "migration", "batch"},
		"jobs":       {"id", "queue", "payload"},
		"users":      {"id", "email"},
	}

	cases := []struct {
		name     string
		tables   map[string][]string
		src      Offline
		platform []string
		details  map[string][]string
	}{
		{"wordpress", wp, settings(map[string]string{"wp_options/db_version": "57155"}),
			[]string{"wordpress"}, map[string][]string{"wordpress": {"db_version 57155"}}},
		{"multisite", multi, settings(nil), []string{"wordpress"},
			map[string][]string{"wordpress": {"multisite, 2 sites"}}},
		{"woocommerce hpos", woo, settings(map[string]string{
			"wp_options/woocommerce_version":                     "9.1.0",
			"wp_options/woocommerce_custom_orders_table_enabled": "yes"}),
			[]string{"wordpress", "woocommerce"},
			map[string][]string{"woocommerce": {"orders in HPOS tables"}}},
		{"woocommerce no hpos", woo, settings(map[string]string{
			"wp_options/woocommerce_version":                     "9.1.0",
			"wp_options/woocommerce_custom_orders_table_enabled": "no"}),
			[]string{"wordpress", "woocommerce"},
			map[string][]string{"woocommerce": {"orders stored as posts (HPOS tables exist but are not in use)"}}},
		{"magento", mg, Offline{
			Options: settings(nil).Options,
			Rows: func(table string, cols []string) [][]string {
				switch table {
				case "eav_entity_type":
					return [][]string{{"1", "customer"}, {"2", "customer_address"}, {"4", "catalog_product"}}
				case "eav_attribute":
					return [][]string{{"10", "firstname", "1"}, {"11", "street", "2"}, {"12", "name", "4"}}
				}
				return nil
			}}, []string{"magento2"}, nil},
		{"laravel", lv, settings(nil), []string{"laravel"}, nil},
		{"none", map[string][]string{"widgets": {"id", "name"}}, settings(nil), nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := offlineEnv(t, schemaOf(c.tables), c.src).detect("auto")
			var got []string
			for _, p := range res.Platforms {
				got = append(got, p.Name)
				if want, ok := c.details[p.Name]; ok && !reflect.DeepEqual(p.Details, want) {
					t.Errorf("%s details = %q, want %q", p.Name, p.Details, want)
				}
				if p.Name == "laravel" || p.Name == "magento2" {
					if len(p.Details) != 0 {
						t.Errorf("%s details = %q, want none offline", p.Name, p.Details)
					}
				}
			}
			if !reflect.DeepEqual(got, c.platform) {
				t.Errorf("platforms = %v, want %v", got, c.platform)
			}
			if len(res.SideEffects) != 0 {
				t.Errorf("side effects offline: %+v", res.SideEffects)
			}
			for _, w := range res.Warnings {
				if strings.Contains(w, "could not") {
					t.Errorf("warning: %s", w)
				}
			}
		})
	}
}

func TestDetectOfflineMagentoLabels(t *testing.T) {
	s := schemaOf(map[string][]string{
		"core_config_data":                {"config_id", "scope", "path", "value"},
		"eav_attribute":                   {"attribute_id", "attribute_code", "entity_type_id"},
		"eav_entity_type":                 {"entity_type_id", "entity_type_code"},
		"customer_entity":                 {"entity_id", "email"},
		"customer_entity_int":             {"value_id", "attribute_id", "entity_id", "value"},
		"customer_address_entity_varchar": {"value_id", "attribute_id", "entity_id", "value"},
	})
	var asked []string
	res := DetectOffline(s, "auto", Offline{
		Options: settings(nil).Options,
		Rows: func(table string, cols []string) [][]string {
			asked = append(asked, table+":"+strings.Join(cols, ","))
			switch table {
			case "eav_entity_type":
				return [][]string{{"1", "Customer"}, {"2", "customer_address"}, {"4", "catalog_product"}}
			case "eav_attribute":
				return [][]string{{"10", "firstname", "1"}, {"11", "street", "2"}, {"12", "name", "4"}, {"13", "bad@name", "1"}}
			}
			return nil
		},
	})
	m := res.Meta["customer_entity_int"]
	if m == nil {
		t.Fatalf("no meta table; platforms %v", res.Platforms)
	}
	for id, want := range map[string]string{"10": "firstname", "11": "street", "12": "attribute_12", "13": "(unnamed)", "99": "attribute_99"} {
		if got := m.Label(id); got != want {
			t.Errorf("Label(%s) = %q, want %q", id, got, want)
		}
	}
	if len(asked) != 2 {
		t.Errorf("rows asked for: %v", asked)
	}
	if len(res.SideEffects) != 0 {
		t.Errorf("side effects: %+v", res.SideEffects)
	}
}

// SettingsKeys are the keys the presets ask for from a dump's settings
// tables: every key a detection asks for offline, on single sites, a
// multisite and a WooCommerce store, is in the list, and every key in the
// list is asked for. A key the code asks for and the list leaves out would
// have no answer from a dump.
func TestOfflineKeys(t *testing.T) {
	asked := map[string]bool{}
	src := Offline{
		Options: func(table, keyCol, valueCol string, keys []string) map[string]string {
			if !strings.HasSuffix(table, "options") || keyCol != "option_name" || valueCol != "option_value" {
				t.Errorf("settings read from %s(%s, %s)", table, keyCol, valueCol)
			}
			for _, k := range keys {
				asked[k] = true
			}
			return map[string]string{"db_version": "57155", "woocommerce_version": "8.5.1", "woocommerce_custom_orders_table_enabled": "yes"}
		},
		Rows: func(string, []string) [][]string { return nil },
	}
	single, multi := map[string][]string{}, map[string][]string{}
	wpTables("wp_", single)
	single["wp_users"] = []string{"ID", "user_email", "user_pass"}
	single["wp_wc_orders"] = []string{"id", "billing_email"}
	single["wp_woocommerce_order_items"] = []string{"order_item_id", "order_id"}
	wpTables("wp_", multi)
	wpTables("wp_2_", multi)
	multi["wp_blogs"] = []string{"blog_id", "domain"}
	for _, s := range []map[string][]string{single, multi} {
		DetectOffline(schemaOf(s), "auto", src)
	}
	var got []string
	for k := range asked {
		got = append(got, k)
	}
	sort.Strings(got)
	want := append([]string(nil), SettingsKeys()...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("keys asked for %v, SettingsKeys %v", got, want)
	}
	w := WholeTables()
	if len(w) != 2 || len(w["eav_attribute"]) != 3 || len(w["eav_entity_type"]) != 2 {
		t.Errorf("WholeTables = %v", w)
	}
}
