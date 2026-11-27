package preset_test

import (
	"context"
	"database/sql"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/introspect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// dumpSource answers DetectOffline from the database, the way a dump reader
// would answer it from the rows it kept: the SettingsKeys rows of the
// *options tables, and the WholeTables rows.
func dumpSource(ctx context.Context, t *testing.T, db *sql.DB) preset.Offline {
	t.Helper()
	query := func(q string, args ...any) [][]string {
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		var out [][]string
		for rows.Next() {
			raw := make([]sql.RawBytes, len(cols))
			dest := make([]any, len(cols))
			for i := range raw {
				dest[i] = &raw[i]
			}
			if err := rows.Scan(dest...); err != nil {
				t.Fatal(err)
			}
			row := make([]string, len(cols))
			for i, b := range raw {
				row[i] = string(b)
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	kept := map[string]bool{}
	for _, k := range preset.SettingsKeys() {
		kept[k] = true
	}
	return preset.Offline{
		Options: func(table, keyCol, valueCol string, keys []string) map[string]string {
			out := map[string]string{}
			if !strings.HasSuffix(table, "options") || keyCol != "option_name" || valueCol != "option_value" {
				t.Errorf("settings read from %s(%s, %s), which the dump does not keep", table, keyCol, valueCol)
				return out
			}
			for _, k := range keys {
				if !kept[k] {
					t.Errorf("settings key %q is not in SettingsKeys", k)
				}
			}
			for _, r := range query("SELECT option_name, LEFT(option_value, 65535) FROM " + sample.QuoteIdent(table) +
				" WHERE option_name IN ('db_version', 'woocommerce_version', 'woocommerce_custom_orders_table_enabled')") {
				if _, ok := out[r[0]]; !ok {
					out[r[0]] = r[1]
				}
			}
			return out
		},
		Rows: func(table string, columns []string) [][]string {
			base := table
			for name := range preset.WholeTables() {
				if strings.HasSuffix(table, name) {
					base = name
				}
			}
			want, ok := preset.WholeTables()[base]
			if !ok {
				t.Errorf("rows read from %s, which the dump does not keep whole", table)
				return nil
			}
			for _, c := range columns {
				found := false
				for _, w := range want {
					found = found || w == c
				}
				if !found {
					t.Errorf("column %s of %s is not in WholeTables", c, table)
				}
			}
			quoted := make([]string, len(columns))
			for i, c := range columns {
				quoted[i] = sample.QuoteIdent(c)
			}
			return query("SELECT " + strings.Join(quoted, ", ") + " FROM " + sample.QuoteIdent(table))
		},
	}
}

// readBased drops the platform details that only a server can give.
func readBased(ps []model.Platform) []model.Platform {
	out := make([]model.Platform, len(ps))
	for i, p := range ps {
		p.Details = nil
		for _, d := range ps[i].Details {
			if strings.HasPrefix(d, "db_version ") || strings.HasSuffix(d, " store views") || strings.HasSuffix(d, " migrations") {
				continue
			}
			p.Details = append(p.Details, d)
		}
		out[i] = p
	}
	return out
}

func TestDetectOfflineAgreesWithDetect(t *testing.T) {
	dsn := testdb.DSN(t)
	adminCfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminCfg.MultiStatements = true
	adminCfg.DBName = ""
	connector, err := mysql.NewConnector(adminCfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	t.Cleanup(func() { admin.Close() })
	ctx := context.Background()

	for _, platform := range fixture.Platforms {
		t.Run(platform, func(t *testing.T) {
			database := "prodmask_s5_" + platform
			t.Cleanup(func() {
				admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS `"+database+"`")
			})
			if err := fixture.Build(ctx, admin, platform, database, fixture.Options{}); err != nil {
				t.Fatal(err)
			}
			cfg := adminCfg.Clone()
			cfg.MultiStatements = false
			cfg.DBName = database
			sess, err := dbconn.Open(ctx, cfg, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { sess.Close() })
			schema, err := introspect.Load(ctx, sess.DB, sess.Database)
			if err != nil {
				t.Fatal(err)
			}

			live := preset.Detect(ctx, sess.DB, schema, "auto", 10*time.Second)
			off := preset.DetectOffline(schema, "auto", dumpSource(ctx, t, sess.DB))

			if len(off.SideEffects) != 0 {
				t.Errorf("offline side effects: %+v", off.SideEffects)
			}
			if platform != "generic" && len(live.Platforms) == 0 {
				t.Fatalf("no platform found on the %s fixture", platform)
			}
			if got, want := readBased(off.Platforms), readBased(live.Platforms); !reflect.DeepEqual(got, want) {
				t.Errorf("platforms differ:\n offline %+v\n live    %+v", got, want)
			}
			if !reflect.DeepEqual(off.Columns, live.Columns) {
				t.Errorf("columns differ:\n offline %+v\n live    %+v", off.Columns, live.Columns)
			}
			if !reflect.DeepEqual(off.Actions, live.Actions) {
				t.Errorf("actions differ")
			}
			if !reflect.DeepEqual(off.Relationships, live.Relationships) {
				t.Errorf("relationships differ")
			}
			if !reflect.DeepEqual(off.RowSubjects, live.RowSubjects) {
				t.Errorf("row subjects differ")
			}
			if !reflect.DeepEqual(off.Prefixes, live.Prefixes) {
				t.Errorf("prefixes differ: %v and %v", off.Prefixes, live.Prefixes)
			}

			if len(off.Meta) != len(live.Meta) {
				t.Errorf("meta tables differ: %d and %d", len(off.Meta), len(live.Meta))
			}
			for table, lm := range live.Meta {
				om := off.Meta[table]
				if om == nil {
					t.Errorf("meta table %s missing offline", table)
					continue
				}
				if om.Key != lm.Key || om.Value != lm.Value || om.Platform != lm.Platform ||
					om.Settings != lm.Settings || om.Primary != lm.Primary || om.Labels != lm.Labels || om.Guard != lm.Guard {
					t.Errorf("meta table %s differs: %+v and %+v", table, om, lm)
				}
				if !reflect.DeepEqual(om.Keys, lm.Keys) {
					t.Errorf("meta table %s: keys differ", table)
				}
				// The side-effect checks append the options they look at to the probe,
				// and offline they don't run: the offline probe is the live one up to them.
				if len(om.Probe) > len(lm.Probe) || !reflect.DeepEqual(om.Probe, lm.Probe[:len(om.Probe)]) {
					t.Errorf("meta table %s: probe differs: %v offline, %v live", table, om.Probe, lm.Probe)
				}
				if (om.Label == nil) != (lm.Label == nil) {
					t.Errorf("meta table %s: label func differs", table)
				} else if lm.Label != nil {
					for id := 0; id < 300; id++ {
						k := strconv.Itoa(id)
						if om.Label(k) != lm.Label(k) {
							t.Errorf("meta table %s: Label(%s) = %q offline, %q live", table, k, om.Label(k), lm.Label(k))
						}
					}
				}
			}
			if platform == "magento2" {
				m := off.Meta["customer_entity_varchar"]
				if m == nil || m.Label("180") != "mobile_phone" {
					t.Errorf("magento labels did not come from the dump rows: %v", m)
				}
			}
			if platform == "wordpress" {
				found := false
				for _, p := range off.Platforms {
					for _, d := range p.Details {
						found = found || d == "orders in HPOS tables"
					}
				}
				if !found {
					t.Errorf("no HPOS detail offline: %+v", off.Platforms)
				}
			}
		})
	}
}
