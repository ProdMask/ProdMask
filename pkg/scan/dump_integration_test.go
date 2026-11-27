package scan_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/introspect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// These tests write a dump from a database on a real server, the way the
// server writes the literals (SHOW CREATE TABLE and QUOTE), scan the dump,
// and compare it with the scan of the database. Their databases start with
// prodmask_s6_ and are dropped afterwards.

func quoteName(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// literalExpr is the expression that makes the server write a column's
// literal: QUOTE for text and numbers, an X'..' literal for bytes.
func literalExpr(col, dataType string) string {
	c := quoteName(col)
	switch strings.ToLower(dataType) {
	case "binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "uuid", "inet6", "inet4":
		return "IFNULL(CONCAT('X''',HEX(" + c + "),''''),'NULL')"
	}
	return "QUOTE(" + c + ")"
}

// serverDump writes the database as a dump: each table's SHOW CREATE
// statement, then its rows as INSERTs, in primary-key order, or in the order
// a plain SELECT returns without one. Its header names the database, as
// mysqldump's does for a dump of one, with no USE: the report takes the name
// from the file, never from --database.
func serverDump(ctx context.Context, t *testing.T, admin *sql.DB, db string) string {
	t.Helper()
	var version string
	if err := admin.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "-- Host: localhost    Database: %s\n-- Server version\t%s\n\nSET sql_mode='NO_AUTO_VALUE_ON_ZERO';\nSET NAMES utf8mb4;\n\n", db, version)
	rows, err := admin.QueryContext(ctx, "SELECT TABLE_NAME, TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME", db)
	if err != nil {
		t.Fatal(err)
	}
	type tbl struct{ name, kind string }
	var tables []tbl
	for rows.Next() {
		var x tbl
		if err := rows.Scan(&x.name, &x.kind); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, x)
	}
	rows.Close()
	for _, x := range tables {
		qt := quoteName(db) + "." + quoteName(x.name)
		show := "SHOW CREATE TABLE "
		switch x.kind {
		case "VIEW":
			show = "SHOW CREATE VIEW "
		case "SEQUENCE":
			show = "SHOW CREATE SEQUENCE "
		}
		cols, err := admin.QueryContext(ctx, show+qt)
		if err != nil {
			t.Fatalf("%s%s: %v", show, x.name, err)
		}
		names, _ := cols.Columns()
		raw := make([]sql.RawBytes, len(names))
		dest := make([]any, len(names))
		for i := range raw {
			dest[i] = &raw[i]
		}
		if !cols.Next() {
			t.Fatalf("%s%s: no row", show, x.name)
		}
		if err := cols.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s;\n", raw[1])
		cols.Close()
		if x.kind == "VIEW" || x.kind == "SEQUENCE" {
			continue
		}
		writeInserts(ctx, t, admin, db, x.name, &b)
	}
	return b.String()
}

func writeInserts(ctx context.Context, t *testing.T, admin *sql.DB, db, table string, b *strings.Builder) {
	t.Helper()
	crows, err := admin.QueryContext(ctx, "SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION", db, table)
	if err != nil {
		t.Fatal(err)
	}
	var cols, exprs []string
	for crows.Next() {
		var c, dt string
		if err := crows.Scan(&c, &dt); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, quoteName(c))
		exprs = append(exprs, literalExpr(c, dt))
	}
	crows.Close()
	prows, err := admin.QueryContext(ctx, "SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND INDEX_NAME = 'PRIMARY' ORDER BY SEQ_IN_INDEX", db, table)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for prows.Next() {
		var c string
		if err := prows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		order = append(order, quoteName(c))
	}
	prows.Close()
	q := "SELECT " + strings.Join(exprs, ", ") + " FROM " + quoteName(db) + "." + quoteName(table)
	if len(order) > 0 {
		q += " ORDER BY " + strings.Join(order, ", ")
	}
	drows, err := admin.QueryContext(ctx, q)
	if err != nil {
		t.Fatalf("%s: %v", table, err)
	}
	defer drows.Close()
	raw := make([]sql.RawBytes, len(cols))
	dest := make([]any, len(cols))
	for i := range raw {
		dest[i] = &raw[i]
	}
	var batch []string
	flush := func() {
		if len(batch) > 0 {
			fmt.Fprintf(b, "INSERT INTO %s (%s) VALUES %s;\n", quoteName(table), strings.Join(cols, ","), strings.Join(batch, ","))
			batch = batch[:0]
		}
	}
	for drows.Next() {
		if err := drows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		parts := make([]string, len(raw))
		for i, r := range raw {
			parts[i] = string(r)
		}
		batch = append(batch, "("+strings.Join(parts, ",")+")")
		if len(batch) == 100 {
			flush()
		}
	}
	flush()
	if err := drows.Err(); err != nil {
		t.Fatal(err)
	}
}

func openString(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
}

// dumpScan scans a dump with the options the live scan runs at by default.
func dumpScan(ctx context.Context, t *testing.T, text, database string, tune func(*scan.DumpOptions)) *model.Result {
	t.Helper()
	opts := scan.DumpOptions{Options: scan.Options{SampleRows: scan.DefaultSampleRows, MetaSampleRows: scan.DefaultMetaSampleRows,
		Samples: true, Preset: "auto", Version: "test"}, Database: database, File: "test.sql"}
	if tune != nil {
		tune(&opts)
	}
	res, err := scan.RunDump(ctx, openString(text), opts)
	if err != nil {
		t.Fatalf("the dump scan: %v", err)
	}
	return res
}

// --- fixtures ---

type dumpFixture struct {
	name    string
	build   func(ctx context.Context, t *testing.T, admin *sql.DB, db string) *fixture.Planted
	checkFn func(t *testing.T, res *model.Result)
}

func execAll(ctx context.Context, t *testing.T, admin *sql.DB, stmts []string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := admin.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func recreate(db string) []string {
	return []string{"DROP DATABASE IF EXISTS `" + db + "`", "CREATE DATABASE `" + db + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"}
}

func platformFixture(platform string) dumpFixture {
	return dumpFixture{name: platform, build: func(ctx context.Context, t *testing.T, admin *sql.DB, db string) *fixture.Planted {
		var planted fixture.Planted
		if err := fixture.Build(ctx, admin, platform, db, fixture.Options{Canary: canary, Planted: &planted}); err != nil {
			t.Fatalf("build fixture: %v", err)
		}
		return &planted
	}}
}

func multisiteFixture() dumpFixture {
	return dumpFixture{name: "multisite", build: func(ctx context.Context, t *testing.T, admin *sql.DB, db string) *fixture.Planted {
		stmts := append(recreate(db),
			"CREATE TABLE "+db+".wp_users (ID bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, user_login varchar(60) NOT NULL DEFAULT '')")
		for _, p := range []string{"wp_", "wp_2_"} {
			stmts = append(stmts,
				"CREATE TABLE "+db+"."+p+"options (option_id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, "+
					"option_name varchar(191) NOT NULL DEFAULT '', option_value longtext NOT NULL, UNIQUE KEY option_name (option_name))",
				"CREATE TABLE "+db+"."+p+"posts (ID bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, "+
					"post_type varchar(20) NOT NULL DEFAULT 'post', post_password varchar(255) NOT NULL DEFAULT '')",
				"CREATE TABLE "+db+"."+p+"postmeta (meta_id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, "+
					"post_id bigint unsigned NOT NULL DEFAULT 0, meta_key varchar(255) DEFAULT NULL, meta_value longtext)",
				"INSERT INTO "+db+"."+p+"options (option_name, option_value) VALUES ('db_version', '60421'), "+
					"('fixture_admin_recipient', 'manager@fixture-store.gr')",
				"INSERT INTO "+db+"."+p+"posts (post_type, post_password) VALUES ('page', 'members only')",
			)
		}
		stmts = append(stmts,
			"INSERT INTO "+db+".wp_2_options (option_name, option_value) VALUES ('woocommerce_version', '9.3.3'), "+
				"('fixture_b_recipient', 'staff@fixture-store.gr'), ('fixture_a_recipient', 'owner@fixture-store.gr')",
			"INSERT INTO "+db+".wp_2_posts (post_type, post_password) VALUES ('shop_order', 'wc_order_"+strings.Repeat("x", 13)+"')",
		)
		execAll(ctx, t, admin, stmts)
		return nil
	}}
}

func fitsFixture() dumpFixture {
	return dumpFixture{name: "fits", build: func(ctx context.Context, t *testing.T, admin *sql.DB, db string) *fixture.Planted {
		q := "`" + db + "`."
		const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.%d"
		var uas []string
		for i := range 6 {
			uas = append(uas, "('"+fmt.Sprintf(ua, i)+"')")
		}
		execAll(ctx, t, admin, append(recreate(db),
			"CREATE TABLE "+q+"fraud_rules (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, rule_email char(1) NULL, rule_amount char(1) NULL) ENGINE=InnoDB",
			"CREATE TABLE "+q+"brokers (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, user_agent varchar(255) NOT NULL, UNIQUE KEY user_agent (user_agent)) ENGINE=InnoDB",
			"INSERT INTO "+q+"brokers (user_agent) VALUES "+strings.Join(uas, ", "),
			"CREATE TABLE "+q+"towns (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, city varchar(50) NOT NULL, UNIQUE KEY city (city)) ENGINE=InnoDB",
			"INSERT INTO "+q+"towns (city) VALUES ('Springfield'), ('Riverton'), ('Lakeside'), ('Fairview'), ('Oakdale')",
			"CREATE TABLE "+q+"branches (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, city char(2) NOT NULL, UNIQUE KEY city (city)) ENGINE=InnoDB",
			"INSERT INTO "+q+"branches (city) VALUES ('SP'), ('RV'), ('LK')",
			"CREATE TABLE "+q+"partners (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, api_key char(2) NOT NULL, UNIQUE KEY api_key (api_key)) ENGINE=InnoDB",
			"INSERT INTO "+q+"partners (api_key) VALUES ('k1'), ('k2')",
			"CREATE TABLE "+q+"contacts (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, email varchar(255) NOT NULL, UNIQUE KEY email (email(10))) ENGINE=InnoDB",
			"INSERT INTO "+q+"contacts (email) VALUES ('ann@shop.example'), ('bob@shop.example'), ('cy@shop.example')",
		))
		return nil
	}}
}

// shapesDDL is the dump-shapes fixture of pkg/sqldump's tests, copied: the
// objects a dump of a real database holds that the other fixtures don't.
func shapesDDL(mariadb bool) []string {
	s := []string{
		"CREATE TABLE shape_latin1 (id int NOT NULL AUTO_INCREMENT, " +
			"name varchar(40) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL DEFAULT '', " +
			"note text CHARACTER SET latin1, tag char(3) COLLATE utf8mb4_bin DEFAULT NULL, " +
			"PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='a latin1 column'",
		"CREATE TABLE shape_latin1_table (id int NOT NULL, name varchar(40) NOT NULL, " +
			"kind enum('a','bb','ccc') NOT NULL DEFAULT 'a', flags set('x','yy') DEFAULT NULL, PRIMARY KEY (id)) " +
			"ENGINE=InnoDB DEFAULT CHARSET=latin1",
		"CREATE TABLE shape_generated (id int NOT NULL, a int NOT NULL, b int GENERATED ALWAYS AS (a + 1) VIRTUAL, " +
			"c int GENERATED ALWAYS AS (a * 2) STORED, d varchar(30) GENERATED ALWAYS AS (concat('x', a)) VIRTUAL, " +
			"PRIMARY KEY (id), KEY c (c))",
		"CREATE TABLE shape_invisible (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, " +
			"secret varchar(30) INVISIBLE, plain int NOT NULL DEFAULT 7)",
		"CREATE TABLE shape_partitioned (id int NOT NULL, created date NOT NULL, note varchar(20) DEFAULT NULL, " +
			"PRIMARY KEY (id, created)) PARTITION BY RANGE (YEAR(created)) " +
			"(PARTITION p0 VALUES LESS THAN (2020), PARTITION p1 VALUES LESS THAN MAXVALUE)",
		"CREATE TABLE shape_prefix (id int NOT NULL, email varchar(255) DEFAULT NULL, body text, " +
			"KEY email_prefix (email(20)), KEY body_prefix (body(30)), UNIQUE KEY u (email(10)), " +
			"KEY whole (email(255)))",
		"CREATE TABLE shape_nopk (a int DEFAULT NULL, b varchar(10) DEFAULT NULL, c varchar(10) DEFAULT NULL, KEY (a))",
		"CREATE TABLE shape_keys (a int NOT NULL, b int NOT NULL, c int DEFAULT NULL, d int NOT NULL, e int DEFAULT NULL, " +
			"PRIMARY KEY (a, b), UNIQUE KEY uk_d (d), UNIQUE KEY uk_cd (c, d), KEY k_c (c), KEY k_ec (e, c), UNIQUE KEY uk_e (e))",
		"CREATE TABLE shape_promoted (a int NOT NULL, b int DEFAULT NULL, c int NOT NULL, UNIQUE KEY uk_a (a), KEY k_b (b), " +
			"UNIQUE KEY uk_c (c))",
		"CREATE TABLE shape_promoted_composite (a int NOT NULL, b int NOT NULL, UNIQUE KEY uk_ab (a, b))",
		"CREATE TABLE shape_unique_null (a int DEFAULT NULL, b int DEFAULT NULL, UNIQUE KEY uk_a (a), UNIQUE KEY uk_ab (a, b))",
		"CREATE TABLE shape_fk_parent (id int NOT NULL, code varchar(10) NOT NULL, PRIMARY KEY (id), UNIQUE KEY code (code))",
		"CREATE TABLE shape_fk_child (id int NOT NULL, parent_id int DEFAULT NULL, parent_code varchar(10) DEFAULT NULL, " +
			"PRIMARY KEY (id), KEY fk_parent (parent_id), KEY fk_code (parent_code), " +
			"CONSTRAINT fk_child_parent FOREIGN KEY (parent_id) REFERENCES shape_fk_parent (id) ON DELETE CASCADE, " +
			"CONSTRAINT fk_child_code FOREIGN KEY (parent_code) REFERENCES shape_fk_parent (code) ON UPDATE CASCADE)",
		"CREATE TABLE shape_fulltext (id int NOT NULL, title varchar(100) DEFAULT NULL, body text, PRIMARY KEY (id), " +
			"FULLTEXT KEY ft (title, body)) ENGINE=InnoDB",
		"CREATE TABLE shape_spatial (id int NOT NULL, g geometry NOT NULL, PRIMARY KEY (id), SPATIAL KEY sp (g)) ENGINE=InnoDB",
		"CREATE TABLE shape_types (id bigint unsigned NOT NULL AUTO_INCREMENT, flag tinyint(1) NOT NULL DEFAULT 0, " +
			"price decimal(10,2) NOT NULL DEFAULT 0.00, ratio float DEFAULT NULL, big double DEFAULT NULL, bits bit(3) DEFAULT NULL, " +
			"born date DEFAULT NULL, seen datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), " +
			"touched timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, " +
			"touched6 timestamp(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6), yr year DEFAULT NULL, at time(2) DEFAULT NULL, " +
			"doc json DEFAULT NULL, blob_a blob, blob_l longblob, text_m mediumtext, text_t tinytext, text_l longtext, " +
			"bin binary(16) DEFAULT NULL, vbin varbinary(20) DEFAULT NULL, one char(1) NOT NULL DEFAULT 'x', " +
			"kind enum('red','green','blue') NOT NULL DEFAULT 'green', picks set('a','bb','ccc') DEFAULT NULL, " +
			"quote varchar(10) NOT NULL DEFAULT 'it''s', num int NOT NULL DEFAULT -5, nul int DEFAULT NULL, " +
			"cmt int DEFAULT NULL COMMENT 'with ''quotes''', PRIMARY KEY (id)) ENGINE=InnoDB COMMENT='table comment'",
		"CREATE TABLE shape_charsets (a varchar(10) COLLATE utf8mb4_bin, b varchar(10) BINARY, c varchar(10) CHARACTER SET ascii, " +
			"d text COLLATE latin1_bin, e char(2) CHARACTER SET utf8mb3) DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
		"CREATE TABLE shape_collate_only (a varchar(10), b varchar(10) CHARACTER SET latin1) COLLATE=latin1_general_ci",
		"CREATE TABLE shape_memory (a int NOT NULL, b varchar(10) DEFAULT NULL, KEY k_a (a), KEY k_b (b) USING BTREE) ENGINE=MEMORY",
		"CREATE TABLE shape_myisam (a int NOT NULL, b varchar(10) DEFAULT NULL, KEY k_a (a)) ENGINE=MyISAM",
		"CREATE VIEW shape_view AS SELECT id, name FROM shape_latin1",
		"CREATE PROCEDURE shape_proc() SELECT 1",
		"CREATE EVENT shape_event ON SCHEDULE EVERY 1 DAY DO SELECT 1",
	}
	if mariadb {
		s = append(s,
			"CREATE SEQUENCE shape_seq START WITH 100 INCREMENT BY 5",
			"CREATE TABLE shape_sysver (id int NOT NULL, v varchar(10) DEFAULT NULL, PRIMARY KEY (id)) ENGINE=InnoDB WITH SYSTEM VERSIONING",
			"CREATE TABLE shape_uuid (id int NOT NULL, u uuid DEFAULT uuid(), j longtext DEFAULT NULL CHECK (json_valid(j)), "+
				"d date DEFAULT curdate(), PRIMARY KEY (id))",
		)
	} else {
		s = append(s,
			"CREATE TABLE shape_functional (id int NOT NULL, email varchar(100) DEFAULT NULL, PRIMARY KEY (id), "+
				"KEY lower_email ((lower(email))), KEY mixed (id, (concat(email, 'x'))), KEY prefix_fn (email(10), (id + 1)))",
			"CREATE TABLE shape_expr (id int NOT NULL, u varchar(36) DEFAULT (uuid()), n int DEFAULT (1 + 2), "+
				"d date DEFAULT (curdate()), PRIMARY KEY (id), CONSTRAINT chk_n CHECK ((n > 0)))",
		)
	}
	return s
}

func shapesFixture() dumpFixture {
	return dumpFixture{name: "shapes", build: func(ctx context.Context, t *testing.T, admin *sql.DB, db string) *fixture.Planted {
		var version string
		if err := admin.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
			t.Fatal(err)
		}
		execAll(ctx, t, admin, recreate(db))
		conn, err := admin.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.ExecContext(ctx, "USE `"+db+"`"); err != nil {
			t.Fatal(err)
		}
		for _, s := range shapesDDL(strings.Contains(strings.ToLower(version), "mariadb")) {
			if _, err := conn.ExecContext(ctx, s); err != nil {
				t.Fatalf("%s: %v", s, err)
			}
		}
		for _, s := range []string{
			"INSERT INTO shape_latin1 (name, note, tag) VALUES ('Jos\u00e9', 'a note', 'ab'), ('Ann', NULL, NULL), ('it''s', 'back\\\\slash', 'x')",
			"INSERT INTO shape_nopk (a, b, c) VALUES (3, 'c', 'z'), (1, 'a', 'y'), (2, 'b', 'x'), (NULL, NULL, NULL)",
			"INSERT INTO shape_keys (a, b, c, d, e) VALUES (2, 1, 5, 10, 1), (1, 2, 6, 11, 2), (1, 1, 7, 12, 3)",
			"INSERT INTO shape_types (flag, price, ratio, big, born, doc, blob_a, text_m, bin, one, kind, picks, num) VALUES " +
				"(1, 12.50, 1.5, 2.25, '2020-02-03', '{\"a\": 1}', 'raw', 'medium', 'abcdefghijklmnop', 'y', 'red', 'a,bb', 3), " +
				"(0, 0.00, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'x', 'green', NULL, -5)",
			"INSERT INTO shape_fk_parent (id, code) VALUES (1, 'a'), (2, 'b')",
			"INSERT INTO shape_fk_child (id, parent_id, parent_code) VALUES (1, 1, 'a'), (2, 2, 'b')",
			"INSERT INTO shape_charsets (a, b, c, d, e) VALUES ('x', 'y', 'z', 'w', 'v')",
			"INSERT INTO shape_memory (a, b) VALUES (2, 'm'), (1, 'n')",
			"INSERT INTO shape_myisam (a, b) VALUES (2, 'm'), (1, 'n')",
		} {
			if _, err := conn.ExecContext(ctx, s); err != nil {
				t.Fatalf("%s: %v", s, err)
			}
		}
		return nil
	}}
}

func TestDumpEquivalence(t *testing.T) {
	admin, adminCfg := testServer(t)
	fixtures := []dumpFixture{platformFixture("wordpress"), platformFixture("magento2"), platformFixture("laravel"),
		platformFixture("generic"), multisiteFixture(), fitsFixture(), shapesFixture()}
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			db := "prodmask_s6_" + fx.name
			planted := fx.build(ctx, t, admin, db)
			t.Cleanup(func() { admin.Exec("DROP DATABASE IF EXISTS `" + db + "`") })

			liveModes := map[string]int{}
			restore := scan.SetKVModeHook(func(table string, mode int) { liveModes[table] = mode })
			live := runScan(ctx, t, openScan(ctx, t, adminCfg, db), "auto")
			restore()

			text := serverDump(ctx, t, admin, db)
			dumpModes := map[string]int{}
			dump := dumpScan(ctx, t, text, db, func(o *scan.DumpOptions) {
				scan.DumpTap(o, func(table string, _ map[int]*sample.Sample, mode int) { dumpModes[table] = mode })
			})
			compareScans(ctx, t, admin, db, live, dump, liveModes, dumpModes)

			if dump.Dump == nil || dump.Dump.Unread != 0 {
				t.Errorf("dump info: %+v", dump.Dump)
			}
			// The canary and planted-secret checks of TestFixtures, on the
			// dump scan's outputs.
			outputs := render(t, dump)
			for name, out := range outputs {
				if strings.Contains(out, canary) {
					t.Errorf("the %s output of the dump scan contains a sampled value", name)
				}
			}
			if planted != nil {
				checkPlanted(t, fx.name, planted, outputs)
			}
			if fx.name == "generic" {
				checkGenericSecrets(t, dump)
			}
			checkConfigTables(t, outputs["yml"])
		})
	}
}

// compareScans asserts that the scan of a dump equals the scan of its
// database, but for the differences each assertion below names.
func compareScans(ctx context.Context, t *testing.T, admin *sql.DB, db string, live, dump *model.Result, liveModes, dumpModes map[string]int) {
	t.Helper()

	// Allowed: the server line (the dump's has no address or user).
	if live.Server.Flavor != dump.Server.Flavor || live.Server.Version != dump.Server.Version {
		t.Errorf("server: live %+v, dump %+v", live.Server, dump.Server)
	}
	if dump.Server.Address != "" || dump.Server.User != "" {
		t.Errorf("the dump's server line has an address or a user: %+v", dump.Server)
	}
	if dump.Database != db {
		t.Errorf("database %q", dump.Database)
	}

	// Allowed: side effects (none on a dump).
	if len(dump.SideEffects) != 0 {
		t.Errorf("side effects on a dump: %+v", dump.SideEffects)
	}

	// Allowed: platform details that only reads give; the rest is equal.
	if len(live.Platforms) != len(dump.Platforms) {
		t.Fatalf("platforms: live %+v, dump %+v", live.Platforms, dump.Platforms)
	}
	for i, lp := range live.Platforms {
		dp := dump.Platforms[i]
		if lp.Name != dp.Name || lp.Label != dp.Label || lp.Version != dp.Version || lp.Prefix != dp.Prefix {
			t.Errorf("platform: live %+v, dump %+v", lp, dp)
		}
		if lp.Name == "wordpress" || lp.Name == "woocommerce" {
			if !reflect.DeepEqual(lp.Details, dp.Details) {
				t.Errorf("%s details: live %q, dump %q", lp.Name, lp.Details, dp.Details)
			}
		} else {
			for _, d := range dp.Details {
				if !slices.Contains(lp.Details, d) {
					t.Errorf("%s: the dump has the detail %q, the database doesn't", lp.Name, d)
				}
			}
		}
	}

	// Outside the key/value envelope (either side's read isn't a whole read),
	// the counts, Keys, RowsSampled and warnings may differ.
	outside := map[string]bool{}
	valueCols := map[string]string{}
	for _, res := range []*model.Result{live, dump} {
		for _, ts := range res.Tables {
			if ts.ValueColumn != "" {
				valueCols[ts.Name] = ts.ValueColumn
			}
		}
	}
	for table, m := range liveModes {
		if m != 1 || dumpModes[table] != 1 {
			outside[table] = true
		}
	}
	for table, m := range dumpModes {
		if m != 0 && m != 1 {
			outside[table] = true
		}
	}

	// Tables: everything but the estimate, which a dump knows exactly.
	if len(live.Tables) != len(dump.Tables) {
		t.Fatalf("tables: live %d, dump %d", len(live.Tables), len(dump.Tables))
	}
	for i, lt := range live.Tables {
		dt := dump.Tables[i]
		if lt.Name != dt.Name {
			t.Fatalf("table %d: live %s, dump %s", i, lt.Name, dt.Name)
		}
		if lt.Kind != "view" && lt.Kind != "sequence" {
			var n int64
			if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteName(db)+"."+quoteName(lt.Name)).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if dt.RowsEstimate != n {
				t.Errorf("%s: rows_estimate %d, the table has %d", lt.Name, dt.RowsEstimate, n)
			}
		}
		lt.RowsEstimate, dt.RowsEstimate = 0, 0
		if outside[lt.Name] {
			for _, ts := range []*model.TableSummary{&lt, &dt} {
				ts.Keys, ts.RowsSampled, ts.Findings, ts.Highest, ts.HiddenKeys, ts.ReadFailed = 0, 0, 0, model.SeverityNone, 0, false
			}
		}
		if !reflect.DeepEqual(lt, dt) {
			t.Errorf("table %s:\n live %+v\n dump %+v", lt.Name, lt, dt)
		}
	}

	// Findings. A finding on an outside table's keys or values may differ in
	// its counts; the dump's must hold the live ones by (table, column, key,
	// path, category). A row subject's finding with more than 50 matching
	// rows may be read from other rows.
	relaxed := func(f model.Finding) bool {
		return outside[f.Table] && (f.MetaKey != "" || f.KeyName || valueCols[f.Table] == f.Column)
	}
	overSubjects := map[string]bool{}
	for _, f := range dump.Findings {
		if f.Where == "" {
			continue
		}
		var n int
		if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteName(db)+"."+quoteName(f.Table)+" WHERE "+f.Where).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 50 {
			overSubjects[f.Table+"."+f.Column] = true
		}
	}
	relaxedSubject := func(f model.Finding) bool { return f.Where != "" && overSubjects[f.Table+"."+f.Column] }
	// Allowed: the device-ID note, and what it keeps: a device ID on a column
	// a platform link joins is weakened on a database whose link was checked.
	joined := map[string]bool{}
	for _, r := range dump.Relationships {
		if strings.HasPrefix(r.Source, "preset:") && len(r.ChildColumns) == 1 {
			joined[r.ChildTable+"."+r.ChildColumns[0]] = true
		}
	}
	deviceNote := func(f model.Finding) bool {
		return f.Category == model.CatDeviceID && joined[f.Table+"."+f.Column]
	}
	type place struct{ table, column, key, path, category string }
	at := func(f model.Finding) place { return place{f.Table, f.Column, f.MetaKey, f.Path, string(f.Category)} }
	var liveStrict, dumpStrict []model.Finding
	dumpPlaces := map[place]bool{}
	for _, f := range dump.Findings {
		dumpPlaces[at(f)] = true
		if !relaxed(f) && !relaxedSubject(f) && !deviceNote(f) {
			dumpStrict = append(dumpStrict, f)
		}
	}
	for _, f := range live.Findings {
		switch {
		case relaxed(f) || relaxedSubject(f):
			if f.Confidence > model.ConfidenceLow && !dumpPlaces[at(f)] {
				t.Errorf("the dump scan lacks the finding %+v", at(f))
			}
		case deviceNote(f):
			if !dumpPlaces[at(f)] {
				t.Errorf("the dump scan lacks the device ID finding %+v", at(f))
			}
		default:
			liveStrict = append(liveStrict, f)
		}
	}
	t.Logf("%d findings compared strictly, %d held by place; outside the envelope: %v", len(liveStrict), len(live.Findings)-len(liveStrict), sortedKeys(outside))
	if len(liveStrict) != len(dumpStrict) {
		t.Errorf("findings: live %d, dump %d", len(liveStrict), len(dumpStrict))
		diffFindings(t, liveStrict, dumpStrict)
	} else {
		for i := range liveStrict {
			if !reflect.DeepEqual(liveStrict[i], dumpStrict[i]) {
				t.Errorf("finding %d:\n live %+v\n dump %+v", i, liveStrict[i], dumpStrict[i])
			}
		}
	}
	for _, f := range dump.Findings {
		if deviceNote(f) && f.Confidence != model.ConfidenceLow && !strings.Contains(f.Note, "a scan of the database could find it to be a reference") {
			t.Errorf("a device ID on a column a platform link joins has no note: %+v", f)
		}
	}

	// Allowed: relationships. The dump has the declared keys and the platform
	// links, the latter unverified; each is one the database scan has too.
	liveRels := map[string]model.Relationship{}
	for _, r := range live.Relationships {
		liveRels[r.Key()] = r
	}
	for _, r := range dump.Relationships {
		lr, ok := liveRels[r.Key()]
		switch {
		case !ok:
			t.Errorf("the dump has a relationship the database scan lacks: %+v", r)
		case r.Source == "declared" && !reflect.DeepEqual(r, lr):
			t.Errorf("declared relationship: live %+v, dump %+v", lr, r)
		case r.Source != "declared" && (r.Status != model.RelUnverified || r.Note != "not checked in a dump file"):
			t.Errorf("a platform link is %s with the note %q", r.Status, r.Note)
		}
	}
	for _, r := range live.Relationships {
		if r.Source == "declared" {
			found := false
			for _, d := range dump.Relationships {
				found = found || d.Key() == r.Key()
			}
			if !found {
				t.Errorf("the dump lacks the declared key %+v", r)
			}
		}
	}

	// Warnings, in order, but for the scan user's own and those of the
	// outside tables.
	skip := func(w string) bool {
		if strings.Contains(w, "scan user can change") {
			return true
		}
		for table := range outside {
			if strings.Contains(w, " "+table+" ") || strings.Contains(w, " "+table+":") || strings.Contains(w, " "+table+",") ||
				strings.Contains(w, " "+table+"(") || strings.HasPrefix(w, table+" ") {
				return true
			}
		}
		return false
	}
	var lw, dw []string
	for _, w := range live.Warnings {
		if !skip(w) {
			lw = append(lw, w)
		}
	}
	for _, w := range dump.Warnings {
		// The scan user's warning is live-only: a dump has no user.
		if strings.Contains(w, "scan user can change") {
			t.Errorf("the dump scan carries a live-only warning: %q", w)
		}
		if !skip(w) {
			dw = append(dw, w)
		}
	}
	if !reflect.DeepEqual(lw, dw) {
		t.Errorf("warnings:\n live %q\n dump %q", lw, dw)
	}
}

func diffFindings(t *testing.T, live, dump []model.Finding) {
	t.Helper()
	key := func(f model.Finding) string {
		return fmt.Sprintf("%s.%s [%s] %s %s", f.Table, f.Column, f.MetaKey, f.Path, f.Category)
	}
	l, d := map[string]bool{}, map[string]bool{}
	for _, f := range live {
		l[key(f)] = true
	}
	for _, f := range dump {
		d[key(f)] = true
	}
	var only []string
	for k := range l {
		if !d[k] {
			only = append(only, "live only: "+k)
		}
	}
	for k := range d {
		if !l[k] {
			only = append(only, "dump only: "+k)
		}
	}
	sort.Strings(only)
	for _, s := range only {
		t.Log(s)
	}
}

// --- the live sampler's rows, directly ---

func fillTable(ctx context.Context, t *testing.T, admin *sql.DB, table, cols string, n int, row func(i int) string) {
	t.Helper()
	for start := 0; start < n; start += 500 {
		var parts []string
		for i := start; i < min(start+500, n); i++ {
			parts = append(parts, row(i))
		}
		if _, err := admin.ExecContext(ctx, "INSERT INTO "+table+" ("+cols+") VALUES "+strings.Join(parts, ",")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDumpSamplerRowsMatchLive(t *testing.T) {
	admin, adminCfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	const db = "prodmask_s6_sampler"
	t.Cleanup(func() { admin.Exec("DROP DATABASE IF EXISTS `" + db + "`") })
	q := "`" + db + "`."
	execAll(ctx, t, admin, append(recreate(db),
		"CREATE TABLE "+q+"s650 (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, v varchar(30), n int)",
		"CREATE TABLE "+q+"s6100 (id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, v varchar(30), n int)",
		"CREATE TABLE "+q+"s_dense (id int NOT NULL PRIMARY KEY, v varchar(30))",
		"CREATE TABLE "+q+"s_nokey (a int, v varchar(30), KEY (a))",
		"CREATE TABLE "+q+"s_strkey (code varchar(20) NOT NULL PRIMARY KEY, v varchar(30))",
		"CREATE TABLE "+q+"s_compkey (a int NOT NULL, b int NOT NULL, v varchar(30), PRIMARY KEY (a, b))",
		"CREATE TABLE "+q+"s_entries (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, meta_key varchar(60) DEFAULT NULL, meta_value text, KEY meta_key (meta_key))",
		"CREATE TABLE "+q+"s_meta (meta_id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, user_id bigint NOT NULL DEFAULT 0, "+
			"meta_key varchar(255) DEFAULT NULL, meta_value longtext, KEY meta_key (meta_key(191)))",
	))
	// Gaps, so the span is wider than the row count.
	fillTable(ctx, t, admin, q+"s650", "id, v, n", 650, func(i int) string { return fmt.Sprintf("(%d,'v%d',%d)", i*5+1, i, i%7) })
	fillTable(ctx, t, admin, q+"s6100", "id, v, n", 6100, func(i int) string { return fmt.Sprintf("(%d,'v%d',%d)", i*3+10, i, i%11) })
	// A span of exactly twice the limit, and one past it.
	fillTable(ctx, t, admin, q+"s_dense", "id, v", 601, func(i int) string { return fmt.Sprintf("(%d,'d%d')", i+1, i) })
	fillTable(ctx, t, admin, q+"s_nokey", "a, v", 700, func(i int) string { return fmt.Sprintf("(%d,'k%d')", (i*37)%101, i) })
	fillTable(ctx, t, admin, q+"s_strkey", "code, v", 700, func(i int) string { return fmt.Sprintf("('c%05d','s%d')", i, i) })
	fillTable(ctx, t, admin, q+"s_compkey", "a, b, v", 700, func(i int) string { return fmt.Sprintf("(%d,%d,'p%d')", i/10, i%10, i) })
	first := []string{"Ama", "Brisa", "Cato", "Dren", "Elio", "Faye", "Garo", "Hesper"}
	last := []string{"Vexley", "Quillon", "Marrow", "Tamsk", "Orrin", "Pellow", "Strand", "Ivel"}
	fillTable(ctx, t, admin, q+"s_entries", "meta_key, meta_value", 21000, func(i int) string {
		return fmt.Sprintf("('%s %s %d','value %d')", first[i%8], last[(i/8)%8], i, i)
	})
	fillTable(ctx, t, admin, q+"s_meta", "user_id, meta_key, meta_value", 21000, func(i int) string {
		return fmt.Sprintf("(%d,'key_%d','value %d')", i%300, i%40, i)
	})

	sess := openScan(ctx, t, adminCfg, db)
	schema, err := introspect.Load(ctx, sess.DB, db)
	if err != nil {
		t.Fatal(err)
	}
	text := serverDump(ctx, t, admin, db)
	sm := &sample.Sampler{DB: sess.DB, MaxValueLen: 4096, Timeout: time.Minute}

	for _, rows := range [][2]int{{300, 3000}, {3000, 3000}} {
		collected := map[string]map[int]*sample.Sample{}
		modes := map[string]int{}
		res := dumpScan(ctx, t, text, db, func(o *scan.DumpOptions) {
			o.SampleRows, o.MetaSampleRows = rows[0], rows[1]
			scan.DumpTap(o, func(table string, wins map[int]*sample.Sample, mode int) {
				collected[table] = wins
				modes[table] = mode
			})
		})
		for _, tbl := range schema.Tables {
			for limit, got := range collected[tbl.Name] {
				want, err := sm.Table(ctx, tbl, limit)
				if err != nil {
					t.Fatal(err)
				}
				if got.Method != want.Method || len(got.Rows) != len(want.Rows) {
					t.Errorf("%s at %d: method %q with %d rows, the live sampler's %q with %d", tbl.Name, limit, got.Method, len(got.Rows), want.Method, len(want.Rows))
					continue
				}
				t.Logf("%s at %d: %s, %d rows", tbl.Name, limit, got.Method, len(got.Rows))
				for i := range want.Rows {
					if !reflect.DeepEqual(got.Rows[i], want.Rows[i]) {
						t.Errorf("%s at %d: row %d is %v, the live sampler's is %v", tbl.Name, limit, i, got.Rows[i], want.Rows[i])
						break
					}
				}
				if len(want.Rows) == 0 && tbl.Name != "s_empty" {
					t.Errorf("%s at %d: no rows", tbl.Name, limit)
				}
			}
		}
		if rows[0] == 300 {
			for _, name := range []string{"s650", "s6100", "s_dense", "s_nokey", "s_strkey", "s_compkey", "s_entries", "s_meta"} {
				if collected[name] == nil {
					t.Errorf("%s: nothing collected", name)
				}
			}
			if len(collected["s_meta"]) != 2 || len(collected["s_entries"]) != 2 || len(collected["s650"]) != 1 {
				t.Errorf("windows kept: s_meta %d, s_entries %d, s650 %d", len(collected["s_meta"]), len(collected["s_entries"]), len(collected["s650"]))
			}
			if modes["s_entries"] != 2 || modes["s_meta"] != 2 {
				t.Errorf("modes: s_entries %d, s_meta %d, want listed keys", modes["s_entries"], modes["s_meta"])
			}
			// A demoted generic table outside the envelope gets the 300-row window,
			// as on the database.
			liveModes := map[string]int{}
			restore := scan.SetKVModeHook(func(table string, mode int) { liveModes[table] = mode })
			live := runScan(ctx, t, sess, "auto")
			restore()
			if liveModes["s_entries"] == 1 {
				t.Errorf("the live scan read s_entries whole")
			}
			for _, r := range []*model.Result{live, res} {
				var ts model.TableSummary
				for _, x := range r.Tables {
					if x.Name == "s_entries" {
						ts = x
					}
				}
				if ts.Kind != "table" || ts.RowsSampled != 300 {
					t.Errorf("s_entries: %+v, want a plain table with the 300-row window", ts)
				}
			}
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
