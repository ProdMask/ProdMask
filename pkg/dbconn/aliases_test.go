package dbconn

import (
	"reflect"
	"slices"
	"testing"
)

func TestStatementAliases(t *testing.T) {
	cases := []struct {
		q      string
		tables map[string]string
		twice  []string
		read   []string
	}{
		{"SELECT * FROM customers", map[string]string{"customers": "customers"}, nil, []string{"customers"}},
		{"SELECT c.email FROM shop.customers AS c", map[string]string{"c": "customers"}, nil, []string{"customers"}},
		{"SELECT * FROM customers c JOIN orders o ON o.customer_id = c.id, wp_usermeta m",
			map[string]string{"c": "customers", "o": "orders", "m": "wp_usermeta"}, nil, []string{"customers", "orders", "wp_usermeta"}},
		{"SELECT * FROM customers c LEFT JOIN orders USING (id) WHERE c.id IN (SELECT customer_id FROM orders c)",
			map[string]string{"c": "orders", "orders": "orders"}, []string{"c", "orders"}, []string{"customers", "orders"}},
		{"SELECT d.n FROM (SELECT COUNT(*) AS n FROM orders o) AS d",
			map[string]string{"d": "", "o": "orders"}, nil, []string{"orders"}},
		// A CTE's name stays among the tables read: a table may share it.
		{"WITH w AS (SELECT * FROM customers) SELECT w.email FROM w",
			map[string]string{"w": "", "customers": "customers"}, nil, []string{"customers", "w"}},
		{"WITH w (a) AS (SELECT 1), v AS (SELECT 2) SELECT * FROM w x, v",
			map[string]string{"w": "", "v": "", "x": ""}, nil, []string{"w", "v"}},
		{"WITH customers AS (SELECT * FROM customers) SELECT CONCAT(first_name) FROM customers",
			map[string]string{"customers": ""}, nil, []string{"customers"}},
		// An alias after PARTITION (...); the reviewer's case, where missing
		// it tied c to orders.
		{"SELECT c.note FROM customers PARTITION (p0) c WHERE EXISTS (SELECT 1 FROM orders c)",
			map[string]string{"c": "orders"}, []string{"c"}, []string{"customers", "orders"}},
		{"SELECT c.a FROM customers PARTITION (p0, p1) AS c USE INDEX FOR JOIN (i) WHERE 1",
			map[string]string{"c": "customers"}, nil, []string{"customers"}},
		// The reviewer's other forms: ODBC's {oj}, parenthesised joins and an
		// index hint whose ORDER BY doesn't end the FROM list.
		{"SELECT c.note FROM {oj customers c LEFT OUTER JOIN orders o ON 1=1}",
			map[string]string{"c": "customers", "o": "orders"}, nil, []string{"customers", "orders"}},
		{"SELECT c.note FROM {oj customers c LEFT OUTER JOIN orders o ON 1=1} WHERE EXISTS (SELECT 1 FROM orders c)",
			map[string]string{"c": "orders", "o": "orders"}, []string{"c"}, []string{"customers", "orders"}},
		{"SELECT c.note FROM ((customers c) JOIN orders o ON 1=1) WHERE EXISTS (SELECT 1 FROM orders c)",
			map[string]string{"c": "orders", "o": "orders"}, []string{"c"}, []string{"customers", "orders"}},
		{"SELECT c.note FROM t LEFT JOIN ((customers c)) ON 1=1",
			map[string]string{"t": "t", "c": "customers"}, nil, []string{"t", "customers"}},
		{"SELECT o.note FROM t USE INDEX FOR ORDER BY (i) JOIN orders o WHERE EXISTS (SELECT 1 FROM customers o)",
			map[string]string{"t": "t", "o": "customers"}, []string{"o"}, []string{"t", "orders", "customers"}},
		{"SELECT d.a FROM ((SELECT 1 AS a) UNION (SELECT 2)) AS d", map[string]string{"d": ""}, nil, nil},
		{"TABLE customers", map[string]string{"customers": "customers"}, nil, []string{"customers"}},
		// FROM between a function's arguments reads no table; a subquery
		// inside one has its own.
		{"SELECT EXTRACT(YEAR FROM o.created) FROM orders o", map[string]string{"o": "orders"}, nil, []string{"orders"}},
		{"SELECT TRIM(' ' FROM (SELECT n FROM t)) FROM orders o",
			map[string]string{"t": "t", "o": "orders"}, nil, []string{"t", "orders"}},
		{"SELECT 1 UNION TABLE shop.orders", map[string]string{"orders": "orders"}, nil, []string{"orders"}},
		{"SELECT * FROM (customers c JOIN orders o ON o.c = c.id)",
			map[string]string{"c": "customers", "o": "orders"}, nil, []string{"customers", "orders"}},
		{"SELECT * FROM customers USE INDEX (i) WHERE 1", map[string]string{"customers": "customers"}, nil, []string{"customers"}},
		{"SELECT a FROM t1 UNION SELECT b FROM t2", map[string]string{"t1": "t1", "t2": "t2"}, nil, []string{"t1", "t2"}},
		{"SELECT (SELECT COUNT(*) FROM orders o WHERE o.c = c.id) AS n FROM customers c",
			map[string]string{"o": "orders", "c": "customers"}, nil, []string{"orders", "customers"}},
		{"SELECT j.a FROM t, JSON_TABLE(t.doc, '$[*]' COLUMNS (a INT PATH '$.a')) AS j",
			map[string]string{"t": "t", "j": ""}, nil, []string{"t"}},
		{"SELECT * FROM `Customers` AS `C`", map[string]string{"c": "Customers"}, nil, []string{"Customers"}},
		{"SHOW CREATE TABLE customers", map[string]string{}, nil, nil},
		{"SELECT 'x\\' FROM t", map[string]string{}, nil, nil},
	}
	for _, c := range cases {
		got := StatementAliases(c.q)
		var twice []string
		for k := range got.Twice {
			twice = append(twice, k)
		}
		slices.Sort(twice)
		if !reflect.DeepEqual(got.Tables, c.tables) || !slices.Equal(twice, c.twice) || !slices.Equal(got.Read, c.read) {
			t.Errorf("%s:\n got %v, twice %v, read %v\nwant %v, twice %v, read %v", c.q, got.Tables, twice, got.Read, c.tables, c.twice, c.read)
		}
	}
}

// TestStatementAliasesBackstop: an alias in a form the walk doesn't read,
// here after MariaDB's FOR SYSTEM_TIME, stands bare a second time when the
// statement defines it again, and is marked Twice.
func TestStatementAliasesBackstop(t *testing.T) {
	al := StatementAliases("SELECT c.a FROM customers FOR SYSTEM_TIME ALL c WHERE EXISTS (SELECT 1 FROM orders c)")
	if !al.Twice["c"] {
		t.Errorf("an alias the walk missed, defined again: %+v", al)
	}
	if al := StatementAliases("SELECT c.a FROM customers FOR SYSTEM_TIME ALL c"); al.Tables["c"] != "" || al.Twice["c"] {
		t.Errorf("an alias the walk missed, defined once: %+v", al)
	}
}

// TestCollectAliasesQualifiers: the database part of each table reference,
// and nothing else.
func TestCollectAliasesQualifiers(t *testing.T) {
	for q, want := range map[string][]string{
		"SELECT x.a FROM hr.salaries x JOIN shop.t ON x.b = t.b":      {"hr", "shop"},
		"SELECT * FROM {oj hr.s LEFT OUTER JOIN t ON 1=1}, ((db2.u))": {"hr", "db2"},
		"TABLE hr.s":    {"hr"},
		"DESCRIBE hr.s": {"hr"},
		"SELECT EXTRACT(YEAR FROM o.created) FROM shop.orders o": {"shop"},
		"SHOW COLUMNS FROM hr.s FROM shop":                       {"hr"},
		"SELECT hr.s.a, f(x.y) FROM t":                           nil,
		"SELECT * FROM t WHERE t.a IN (1, 2)":                    nil,
	} {
		toks, err := statementTokens(q)
		if err != nil {
			t.Fatal(err)
		}
		_, quals := collectAliases(toks)
		var got []string
		for k := range toks {
			if quals[k] {
				got = append(got, toks[k].raw)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: qualifiers %q, want %q", q, got, want)
		}
	}
}

func TestLeadingWord(t *testing.T) {
	for q, want := range map[string]string{
		"SHOW TRIGGERS":               "SHOW",
		"-- triggers\nSHOW TRIGGERS":  "SHOW",
		"/**/SHOW TRIGGERS":           "SHOW",
		"(SELECT 1) UNION (SELECT 2)": "SELECT",
		"  # x\n  select 1":           "SELECT",
		"SELECT '\\'":                 "",
	} {
		if got := LeadingWord(q); got != want {
			t.Errorf("LeadingWord(%q) = %q, want %q", q, got, want)
		}
	}
}

func TestInformationSchemaOnly(t *testing.T) {
	for q, want := range map[string]bool{
		"SELECT TABLE_NAME, TABLE_COMMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()":            true,
		"SELECT c.COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS c JOIN information_schema.TABLES t USING (TABLE_NAME)": true,
		"SELECT * FROM (SELECT TABLE_NAME FROM information_schema.TABLES) d":                                         true,
		"SELECT t.TABLE_NAME, c.email FROM information_schema.TABLES t JOIN customers c ON 1=1":                      false,
		"SELECT * FROM shop.customers": false,
		"SELECT 1":                     false,
	} {
		if got := StatementAliases(q).InformationSchemaOnly; got != want {
			t.Errorf("%s: %v, want %v", q, got, want)
		}
	}
}

// TestInformationSchemaOnlyTable: the TABLE statement on a table named
// status is a table reference (only SHOW TABLE STATUS isn't), and a stored
// function's call takes a result out of the information_schema-only kind.
func TestInformationSchemaOnlyTable(t *testing.T) {
	for _, q := range []string{
		"TABLE status UNION SELECT ENGINE, 1 FROM information_schema.ENGINES",
		"SELECT ENGINE, 1 FROM information_schema.ENGINES UNION TABLE status",
		"SELECT ENGINE FROM information_schema.ENGINES WHERE ENGINE IN (TABLE status)",
		"SELECT ENGINE, (SELECT MAX(s.note) FROM (TABLE status) s) FROM information_schema.ENGINES",
		"SELECT shop.f(1), 2 FROM information_schema.ENGINES",
	} {
		if StatementAliases(q).InformationSchemaOnly {
			t.Errorf("%s: information_schema-only", q)
		}
	}
	if al := StatementAliases("SHOW TABLE STATUS LIKE 'x'"); len(al.Tables) != 0 || len(al.Read) != 0 {
		t.Errorf("SHOW TABLE STATUS reads a table: %+v", al)
	}
	if al := StatementAliases("SELECT t.TABLE_NAME FROM information_schema.TABLES t"); al.Names["tables"] || al.Names["information_schema"] || !al.Names["t"] {
		t.Errorf("names outside the information_schema pair: %v", al.Names)
	}
}
