package dbconn

import (
	"context"
	"database/sql"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// helpFunctionCategories are the server help categories whose topics are
// functions and operators: the ones the list's generator reads. Those for
// loadable functions, components and plugins are left out.
var helpFunctionCategories = wordLines(`Aggregate Functions and Modifiers
Bit Functions
Cast Functions and Operators
Comparison Operators
Date and Time Functions
Encryption Functions
Flow Control Functions
Control Flow Functions
Geometry Constructors
Geometry Property Functions
Geometry Relation Functions
GeometryCollection Property Functions
GTID
Information Functions
Internal Functions
LineString Property Functions
Locking Functions
Logical Operators
MBR Functions
MBR
Miscellaneous Functions
Numeric Functions
Performance Schema Functions
Point Property Functions
Polygon Property Functions
String Functions
Window Functions
WKB Functions
WKT Functions
WKB
WKT
XML
Arithmetic Operators
Dynamic Column Functions
Functions and Modifiers for Use with GROUP BY
Galera Functions
GeoJSON
Geometry Properties
Geometry Relations
JSON Functions
LineString Properties
Point Properties
Polygon Properties
Sequences
Functions
Operators
Spider Functions`)

func wordLines(s string) map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		m[strings.TrimSpace(line)] = true
	}
	return m
}

var helpIdent = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// helpTopicName is a help topic's function name, or "" for an operator or a
// statement, as the generator reads it.
func helpTopicName(topic string) string {
	t := strings.ToUpper(strings.TrimSpace(topic))
	for _, suffix := range []string{" FUNCTION", " OPERATOR", "()"} {
		t = strings.TrimSpace(strings.TrimSuffix(t, suffix))
	}
	if !helpIdent.MatchString(t) {
		return ""
	}
	return t
}

// TestAgentFunctionsCoverServer checks agent_functions.go against the
// server it runs on, as its root user: the help tables, and on MariaDB its
// registry of functions, aren't empty; every function in them is on the
// list for this flavour; and no name the list allows is a loadable function
// here. A new server version that adds a function fails it, so the function
// is classified before an agent can call it.
func TestAgentFunctionsCoverServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, _ := snapshotServer(t)
	var version, comment string
	if err := admin.QueryRowContext(ctx, "SELECT VERSION(), @@version_comment").Scan(&version, &comment); err != nil {
		t.Fatal(err)
	}
	flavor, bit := "mysql", onMySQL
	if strings.Contains(strings.ToLower(version+" "+comment), "mariadb") {
		flavor, bit = "mariadb", onMariaDB
	}
	names := map[string]bool{}
	rows, err := admin.QueryContext(ctx, "SELECT t.name, c.name FROM mysql.help_topic t "+
		"JOIN mysql.help_category c ON c.help_category_id = t.help_category_id")
	if err != nil {
		t.Fatal(err)
	}
	topics := 0
	for rows.Next() {
		var topic, category string
		if err := rows.Scan(&topic, &category); err != nil {
			t.Fatal(err)
		}
		topics++
		if n := helpTopicName(topic); n != "" && helpFunctionCategories[category] {
			names[n] = true
		}
	}
	rows.Close()
	if topics == 0 || len(names) < 200 {
		t.Fatalf("%s's help tables hold %d topics and %d functions: load them, or the list can't be checked", flavor, topics, len(names))
	}
	loadableQuery := "SELECT UDF_NAME FROM performance_schema.user_defined_functions"
	if flavor == "mariadb" {
		before := len(names)
		rows, err := admin.QueryContext(ctx, "SELECT FUNCTION FROM information_schema.SQL_FUNCTIONS")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			names[strings.ToUpper(n)] = true
		}
		rows.Close()
		if len(names) == before {
			t.Fatal("information_schema.SQL_FUNCTIONS added no function")
		}
		loadableQuery = "SELECT name FROM mysql.func"
	}
	var loadable []string
	rows, err = admin.QueryContext(ctx, loadableQuery)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		loadable = append(loadable, strings.ToUpper(n))
		delete(names, strings.ToUpper(n))
	}
	rows.Close()
	var missing []string
	for n := range names {
		if f, ok := agentFuncs[n]; !ok || f.flavors&bit == 0 {
			missing = append(missing, n)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%s (%s) has functions agent_functions.go doesn't list for it; classify them: %s", flavor, version, strings.Join(missing, " "))
	}
	for _, n := range loadable {
		if f, ok := agentFuncs[n]; ok && f.class.allowed() && f.flavors&bit != 0 {
			t.Errorf("%s is a loadable function on this server, and the list allows it", n)
		}
	}
}

// TestAgentAllowedRun runs every read the agent's rules allow, on a
// database that has what they name, through a Session: the rules let
// through only statements the server reads as reads.
func TestAgentAllowedRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const db = "prodmask_fixture_agent"
	_, _, sess := sessionDatabase(ctx, t, db,
		"CREATE TABLE "+db+".customers (id INT PRIMARY KEY, name VARCHAR(40), first_name VARCHAR(40), FULLTEXT ft (name))",
		"CREATE TABLE "+db+".orders (id INT PRIMARY KEY, customer_id INT, total DECIMAL(10,2), a VARCHAR(20))",
		"CREATE TABLE "+db+".t (id INT PRIMARY KEY, a VARCHAR(20), b INT, d DATE, created_at DATETIME, v VARCHAR(10), INDEX i (a)) "+
			"PARTITION BY KEY (id) PARTITIONS 2",
		"CREATE TABLE "+db+".big (i INT PRIMARY KEY)",
		"CREATE TABLE "+db+".wp_usermeta (umeta_id INT PRIMARY KEY, user_id INT, meta_key VARCHAR(255), meta_value LONGTEXT)",
		"CREATE VIEW "+db+".v AS SELECT id FROM "+db+".t",
		"CREATE TRIGGER "+db+".tr BEFORE INSERT ON "+db+".t FOR EACH ROW SET NEW.b = 1",
		"CREATE FUNCTION "+db+".discount(x INT) RETURNS INT DETERMINISTIC NO SQL RETURN x - 1")
	scope := AgentScope{Flavor: sess.Flavor(), Database: db,
		Tables:    []string{"customers", "orders", "t", "big", "wp_usermeta", "v"},
		Functions: []string{"discount"}}
	rows, err := sess.DB.QueryContext(ctx, "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		scope.Databases = append(scope.Databases, n)
	}
	rows.Close()
	list := append([]string(nil), agentAllowed...)
	if scope.Flavor == "mariadb" {
		list = append(list, agentAllowedMariaDB...)
	} else {
		list = append(list, agentAllowedMySQL...)
	}
	shop := regexp.MustCompile(`\bshop\b`)
	for _, q := range list {
		q = shop.ReplaceAllString(q, db)
		if err := CheckAgentStatement(q, scope); err != nil {
			t.Errorf("%q: %v", q, err)
			continue
		}
		rows, err := sess.DB.QueryContext(ctx, q)
		if err != nil {
			t.Errorf("%q: %v", q, err)
			continue
		}
		for rows.Next() {
		}
		if err := rows.Err(); err != nil {
			t.Errorf("%q: %v", q, err)
		}
		rows.Close()
	}
}

// TestTraditionalExplain: an agent's session sets explain_format where MySQL
// has it, so the runner reads it back with the other settings; MariaDB has
// none to set.
func TestTraditionalExplain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const db = "prodmask_fixture_explain"
	_, cfg, sess := sessionDatabase(ctx, t, db, "CREATE TABLE "+db+".t (id INT PRIMARY KEY)")
	agent, err := OpenWith(ctx, cfg, SessionOptions{Timeout: 30 * time.Second, TraditionalExplain: true})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	var probe sql.NullString
	has := sess.Server.Flavor == "mysql" && sess.DB.QueryRowContext(ctx, "SELECT @@SESSION.explain_format").Scan(&probe) == nil
	if got, ok := agent.Settings["explain_format"]; ok != has || has && got != "TRADITIONAL" {
		t.Fatalf("explain_format in the settings: %q, %v; the server has it: %v", got, ok, has)
	}
	if !has {
		return
	}
	var format string
	if err := agent.DB.QueryRowContext(ctx, "SELECT @@SESSION.explain_format").Scan(&format); err != nil || format != "TRADITIONAL" {
		t.Errorf("the session's explain_format: %q, %v", format, err)
	}
}

// TestServerBigSelects: an agent's session leaves sql_big_selects at the
// server's value, so a DBA's max_join_size still refuses the largest joins;
// the scan's own session sets it.
func TestServerBigSelects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const db = "prodmask_fixture_bigselects"
	_, cfg, sess := sessionDatabase(ctx, t, db, "CREATE TABLE "+db+".t (id INT PRIMARY KEY)")
	agent, err := OpenWith(ctx, cfg, SessionOptions{Timeout: 30 * time.Second, ServerBigSelects: true})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if v, ok := agent.Settings["sql_big_selects"]; ok {
		t.Errorf("the agent's session sets sql_big_selects to %q", v)
	}
	if v := sess.Settings["sql_big_selects"]; v != "1" {
		t.Errorf("the scan's session sets sql_big_selects to %q, want 1", v)
	}
}
