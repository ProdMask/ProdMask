package dbconn

import (
	"errors"
	"strings"
	"testing"
)

// testScope is a session on the database shop, whose list of databases was
// read.
func testScope(flavor string) AgentScope {
	return AgentScope{
		Flavor:    flavor,
		Database:  "shop",
		Tables:    []string{"customers", "orders", "wp_usermeta", "t", "big", "v"},
		Functions: []string{"discount"},
		Databases: []string{"shop", "other", "information_schema", "mysql", "performance_schema", "sys"},
	}
}

// agentRefused are statements CheckAgentStatement must refuse on both
// servers. Each is made harmless if it ever got through: outfiles go to
// '.', which the server refuses.
var agentRefused = []string{
	// DBHub #504: a backslash-escaped quote hiding statements.
	`SELECT '\' , '; SET SESSION transaction_read_only = 0; COMMIT; DROP TABLE t; SELECT ''`,
	`SELECT '\' , '; SET SESSION tx_read_only = 0; COMMIT; DROP TABLE t; SELECT ''`,
	`SELECT '\' , '; SELECT GET_LOCK('x', 0) AS lk; SELECT ''`,
	// MariaDB/mcp #55: SHOW and other sessions' statements; credentials.
	`SHOW PROCESSLIST`,
	`SHOW FULL PROCESSLIST`,
	`SELECT * FROM information_schema.PROCESSLIST`,
	`SELECT * FROM performance_schema.events_statements_history`,
	`SHOW ENGINE INNODB STATUS`,
	`SHOW BINLOG EVENTS`,
	`SHOW RELAYLOG EVENTS`,
	`SHOW SLAVE STATUS`,
	`SHOW REPLICA STATUS`,
	`SHOW MASTER STATUS`,
	`SHOW CREATE USER root`,
	`SHOW GRANTS`,
	`SHOW GRANTS FOR root`,
	`SELECT authentication_string FROM mysql.user`,
	`SHOW DATABASES`,
	`SHOW VARIABLES`,
	`SHOW STATUS`,
	`SELECT @@report_password`,
	`SELECT @@GLOBAL.secure_file_priv`,
	`SELECT @@hostname`,
	`SELECT CURRENT_USER()`,
	`SELECT CURRENT_USER`,
	`SELECT CURRENT_ROLE`,
	`SELECT USER()`,
	`SHOW WARNINGS`,
	`SHOW COUNT(*) WARNINGS`,
	`SELECT * FROM information_schema.INNODB_TRX`,
	`SELECT * FROM information_schema.ROUTINES`,
	`SELECT * FROM information_schema.USER_PRIVILEGES`,
	// SHOW filters: no WHERE, whose subquery MySQL doesn't time-limit.
	`SHOW TABLES WHERE (SELECT COUNT(*) FROM big) > 0`,
	`SHOW COLUMNS FROM t WHERE Field = 'a'`,
	`SHOW TABLES LIKE 'wp\_%'`,
	`SHOW INDEX FROM t LIKE 'a'`,
	// Files, locks and waits.
	`SELECT LOAD_FILE('.')`,
	"SELECT `load_file` ('.')",
	`SELECT 1 INTO OUTFILE '.'`,
	`SELECT 1 INTO DUMPFILE '.'`,
	`TABLE t INTO OUTFILE '.'`,
	`LOAD DATA INFILE '.' INTO TABLE t`,
	`SELECT GET_LOCK('x', 0)`,
	`SELECT IS_USED_LOCK('x')`,
	`SELECT RELEASE_ALL_LOCKS()`,
	`SELECT * FROM t FOR UPDATE`,
	`SELECT * FROM t FOR SHARE`,
	`SELECT * FROM t LOCK IN SHARE MODE`,
	`LOCK TABLES t READ`,
	`SELECT SLEEP(10)`,
	`SELECT BENCHMARK(1000000, MD5('a'))`,
	`SELECT MASTER_POS_WAIT('f', 4)`,
	`SELECT WAIT_FOR_EXECUTED_GTID_SET('x', 1)`,
	// Functions that aren't on the list, or not where they stand.
	`SELECT innodb_redo_log_archive_start('x')`,
	`SELECT group_replication_set_as_primary('x')`,
	`SELECT xyz_exec('x')`,
	"SELECT `xyz_exec`('x')",
	`SELECT "xyz_exec"('x')`,
	"SELECT LOAD_FİLE('.')",
	"SELECT CONCΑT('a')",
	`WITH xyz_exec (a) AS (SELECT 1) SELECT xyz_exec('x') FROM xyz_exec`,
	`WITH xyz_exec AS (SELECT 1) SELECT xyz_exec('x') FROM xyz_exec`,
	`SELECT xyz_exec('x') FROM (SELECT 1) AS xyz_exec (a)`,
	`SELECT discount(1)`,
	`SELECT other.discount(1)`,
	`SELECT DECIMAL(10)`,
	"SELECT (`select`('x'))",
	"SELECT CONCAT(first_name, '') AS `p.name` FROM customers",
	"SELECT a FROM `t.x`",
	`SELECT CAN_ACCESS_TABLE('shop', 't')`,
	`SELECT ROLES_GRAPHML()`,
	// Writes and control.
	`INSERT INTO t VALUES (1)`,
	`UPDATE t SET a = 1`,
	`DELETE FROM t`,
	`REPLACE INTO t VALUES (1)`,
	`TRUNCATE t`,
	`DROP TABLE t`,
	`ALTER TABLE t ADD c INT`,
	`CREATE TABLE x (a INT)`,
	`RENAME TABLE t TO u`,
	`GRANT SELECT ON *.* TO x`,
	`WITH c AS (SELECT 1) DELETE FROM t`,
	`EXPLAIN DELETE FROM t`,
	`EXPLAIN ANALYZE SELECT * FROM t`,
	`EXPLAIN FORMAT=TREE ANALYZE SELECT 1`,
	`PREPARE s FROM 'SELECT 1'`,
	`EXECUTE s`,
	`CALL p()`,
	`DO 1`,
	`HANDLER t OPEN`,
	`SET @a = 1`,
	`USE other`,
	`KILL 1`,
	`START TRANSACTION`,
	`XA START 'x'`,
	`BEGIN NOT ATOMIC SELECT 1; END`,
	`SELECT * FROM t PROCEDURE ANALYSE()`,
	`SELECT NEXTVAL(s)`,
	`SELECT NEXT VALUE FOR s`,
	`SELECT s.nextval`,
	// Hiding.
	`SELECT /*! 1 */`,
	`SELECT /*M! 1 */`,
	`SELECT /*+ BKA(t) */ 1`,
	"SELECT 1 --\x7f\nINTO OUTFILE '.'",
	"SELECT 1\x00",
	`SELECT 1; SELECT 2`,
	`SEL/**/ECT 1`,
	// Other databases, and names that fold onto them. A qualifier in no
	// list is refused too: a database made after the list was read.
	`SELECT * FROM nowhere.t`,
	// A column's alias is no qualifier: hr here is a database's name.
	`SELECT 1 AS hr FROM hr.salaries`,
	// A quoted name before ( is a loadable or stored function to the server,
	// even when it's a built-in's or a keyword's name.
	"SELECT `if`(1, 2, 3)",
	"SELECT `in`(1)",
	"SELECT `concat`('a')",
	// A digit-led name after a dot glued to a word is a name to the
	// servers, not a number.
	`SELECT * FROM hr.2024_salaries`,
	`SELECT * FROM other.1`,
	`SELECT * FROM mysql.1x`,
	`SELECT hr.2x.a FROM t`,
	`SELECT * FROM hr . 2x`,
	// Before a table's name, a qualifier is a database, whatever the
	// statement defines or the session's tables are called.
	`SELECT * FROM hr.salaries hr`,
	`WITH hr AS (SELECT 1) SELECT * FROM hr.salaries`,
	`SELECT * FROM hr.salaries s JOIN t hr ON 1=1`,
	`SELECT * FROM customers.items`,
	`TABLE customers.items`,
	`DESCRIBE customers.items`,
	`SHOW CREATE TABLE customers.items`,
	`SHOW COLUMNS FROM customers.items`,
	`SHOW COLUMNS IN customers.items`,
	`SHOW INDEX IN customers.items`,
	`SHOW CREATE VIEW customers.v`,
	// EXPLAIN's tree and JSON forms print a const table's values in their
	// conditions; FOR CONNECTION explains another session's statement (the
	// read-only rules refuse that one).
	`EXPLAIN FORMAT=TREE SELECT o.id FROM customers c JOIN orders o ON o.a = c.name WHERE c.id = 1`,
	`EXPLAIN FORMAT=JSON SELECT 1`,
	`DESCRIBE FORMAT=TREE SELECT 1`,
	`EXPLAIN FORMAT='JSON' SELECT 1`,
	`EXPLAIN FOR CONNECTION 1`,
	`SELECT * FROM {oj customers.items x LEFT OUTER JOIN t ON 1=1}`,
	`SELECT * FROM ((customers.items x))`,
	`SELECT * FROM other.t`,
	"SELECT * FROM `other`.`t`",
	`SELECT * FROM other . t`,
	`SELECT other.t.a FROM other.t`,
	`SHOW TABLES FROM other`,
	`SHOW COLUMNS FROM t FROM other`,
	`SHOW CREATE TABLE other.t`,
	`DESCRIBE other.t`,
	`TABLE other.t`,
	`SELECT other.a FROM t other`,
	"SELECT * FROM Kother.t",
	"SELECT COUNT(*) FROM İNFORMATION_SCHEMA.TABLES",
	"SELECT * FROM ınformation_schema.TABLES",
	"SELECT * FROM shöp.t",
	// A qualifier outside ASCII must be this database's or a table's own
	// name, byte for byte, even when the statement defines it as an alias.
	"SELECT ſhop.a FROM t ſhop",
}

// agentAllowed are statements CheckAgentStatement must let through on
// MySQL; agentAllowedMariaDB adds MariaDB's own forms.
var agentAllowed = []string{
	`SELECT .5`,
	`SELECT x.a FROM t PARTITION (p0) x`,
	`SELECT x.a FROM t PARTITION (p0, p1) AS x WHERE x.b > 1`,
	`SELECT 1 AND .5 < 2`,
	`SELECT c.name FROM shop.customers c`,
	`DESCRIBE shop.customers`,
	`SELECT c.name FROM {oj customers c LEFT OUTER JOIN orders o ON c.id = o.customer_id}`,
	`SELECT c.name FROM ((customers c) JOIN orders o ON c.id = o.customer_id)`,
	`SELECT o.total FROM t USE INDEX FOR ORDER BY (i) JOIN orders o ON o.id = t.id`,
	// FROM between a function's arguments is no FROM clause.
	`SELECT EXTRACT(YEAR FROM x.created_at) FROM t x`,
	`SELECT EXTRACT(YEAR FROM t.created_at) FROM t`,
	`SELECT TRIM(BOTH ' ' FROM c.name) FROM customers c`,
	`SELECT SUBSTRING(c.name FROM c.id) FROM customers c`,
	`SELECT o.id, c.name FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.total > 10`,
	`SELECT * FROM (SELECT id FROM orders) d WHERE d.id IN (SELECT id FROM customers)`,
	`WITH c (a, b) AS (SELECT 1, 2) SELECT a, b FROM c`,
	`WITH RECURSIVE c AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM c WHERE n < 3) SELECT n FROM c`,
	`SELECT id, ROW_NUMBER() OVER (PARTITION BY a ORDER BY b) FROM t`,
	`SELECT CASE WHEN (a > 1) THEN (1) ELSE (0) END FROM t`,
	`SELECT DISTINCT (a) FROM t`,
	`(SELECT a FROM t) UNION (SELECT a FROM orders)`,
	`(SELECT a FROM t) UNION ALL (SELECT a FROM orders)`,
	`SELECT * FROM t WHERE a BETWEEN (1) AND (2)`,
	`SELECT * FROM t PARTITION (p0)`,
	`SELECT * FROM t USE INDEX (i)`,
	`SELECT * FROM t FORCE INDEX FOR JOIN (i)`,
	`SELECT * FROM customers WHERE MATCH (name) AGAINST ('x')`,
	`SELECT INTERVAL(5, 1, 10)`,
	`SELECT CAST(a AS DECIMAL(10,2)) FROM t`,
	`SELECT CAST(a AS CHAR(10) CHARACTER SET utf8mb4) FROM t`,
	`SELECT CONVERT(a, CHAR(10)) FROM t`,
	`SELECT CONVERT(a USING utf8mb4) FROM t`,
	`SELECT * FROM JSON_TABLE('[1]', '$[*]' COLUMNS (a VARCHAR(10) PATH '$')) j`,
	`SELECT * FROM t WHERE a LIKE ('x%')`,
	`SELECT * FROM t WHERE created_at > NOW() - INTERVAL 7 DAY`,
	`SELECT CURDATE(), UNIX_TIMESTAMP(), CURRENT_TIMESTAMP, LOCALTIME`,
	`SELECT a, b FROM (SELECT 1, 2) AS d (a, b)`,
	`SELECT shop.discount(1)`,
	"SELECT `shop`.`discount`(1)",
	`SELECT column_name FROM information_schema.COLUMNS WHERE table_schema = 'shop'`,
	`SELECT * FROM INFORMATION_SCHEMA.TABLES`,
	`SELECT ';'`,
	`SELECT '/*!'`,
	`SELECT @@sql_mode, @@SESSION.time_zone, @@version, @x`,
	`SELECT DATABASE(), CONNECTION_ID(), FOUND_ROWS(), LAST_INSERT_ID()`,
	`SELECT IF(a, 1, 2), IFNULL(a, 0), COALESCE(a, b), NULLIF(a, b) FROM t`,
	`SELECT COUNT(*), SUM(total), GROUP_CONCAT(DISTINCT a ORDER BY a SEPARATOR ',') FROM orders`,
	`SELECT LEFT(a, 3), RIGHT(a, 2), INSERT(a, 1, 2, 'x'), REPLACE(a, 'x', 'y'), MOD(a, 3), TRUNCATE(a, 1) FROM t`,
	`SELECT JSON_EXTRACT(a, '$.x'), JSON_UNQUOTE(a) FROM t`,
	`SELECT TRIM(BOTH ' ' FROM (a)), EXTRACT(YEAR FROM d), POSITION('a' IN b), SUBSTRING(a FROM 2 FOR 3) FROM t`,
	`SELECT * FROM t WHERE (a, b) IN (ROW(1, 2), ROW(3, 4))`,
	`SELECT * FROM t WHERE a = ANY (SELECT a FROM orders)`,
	`SELECT * FROM t WHERE a > SOME (SELECT a FROM orders)`,
	`SHOW COLUMNS FROM t`,
	`SHOW FULL COLUMNS FROM t FROM shop LIKE 'a%'`,
	`SHOW FIELDS IN t`,
	`SHOW TABLES FROM shop`,
	`SHOW TABLES LIKE 'wp_%'`,
	`SHOW FULL TABLES`,
	`SHOW TABLE STATUS LIKE 'w%'`,
	`SHOW INDEX FROM t`,
	`SHOW KEYS FROM shop.t`,
	`SHOW CREATE TABLE t`,
	`SHOW CREATE TABLE shop.t`,
	`SHOW CREATE VIEW v`,
	`SHOW CREATE TRIGGER tr`,
	`SHOW TRIGGERS`,
	`SHOW CHARACTER SET LIKE 'utf8%'`,
	`SHOW COLLATION`,
	`SHOW ENGINES`,
	`EXPLAIN SELECT * FROM t`,
	`DESCRIBE t`,
	`DESC t a`,
	`EXPLAIN t`,
	`SELECT c.v FROM t c`,
	`SELECT t.* FROM t`,
	`SELECT shop.t.a FROM shop.t`,
	`SELECT 1.5, .5, 1e3, 1.5e3`,
	`SELECT a AS customer FROM t`,
}

var agentAllowedMySQL = []string{
	`TABLE t`,
	`TABLE shop.big`,
	`EXPLAIN FORMAT=TRADITIONAL SELECT * FROM t`,
	`SELECT JSON_VALUE('{"a": 1}', '$.a' RETURNING DECIMAL(10,2))`,
	`SELECT 1 MEMBER OF ('[1, 2]')`,
	`SELECT * FROM orders o, LATERAL (SELECT 1) AS x`,
	`VALUES ROW(1, 2)`,
}

var agentAllowedMariaDB = []string{
	`SELECT NVL(a, 1), SFORMAT('{}', a) FROM t`,
	`SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY b) OVER () FROM t`,
	`VALUES (1, 2)`,
}

func TestAgentRefuses(t *testing.T) {
	for _, flavor := range []string{"mysql", "mariadb"} {
		for _, q := range agentRefused {
			err := CheckAgentStatement(q, testScope(flavor))
			if !errors.Is(err, ErrAgentStatement) {
				t.Errorf("%s: %q: %v, want ErrAgentStatement", flavor, q, err)
				continue
			}
			if errors.Is(err, ErrStatementRefused) {
				t.Errorf("%s: %q: the refusal carries the fault-report error", flavor, q)
			}
		}
	}
	long := "SELECT '" + strings.Repeat("a", MaxAgentStatement) + "'"
	if err := CheckAgentStatement(long, testScope("mysql")); !errors.Is(err, ErrAgentStatement) {
		t.Errorf("a statement over 64 KB: %v", err)
	}
}

func TestAgentAllows(t *testing.T) {
	for _, flavor := range []string{"mysql", "mariadb"} {
		for _, q := range agentAllowed {
			if err := CheckAgentStatement(q, testScope(flavor)); err != nil {
				t.Errorf("%s: %q: %v", flavor, q, err)
			}
		}
	}
	for flavor, list := range map[string][]string{"mysql": agentAllowedMySQL, "mariadb": agentAllowedMariaDB} {
		for _, q := range list {
			if err := CheckAgentStatement(q, testScope(flavor)); err != nil {
				t.Errorf("%s: %q: %v", flavor, q, err)
			}
		}
	}
}

// TestAgentFlavor: a function only MariaDB has built in is refused on
// MySQL, where its name would reach a loadable or stored function.
func TestAgentFlavor(t *testing.T) {
	q := `SELECT NVL(a, 1) FROM t`
	if err := CheckAgentStatement(q, testScope("mysql")); !errors.Is(err, ErrAgentStatement) {
		t.Errorf("mysql: %q: %v, want a refusal", q, err)
	}
	if err := CheckAgentStatement(`SELECT REGEXP_LIKE(a, 'x') FROM t`, testScope("mariadb")); !errors.Is(err, ErrAgentStatement) {
		t.Errorf("mariadb: REGEXP_LIKE: %v, want a refusal", err)
	}
	if err := CheckAgentStatement(q, AgentScope{Database: "shop"}); !errors.Is(err, ErrAgentStatement) {
		t.Errorf("unknown flavour: %q: %v, want a refusal", q, err)
	}
	// MariaDB reserves neither OF nor LATERAL: there they call functions of
	// those names. KDF there burns time as its iterations ask.
	for _, q := range []string{`SELECT OF(1)`, `SELECT 1, LATERAL(1)`, `SELECT * FROM orders o, LATERAL (SELECT 1) AS x`,
		`SELECT 1 MEMBER OF ('[1, 2]')`, `SELECT KDF('a', 'b', 'c', 'd', 100000000)`} {
		if err := CheckAgentStatement(q, testScope("mariadb")); !errors.Is(err, ErrAgentStatement) {
			t.Errorf("mariadb: %q: %v, want a refusal", q, err)
		}
	}
	if err := CheckAgentStatement(`SELECT OF(1)`, testScope("mysql")); !errors.Is(err, ErrAgentStatement) {
		t.Errorf("mysql: OF( outside MEMBER OF: %v, want a refusal", err)
	}
}

// TestAgentDatabaseCase: on a server with case-sensitive names, a database
// named like the session's but in another case is another database. The
// session's own name, as the server gives it, is exempt.
func TestAgentDatabaseCase(t *testing.T) {
	scope := testScope("mysql")
	scope.Databases = []string{"shop", "Shop", "information_schema"}
	refused := []string{`SELECT * FROM Shop.customers`, `SHOW TABLES FROM Shop`, `SELECT Shop.discount(1)`, `SELECT * FROM SHOP.customers`}
	for _, q := range refused {
		if err := CheckAgentStatement(q, scope); !errors.Is(err, ErrAgentStatement) {
			t.Errorf("%q: %v, want a refusal", q, err)
		}
	}
	for _, q := range []string{`SELECT * FROM shop.customers`, `SHOW TABLES FROM shop`, `SELECT shop.discount(1)`} {
		if err := CheckAgentStatement(q, scope); err != nil {
			t.Errorf("%q, the session's own name beside another spelling: %v", q, err)
		}
	}
	scope.Databases = nil
	if err := CheckAgentStatement(`SELECT * FROM Shop.customers`, scope); !errors.Is(err, ErrAgentStatement) {
		t.Errorf("another spelling with the list unread: %v, want a refusal", err)
	}
	// Where the server folds case, the name in any case is the session's.
	scope.Databases, scope.FoldCase = []string{"shop", "information_schema"}, true
	for _, q := range []string{`SELECT * FROM SHOP.customers`, `SHOW TABLES FROM Shop`, `SELECT Shop.discount(1)`} {
		if err := CheckAgentStatement(q, scope); err != nil {
			t.Errorf("%q, on a server that folds case: %v", q, err)
		}
	}
}

// TestAgentUnreadDatabases: without the list of databases, a qualifier must
// be one the statement or the session can place.
func TestAgentUnreadDatabases(t *testing.T) {
	scope := testScope("mysql")
	scope.Databases = nil
	for _, q := range []string{`SELECT * FROM unknown.t`, `SELECT unknown.a FROM t`} {
		if err := CheckAgentStatement(q, scope); !errors.Is(err, ErrAgentStatement) {
			t.Errorf("%q: %v, want a refusal", q, err)
		}
	}
	for _, q := range []string{`SELECT c.a FROM customers c`, `SELECT shop.t.a FROM shop.t`, `SELECT customers.a FROM customers`,
		`SELECT d.a FROM (SELECT 1 AS a) d`, `SELECT * FROM information_schema.TABLES`} {
		if err := CheckAgentStatement(q, scope); err != nil {
			t.Errorf("%q: %v", q, err)
		}
	}
}

// TestAgentDatabaseNamedLikeTable: a qualifier that names another database
// is refused even when a table of the session's database has the same name,
// since the server reads other.t as that database's table.
func TestAgentDatabaseNamedLikeTable(t *testing.T) {
	scope := testScope("mysql")
	scope.Tables = append(scope.Tables, "other")
	err := CheckAgentStatement(`SELECT * FROM other.t`, scope)
	if !errors.Is(err, ErrAgentStatement) || !strings.Contains(err.Error(), "a name in another database") {
		t.Errorf("SELECT * FROM other.t, with a table named other: %v, want the other-database refusal", err)
	}
}

// TestAgentWords: the refusal's words never hold the statement, name the
// rule, and give a way out where there is one.
func TestAgentWords(t *testing.T) {
	const canary = "c4n4ry_s3cr3t"
	for _, q := range []string{
		"SELECT * FROM other.t WHERE x = '" + canary + "'",
		"SELECT xyz_exec('" + canary + "')",
		"SHOW PROCESSLIST /* " + canary + " */",
		"SELECT '" + canary + "\\'",
	} {
		err := CheckAgentStatement(q, testScope("mysql"))
		if err == nil || strings.Contains(err.Error(), canary) {
			t.Errorf("%q: %v", q, err)
		}
	}
	for q, want := range map[string]string{
		`SELECT 'a\b'`:              "LIKE … ESCAPE '|'",
		`SHOW TABLES LIKE 'wp\_%'`:  "information_schema.TABLES",
		`SELECT xyz_exec(1)`:        "xyz_exec",
		`SELECT SLEEP(1)`:           "waits",
		`SELECT discount(1)`:        "shop.discount",
		`SHOW TABLES WHERE 1`:       "WHERE",
		`SELECT @@report_password`:  "report_password",
		"SELECT `xé`(1)":            "outside ASCII",
		"SELECT `x-y`(1)":           "a name it doesn't show",
		`DELETE FROM t`:             "not a read",
		`SELECT * FROM mysql.user`:  "mysql",
		`EXPLAIN ANALYZE SELECT 1`:  "EXPLAIN ANALYZE",
		"SELECT a AS `p.name`":      "dot",
		`SELECT * FROM t PROCEDURE`: "PROCEDURE",
	} {
		err := CheckAgentStatement(q, testScope("mysql"))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want words with %q", q, err, want)
		}
	}
}

// TestAgentFunctionsListed: every name the rules refuse by class or name is
// on the list with that class, and the list's own invariants hold.
func TestAgentFunctionsListed(t *testing.T) {
	for name, class := range map[string]funcClass{
		"SLEEP": classWait, "BENCHMARK": classWait, "GET_LOCK": classLock, "RELEASE_ALL_LOCKS": classLock,
		"LOAD_FILE": classFile, "USER": classAccount, "CURRENT_USER": classAccount, "ROLES_GRAPHML": classServer,
		"NOW": classTime, "CURDATE": classTime, "DATABASE": classSession, "CONCAT": classPure,
	} {
		if f, ok := agentFuncs[name]; !ok || f.class != class {
			t.Errorf("%s: %+v, want class %d", name, f, class)
		}
	}
	for name, f := range agentFuncs {
		if f.class < classPure || f.class > classAccount || f.flavors == 0 || f.flavors&^(onMySQL|onMariaDB) != 0 {
			t.Errorf("%s: %+v", name, f)
		}
		if name != strings.ToUpper(name) || !isASCII(name) {
			t.Errorf("%s: not upper-case ASCII", name)
		}
	}
}
