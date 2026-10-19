package dbconn

import (
	"errors"
	"strings"
	"testing"
)

func TestStatementRules(t *testing.T) {
	sets := []string{
		"SET NAMES binary",
		"SET NAMES utf8mb4 COLLATE utf8mb4_bin",
		"SET CHARACTER SET utf8mb4",
		"SET SESSION sql_mode = ''",
		"SET sql_quote_show_create = 1, @@session.time_zone = '+00:00'",
		"SET LOCAL lock_wait_timeout = 5",
		"SET @@lock_wait_timeout := 5",
		"SET @@LOCAL.net_write_timeout = 60",
		"SET @x = 1, @y := (SELECT COUNT(*) FROM t)",
		"set session show_gipk_in_create_table_and_information_schema = ON;",
		"SET /* note */ SESSION -- why\n sql_mode = ''",
	}
	for _, q := range sets {
		if err := checkStatement(q, true); err != nil {
			t.Errorf("ExecContext(%q) refused: %v", q, err)
		}
	}
	reads := []string{
		"SELECT 1",
		"select * from t where id = ?",
		"(SELECT 1) UNION (SELECT 2)",
		"SHOW CREATE TABLE `shop`.`orders`",
		"SHOW GRANTS",
		"DESCRIBE t", "DESC `t`", "DESCRIBE shop.t",
		"EXPLAIN SELECT * FROM t",
		"EXPLAIN FORMAT=JSON SELECT 1",
		"EXPLAIN ANALYZE SELECT 1",
		"VALUES ROW(1, 2)",
		"TABLE t",
		"WITH c AS (SELECT 1) SELECT * FROM c",
		"WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5), s AS (SELECT 2) SELECT * FROM r, s",
		"WITH c AS (SELECT 1) (SELECT * FROM c)",
		"EXPLAIN WITH c AS (SELECT 1) SELECT * FROM c",
		"SELECT * FROM t FOR SYSTEM_TIME AS OF TIMESTAMP '2020-01-01 00:00:00'",
		"SELECT 'for update', `into`, \"lock in share mode\" FROM `for`",
		"SELECT 1 # FOR UPDATE",
		"SELECT 1 -- INTO @x",
		"SELECT 1 /* INTO @x */",
		"SELECT `a\\b` FROM t",
		"SELECT 'it''s' FROM t",
		"SELECT GET_LOCK(?, 0)",
		"SELECT 1;",
	}
	for _, q := range reads {
		if err := checkStatement(q, false); err != nil {
			t.Errorf("a read %q refused: %v", q, err)
		}
	}

	refusedSets := []string{
		"SELECT 1",
		"COMMIT",
		"ROLLBACK",
		"START TRANSACTION",
		"BEGIN",
		"INSERT INTO t VALUES (1)",
		"SET autocommit = 1",
		"SET @@autocommit = 1",
		"SET SESSION autocommit = 1",
		"SET @@session.autocommit = 1",
		"SET @ @ session . autocommit = 1",
		"SET LOCAL completion_type = 2",
		"SET sql_mode = '', autocommit = 1",
		"SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
		"SET SESSION TRANSACTION READ WRITE",
		"SET transaction_isolation = 'READ-COMMITTED'",
		"SET @@tx_read_only = 0",
		"SET transaction_read_only = 0",
		"SET GLOBAL max_connections = 10",
		"SET @@global.max_connections = 10",
		"SET sql_mode = '', GLOBAL max_connections = 10",
		"SET PERSIST max_connections = 10",
		"SET PERSIST_ONLY max_connections = 10",
		"SET @@persist.max_connections = 10",
		"SET PASSWORD = 'x'",
		"SET PASSWORD FOR u = 'x'",
		"SET ROLE ALL",
		"SET DEFAULT ROLE ALL TO u",
		"SET STATEMENT max_statement_time = 1 FOR SELECT 1",
		"SET RESOURCE GROUP g",
		"SET `autocommit` = 1",
		"SET hot_cache.key_buffer_size = 1",
		"SET @x = (SELECT a FROM t FOR UPDATE)",
		"SET @x = (SELECT a FROM t LOCK IN SHARE MODE)",
		"SET @x = 1 INTO @y",
		"SET sql_mode",
		"SET",
		"SET NAMES binary; COMMIT",
		"SET /*!40101 autocommit = 1 */ @x = 1",
		"SET @x = 'a\\'', autocommit = 1 -- '",
		"",
		"   ",
		"-- nothing",
	}
	for _, q := range refusedSets {
		if err := checkStatement(q, true); !errors.Is(err, ErrStatementRefused) {
			t.Errorf("ExecContext(%q) not refused: %v", q, err)
		}
	}
	refusedReads := []string{
		"SET NAMES binary",
		"INSERT INTO t VALUES (1)",
		"UPDATE t SET a = 1",
		"DELETE FROM t",
		"REPLACE INTO t VALUES (1)",
		"CALL p()",
		"DO SLEEP(1)",
		"COMMIT",
		"LOCK TABLES t READ",
		"FLUSH TABLES",
		"KILL 5",
		"HANDLER t OPEN",
		"ANALYZE TABLE t",
		"ANALYZE SELECT 1",
		"CHECKSUM TABLE t",
		"USE shop",
		"SELECT * FROM t FOR UPDATE",
		"SELECT * FROM t FOR UPDATE SKIP LOCKED",
		"SELECT * FROM t FOR SHARE",
		"SELECT * FROM t LOCK IN SHARE MODE",
		"SELECT * FROM t FOR /* x */ UPDATE",
		"SELECT * FROM (SELECT * FROM t FOR UPDATE) x",
		"SELECT 1 INTO @x",
		"SELECT * FROM t INTO OUTFILE '/tmp/x'",
		"SELECT * INTO DUMPFILE '/tmp/x' FROM t",
		"SELECT /*! SLEEP(1) */ 1",
		"SELECT /*!50000 1 */",
		"SELECT /*M!100100 1 */",
		"SELECT /*+ SET_VAR(sql_mode='') */ 1",
		"SELECT 1 /* unterminated",
		"SELECT 'unterminated",
		"SELECT 'a\\' FROM t -- '",
		"SELECT \"a\\\" INTO @x -- \"",
		"SELECT 1; SELECT 2",
		"SELECT 1; COMMIT",
		"WITH c AS (SELECT 1) UPDATE t SET a = 1",
		"WITH c AS (SELECT 1) DELETE FROM t",
		"WITH c AS (SELECT 1)",
		"WITH c SELECT 1",
		"EXPLAIN UPDATE t SET a = 1",
		"EXPLAIN ANALYZE UPDATE t SET a = 1",
		"EXPLAIN ANALYZE DELETE FROM t",
		"EXPLAIN FORMAT=TREE ANALYZE INSERT INTO t VALUES (1)",
		"EXPLAIN FOR CONNECTION 5",
		"DESCRIBE REPLACE INTO t VALUES (1)",
		"EXPLAIN",
		"(UPDATE t SET a = 1)",
		"",
	}
	for _, q := range refusedReads {
		if err := checkStatement(q, false); !errors.Is(err, ErrStatementRefused) {
			t.Errorf("a query %q not refused: %v", q, err)
		}
	}
}

// TestStatementRefusalsQuoteNothing checks that a refusal never repeats
// the statement it refused.
func TestStatementRefusalsQuoteNothing(t *testing.T) {
	const canary = "zq7canary"
	for _, q := range []string{
		"UPDATE t SET a = '" + canary + "'",
		"SELECT '" + canary + "' INTO @x",
		"SET GLOBAL " + canary + " = 1",
		"SELECT /*! " + canary + " */ 1",
	} {
		for _, exec := range []bool{true, false} {
			if err := checkStatement(q, exec); err == nil || strings.Contains(err.Error(), canary) {
				t.Errorf("%q: %v", q, err)
			}
		}
	}
}
