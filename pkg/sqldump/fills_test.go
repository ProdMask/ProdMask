package sqldump

import (
	"slices"
	"testing"
)

const thingsTable = "CREATE TABLE things (id int NOT NULL, note varchar(100), PRIMARY KEY (id));\n"

const thingsSelect = "SELECT 1 AS id, 'a@example.test' AS note UNION ALL SELECT 2, 'b@example.test'"

// A CREATE TABLE whose list is followed by a query, rows or a table fills the
// table from them on the servers: the statement is unread, naming no table.
func TestCreateTableFilledFromAQuery(t *testing.T) {
	const cols = "CREATE TABLE things (id int NOT NULL, note varchar(100), PRIMARY KEY (id))"
	for name, sql := range map[string]string{
		"a query in parentheses": cols + " (" + thingsSelect + ");\n",
		"after a PARTITION, AS":  cols + " PARTITION BY HASH(id) PARTITIONS 2 AS " + thingsSelect + ";\n",
		"after a PARTITION":      cols + " PARTITION BY HASH(id) PARTITIONS 2 " + thingsSelect + ";\n",
		"IGNORE":                 cols + " IGNORE (" + thingsSelect + ");\n",
		"REPLACE":                cols + " REPLACE " + thingsSelect + ";\n",
		"VALUES ROW":             cols + " VALUES ROW(1,'a@example.test'), ROW(2,'b@example.test');\n",
		"TABLE":                  cols + " TABLE src;\n",
		"WITH":                   cols + " WITH q AS (" + thingsSelect + ") SELECT * FROM q;\n",
		"held, IF NOT EXISTS":    thingsTable + "CREATE TABLE IF NOT EXISTS things (id int NOT NULL, note varchar(100), PRIMARY KEY (id)) " + thingsSelect + ";\n",
	} {
		t.Run(name, func(t *testing.T) {
			v, st := readRowsOpts(t, rowsPrelude+"CREATE TABLE src (id int NOT NULL, note varchar(100), PRIMARY KEY (id));\n"+sql, testOpts())
			n := len(v.unread)
			if n != 1 || v.unread[0].Reason != ReasonInsertForm || v.unread[0].Table != "" || v.unread[0].Kind != KindCreateTable || st.Rows != 0 {
				t.Fatalf("unread %+v, %d rows", v.unread, st.Rows)
			}
		})
	}
	// What the tools write after the list stays read: partitions in mysqldump
	// 8.4's and mariadb-dump 11.8's text, a MERGE table's UNION, MariaDB's
	// system versioning and PERIOD FOR.
	for name, sql := range map[string]string{
		"RANGE, mysqldump 8.4": "CREATE TABLE `t_range` (\n  `id` int NOT NULL,\n  `note` varchar(100) DEFAULT NULL,\n  PRIMARY KEY (`id`)\n" +
			") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci\n/*!50100 PARTITION BY RANGE (`id`)\n" +
			"(PARTITION p0 VALUES LESS THAN (10) ENGINE = InnoDB,\n PARTITION p1 VALUES LESS THAN MAXVALUE ENGINE = InnoDB) */;\n",
		"LIST, mysqldump 8.4": "CREATE TABLE `t_list` (\n  `id` int NOT NULL,\n  `note` varchar(100) DEFAULT NULL,\n  PRIMARY KEY (`id`)\n" +
			") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci\n/*!50100 PARTITION BY LIST (`id`)\n" +
			"(PARTITION p0 VALUES IN (1,2) ENGINE = InnoDB,\n PARTITION p1 VALUES IN (3,4) ENGINE = InnoDB) */;\n",
		"subpartitions, mysqldump 8.4": "CREATE TABLE `t_sub` (\n  `id` int NOT NULL,\n  `d` date NOT NULL,\n  `note` varchar(100) DEFAULT NULL,\n" +
			"  PRIMARY KEY (`id`,`d`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci\n" +
			"/*!50100 PARTITION BY RANGE (year(`d`))\nSUBPARTITION BY HASH (to_days(`d`))\nSUBPARTITIONS 2\n" +
			"(PARTITION p0 VALUES LESS THAN (2000) ENGINE = InnoDB,\n PARTITION p1 VALUES LESS THAN MAXVALUE ENGINE = InnoDB) */;\n",
		"LIST, mariadb-dump 11.8": "CREATE TABLE `t_list` (\n  `id` int(11) NOT NULL,\n  `note` varchar(100) DEFAULT NULL,\n  PRIMARY KEY (`id`)\n" +
			") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci\n PARTITION BY LIST (`id`)\n" +
			"(PARTITION `p0` VALUES IN (1,2) ENGINE = InnoDB,\n PARTITION `p1` VALUES IN (3,4) ENGINE = InnoDB);\n",
		"MERGE, mysqldump 8.4": "CREATE TABLE `tm` (\n  `id` int NOT NULL,\n  `note` varchar(100) DEFAULT NULL,\n  KEY `id` (`id`)\n" +
			") ENGINE=MRG_MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci INSERT_METHOD=LAST UNION=(`m1`,`m2`);\n",
		"system versioning, mariadb-dump 11.8": "CREATE TABLE `tv` (\n  `id` int(11) NOT NULL,\n  `note` varchar(100) DEFAULT NULL,\n  PRIMARY KEY (`id`)\n" +
			") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci WITH SYSTEM VERSIONING;\n",
		"PERIOD FOR, mariadb-dump 11.8": "CREATE TABLE `tp` (\n  `id` int(11) NOT NULL,\n  `note` varchar(100) DEFAULT NULL,\n  `s` date NOT NULL,\n" +
			"  `e` date NOT NULL,\n  PERIOD FOR `p` (`s`, `e`),\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;\n",
	} {
		t.Run(name, func(t *testing.T) {
			if v, st := readRowsOpts(t, rowsPrelude+sql, testOpts()); st.Unread != 0 || len(v.calls) != 1 {
				t.Fatalf("unread %+v, %d structures", v.unread, len(v.calls))
			}
		})
	}
	// A partition's own options aren't the table's.
	v, _ := readRowsOpts(t, rowsPrelude+"CREATE TABLE p (id int NOT NULL, PRIMARY KEY (id)) ENGINE=InnoDB COMMENT='tbl'\n"+
		"/*!50100 PARTITION BY RANGE (id) (PARTITION p0 VALUES LESS THAN (10) COMMENT = 'part' ENGINE = MyISAM) */;\n", testOpts())
	if len(v.calls) != 1 || v.calls[0].t.Comment != "tbl" || v.calls[0].t.Engine != "InnoDB" {
		t.Fatalf("calls %+v", v.calls)
	}
}

// A bit-value literal into a column that isn't BIT is the bytes its bits
// make, left-padded with zeros to whole bytes, read as a hex literal's.
func TestBitLiteralsOutsideBit(t *testing.T) {
	ddl := rowsPrelude + "CREATE TABLE t (id int NOT NULL, a varchar(20), b varbinary(4), c bit(9), d bit(3), PRIMARY KEY (id));\n"
	v, st := readRows(t, ddl+"INSERT INTO t VALUES (1,b'0100000101000010',b'01000001',b'101000001',0b101),"+
		"(2,0b1000001,0b0000000001000001,b'1',b'0');\n")
	want := []string{"n:1|s:AB|b:A|t:101000001|t:101", "n:2|s:A|b:\x00A|t:1|t:0"}
	if st.Unread != 0 || !slices.Equal(v.rendered(), want) {
		t.Fatalf("unread %+v, rows %q", v.unread, v.rendered())
	}
}

// Database names that differ only by letter case are one database, shown in
// the file's first spelling.
func TestDatabaseNamesByCase(t *testing.T) {
	const rows = "INSERT INTO things VALUES (1,'a@example.test');\n"
	for name, sql := range map[string]string{
		"USE by another case":     "CREATE DATABASE IF NOT EXISTS shop;\nUSE shop;\nCREATE TABLE first (id int NOT NULL, PRIMARY KEY (id));\nUSE Shop;\n" + thingsTable + rows,
		"a qualified name":        "CREATE DATABASE IF NOT EXISTS shop;\nUSE shop;\n" + thingsTable + "INSERT INTO Shop.things VALUES (1,'a@example.test');\n",
		"CREATE TABLE, qualified": "USE shop;\nCREATE TABLE SHOP.things (id int NOT NULL, note varchar(100), PRIMARY KEY (id));\n" + rows,
	} {
		t.Run(name, func(t *testing.T) {
			v, _ := readRowsOpts(t, rowsPrelude+sql, testOpts())
			if len(v.rows) != 1 || v.rows[0].DB != "shop" || !slices.Equal(v.dbs, []string{"shop"}) {
				t.Fatalf("rows %+v, databases %q", v.rows, v.dbs)
			}
			for _, c := range v.calls {
				if c.db != "shop" {
					t.Fatalf("a structure in %q", c.db)
				}
			}
		})
	}
}

// Values the server fills from an expression are counted with the defaults
// without a literal: a column left out or given DEFAULT whose default is an
// expression, and a generated column.
func TestValuesFilledByExpressions(t *testing.T) {
	for name, c := range map[string]struct {
		sql   string
		count int64
	}{
		"an expression default": {"CREATE TABLE t (id int NOT NULL, note varchar(100) DEFAULT (CONCAT('a','@example.test')), PRIMARY KEY (id));\n" +
			"INSERT INTO t (id) VALUES (1),(2),(3);\n", 3},
		"given DEFAULT": {"CREATE TABLE t (id int NOT NULL, note varchar(100) DEFAULT (uuid()), PRIMARY KEY (id));\nINSERT INTO t VALUES (1,DEFAULT);\n", 1},
		"generated": {"CREATE TABLE t (id int NOT NULL, a varchar(9), b varchar(20) GENERATED ALWAYS AS (concat(a,'x')) VIRTUAL, PRIMARY KEY (id));\n" +
			"INSERT INTO t (id, a) VALUES (1,'p'),(2,'q');\nINSERT INTO t VALUES (3,'r',DEFAULT);\n", 3},
		"a literal default": {"CREATE TABLE t (id int NOT NULL, note varchar(100) DEFAULT 'a@example.test', PRIMARY KEY (id));\n" +
			"INSERT INTO t (id) VALUES (1),(2),(3);\n", 0},
	} {
		t.Run(name, func(t *testing.T) {
			if v, st := readRows(t, rowsPrelude+c.sql); st.Unread != 0 || st.DefaultsNoLiteral != c.count {
				t.Fatalf("unread %+v, %d counted", v.unread, st.DefaultsNoLiteral)
			}
		})
	}
}

// A number into an ENUM or SET is the member its index or mask picks, as the
// servers store it, and so is a quoted, hex or bit literal that spells a
// whole number and names no member. One the servers would map otherwise is
// unread.
func TestNumbersIntoEnumAndSet(t *testing.T) {
	ddl := rowsPrelude + "CREATE TABLE t (id int NOT NULL, e enum('x','a@example.test','b@example.test'), " +
		"s set('a@example.test','b@example.test','c@example.test'), PRIMARY KEY (id));\n"
	v, st := readRows(t, ddl+"INSERT INTO t VALUES (1,2,1),(2,3,6),(3,0,0),(4,'2','3'),(5,0x33,0x34),"+
		"(6,'x','b@example.test,a@example.test'),(7,TRUE,b'00110111'),(8,'123456','x');\n")
	want := []string{
		"n:1|s:a@example.test|s:a@example.test",
		"n:2|s:b@example.test|s:b@example.test,c@example.test",
		"n:3|s:|s:",
		"n:4|s:a@example.test|s:a@example.test,b@example.test",
		"n:5|s:b@example.test|s:c@example.test",
		"n:6|s:x|s:b@example.test,a@example.test",
		"n:7|s:x|s:a@example.test,b@example.test,c@example.test",
		"n:8|s:123456|s:x",
	}
	if st.Unread != 0 || !slices.Equal(v.rendered(), want) {
		t.Fatalf("unread %+v, rows %q", v.unread, v.rendered())
	}
	for name, row := range map[string]string{
		"an index past the members": "(1,4,1)",
		"a bit past the members":    "(1,1,8)",
		"a sign":                    "(1,-1,1)",
		"a decimal point":           "(1,1.5,1)",
		"an exponent":               "(1,1e0,1)",
		"a quoted index past":       "(1,'9',1)",
		"too large":                 "(1,1,18446744073709551616)",
	} {
		t.Run(name, func(t *testing.T) {
			v, st := readRows(t, ddl+"INSERT INTO t VALUES "+row+";\n")
			if st.Unread != 1 || v.unread[0].Reason != ReasonExpression || len(v.rows) != 0 {
				t.Fatalf("unread %+v, %d rows", v.unread, len(v.rows))
			}
		})
	}
}
