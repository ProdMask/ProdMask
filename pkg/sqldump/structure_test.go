package sqldump

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

type ixShape struct {
	name   string
	unique bool
	typ    string
	cols   []string
	subs   []int
}

func shapesOf(tb *model.Table) []ixShape {
	var got []ixShape
	for _, x := range tb.Indexes {
		got = append(got, ixShape{x.Name, x.Unique, x.Type, x.Columns, x.SubParts})
	}
	return got
}

func TestIndexes(t *testing.T) {
	tb := tableOf(t, mysqlHdr+"CREATE TABLE t (\n"+
		"  id int NOT NULL, email varchar(255), body text, title varchar(100), g geometry NOT NULL,\n"+
		"  KEY email_prefix (email(20)),\n"+
		"  KEY body_prefix (body(30), id),\n"+
		"  UNIQUE KEY u (email(10)),\n"+
		"  KEY whole (email(255)),\n"+
		"  KEY fn ((lower(email)), id),\n"+
		"  FULLTEXT KEY ft (title, body) /*!50100 WITH PARSER ngram */,\n"+
		"  SPATIAL KEY sp (g),\n"+
		"  KEY hashed (id) USING HASH COMMENT 'x',\n"+
		"  KEY (title),\n"+
		"  KEY (title, id),\n"+
		"  PRIMARY KEY (id)\n"+
		") ENGINE=InnoDB;", "t")
	want := []ixShape{
		{"PRIMARY", true, "BTREE", []string{"id"}, []int{0}},
		{"email_prefix", false, "BTREE", []string{"email"}, []int{20}},
		{"body_prefix", false, "BTREE", []string{"body", "id"}, []int{30, 0}},
		{"u", true, "BTREE", []string{"email"}, []int{10}},
		{"whole", false, "BTREE", []string{"email"}, []int{0}},
		{"fn", false, "BTREE", []string{"", "id"}, []int{0, 0}},
		{"ft", false, "FULLTEXT", []string{"title", "body"}, []int{0, 0}},
		{"sp", false, "SPATIAL", []string{"g"}, []int{32}},
		{"hashed", false, "BTREE", []string{"id"}, []int{0}},
		{"title", false, "BTREE", []string{"title"}, []int{0}},
		{"title_2", false, "BTREE", []string{"title", "id"}, []int{0, 0}},
	}
	if got := shapesOf(tb); !reflect.DeepEqual(got, want) {
		t.Fatalf("indexes:\n got %+v\nwant %+v", got, want)
	}
	if !reflect.DeepEqual(tb.PrimaryKey, []string{"id"}) {
		t.Errorf("PrimaryKey = %v", tb.PrimaryKey)
	}
	// MEMORY tables use hash keys unless the key says BTREE.
	m := tableOf(t, mysqlHdr+"CREATE TABLE t (a int, b int, KEY ka (a), KEY kb (b) USING BTREE) ENGINE=MEMORY;", "t")
	if m.Indexes[0].Type != "HASH" || m.Indexes[1].Type != "BTREE" {
		t.Errorf("memory table index types: %v %v", m.Indexes[0].Type, m.Indexes[1].Type)
	}
	// What the scan reads from them.
	if u := tb.KeyIndex("body"); !u.Found || u.Full || u.Unique {
		t.Errorf("KeyIndex(body) = %+v", u)
	}
	if u := tb.KeyIndex("email"); !u.Found || !u.Full || u.Unique {
		t.Errorf("KeyIndex(email) = %+v", u)
	}
}

func TestIndexNamesAndCase(t *testing.T) {
	tb := tableOf(t, mysqlHdr+"CREATE TABLE t (Id int NOT NULL, Name varchar(9), CONSTRAINT pk_name PRIMARY KEY (ID), "+
		"CONSTRAINT `uq` UNIQUE (name), UNIQUE INDEX (id, name), KEY USING BTREE (name));", "t")
	var names []string
	for _, x := range tb.Indexes {
		names = append(names, x.Name)
	}
	if !reflect.DeepEqual(names, []string{"PRIMARY", "uq", "Id", "Name"}) {
		t.Fatalf("names %v", names)
	}
	if !reflect.DeepEqual(tb.PrimaryKey, []string{"Id"}) {
		t.Errorf("a key names a column by its own spelling: %v", tb.PrimaryKey)
	}
}

func TestForeignKeys(t *testing.T) {
	tb := tableOf(t, mysqlHdr+"USE shop;\nCREATE TABLE child (id int, a int, b int, c int, "+
		"CONSTRAINT fk_a FOREIGN KEY (a) REFERENCES parent (id) ON DELETE CASCADE ON UPDATE SET NULL, "+
		"CONSTRAINT `fk_b` FOREIGN KEY (b, c) REFERENCES `other`.`p2` (x, y), "+
		"FOREIGN KEY (c) REFERENCES parent (id) MATCH FULL);", "child")
	want := []model.ForeignKey{
		{Name: "fk_a", Columns: []string{"a"}, RefSchema: "shop", RefTable: "parent", RefColumns: []string{"id"}},
		{Name: "fk_b", Columns: []string{"b", "c"}, RefSchema: "other", RefTable: "p2", RefColumns: []string{"x", "y"}},
		{Name: "child_ibfk_3", Columns: []string{"c"}, RefSchema: "shop", RefTable: "parent", RefColumns: []string{"id"}},
	}
	if !reflect.DeepEqual(tb.ForeignKeys, want) {
		t.Fatalf("foreign keys:\n got %+v\nwant %+v", tb.ForeignKeys, want)
	}
	// With no USE the reference has no schema to be in, as the dump has none.
	tb = tableOf(t, mysqlHdr+"CREATE TABLE child (a int, FOREIGN KEY (a) REFERENCES parent (id));", "child")
	if tb.ForeignKeys[0].RefSchema != "" {
		t.Errorf("RefSchema = %q", tb.ForeignKeys[0].RefSchema)
	}
}

func TestTableOptions(t *testing.T) {
	tb := tableOf(t, mysqlHdr+"CREATE TABLE t (a int) ENGINE=MyISAM AUTO_INCREMENT=7 DEFAULT CHARSET=latin1 COLLATE=latin1_bin "+
		"ROW_FORMAT=DYNAMIC COMMENT='it''s a table' STATS_PERSISTENT=DEFAULT\n/*!50100 PARTITION BY HASH (a) PARTITIONS 4 */;", "t")
	if tb.Engine != "MyISAM" || tb.Comment != "it's a table" || tb.Type != "BASE TABLE" {
		t.Fatalf("engine %q comment %q type %q", tb.Engine, tb.Comment, tb.Type)
	}
	tb = tableOf(t, mysqlHdr+"CREATE TABLE t (a int) engine=innodb;", "t")
	if tb.Engine != "InnoDB" {
		t.Errorf("engine %q", tb.Engine)
	}
	tb = tableOf(t, mysqlHdr+"CREATE TABLE t (a int);", "t")
	if tb.Engine != "InnoDB" || tb.Comment != "" {
		t.Errorf("default engine %q comment %q", tb.Engine, tb.Comment)
	}
	tb = tableOf(t, maria11+noMode+"CREATE TABLE t (a int) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 WITH SYSTEM VERSIONING;", "t")
	if tb.Type != "SYSTEM VERSIONED" || !tb.IsData() {
		t.Errorf("type %q", tb.Type)
	}
	tb = tableOf(t, maria11+noMode+"CREATE TABLE s (next_not_cached_value bigint(21) NOT NULL) ENGINE=InnoDB SEQUENCE=1;", "s")
	if tb.Type != "SEQUENCE" {
		t.Errorf("type %q", tb.Type)
	}
	// A comment or a default that holds option words changes nothing.
	tb = tableOf(t, mysqlHdr+"CREATE TABLE t (a varchar(9) DEFAULT 'ENGINE=X', b int COMMENT 'WITH SYSTEM VERSIONING') COMMENT='SEQUENCE=1';", "t")
	if tb.Type != "BASE TABLE" || tb.Engine != "InnoDB" {
		t.Errorf("type %q engine %q", tb.Type, tb.Engine)
	}
}

func TestCreateTableForms(t *testing.T) {
	v, _, st := readTables(t, mysqlHdr+
		"CREATE TABLE IF NOT EXISTS `db`.`a` (x int);\n"+
		"CREATE TABLE b LIKE a;\n"+
		"CREATE TABLE c (LIKE a);\n"+
		"CREATE TABLE d AS SELECT 1;\n"+
		"CREATE TABLE e (x int) SELECT 1;\n"+
		"CREATE TEMPORARY TABLE f (x int);\n", false)
	// A temporary table is unread too: it shadows one of its name.
	if len(v.calls) != 1 || v.calls[0].db != "db" || v.calls[0].t.Name != "a" {
		t.Fatalf("calls %+v", v.calls)
	}
	if len(v.unread) != 5 || st.Structure != 1 {
		t.Fatalf("unread %+v structure %d", v.unread, st.Structure)
	}
	// A list and then a query fills the table from the query.
	for _, u := range v.unread {
		want := ReasonKind
		if u.Line == 7 {
			want = ReasonInsertForm
		}
		if u.Reason != want || u.Table != "" {
			t.Errorf("unread %+v", u)
		}
	}
}

func TestStructureHandedOnce(t *testing.T) {
	v, rd, st := readTables(t, mysqlHdr+"USE shop;\nCREATE TABLE t (a int);\n", false)
	if len(v.calls) != 1 || v.calls[0].db != "shop" || st.Structure != 1 {
		t.Fatalf("calls %+v", v.calls)
	}
	if !rd.isKnown("shop", "t") {
		t.Error("the table is not known")
	}
	if rd.table("shop", "t").t != v.calls[0].t {
		t.Error("the reader's table is not the one handed on")
	}
}

func TestAlterTable(t *testing.T) {
	base := mysqlHdr + "CREATE TABLE t (a int NOT NULL, b varchar(10), c int, KEY kc (c));\n"
	t.Run("keys", func(t *testing.T) {
		tb := tableOf(t, base+"ALTER TABLE t ADD PRIMARY KEY (a), ADD UNIQUE KEY ub (b), ADD KEY kab (a, b), ADD INDEX ic (c), "+
			"ADD FULLTEXT KEY fb (b), ADD CONSTRAINT uq2 UNIQUE (c, b);", "t")
		var names []string
		for _, x := range tb.Indexes {
			names = append(names, x.Name)
		}
		if !reflect.DeepEqual(names, []string{"PRIMARY", "kc", "ub", "kab", "ic", "fb", "uq2"}) {
			t.Fatalf("indexes %v", names)
		}
		if k := tb.Column("a").Key + tb.Column("b").Key + tb.Column("c").Key; k != "PRIUNIMUL" {
			t.Errorf("keys %q", k)
		}
		if !reflect.DeepEqual(tb.PrimaryKey, []string{"a"}) {
			t.Errorf("primary key %v", tb.PrimaryKey)
		}
	})
	t.Run("phpMyAdmin's order", func(t *testing.T) {
		v, _, st := readTables(t, mysqlHdr+"CREATE TABLE `t` (`id` int(11) NOT NULL, `n` varchar(9) NOT NULL) ENGINE=InnoDB;\n"+
			"INSERT INTO `t` VALUES (1, 'a');\n"+
			"ALTER TABLE `t`\n  ADD PRIMARY KEY (`id`),\n  ADD KEY `n` (`n`);\n"+
			"ALTER TABLE `t`\n  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;\n", false)
		if st.Unread != 0 || st.Structure != 3 {
			t.Fatalf("unread %+v, structure %d", v.unread, st.Structure)
		}
		tb := v.last("t")
		if c := tb.Column("id"); c.Key != "PRI" || c.Extra != "auto_increment" || c.ColumnType != "int(11)" {
			t.Errorf("id: %+v", c)
		}
		if tb.Column("n").Key != "MUL" || len(tb.Indexes) != 2 {
			t.Errorf("n: %+v, indexes %+v", tb.Column("n"), tb.Indexes)
		}
		// each statement handed its own structure
		if len(v.calls) != 3 || v.calls[0].t == v.calls[1].t || len(v.calls[0].t.Indexes) != 0 {
			t.Errorf("the first structure changed after it was handed on: %+v", v.calls[0].t.Indexes)
		}
	})
	t.Run("modify", func(t *testing.T) {
		tb := tableOf(t, base+"ALTER TABLE t MODIFY COLUMN b text CHARACTER SET latin1 NOT NULL COMMENT 'x';", "t")
		c := tb.Column("b")
		if c.DataType != "text" || c.Nullable || c.Charset != "latin1" || c.Comment != "x" || c.MaxLength != 65535 || c.Position != 2 {
			t.Errorf("b: %+v", c)
		}
		tb = tableOf(t, base+"ALTER TABLE t MODIFY c int NOT NULL FIRST;", "t")
		if tb.Columns[0].Name != "c" || tb.Columns[0].Position != 1 || tb.Columns[2].Position != 3 || tb.Columns[0].Key != "MUL" {
			t.Errorf("columns %v", []string{tb.Columns[0].Name, tb.Columns[1].Name, tb.Columns[2].Name})
		}
		tb = tableOf(t, base+"ALTER TABLE t MODIFY a int NOT NULL AFTER b;", "t")
		if tb.Columns[0].Name != "b" || tb.Columns[1].Name != "a" || tb.Columns[1].Position != 2 {
			t.Errorf("after: %v %v", tb.Columns[0].Name, tb.Columns[1].Name)
		}
		// MODIFY keeps the table's character set for a column that names none.
		tb = tableOf(t, mysqlHdr+"CREATE TABLE t (a varchar(9)) DEFAULT CHARSET=latin1;\nALTER TABLE t MODIFY a varchar(20);", "t")
		if c := tb.Column("a"); c.Charset != "latin1" || c.MaxLength != 20 {
			t.Errorf("a: %+v", c)
		}
	})
	t.Run("foreign key", func(t *testing.T) {
		tb := tableOf(t, mysqlHdr+"USE s;\nCREATE TABLE t (a int);\nALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES p (id);", "t")
		if len(tb.ForeignKeys) != 1 || tb.ForeignKeys[0].RefSchema != "s" || tb.ForeignKeys[0].Name != "fk" {
			t.Errorf("foreign keys %+v", tb.ForeignKeys)
		}
	})
	t.Run("no change", func(t *testing.T) {
		v, _, st := readTables(t, base+"/*!40000 ALTER TABLE t DISABLE KEYS */;\n/*!40000 ALTER TABLE t ENABLE KEYS */;\nALTER TABLE t AUTO_INCREMENT = 9;\n", false)
		if len(v.calls) != 1 || st.Structure != 4 || st.Unread != 0 {
			t.Errorf("calls %d, structure %d, unread %+v", len(v.calls), st.Structure, v.unread)
		}
	})
	t.Run("a table the dump never created", func(t *testing.T) {
		v, _, st := readTables(t, mysqlHdr+"ALTER TABLE x DISABLE KEYS;\nALTER TABLE x ADD KEY (a);\nALTER TABLE x MODIFY a int;\n", false)
		if st.Structure != 1 || len(v.unread) != 2 || v.unread[0].Reason != ReasonAlter || v.unread[0].Table != "" {
			t.Errorf("structure %d, unread %+v", st.Structure, v.unread)
		}
	})
	for _, sql := range []string{
		"ALTER TABLE t ADD COLUMN d int",
		"ALTER TABLE t ADD d int",
		"ALTER TABLE t DROP COLUMN b",
		"ALTER TABLE t DROP INDEX kc",
		"ALTER TABLE t CHANGE b b2 int",
		"ALTER TABLE t RENAME TO u",
		"ALTER TABLE t ENGINE=MyISAM",
		"ALTER TABLE t CONVERT TO CHARACTER SET latin1",
		"ALTER TABLE t ADD CHECK (a > 0)",
		"ALTER TABLE t ADD PARTITION (PARTITION p9 VALUES LESS THAN (9))",
		"ALTER TABLE t MODIFY nosuch int",
		"ALTER TABLE t MODIFY a int AFTER nosuch",
		"ALTER TABLE t ADD KEY k2 (b), DROP COLUMN c",
		"ALTER TABLE t DISABLE FOO",
		"ALTER TABLE t",
	} {
		t.Run(sql, func(t *testing.T) {
			v, rd, st := readTables(t, base+sql+";\n", false)
			if len(v.unread) != 1 || v.unread[0].Reason != ReasonAlter || st.Unread != 1 || len(v.calls) != 1 {
				t.Fatalf("unread %+v, structure calls %d", v.unread, len(v.calls))
			}
			if u := v.unread[0]; u.Table != "t" || u.Kind != KindAlterTable {
				t.Errorf("unread %+v", u)
			}
			if got := rd.table("", "t").t; len(got.Indexes) != 1 || len(got.Columns) != 3 {
				t.Errorf("a refused ALTER changed the table: %+v", got.Indexes)
			}
		})
	}
}

func TestCreateIndex(t *testing.T) {
	base := mysqlHdr + "CREATE TABLE t (a int NOT NULL, b varchar(100), g geometry NOT NULL);\n"
	tb := tableOf(t, base+"CREATE INDEX ib ON t (b(10), a);\nCREATE UNIQUE INDEX ua ON `t` (a) USING BTREE;\n"+
		"CREATE FULLTEXT INDEX fb ON t (b);\nCREATE SPATIAL INDEX sg ON t (g);\nCREATE INDEX IF NOT EXISTS ia ON t (a DESC) ALGORITHM=INPLACE LOCK=NONE;\n", "t")
	want := []ixShape{
		{"ib", false, "BTREE", []string{"b", "a"}, []int{10, 0}},
		{"ua", true, "BTREE", []string{"a"}, []int{0}},
		{"fb", false, "FULLTEXT", []string{"b"}, []int{0}},
		{"sg", false, "SPATIAL", []string{"g"}, []int{32}},
		{"ia", false, "BTREE", []string{"a"}, []int{0}},
	}
	if got := shapesOf(tb); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if tb.Column("a").Key != "PRI" || tb.Column("b").Key != "MUL" {
		t.Errorf("keys: a=%q b=%q", tb.Column("a").Key, tb.Column("b").Key)
	}
	v, _, st := readTables(t, base+"CREATE INDEX i ON nosuch (a);\nCREATE INDEX i ON db.t (a);\n", false)
	if len(v.unread) != 2 || st.Unread != 2 || v.unread[0].Reason != ReasonAlter {
		t.Errorf("unread %+v", v.unread)
	}
}

const viewBase = "CREATE TABLE base (id int NOT NULL, name varchar(9));\n"

func TestViewPlaceholders(t *testing.T) {
	forms := map[string]string{
		"mysqldump 8.4, a placeholder view": viewBase +
			"/*!50001 DROP VIEW IF EXISTS `v`*/;\n" +
			"SET @saved_cs_client     = @@character_set_client;\nSET character_set_client = utf8mb4;\n" +
			"/*!50001 CREATE VIEW `v` AS SELECT\n 1 AS `id`,\n 1 AS `name`*/;\n" +
			"SET character_set_client = @saved_cs_client;\n" +
			"/*!50001 DROP VIEW IF EXISTS `v`*/;\n" +
			"/*!50001 CREATE ALGORITHM=UNDEFINED */\n/*!50013 DEFINER=`root`@`localhost` SQL SECURITY DEFINER */\n" +
			"/*!50001 VIEW `v` AS select `base`.`id` AS `id`,`base`.`name` AS `name` from `base` */;\n",
		"mariadb-dump 11.8, NULL AS": viewBase +
			"DROP TABLE IF EXISTS `v`;\n/*!50001 DROP VIEW IF EXISTS `v`*/;\n" +
			"/*!50001 CREATE VIEW `v` AS SELECT\n NULL AS `id`,\n NULL AS `name` */;\n" +
			"/*!50001 DROP VIEW IF EXISTS `v`*/;\n" +
			"/*!50001 CREATE ALGORITHM=UNDEFINED */\n/*!50013 DEFINER=`root`@`localhost` SQL SECURITY DEFINER */\n" +
			"/*!50001 VIEW `v` AS select `base`.`id` AS `id`,`base`.`name` AS `name` from `base` */;\n",
		"older mysqldump, a placeholder table": viewBase +
			"DROP TABLE IF EXISTS `v`;\n/*!50001 DROP VIEW IF EXISTS `v`*/;\n" +
			"/*!50001 CREATE TABLE `v` (\n  `id` int(11),\n  `name` varchar(9)\n) ENGINE=MyISAM */;\n" +
			"/*!50001 DROP TABLE IF EXISTS `v`*/;\n/*!50001 DROP VIEW IF EXISTS `v`*/;\n" +
			"/*!50001 CREATE ALGORITHM=UNDEFINED */\n/*!50013 DEFINER=`root`@`localhost` SQL SECURITY DEFINER */\n" +
			"/*!50001 VIEW `v` AS select `base`.`id` AS `id`,`base`.`name` AS `name` from `base` */;\n",
		"a view whose select names no column": viewBase +
			"/*!50001 CREATE VIEW `v` AS SELECT 1 AS `id`, 1 AS `name` */;\nDROP TABLE `v`;\n" +
			"CREATE VIEW `v` AS select * from base;\n",
		"a view with a column list": viewBase +
			"CREATE OR REPLACE VIEW v (id, name) AS SELECT a, b FROM base;\n",
	}
	for name, sql := range forms {
		t.Run(name, func(t *testing.T) {
			v, rd, st := readTables(t, mysqlHdr+sql, false)
			tb := v.last("v")
			if tb == nil || tb.Type != "VIEW" || tb.IsData() || !tb.IsView() {
				t.Fatalf("v = %+v; unread %+v", tb, v.unread)
			}
			var cols []string
			for _, c := range tb.Columns {
				cols = append(cols, c.Name)
			}
			if !reflect.DeepEqual(cols, []string{"id", "name"}) {
				t.Errorf("columns %v", cols)
			}
			if len(tb.Indexes) != 0 || len(tb.PrimaryKey) != 0 || tb.Engine != "" {
				t.Errorf("a view has keys or an engine: %+v", tb)
			}
			if st.Unread != 0 {
				t.Errorf("unread %+v", v.unread)
			}
			if rd.table("", "v").t != tb {
				t.Error("the reader's table is not the last one handed on")
			}
		})
	}
	// A view that names no column and replaces nothing has none.
	v, _, _ := readTables(t, mysqlHdr+"CREATE VIEW w AS SELECT * FROM base;\n", false)
	if w := v.last("w"); w == nil || w.Type != "VIEW" || len(w.Columns) != 0 {
		t.Errorf("w = %+v", w)
	}
	// An alias inside a function or a subquery is not a column of the view.
	v, _, _ = readTables(t, mysqlHdr+"CREATE VIEW w AS SELECT CAST(a AS char) AS x, (SELECT 1 AS y) AS z, a FROM base;\n", false)
	if w := v.last("w"); len(w.Columns) != 2 || w.Columns[0].Name != "x" || w.Columns[1].Name != "z" {
		t.Errorf("w = %+v", w.Columns)
	}
}

func TestSequence(t *testing.T) {
	v, _, st := readTables(t, maria11+noMode+
		"DROP SEQUENCE IF EXISTS `s`;\nCREATE SEQUENCE `s` start with 100 minvalue 1 maxvalue 9223372036854775806 increment by 5 cache 1000 nocycle ENGINE=InnoDB;\n"+
		"DO SETVAL(`s`, 100, 0);\n", false)
	s := v.last("s")
	if s == nil || s.Type != "SEQUENCE" || s.IsData() || s.IsView() {
		t.Fatalf("s = %+v", s)
	}
	if st.Known != 3+1 /* the SET */ || st.Structure != 0 || st.Unread != 0 {
		t.Errorf("known %d structure %d unread %d", st.Known, st.Structure, st.Unread)
	}
}

func TestSecondCreateTable(t *testing.T) {
	first := mysqlHdr + "CREATE TABLE t (a int, b varchar(9));\n"
	t.Run("the same columns", func(t *testing.T) {
		v, _, st := readTables(t, first+"DROP TABLE IF EXISTS t;\nCREATE TABLE t (a int, b varchar(9) COMMENT 'x', KEY (a));\n", true)
		if len(v.calls) != 1 || st.Known != 1+1+1 || st.Unread != 0 || st.Structure != 1 {
			t.Fatalf("calls %d, known %d, structure %d, unread %+v", len(v.calls), st.Known, st.Structure, v.unread)
		}
	})
	t.Run("the same columns in other case", func(t *testing.T) {
		v, _, _ := readTables(t, first+"CREATE TABLE t (A int, B varchar(9));\n", true)
		if len(v.calls) != 1 || len(v.unread) != 0 {
			t.Fatalf("calls %d unread %+v", len(v.calls), v.unread)
		}
	})
	for name, second := range map[string]string{
		"other names":   "CREATE TABLE t (a int, c varchar(9));",
		"more columns":  "CREATE TABLE t (a int, b varchar(9), c int);",
		"fewer":         "CREATE TABLE t (a int);",
		"another order": "CREATE TABLE t (b varchar(9), a int);",
	} {
		t.Run(name, func(t *testing.T) {
			v, rd, st := readTables(t, first+second+"\n", true)
			if len(v.unread) != 1 || v.unread[0].Reason != ReasonRecreate || v.unread[0].Table != "t" || st.Unread != 1 {
				t.Fatalf("unread %+v", v.unread)
			}
			if len(v.calls) != 1 || len(rd.table("", "t").t.Columns) != 2 || rd.table("", "t").t.Columns[0].Name != "a" {
				t.Errorf("the earlier structure was replaced")
			}
		})
	}
	// Servers keep the first table with no rows too.
	t.Run("no rows yet", func(t *testing.T) {
		v, _, st := readTables(t, first+"CREATE TABLE t (a int, c varchar(9));\n", false)
		if len(v.unread) != 1 || v.unread[0].Reason != ReasonRecreate || len(v.calls) != 1 || v.last("t").Columns[1].Name != "b" || st.Structure != 1 {
			t.Fatalf("calls %d, unread %+v", len(v.calls), v.unread)
		}
	})
	t.Run("the set of tables with rows", func(t *testing.T) {
		_, rd, _ := readTables(t, first+"CREATE TABLE u (a int);\n", false)
		rd.markRows("", "u")
		if rd.rowsOf("", "t") || !rd.rowsOf("", "u") || rd.rowsOf("x", "u") {
			t.Error("rowsOf")
		}
	})
}

func TestDropAndTruncateAfterRows(t *testing.T) {
	first := mysqlHdr + "CREATE TABLE t (a int);\nCREATE TABLE u (a int);\n"
	v, _, st := readTables(t, first+"DROP TABLE IF EXISTS t;\nDROP TABLE t, u;\nTRUNCATE TABLE t;\nTRUNCATE u;\n", true)
	if st.Unread != 0 || st.Known != 1+4 {
		t.Fatalf("known %d unread %+v", st.Known, v.unread)
	}
	var drop, trunc int
	for _, w := range v.warns {
		switch w {
		case WarnDropAfterRows:
			drop++
		case WarnTruncateAfterRows:
			trunc++
		}
	}
	if drop != 1 || trunc != 1 || len(v.warns) != 2 {
		t.Errorf("warnings %v", v.warns)
	}
	// With no rows there is nothing to warn about.
	v, _, _ = readTables(t, first+"DROP TABLE t;\nTRUNCATE t;\nDROP VIEW IF EXISTS u;\n", false)
	if len(v.warns) != 0 {
		t.Errorf("warnings %v", v.warns)
	}
	// Another database's rows are not this one's.
	v, _, _ = readTables(t, mysqlHdr+"USE a;\nCREATE TABLE t (a int);\nUSE b;\nDROP TABLE t;\nDROP TABLE a.t;\n", true)
	if len(v.warns) != 1 {
		t.Errorf("warnings %v", v.warns)
	}
}

func TestStructureFaults(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		why       Reason
		alter     bool
	}{
		{"a string that doesn't end", "CREATE TABLE t (a int COMMENT 'abc", ReasonString, false},
		{"the file ends", "CREATE TABLE t (a int, b int", ReasonEOF, false},
		{"the file ends after the list", "CREATE TABLE t (a int) ENGINE=InnoDB", ReasonEOF, false},
		{"a long column name", "CREATE TABLE t (`" + strings.Repeat("a", 300) + "` int);", ReasonIdentLength, false},
		{"a long index name", "CREATE TABLE t (a int, KEY `" + strings.Repeat("a", 300) + "` (a));", ReasonIdentLength, false},
		{"an alter that ends", "CREATE TABLE t (a int);\nALTER TABLE t ADD KEY k (a", ReasonEOF, true},
		{"an alter with a long name", "CREATE TABLE t (a int);\nALTER TABLE t ADD KEY `" + strings.Repeat("a", 300) + "` (a);", ReasonIdentLength, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, rd, st := readTables(t, mysqlHdr+tc.sql, false)
			if len(v.unread) != 1 || v.unread[0].Reason != tc.why || st.Unread != 1 {
				t.Fatalf("unread %+v", v.unread)
			}
			// a statement that failed leaves no half-built table
			if tc.alter {
				if tb := rd.table("", "t"); tb == nil || len(tb.t.Indexes) != 0 || len(v.calls) != 1 {
					t.Errorf("the table changed: %+v", v.calls)
				}
			} else if len(v.calls) != 0 || rd.table("", "t") != nil {
				t.Errorf("structure given: %+v", v.calls)
			}
		})
	}
}

func TestStructureNamesNothingFromTheFile(t *testing.T) {
	const canary = "zq9canary7x"
	v, _, _ := readTables(t, mysqlHdr+
		"CREATE TABLE t (a int COMMENT '"+canary+"', b varchar(9) DEFAULT '"+canary+"') COMMENT='"+canary+"';\n"+
		"CREATE TABLE "+canary+" (a int) SELECT 1;\n"+
		"ALTER TABLE t ADD COLUMN "+canary+" int;\n"+
		"ALTER TABLE t ADD COLUMN c int COMMENT '"+canary+"';\n"+
		"CREATE TABLE t (z int) COMMENT='"+canary+"';\n", true)
	if len(v.unread) != 4 {
		t.Fatalf("unread %+v", v.unread)
	}
	var all []string
	for _, u := range v.unread {
		all = append(all, string(u.Kind), string(u.Reason), u.Database, u.Table)
	}
	all = append(all, v.warns...)
	for _, s := range all {
		if strings.Contains(s, canary) {
			t.Errorf("%q holds text from the dump", s)
		}
	}
}

func TestRealMariaDBDump(t *testing.T) {
	// the start of a real mariadb-dump of a view, a sequence and a table
	v, _, st := readTables(t, "/*M!999999\\- enable the sandbox mode */ \n-- MariaDB dump 10.20-11.8.9-MariaDB, for Win64 (AMD64)\n--\n"+
		"-- Host: 127.0.0.1    Database: d\n-- ------------------------------------------------------\n-- Server version\t11.8.9-MariaDB\n\n"+
		"/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n/*!40101 SET NAMES utf8mb4 */;\n"+
		"/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;\n"+
		"CREATE DATABASE /*!32312 IF NOT EXISTS*/ `d` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;\nUSE `d`;\n"+
		"DROP TABLE IF EXISTS `v`;\n/*!50001 DROP VIEW IF EXISTS `v`*/;\nSET @saved_cs_client     = @@character_set_client;\nSET character_set_client = utf8mb4;\n"+
		"/*!50001 CREATE VIEW `v` AS SELECT\n NULL AS `id`,\n NULL AS `name` */;\nSET character_set_client = @saved_cs_client;\n"+
		"DROP SEQUENCE IF EXISTS `s`;\nCREATE SEQUENCE `s` start with 100 minvalue 1 maxvalue 9223372036854775806 increment by 5 cache 1000 nocycle ENGINE=InnoDB;\nDO SETVAL(`s`, 100, 0);\n"+
		"CREATE TABLE `t` (\n  `a` varchar(9) DEFAULT NULL\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;\n", false)
	if st.Unread != 0 || v.last("v").Type != "VIEW" || v.last("s").Type != "SEQUENCE" || v.header.Producer != "mariadb-dump 11.8.9" {
		t.Fatalf("unread %+v, producer %q", v.unread, v.header.Producer)
	}
	if c := v.last("t").Column("a"); c.Collation != "utf8mb4_unicode_ci" {
		t.Errorf("collation %q", c.Collation)
	}
}
