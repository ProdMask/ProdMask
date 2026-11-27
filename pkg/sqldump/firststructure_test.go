package sqldump

import (
	"slices"
	"testing"
)

const peopleTable = "SET sql_mode='';\nCREATE TABLE people (id int NOT NULL, email varchar(100), PRIMARY KEY (id));\n"

const peopleRows = "INSERT INTO people VALUES (1,'a@example.test'),(2,'b@example.test');\n"

// emailTypes gives the type of the email column in the structure each row of
// people was read against.
func emailTypes(v *rrec) []string {
	var out []string
	for _, r := range v.rows {
		for _, c := range r.Struct.Columns {
			if c.Name == "email" {
				out = append(out, c.DataType)
			}
		}
	}
	return out
}

// A whole statement in an uncertain comment may be only a SET or an ANALYZE.
// Any other is unread and changes nothing the reader holds, so the table
// keeps its first structure and the rows after it are read against that.
func TestWholeVersionCommentsChangeNothing(t *testing.T) {
	for name, sql := range map[string]string{
		"ALTER TABLE":                "/*!99999 ALTER TABLE people MODIFY email blob */;\n",
		"CREATE TABLE IF NOT EXISTS": "/*M!100100 CREATE TABLE IF NOT EXISTS people (id int NOT NULL, email blob, PRIMARY KEY (id)) */;\n",
		"CREATE OR REPLACE TABLE":    "/*!99999 CREATE OR REPLACE TABLE people (id int NOT NULL, email blob, PRIMARY KEY (id)) */;\n",
		"DROP TABLE":                 "/*!99999 DROP TABLE people */;\n",
		"CREATE OR REPLACE VIEW":     "/*!99999 CREATE OR REPLACE VIEW people AS SELECT 1 AS id, 2 AS email */;\n",
		"INSERT":                     "/*!99999 INSERT INTO people VALUES (9,'c@example.test') */;\n",
		"AUTO_INCREMENT":             "/*!99999 ALTER TABLE people AUTO_INCREMENT=5 */;\n",
		"CREATE INDEX":               "/*!99999 CREATE UNIQUE INDEX u ON people (email) */;\n",
	} {
		t.Run(name, func(t *testing.T) {
			v, st := readRowsOpts(t, peopleTable+sql+peopleRows, testOpts())
			if st.Unread != 1 || v.unread[0].Reason != ReasonVersion || v.unread[0].Line != 3 || v.unread[0].Table != "" ||
				len(v.calls) != 1 || len(v.rows) != 2 || !slices.Equal(emailTypes(v), []string{"varchar", "varchar"}) ||
				len(v.calls[0].t.Indexes) != 1 {
				t.Fatalf("unread %+v, %d structures, rows %q", v.unread, len(v.calls), emailTypes(v))
			}
		})
	}
	// No counter moves: the key the server counts is 1, not 5.
	v, _ := readRowsOpts(t, "SET sql_mode='';\nCREATE TABLE s (id int NOT NULL AUTO_INCREMENT, n int, PRIMARY KEY (id));\n"+
		"/*!99999 ALTER TABLE s AUTO_INCREMENT=5 */;\nINSERT INTO s (n) VALUES (1);\n", testOpts())
	if len(v.rows) != 1 || v.rows[0].Values[0].Bytes != "1" {
		t.Fatalf("counter: rows %+v", v.rows)
	}
	// A whole CREATE first is unread and creates nothing; the plain one
	// after it creates the table.
	v, st := readRowsOpts(t, "SET sql_mode='';\n/*!99999 CREATE TABLE people (id int NOT NULL, email blob, PRIMARY KEY (id)) */;\n"+
		"CREATE TABLE IF NOT EXISTS people (id int NOT NULL, email varchar(100), PRIMARY KEY (id));\n"+peopleRows, testOpts())
	if st.Unread != 1 || len(v.calls) != 1 || !slices.Equal(emailTypes(v), []string{"varchar", "varchar"}) {
		t.Fatalf("a whole CREATE in a version comment, then a plain one: unread %+v, %d structures, rows %q", v.unread, len(v.calls), emailTypes(v))
	}
}

// A second CREATE for a table or view the reader holds, with no DROP between
// and no OR REPLACE, keeps the first structure, as servers do: known with the
// same columns, unread with others. A view over a held table is unread.
func TestSecondCreateKeepsTheFirst(t *testing.T) {
	for name, sql := range map[string]string{
		"IF NOT EXISTS":              "CREATE TABLE IF NOT EXISTS people (id int NOT NULL, email blob, PRIMARY KEY (id));\n",
		"a view, IF NOT EXISTS":      "CREATE VIEW IF NOT EXISTS people AS SELECT 1 AS id, 2 AS email;\n",
		"IF NOT EXISTS in a comment": "CREATE TABLE /*!32312 IF NOT EXISTS*/ people (id int NOT NULL, email blob, PRIMARY KEY (id));\n",
		"plain, other columns":       "CREATE TABLE people (id int NOT NULL, note varchar(10), PRIMARY KEY (id));\n",
		"a view, OR REPLACE":         "CREATE OR REPLACE VIEW people AS SELECT 1 AS id, 2 AS email;\n",
	} {
		t.Run(name, func(t *testing.T) {
			v, st := readRowsOpts(t, peopleTable+sql+peopleRows, testOpts())
			if st.Unread != 1 || v.unread[0].Reason != ReasonRecreate || len(v.calls) != 1 ||
				!slices.Equal(emailTypes(v), []string{"varchar", "varchar"}) {
				t.Fatalf("unread %+v, %d structures, rows %q", v.unread, len(v.calls), emailTypes(v))
			}
		})
	}
	for _, c := range []struct {
		name, sql string
		calls     int
		email     string
	}{
		{"the same columns", "CREATE TABLE IF NOT EXISTS people (id int NOT NULL, email varchar(100), PRIMARY KEY (id));\n", 1, "varchar"},
		{"OR REPLACE with no rows", "CREATE OR REPLACE TABLE people (id int NOT NULL, email blob, PRIMARY KEY (id));\n", 2, "blob"},
		{"a DROP, then a CREATE", "DROP TABLE people;\nCREATE TABLE people (id int NOT NULL, email blob, PRIMARY KEY (id));\n", 2, "blob"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, st := readRowsOpts(t, peopleTable+c.sql+peopleRows, testOpts())
			if st.Unread != 0 || len(v.calls) != c.calls || !slices.Equal(emailTypes(v), []string{c.email, c.email}) {
				t.Fatalf("unread %+v, %d structures, rows %q", v.unread, len(v.calls), emailTypes(v))
			}
		})
	}
	// The placeholders the tools write drop before they create the view.
	for name, sql := range map[string]string{
		"mysqldump 8.4": "CREATE VIEW v AS SELECT 1 AS id, 1 AS email;\n/*!50001 DROP VIEW IF EXISTS v*/;\n" +
			"/*!50001 CREATE ALGORITHM=UNDEFINED */ /*!50013 DEFINER=`root`@`localhost` SQL SECURITY DEFINER */ /*!50001 VIEW v AS select id, email from people */;\n",
		"old mysqldump": "/*!50001 CREATE TABLE `v` (`id` int, `email` varchar(100)) ENGINE=MyISAM */;\n/*!50001 DROP TABLE IF EXISTS `v`*/;\n" +
			"/*!50001 DROP VIEW IF EXISTS `v`*/;\n/*!50001 CREATE ALGORITHM=UNDEFINED */ /*!50001 VIEW `v` AS select `id`, `email` from `people` */;\n",
		"phpMyAdmin": "CREATE TABLE `v` (`id` int, `email` varchar(100));\nDROP TABLE IF EXISTS `v`;\n" +
			"CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v` AS SELECT `id` AS `id`, `email` AS `email` FROM `people`;\n",
	} {
		t.Run(name, func(t *testing.T) {
			if v, st := readRowsOpts(t, peopleTable+sql+peopleRows, testOpts()); st.Unread != 0 || v.last("v").Type != "VIEW" {
				t.Fatalf("unread %+v", v.unread)
			}
		})
	}
}
