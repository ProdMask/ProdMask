package sqldump

import "strings"

// shapesDDL is the dump-shapes fixture: the objects a dump of a real
// database holds that the other fixtures don't, and the table shapes the
// structure reader has to follow. mariadb says which server it is for; the
// two differ in the syntax of a few columns and in what each has (sequences
// and system versioning on MariaDB, functional keys on MySQL).
//
// Each entry is one statement. The trigger, which is created while the
// session's SQL mode differs from the server's, is built apart, by
// shapesTrigger.
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

// shapesTrigger creates a trigger under an SQL mode the session sets and
// the server's own differs from, as a dump of a trigger records it.
func shapesTrigger() (mode, create string) {
	return "ANSI_QUOTES,NO_BACKSLASH_ESCAPES,STRICT_TRANS_TABLES",
		`CREATE TRIGGER shape_trigger BEFORE INSERT ON shape_latin1 FOR EACH ROW SET NEW.name = "x"`
}

// multisiteDDL is the multisite fixture's tables, as
// pkg/scan/integration_test.go's TestWordPressMultisite makes them.
func multisiteDDL() []string {
	s := []string{
		"CREATE TABLE wp_users (ID bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, user_login varchar(60) NOT NULL DEFAULT '')",
	}
	for _, p := range []string{"wp_", "wp_2_"} {
		s = append(s,
			"CREATE TABLE "+p+"options (option_id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, "+
				"option_name varchar(191) NOT NULL DEFAULT '', option_value longtext NOT NULL, UNIQUE KEY option_name (option_name))",
			"CREATE TABLE "+p+"posts (ID bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, "+
				"post_type varchar(20) NOT NULL DEFAULT 'post', post_password varchar(255) NOT NULL DEFAULT '')",
			"CREATE TABLE "+p+"postmeta (meta_id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY, "+
				"post_id bigint unsigned NOT NULL DEFAULT 0, meta_key varchar(255) DEFAULT NULL, meta_value longtext)",
		)
	}
	return s
}

// fitsDDL is the tables of pkg/scan/fit_integration_test.go's TestStarterFits.
func fitsDDL() []string {
	return []string{
		"CREATE TABLE fraud_rules (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, rule_email char(1) NULL, " +
			"rule_amount char(1) NULL) ENGINE=InnoDB",
		"CREATE TABLE brokers (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, user_agent varchar(255) NOT NULL, " +
			"UNIQUE KEY user_agent (user_agent)) ENGINE=InnoDB",
		"CREATE TABLE towns (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, city varchar(50) NOT NULL, " +
			"UNIQUE KEY city (city)) ENGINE=InnoDB",
		"CREATE TABLE branches (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, city char(2) NOT NULL, " +
			"UNIQUE KEY city (city)) ENGINE=InnoDB",
		"CREATE TABLE partners (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, api_key char(2) NOT NULL, " +
			"UNIQUE KEY api_key (api_key)) ENGINE=InnoDB",
		"CREATE TABLE contacts (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, email varchar(255) NOT NULL, " +
			"UNIQUE KEY email (email(10))) ENGINE=InnoDB",
	}
}

func quoteIdent(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }
