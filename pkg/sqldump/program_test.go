package sqldump

import (
	"strings"
	"testing"
)

// programSQL wraps a stored program as mysqldump does, after clientHead; the
// program starts on line 7.
func programSQL(def string) string {
	return clientHead + "DELIMITER ;;\n" + def + ";;\nDELIMITER ;\n"
}

// A stored program whose body follows the grammar is read: the semicolons
// inside the body end no statement.
func TestProgramBodiesStayRead(t *testing.T) {
	for _, c := range []struct {
		name string
		kind Kind
		def  string
	}{
		{"nested if", KindCreateProcedure, `CREATE PROCEDURE p(IN a INT)
BEGIN
  IF a > 0 THEN
    SET @x = 1;
  ELSEIF a < 0 THEN
    IF a < -5 THEN SET @x = -2; ELSE SET @x = -1; END IF;
  ELSE
    SET @x = 0;
  END IF;
END`},
		{"case statements and expressions", KindCreateProcedure, `CREATE PROCEDURE p(a INT)
BEGIN
  CASE a
    WHEN 1 THEN SELECT 'one';
    WHEN CASE WHEN a > 5 THEN 2 ELSE 3 END THEN SELECT 'two'; SELECT 'three';
    ELSE BEGIN END;
  END CASE;
  CASE WHEN a IS NULL THEN SET @y = CASE a WHEN 1 THEN 'x' ELSE 'y' END; END CASE;
  IF CASE WHEN a > 1 THEN TRUE ELSE FALSE END THEN SET @z = 1; END IF;
  WHILE CASE a WHEN 0 THEN FALSE ELSE a < 3 END DO SET a = a + 1; END WHILE;
END`},
		{"labelled loops", KindCreateProcedure, "CREATE PROCEDURE p()\nBEGIN\n  DECLARE i INT DEFAULT 0;\n" +
			"  outer_loop: LOOP\n    SET i = i + 1;\n    IF i > 3 THEN LEAVE outer_loop; END IF;\n" +
			"    inner: WHILE i < 2 DO SET i = i + 1; END WHILE inner;\n" +
			"    rep: REPEAT SET i = i + 1; UNTIL i > 5 END REPEAT rep;\n" +
			"    `quoted label`: BEGIN ITERATE outer_loop; END `quoted label`;\n" +
			"    REPEAT SET i = i + 1; UNTIL CASE WHEN i > 9 THEN 1 ELSE 0 END = 1 END REPEAT;\n" +
			"  END LOOP outer_loop;\nEND"},
		{"mariadb for loops", KindCreateProcedure, "CREATE PROCEDURE p()\nBEGIN\n  FOR i IN 1..3 DO SET @s = i; END FOR;\n" +
			"  lbl: FOR r IN (SELECT 1 AS a) DO SELECT r.a; END FOR lbl;\nEND"},
		{"handlers", KindCreateProcedure, "CREATE PROCEDURE p()\nBEGIN\n  DECLARE done INT DEFAULT FALSE;\n" +
			"  DECLARE c CURSOR FOR SELECT id FROM t;\n" +
			"  DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;\n" +
			"  DECLARE EXIT HANDLER FOR SQLWARNING, 1062, SQLSTATE VALUE '23000', SQLSTATE '42S02', my_cond BEGIN ROLLBACK; RESIGNAL; END;\n" +
			"  DECLARE CONTINUE HANDLER FOR SQLEXCEPTION BEGIN SET @e = 1; END;\n" +
			"  DECLARE UNDO HANDLER FOR SQLEXCEPTION SET @u = 1;\n" +
			"  OPEN c;\n  read_loop: LOOP FETCH c INTO done; IF done THEN LEAVE read_loop; END IF; END LOOP;\n  CLOSE c;\nEND"},
		{"a bare IF trigger", KindCreateTrigger, "CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW IF NEW.id < 0 THEN SET NEW.id = 0; END IF"},
		{"a simple body with a CASE", KindCreateTrigger, "CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.email = CASE WHEN NEW.id > 0 THEN 'a' ELSE 'b' END"},
		{"the IF and REPEAT functions", KindCreateTrigger, "CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.email = IF(NEW.id > 0, REPEAT('a', 2), 'b')"},
		{"IF with parentheses", KindCreateProcedure, "CREATE PROCEDURE p(x INT) BEGIN IF (x) THEN SET @a = IF(x, 1, 2); END IF; WHILE (x > 0) DO SET x = x - 1; END WHILE; END"},
		{"trigger IF NOT EXISTS", KindCreateTrigger, "CREATE TRIGGER IF NOT EXISTS trg BEFORE INSERT ON t FOR EACH ROW SET NEW.id = 1"},
		{"OR REPLACE and FOLLOWS", KindCreateTrigger, "CREATE OR REPLACE DEFINER=`root`@`localhost` TRIGGER trg2 AFTER UPDATE ON t FOR EACH ROW FOLLOWS trg SET @a = 1"},
		{"PRECEDES", KindCreateTrigger, "CREATE TRIGGER d.trg3 BEFORE DELETE ON d.t FOR EACH ROW PRECEDES `trg` BEGIN END"},
		{"function", KindCreateFunction, "CREATE DEFINER=`root`@`localhost` FUNCTION f(a INT) RETURNS varchar(10) CHARSET utf8mb4 DETERMINISTIC\n" +
			"BEGIN\n  DECLARE s VARCHAR(10);\n  SET s = CONCAT('x', a);\n  RETURN s;\nEND"},
		{"function, every characteristic", KindCreateFunction, "CREATE FUNCTION IF NOT EXISTS g(a INT, b VARCHAR(3)) RETURNS int(10) unsigned zerofill " +
			"COMMENT 'a' NOT DETERMINISTIC NO SQL LANGUAGE SQL READS SQL DATA MODIFIES SQL DATA CONTAINS SQL SQL SECURITY DEFINER RETURN a"},
		{"function, a column's type", KindCreateFunction, "CREATE FUNCTION h() RETURNS TYPE OF `d`.`t`.`email` BEGIN DECLARE x INT; RETURN 'a'; END"},
		{"function, a row type", KindCreateFunction, "CREATE FUNCTION h2() RETURNS ROW TYPE OF `d`.`t` BEGIN DECLARE r ROW TYPE OF t; RETURN r; END"},
		{"procedure", KindCreateProcedure, "CREATE DEFINER=`root`@`localhost` PROCEDURE p(IN a INT, OUT b VARCHAR(10))\n" +
			"    COMMENT 'it''s; a comment'\n    SQL SECURITY INVOKER\nBEGIN\n  SELECT a INTO b;\nEND"},
		{"event", KindCreateEvent, "CREATE EVENT e ON SCHEDULE EVERY 1 DAY STARTS '2024-01-01 00:00:00' ON COMPLETION NOT PRESERVE ENABLE " +
			"COMMENT 'nightly' DO BEGIN\n  DELETE FROM t WHERE id < 0;\nEND"},
		{"mysqldump's trigger", KindCreateTrigger, "/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`localhost`*/ /*!50003 TRIGGER `trg` BEFORE INSERT ON `t` FOR EACH ROW BEGIN\n" +
			"  IF NEW.id < 0 THEN\n    SET NEW.id = 0;\n  END IF;\nEND */"},
		{"mysqldump's event", KindCreateEvent, "/*!50106 CREATE*/ /*!50117 DEFINER=`root`@`localhost`*/ /*!50106 EVENT `e` ON SCHEDULE EVERY 1 DAY " +
			"STARTS '2024-01-01 00:00:00' ON COMPLETION NOT PRESERVE ENABLE DO BEGIN\n  DELETE FROM t WHERE id < 0;\nEND */ "},
		{"a loadable function", KindCreateFunction, "CREATE FUNCTION metaphon RETURNS STRING SONAME 'udf_example.so'"},
		{"a loadable aggregate", KindCreateFunction, "CREATE AGGREGATE FUNCTION IF NOT EXISTS avgcost RETURNS REAL SONAME 'udf_example.so'"},
		{"nesting at the cap", KindCreateProcedure, "CREATE PROCEDURE p() " + strings.Repeat("BEGIN ", 256) + strings.Repeat("END; ", 255) + "END"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, st := readSQL(t, programSQL(c.def))
			if st.Unread != 0 || count(st, c.kind) != 1 || st.Known != 4 {
				t.Fatalf("unread %+v, kinds %v, %d known", v.unread, st.ByKind, st.Known)
			}
		})
	}
}

// A stored program followed by another statement before the delimiter, or
// whose body the reader can't follow, is unread and names no table.
func TestProgramBodiesUnread(t *testing.T) {
	for _, c := range []struct {
		name string
		kind Kind
		why  Reason
		def  string
	}{
		{"a simple body, then an INSERT", KindCreateTrigger, ReasonSeveral, "CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.id = NEW.id; " + clientRow},
		{"a trigger's BEGIN, then an INSERT", KindCreateTrigger, ReasonSeveral, "CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.id = 1; END; " + clientRow},
		{"a procedure's BEGIN, then an INSERT", KindCreateProcedure, ReasonSeveral, "CREATE PROCEDURE p() BEGIN SELECT 1; END; " + clientRow},
		{"an event's BEGIN, then an INSERT", KindCreateEvent, ReasonSeveral, "CREATE EVENT e ON SCHEDULE EVERY 1 DAY DO BEGIN SELECT 1; END; " + clientRow},
		{"mysqldump's wrapper, then an INSERT", KindCreateTrigger, ReasonSeveral, "/*!50003 CREATE*/ /*!50003 TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.id = 1 */; " + clientRow},
		{"a label, then an INSERT", KindCreateProcedure, ReasonSeveral, "CREATE PROCEDURE p() lbl: BEGIN SELECT 1; END lbl " + clientRow},
		{"a loadable function, then an INSERT", KindCreateFunction, ReasonSeveral, "CREATE FUNCTION f RETURNS STRING SONAME 'x.so'; " + clientRow},
		{"a BEGIN with no END", KindCreateProcedure, ReasonKind, "CREATE PROCEDURE p() BEGIN SELECT 1; " + clientRow},
		{"a mismatched END LOOP", KindCreateProcedure, ReasonKind, "CREATE PROCEDURE p() BEGIN l: LOOP LEAVE l; END WHILE; " + clientRow + "; END"},
		{"END IF closing a CASE", KindCreateProcedure, ReasonKind, "CREATE PROCEDURE p(a INT) BEGIN CASE a WHEN 1 THEN SELECT 1; END IF; " + clientRow + "; END"},
		{"an expression that meets a semicolon", KindCreateProcedure, ReasonKind, "CREATE PROCEDURE p() BEGIN IF 1; " + clientRow + "; THEN SELECT 1; END IF; END"},
		{"an empty statement", KindCreateProcedure, ReasonKind, "CREATE PROCEDURE p() BEGIN ; " + clientRow + "; END"},
		{"nesting past the cap", KindCreateProcedure, ReasonKind, "CREATE PROCEDURE p() " + strings.Repeat("BEGIN ", 257) + strings.Repeat("END; ", 256) + "END"},
		{"no FOR EACH ROW", KindCreateTrigger, ReasonKind, "CREATE TRIGGER trg BEFORE INSERT ON t; " + clientRow},
		{"an event with no DO", KindCreateEvent, ReasonKind, "CREATE EVENT e ON SCHEDULE EVERY 1 DAY; " + clientRow},
		{"parameters that meet a semicolon", KindCreateProcedure, ReasonKind, "CREATE PROCEDURE p(; " + clientRow + ") SELECT 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, st := readSQL(t, programSQL(c.def))
			if st.Unread != 1 || len(v.unread) != 1 {
				t.Fatalf("unread %d: %+v", st.Unread, v.unread)
			}
			u := v.unread[0]
			if u.Kind != c.kind || u.Reason != c.why || u.Database != "" || u.Table != "" || u.ToEnd || u.Line != 7 || st.Rows != 1 {
				t.Fatalf("unread = %+v, %d rows; want kind %s, reason %q, line 7, no table, 1 row", u, st.Rows, c.kind, c.why)
			}
		})
	}
}
