package dbconn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHash stands for a password hash in MariaDB's SHOW GRANTS lines; it is
// no real hash.
var fakeHash = "'*" + strings.Repeat("A", 40) + "'"

// grantSets are SHOW GRANTS outputs in the shapes MySQL 8.4 and MariaDB
// 11.8 print them (read from both servers on 19 November 2026), each with
// the database the check asks about.
var grantSets = []struct {
	name, db string
	lines    []string
}{
	{"select-only", "shop", []string{
		"GRANT USAGE ON *.* TO `prodmask`@`%`",
		"GRANT SELECT, SHOW VIEW ON `shop`.* TO `prodmask`@`%`"}},
	{"all-on-database", "shop", []string{
		"GRANT ALL PRIVILEGES ON `shop`.* TO `app`@`localhost`"}},
	{"all-on-other-database", "shop", []string{
		"GRANT ALL PRIVILEGES ON `blog`.* TO `app`@`localhost`",
		"GRANT SELECT ON `shop`.* TO `app`@`localhost`"}},
	{"table-level", "shop", []string{
		"GRANT SELECT ON `shop`.* TO `u`@`%`",
		"GRANT INSERT ON `shop`.`log` TO `u`@`%`"}},
	{"mysql-root", "shop", []string{
		"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, SHUTDOWN, PROCESS, FILE, REFERENCES, INDEX, ALTER, SHOW DATABASES, SUPER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, REPLICATION SLAVE, REPLICATION CLIENT, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, CREATE USER, EVENT, TRIGGER, CREATE TABLESPACE, CREATE ROLE, DROP ROLE ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT ALLOW_NONEXISTENT_DEFINER,APPLICATION_PASSWORD_ADMIN,BACKUP_ADMIN,BINLOG_ADMIN,CONNECTION_ADMIN,SYSTEM_VARIABLES_ADMIN,XA_RECOVER_ADMIN ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT PROXY ON ``@`` TO `root`@`localhost` WITH GRANT OPTION"}},
	{"mysql-dynamic-only", "shop", []string{
		"GRANT USAGE ON *.* TO `ops`@`%`",
		"GRANT BACKUP_ADMIN,SYSTEM_VARIABLES_ADMIN ON *.* TO `ops`@`%`"}},
	{"mysql-active-role-merged", "kit_f1", []string{
		"GRANT USAGE ON *.* TO `kit_u1`@`127.0.0.1`",
		"GRANT SELECT, INSERT, UPDATE ON `kit_f1`.* TO `kit_u1`@`127.0.0.1`",
		"GRANT `kit_writer`@`%` TO `kit_u1`@`127.0.0.1`"}},
	{"mysql-role-not-active", "kit_f1", []string{
		"GRANT USAGE ON *.* TO `kit_u2`@`127.0.0.1`",
		"GRANT SELECT ON `kit_f1`.* TO `kit_u2`@`127.0.0.1`",
		"GRANT `kit_writer`@`%` TO `kit_u2`@`127.0.0.1`"}},
	{"mysql-partial-revoke", "kit_f1", []string{
		"GRANT SELECT, INSERT ON *.* TO `kit_u5`@`127.0.0.1`",
		"REVOKE INSERT ON `kit_f1`.* FROM `kit_u5`@`127.0.0.1`"}},
	{"mariadb-root", "shop", []string{
		"GRANT `kit_outer` TO `root`@`localhost` WITH ADMIN OPTION",
		"GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT PROXY ON ``@`%` TO `root`@`localhost` WITH GRANT OPTION"}},
	{"mariadb-role-lines", "kit_f1", []string{
		"GRANT `kit_writer` TO `kit_u1`@`127.0.0.1`",
		"GRANT USAGE ON *.* TO `kit_u1`@`127.0.0.1`",
		"GRANT SELECT ON `kit_f1`.* TO `kit_u1`@`127.0.0.1`",
		"GRANT USAGE ON *.* TO `kit_writer`",
		"GRANT INSERT, UPDATE ON `kit_f1`.* TO `kit_writer`",
		"SET DEFAULT ROLE `kit_writer` FOR `kit_u1`@`127.0.0.1`"}},
	{"mariadb-nested-role", "kit_f1", []string{
		"GRANT `kit_outer` TO `kit_u4`@`127.0.0.1`",
		"GRANT USAGE ON *.* TO `kit_u4`@`127.0.0.1`",
		"GRANT SELECT ON `kit_f1`.* TO `kit_u4`@`127.0.0.1`",
		"GRANT `kit_inner` TO `kit_outer`",
		"GRANT USAGE ON *.* TO `kit_outer`",
		"GRANT USAGE ON *.* TO `kit_inner`",
		"GRANT DELETE ON `kit_f1`.* TO `kit_inner`",
		"SET DEFAULT ROLE `kit_outer` FOR `kit_u4`@`127.0.0.1`"}},
	{"mariadb-public-on-test", "test_shop", []string{
		"GRANT USAGE ON *.* TO `u`@`%`",
		"GRANT SELECT ON `test_shop`.* TO `u`@`%`",
		"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, EVENT, TRIGGER, DELETE HISTORY, SHOW CREATE ROUTINE ON `test`.* TO PUBLIC",
		"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, EVENT, TRIGGER, DELETE HISTORY, SHOW CREATE ROUTINE ON `test\\_%`.* TO PUBLIC"}},
	{"mariadb-public-elsewhere", "shop", []string{
		"GRANT USAGE ON *.* TO `u`@`%`",
		"GRANT SELECT ON `shop`.* TO `u`@`%`",
		"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, EVENT, TRIGGER, DELETE HISTORY, SHOW CREATE ROUTINE ON `test`.* TO PUBLIC"}},
	{"mariadb-password", "shop", []string{
		"GRANT USAGE ON *.* TO `u`@`%` IDENTIFIED BY PASSWORD " + fakeHash,
		"GRANT SELECT ON `shop`.* TO `u`@`%`"}},
	{"mariadb-space-spelled", "kit_f1", []string{
		"GRANT PROCESS, FILE, BINLOG MONITOR, READ_ONLY ADMIN, SLAVE MONITOR ON *.* TO `kit_g1`@`%` WITH GRANT OPTION",
		"GRANT SELECT ON `kit\\_f%`.* TO `kit_g1`@`%`"}},
	{"columns-wildcards-routines", "kit_f1", []string{
		"GRANT PROCESS, FILE ON *.* TO `kit_g1`@`%` WITH GRANT OPTION",
		"GRANT SELECT ON `kit\\_f%`.* TO `kit_g1`@`%`",
		"GRANT SELECT (`id`, `v`), UPDATE (`v`) ON `kit_f1`.`t` TO `kit_g1`@`%`",
		"GRANT EXECUTE ON FUNCTION `kit_f1`.`lk` TO `kit_g1`@`%`"}},
	{"escaped-wildcard-elsewhere", "kitxf1", []string{
		"GRANT SELECT, INSERT ON `kit\\_f%`.* TO `kit_g1`@`%`"}},
	{"wildcard-matches", "shop_eu", []string{
		"GRANT SELECT, INSERT ON `shop%`.* TO `u`@`%`"}},
}

// TestWritePrivilegesGolden pins WritePrivileges' output over grantSets.
// The golden was captured on 4b7d38e's code, before the grant parser was
// shared, and must not change: the scan's warning and Pro read it.
func TestWritePrivilegesGolden(t *testing.T) {
	var b strings.Builder
	for _, s := range grantSets {
		b.WriteString(s.name + ": " + strings.Join(WritePrivileges(s.lines, s.db), ", ") + "\n")
	}
	path := filepath.Join("testdata", "writeprivileges.golden")
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("WritePrivileges' output changed:\n%s\nwant:\n%s", got, want)
	}
}
