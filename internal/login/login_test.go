package login

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/model"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name     string
		db       string
		active   []string
		lines    []string
		canWrite bool
	}{
		{"select only", "shop", nil, []string{
			"GRANT USAGE ON *.* TO `p`@`%`", "GRANT SELECT, SHOW VIEW ON `shop`.* TO `p`@`%`"}, false},
		{"all on the database", "shop", nil, []string{"GRANT ALL PRIVILEGES ON `shop`.* TO `a`@`%`"}, true},
		{"all elsewhere", "shop", nil, []string{
			"GRANT ALL PRIVILEGES ON `blog`.* TO `a`@`%`", "GRANT SELECT ON `shop`.* TO `a`@`%`"}, false},
		{"a table's insert", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT INSERT ON `shop`.`log` TO `u`@`%`"}, true},
		{"dynamic only", "shop", nil, []string{"GRANT BACKUP_ADMIN,SYSTEM_VARIABLES_ADMIN ON *.* TO `o`@`%`"}, true},
		{"FILE only", "shop", nil, []string{"GRANT FILE ON *.* TO `f`@`%`", "GRANT SELECT ON `shop`.* TO `f`@`%`"}, true},
		{"SUPER only", "shop", nil, []string{"GRANT SUPER ON *.* TO `s`@`%`", "GRANT SELECT ON `shop`.* TO `s`@`%`"}, true},
		{"PROCESS is reported, not refused", "shop", nil, []string{"GRANT PROCESS ON *.* TO `p`@`%`", "GRANT SELECT ON `shop`.* TO `p`@`%`"}, false},
		{"active role merged (MySQL)", "kit_f1", []string{"`kit_writer`@`%`"}, []string{
			"GRANT USAGE ON *.* TO `u`@`h`", "GRANT SELECT, INSERT, UPDATE ON `kit_f1`.* TO `u`@`h`", "GRANT `kit_writer`@`%` TO `u`@`h`"}, true},
		{"role not active (MySQL)", "kit_f1", []string{"NONE"}, []string{
			"GRANT USAGE ON *.* TO `u`@`h`", "GRANT SELECT ON `kit_f1`.* TO `u`@`h`", "GRANT `kit_writer`@`%` TO `u`@`h`"}, false},
		{"role's own lines (MariaDB)", "kit_f1", []string{"kit_writer"}, []string{
			"GRANT `kit_writer` TO `u`@`h`", "GRANT SELECT ON `kit_f1`.* TO `u`@`h`", "GRANT INSERT, UPDATE ON `kit_f1`.* TO `kit_writer`",
			"SET DEFAULT ROLE `kit_writer` FOR `u`@`h`"}, true},
		{"partial revoke never helps", "kit_f1", nil, []string{
			"GRANT SELECT, INSERT ON *.* TO `u`@`h`", "REVOKE INSERT ON `kit_f1`.* FROM `u`@`h`"}, true},
		{"PUBLIC on test_ (MariaDB)", "test_shop", nil, []string{
			"GRANT SELECT ON `test_shop`.* TO `u`@`%`", "GRANT SELECT, INSERT, DROP ON `test\\_%`.* TO PUBLIC"}, true},
		{"PUBLIC elsewhere (MariaDB)", "shop", nil, []string{
			"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT SELECT, INSERT, DROP ON `test\\_%`.* TO PUBLIC"}, false},
		{"MariaDB's monitors served, its admin refused", "shop", nil, []string{
			"GRANT BINLOG MONITOR, SLAVE MONITOR ON *.* TO `m`@`%`", "GRANT SELECT ON `shop`.* TO `m`@`%`"}, false},
		{"READ_ONLY ADMIN", "shop", nil, []string{"GRANT READ_ONLY ADMIN ON *.* TO `m`@`%`"}, true},
		{"an unknown privilege", "shop", nil, []string{"GRANT FROBNICATE THINGS ON *.* TO `u`@`%`"}, true},
		{"an unreadable line", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "something new"}, true},
		{"grant option", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%` WITH GRANT OPTION"}, true},
		{"proxy", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT PROXY ON ``@`` TO `u`@`%`"}, true},
		{"insert on the mysql schema", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT INSERT ON `mysql`.* TO `u`@`%`"}, true},
		{"update on mysql.user", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT UPDATE ON `mysql`.`user` TO `u`@`%`"}, true},
		{"insert on a pattern that takes in mysql", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT INSERT ON `my%`.* TO `u`@`%`"}, true},
		{"select on the mysql schema is reported, not refused", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT SELECT ON `mysql`.* TO `u`@`%`"}, false},
		{"lock tables on the mysql schema", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT SELECT, LOCK TABLES ON `mysql`.* TO `u`@`%`"}, false},
		{"temporary tables and monitoring are served", "shop", nil, []string{"GRANT SELECT, CREATE TEMPORARY TABLES ON `shop`.* TO `u`@`%`",
			"GRANT REPLICATION CLIENT ON *.* TO `u`@`%`"}, false},
		{"SHOW CREATE ROUTINE isn't served (MariaDB)", "shop", nil, []string{"GRANT SELECT, SHOW CREATE ROUTINE ON `shop`.* TO `u`@`%`"}, true},
		{"a role WITH ADMIN OPTION", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT `r1`@`%` TO `u`@`%` WITH ADMIN OPTION"}, true},
		{"grant option on the mysql schema", "shop", nil, []string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT SELECT ON `mysql`.* TO `u`@`%` WITH GRANT OPTION"}, true},
	}
	for _, c := range cases {
		l := Classify(dbconn.ParseGrants(c.lines), c.db, c.active)
		if l.CanWrite() != c.canWrite {
			t.Errorf("%s: CanWrite %v, want %v: %+v", c.name, l.CanWrite(), c.canWrite, l)
		}
	}
	l := Classify(dbconn.ParseGrants([]string{
		"GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, SHUTDOWN, PROCESS, FILE, REFERENCES, INDEX, ALTER, SHOW DATABASES, SUPER, LOCK TABLES, EXECUTE, REPLICATION SLAVE, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, CREATE USER, EVENT, TRIGGER ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT BACKUP_ADMIN,SYSTEM_VARIABLES_ADMIN ON *.* TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT PROXY ON ``@`` TO `root`@`localhost` WITH GRANT OPTION",
		"GRANT ALL PRIVILEGES ON `blog`.* TO `root`@`localhost`",
	}), "shop", nil)
	if !reflect.DeepEqual(l.ChangeData, []string{"DELETE", "INSERT", "LOCK TABLES", "UPDATE"}) ||
		!reflect.DeepEqual(l.ChangeSchema, []string{"ALTER", "ALTER ROUTINE", "CREATE", "CREATE ROUTINE", "CREATE VIEW", "EVENT", "INDEX", "REFERENCES", "TRIGGER"}) ||
		!reflect.DeepEqual(l.Drop, []string{"DROP"}) || l.Files != "unknown" || !l.Process || !l.SystemTables || l.OtherDatabases != 1 {
		t.Errorf("root: %+v", l)
	}
	for _, want := range []string{"BACKUP_ADMIN", "CREATE USER", "GRANT OPTION", "PROXY", "RELOAD", "REPLICATION SLAVE", "SHUTDOWN", "SUPER", "SYSTEM_VARIABLES_ADMIN"} {
		if !slices.Contains(l.Admin, want) {
			t.Errorf("root's admin lacks %s: %v", want, l.Admin)
		}
	}
	if !slices.Contains(l.Admin, "INSERT on the mysql schema") || slices.Contains(l.Admin, "FILE on the mysql schema") ||
		slices.Contains(l.Admin, "ALL PRIVILEGES on the mysql schema") {
		t.Errorf("root's writes on the mysql schema: %v", l.Admin)
	}
	l = Classify(dbconn.ParseGrants([]string{"GRANT SELECT ON `shop`.* TO `u`@`%`", "GRANT INSERT, DROP ON `mysql`.* TO `u`@`%`"}), "shop", nil)
	if !reflect.DeepEqual(l.Admin, []string{"DROP on the mysql schema", "INSERT on the mysql schema"}) || len(l.ChangeData) > 0 || len(l.Drop) > 0 {
		t.Errorf("writes on the mysql schema alone: %+v", l)
	}
	if l := Classify(dbconn.ParseGrants([]string{"GRANT `r1` TO `u`@`%` WITH ADMIN OPTION"}), "shop", nil); !slices.Contains(l.Admin, "ADMIN OPTION on a role") {
		t.Errorf("a role's ADMIN OPTION: %v", l.Admin)
	}
	if l := Classify(dbconn.ParseGrants([]string{"GRANT `r1`@`%`,`r2`@`%` TO `u`@`%`"}), "shop", []string{"`r1`@`%`"}); l.RolesNotActive != 1 {
		t.Errorf("roles not active: %d, want 1", l.RolesNotActive)
	}
	if l := Classify(dbconn.ParseGrants([]string{"GRANT FROBNICATE THINGS ON *.* TO `u`@`%`"}), "shop", nil); len(l.NotRead) == 0 {
		t.Errorf("an unknown privilege isn't listed as not read: %+v", l)
	}
}

func TestMarkerWords(t *testing.T) {
	cases := []struct {
		m    Marker
		want string
	}{
		{Marker{}, "no prodmask copy marker"},
		{Marker{Found: true}, "couldn't be read"},
		{Marker{Found: true, State: "incomplete"}, "isn't complete"},
		{Marker{Found: true, State: "complete", Masking: "none"}, "no masking"},
		{Marker{Found: true, State: "complete", Masking: "fpe"}, "couldn't be read"},
		{Marker{Found: true, Holds: true, State: "complete", Masking: "stable", Tool: "prodmask Pro 1.0.0", Finished: "2026-11-18 10:00:00"},
			"masked with a stable key, made by prodmask Pro 1.0.0 on 2026-11-18 10:00:00 UTC."},
		{Marker{Found: true, Holds: true, State: "complete", Masking: "per-run", Tool: "prodmask Pro 1.0.0"}, "a key for this run only, made by prodmask Pro 1.0.0."},
		{Marker{Found: true, Holds: true, State: "complete", Masking: "stable", Tool: "evil\x1b[2Jtool"}, "made by evil?[2Jtool."},
		{Marker{Found: true, Holds: true, State: "complete", Masking: "stable", Tool: strings.Repeat("a", 200)}, strings.Repeat("a", 60) + "…."},
		{Marker{Found: true, Holds: true, State: "complete", Masking: "stable", Finished: "2026-11-18T10:05:00.5Z"}, "finished on 2026-11-18 10:05:00 UTC"},
		{Marker{Found: true, Holds: true, State: "complete", Masking: "stable"}, "masked with a stable key. It's"},
	}
	for _, c := range cases {
		if got := c.m.Words(); !strings.Contains(got, c.want) {
			t.Errorf("%+v: %q, want %q", c.m, got, c.want)
		}
	}
}

func TestRefusal(t *testing.T) {
	if got := Refusal(&model.Login{Process: true, OtherDatabases: 2, RolesNotActive: 1}, "shop"); got != "" {
		t.Errorf("a login that can only read is refused: %q", got)
	}
	got := Refusal(&model.Login{ChangeData: []string{"ALL PRIVILEGES", "INSERT"}, Drop: []string{"ALL PRIVILEGES"}, Files: "off",
		Admin: []string{"SUPER"}, NotRead: []string{"a privilege prodmask doesn't know"}}, "sh`op\x1b")
	for _, want := range []string{
		"prodmask mcp won't serve this login: it can change `sh``op?` (ALL PRIVILEGES, INSERT); it holds FILE",
		"it can administer the server (SUPER); prodmask couldn't read all it can do (a privilege prodmask doesn't know).",
		"Ask the person who set this up for a login that can only read; don't change this server's settings yourself.",
		"GRANT SELECT, SHOW VIEW ON `sh``op?`.* TO 'agent'@'%';",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the refusal %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "allow-write") {
		t.Errorf("the refusal names the flag: %q", got)
	}
}

// TestClassifyReported: the served privileges the plan reports are kept on
// the Login, and partial revokes are counted.
func TestClassifyReported(t *testing.T) {
	l := Classify(dbconn.ParseGrants([]string{
		"GRANT SELECT, INSERT, CREATE TEMPORARY TABLES ON *.* TO `u`@`%`",
		"GRANT BINLOG MONITOR, REPLICATION CLIENT ON *.* TO `u`@`%`",
		"REVOKE INSERT ON `shop`.* FROM `u`@`%`",
	}), "shop", nil)
	if !l.TempTables || !reflect.DeepEqual(l.Monitoring, []string{"BINLOG MONITOR", "REPLICATION CLIENT"}) || l.Revokes != 1 {
		t.Errorf("reported: temporary tables %v, monitoring %v, revokes %d", l.TempTables, l.Monitoring, l.Revokes)
	}
}
