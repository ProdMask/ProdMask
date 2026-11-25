package dbconn

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseGrants(t *testing.T) {
	g := ParseGrants([]string{
		"GRANT USAGE ON *.* TO `u`@`%` IDENTIFIED BY PASSWORD " + fakeHash,
		"GRANT SELECT, SHOW VIEW ON `shop`.* TO `u`@`%`",
		"GRANT SELECT (`id`, `v`), UPDATE (`v`) ON `shop`.`t` TO `u`@`%`",
		"GRANT EXECUTE ON FUNCTION `shop`.`f` TO `u`@`%`",
		"GRANT PROCESS, FILE, BINLOG MONITOR, READ_ONLY ADMIN ON *.* TO `u`@`%` WITH GRANT OPTION",
		"GRANT BACKUP_ADMIN,SYSTEM_VARIABLES_ADMIN ON *.* TO `u`@`%`",
		"GRANT `r1`@`%`,`r2`@`%` TO `u`@`%`",
		"GRANT `kit_writer` TO `u`@`%` WITH ADMIN OPTION",
		"GRANT INSERT ON `shop`.* TO `kit_writer`",
		"GRANT SELECT ON `test\\_%`.* TO PUBLIC",
		"SET DEFAULT ROLE `kit_writer` FOR `u`@`%`",
		"REVOKE INSERT ON `shop`.* FROM `u`@`%`",
		"something else",
	})
	if len(g.Grants) != 8 {
		t.Fatalf("grants: %d, want 8: %+v", len(g.Grants), g.Grants)
	}
	if got := g.Grants[0]; got.Grantee != "`u`@`%`" || !got.Global() || !reflect.DeepEqual(got.Privileges, []string{"USAGE"}) {
		t.Errorf("the line with a password: %+v", got)
	}
	for _, gr := range g.Grants {
		if strings.Contains(gr.Grantee+gr.Target, "AAAA") {
			t.Errorf("a password hash kept in %+v", gr)
		}
	}
	if got := g.Grants[2].Privileges; !reflect.DeepEqual(got, []string{"SELECT", "UPDATE"}) {
		t.Errorf("column lists: %v", got)
	}
	if got := g.Grants[3].Target; got != "FUNCTION `shop`.`f`" {
		t.Errorf("a routine's target: %q", got)
	}
	if got := g.Grants[4]; !got.GrantOption || !reflect.DeepEqual(got.Privileges, []string{"PROCESS", "FILE", "BINLOG MONITOR", "READ_ONLY ADMIN"}) {
		t.Errorf("space-spelled privileges and the grant option: %+v", got)
	}
	if got := g.Grants[5].Privileges; !reflect.DeepEqual(got, []string{"BACKUP_ADMIN", "SYSTEM_VARIABLES_ADMIN"}) {
		t.Errorf("dynamic privileges: %v", got)
	}
	if got := g.Grants[6]; got.Grantee != "`kit_writer`" {
		t.Errorf("a role's own line: %+v", got)
	}
	if got := g.Grants[7]; got.Grantee != "PUBLIC" || got.Target != "`test\\_%`.*" {
		t.Errorf("PUBLIC's line: %+v", got)
	}
	if want := []string{"`r1`@`%`", "`r2`@`%`", "`kit_writer`"}; !reflect.DeepEqual(g.Roles, want) {
		t.Errorf("roles: %q, want %q", g.Roles, want)
	}
	if want := []string{"`kit_writer`"}; !reflect.DeepEqual(g.DefaultRoles, want) {
		t.Errorf("default roles: %q", g.DefaultRoles)
	}
	if !g.RoleAdmin {
		t.Error("a role granted WITH ADMIN OPTION isn't read")
	}
	if ParseGrants([]string{"GRANT `r1`@`%` TO `u`@`%`", "GRANT SELECT ON `shop`.* TO `u`@`%` WITH GRANT OPTION"}).RoleAdmin {
		t.Error("RoleAdmin without an ADMIN OPTION")
	}
	if len(g.Revokes) != 1 || g.Revokes[0].Target != "`shop`.*" || !reflect.DeepEqual(g.Revokes[0].Privileges, []string{"INSERT"}) {
		t.Errorf("revokes: %+v", g.Revokes)
	}
	if g.Unread != 1 {
		t.Errorf("unread: %d, want 1", g.Unread)
	}
	if got := g.On("shop"); !reflect.DeepEqual(got, []string{"BACKUP_ADMIN", "BINLOG MONITOR", "EXECUTE", "FILE", "INSERT",
		"PROCESS", "READ_ONLY ADMIN", "SELECT", "SHOW VIEW", "SYSTEM_VARIABLES_ADMIN", "UPDATE", "USAGE"}) {
		t.Errorf("On(shop): %v", got)
	}
	if got := g.On("test_eu"); !reflect.DeepEqual(got, []string{"BACKUP_ADMIN", "BINLOG MONITOR", "FILE", "PROCESS",
		"READ_ONLY ADMIN", "SELECT", "SYSTEM_VARIABLES_ADMIN", "USAGE"}) {
		t.Errorf("On(test_eu), through PUBLIC's escaped pattern: %v", got)
	}
	if got := g.On("testxeu"); strings.Contains(strings.Join(got, ","), "SELECT") {
		t.Errorf("an escaped underscore matched any character: %v", got)
	}
}

// TestGrantNames checks quoting and wildcards in a grant's database name:
// a doubled backtick is one, an unescaped _ or % is a wildcard, and a name
// may be printed unquoted.
func TestGrantNames(t *testing.T) {
	cases := []struct {
		line, database string
		covers         bool
	}{
		{"GRANT SELECT ON `we``ird`.* TO `u`@`%`", "we`ird", true},
		{"GRANT SELECT ON `we``ird`.* TO `u`@`%`", "weird", false},
		{"GRANT INSERT ON `sh_p`.* TO `u`@`%`", "shop", true},
		{"GRANT INSERT ON `sh\\_p`.* TO `u`@`%`", "shop", false},
		{"GRANT INSERT ON `sh\\_p`.* TO `u`@`%`", "sh_p", true},
		{"GRANT DELETE ON `s%`.* TO `u`@`%`", "shop", true},
		{"GRANT DELETE ON `s%`.* TO `u`@`%`", "blog", false},
		{"GRANT SELECT ON shop.* TO u@'%'", "shop", true},
		{"GRANT INSERT ON `blog`.`t` TO `u`@`%`", "shop", false},
		{"GRANT INSERT ON `SHOP`.* TO `u`@`%`", "shop", true},
		{"GRANT EXECUTE ON PROCEDURE `shop`.`p` TO `u`@`%`", "shop", true},
	}
	for _, c := range cases {
		g := ParseGrants([]string{c.line})
		if len(g.Grants) != 1 || g.Grants[0].Covers(c.database) != c.covers || (len(g.On(c.database)) > 0) != c.covers {
			t.Errorf("%s on %q: covers %v, want %v", c.line, c.database, !c.covers, c.covers)
		}
	}
}
