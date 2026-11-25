package dbconn

import (
	"sort"
	"strings"
)

// Grant is one GRANT … ON … TO … line of SHOW GRANTS: privileges on a
// target, given to a grantee.
type Grant struct {
	// Privileges are upper-cased, with runs of spaces made one and column
	// lists dropped: SELECT, SHOW VIEW, BINLOG MONITOR, SYSTEM_VARIABLES_ADMIN.
	Privileges []string
	// Target is the line's target as written: *.*, `shop`.*, `shop`.`t`,
	// FUNCTION `shop`.`f`, or an account for PROXY.
	Target string
	// Grantee is the account, role or PUBLIC the line gives to, as written.
	Grantee string
	// GrantOption marks WITH GRANT OPTION.
	GrantOption bool
}

// Grants is SHOW GRANTS' output, parsed. Its lines never leave it: MariaDB
// prints the account's password hash in them.
type Grants struct {
	Grants []Grant
	// Revokes are MySQL's partial revokes, REVOKE … ON … FROM … lines.
	Revokes []Grant
	// Roles are the role-granting lines' roles, as written: those granted to
	// the account and to its roles.
	Roles []string
	// DefaultRoles are the roles of MariaDB's SET DEFAULT ROLE line.
	DefaultRoles []string
	// RoleAdmin is set by a role-granting line WITH ADMIN OPTION: the login
	// can grant those roles to other accounts.
	RoleAdmin bool
	// Unread counts the lines of no shape it knows.
	Unread int
}

// ParseGrants reads SHOW GRANTS lines. Every GRANT … ON … TO … line counts,
// whatever its grantee: SHOW GRANTS lists an active role's privileges
// either merged into the account's own line (MySQL) or as the role's own
// lines (MariaDB), and a role that isn't active shows no privilege line.
func ParseGrants(lines []string) Grants {
	var g Grants
	for _, line := range lines {
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "GRANT "):
			on := strings.Index(up, " ON ")
			if on < 0 {
				g.Roles = append(g.Roles, roleList(line[len("GRANT "):], " TO ")...)
				g.RoleAdmin = g.RoleAdmin || strings.Contains(up, " WITH ADMIN OPTION")
				continue
			}
			to := strings.Index(up[on:], " TO ")
			if to < 0 {
				g.Unread++
				continue
			}
			g.Grants = append(g.Grants, Grant{
				Privileges:  splitPrivileges(up[len("GRANT "):on]),
				Target:      strings.TrimSpace(line[on+4 : on+to]),
				Grantee:     grantee(line[on+to+4:]),
				GrantOption: strings.Contains(up[on+to:], " WITH GRANT OPTION"),
			})
		case strings.HasPrefix(up, "REVOKE "):
			on := strings.Index(up, " ON ")
			from := strings.Index(up, " FROM ")
			if on < 0 || from < on {
				g.Unread++
				continue
			}
			g.Revokes = append(g.Revokes, Grant{
				Privileges: splitPrivileges(up[len("REVOKE "):on]),
				Target:     strings.TrimSpace(line[on+4 : from]),
				Grantee:    grantee(line[from+6:]),
			})
		case strings.HasPrefix(up, "SET DEFAULT ROLE "):
			g.DefaultRoles = append(g.DefaultRoles, roleList(line[len("SET DEFAULT ROLE "):], " FOR ")...)
		default:
			g.Unread++
		}
	}
	return g
}

// roleList reads a role-granting line's list of roles, up to the keyword
// before the grantee.
func roleList(s, until string) []string {
	if i := strings.Index(strings.ToUpper(s), until); i >= 0 {
		s = s[:i]
	}
	var out []string
	for _, r := range strings.Split(s, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// grantee is what follows TO or FROM, up to IDENTIFIED, REQUIRE or WITH.
func grantee(s string) string {
	up := strings.ToUpper(s)
	end := len(s)
	for _, kw := range []string{" IDENTIFIED ", " REQUIRE ", " WITH ", " PASSWORD "} {
		if i := strings.Index(up, kw); i >= 0 && i < end {
			end = i
		}
	}
	return strings.TrimSpace(s[:end])
}

// On returns the privileges of the grants that reach the database: on *.*,
// on the database by its pattern, or on its tables, columns or routines.
// Sorted, each once.
func (g Grants) On(database string) []string {
	found := map[string]bool{}
	for _, gr := range g.Grants {
		if !grantCovers(gr.Target, database) {
			continue
		}
		for _, p := range gr.Privileges {
			found[p] = true
		}
	}
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Covers reports whether a grant's target reaches the database: *.*, the
// database by its pattern, or one of its tables or routines.
func (gr Grant) Covers(database string) bool { return grantCovers(gr.Target, database) }

// Global reports whether a grant's target is the whole server, *.*.
func (gr Grant) Global() bool {
	t := strings.TrimSpace(gr.Target)
	return t == "*.*" || t == "*"
}
