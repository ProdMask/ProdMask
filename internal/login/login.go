// Package login reads what a database login can do: its privileges on the
// database and the server, classified by an allowlist, the database's
// objects that run with their definer's rights, and whether the database
// says it is a prodmask copy. prodmask mcp decides by it whether to serve.
package login

import (
	"context"
	"database/sql"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
)

// served are the privileges prodmask mcp serves a login with: they read,
// or see only what they report.
var served = set("USAGE", "SELECT", "SHOW VIEW", "SHOW DATABASES", "EXECUTE", "CREATE TEMPORARY TABLES",
	"PROCESS", "REPLICATION CLIENT", "BINLOG MONITOR", "SLAVE MONITOR", "REPLICA MONITOR")

// monitoring are the served privileges that show the server's replication
// and binary log status; they're reported.
var monitoring = set("REPLICATION CLIENT", "BINLOG MONITOR", "SLAVE MONITOR", "REPLICA MONITOR")

var (
	changeData   = set("INSERT", "UPDATE", "DELETE", "LOCK TABLES")
	changeSchema = set("CREATE", "ALTER", "INDEX", "CREATE VIEW", "TRIGGER", "EVENT", "CREATE ROUTINE",
		"ALTER ROUTINE", "REFERENCES")
	dropPrivs = set("DROP", "DELETE HISTORY")
	allPrivs  = set("ALL", "ALL PRIVILEGES")
	// knownAdmin are administrative privileges by name; MySQL's dynamic
	// privileges (words joined by underscores) and MariaDB's "… ADMIN" ones
	// count too. Anything else is unknown: refused, and listed as not read.
	// MariaDB's SHOW CREATE ROUTINE counts as MySQL's SHOW_ROUTINE does, a
	// dynamic privilege.
	knownAdmin = set("SUPER", "GRANT OPTION", "CREATE USER", "SHUTDOWN", "RELOAD", "REPLICATION SLAVE",
		"REPLICATION SLAVE ADMIN", "CREATE TABLESPACE", "CREATE ROLE", "DROP ROLE", "PROXY", "SET USER",
		"BINLOG REPLAY", "SHOW CREATE ROUTINE")
)

var dynamicPriv = regexp.MustCompile(`^[A-Z]+(?:_[A-Z]+)+$`)

func set(words ...string) map[string]bool {
	m := map[string]bool{}
	for _, w := range words {
		m[w] = true
	}
	return m
}

// Classify reads parsed grants for the database. active are the login's
// active roles as CURRENT_ROLE() names them, to count those granted but not
// active. REVOKE lines never make a login look safer: a revoke's pattern is
// read loosely, so they're left out of the decision.
func Classify(g dbconn.Grants, database string, active []string) *model.Login {
	l := &model.Login{}
	add := func(list *[]string, p string) {
		if !slices.Contains(*list, p) {
			*list = append(*list, p)
		}
	}
	others := map[string]bool{}
	for _, gr := range g.Grants {
		if gr.GrantOption && (gr.Global() || gr.Covers(database) || gr.Covers("mysql")) {
			add(&l.Admin, "GRANT OPTION")
		}
		for _, p := range gr.Privileges {
			if p == "PROXY" {
				add(&l.Admin, p)
			}
		}
		if (gr.Covers("mysql") || gr.Global()) && hasAny(gr.Privileges, "SELECT", "ALL", "ALL PRIVILEGES") {
			l.SystemTables = true
		}
		// Writes on the mysql schema change accounts and their privileges:
		// that administers the server, wherever else the grant reaches.
		if gr.Covers("mysql") {
			for _, p := range gr.Privileges {
				if (changeData[p] && p != "LOCK TABLES") || changeSchema[p] || dropPrivs[p] || (allPrivs[p] && !gr.Global()) {
					add(&l.Admin, p+" on the mysql schema")
				}
			}
		}
		if !gr.Covers(database) {
			if !gr.Global() && !strings.HasPrefix(strings.ToUpper(gr.Target), "PROXY") && !hasAny(gr.Privileges, "PROXY") {
				if db, _, ok := strings.Cut(gr.Target, "."); ok {
					others[strings.ToLower(db)] = true
				}
			}
			continue
		}
		for _, p := range gr.Privileges {
			switch {
			case served[p]:
				switch {
				case p == "PROCESS":
					l.Process = true
				case p == "CREATE TEMPORARY TABLES":
					l.TempTables = true
				case monitoring[p]:
					add(&l.Monitoring, p)
				}
			case allPrivs[p]:
				add(&l.ChangeData, "ALL PRIVILEGES")
				add(&l.ChangeSchema, "ALL PRIVILEGES")
				add(&l.Drop, "ALL PRIVILEGES")
				if gr.Global() {
					add(&l.Admin, "ALL PRIVILEGES on *.*")
					l.Files = "unknown"
				}
			case changeData[p]:
				add(&l.ChangeData, p)
			case changeSchema[p]:
				add(&l.ChangeSchema, p)
			case dropPrivs[p]:
				add(&l.Drop, p)
			case p == "FILE":
				l.Files = "unknown"
			case p == "PROXY":
			case knownAdmin[p], dynamicPriv.MatchString(p), strings.HasSuffix(p, " ADMIN"):
				add(&l.Admin, p)
			default:
				add(&l.Admin, p)
				add(&l.NotRead, "a privilege prodmask doesn't know")
			}
		}
	}
	if g.RoleAdmin {
		add(&l.Admin, "ADMIN OPTION on a role")
	}
	l.Revokes = len(g.Revokes)
	l.OtherDatabases = len(others)
	l.RolesNotActive = notActive(g.Roles, active)
	for _, list := range [][]string{l.ChangeData, l.ChangeSchema, l.Drop, l.Admin, l.Monitoring} {
		sort.Strings(list)
	}
	if g.Unread > 0 {
		add(&l.NotRead, "a line of SHOW GRANTS prodmask can't read")
	}
	return l
}

// Serves reports whether prodmask mcp serves the login: one that can only
// read, or any with --allow-write-login or a checked --copy.
func Serves(l *model.Login, allowWrite, checkedCopy bool) bool {
	return allowWrite || checkedCopy || !l.CanWrite()
}

// Refusal says why prodmask mcp won't serve the login, in the words the
// agent reads, or "" for a login that can only read. It never names the
// flag that would let the login through: that's the person's call.
func Refusal(l *model.Login, database string) string {
	name := "`" + strings.ReplaceAll(report.Clean(database), "`", "``") + "`"
	var why []string
	var change []string
	for _, list := range [][]string{l.ChangeData, l.ChangeSchema, l.Drop} {
		for _, p := range list {
			if !slices.Contains(change, p) {
				change = append(change, p)
			}
		}
	}
	if len(change) > 0 {
		why = append(why, "it can change "+name+" ("+strings.Join(change, ", ")+")")
	}
	if l.Files != "" {
		why = append(why, "it holds FILE, which reads and writes files on the server")
	}
	if len(l.Admin) > 0 {
		why = append(why, "it can administer the server ("+strings.Join(l.Admin, ", ")+")")
	}
	if len(l.NotRead) > 0 {
		why = append(why, "prodmask couldn't read all it can do ("+strings.Join(l.NotRead, "; ")+")")
	}
	if len(why) == 0 {
		return ""
	}
	return "prodmask mcp won't serve this login: " + strings.Join(why, "; ") +
		". Ask the person who set this up for a login that can only read; don't change this server's settings yourself. " +
		"For example: CREATE USER 'agent'@'%' IDENTIFIED BY '…'; GRANT SELECT, SHOW VIEW ON " + name + ".* TO 'agent'@'%';"
}

func hasAny(privs []string, wanted ...string) bool {
	for _, p := range privs {
		for _, a := range wanted {
			if p == a {
				return true
			}
		}
	}
	return false
}

// notActive counts the granted roles not among the active ones, comparing
// names without quotes or hosts.
func notActive(granted, active []string) int {
	on := map[string]bool{}
	for _, a := range active {
		for _, r := range strings.Split(a, ",") {
			on[roleName(r)] = true
		}
	}
	n := 0
	seen := map[string]bool{}
	for _, r := range granted {
		name := roleName(r)
		if name != "" && !on[name] && !seen[name] {
			seen[name] = true
			n++
		}
	}
	return n
}

func roleName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.Trim(s, "`'\" "))
}

// Read reads what the session's login can do on its database: SHOW GRANTS,
// the active roles, where FILE reaches, and the database's objects that run
// with their definer's rights. Whatever it can't read lands in NotRead, so a
// caller that refuses what it can't read fails closed.
func Read(ctx context.Context, db *sql.DB, database string) *model.Login {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var lines []string
	rows, err := db.QueryContext(ctx, "SHOW GRANTS")
	if err != nil {
		return &model.Login{NotRead: []string{"SHOW GRANTS (" + dbconn.ErrorText(err) + ")"}}
	}
	for rows.Next() {
		var line string
		if rows.Scan(&line) == nil {
			lines = append(lines, line)
		}
	}
	readErr := rows.Err()
	rows.Close()
	var active sql.NullString
	activeErr := db.QueryRowContext(ctx, "SELECT CURRENT_ROLE()").Scan(&active)
	g := dbconn.ParseGrants(lines)
	l := Classify(g, database, []string{active.String})
	if readErr != nil {
		l.NotRead = append(l.NotRead, "SHOW GRANTS ("+dbconn.ErrorText(readErr)+")")
	}
	if activeErr != nil && len(g.Roles) > 0 {
		l.NotRead = append(l.NotRead, "the active roles ("+dbconn.ErrorText(activeErr)+")")
	}
	if l.Files == "unknown" {
		var where sql.NullString
		switch err := db.QueryRowContext(ctx, "SELECT @@GLOBAL.secure_file_priv").Scan(&where); {
		case err != nil:
		case !where.Valid:
			l.Files = "off"
		case where.String == "":
			l.Files = "anywhere"
		default:
			l.Files = "folder"
		}
	}
	routes, err := readRoutes(ctx, db, database)
	if err != nil {
		l.NotRead = append(l.NotRead, "the database's views, routines, triggers and events ("+dbconn.ErrorText(err)+")")
	}
	l.Routes = routes
	return l
}

// readRoutes lists the database's objects that run with their definer's
// rights, in name order within each kind.
func readRoutes(ctx context.Context, db *sql.DB, database string) ([]model.LoginRoute, error) {
	var out []model.LoginRoute
	queries := []struct{ kind, q string }{
		{"view", "SELECT TABLE_NAME, SECURITY_TYPE = 'DEFINER' FROM information_schema.VIEWS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME"},
		{"routine", "SELECT ROUTINE_NAME, SECURITY_TYPE = 'DEFINER', LOWER(ROUTINE_TYPE) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? ORDER BY ROUTINE_NAME"},
		{"trigger", "SELECT TRIGGER_NAME, 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ? ORDER BY TRIGGER_NAME"},
		{"event", "SELECT EVENT_NAME, 1 FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ? ORDER BY EVENT_NAME"},
	}
	for _, q := range queries {
		rows, err := db.QueryContext(ctx, q.q, database)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var name string
			var definer bool
			kind := q.kind
			dest := []any{&name, &definer}
			if kind == "routine" {
				dest = append(dest, &kind)
			}
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				return out, err
			}
			if definer {
				out = append(out, model.LoginRoute{Kind: kind, Name: name, DefinerRights: true})
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
