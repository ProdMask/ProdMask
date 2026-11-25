package model

// Login is what a login can do on the database and the server, from SHOW GRANTS and the database's own views, routines,
// triggers and events. No field holds a value, a host, a path or an account.
type Login struct {
	// ChangeData, ChangeSchema and Drop are privileges that reach the
	// database: INSERT, UPDATE, DELETE, LOCK TABLES; CREATE, ALTER and the
	// rest of the schema's; DROP and DELETE HISTORY. ALL PRIVILEGES counts in
	// each.
	ChangeData   []string `json:"change_data,omitempty"`
	ChangeSchema []string `json:"change_schema,omitempty"`
	Drop         []string `json:"drop,omitempty"`
	// Files is where FILE reaches: "anywhere", "folder", "off", or
	// "unknown" when it couldn't be read; empty without FILE.
	Files string `json:"files,omitempty"`
	// Admin lists the administrative privileges, such as SUPER, GRANT
	// OPTION, CREATE USER and MySQL's *_ADMIN ones.
	Admin []string `json:"admin,omitempty"`
	// Process marks PROCESS: other sessions' statements, with their values.
	Process bool `json:"process,omitempty"`
	// TempTables marks CREATE TEMPORARY TABLES, which is served: the
	// statement rules don't run CREATE.
	TempTables bool `json:"temporary_tables,omitempty"`
	// Monitoring lists the served monitoring privileges, such as REPLICATION
	// CLIENT: the server's replication and binary log status.
	Monitoring []string `json:"monitoring,omitempty"`
	// Revokes counts MySQL's partial revokes, which never make a login
	// servable: a revoke's pattern is read loosely.
	Revokes int `json:"revokes,omitempty"`
	// OtherDatabases counts the other databases, or patterns of them, the
	// login has privileges on, PUBLIC's included.
	OtherDatabases int `json:"other_databases,omitempty"`
	// SystemTables marks a login that can read the mysql schema's tables,
	// password hashes included.
	SystemTables bool `json:"system_tables,omitempty"`
	// RolesNotActive counts roles granted but not active: their privileges
	// aren't read, and prodmask can't activate them.
	RolesNotActive int `json:"roles_not_active,omitempty"`
	// Routes are the database's views, routines, triggers and events that
	// run with their definer's rights.
	Routes []LoginRoute `json:"routes,omitempty"`
	// NotRead names what couldn't be read or classified, in fixed words.
	NotRead []string `json:"not_read,omitempty"`
}

// LoginRoute is a view, routine, trigger or event that runs with its
// definer's rights. Its definer's account isn't kept: it holds a host.
type LoginRoute struct {
	Kind          string `json:"kind"` // view, function, procedure, trigger or event
	Name          string `json:"name"`
	DefinerRights bool   `json:"definer_rights"`
}

// CanWrite reports whether the login can change the database or the
// server, or holds a privilege prodmask doesn't know, or wasn't all read:
// prodmask mcp refuses such a login unless told otherwise.
func (l *Login) CanWrite() bool {
	return len(l.ChangeData)+len(l.ChangeSchema)+len(l.Drop)+len(l.Admin)+len(l.NotRead) > 0 || l.Files != ""
}
