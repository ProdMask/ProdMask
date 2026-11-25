package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
)

// Check connects once, as the server would, and says what it found, for a
// person at a terminal: the server, the copy status, what the login can do,
// and whether prodmask mcp would serve. It never starts the protocol.
func Check(ctx context.Context, opts Options) (lines []string, serves bool, err error) {
	s := NewServer(opts)
	c, failure := s.connect(ctx)
	if c == nil {
		return nil, false, errors.New(failure)
	}
	defer c.close()
	lines = append(lines,
		"Database:     "+report.Clean(c.database)+" ("+report.Clean(c.agent.Server.Flavor+" "+c.agent.Server.Version)+")",
		"Copy status:  "+c.copyStatus(),
		"--copy:       "+onOff(s.opts.Copy))
	if c.login != nil {
		can := LoginLines(c.login)
		if !c.login.CanWrite() {
			can = append([]string{"can only read"}, can...)
		}
		lines = append(lines, "Login:        "+can[0])
		for _, l := range can[1:] {
			lines = append(lines, "              "+l)
		}
	}
	if c.refusal != "" {
		lines = append(lines, "", c.refusal)
		if c.loginRefusal {
			lines = append(lines, "With --allow-write-login, prodmask mcp serves this login anyway; the read-only checks still hold.")
		}
		return lines, false, nil
	}
	return append(lines, "", "prodmask mcp would serve this database."), true, nil
}

// LoginLines says what a login can do, a line per kind; none for a login
// that can only read and reaches nothing else.
func LoginLines(l *model.Login) []string {
	var out []string
	add := func(label string, privs []string) {
		if len(privs) > 0 {
			out = append(out, label+": "+strings.Join(privs, ", "))
		}
	}
	add("change data", l.ChangeData)
	add("change the schema", l.ChangeSchema)
	add("drop", l.Drop)
	switch l.Files {
	case "anywhere":
		out = append(out, "files: FILE reads and writes files anywhere the server can")
	case "folder":
		out = append(out, "files: FILE reads and writes files in the server's one folder for them")
	case "off":
		out = append(out, "files: FILE, though the server lets no statement reach files")
	case "unknown":
		out = append(out, "files: FILE, and prodmask couldn't read where it reaches")
	}
	add("administer", l.Admin)
	if l.Process {
		out = append(out, "other sessions: PROCESS shows other sessions' statements, with their values")
	}
	if l.TempTables {
		out = append(out, "temporary tables: CREATE TEMPORARY TABLES, which the statement rules don't run")
	}
	if len(l.Monitoring) > 0 {
		out = append(out, "server status: "+strings.Join(l.Monitoring, ", ")+" (replication and binary log status)")
	}
	if l.Revokes > 0 {
		out = append(out, fmt.Sprintf("revokes: %d partial revokes, which prodmask doesn't count: a revoke never makes a login servable", l.Revokes))
	}
	if l.OtherDatabases > 0 {
		out = append(out, fmt.Sprintf("elsewhere: privileges on %d other databases or patterns", l.OtherDatabases))
	}
	if l.SystemTables {
		out = append(out, "elsewhere: it can read the mysql schema's tables, password hashes included")
	}
	if l.RolesNotActive > 0 {
		out = append(out, fmt.Sprintf("roles not active: %d, whose privileges aren't read; prodmask can't activate them", l.RolesNotActive))
	}
	if len(l.Routes) > 0 {
		kinds := map[string]int{}
		var order []string
		for _, r := range l.Routes {
			if kinds[r.Kind] == 0 {
				order = append(order, r.Kind)
			}
			kinds[r.Kind]++
		}
		var parts []string
		for _, k := range order {
			parts = append(parts, fmt.Sprintf("%d %s", kinds[k], k))
		}
		out = append(out, "definer's rights: "+strings.Join(parts, ", ")+" run with their definer's rights")
	}
	add("not read", l.NotRead)
	return out
}
