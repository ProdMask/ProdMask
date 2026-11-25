package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/harden"
	"github.com/ProdMask/ProdMask/internal/mcp"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
)

func mcpCommand() *Command {
	return &Command{
		Name:    "mcp",
		Args:    "[flags]",
		Summary: "serve a database to a coding agent over MCP (read-only)",
		Run:     runMCP,
	}
}

const mcpUsage = `Usage: prodmask mcp [flags]

Serves one MySQL or MariaDB database to a coding agent over the Model Context
Protocol, on standard input and output. Every statement goes through
prodmask's read-only checks, in a read-only session with row and time
limits, and the personal data and secrets prodmask recognises are replaced
by tokens. A login that can change the database or the server is refused.
For no real customer details, point it at a prodmask Pro copy. Each agent's
setup: https://github.com/ProdMask/ProdMask/blob/main/docs/coding-agents.md

Exit status: 0 done, 1 error, 2 bad usage. With --check: 0 if it would
serve, and 3 if it would refuse (3 is the scan's "found something" status;
here it found a reason to refuse).
`

func runMCP(ctx context.Context, env *Env, args []string) int {
	stdout, stderr := env.Stdout, env.Stderr
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	dsn := fs.String("dsn", "", "connection string, mysql://user@host:3306/db or user@tcp(host:3306)/db\n(default $PRODMASK_DSN; the password may come from $PRODMASK_PASSWORD)")
	project := fs.String("project", "", "read the database settings from the app's config in this folder instead,\nfor a person at a terminal: the app's login can write, and an agent can read its config")
	timeout := fs.Duration("timeout", 10*time.Second, "server-side time limit for each statement, at least 1s")
	maxRows := fs.Int("max-rows", 100, "at most this many rows per statement, up to 1000")
	copyFlag := fs.Bool("copy", false, "show a prodmask Pro copy's values as stored, except secrets, once its\n_prodmask marker checks out; refuse any other database")
	allowWrite := fs.Bool("allow-write-login", false, "serve a login that can change the database or the server; the read-only\nchecks, the read-only session and the limits still hold")
	check := fs.Bool("check", false, "connect, print what the login can do and the copy status, and exit:\n0 if it would serve, 3 if it would refuse, 1 on an error")
	if ok, code := parseQuiet(env, "mcp", fs, mcpUsage, args); !ok {
		return code
	}
	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "prodmask mcp: "+format+"\n", a...)
		return ExitUsage
	}
	if *timeout < time.Second {
		return usageErr("--timeout must be at least 1s")
	}
	if *maxRows < 1 || *maxRows > 1000 {
		return usageErr("--max-rows must be from 1 to 1000")
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	var cfg *mysql.Config
	if given["project"] {
		switch {
		case given["dsn"]:
			return usageErr("give --dsn or --project, not both")
		case *project == "":
			return usageErr("--project is empty: give the app's folder")
		}
		proj, err := readProject(stderr, *project)
		if err != nil {
			return usageErr("%v", err)
		}
		cfg = proj.Config
		if *allowWrite {
			fmt.Fprintln(stderr, "prodmask mcp: --project gives the app's own login, which can write; give agents a login that can only read")
		}
	} else {
		conn := *dsn
		if conn == "" {
			conn = os.Getenv("PRODMASK_DSN")
		}
		var err error
		cfg, err = dbconn.ParseDSN(conn, os.Getenv("PRODMASK_PASSWORD"))
		if err != nil {
			return usageErr("%v", err)
		}
	}
	if cfg.DBName == "" {
		return usageErr("the DSN names no database: prodmask mcp serves one")
	}
	if mcp.SystemSchema(cfg.DBName) {
		return usageErr("the DSN names the server's own %s schema: give the app's database", cfg.DBName)
	}

	// The process holds the DSN and the rows it reads: keep them out of core
	// files and out of reach of the agent, which runs as the same user.
	harden.Process()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	// After the first Ctrl-C, a second one stops the process at once.
	context.AfterFunc(ctx, stop)
	opts := mcp.Options{Config: cfg, Timeout: *timeout, MaxRows: *maxRows, Copy: *copyFlag, AllowWrite: *allowWrite,
		Version: env.App.Version, Log: stderr}
	if *check {
		lines, serves, err := mcp.Check(ctx, opts)
		if err != nil {
			fmt.Fprintf(stderr, "prodmask mcp: %v\n", err)
			return ExitError
		}
		for _, l := range lines {
			fmt.Fprintln(stdout, l)
		}
		if !serves {
			return ExitFindings
		}
		return ExitOK
	}

	stdin := env.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	fmt.Fprintf(stderr, "prodmask mcp: %s, reading MCP messages on standard input\n", env.App.VersionLine())
	s := mcp.NewServer(opts)
	s.Start(ctx)
	err := s.Wire().Serve(ctx, stdin, stdout)
	s.Close()
	if err != nil {
		fmt.Fprintln(stderr, "prodmask mcp: reading standard input failed")
		return ExitError
	}
	return ExitOK
}
