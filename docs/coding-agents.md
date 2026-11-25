# Give a coding agent the database

`prodmask mcp` lets a coding agent such as Claude Code, Cursor, Codex or Copilot's coding agent read one MySQL or MariaDB database through prodmask's checks. It's a server for the Model Context Protocol (MCP) that the agent's client starts, and they talk over standard input and output.

For no real customer details, point it at a prodmask Pro copy, with [its caveats](#a-prodmask-pro-copy). Pointed at any other database, it replaces the personal data and secrets it recognises, and shows the rest as stored. It doesn't catch everything; [what it doesn't catch](#what-it-doesnt-catch) says what it misses.

## What it does

The agent gets four tools:

| Tool | What it returns |
|---|---|
| `about` | the server, the database, whether it's a prodmask copy, what this login can do, the limits, and what the replacement doesn't catch |
| `list_tables` | each table and view: kind, estimated rows, comment, and how many of its columns' names say personal data |
| `describe_table` | one table's columns, with what each name says (such as "email address (by name)"), its indexes, foreign keys, and the relationships prodmask's platform presets know |
| `query` | one read-only statement's columns, rows, warnings and notes |

Every statement must be a single read. These run: `SELECT`, `WITH`, `TABLE`, `VALUES`, `DESCRIBE`, `EXPLAIN`, and a short list of `SHOW` forms. Four layers stand between a statement and your data, each stopping things the others don't:

- **The statement rules.** They allow one statement at a time, and only a read. Built-in functions come from a reviewed list: those that wait, lock, read files, change or read the server's state, or name an account are refused, and so is any function the list doesn't know. Only the session's database can be named, plus a short list of `information_schema` tables, and the session's database can't be one of the server's own: `mysql`, `information_schema`, `performance_schema` or `sys`. Those `information_schema` tables still list, by name, the tables and columns of other databases the login can see. Variables, too, come from a short list. A `SHOW` with `WHERE` is refused, since MySQL doesn't bound a subquery there; filter with a `SELECT` on `information_schema` instead.
- **The login check.** A login that can change the database or the server is refused (see [the login](#the-login)).
- **A read-only session.** The server itself refuses writes, even from a stored function. Before each statement, prodmask checks that the connection still has its settings.
- **Limits.** Each statement has a server-side time limit and a row ceiling. Calls run one at a time, and the user locks a statement took are released after it.

The replacement, for each result:

- **By column.** A result column is tied to its table through the statement's aliases. It then takes the scan's verdict for that column: prodmask samples the table the first time a result touches it, as `prodmask scan` would. A renamed column takes the worst verdict among its table's columns of the same type. A computed column is judged by its label and values.
- **By key.** In a key/value table such as `wp_usermeta`, each value is judged by the key beside it in the same row. Select the key column with the value column: a value column without its key is withheld.
- **In text.** Emails, phone numbers with a country or area code, card numbers, IBANs, IP addresses, password hashes, secrets and passwords in URLs are replaced wherever they appear, inside JSON and PHP-serialized values too. Some stay as stored: emails at the domains reserved for examples, published test card numbers, and the loopback and documentation address ranges.
- **Withheld.** These show as `[withheld]`: a value over 1 MiB, a value that isn't valid UTF-8, and a structured value prodmask couldn't edit.
- **SHOW output.** A `DEFINER=` clause shows as `DEFINER=[account]` and a `CONNECTION='…'` string as `CONNECTION='[redacted]'`.

A replaced value is a token such as `[email 3f9a1c2b7d4e]`. Equal values give equal tokens while the server runs, so joins and `GROUP BY` still line up. The key is random and lives only in memory, so tokens don't link from one run to the next. A binary value becomes a token with its size, such as `[binary 16 bytes 0c41e9b27a55]`.

Server errors and warnings show their number and fixed words, never the server's message, which can quote a value. A warning such as 1292 reads "warning 1292, message withheld".

Each result's notes say, by column, how many values were replaced or withheld and why. They never show the values themselves.

## What it doesn't catch

- A column renamed to another column of the same table and type, such as `last_name AS city`.
- Computed columns, which are judged by their label and values only. So `CONCAT(first_name, ' ', last_name) AS customer` and `REVERSE(first_name)` show as stored, unless the label says what they hold.
- People named in free text.
- Keys of a key/value table that neither the sample nor the name rules flag.
- A value inside a JSON or serialized value whose nearest key says nothing, such as `{"first_name": {"x": "Ada"}}`: only the nearest key is read.
- A view's columns whose names and values don't show what they hold.
- Low-confidence findings, which aren't replaced.

An agent that wants to get around the replacement can. What prodmask holds firmly is read-only: the statement rules, the login check, the server's read-only session and the limits. For no real customer details, use a prodmask Pro copy.

Values are data from the database, never instructions. A review or a name can hold text written to steer an agent. Read-only limits what the database can suffer from that; keep the agent's own shell permissions as they are.

## The login

Give the agent a login of its own that can only read:

```sql
CREATE USER 'agent'@'%' IDENTIFIED BY '…';
GRANT SELECT, SHOW VIEW ON `shop`.* TO 'agent'@'%';
```

Use the `agent` login for agents, and keep `prodmask` for scans.

Any MCP config the agent's client can read gives the agent this login. An agent with a shell can read its own client's config, and can then use the login without prodmask. So what keeps your data intact is that the login can only read. Where the config lives matters less, but keep it out of the project and out of your shell's environment.

On each connection, `prodmask mcp` reads `SHOW GRANTS`, the active roles and the database's views, routines, triggers and events. It refuses to serve a login that can:

- change the data (`INSERT`, `UPDATE`, `DELETE`, `LOCK TABLES`);
- change the schema (`CREATE`, `ALTER`, `INDEX`, `TRIGGER`, `EVENT`, routines, views);
- drop anything;
- use `FILE`;
- administer the server (`SUPER`, `GRANT OPTION`, `CREATE USER` and the admin privileges), write to the `mysql` schema, or grant a role it holds `WITH ADMIN OPTION`;
- or holds a privilege prodmask doesn't know, or one it couldn't read.

These are refused whether they come directly or through an active role.

`SELECT`, `SHOW VIEW`, `SHOW DATABASES`, `EXECUTE`, `CREATE TEMPORARY TABLES`, `PROCESS` and the monitoring privileges (`REPLICATION CLIENT`, `BINLOG MONITOR`, `SLAVE MONITOR`, `REPLICA MONITOR`) are served; `CREATE TEMPORARY TABLES`, `PROCESS` and the monitoring privileges are also reported. Under a refusal, `about` still answers, and every other tool tells the agent to ask you for a login that can only read. Once you fix the grants, the next call is served, with no restart.

Check a login before you hand it over:

```bash
PRODMASK_PASSWORD='…' prodmask mcp --check --dsn 'mysql://agent@db.internal:3306/shop'
```

It prints the copy status and what the login can do. It exits 0 if `prodmask mcp` would serve the login, 3 if it would refuse it, and 1 if it couldn't connect.

`--allow-write-login` serves a login that can write anyway. The statement rules, the read-only session and the limits still hold. It's for a database you're willing to have changed if something gets past them.

## A prodmask Pro copy

A copy made by prodmask Pro holds masked data and a `_prodmask` table that says so. Start the server with `--copy`, and values show as stored, except secrets, passwords in URLs and password hashes, which are still replaced:

```bash
prodmask mcp --copy --dsn 'mysql://agent@127.0.0.1:3306/shop_copy'
```

`--copy` checks the marker as Pro does. It needs one row, a run id of Pro's shape, a complete copy, a stable or per-run masking key, and Pro's comment on the table. Anything else is refused: no marker, a copy that isn't complete, a copy made with no masking, or a marker of another shape. A masking mode added by a later Pro reads as no marker until this build knows it.

With `--copy`, values show as the copy holds them. That includes any column the copy's config kept unmasked, and anything Pro didn't recognise.

The marker is what the copy wrote. It isn't a check of the rows. Pro's `verify` checks the rows. A database refreshed from a plain dump after the copy keeps its old marker, so refresh a copy only with prodmask.

## Limits

| Limit | Default | |
|---|---|---|
| `--timeout` | 10s | each statement's time limit, set on the server; at least 1s |
| `--max-rows` | 100 | rows per call, at most 1,000; a call's `max_rows` can lower it |
| result | 256 KB | a result stops there, with `more_rows` |
| value | 1,000 characters | a longer value is cut, never inside a token |
| read | 64 MiB | per call |
| a value withheld | over 1 MiB | |
| a statement | 64 KB | longer ones are refused |

`prodmask mcp` holds two connections: one for the agent's statements and one for its own reads. The first time a result touches a table, it samples that table as `prodmask scan` does: a few hundred rows, or a key/value table's keys. Against production, a statement holds a shared metadata lock until it ends, so a deploy's `ALTER TABLE` can wait behind it and the app's queries behind that. Use a lower `--timeout`, a replica, or better, a Pro copy.

It needs MySQL 5.7 or MariaDB 10.5.2 or later to release locks after each statement; on older servers it closes the connection after each one instead. It refuses a server that can't mark a session read-only or has no statement time limit.

Standard output carries only protocol messages. Standard error gets a line when the server starts, a line per connection, and a line per call with the tool, the outcome and the time. It never shows a statement, a value, a host, a user name or a DSN. On Linux the process can't be read through `/proc` or a debugger, and writes no core file.

## Where the connection string goes

Put the DSN in the server's own entry in your client's user-level config. Never put it in the project, the shell profile or the project's `.env`. Keep the password in `PRODMASK_PASSWORD` or in the DSN of that entry. `--project` reads an app's own config, whose login can write, so it's for people at a terminal and not for an agent's config.

## Recipes

Each recipe points at a Pro copy first. For any other database, drop `--copy` and use the `agent` login.

### Claude Code

Tried with Claude Code 2.1.221 on 20 November 2026: the server is added, connects, and its four tools are listed.

```bash
claude mcp add prodmask --env PRODMASK_DSN='mysql://agent:…@127.0.0.1:3306/shop_copy' -- prodmask mcp --copy
```

This writes to the default (local) scope, which is yours and this project's, in `~/.claude.json`. `--scope user` makes it yours in every project. Never use `--scope project`: it writes `.mcp.json` at the project's root, which is meant to be committed.

### Cursor

From Cursor's docs, read 19 November 2026; not run here. Put this in your user config, `~/.cursor/mcp.json`, never the project's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "prodmask": {
      "type": "stdio",
      "command": "prodmask",
      "args": ["mcp", "--copy"],
      "env": { "PRODMASK_DSN": "mysql://agent:…@127.0.0.1:3306/shop_copy" }
    }
  }
}
```

### Codex

From Codex's docs, read 19 November 2026; not run here. Put this in `~/.codex/config.toml`:

```toml
[mcp_servers.prodmask]
command = "prodmask"
args = ["mcp", "--copy"]
env = { PRODMASK_DSN = "mysql://agent:…@127.0.0.1:3306/shop_copy" }
```

### Copilot's coding agent

From GitHub's docs, read 19 November 2026; not run here. Copilot's coding agent runs in GitHub Actions. Give it a database of its own: a MySQL service container, loaded with a dump of a Pro copy (`prodmask copy --dump`) that the job fetches from a private store. Never commit the dump: it can still hold what Pro didn't recognise.

`.github/workflows/copilot-setup-steps.yml`, on the default branch, with the job named `copilot-setup-steps`:

```yaml
name: Copilot setup steps
on: workflow_dispatch
jobs:
  copilot-setup-steps:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    services:
      db:
        image: mysql:8.4
        env:
          MYSQL_ROOT_PASSWORD: ci-only-root
          MYSQL_DATABASE: shop_copy
        ports: ["3306:3306"]
        options: >-
          --health-cmd="mysqladmin ping -h 127.0.0.1 -pci-only-root"
          --health-interval=5s --health-retries=30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Fetch the Pro copy's dump from your private store
        run: ./scripts/fetch-copy-dump.sh shop_copy.sql   # yours: an S3 bucket, a private release asset
        env:
          DUMP_TOKEN: ${{ secrets.DUMP_TOKEN }}
      - name: Load it, and add the agent's read-only login
        run: |
          mysql -h 127.0.0.1 -uroot -pci-only-root shop_copy < shop_copy.sql
          mysql -h 127.0.0.1 -uroot -pci-only-root -e "CREATE USER 'agent'@'%' IDENTIFIED BY 'agent-local-only'; GRANT SELECT, SHOW VIEW ON shop_copy.* TO 'agent'@'%';"
      - name: Install prodmask
        run: go install github.com/ProdMask/ProdMask/cmd/prodmask@v0.16.0
```

Then, in the repository's Settings, under Copilot and MCP servers:

```json
{
  "mcpServers": {
    "prodmask": {
      "type": "local",
      "command": "prodmask",
      "args": ["mcp", "--copy"],
      "env": { "PRODMASK_DSN": "$COPILOT_MCP_PRODMASK_DSN" },
      "tools": ["about", "list_tables", "describe_table", "query"]
    }
  }
}
```

Add an Agents secret, `COPILOT_MCP_PRODMASK_DSN`, set to `mysql://agent:agent-local-only@127.0.0.1:3306/shop_copy`. Copilot runs the tools it lists without asking, so list these four; they only read.

### Laravel Boost

Boost's own database tools connect with the login in your app's `.env`, which can write and reaches whatever that file points at. For an agent, point `DB_*` at a Pro copy. Or, for a database with real data, give the agent `prodmask mcp` with the `agent` login in place of Boost's database tools.

### Docker

```bash
docker run -i --rm -e PRODMASK_DSN='mysql://agent:…@db.internal:3306/shop_copy' ghcr.io/prodmask/prodmask:0.16.0 mcp --copy
```

Keep `-i`, since the client talks to the server over standard input. Inside the container, `localhost` is the container itself, not your machine. To reach a server on your machine, use `host.docker.internal` (Docker Desktop) or `--network host` (Linux).
