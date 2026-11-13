# prodmask

[![CI](https://github.com/ProdMask/ProdMask/actions/workflows/ci.yml/badge.svg)](https://github.com/ProdMask/ProdMask/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ProdMask/ProdMask.svg)](https://pkg.go.dev/github.com/ProdMask/ProdMask)
[![Release](https://img.shields.io/github/v/release/ProdMask/ProdMask)](https://github.com/ProdMask/ProdMask/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Find out what a plain copy of your production MySQL or MariaDB database would carry into staging, before you make one.

![A terminal recording of prodmask scan on the fake shop: the summary, what staging could do to real people, and the findings by table](https://raw.githubusercontent.com/ProdMask/ProdMask/main/docs/demo.gif)

`prodmask scan` connects read-only and samples a few hundred rows per table. It reports:

- **Personal data and secrets:**
  - emails, phone numbers, addresses, names, dates of birth, national and tax IDs, device and hardware IDs, push notification tokens;
  - IBANs, card numbers, password hashes, and passwords stored as plain text;
  - API keys and tokens: Stripe, AWS, GitHub, Slack, Discord, Telegram, Google OAuth, Paddle, Postman and about 60 more formats, keys labelled `apikey`, and passwords inside URLs and `Authorization` headers ([what counts](#what-counts-as-a-credential)), including inside JSON and PHP-serialized values;
  - email addresses inside URLs, and messages people send each other, such as private messages and notifications.
- **What staging would do to real people:**
  - payment gateways in live mode;
  - mail settings that reach real inboxes;
  - active webhooks;
  - scheduled subscription renewals and queued jobs.
- **How the tables link up:** declared foreign keys, plus links inferred from naming and checked against the data, including Laravel polymorphic relations.

It knows WordPress and WooCommerce, Magento 2 and Laravel, and works on any MySQL or MariaDB schema. Every change is tested against MySQL 8.4 and MariaDB 11.8. For Magento it handles 2.4, Open Source or Adobe Commerce, with or without a table prefix; its tests use a trimmed 2.4 schema with no prefix, and older releases aren't tested.

Reports name tables, columns, keys and JSON paths, with counts and categories. They never contain the sampled values. Key names can hold data too, such as a user's email address inside a meta key. Those are shown as patterns like `um_email_as_username_*`, one line for all the keys that share the pattern.

It runs on your machine and connects only to the database you name. It sends nothing anywhere: no telemetry, no update checks.

See a [sample report](https://prodmask.com/sample-report) from test databases filled with made-up customers.

## Try it in 60 seconds

With Docker and [prodmask installed](#install), scan the [fake shop](examples/), a WooCommerce database full of invented customers, orders and keys:

```bash
git clone --depth 1 https://github.com/ProdMask/ProdMask.git
cd ProdMask/examples
docker compose up -d --wait
PRODMASK_PASSWORD=demo prodmask scan --dsn 'mysql://prodmask_ro@127.0.0.1:3399/shop'
```

The first start downloads MariaDB and loads the shop, which takes a minute or so. `docker compose down -v` removes it all. [examples/README.md](examples/README.md) has the steps for PowerShell, and for loading the shop into a server of your own.

With only Docker, skip the install: in `examples/`, `docker compose run --rm scan` starts the shop and scans it with prodmask's image. `docker compose --profile scan down -v` removes it all.

## Install

1. Download the archive for your system from the [releases page](https://github.com/ProdMask/ProdMask/releases). There are builds for Linux, macOS and Windows, each for amd64 and arm64.
2. Download `checksums.txt` from the same release.
3. Check the archive against it, changing `linux_amd64` to match your archive. On macOS, use `shasum -a 256 -c` instead of `sha256sum -c`:

```bash
grep _linux_amd64.tar.gz checksums.txt | sha256sum -c
```

4. Unpack the archive and put `prodmask` on your `PATH`.

On Windows, compare the output of `Get-FileHash` with the line in `checksums.txt`.

To build it yourself instead, use Go 1.27 or later. The only dependency is `github.com/go-sql-driver/mysql`. Install it straight from the module:

```bash
go install github.com/ProdMask/ProdMask/cmd/prodmask@latest
```

Or build it from a checkout:

```bash
go build -o prodmask ./cmd/prodmask
```

### With Docker

The image `ghcr.io/prodmask/prodmask` holds the same release, for linux/amd64 and linux/arm64. Pin a version, as you would in CI:

```bash
docker run --rm ghcr.io/prodmask/prodmask:0.13.0 version
```

To reach a database on your own machine:

- **Linux:** add `--network host` and use `127.0.0.1` in the DSN. That also reaches a server listening on loopback only. Or add `--add-host host.docker.internal:host-gateway` and use `host.docker.internal`, which reaches only servers listening beyond loopback.
- **Docker Desktop on macOS or Windows:** use `host.docker.internal` as the host, or turn on host networking (Docker Desktop 4.34 or later, in Settings). This is from Docker's docs, untested here.
- **A database in the same Compose project:** use its service name as the host.

Pass the password from your shell with `-e PRODMASK_PASSWORD`, so it isn't typed on the command line:

```bash
PRODMASK_PASSWORD='…' docker run --rm --network host -e PRODMASK_PASSWORD \
  ghcr.io/prodmask/prodmask:0.13.0 scan --dsn 'mysql://prodmask_ro@127.0.0.1:3306/shop'
```

The report goes to standard output. For a file, mount a folder at `/work` and, on Linux, run as yourself so the file is yours:

```bash
docker run --rm --network host -e PRODMASK_PASSWORD --user "$(id -u):$(id -g)" -v "$PWD:/work" \
  ghcr.io/prodmask/prodmask:0.13.0 scan --dsn 'mysql://prodmask_ro@127.0.0.1:3306/shop' \
  --format markdown --out report.md
```


## Use

```bash
PRODMASK_PASSWORD='…' prodmask scan --dsn 'mysql://prodmask_ro@db.internal:3306/shop'
```

The DSN can be a URL (`mysql://user:pass@host:port/db?tls=true`, or `?socket=/path/mysqld.sock` for a socket) or the Go driver form (`user:pass@tcp(host:3306)/db`). The `PRODMASK_DSN` environment variable works too. Keep the password in `PRODMASK_PASSWORD` rather than in the DSN, so it stays out of shell history.

| Flag | Default | |
|---|---|---|
| `--format` | `text` | `text`, `markdown` or `json` |
| `--out` | stdout | write the report to a file |
| `--config-out` | | also write a starter masking config, `prodmask.yml` |
| `--fail-on` | `none` | exit with status 3 if anything at this severity or above is found: `low`, `medium`, `high` or `critical` |
| `--preset` | `auto` | `none`, `wordpress`, `woocommerce`, `magento2` or `laravel` |
| `--sample-rows` | 300 | rows sampled per table |
| `--meta-sample-rows` | 3000 | rows sampled from a key/value table such as `wp_postmeta` that is too big to read whole (see below) |
| `--no-samples` | | judge column names only; read no rows |
| `--timeout` | `10s` | server-side limit for each statement |
| `--verbose` | | also list low-confidence matches, inferred relationships and full evidence |

Exit status: 0 done, 1 error, 2 bad usage, 3 found something at or above `--fail-on`.

In CI, scan the database your staging copy came from, or the copy itself, and fail the build when it still holds personal data:

```bash
prodmask scan --dsn "$STAGING_DSN" --fail-on high --format markdown --out prodmask-report.md
```

With `--fail-on high`, the build fails on a high or critical finding, such as a column of customer emails or a live API key, and passes on medium and low ones, such as a test-mode key. A new version can find more, or rate a finding higher, so a build that passed may fail after an upgrade. [CHANGELOG.md](CHANGELOG.md) lists each change.

### GitHub Actions

The action runs the same scan in a workflow. Pin it to a release:

```yaml
- uses: ProdMask/ProdMask@v0.13.0
  with:
    dsn: ${{ secrets.STAGING_DSN }}
    password: ${{ secrets.STAGING_DB_PASSWORD }}
    fail-on: high
```

- **What it runs:** it downloads that release and checks it against `checksums.txt`. It fails the step on a finding at or above `fail-on`, which defaults to `high`.
- **Your credentials:** the DSN and password reach prodmask through its environment, never a command line.
- **What the log shows:** only prodmask's own lines. The Markdown report goes to the file named by the step's `report` output.

**The job summary:**
- In a private repository, the report also becomes the job summary.
- In a public one it doesn't, since anyone can read a public repository's summaries, and the report names your tables and columns.
- `summary: true` writes one anyway.

To keep the report when a job in a private repository fails, upload it:

```yaml
- uses: ProdMask/ProdMask@v0.13.0
  id: prodmask
  with:
    dsn: ${{ secrets.STAGING_DSN }}
- uses: actions/upload-artifact@v7
  if: always()
  with:
    name: prodmask-report
    path: ${{ steps.prodmask.outputs.report }}
```

Anyone can download a public repository's artifacts too, so leave this step out there.

- **Inputs:** `dsn` (required), `password`, `fail-on`, `preset`, `report`, `summary` (`auto`, `true` or `false`) and `version`.
- **Outputs:** `report`, `exit-code` and `summary-written`.

### Other CI systems

The image also works as a job image, wherever a job runs its steps through a shell. GitLab CI needs its entrypoint cleared (untested here). Set `PRODMASK_DSN` and `PRODMASK_PASSWORD` as masked CI/CD variables; prodmask reads both, so neither is on a command line:

```yaml
prodmask:
  image:
    name: ghcr.io/prodmask/prodmask:0.13.0
    entrypoint: [""]
  script:
    - prodmask scan --fail-on high
```

## Check a staging database for real values

`prodmask leak-check` checks your staging database for a sample of real customer values from production. Your key stays with you, and the report shows counts, never values.

```bash
prodmask leak-check key --out leak.key
```

```bash
PRODMASK_PASSWORD='…' prodmask leak-check hash --dsn 'mysql://prodmask_ro@prod.internal:3306/shop' --key-file leak.key --out shop.leakhashes.json
```

```bash
PRODMASK_PASSWORD='…' prodmask leak-check compare --dsn 'mysql://prodmask_ro@staging.internal:3306/shop' --key-file leak.key --hashes shop.leakhashes.json --fail-on high
```

The first step samples the columns `scan` flags on production and writes keyed hashes. Treat that file as personal data. The second reads those columns whole on staging, so it belongs on staging, and reports per column how many sampled values turned up.

A zero isn't proof that none are there. Only a sample is looked for, and only kinds unlikely to match by chance: email addresses, phone numbers, IBANs, national and tax IDs, payment tokens, password hashes and secrets, not names or street addresses. See [docs/leak-check.md](docs/leak-check.md) for the odds, the costs, the exit statuses and the data protection notes.

## What it does to your database

`prodmask scan` is built to be safe to run against production:

- **Session settings:**
  - one connection with a read-only session (`transaction_read_only`) in autocommit mode, so no snapshot or lock outlives a statement;
  - `lock_wait_timeout` of 5 seconds, so it never queues behind a schema change;
  - a server-side statement timeout (`max_statement_time` on MariaDB, `max_execution_time` on MySQL).
- **Queries:**
  - every sampling query is a `SELECT` with a `LIMIT`, ordered by primary key where there is one; key/value lookups (below) have a `LIMIT` per key instead;
  - text values are cut to 4,096 characters on the server, and settings to 65,536;
  - binary columns are skipped, except binary columns of up to 16 bytes named like IP addresses: those are read as hex in the same sampling query and decoded in memory, and their values are never shown;
  - row counts come from `information_schema` estimates.
- **Key/value tables** (`wp_options`, `wp_postmeta`, Magento EAV and the like) are read key by key where they can be, so a key on only a few rows is still seen:
  - **Small tables:** a table of up to 20,000 rows and 32 MB is read once.
  - **Larger tables:** when its key column is indexed and the server enforces the statement timeout, a larger table has its keys listed with one `SELECT DISTINCT`. Up to 20 rows per key are then read with indexed lookups, alongside the usual sample of 3,000 rows.
    - **Prefix indexes:** a table indexed only on a prefix of its key column, as WordPress meta tables are, needs a full scan to list its keys. It's listed only up to 256 MB.
  - **Bigger tables**, and tables whose keys can't be listed, are sampled, 3,000 rows each, plus lookups for the keys the platform presets know. Without an index on the key column, those lookups are one pass over the table, run only when the table is small or the server enforces the statement timeout.
  - **Budgets:** a scan looks up at most 3,000 keys and reads at most 32 MB of values per table, and 30,000 keys, 256 MB of values and 1 GB of full-scan listings and passes in all, the main site's tables first.
  - **What's left out:** keys past these limits, or past the first 200,000 of a table, are judged by name only, and a warning says so. In a sampled table, keys outside the sample that no preset knows aren't seen.
  - **Without a preset,** a table counts as a key/value table when it has one of these shapes. It's then read the same way: whole, by listing and looking up its keys, or from a 3,000-row window when it's too large for both.
    - `key`/`value`, `meta_key`/`meta_value`, `option_name`/`option_value`, `setting_key`/`setting_value` or `config_key`/`config_value`;
    - `name`/`value`, `path`/`value` or `param`/`value`, when the table's name has a settings word such as `settings` or `options`;
    - any `X_key` beside an `X_value`;
    - an `X_name` beside a text `X_value`, when X names settings or fields, as in `setting_name` or `field_name`, or when the table's name has a settings word.

    An X that names people (`member_name`, `user_key`) or data (`customer_name`, `license_key`) keeps the table plain. Except for the shapes that need a settings word, the keys must read as identifiers or labels. Keys with a space that don't read as labels may be names. This check runs before any key is looked up:
    - a table keyed by people's names is judged as a plain table instead. Unless it's a translation table, or the column has a finding of its own, its key column gets a low-confidence finding: the starter config suggests hashing it, commented out;
    - the other keys that may be names are shown as `(key hidden)`.
- **Small extra checks:**
  - a few queries on indexed columns look for pending jobs, active webhooks, scheduled WordPress events, plugin email settings and Contact Form 7 forms;
  - some lookups (`IN` lists of up to 100 sampled IDs) verify inferred relationships.

Give it a user that can only read:

```sql
CREATE USER 'prodmask_ro'@'%' IDENTIFIED BY '…';
GRANT SELECT, SHOW VIEW ON shop.* TO 'prodmask_ro'@'%';
```

The report warns when the user it runs as could change the database.

`prodmask leak-check` uses the same read-only session. Its `hash` step reads about ten times what `scan` reads from each flagged table. Its `compare` step reads whole columns, so it's for staging, never production. [docs/leak-check.md](docs/leak-check.md) has the details.

## What counts as a credential

- **A key in an `Authorization: Basic` credential:** the credential is decoded, and its user and password are read for the known key formats. A key sent as either, as Stripe's `curl -u sk_live_…:` sends it, is reported as that key with its live or test mode, whatever the other part holds. If a real password comes with it, that's reported as well.
- **A password with no key in it** is critical, unless it reads as an example: a placeholder word such as `password`, one character repeated, a value that starts with `$`, `%`, `{`, `[` or `<`, or the user's own name, as in `admin:admin`.
- **An empty or missing password:** the credential is critical only if its user reads as a random key: a part of 16 or more characters, with two kinds of character and 10 distinct ones, and no spaces, `@` or dots. `deploybot:` doesn't count.
- **A password in a URL** follows the same rule for examples, read after its percent-escapes, and doesn't count at a host reserved for examples. The host can be a name, a bracketed IPv6 address, a template such as `${DB_HOST}`, or empty, as in socket URLs. In a list of hosts, only the first is judged. A user or password can hold an `@`, written plainly or as `%40`, so each `@` before the path may be the one that ends the password, and it counts if any of those readings does: an address after the URL, such as `,ops@example.com`, doesn't make the URL an example. The scheme can have capitals or an underscore, and the user can be any length.
- **A password that holds a `/`, `?`, `#` or one `'`** counts too, as in `mysql://app:…/…@db/shop`, since some parsers take one. Those bytes end a URL for most, so such a password isn't read if the text before the first of them reads as a port, if the user reads as a host, with a dot and no `@`, or if the password holds a colon or a `%40`, or ends in one of them. In a web link or a repository's URL, such as `https://` or `git+ssh://`, only a `'` can be part of a password.
- **A Go driver's DSN** reads as a URL, with or without a scheme, as in `app:…@tcp(db:3306)/shop`. The password runs from the first colon to the `@` before `tcp(`, `tcp4(`, `tcp6(`, `unix(`, or a bracket that holds a port and closes before a `/`, and the host is the address in the brackets. Text can come before a DSN, so a label such as `dsn:`, or a port or a time, isn't read as its user or password.

What doesn't count stays out of the report, though it may be a working credential. The span finders in `pkg/detect` still find it, with the detail `placeholder`, for tools that clear credentials rather than count them. A Basic credential that doesn't decode to ASCII text is read only if it holds a key.

## Starter config

`--config-out prodmask.yml` turns the findings into a starting point for masking:

- a strategy per column, meta key or JSON path (`fake_email`, `fake_phone`, `hash`, `null`, …), with a different one for some rows where a platform needs it, such as the WooCommerce orders among WordPress posts;
- `hash` instead of `null` or `empty` in a column with a unique index, where those would give every row the same value, with a comment that says why;
- one rule per family of keys, written as a pattern such as `"um_cache_userdata_*": delete`, where `*` stands for the part that varies. Caches the platform rebuilds get `delete`.
- a `name:` rule beside `mask:` when the key names themselves hold personal data;
- tables to empty;
- the inferred relationships;
- the settings to neutralise.

Weak matches appear commented out, and so do suggestions such as emptying a table that looks like a cache. Keys shown as `(key hidden)` get no rule, since no rule could name them without printing them; a comment says what they hold. The file's header explains patterns and paths, and [docs/config.md](docs/config.md) describes every section, including the ones prodmask Pro reads. Review every line: the config is a starting point, not a guarantee.

## Development

```bash
go test ./...
```

The integration tests build fake WordPress/WooCommerce, Magento 2 and Laravel databases, plus a generic schema no preset knows, and scan them. They run when `PRODMASK_TEST_DSN` points at a server where the user can create databases:

```bash
PRODMASK_TEST_DSN='root:…@tcp(127.0.0.1:3306)/' go test ./...
```

Their findings are compared with the golden files in `pkg/scan/testdata`. After a deliberate change, rewrite them with `go test ./pkg/scan -update`, with `PRODMASK_TEST_DSN` set, and review the diff line by line.

The scanner engine lives in importable packages under `github.com/ProdMask/ProdMask/pkg/...`. The command line is `pkg/cli`, which other builds can add commands to; `cmd/prodmask` is a thin main on top.

All fixture data is invented:

- phone numbers come from the 555-01xx fiction range;
- IP addresses come from the documentation ranges;
- secret-shaped test strings are assembled at run time.

## prodmask Pro

The scanner is free and stays open source. prodmask Pro is a separate paid product that:

- makes copies with the real shape and fake customers;
- switches off the settings that let staging email or charge anyone;
- checks the result.

Text and Markdown reports end with one line about it. See [prodmask.com](https://prodmask.com).

Pro's downloads are signed with minisign. Before you run one, check the release's `checksums.txt` against this key, the release key, whose key ID is `1B96620872FA537D`, and then your archive against `checksums.txt`, as [Install](#install) does:

```bash
minisign -Vm checksums.txt -P RWR9U/pyCGKWG6WkijsA6H8HDQghEFq7ix9bA4IdyMS9BsGbA9ctqOuP
```

## Security

Report a security issue privately, as [SECURITY.md](SECURITY.md) explains, not in a public issue.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
