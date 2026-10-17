# prodmask

Find out what a plain copy of your production MySQL or MariaDB database would carry into staging, before you make one.

`prodmask scan` connects read-only and samples a few hundred rows per table. It reports:

- **Personal data and secrets:**
  - emails, phone numbers, addresses, names, dates of birth, national and tax IDs;
  - IBANs, card numbers, password hashes;
  - API keys (Stripe, AWS, SendGrid, GitHub and more), including inside JSON and PHP-serialized values.
- **What staging would do to real people:**
  - payment gateways in live mode;
  - mail settings that reach real inboxes;
  - active webhooks;
  - scheduled subscription renewals and queued jobs.
- **How the tables link up:** declared foreign keys, plus links inferred from naming and checked against the data, including Laravel polymorphic relations.

It knows WordPress and WooCommerce, Magento 2 and Laravel, and works on any MySQL or MariaDB schema.

Reports name tables, columns, keys and JSON paths, with counts and categories. They never contain the sampled values.

## Install

1. Download the archive for your system from the [releases page](https://github.com/ProdMask/ProdMask/releases). There are builds for Linux, macOS and Windows, each for amd64 and arm64.
2. Download `checksums.txt` from the same release.
3. Check the archive against it. On macOS, use `shasum -a 256 -c` instead of `sha256sum -c`:

```bash
grep prodmask_0.1.0_linux_amd64.tar.gz checksums.txt | sha256sum -c
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
| `--fail-on` | `none` | exit with status 3 if anything at or above `low`, `medium`, `high` or `critical` is found |
| `--preset` | `auto` | `none`, `wordpress`, `woocommerce`, `magento2` or `laravel` |
| `--sample-rows` | 300 | rows sampled per table |
| `--meta-sample-rows` | 3000 | rows sampled per key/value table such as `wp_postmeta` |
| `--no-samples` | | judge column names only; read no rows |
| `--timeout` | `10s` | server-side limit for each statement |
| `--verbose` | | also list low-confidence matches, inferred relationships and full evidence |

Exit status: 0 done, 1 error, 2 bad usage, 3 found something at or above `--fail-on`.

In CI, scan the database your staging copy came from, or the copy itself, and fail the build when it still holds personal data:

```bash
prodmask scan --dsn "$STAGING_DSN" --fail-on high --format markdown --out prodmask-report.md
```

## What it does to your database

`prodmask scan` is built to be safe to run against production:

- **Session settings:**
  - one connection with a read-only session (`transaction_read_only`) in autocommit mode, so no snapshot or lock outlives a statement;
  - `lock_wait_timeout` of 5 seconds, so it never queues behind a schema change;
  - a server-side statement timeout (`max_statement_time` on MariaDB, `max_execution_time` on MySQL).
- **Queries:**
  - every sampling query is a `SELECT … LIMIT`, ordered by primary key where there is one;
  - text values are cut to 4,096 characters on the server;
  - binary columns are skipped;
  - row counts come from `information_schema` estimates.
- **Small extra checks:** a few indexed queries look for pending jobs and active webhooks, and some lookups (`IN` lists of up to 100 sampled IDs) verify inferred relationships.

Give it a user that can only read:

```sql
CREATE USER 'prodmask_ro'@'%' IDENTIFIED BY '…';
GRANT SELECT, SHOW VIEW ON shop.* TO 'prodmask_ro'@'%';
```

The report warns when the user it runs as could change the database.

## Starter config

`--config-out prodmask.yml` turns the findings into a starting point for masking:

- a strategy per column, meta key or JSON path (`fake_email`, `fake_phone`, `hash`, `null`, …), with a different one for some rows where a platform needs it, such as the WooCommerce orders among WordPress posts;
- tables to empty;
- the inferred relationships;
- the settings to neutralise.

Weak matches appear commented out. Review every line: the config is a starting point, not a guarantee.

## Development

```bash
go test ./...
```

The integration tests build fake WordPress/WooCommerce, Magento 2 and Laravel databases and scan them. They run when `PRODMASK_TEST_DSN` points at a server where the user can create databases:

```bash
PRODMASK_TEST_DSN='root:…@tcp(127.0.0.1:3306)/' go test ./...
```

The scanner engine lives in importable packages under `github.com/ProdMask/ProdMask/pkg/...`. The command line is `pkg/cli`, which other builds can add commands to; `cmd/prodmask` is a thin main on top.

All fixture data is invented:

- phone numbers come from the 555-01xx fiction range;
- IP addresses come from the documentation ranges;
- secret-shaped test strings are assembled at run time.

### Releasing

Push a version tag:

```bash
git tag v0.1.0
```

```bash
git push origin v0.1.0
```

The release workflow then:

1. runs the tests;
2. builds `prodmask` for Linux, macOS and Windows (amd64 and arm64);
3. publishes the archives with a `checksums.txt` to GitHub Releases.

Tags with a suffix, such as `v0.2.0-rc.1`, are published as pre-releases.

To try the release build without publishing, run `goreleaser release --snapshot --clean`. The archives land in `dist/`. CI runs the same snapshot build on every push to `main` and on every pull request.

## prodmask Pro

The scanner is free and stays open source. prodmask Pro is a separate paid product, in development. It will:

- make small copies with the real shape and fake customers;
- switch off the settings that let staging email or charge anyone;
- check the result.

Text and Markdown reports end with one line about it. See [prodmask.com](https://prodmask.com).

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
