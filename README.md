# prodmask

Find out what a plain copy of your production MySQL or MariaDB database would carry into staging, before you make one.

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

It knows WordPress and WooCommerce, Magento 2 and Laravel, and works on any MySQL or MariaDB schema.

Reports name tables, columns, keys and JSON paths, with counts and categories. They never contain the sampled values. Key names can hold data too, such as a user's email address inside a meta key. Those are shown as patterns like `um_email_as_username_*`, one line for all the keys that share the pattern.

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
| `--fail-on` | `none` | exit with status 3 if anything at or above `low`, `medium`, `high` or `critical` is found. Severities can rise between versions: v0.4.0 rates passwords stored as plain text critical. v0.5.0 adds critical findings for live keys in the new formats and for passwords in URLs and Basic headers, high ones for tokens whose mode can't be told and for `vendor_auth_code`, and medium ones for webhook names and test-mode keys; `sk-` findings on URL slugs go away. v0.9.0 rates a key inside a Basic credential as that key, so one sent as the user is now found, and one sent as the password can fall from critical: a test-mode key to medium, a token whose mode can't be told to high. It adds critical findings for a Basic credential with no password whose user reads as a random key, and for passwords in URLs that start with a percent-escape such as `%40`, or whose user holds a plain `@`. v0.10.0 adds critical findings for GitHub's stateless installation tokens, the long form an Actions `GITHUB_TOKEN` takes too. They had no finding before, or a high one after `Bearer` or `access_token=`. v0.11.0 adds critical findings for passwords in URLs at an IPv6 host, an empty host or a template such as `${DB_HOST}`, at a name that only looks reserved, such as `db.test_env` or `db_1.example.com`, and in URLs that a later address at a reserved host hid, as in `mysql://app:…@db.internal.shop,ops@example.com`. It adds one for a password that isn't ASCII beside a key in a Basic credential. A placeholder word in parentheses, such as `(password)`, no longer counts in a URL. v0.12.0 adds critical findings for passwords in Go driver DSNs with no scheme, such as `app:…@tcp(db:3306)/shop`, in URLs whose scheme has capitals or an underscore, such as `MYSQL://` or `pdo_mysql://`, or whose user is over 64 characters, and for passwords that hold a `/`, `?`, `#` or `'`, as in `mysql://app:…/…@db/shop`. A password of one character repeated no longer counts past ASCII either, such as `…`, and neither does a password whose `tcp(…)` address is at a host reserved for examples, as in `mysql://app:…@tcp(db.example.com:3306)/shop` |
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

The scanner is free and stays open source. prodmask Pro is a separate paid product, in development. It will:

- make small copies with the real shape and fake customers;
- switch off the settings that let staging email or charge anyone;
- check the result.

Text and Markdown reports end with one line about it. See [prodmask.com](https://prodmask.com).

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
