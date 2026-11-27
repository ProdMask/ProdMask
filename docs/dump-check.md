# Checking a dump file

`prodmask scan --dump FILE` reads a SQL dump file in place of a database and reports what a scan of that database would find in it. Run it on the dump your masking tool wrote, before the dump goes anywhere: it shows which columns and keys still look like personal data or secrets. It reads the file and nothing else. There is no server and no password, and it changes nothing.

```bash
prodmask scan --dump shop-masked.sql.gz --fail-on high
```

Reports hold names, counts and categories, never a value from the file.

## What it can't tell you

Read this first, because "nothing found" is the result most people hope for.

- **A finding is a shape.** The scan judges the names of columns and keys and the shape of the values in them: something that looks like an email address, a phone number or a key. A masked value can look the same as a real one, and a real one can look like nothing. A masker's fake addresses are found, and so is a real address that was left alone. To count real production values in a dump, use `prodmask leak-check compare --dump`, which looks for values from production by their keyed hashes.
- **It judges a sample.** By default, up to 300 rows of each table, the same rows a scan of a database reads, and every key of the key/value tables such as `wp_options` and `wp_postmeta`. A value in a row it didn't read isn't judged. Raise `--sample-rows` to read more.
- **For a table with no integer key, it judges the first rows of the file.** A scan of a database reads the first rows the server returns. From a file, those are the first rows written, which are the same rows only when the dump was written in the table's natural order, as `mysqldump` writes it. A table whose first rows are masked and whose later rows aren't looks clean.
- **Triggers, routines, events and views aren't judged.** Their bodies can hold values, such as a literal address in a trigger. The report says how many there are (the JSON report in `bodies_not_judged`), and it passes the gate. A trigger, routine or event whose body the reader can't follow isn't read, and fails the gate.
- **Expression defaults and generated columns aren't judged either.** A column's `DEFAULT (…)` expression, or a generated column's, can fill it with a value when a row leaves it out or gives `DEFAULT`, as `DEFAULT (uuid())` does. The JSON report counts those values in `defaults_without_literal`, and they pass the gate.
- **`IDENTIFIED BY` clauses aren't judged.** A `CREATE USER` or `GRANT` in the file can hold a password. The report warns that the file creates users (the JSON report counts the statements that can set a password in `user_statements`), and it passes the gate.
- **Rows are judged as written.** A file with `REPLACE` or `INSERT IGNORE` rows that repeat a key holds more rows than the database it loads into, since the database keeps one row for the key. Both rows are judged, and a value that only a replaced row held is reported.
- **Version comments are read as SQL.** The text of every `/*!…*/` and `/*M!…*/` comment is read as the servers that run it read it. A comment a supported server might skip (every `/*M!`, and a `/*!` from 5.7.00 on) is accepted only where skipping it can't change what loads; anywhere else the statement isn't read. Supported means MySQL 5.7 or later and MariaDB 10 or later: a server older than that can skip comments the reader counts as run.
- **It assumes the file loads without `--force`.** A statement the server rejects stops a default load of the file, so what follows it never loads. With `mysql --force` the load goes on past it, and the file can then load other rows into other tables than the check judged.
- **It can't know the server's `lower_case_table_names`.** A server with it set (the default on Windows and macOS) takes table names that differ only by letter case for one table. A table created again under another case keeps its first structure, as on such a server, and unless the two match, that statement isn't read and the gate fails. A `DROP` by another case drops nothing, as on Linux, and a `CREATE` after it meets the same rule.
- **Side effects aren't checked.** The scan of a database also reads live settings and queues, such as payment gateways, mail settings, webhooks and scheduled jobs, which a file doesn't hold in a form that can be told from data. The report says so in that section, and the JSON report lists `side_effects` under `not_checked`.
- **Data in the file's other databases, or in statements it couldn't read, isn't judged.** The report lists every statement it couldn't read, and the gate fails on them (see below).
- **It doesn't decide what the law calls anonymous.** A report with no findings isn't a statement about data protection law.

## Use it after each masker

Check the file the masker wrote, in the form you will ship.

With `mysqldump` or `mariadb-dump`, dump the masked database to a file, keeping its structure:

```bash
mysqldump --single-transaction --default-character-set=utf8mb4 --databases shop_staging > shop-masked.sql
prodmask scan --dump shop-masked.sql --fail-on high
```

With [gdpr-dump](https://github.com/Smile-SA/gdpr-dump), which writes a masked dump as it goes:

```bash
gdpr-dump config.yaml > shop-masked.sql
prodmask scan --dump shop-masked.sql --fail-on high
```

With [myanon](https://github.com/ppomes/myanon), which masks a dump on its way through:

```bash
myanon -f myanon.conf < shop.sql > shop-masked.sql
prodmask scan --dump shop-masked.sql --fail-on high
```

Compress the file if you like; `--dump` reads gzip as it is. The file is read twice, so it takes a path, not standard input, and it must not change while the scan runs.

If a masked dump is made by a pipeline, write it to a file first, which is what you ship anyway.

## What it reads

- **Files:** a plain file or a gzip file. zstd, xz, bzip2, zip and 7z give an error that says how to decompress the file first. A file that isn't a dump gives an error and no report.
- **Dumps from:** `mysqldump` and `mariadb-dump`, `mysqldump-php` (the library behind gdpr-dump), phpMyAdmin, and a hand-written file in the same statements. The report names the producer from the header when the file has one.
- **Structure:** `CREATE TABLE`, `CREATE INDEX` and the `ALTER TABLE` forms that add keys and constraints. A table's columns and keys are read as a database reports them, so the same findings follow.
- **Rows:** `INSERT` and `REPLACE`, extended or single, with or without a column list. A table with rows but no `CREATE TABLE` is read as text under the `INSERT`'s column names, with a warning; this is also how a file made with `--no-create-info` reads.
- **Platforms:** WordPress, WooCommerce, Magento and Laravel are recognised from the file's own tables and settings, as on a database.
- **Counted:** every statement. Each is read, known and holding no rows (`SET`, `LOCK TABLES`, `CREATE VIEW` and so on), part of the structure, or not read.

### Statements it couldn't read

Each one is listed in the report, under Warnings, with its line, its kind and why:

```
! line 1,234: an INSERT into wp_users wasn't read: an expression the reader doesn't evaluate
```

The first 100 are listed, then a count. The reasons are a closed list: a statement kind it doesn't read (`UPDATE`, `LOAD DATA`, `CREATE TEMPORARY TABLE`), an expression in a row (`CONCAT(…)`, `NOW()`), a form of `INSERT` it doesn't read (`INSERT … SELECT`, `ON DUPLICATE KEY UPDATE`), a row with too many or too few values, a character set it doesn't decode, a file that ends inside a statement or inside quotes, an identifier longer than 256 bytes, an `ALTER TABLE` it doesn't follow, a table created twice with other columns, more than one statement before the delimiter (the `mysql` client sends everything up to the delimiter as one query, and the server runs each statement in it; when one after a `;` is a `SET`, `USE` or `DELIMITER`, the rest of the file isn't read either), a version comment some servers skip, where skipping it changes the statement (when skipping it can change the database, the SQL mode or the character set, the rest of the file isn't read either), and two that leave the rest of the file unread from that statement on: an SQL mode it can't work out, and a command of the `mysql` client's own, such as `\g` or a `use db` line with no `;`.

### Options

| Flag | |
|---|---|
| `--dump FILE` | the dump file, a path |
| `--database NAME` | the database to scan, when the file holds tables of several |
| `--sample-rows N` | rows judged of each table (default 300) |
| `--no-samples` | judge names only, and read the file once |
| `--preset`, `--format`, `--out`, `--force`, `--fail-on`, `--verbose`, `--no-color` | as for a database |

These don't go with `--dump`, and give exit status 2: `--dsn` and `--project`, `--timeout` and `--meta-sample-rows` (which don't apply), `--config-out` (the starter config is for a copy made by reading the database), and `-` in place of a path. `$PRODMASK_DSN` isn't read, and a line on standard error says so when it's set.

## The gate

`--fail-on` works as it does on a database, with one addition: a statement that wasn't read can hide a finding, so it fails the gate too.

| Case | Exit |
|---|---|
| a finding at or above `--fail-on` | 3, whatever else is unread |
| no such finding, and a statement was left unread | 1, after the report, with a line on standard error |
| everything read, nothing at the threshold | 0 |
| no `--fail-on` | 0; the report lists everything |
| a file with no rows | 0, with the warning that no values were judged |
| unread statements of another database than the one checked | not counted |
| an unread statement whose database can't be told | counted |
| a gzip file that ends early or is damaged | 1, after the report of what was read, whatever `--fail-on` says |
| a file that isn't a dump | 1, with no report |
| tables of several databases and no `--database` | 2 |

## What the report says at its end

A report on a dump closes with the bodies of triggers, routines, events and views it didn't judge, when the file creates any; with how many rows were judged; with what a finding is (above); and, in the free build, with a line about prodmask Pro, which makes masked copies and checks every value of them. The JSON report carries the same facts in its `dump` object: the file's base name, the statements by kind, the rows, the unread statements, the bodies not judged and the rows judged. The file's path is never printed.
