# The staging leak check

`prodmask leak-check` answers one question: how many real production values are on this staging database?

It's for a staging database made by your own masking script, or one you inherited. It samples the columns `prodmask scan` flags on production and keeps keyed hashes of those values, under a key only you hold. Then it reads those columns whole on staging, hashes what it finds the same way, and reports per column how many of the sampled values turned up. Reports hold counts, never a value or a row.

## What it can't tell you

Read this first, because a zero is the result most people hope for.

- **A zero is not proof.** Only a sample of values is looked for. See [the odds](#the-odds).
- **Only some kinds of data count:** email addresses, phone numbers, IBANs, national and tax IDs, payment tokens, password hashes and secrets. Real names, street addresses, cities and dates aren't looked for, because they match by chance, so they can still be there.
- **Card numbers aren't hashed.** `prodmask scan` on staging samples for them, and any real-looking card number there is a problem wherever it came from.
- **Only columns flagged on production are read.** A column `scan` didn't flag isn't looked at.
- **A value that was changed doesn't match.** A real name before a swapped domain, a common home-made mask, reads as a zero, and so does a real address with a suffix added.
- **Values no longer on production can't be sampled.** Copies of deleted customers on staging aren't found.

## Use

```bash
prodmask leak-check key --out leak.key
```

```bash
PRODMASK_PASSWORD='…' prodmask leak-check hash --dsn 'mysql://prodmask_ro@prod.internal:3306/shop' --key-file leak.key --allow-email shop.example --out shop.leakhashes.json
```

```bash
PRODMASK_PASSWORD='…' prodmask leak-check compare --dsn 'mysql://prodmask_ro@staging.internal:3306/shop' --key-file leak.key --hashes shop.leakhashes.json --fail-on high
```

`--dsn` is required on both steps, and `PRODMASK_DSN` is ignored: a wrong source gives a comforting zero, and a wrong target reads whole columns on production. **`compare` belongs on staging. Never point it at production.**

Run both steps from one machine if it can reach both databases, so the file never moves. Otherwise move it yourself, with something like `scp`. The tool never moves it.

### `hash`

| Flag | Default | |
|---|---|---|
| `--dsn` | required | production's connection string |
| `--out` | required | the file to write. There's no way to send it to standard output, so it can't land in a CI log |
| `--key-file` | `$PRODMASK_LEAK_KEY` | the file holding the key |
| `--allow-email` | | keep staff addresses out: a domain with its subdomains, or an exact address. Can be given many times |
| `--preset` | `auto` | as in `scan` |
| `--timeout` | `10s` | server-side limit for each statement |
| `--force` | | overwrite `--out` |

### `compare`

| Flag | Default | |
|---|---|---|
| `--dsn` | required | staging's connection string |
| `--hashes` | required | the file `hash` wrote |
| `--key-file` | `$PRODMASK_LEAK_KEY` | the file holding the key |
| `--allow-email` | | skip staff addresses, as on `hash`. You can add one here without running `hash` again |
| `--fail-on` | `none` | see [the gate](#the-gate) |
| `--fail-except` | | a column, key or table that can't fail the gate. Can be given many times |
| `--format` | `text` | `text` or `json` |
| `--out` | stdout | write the report to a file |
| `--max-time` | `1h` | the limit on the whole read, 0 for none |
| `--timeout` | `60s` | server-side limit for each statement |
| `--force` | | overwrite `--out` |
| `--no-color` | | plain text report without colours (also: `$NO_COLOR`) |

The last line on standard error always says what was found, so a CI log has it even with `--out`. With no match, that line says a zero isn't proof.

## The key

`prodmask leak-check key --out FILE` makes one: 32 random bytes, in hex, in a new file that only you can read, on systems with owner-only permissions. `openssl rand -hex 32` makes one too, but send it to a file you've made private first.

- A key is at least 64 hex characters. Passphrases are refused, because they're the one way a keyed hash can be guessed.
- No flag takes the key itself, so it stays out of process lists and shell history. It comes from `--key-file` or `$PRODMASK_LEAK_KEY`.
- The verbs' errors about flags and arguments don't repeat what you typed, in case the key went in the wrong place.
- The hash file holds a salt and a short check value, so `compare` can refuse a wrong key. It doesn't hold the key. A wrong key would otherwise read as a zero.
- Each file has its own salt, so one key used across checks, or across clients, gives unrelated hashes in each file. That doesn't protect a kept file: it stays testable for as long as the key lives.

## What counts

The same code reads both sides, so what a value yields on production it yields on staging, whether it's a whole column or sits inside JSON, PHP-serialized data or free text.

| Kind | Where it's looked for | Compared as |
|---|---|---|
| Email address | any flagged column | lower case. Domains reserved for examples, such as `example.com` and `.test`, don't count |
| Phone number | any flagged column when its layout says phone; any layout in a column flagged as phones | its digits, without a leading `00`. Under 8 digits, under 4 different digits, and runs such as `1234567890` don't count |
| IBAN | any flagged column | upper case, no spaces |
| National or tax ID | the whole value of a column flagged as that | upper case, without spaces, dots, dashes and slashes. At least 8 characters |
| Payment token | the whole value of a column flagged as that | exact, at least 12 characters |
| Password hash | any flagged column, and the whole value of a column flagged as that | exact |
| Secret, key, token, or password in a URL or Basic header | any flagged column, and the whole value of a column flagged as a secret | exact. A password needs at least 16 characters, as does a whole value. Test-mode keys and placeholders don't count |

Some flagged columns can't be compared, and the report lists them as left out: keys of a key/value table whose name can't be shown, findings about key names themselves, findings on some rows only, and key/value tables whose keys are stored as numbers, as in Magento's EAV tables.

## The odds

Sampling both sides wouldn't work: 300 rows each from a table of 100,000 share about one value even on a full real copy. So production is sampled and staging is read whole.

`hash` samples 3,000 rows per table. If a column holds `N` values, of which `L` are on staging, the chance of at least one match is close to `1 - (1 - 3000/N)^L`. In a table of 100,000:

| Real rows on staging | Chance of a match |
|---:|---:|
| 5 | 14% |
| 50 | 78% |
| 99 | 95% |
| 200 | 99.8% |

So the same zero means different things on different tables, and the report says what it means for each column: "about 98 real values would show 95% of the time; fewer may not", or, on a small staging table, "even if all 40 values here were real, this would catch it about 18% of the time".

**How the rows are picked.** The primary key's range is cut into 3,000 equal slices, and one row is read from a random spot in each. So a leak scattered through a table has the odds above, and a block is safer still: in a plain table, any unbroken run of rows covering two slices can't be missed, which is 67 rows in a table of 100,000. So "the last 90 days are real" can't slip through.

Some samples are weaker, and the report gives no odds for them, saying a copy of other rows reads as zero:
- a table with no single integer primary key, which gets its first 3,000 rows;
- a key with large gaps or tight clusters, where under half the slices find a row of their own, or rows sit far from their slices;
- a key of a key/value table on few rows, which gets one indexed lookup of its oldest 300, if its key column has an index;
- a sample a failed statement cut short.

A table under 3,000 rows is sampled whole, so its count is exact for the kinds above.

**A match can be chance.** Phone numbers and IDs are short enough that a masking tool making up realistic numbers can land on real ones. With 3,000 sampled and 1,000,000 values on staging, up to about 30 could match that way. The report says so on those lines, and if every match in a column could be chance, it says it can't tell either way. If no tool made those numbers, they're real.

From 10 matches up, on a spread sample, the report estimates the total: "1,860 of 3,000 (62%) · roughly 62,000 values in all". That's what tells a real 1% subset from a copy that kept a few real values: the subset matches 1% of the sample but holds about as many real values as it has rows.

## What it does to your databases

Both steps use the same read-only session as `prodmask scan`: one connection, read-only, in autocommit mode, with a server-side time limit on every statement. One statement runs at a time, and no snapshot or lock outlives a statement.

**On production,** `hash` runs a normal scan, then samples what it flagged:
- a plain table takes 3,000 one-row reads by primary key, in 60 statements;
- a key/value table reads primary keys and keys only at 3,000 points, 10 rows each, then the values of the flagged rows by primary key, so 30,000 rows of keys at most, and, where the key column has an index, at most 300 more rows for each rare key.

**On staging,** `compare` reads only the columns in the file, whole:
- a table with a single integer primary key is read in chunks of 5,000 rows, each a statement of its own;
- any other table is one statement, under `--timeout`;
- a key/value table is read the same way, row by row by primary key, keeping only the flagged keys' values, so a rare key can't turn one statement into a long scan;
- text is cut on the server to 4,096 characters, as `scan` does, or 65,536 for a key/value table with a unique key column, the same on both sides.

Tables are read smallest first. There's no cap on a table's rows: a table is read whole, or the report says it wasn't. `--max-time` is the bound on the whole read. As a guide, about 230,000 rows a second were read on an idle local server with everything cached; a server reading cold pages can be 10 to 50 times slower.

Give it a user that can only read, as for `scan`.

## The gate

Without `--fail-on`, `compare` exits 0 unless it read nothing at all. With it:

| Status | When |
|---|---|
| 0 | Done, and `--fail-on` wasn't tripped |
| 1 | An error, or nothing read at all, or a column at or above `--fail-on` couldn't be checked in full |
| 2 | Bad usage: a wrong or missing key, an unreadable file, or one made by another version |
| 3 | A sampled value at or above `--fail-on` turned up, even in a column read only in part |

`--fail-on` takes the same words as `scan`. Secrets are critical, since the exact production value is on staging, and every other kind is high. So `--fail-on high` means any kind, and `--fail-on critical` means secrets only.

**The gate fails whenever it couldn't look,** including when a column is missing on staging, since a renamed column would otherwise go unnoticed. That's status 1 for a column:
- stopped by a time limit or an error;
- not read because `--max-time` came first;
- not on staging;
- no longer readable, as a view or a binary column;
- whose production sample was cut short, or which production couldn't sample at all, with no match;
- on a table the scan couldn't read all of on production, since some of its columns may have gone unflagged;
- a rare key of a key/value table the sample couldn't reach.

A match counts whatever its line says, including "all of these could be chance". `--fail-except` is the way out, and it's explicit: `--fail-except wp_options.option_value[store_phone]` for the shop's own phone number in a settings row, or a whole table dropped on purpose. The column is still read and reported.

`hash` exits 1 and writes no file if it finds nothing to hash, since an empty file would only give a zero.

## In CI

Run both steps in one job, with a key made for that job, so there's no secret to keep and no file to move:

```yaml
- name: Check staging for real production values
  env:
    PROD_DSN: ${{ secrets.PROD_DSN }}
    STAGING_DSN: ${{ secrets.STAGING_DSN }}
  run: |
    prodmask leak-check key --out "$RUNNER_TEMP/leak.key"
    prodmask leak-check hash --dsn "$PROD_DSN" --key-file "$RUNNER_TEMP/leak.key" --allow-email shop.example --out "$RUNNER_TEMP/hashes.json"
    prodmask leak-check compare --dsn "$STAGING_DSN" --key-file "$RUNNER_TEMP/leak.key" --hashes "$RUNNER_TEMP/hashes.json" --fail-on high
```

If one runner can't reach both databases, a CI artifact can carry the file, but it then sits on your CI vendor's storage, readable by anyone with read access to the repository. Keep the key out of it, in a CI secret both jobs read, and give the artifact the shortest retention your CI allows.

## Data protection notes

**This isn't legal advice.** It's what the tool does and what follows from it, for you and your data protection officer or lawyer to judge for your own case.

1. **The hash file comes from real people's data. Treat it as personal data,** wherever it goes, with the same limits as production.
2. **Anyone with both the key and the file can test a guess:** confirm whether an address from any list is in the sample, and try every phone number or ID. A kept file stays testable for as long as the key lives. Keep them apart. Run `compare` from a machine you trust, not on a staging box less protected than production. Delete the file when you're done. Don't commit it or attach it to tickets.
3. **ProdMask receives nothing:** no telemetry, no calls home. Where the file goes is up to you, as under [In CI](#in-ci).
4. **Running the check is a use of production data.** Record it however your process requires, with its lawful basis. If you run it on a client's database, do it on the client's instructions.
5. **Moving the file to another country may be a transfer** under Chapter V of the GDPR. Prefer one machine, or the same region.
6. **The report holds table, column and key names with counts, and no values.** A report with matches is a record that real data is on staging, unless every line says all its matches could be chance; then it can't tell either way. Take it to your data protection officer promptly: at least one EU controller has notified a regulator of a similar finding, in an Article 60 decision of the Estonian Data Protection Inspectorate. The tool doesn't decide what happens next.
7. **A zero doesn't show that staging holds no personal data.** See [What it can't tell you](#what-it-cant-tell-you).
8. **What else the files show:** the hash file alone shows flagged table and column names, table sizes and the staff domains you allowed. An address you allow on the command line sits in your shell history or CI config, though it's never written to the file or a report. Anyone who can write to staging and read reports can test a guess by watching the counts. On Windows the files don't get owner-only permissions; they take their folder's.
