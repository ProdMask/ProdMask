# prodmask.yml

`prodmask.yml` says how to copy a database for staging, development or tests: what each column, key and path should get in the copy, which tables to empty, and what to switch off.

- `prodmask scan --config-out prodmask.yml` writes a starter version from a scan's findings. Review every line: it is a starting point, not a guarantee.
- prodmask Pro reads the same file to make copies. `prodmask plan` turns it into `prodmask.lock`, which records the rule for every table and column, and for the keys it lists, and `prodmask copy` follows the lock.

This page describes every section, which ones the starter config holds, and how Pro reads them.

## Sections

| Section | In the starter config | Read by Pro |
|---|---|---|
| `version`, `database`, `platforms` | yes | `version` must be 1 |
| `tables` | yes | yes, plus two keys of Pro's own: `class` and `without_primary_key` |
| `relationships` | yes | to check text keys |
| `neutralise` | yes | accepted; a copy warns that it doesn't apply them yet |
| `source`, `target` | no | where to copy from and to |
| `keys` | no | how fakes are derived |
| `staging_password_env` | no | the password staging logins get |
| `classes` | no | which rows are customer data, content, settings or transient |
| `rules`, `keep`, `public` | no | rules by pattern, values to keep, and public fields |
| `views` | no | views that read other schemas |

Pro reads the file strictly:

- an unknown key, a wrong type or a bad value is an error that names the line;
- YAML anchors, aliases, tags and duplicate keys are refused;
- the file may be at most 1 MB.

Errors about the file never quote what you wrote in it. They give the line, where in the file in plain words, and what is wrong.

Column names match whatever their letter case, as MySQL's do. Table names match as the server's `lower_case_table_names` says.

## An example

```yaml
version: 1
database: shop
platforms: [wordpress, woocommerce]

source: { dsn_env: PRODMASK_SOURCE_DSN, password_env: PRODMASK_SOURCE_PASSWORD }
target: { dsn_env: PRODMASK_TARGET_DSN, allow_hosts: [staging-db.internal] }
keys: { mode: stable, key_env: PRODMASK_MASK_KEY }
staging_password_env: PRODMASK_STAGING_PASSWORD

classes:
  wp_my_plugin_log: transient
  wp_posts:
    - { where: "post_type = 'event' AND post_status = 'publish'", class: content }

rules:
  - { match: "*.billing_vat_number", rule: hash }
  - { match: "wp_postmeta[_my_plugin_*]", rule: redact }
keep: [ "wp_options[my_theme_layout]" ]
public: [ "wp_my_reviews.author_name" ]
views: { keep_cross_schema: [ v_orders_with_stock ] }

tables:
  wp_users:
    columns:
      user_email: fake_email  # email address, high confidence
      user_pass: staging_password
  wp_usermeta:
    key_column: meta_key
    value_column: meta_value
    keys:
      billing_phone: fake_phone
      "um_cache_userdata_*": delete
  wp_woocommerce_sessions:
    action: truncate
```

## Masks

Each rule in `tables`, `rules` and `rows` names one of these:

| Mask | What the copy writes |
|---|---|
| `keep` | the value as it is, except that secrets, and the customer details Pro finds in kept text, are replaced |
| `null` | NULL; in a NOT NULL column, the type's empty value |
| `empty` | the type's empty value: `''`, `0`, a zero date, JSON `null` |
| `delete` | in a key/value table, no row at all |
| `hash` | a keyed hash of the value, as lower-case hex |
| `redact` | generated text of about the same length |
| `fake_email`, `fake_phone`, `fake_name`, `fake_first_name`, `fake_last_name`, `fake_username` | a generated value of that kind |
| `fake_street`, `fake_postcode`, `fake_city`, `fake_company` | a generated address part or company name |
| `fake_iban`, `fake_ip`, `fake_user_agent`, `fake_date` | a generated IBAN, IP address, browser user agent, or a date moved by up to a year (one that reads either way, such as 05/06/1990, moves by whole years) |
| `test_card` | a card number payment providers publish for testing; in a unique column, a valid number that starts as one does |
| `staging_password` | the staging password, hashed the way the original was |

Pro also reads `keep_if_integer`, `keep_if_decimal`, `keep_if_date`, `keep_if_boolean` and `keep_if_uuid`: the value is kept when it has that shape, checked value by value, and gets its row's default otherwise.

Generated values fit the column. Emails use the reserved domain `example.com`. Phones keep their layout and use fiction ranges where they can: 07700 900xxx for UK mobiles and 555-01xx for North American numbers. Other phone numbers, and those in unique columns, are random numbers that look real. A phone or card column's value keeps only its number's layout: any text beside the number is dropped. IP addresses come from the ranges reserved for documentation, and for unique columns from 198.18.0.0/15, which is reserved for benchmarking and never routed.

## tables

The starter config writes one entry per table that needs a rule:

- `columns:` a mask per column;
- `key_column`, `value_column` and `keys:` for key/value tables, such as `wp_usermeta`, a mask per key or family of keys;
- `action: truncate` for a table the copy should empty, such as sessions and logs;
- under a column or key, a map instead of a mask when more is needed:
  - `mask:` the value's mask;
  - `paths:` masks for paths inside a JSON or PHP-serialized value;
  - `rows:` masks for some rows only, each with a `where` condition;
  - `name:` a rule for the key's own name, when the name holds personal data.

Weak matches are written commented out, and so are suggestions such as emptying a table that looks like a cache.

Pro adds two keys under a table:

- `class:` the table's class (see [Classes](#classes));
- `without_primary_key: copy`, for a table with no primary key and more than 100,000 rows, which Pro won't copy without a rule (`class: transient` empties it instead).

### Patterns and paths

- In keys and in path segments, `*` stands for one or more characters that vary, such as a user ID: `"um_cache_userdata_*"`.
- A path segment that is exactly `*` stands for the keys at that level that aren't plain names, such as hashes, labels with spaces or data. Plain-named keys beside them keep their own rules. Stored keys never contain `*`.
- In paths, `[]` stands for each item of a list, or each numeric key of a map, such as a timestamp. `{}`, always last, stands for the keys of a map whose keys are data, such as email or IP addresses.
- An exact name wins over a pattern, more fixed characters win over fewer, and on a tie the earlier line wins.

`rules`, `keep` and `public` take patterns of the same kind, naming a column (`wp_users.user_email`), a key of a key/value table (`wp_usermeta[billing_phone]`), or a path inside a structured value (`wp_options[woocommerce_paypal_settings]:api_password`). In each part, `*` stands for one or more characters.

### Keys the scan doesn't show

A key name can itself be personal data, such as a customer's name or handle. The scan shows those keys as `(key hidden)`, and the starter config gets a comment saying what they hold, but no rule, since it can't name them without printing them. You can still write a rule for a key you know by its exact name: Pro matches it without printing it.

Pro doesn't print them either. In customer rows it replaces their names with keyed hashes and gives their values its default for customer data. In published content and settings, their values are kept, with the customer details Pro finds in them replaced.

## Classes

Pro gives every row a class, and the class decides what the copy does with values no rule covers:

| Class | Default |
|---|---|
| customer | values are replaced: text with generated text, structured values with the same structure and generated leaves, other types with NULL or the type's empty value |
| content | values are kept, except that secrets are cleared and the customer details found in them replaced |
| config | as content |
| transient | the copy has no rows |

Numbers, dates, enums and key columns are kept in every class, unless a rule says otherwise.

**WordPress** comes with its classes:

- `users`, `usermeta`, `comments` and `commentmeta` are customer data;
- `options` and `sitemeta` are settings, except transients (`_transient_*`, `_site_transient_*`), which the copy drops;
- `terms`, `term_taxonomy`, `termmeta`, `term_relationships` and `links` are content;
- tables the preset empties, such as WooCommerce sessions, logs and API keys, are transient;
- `posts` is decided row by row, by these rules in order:
  1. attachments and revisions with a parent take their parent's class;
  2. attachments without a parent are content, unless they are trashed or private;
  3. block theme parts, menu items and field groups (`wp_template`, `wp_template_part`, `wp_global_styles`, `wp_navigation`, `wp_block`, `wp_font_family`, `wp_font_face`, `nav_menu_item`, `acf-field-group`, `acf-field`, `custom_css`) are content;
  4. published posts, pages and products are content, and so are published and private product variations;
  5. everything else is customer data: orders, drafts, private posts, privacy requests, form entries and every post type no rule names;
- `postmeta` rows take their post's class.

Any other table is customer data. `prodmask plan` lists the tables and post types that fell to customer data, with row counts, so you can see what to change.

`classes:` sets a class for a table, or row rules for it, which come before the preset's:

```yaml
classes:
  wp_my_plugin_log: transient
  wp_posts:
    - { where: "post_type = 'event' AND post_status = 'publish'", class: content }
```

### Published content

Content is copied as the live site shows it. Customer details found in it, such as a customer's name quoted on a testimonials page, an email address or a phone number, get generated values that link to nothing else in the copy. Every email address, IBAN, card number, IP address and phone number in a phone's layout found there is replaced, the site's own included, since a copy can't tell them apart.

The starter config's `tables:` rules were written from findings, not for published pages. So in content and settings rows:

- a `tables:` rule that generates a value (a `fake_*` mask, `redact`, `hash`) gives way to the content default: the page is kept, and the details found in it are replaced;
- a `tables:` rule that keeps or removes a value (`keep`, `keep_if_*`, `null`, `empty`, `delete`) applies as written;
- rules under `rules:`, `keep:` and `public:` apply as written in every row, so that is where to override the content default on purpose.

`prodmask plan` lists every rule that gave way.

**Public fields** are values the live site shows, such as the names of comment authors and of the users who write posts. Their generated values link to nothing else either. Name your own in `public:`.

**Settings keep their names.** A setting's name is copied as it is, even when it holds a customer's handle; its value follows the settings default.

## Rows: the where grammar

`rows:`, `classes:` and the scan's row rules select rows with a small grammar: columns, literals, comparisons, `IN`, `IS NULL`, `AND`, `OR`, `NOT`, and `NOW()` with `INTERVAL`.

```text
post_type IN ('shop_order', 'shop_order_refund') AND post_status <> 'trash'
post_date < NOW() - INTERVAL 2 YEAR
```

- **Operators:** `=`, `!=`, `<>`, `<`, `<=`, `>`, `>=`, `[NOT] IN (…)`, `IS [NOT] NULL`.
- **Literals:** quoted strings (with `''` and backslash escapes, as MySQL reads them by default), integers, decimals, `NULL`, `TRUE` and `FALSE`.
- **Columns** are bare or in backquotes, and must be columns the copy reads. Generated columns are refused.
- **Units:** `SECOND`, `MINUTE`, `HOUR`, `DAY`, `WEEK`, `MONTH`, `YEAR`.
- **Limits:** 4 KB of text, 32 levels of nesting, 256 items in an `IN` list.
- No subqueries and no other functions.

Pro evaluates conditions itself, on the rows as they are before anything is replaced, with SQL's rules for NULL: a row matches only when the condition is true.

- Numbers compare as numbers. Comparing a number column with a string, or a text column with a number, is refused.
- Dates compare as dates. `NOW()` is the moment the copy's snapshot starts, in UTC.
- Text compares either exactly or ignoring case and accents, and `<`, `>` and the like are refused on text. Which one depends on which way is safe:
  - a rule is **protective** when matching more rows is safer: rules that make rows customer data or transient, and row masks that replace or remove values. Its tests match ignoring case and accents, so `post_status = 'Private'` matches `private` too;
  - every other rule is **permissive**, such as one that makes rows content or keeps values. Its tests match exactly;
  - under `NOT`, it's the other way round, so a permissive `post_status <> 'Private'` still leaves out `private`.

  Ignoring accents drops letters outside the Latin alphabet, so in a protective rule a Greek or Cyrillic literal matches any value written only in those letters. That matches more rows, which for a protective rule is the safe side.

When later versions use the same grammar to select rows on the server, such as the root rows of a subset, the server's collation decides how text compares. This page will say so where it applies.

The scan's `relationships:` and `neutralise:` entries also have a `where`, but it isn't this grammar: in `relationships:` it is the type column and value of a polymorphic link, and in `neutralise:` the table and setting to change.

## source and target

```yaml
source: { dsn_env: PRODMASK_SOURCE_DSN, password_env: PRODMASK_SOURCE_PASSWORD }
target: { dsn_env: PRODMASK_TARGET_DSN, password_env: PRODMASK_TARGET_PASSWORD, allow_hosts: [staging-db.internal] }
```

`dsn_env` and `password_env` name environment variables, so DSNs and passwords never sit in the file. `prodmask copy`'s flags take precedence, and `--allow-host` adds to `allow_hosts`. Changing these needs no new plan.

## keys

```yaml
keys: { mode: stable, key_env: PRODMASK_MASK_KEY }
```

Each generated value is derived from the original with a keyed hash, so the same email gets the same fake in every table and every column.

- **`mode: stable`** uses a key you keep. The same data then gives the same copy every time (with `staging_password_env` set, so the staging password is the same too), which keeps test fixtures, screenshots and bug reports working across refreshes.
- **`mode: per_run`** uses a new random key for each copy, which is never written anywhere, so no copy's fakes can be matched with another's.

The key is 32 random bytes, written as `pmkey1.` and 43 more characters. `prodmask keys new --out FILE` writes a new one to a new file and prints only its fingerprint. Give it to Pro through the variable `key_env` names (`PRODMASK_MASK_KEY` by default) or with `key_file`. Keep it out of the repository, in a folder only you can read: on Windows the file takes its folder's permissions.

The lock holds a **scope**, a random value the first `prodmask plan` creates, which every later plan keeps. Fakes depend on the key and the scope together, so two projects that share a key still get different fakes. Don't edit or regenerate the scope: every fake would change. `plan` and `copy` warn before anything would change every fake: a new scope, a different key, a change of mode, or new word lists.

## staging_password_env

Staging logins get one password, so you can log in as anyone:

- from the variable `staging_password_env` names, which must not be empty;
- otherwise generated for each copy, 20 letters and digits.

Columns with the `staging_password` mask, such as `wp_users.user_pass`, get a hash of it in the format the original used: phpass, bcrypt, WordPress's `$wp$` bcrypt, or MD5 for legacy WordPress hashes. Other formats get bcrypt. A column that holds passwords as plain text gets the staging password as plain text. In settings, passwords are service credentials, not logins, so they are cleared instead.

WordPress pages protected by a password get a password of their own, derived from the staging password, so the pages' passwords don't reveal the staging password.

A generated password is printed only when the copy runs in a terminal, and not in CI. Otherwise `--staging-password-file` is required, and the passwords are written to that file before anything is copied. Git Bash's terminal on Windows doesn't count as one, so runs there need the file too. On Windows the file takes its folder's permissions.

## rules, keep and public

```yaml
rules:
  - { match: "*.billing_vat_number", rule: hash }
  - { match: "wp_postmeta[_my_plugin_*]", rule: redact }
keep: [ "wp_options[my_theme_layout]" ]
public: [ "wp_my_reviews.author_name" ]
```

- `rules:` gives a mask to every column, key or path a pattern matches.
- `keep:` keeps values as they are. Kept text is still checked for secrets and for the customer details Pro looks for. A secret, a password hash, a payment token or session data is never kept in customer rows, whatever a rule says.
- `public:` marks values the live site shows, which get generated values that link to nothing else.

Which rule decides a value, first match wins:

1. `prodmask.yml`: a `rows:` rule whose condition matches; the field's own rule under `tables:`; then `rules:`, `keep:` and `public:`.
2. Pro's presets for the platform.
3. The scan's confident findings, their row rules first.
4. The type: numbers, dates and key columns are kept.
5. The row's class default.

## views

```yaml
views: { keep_cross_schema: [ v_orders_with_stock ] }
```

A copy leaves out views that read other schemas, since they would read the other schema's real data on the target. A view listed here is kept when every schema it reads exists on the target, as a copy that is complete and masked, and the target isn't the source's server. Otherwise it is left out, and the copy says why.

## Unique values

Generated values stay unique where the column has a unique index, and where an application keeps values unique without one, such as WordPress's logins, emails and nicenames. Values compare ignoring case and accents, as the common collations do. Where a collation equates more, such as `general_ci` with `ß` and `s`, a generated value could still meet a kept one: under an index the copy then stops with an error naming the column; without an index, such as the application-level uniques, it would pass unnoticed. Both are rare, since generated unique values end in random characters.

## What a copy keeps as it is

- **The schema's own text.** Tables, views and triggers are created as the source prints them, so literals in column defaults, comments, CHECK constraints, view definitions and partition values reach the copy as they are. Developers write those, not customers, but check them if yours hold data.
- **Settings' names**, as above.

## Coming in later versions

Pro refuses these sections for now, with "not in this version yet":

- `rewrite_urls`, to point a copied site at its staging address;
- `subset`, to copy part of the data, following its relationships.
