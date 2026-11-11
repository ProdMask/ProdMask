# Changelog

These are the changes that can change a build's result: findings that appear, go away or change severity. A `--fail-on` gate that passed may fail after an upgrade, or the other way round. Each release's notes on GitHub have the rest.

## v0.12.0

Adds critical findings for passwords in Go driver DSNs with no scheme, such as `app:…@tcp(db:3306)/shop`, in URLs whose scheme has capitals or an underscore, such as `MYSQL://` or `pdo_mysql://`, or whose user is over 64 characters, and for passwords that hold a `/`, `?`, `#` or `'`, as in `mysql://app:…/…@db/shop`. A password of one character repeated no longer counts past ASCII either, such as `…`, and neither does a password whose `tcp(…)` address is at a host reserved for examples, as in `mysql://app:…@tcp(db.example.com:3306)/shop`.

In free text, it adds medium findings for a phone number with one digit after the country code, such as `+33 6 12 34 56 78`, or followed by other digits, as in `+14155550123 2024-01-02`. A date or an IP address with a plus in front no longer counts as a phone number, and neither does an ISBN with a plus in free text.

## v0.11.0

Adds critical findings for passwords in URLs at an IPv6 host, an empty host or a template such as `${DB_HOST}`, at a name that only looks reserved, such as `db.test_env` or `db_1.example.com`, and in URLs that a later address at a reserved host hid, as in `mysql://app:…@db.internal.shop,ops@example.com`. It adds one for a password that isn't ASCII beside a key in a Basic credential. A placeholder word in parentheses, such as `(password)`, no longer counts in a URL.

## v0.10.0

Adds critical findings for GitHub's stateless installation tokens, the long form an Actions `GITHUB_TOKEN` takes too. They had no finding before, or a high one after `Bearer` or `access_token=`.

## v0.9.0

Rates a key inside a Basic credential as that key, so one sent as the user is now found, and one sent as the password can fall from critical: a test-mode key to medium, a token whose mode can't be told to high. It adds critical findings for a Basic credential with no password whose user reads as a random key, and for passwords in URLs that start with a percent-escape such as `%40`, or whose user holds a plain `@`.

## v0.5.0

Adds critical findings for live keys in the new formats and for passwords in URLs and Basic headers, high ones for tokens whose mode can't be told and for `vendor_auth_code`, and medium ones for webhook names and test-mode keys. `sk-` findings on URL slugs go away.

## v0.4.0

Rates passwords stored as plain text critical.
