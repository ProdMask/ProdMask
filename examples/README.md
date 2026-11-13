# A fake shop to scan

`shop.sql` is a WordPress and WooCommerce database filled with invented customers, orders and settings. Scan it to see what `prodmask scan` reports before you point it at a database of your own.

Nothing in it belongs to a real person:

- names come from short lists, and streets and cities are mixed at random;
- phone numbers are in the 555-01xx range reserved for fiction;
- IP addresses come from the ranges reserved for documentation;
- every key and password is made up.

It holds what a real shop would: payment gateway keys, mail settings, webhooks, scheduled renewals, and customer data inside PHP-serialized values.

## With Docker

```bash
cd examples
docker compose up -d --wait
```

This starts MariaDB 11.8 on 127.0.0.1:3399 and loads `shop.sql` the first time, which takes a minute or so. Then scan it:

```bash
PRODMASK_PASSWORD=demo prodmask scan --dsn 'mysql://prodmask_ro@127.0.0.1:3399/shop'
```

In PowerShell:

```powershell
$env:PRODMASK_PASSWORD = 'demo'
prodmask scan --dsn 'mysql://prodmask_ro@127.0.0.1:3399/shop'
```

With only Docker, skip installing prodmask: `docker compose run --rm scan` starts the shop and scans it with prodmask's image. `docker compose --profile scan down -v` removes it all afterwards.

Add `--format markdown --out report.md` to keep the report, or `--config-out prodmask.yml` to see the starter config it writes.

When you're done, remove the container and its data:

```bash
docker compose down -v
```

## Without Docker

Load it into a MySQL or MariaDB server you use only for this, as a user that can create databases and users:

```bash
mysql -u root -p < shop.sql
```

It creates the database `shop` and the user `prodmask_ro` with the password `demo`, which can only read `shop`. Then scan it as above, with your server's host and port.

## What you'll see

- **Platforms:** WordPress, and WooCommerce with its orders in the HPOS tables.
- **Critical:** live-looking API keys and passwords in plugin settings.
- **High:** customer emails, phone numbers and addresses, payment tokens, password hashes, and more keys.
- **What staging would do to real people:** subscription renewals that would charge customers, Stripe in live mode, mail sent through SendGrid, active webhooks, and backups that would go to the live site's cloud storage.
- **Key/value tables:** `wp_options` and `wp_postmeta` read key by key, with families of keys shown as patterns.

The exact counts change as the scanner learns new formats.

## How it's made

The data comes from the generator the integration tests use, `pkg/fixture`. Values shaped like API keys are written as adjacent string literals, such as `'abcd' 'efgh'`, which the server joins into one value on insert, so no whole key sits in this repository. `shop.sql` loads on MySQL 8.4 and MariaDB 11.8, and the scan finds the same things it finds in the test databases.
