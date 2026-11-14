# Contributing

The most useful things you can send are reports of false findings, missed findings and bugs. Use the issue forms; for a security issue, see [SECURITY.md](SECURITY.md).

## Never send real data

Don't paste values from a real database into an issue, a pull request or a test: no emails, names, keys or rows. Describe the shape instead, such as "a 40-character hex string in `wp_options.option_value` under the key `foo_api_secret`", or make up a value with the same shape. From a `prodmask scan` report, paste the lines in question: it holds no customer values, but a full report names your server, its user and your tables.

## Building and testing

```bash
go test ./...
```

The integration tests build fake WordPress/WooCommerce, Magento 2 and Laravel databases, plus a generic schema no preset knows, and scan them. They run when `PRODMASK_TEST_DSN` points at a server where the user can create databases:

```bash
PRODMASK_TEST_DSN='root:…@tcp(127.0.0.1:3306)/' go test ./...
```

With `PRODMASK_TEST_REQUIRE_ALL=1` as well (any value but `0` counts), a test that needs a server fails instead of skipping when `PRODMASK_TEST_DSN` isn't set, so a run meant to test against a server can't pass by skipping.

CI runs them on MySQL 8.4 and MariaDB 11.8. Their findings are compared with the golden files in `pkg/scan/testdata`. After a deliberate change, rewrite them with `go test ./pkg/scan -update`, with `PRODMASK_TEST_DSN` set, and review the diff line by line.

## Test data

- All of it is invented: phone numbers in the 555-01xx range, IP addresses from the documentation ranges, and made-up domain names.
- Build anything shaped like an API key from pieces at run time, so no provider prefix sits next to its body. GitHub's push protection blocks a push that holds one, even in a test.

## Pull requests

Keep a pull request to one change, with a test that fails without it. Before you open it, run:

```bash
gofmt -l .
go vet ./...
go test ./...
```

If you change `action.yml` or `.github/action/`, also run `bash .github/action/test.sh`. It prints nothing when every check passes.
