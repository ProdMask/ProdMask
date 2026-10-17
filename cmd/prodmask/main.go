// Command prodmask finds what a plain copy of a MySQL or MariaDB database
// would carry into staging: personal data, secrets, and settings that would
// let staging email or charge real customers.
package main

import (
	"context"
	"os"

	"github.com/ProdMask/ProdMask/pkg/cli"
)

// version is set at build time with -ldflags "-X main.version=...". Builds
// without it, from go install or go build, report the module version Go
// recorded, or "dev".
var version string

func main() {
	app := cli.New(cli.BuildVersion(version))
	os.Exit(app.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
