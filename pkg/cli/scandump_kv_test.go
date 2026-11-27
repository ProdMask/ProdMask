package cli

import (
	"fmt"
	"strings"
	"testing"
)

// From the command line, a key/value table past the envelope read whole is
// judged by a window of the default 3,000 rows as well as by its 300-row
// sample and its first rows of each key, as a scan of a database judges it.
// The addresses sit in the window's first third only, rows 101 to 1,000: the
// 300-row sample takes the first 100 rows and the key's probe its first 20,
// and every other value is empty.
func TestScanDumpKeyValueWindow(t *testing.T) {
	var b strings.Builder
	b.WriteString(dumpHead + "CREATE TABLE `usermeta` (`umeta_id` bigint unsigned NOT NULL AUTO_INCREMENT, " +
		"`user_id` bigint NOT NULL DEFAULT 0, `meta_key` varchar(255) DEFAULT NULL, `meta_value` longtext, " +
		"PRIMARY KEY (`umeta_id`), KEY `meta_key` (`meta_key`(191)));\n")
	const rows, batch = 25000, 500
	for i := 1; i <= rows; i += batch {
		b.WriteString("INSERT INTO `usermeta` VALUES ")
		for j := i; j < i+batch; j++ {
			if j > i {
				b.WriteByte(',')
			}
			v := ""
			if j > 100 && j <= 1000 {
				v = fmt.Sprintf("zq7canary.u%d@fixture-store.gr", j)
			}
			fmt.Fprintf(&b, "(%d,%d,'note','%s')", j, j, v)
		}
		b.WriteString(";\n")
	}
	code, stdout, stderr := scanDump(t, "--dump", writeDump(t, b.String()), "--fail-on", "high")
	if code != ExitFindings || !strings.Contains(stdout, "email address") {
		t.Errorf("status %d\n%s%s", code, stdout, stderr)
	}
	if hasCanary(stdout) || hasCanary(stderr) {
		t.Error("a canary is in the output")
	}
}
