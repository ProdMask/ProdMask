package scan

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

const canaryText = "zq7canary"

// A dump with a value of the file in places a report could copy it from: a
// column, a key and a value of a key/value table, an unread statement, and a
// string that never ends.
const canarySQL = "CREATE TABLE `t` (`id` int NOT NULL, `email` varchar(60), `note` text, PRIMARY KEY (`id`));\n" +
	"INSERT INTO `t` VALUES (1,'zq7canary_a@fixture-store.gr','zq7canary_note'),(2,'zq7canary_b@fixture-store.gr','x');\n" +
	"INSERT INTO `t` VALUES (3,CONCAT('zq7canary_unread','x'),'y');\n" +
	"CREATE TABLE `wp_options` (`option_id` bigint NOT NULL AUTO_INCREMENT, `option_name` varchar(191) NOT NULL, `option_value` longtext, PRIMARY KEY (`option_id`));\n" +
	"INSERT INTO `wp_options` VALUES (1,'zq7canary_key','zq7canary_value'),(2,'admin_email','zq7canary_c@fixture-store.gr');\n" +
	// An unread statement of a table the dump never created: its name is a
	// value the reports must not hold.
	"INSERT INTO zq7canary_sel SELECT 1;\n" +
	"INSERT INTO `t` VALUES (4,'zq7canary_lost@fixture-store.gr);\n" +
	"INSERT INTO zq7canary_late VALUES ('x');\n"

// No report, in any form, holds a value from the file; the coloured and
// verbose text included, which the command line writes only to a terminal.
func TestDumpReportsHoldNoValues(t *testing.T) {
	for _, samples := range []bool{true, false} {
		opts := dumpOpts()
		opts.Samples = samples
		res, err := RunDump(context.Background(), openText(dumpHead+canarySQL), opts)
		if err != nil {
			t.Fatal(err)
		}
		if res.Dump.Unread == 0 || len(res.Findings) == 0 {
			t.Fatalf("samples %v: %d unread, %d findings", samples, res.Dump.Unread, len(res.Findings))
		}
		check := func(what string, out string) {
			t.Helper()
			if strings.Contains(out, canaryText) || strings.Contains(strings.ReplaceAll(out, "\n", ""), canaryText) {
				t.Errorf("samples %v: %s holds a canary", samples, what)
			}
			if len(out) == 0 {
				t.Errorf("samples %v: %s is empty", samples, what)
			}
		}
		for _, o := range []report.TextOptions{{}, {Color: true}, {Verbose: true}, {Color: true, Verbose: true}} {
			var b bytes.Buffer
			if err := report.Text(&b, res, o); err != nil {
				t.Fatal(err)
			}
			check("text", b.String())
		}
		var b bytes.Buffer
		report.Markdown(&b, res)
		check("Markdown", b.String())
		b.Reset()
		report.JSON(&b, res)
		check("JSON", b.String())
		for _, w := range res.Warnings {
			check("a warning", w)
		}
	}
}

// A fault inside the reader or what it calls gives a fixed error, which holds
// nothing of the fault's value.
func TestDumpPanicHoldsNoValue(t *testing.T) {
	opts := dumpOpts()
	opts.limits.tap = func(string, map[int]*sample.Sample, *kvRead) { panic("the value zq7canary_panic") }
	res, err := RunDump(context.Background(), openText(dumpHead+canarySQL), opts)
	if res != nil || err == nil || strings.Contains(err.Error(), canaryText) ||
		!strings.Contains(err.Error(), "the dump reader stopped at line") {
		t.Errorf("result %v, error %v", res != nil, err)
	}
}

// A file with nothing the reader recognises gives an error and no result.
func TestDumpNotSQL(t *testing.T) {
	res, err := RunDump(context.Background(), openText("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR zq7canary"), dumpOpts())
	if res != nil || err != ErrNotDump || strings.Contains(err.Error(), canaryText) {
		t.Errorf("result %v, error %v", res != nil, err)
	}
	if res, err = RunDump(context.Background(), openText(""), dumpOpts()); res != nil || err != ErrNotDump {
		t.Errorf("an empty file: %v, %v", res != nil, err)
	}
}
