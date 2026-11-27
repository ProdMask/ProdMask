package report

import (
	"fmt"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// LeakDumpJudged is the closing line of a leak check that read a dump, where
// columns is how many columns and keys it read in whole and n the size of the
// sample of each.
func LeakDumpJudged(columns, n int) string {
	what := thousands(int64(columns)) + " columns and keys"
	switch columns {
	case 0:
		return fmt.Sprintf("No column or key was read in whole in the dump; production's hashes are a sample of up to %s values of each, so a zero isn't proof.", thousands(int64(n)))
	case 1:
		what = "1 column or key"
	}
	return fmt.Sprintf("Read every value of the %s in the dump; production's hashes are a sample of up to %s values of each, so a zero isn't proof.",
		what, thousands(int64(n)))
}

// LeakLineDump is LeakLine for a check of a dump file.
func LeakLineDump(c model.LeakColumn) string {
	if c.Found == 0 && c.State != model.LeakRead {
		return leakDumpWords(c)
	}
	return LeakLine(c)
}

// leakDumpWords says why a column of a dump wasn't read in whole.
func leakDumpWords(c model.LeakColumn) string {
	switch c.State {
	case model.LeakNotOnStaging:
		return "not in the dump"
	case model.LeakUnreadable:
		return "can't be read in the dump: a view, a binary column, or a table with no columns named"
	case model.LeakStopped:
		rows := thousands(c.RowsRead) + " rows"
		if c.StoppedBy == "--max-time" {
			return "stopped by --max-time after " + rows
		}
		return "stopped after " + rows + " (" + c.StoppedBy + ")"
	}
	return notReadWords(c)
}

// leakDumpServerLine names the dump file in place of a server: dump file
// shop.sql (MariaDB 11.8.2).
func leakDumpServerLine(res *model.LeakResult) string {
	line := "dump file " + Clean(res.Dump.File)
	if v := res.Server.Version; v != "" {
		flavor := "MySQL"
		if res.Server.Flavor == "mariadb" {
			flavor = "MariaDB"
		}
		if i := strings.Index(v, "-MariaDB"); i > 0 {
			v = v[:i]
		}
		line += " (" + flavor + " " + Clean(v) + ")"
	}
	return line
}
