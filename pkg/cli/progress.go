package cli

import (
	"fmt"

	"github.com/ProdMask/ProdMask/pkg/report"
)

// progressLine is a long command's progress, which rewrites one terminal
// line, or clears it when table is empty. The table's name comes from the
// database, so it's cleaned.
func progressLine(verb string, done, total int, table string) string {
	if table == "" {
		return "\r\x1b[K"
	}
	return fmt.Sprintf("\r\x1b[K%s %d/%d %s", verb, done+1, total, report.Clean(table))
}

// readingLine is compare's progress line, with the rows read so far.
func readingLine(done, total int, table string, rows int64) string {
	line := progressLine("Reading", done, total, table)
	if table != "" {
		line += ": " + report.Count(rows) + " rows"
	}
	return line
}
