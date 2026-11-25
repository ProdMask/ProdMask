package login

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"time"

	"github.com/ProdMask/ProdMask/pkg/report"
)

// Marker is what a database's _prodmask table, prodmask Pro's copy marker,
// says. It's what the copy wrote, not a check of the rows.
type Marker struct {
	Found bool // the table is there
	// Holds marks a marker as Pro checks one: one row, a run id of Pro's
	// shape, state complete, masking stable or per-run, and Pro's comment
	// on the table.
	Holds    bool
	State    string // complete or incomplete, when read
	Masking  string // stable, per-run or none, when read
	Tool     string // such as "prodmask Pro 1.0.0"; shown cleaned
	Finished string // when the copy finished, as stored, UTC
}

var markerRunID = regexp.MustCompile(`^[a-z2-7]{12}$`)

const markerComment = "prodmask: this database is a prodmask copy"

// ReadMarker reads the database's _prodmask table through the session. A
// missing table, or one of another shape, gives a Marker that doesn't hold.
func ReadMarker(ctx context.Context, db *sql.DB, database string) Marker {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var comment string
	err := db.QueryRowContext(ctx, "SELECT TABLE_COMMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = '_prodmask'",
		database).Scan(&comment)
	if err != nil {
		return Marker{}
	}
	m := Marker{Found: true}
	rows, err := db.QueryContext(ctx, "SELECT run_id, state, form, masking, tool, finished_at FROM _prodmask LIMIT 2")
	if err != nil {
		return m
	}
	defer rows.Close()
	n := 0
	var run string
	for rows.Next() {
		n++
		var form string
		var tool, finished sql.NullString
		if rows.Scan(&run, &m.State, &form, &m.Masking, &tool, &finished) != nil {
			return Marker{Found: true}
		}
		m.Tool, m.Finished = tool.String, finished.String
	}
	if rows.Err() != nil || n != 1 {
		return Marker{Found: true}
	}
	m.Holds = markerRunID.MatchString(run) && m.State == "complete" && (m.Masking == "stable" || m.Masking == "per-run") &&
		strings.HasPrefix(comment, markerComment)
	return m
}

// Words say what the marker means, in the words prodmask mcp shows. The tool's name and the date come from the table, so they're
// cleaned and cut short.
func (m Marker) Words() string {
	switch {
	case !m.Found:
		return "This database has no prodmask copy marker: it may hold real customer data."
	case m.Holds:
		key := "a stable key"
		if m.Masking == "per-run" {
			key = "a key for this run only"
		}
		made := ""
		tool, at := shortClean(m.Tool, 60), finishedAt(m.Finished)
		switch {
		case tool != "" && at != "":
			made = ", made by " + tool + " on " + at + " UTC"
		case tool != "":
			made = ", made by " + tool
		case at != "":
			made = ", finished on " + at + " UTC"
		}
		return "The _prodmask marker says this database is a prodmask copy: complete, masked with " + key + made +
			". It's what the copy wrote; Pro's verify checks the rows."
	case m.State == "incomplete":
		return "The _prodmask marker says this database is a prodmask copy that isn't complete: it may hold real customer data."
	case m.Masking == "none":
		return "The _prodmask marker says this database is a prodmask copy made with no masking: it may hold real customer data."
	}
	return "This database has a _prodmask table, but the marker couldn't be read: it may hold real customer data."
}

// shortClean cleans a value from the database for a terminal or an agent,
// and cuts it to n characters.
func shortClean(s string, n int) string {
	s = strings.TrimSpace(report.Clean(s))
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

// finishedAt shows the marker's finished_at to the second: the driver gives
// it as stored, with Pro's six decimal places.
func finishedAt(s string) string {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02 15:04:05")
		}
	}
	return shortClean(s, 30)
}
