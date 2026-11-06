package model

import (
	"strings"
	"time"
)

// LeakKind is a kind of value the staging leak check counts: one that two
// people are very unlikely to share by chance.
type LeakKind string

// The kinds the leak check counts.
const (
	LeakEmail        LeakKind = "email"
	LeakPhone        LeakKind = "phone"
	LeakIBAN         LeakKind = "iban"
	LeakNationalID   LeakKind = "national_id"
	LeakPaymentToken LeakKind = "payment_token"
	LeakPasswordHash LeakKind = "password_hash"
	LeakSecret       LeakKind = "secret"
)

func (k LeakKind) category() Category {
	switch k {
	case LeakEmail:
		return CatEmail
	case LeakPhone:
		return CatPhone
	case LeakIBAN:
		return CatBankAccount
	case LeakNationalID:
		return CatNationalID
	case LeakPaymentToken:
		return CatPaymentToken
	case LeakPasswordHash:
		return CatPasswordHash
	}
	return CatSecret
}

// Label is the kind's name in reports.
func (k LeakKind) Label() string { return k.category().Label() }

// Severity is how bad a match of this kind is. A secret is critical: its
// exact production value is on staging, whatever its format says.
func (k LeakKind) Severity() Severity {
	if k == LeakSecret {
		return SeverityCritical
	}
	return k.category().Info().Severity
}

// How a production sample was taken.
const (
	SampleSpread    = "spread"     // one row from each slice of the key range
	SampleFirstRows = "first_rows" // the table's or the key's first rows only
	SampleAllRows   = "all_rows"   // every row
	SampleThin      = "thin"       // gaps in the key left under half the slices with a row of their own
	SampleCut       = "cut"        // a statement failed part-way
)

// The states of a column on staging.
const (
	LeakRead         = "read"           // read whole
	LeakStopped      = "stopped"        // a time limit or an error stopped it part-way
	LeakNotRead      = "not_read"       // the time limit came before it started
	LeakNotOnStaging = "not_on_staging" // the table or column doesn't exist there
	LeakUnreadable   = "unreadable"     // it can't be read there: a view, or now binary
)

// LeakResult is the outcome of a staging leak check. It holds names and
// counts only, never a value, a primary key or a row number.
type LeakResult struct {
	Tool        string         `json:"tool"`
	Version     string         `json:"version"`
	GeneratedAt time.Time      `json:"generated_at"`
	Server      ServerInfo     `json:"server"`
	Database    string         `json:"database"`
	Hashes      LeakHashesInfo `json:"hashes"`
	Allowed     LeakAllowed    `json:"allowed"`
	Summary     LeakSummary    `json:"summary"`
	Columns     []LeakColumn   `json:"columns"`
	LeftOut     []LeakLeftOut  `json:"left_out"`
	Warnings    []string       `json:"warnings"`
	Limits      []string       `json:"limits"`
}

// NothingRead reports whether a check read nothing at all, so it knows nothing.
func (r *LeakResult) NothingRead() bool { return r.Summary.NothingRead }

// LeakHashesInfo says where a check's sampled values came from.
type LeakHashesInfo struct {
	Database    string    `json:"database"`
	CreatedAt   time.Time `json:"created_at"`
	ToolVersion string    `json:"tool_version"`
	SampleRows  int       `json:"sample_rows"`
}

// LeakAllowed says what --allow-email kept out of a check: domains by name,
// and exact addresses only as a count, since an address is a real person's.
type LeakAllowed struct {
	Domains       []string `json:"domains"`
	Addresses     int      `json:"addresses"`
	ValuesSkipped int64    `json:"values_skipped"`
}

// LeakSummary holds a check's headline numbers. Sampled and Found cover the
// columns read whole; SampledInPart and FoundInPart cover stopped columns.
type LeakSummary struct {
	Columns        int      `json:"columns"`
	ColumnsRead    int      `json:"columns_read"`
	ColumnsWithHit int      `json:"columns_with_hits"`
	Sampled        int64    `json:"sampled"`
	Found          int64    `json:"found"`
	SampledInPart  int64    `json:"sampled_in_columns_read_in_part"`
	FoundInPart    int64    `json:"found_in_columns_read_in_part"`
	RowsRead       int64    `json:"rows_read"`
	NothingRead    bool     `json:"nothing_read"`
	Highest        Severity `json:"highest_severity"`
	DurationMillis int64    `json:"duration_ms"`
}

// LeakColumn is what a check found for one kind of value in one column or
// key.
type LeakColumn struct {
	Table    string   `json:"table"`
	Column   string   `json:"column"`
	MetaKey  string   `json:"meta_key,omitempty"`
	Kind     LeakKind `json:"kind"`
	Severity Severity `json:"severity"`
	State    string   `json:"state"`
	// StoppedBy says what stopped the column: "--max-time" or an error's
	// description, which never quotes the server's message.
	StoppedBy string `json:"stopped_by,omitempty"`
	Excepted  bool   `json:"excepted_from_fail_on,omitempty"`
	// Line is the report's line about this column.
	Line string `json:"line"`

	// From production.
	Sample          string `json:"sample"`
	Exact           bool   `json:"every_value_sampled,omitempty"`
	Sampled         int    `json:"sampled"`
	EstimatedValues int64  `json:"production_values_estimate"`

	// From staging.
	Found         int   `json:"found"`
	Rows          int64 `json:"rows_holding_them"`
	Values        int64 `json:"values_read"`
	ValuesSkipped int64 `json:"values_skipped_by_allow_email,omitempty"`
	RowsRead      int64 `json:"rows_read"`
	RowsEstimate  int64 `json:"rows_estimate"`

	// What the numbers say, each 0 where it doesn't apply.
	ShownAt95      float64 `json:"real_values_shown_at_95_percent,omitempty"`
	CatchIfAllReal float64 `json:"chance_of_catching_if_all_read_were_real,omitempty"`
	ChanceMatches  float64 `json:"matches_chance_could_explain,omitempty"`
	EstimateInAll  int64   `json:"estimated_real_values_in_all,omitempty"`
}

// LeakLocation renders where a column is, as reports print it and
// --fail-except takes it: wp_users.user_email, or
// wp_usermeta.meta_value[billing_phone].
func LeakLocation(table, column, metaKey string) string {
	switch {
	case column == "":
		return table
	case metaKey != "":
		return table + "." + column + "[" + metaKey + "]"
	}
	return table + "." + column
}

// Location renders where the column is.
func (c LeakColumn) Location() string { return LeakLocation(c.Table, c.Column, c.MetaKey) }

// LeakLeftOut is a flagged column or key that isn't compared, and why.
// NotRead marks one a rerun might read, such as a table the sample couldn't
// read; it fails a gate, unless Excepted.
type LeakLeftOut struct {
	Location string `json:"location"`
	Why      string `json:"why"`
	NotRead  bool   `json:"not_read,omitempty"`
	Excepted bool   `json:"excepted_from_fail_on,omitempty"`
}

// LeakExcept reports whether a location given to --fail-except covers a
// location: the whole of it, its column or its table, in any letter case.
func LeakExcept(except, location string) bool {
	except, location = strings.ToLower(except), strings.ToLower(location)
	return except == location || strings.HasPrefix(location, except+".") || strings.HasPrefix(location, except+"[")
}
