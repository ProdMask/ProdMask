// Package model holds the types shared by the scanner, the detectors and the
// report writers.
package model

import (
	"fmt"
	"strings"
	"time"
)

// Severity ranks how much harm a finding could do in a non-production copy.
type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"none", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// MarshalText encodes the severity by name in JSON output.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity accepts none, low, medium, high or critical.
func ParseSeverity(s string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(strings.TrimSpace(s), n) {
			return Severity(i), nil
		}
	}
	return SeverityNone, fmt.Errorf("unknown severity %q (want none, low, medium, high or critical)", s)
}

// Confidence says how sure the scanner is that a finding is real.
type Confidence int

const (
	ConfidenceLow Confidence = iota + 1
	ConfidenceMedium
	ConfidenceHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	}
	return fmt.Sprintf("confidence(%d)", int(c))
}

// MarshalText encodes the confidence by name in JSON output.
func (c Confidence) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// Category is the kind of sensitive data a finding is about.
type Category string

const (
	CatEmail        Category = "email"
	CatPhone        Category = "phone"
	CatPersonName   Category = "person_name"
	CatUsername     Category = "username"
	CatAddress      Category = "address"
	CatPostcode     Category = "postcode"
	CatCity         Category = "city"
	CatRegion       Category = "region"
	CatCountry      Category = "country"
	CatDateOfBirth  Category = "date_of_birth"
	CatGender       Category = "gender"
	CatCompany      Category = "company"
	CatNationalID   Category = "national_id"
	CatBankAccount  Category = "bank_account"
	CatCardNumber   Category = "card_number"
	CatCardMeta     Category = "card_meta"
	CatPaymentToken Category = "payment_token"
	CatPasswordHash Category = "password_hash"
	CatSecret       Category = "secret"
	CatIPAddress    Category = "ip_address"
	CatUserAgent    Category = "user_agent"
	CatGeo          Category = "geo_location"
	CatWebsite      Category = "website"
	CatSessionData  Category = "session_data"
	CatFreeText     Category = "free_text"
)

// CategoryInfo describes a category: a label for people, the default
// severity and the masking strategy a starter config suggests.
type CategoryInfo struct {
	Label    string
	Severity Severity
	Mask     string
}

var categoryInfo = map[Category]CategoryInfo{
	CatEmail:        {"email address", SeverityHigh, "fake_email"},
	CatPhone:        {"phone number", SeverityHigh, "fake_phone"},
	CatPersonName:   {"person name", SeverityMedium, "fake_name"},
	CatUsername:     {"username", SeverityMedium, "fake_username"},
	CatAddress:      {"street address", SeverityHigh, "fake_street"},
	CatPostcode:     {"postcode", SeverityMedium, "fake_postcode"},
	CatCity:         {"city", SeverityMedium, "fake_city"},
	CatRegion:       {"region or state", SeverityLow, "keep"},
	CatCountry:      {"country", SeverityLow, "keep"},
	CatDateOfBirth:  {"date of birth", SeverityHigh, "fake_date"},
	CatGender:       {"gender", SeverityLow, "keep"},
	CatCompany:      {"company name", SeverityLow, "fake_company"},
	CatNationalID:   {"national or tax ID", SeverityHigh, "hash"},
	CatBankAccount:  {"bank account or IBAN", SeverityHigh, "fake_iban"},
	CatCardNumber:   {"payment card number", SeverityCritical, "test_card"},
	CatCardMeta:     {"card details", SeverityLow, "keep"},
	CatPaymentToken: {"payment token or ID", SeverityHigh, "null"},
	CatPasswordHash: {"password hash", SeverityHigh, "staging_password"},
	CatSecret:       {"secret, key or token", SeverityHigh, "null"},
	CatIPAddress:    {"IP address", SeverityMedium, "fake_ip"},
	CatUserAgent:    {"user agent", SeverityMedium, "fake_user_agent"},
	CatGeo:          {"geolocation", SeverityMedium, "null"},
	CatWebsite:      {"personal website", SeverityLow, "null"},
	CatSessionData:  {"session data", SeverityMedium, "null"},
	CatFreeText:     {"free text with personal data", SeverityMedium, "redact"},
}

// Info returns the description of a category.
func (c Category) Info() CategoryInfo {
	if info, ok := categoryInfo[c]; ok {
		return info
	}
	return CategoryInfo{Label: string(c), Severity: SeverityMedium, Mask: "null"}
}

// Label is the human-readable name of the category.
func (c Category) Label() string { return c.Info().Label }

// Finding is one column, meta key or JSON path that holds sensitive data.
type Finding struct {
	Table      string     `json:"table"`
	Column     string     `json:"column"`
	MetaKey    string     `json:"meta_key,omitempty"`
	Path       string     `json:"path,omitempty"`
	Category   Category   `json:"category"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Sampled    int        `json:"sampled"`
	Matched    int        `json:"matched"`
	Reasons    []string   `json:"reasons"`
	Mask       string     `json:"suggested_mask"`
	Source     string     `json:"source"`
	Note       string     `json:"note,omitempty"`
}

// Location renders where a finding is, e.g. wp_usermeta.meta_value[billing_phone].
func (f Finding) Location() string {
	s := f.Table + "." + f.Column
	if f.MetaKey != "" {
		s += "[" + f.MetaKey + "]"
	}
	if f.Path != "" {
		s += " → " + f.Path
	}
	return s
}

// SideEffect is something a plain copy would let staging do to real people:
// send them email, charge their cards, call their webhooks.
type SideEffect struct {
	Platform string   `json:"platform"`
	Kind     string   `json:"kind"`
	Table    string   `json:"table"`
	Item     string   `json:"item,omitempty"`
	Severity Severity `json:"severity"`
	Summary  string   `json:"summary"`
	Count    int64    `json:"count,omitempty"`
	Fix      string   `json:"fix"`
}

// Relationship links a child column to a parent key. Declared relationships
// come from foreign keys; the others are inferred and checked against data.
type Relationship struct {
	ChildTable    string   `json:"child_table"`
	ChildColumns  []string `json:"child_columns"`
	ParentTable   string   `json:"parent_table"`
	ParentColumns []string `json:"parent_columns"`
	Source        string   `json:"source"`
	Status        string   `json:"status"`
	Checked       int      `json:"checked,omitempty"`
	Found         int      `json:"found,omitempty"`
	TypeColumn    string   `json:"type_column,omitempty"`
	TypeValue     string   `json:"type_value,omitempty"`
	Note          string   `json:"note,omitempty"`
}

// Relationship statuses.
const (
	RelDeclared   = "declared"
	RelConfirmed  = "confirmed"
	RelLikely     = "likely"
	RelWeak       = "weak"
	RelUnverified = "unverified"
)

// Key identifies a relationship regardless of where it came from.
func (r Relationship) Key() string {
	return r.ChildTable + "(" + strings.Join(r.ChildColumns, ",") + ")->" +
		r.ParentTable + "(" + strings.Join(r.ParentColumns, ",") + ")|" + r.TypeValue
}

// Schema is what the scanner knows about one database.
type Schema struct {
	Database string
	Tables   []*Table
	byName   map[string]*Table
}

// Table looks a table up by name.
func (s *Schema) Table(name string) *Table {
	if s.byName == nil {
		s.byName = make(map[string]*Table, len(s.Tables))
		for _, t := range s.Tables {
			s.byName[t.Name] = t
		}
	}
	return s.byName[name]
}

// Table is one table or view.
type Table struct {
	Name         string
	Type         string // BASE TABLE, VIEW, SYSTEM VERSIONED, SEQUENCE
	Engine       string
	RowsEstimate int64
	DataBytes    int64
	Comment      string
	Columns      []*Column
	PrimaryKey   []string
	Indexes      []Index
	ForeignKeys  []ForeignKey
	byName       map[string]*Column
}

// IsView reports whether the table is a view.
func (t *Table) IsView() bool { return t.Type == "VIEW" }

// IsData reports whether the table holds rows the scanner can sample.
func (t *Table) IsData() bool {
	return t.Type == "BASE TABLE" || t.Type == "SYSTEM VERSIONED"
}

// Column looks a column up by name, ignoring case.
func (t *Table) Column(name string) *Column {
	if t.byName == nil {
		t.byName = make(map[string]*Column, len(t.Columns))
		for _, c := range t.Columns {
			t.byName[strings.ToLower(c.Name)] = c
		}
	}
	return t.byName[strings.ToLower(name)]
}

// SinglePK returns the primary key column when the key has exactly one column.
func (t *Table) SinglePK() *Column {
	if len(t.PrimaryKey) != 1 {
		return nil
	}
	return t.Column(t.PrimaryKey[0])
}

// HasIndexOn reports whether some index starts with the given column.
func (t *Table) HasIndexOn(column string) bool {
	for _, ix := range t.Indexes {
		if len(ix.Columns) > 0 && strings.EqualFold(ix.Columns[0], column) {
			return true
		}
	}
	return false
}

// Column is one column of a table.
type Column struct {
	Name       string
	Position   int
	DataType   string // lower case, e.g. varchar, bigint, longtext
	ColumnType string // full type, e.g. "bigint(20) unsigned"
	Nullable   bool
	MaxLength  int64
	Key        string // PRI, UNI, MUL
	Extra      string // auto_increment, VIRTUAL GENERATED, ...
	Comment    string
}

// AutoIncrement reports whether the column is filled by the server.
func (c *Column) AutoIncrement() bool {
	return strings.Contains(strings.ToLower(c.Extra), "auto_increment")
}

// Index is one index of a table.
type Index struct {
	Name    string
	Unique  bool
	Columns []string
}

// ForeignKey is one declared foreign key.
type ForeignKey struct {
	Name       string
	Columns    []string
	RefSchema  string
	RefTable   string
	RefColumns []string
}

// ServerInfo describes the database server that was scanned.
type ServerInfo struct {
	Flavor  string `json:"flavor"`
	Version string `json:"version"`
	Address string `json:"address"`
	User    string `json:"user"`
}

// Platform is an application the scanner recognised, such as WordPress.
type Platform struct {
	Name    string   `json:"name"`
	Label   string   `json:"label"`
	Version string   `json:"version,omitempty"`
	Prefix  string   `json:"table_prefix,omitempty"`
	Details []string `json:"details,omitempty"`
}

// TableSummary is what the report says about one table.
type TableSummary struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	RowsEstimate int64    `json:"rows_estimate"`
	RowsSampled  int      `json:"rows_sampled"`
	Findings     int      `json:"findings"`
	Highest      Severity `json:"highest_severity"`
	KeyColumn    string   `json:"key_column,omitempty"`
	ValueColumn  string   `json:"value_column,omitempty"`
	Action       string   `json:"suggested_action,omitempty"`
	ActionReason string   `json:"action_reason,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// ScanOptions records the settings a scan ran with.
type ScanOptions struct {
	SampleRows     int     `json:"sample_rows"`
	MetaSampleRows int     `json:"meta_sample_rows"`
	Samples        bool    `json:"samples"`
	Preset         string  `json:"preset"`
	TimeoutSeconds float64 `json:"statement_timeout_seconds"`
}

// Summary holds the headline numbers of a scan.
type Summary struct {
	Tables             int            `json:"tables"`
	TablesSampled      int            `json:"tables_sampled"`
	Views              int            `json:"views"`
	RowsSampled        int64          `json:"rows_sampled"`
	TablesWithFindings int            `json:"tables_with_findings"`
	Findings           int            `json:"findings"`
	BySeverity         map[string]int `json:"by_severity"`
	ByCategory         map[string]int `json:"by_category"`
	Highest            Severity       `json:"highest_severity"`
	SideEffects        int            `json:"side_effects"`
	Relationships      int            `json:"relationships"`
	InferredConfirmed  int            `json:"inferred_relationships_confirmed"`
	DurationMillis     int64          `json:"duration_ms"`
}

// Result is the full outcome of a scan.
type Result struct {
	Tool          string         `json:"tool"`
	Version       string         `json:"version"`
	GeneratedAt   time.Time      `json:"generated_at"`
	Server        ServerInfo     `json:"server"`
	Database      string         `json:"database"`
	Platforms     []Platform     `json:"platforms"`
	Options       ScanOptions    `json:"options"`
	Summary       Summary        `json:"summary"`
	Tables        []TableSummary `json:"tables"`
	Findings      []Finding      `json:"findings"`
	SideEffects   []SideEffect   `json:"side_effects"`
	Relationships []Relationship `json:"relationships"`
	Warnings      []string       `json:"warnings"`
}
