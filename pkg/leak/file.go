package leak

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
)

const (
	fileFormat  = "prodmask-leak-hashes"
	fileVersion = 1
	fileNotice  = "Keyed hashes of values sampled from a production database. Treat this file as personal data: " +
		"keep it as you keep production data, and delete it after the check."
)

// The errors reading a hash file can give. None quotes what it read.
var (
	ErrFileUnreadable = errors.New("can't read the file given to --hashes")
	ErrFileFormat     = errors.New("the file given to --hashes isn't a prodmask leak-check hash file, or it's damaged")
	ErrFileVersion    = errors.New("the file given to --hashes was made by another version of prodmask: run prodmask leak-check hash again")
	ErrWrongKey       = errors.New("this key isn't the one the hash file was made with")
)

// File is a hash file: what hash leaves for compare. It holds names, counts
// and keyed hashes, never a value, and the key's only trace is KeyCheck. It's
// unsigned on purpose: it isn't evidence.
type File struct {
	Format           string              `json:"format"`
	Version          int                 `json:"version"`
	Notice           string              `json:"notice"`
	ToolVersion      string              `json:"tool_version"`
	CreatedAt        time.Time           `json:"created_at"`
	Database         string              `json:"database"`
	Salt             []byte              `json:"salt"`
	KeyCheck         []byte              `json:"key_check"`
	SampleRows       int                 `json:"sample_rows"`
	AllowDomains     []string            `json:"allow_domains"`
	AllowedAddresses int                 `json:"allowed_addresses"`
	ValuesSkipped    int64               `json:"values_skipped"`
	Columns          []FileColumn        `json:"columns"`
	LeftOut          []model.LeakLeftOut `json:"left_out"`
	// Warnings are the sample's own, for compare's report, as the two steps
	// can run apart. They hold names and error numbers only.
	Warnings []string `json:"warnings,omitempty"`
}

// FileColumn is the sample of one kind of value in one column or key.
type FileColumn struct {
	Table     string `json:"table"`
	Column    string `json:"column"`
	KeyColumn string `json:"key_column,omitempty"`
	// MetaKey is a key of a key/value table as scan shows it: a name, or a
	// pattern whose * stands for the part that varies.
	MetaKey string         `json:"meta_key,omitempty"`
	Kind    model.LeakKind `json:"kind"`
	// Whole marks the kinds read with a column's own rule: the loose phone
	// finder, or a whole value.
	Whole           bool   `json:"whole,omitempty"`
	MaxChars        int    `json:"max_chars"`
	Sample          string `json:"sample"`
	Exact           bool   `json:"exact,omitempty"`
	RowsEstimate    int64  `json:"rows_estimate"`
	RowsRead        int64  `json:"rows_read"`
	EstimatedValues int64  `json:"estimated_values"`
	Values          int    `json:"values"`
	// Hashes holds the 16-byte hashes one after another, sorted, so their
	// order says nothing about rows.
	Hashes []byte `json:"hashes"`
}

// Write writes the file as JSON.
func (f *File) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(f)
}

// ReadFile reads a hash file. Its errors don't quote the path, which may be a
// key typed in the wrong place.
func ReadFile(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrFileUnreadable
	}
	return parseFile(b)
}

func parseFile(b []byte) (*File, error) {
	var f File
	if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &f); err != nil {
		return nil, ErrFileFormat
	}
	if f.Format != fileFormat {
		return nil, ErrFileFormat
	}
	if f.Version != fileVersion {
		return nil, ErrFileVersion
	}
	if len(f.Salt) != saltLen || len(f.KeyCheck) != keyCheckLen {
		return nil, ErrFileFormat
	}
	for _, c := range f.Columns {
		if c.Table == "" || c.Column == "" || c.Kind == "" || len(c.Hashes)%hashLen != 0 || len(c.Hashes)/hashLen != c.Values ||
			(c.MetaKey != "" && c.KeyColumn == "") {
			return nil, ErrFileFormat
		}
	}
	return &f, nil
}

// CheckKey refuses a key the file wasn't made with.
func (f *File) CheckKey(k Key) error {
	if !bytes.Equal(k.keyCheck(f.Salt), f.KeyCheck) {
		return ErrWrongKey
	}
	return nil
}

// String keeps a file's hashes out of anything that prints one by accident.
func (f *File) String() string {
	return fmt.Sprintf("hash file of %s: %d columns", f.Database, len(f.Columns))
}
