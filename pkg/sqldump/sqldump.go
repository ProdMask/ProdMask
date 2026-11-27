// Package sqldump reads the SQL text that mysqldump, mariadb-dump and the
// tools that write the same format produce, with no server. It splits
// statements as the mysql client does, follows the SQL mode and the client
// character set, decodes the literals of a row as the server would store
// them, and hands each statement to a Visitor, or lists it as unread.
//
// No value the file holds is ever put into an error or a warning. The errors
// carry a reason from a closed list and a line number. A warning names only a
// table the reader parsed as a name, or a character set from MySQL's own
// list.
package sqldump

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// Kind is the kind of a statement, from a closed list.
type Kind string

// The closed list of statement kinds. A statement whose first words match
// none of them is KindOther.
const (
	KindInsert          Kind = "INSERT"
	KindInsertIgnore    Kind = "INSERT IGNORE"
	KindReplace         Kind = "REPLACE"
	KindCreateTable     Kind = "CREATE TABLE"
	KindAlterTable      Kind = "ALTER TABLE"
	KindCreateIndex     Kind = "CREATE INDEX"
	KindCreateView      Kind = "CREATE VIEW"
	KindCreateTrigger   Kind = "CREATE TRIGGER"
	KindCreateProcedure Kind = "CREATE PROCEDURE"
	KindCreateFunction  Kind = "CREATE FUNCTION"
	KindCreateEvent     Kind = "CREATE EVENT"
	KindCreateSequence  Kind = "CREATE SEQUENCE"
	KindSetval          Kind = "SETVAL"
	KindAnalyzeTable    Kind = "ANALYZE TABLE"
	KindDrop            Kind = "DROP"
	KindTruncate        Kind = "TRUNCATE"
	KindCreateDatabase  Kind = "CREATE DATABASE"
	KindAlterDatabase   Kind = "ALTER DATABASE"
	KindUse             Kind = "USE"
	KindSet             Kind = "SET"
	KindLockTables      Kind = "LOCK TABLES"
	KindUnlockTables    Kind = "UNLOCK TABLES"
	KindTransaction     Kind = "TRANSACTION"
	KindFlush           Kind = "FLUSH"
	KindChangeSource    Kind = "CHANGE SOURCE"
	KindUser            Kind = "USER"
	KindGrant           Kind = "GRANT"
	KindUpdate          Kind = "UPDATE"
	KindDelete          Kind = "DELETE"
	KindLoadData        Kind = "LOAD DATA"
	KindCall            Kind = "CALL"
	KindSource          Kind = "SOURCE"
	KindOther           Kind = "OTHER"
)

// Kinds is the closed list of statement kinds.
var Kinds = []Kind{
	KindInsert, KindInsertIgnore, KindReplace, KindCreateTable, KindAlterTable,
	KindCreateIndex, KindCreateView, KindCreateTrigger, KindCreateProcedure,
	KindCreateFunction, KindCreateEvent, KindCreateSequence, KindSetval,
	KindAnalyzeTable, KindDrop, KindTruncate, KindCreateDatabase,
	KindAlterDatabase, KindUse, KindSet, KindLockTables, KindUnlockTables,
	KindTransaction, KindFlush, KindChangeSource, KindUser, KindGrant,
	KindUpdate, KindDelete, KindLoadData, KindCall, KindSource, KindOther,
}

// Class says what became of a statement.
type Class uint8

const (
	// ClassRead is a statement whose rows were read.
	ClassRead Class = iota
	// ClassKnown is a statement of a kind that holds no rows.
	ClassKnown
	// ClassStructure is a statement that gave or changed a table's structure.
	ClassStructure
	// ClassUnread is a statement the reader did not read.
	ClassUnread
)

// Reason is why a statement was not read. The list below is closed.
type Reason string

// The closed list of reasons.
const (
	ReasonString      Reason = "a string or identifier doesn't end"
	ReasonExpression  Reason = "an expression the reader doesn't evaluate"
	ReasonInsertForm  Reason = "this form of INSERT isn't read"
	ReasonKind        Reason = "this statement kind isn't read"
	ReasonColumns     Reason = "the row's values don't match the table's columns"
	ReasonEOF         Reason = "the file ended inside the statement"
	ReasonCharset     Reason = "a character set the reader doesn't decode"
	ReasonSQLMode     Reason = "the SQL mode is unknown"
	ReasonIdentLength Reason = "an identifier longer than 256 bytes"
	ReasonAlter       Reason = "the ALTER TABLE changes the structure in a way the reader doesn't follow"
	ReasonRecreate    Reason = "the table is created again with other columns"
	ReasonSeveral     Reason = "more than one statement before the delimiter"
	ReasonClient      Reason = "a mysql client command the reader doesn't follow"
	ReasonVersion     Reason = "a version comment some servers skip, where skipping it changes the statement"
)

// Reasons is the closed list of reasons.
var Reasons = []Reason{
	ReasonString, ReasonExpression, ReasonInsertForm, ReasonKind,
	ReasonColumns, ReasonEOF, ReasonCharset, ReasonSQLMode,
	ReasonIdentLength, ReasonAlter, ReasonRecreate, ReasonSeveral,
	ReasonClient, ReasonVersion,
}

// The fixed warnings. The one that names a character set takes it from
// MySQL's list; a name that isn't on the list is never printed.
const (
	WarnNoSQLMode      = "the dump doesn't set its SQL mode, so it was read as a server with default settings reads it"
	WarnUnknownCharset = "the dump uses an unknown character set, so the statements under it were not read; dump with --default-character-set=utf8mb4"
	warnCharsetFormat  = "the dump uses the character set %s, which the reader doesn't decode, so the statements under it were not read; dump with --default-character-set=utf8mb4"
	warnUsersFormat    = "the dump creates %d database %s; an IDENTIFIED BY clause can hold a password"
	warnKeysFormat     = "the keys of the table %s can't be counted from the dump, so it is sampled by its first rows"
	warnNoTableFormat  = "the dump holds rows for the table %s but never creates it, so its columns are named from the INSERT, or column_1 onwards, and read as text"
)

const (
	maxUnreadListed  = 100
	defaultMaxChars  = 65536
	maxHeaderComment = 200
)

// Unread is a statement the reader did not read.
type Unread struct {
	Line   int
	Kind   Kind
	Reason Reason
	// Database and Table are set only when the table already has a parsed
	// structure or fully read rows; otherwise both are empty.
	Database string
	Table    string
	// ToEnd is set when the entry stands for the rest of the file, from Line.
	ToEnd bool
}

// Warning is a fixed warning, with no text from the file.
type Warning struct {
	Text string
}

// Header holds what the leading comments say, each only when it passes the
// strict pattern. None of it is trusted for anything but display.
type Header struct {
	Producer      string
	Database      string
	ServerVersion string
	MariaDB       bool
}

// Visitor receives what the reader finds. Every method is called from the
// goroutine that called Read, and values handed over are valid only during
// the call.
type Visitor interface {
	// Header is called once, after the first statement that isn't a SET, or
	// that starts after line 200, or at the end of the file.
	Header(h Header)
	// Database is called with each database the file names, once: the
	// first time a USE switches to it, or a CREATE or ALTER DATABASE names
	// it. Only USE changes the current database.
	Database(name string)
	// Structure is called with a table's structure when it's read, and again
	// after an ALTER or a CREATE INDEX changes it.
	Structure(db string, t *model.Table)
	// Row is called for each row of an INSERT or a REPLACE. The Row and
	// everything in it is valid only during the call, and read-only.
	Row(r *Row)
	// Unread is called for each statement the reader did not read.
	Unread(u Unread)
	// Warning is called for each fixed warning.
	Warning(w Warning)
}

// BaseVisitor does nothing; embed it to implement only some methods.
type BaseVisitor struct{}

func (BaseVisitor) Header(Header)                  {}
func (BaseVisitor) Database(string)                {}
func (BaseVisitor) Structure(string, *model.Table) {}
func (BaseVisitor) Row(*Row)                       {}
func (BaseVisitor) Unread(Unread)                  {}
func (BaseVisitor) Warning(Warning)                {}

// Row is one row of an INSERT or a REPLACE, aligned to the columns of the
// table's structure. The reader reuses it: a Visitor that keeps anything must
// copy it, and must not change it.
type Row struct {
	DB, Table string
	// Kind is KindInsert, KindInsertIgnore or KindReplace.
	Kind Kind
	// Line is the statement's first line.
	Line int64
	// Ordinal is the row's position among its table's rows in the file,
	// counted from 1. It tells rows apart, as a key repeated by a REPLACE or
	// an INSERT IGNORE can't.
	Ordinal int64
	// Structure is the structure in force for the statement.
	Structure *model.Table
	// Values holds one value for each column of Structure, in its order. A
	// column the statement left out holds its literal default, or NULL.
	Values []Value
	// KeyCounted is set when the auto-increment key in Values is the one the
	// reader counted, as the server would assign it, because the file holds
	// none.
	KeyCounted bool
	// KeysUnknown is set when the table's auto-increment or primary keys
	// can't be counted from the file, from this row on. A table with one such
	// row has unknown keys, and KeyCounted is never set for it again.
	KeysUnknown bool
}

// Stats counts what the reader saw.
type Stats struct {
	// ByKind counts every statement by its kind.
	ByKind map[Kind]int
	// Read, Known, Structure and Unread count statements by class.
	Read      int
	Known     int
	Structure int
	Unread    int
	// Rows counts the rows handed to the Visitor.
	Rows int64
	// DefaultsNoLiteral counts the values of rows the server fills that the
	// reader read as NULL: a DEFAULT keyword for a column with no literal
	// default, and a column left out or given DEFAULT whose default is an
	// expression, or which is generated.
	DefaultsNoLiteral int64
	// UnreadList holds the first 100 unread statements; Unread is exact.
	UnreadList []Unread
	// Bytes is how many bytes of SQL were read.
	Bytes int64
	// Views counts the views the file creates, each once: a placeholder and
	// the view that replaces it are one. Users counts the statements that can
	// set a password: CREATE and ALTER USER, GRANT ... IDENTIFIED BY and SET
	// PASSWORD.
	Views int
	Users int
}

// Statements is how many statements were counted.
func (s Stats) Statements() int { return s.Read + s.Known + s.Structure + s.Unread }

// Options tunes a read.
type Options struct {
	// MaxChars is the most characters of a value kept; the rest is skipped
	// and the value is flagged as cut. The default is 65,536.
	MaxChars int

	test testHooks
}

// testHooks are set by the unit tests only.
type testHooks struct {
	repanic     bool
	panicAtLine int
}

// ErrRead is returned when the input can't be read to its end, such as a
// compressed file that is cut short or damaged.
var ErrRead = errors.New("the dump could not be read to its end")

// PanicError is returned when the reader stopped on an internal fault. It
// holds the line only, never the fault's value.
type PanicError struct {
	Line int
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("the dump reader stopped at line %d", e.Line)
}

// Read reads a dump from r and reports it to v. It returns what it counted
// even when it returns an error. A panic inside the reader becomes a
// *PanicError.
func Read(ctx context.Context, r io.Reader, v Visitor, opts Options) (stats Stats, err error) {
	if v == nil {
		v = BaseVisitor{}
	}
	rd := newReader(ctx, r, v, opts)
	defer func() {
		if p := recover(); p != nil {
			if opts.test.repanic {
				panic(p)
			}
			stats = rd.snapshot()
			err = &PanicError{Line: rd.lx.line}
		}
	}()
	err = rd.run()
	return rd.snapshot(), err
}
