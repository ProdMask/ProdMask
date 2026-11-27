package sqldump

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// typeClass says how a column type is measured.
type typeClass uint8

const (
	classOther  typeClass = iota // numbers, dates, JSON and the rest: no length
	classChar                    // CHAR, VARCHAR: characters
	classBinary                  // BINARY, VARBINARY: bytes
	classText                    // the TEXT types: a fixed number of bytes
	classBlob                    // the BLOB types: a fixed number of bytes
	classEnum                    // ENUM, SET: the longest member
)

// fixedLength is the size in bytes of the TEXT and BLOB types.
var fixedLength = map[string]int64{
	"tinytext": 255, "text": 65535, "mediumtext": 16777215, "longtext": 4294967295,
	"tinyblob": 255, "blob": 65535, "mediumblob": 16777215, "longblob": 4294967295,
}

// typeAlias maps the spellings the server accepts to the name
// information_schema gives.
var typeAlias = map[string]string{
	"integer": "int", "int1": "tinyint", "int2": "smallint", "int3": "mediumint",
	"int4": "int", "int8": "bigint", "middleint": "mediumint",
	"dec": "decimal", "numeric": "decimal", "fixed": "decimal",
	"float4": "float", "float8": "double", "real": "double",
	"character": "char", "nchar": "char", "nvarchar": "varchar",
}

// spatialTypes are the types an SRID attribute belongs to.
var spatialTypes = map[string]bool{
	"geometry": true, "point": true, "linestring": true, "polygon": true, "multipoint": true,
	"multilinestring": true, "multipolygon": true, "geometrycollection": true, "geomcollection": true,
}

// classOf returns the class of a data type.
func classOf(dataType string) typeClass {
	switch dataType {
	case "char", "varchar":
		return classChar
	case "binary", "varbinary":
		return classBinary
	case "tinytext", "text", "mediumtext", "longtext":
		return classText
	case "tinyblob", "blob", "mediumblob", "longblob":
		return classBlob
	case "enum", "set":
		return classEnum
	}
	return classOther
}

// hasCharset reports whether a type's column carries a character set and a
// collation: the CHAR, TEXT, ENUM and SET types.
func hasCharset(c typeClass) bool {
	return c == classChar || c == classText || c == classEnum
}

// quoteMember writes an ENUM or SET member as COLUMN_TYPE does.
func quoteMember(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// memberLength is an ENUM or SET column's length in characters, as both
// servers give it: the longest member for an ENUM, and for a SET the members
// joined by commas, which is the longest value the column holds.
func memberLength(dataType string, members []string) int64 {
	var longest, total int
	for _, m := range members {
		l := utf8.RuneCountInString(m)
		longest = max(longest, l)
		total += l
	}
	if dataType == "set" {
		return int64(total + max(len(members)-1, 0))
	}
	return int64(longest)
}

// bytesPerChar is the widest character of a character set, as
// CHARACTER_OCTET_LENGTH counts it.
func bytesPerChar(cs string) int64 {
	switch cs {
	case "utf8mb4", "utf16", "utf16le", "utf32", "gb18030":
		return 4
	case "utf8mb3", "utf8", "ujis", "eucjpms":
		return 3
	case "big5", "gbk", "gb2312", "sjis", "cp932", "euckr", "ucs2":
		return 2
	}
	return 1
}

// defaultCollations holds the default collation of the character sets that
// don't use <name>_general_ci.
var defaultCollations = map[string]string{
	"latin1": "latin1_swedish_ci", "binary": "binary", "dec8": "dec8_swedish_ci",
	"hp8": "hp8_english_ci", "swe7": "swe7_swedish_ci", "big5": "big5_chinese_ci",
	"gbk": "gbk_chinese_ci", "gb2312": "gb2312_chinese_ci", "gb18030": "gb18030_chinese_ci",
	"sjis": "sjis_japanese_ci", "cp932": "cp932_japanese_ci", "ujis": "ujis_japanese_ci",
	"eucjpms": "eucjpms_japanese_ci", "euckr": "euckr_korean_ci",
	"latin5": "latin5_turkish_ci", "tis620": "tis620_thai_ci",
	"utf16le": "utf16le_general_ci",
}

// flavour is the kind and the major version of the server a dump came from,
// read from its header.
type flavour struct {
	mariadb bool
	major   int
	minor   int
}

// flavourOf reads the server version of a header. An unknown version is
// taken for a current MySQL.
func flavourOf(h Header) flavour {
	f := flavour{mariadb: h.MariaDB}
	v := strings.TrimPrefix(h.ServerVersion, "5.5.5-")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		f.major, _ = strconv.Atoi(parts[0])
		f.minor, _ = strconv.Atoi(strings.TrimRight(parts[1], "-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	}
	return f
}

// atLeast reports a version of at least major.minor.
func (f flavour) atLeast(major, minor int) bool {
	return f.major > major || (f.major == major && f.minor >= minor)
}

// legacyUTF8 reports a server whose information_schema still says utf8 where
// the newer ones say utf8mb3.
func (f flavour) legacyUTF8() bool {
	if f.major == 0 {
		return false
	}
	if f.mariadb {
		return f.major < 10 || (f.major == 10 && f.minor < 6)
	}
	return f.major < 8
}

// defaultUTF8MB4 is the collation a server gives utf8mb4 when nothing says.
func (f flavour) defaultUTF8MB4() string {
	switch {
	case f.mariadb && f.atLeast(11, 6):
		return "utf8mb4_uca1400_ai_ci"
	case f.mariadb, f.major != 0 && f.major < 8:
		return "utf8mb4_general_ci"
	}
	return "utf8mb4_0900_ai_ci"
}

// charsetName lower-cases a character set's name and spells utf8 as the
// server's information_schema does.
func (f flavour) charsetName(cs string) string {
	cs = strings.ToLower(cs)
	if cs == "utf8" && !f.legacyUTF8() {
		return "utf8mb3"
	}
	if cs == "utf8mb3" && f.legacyUTF8() {
		return "utf8"
	}
	return cs
}

// collationName lower-cases a collation's name, with the same spelling of
// utf8 as charsetName.
func (f flavour) collationName(coll string) string {
	coll = strings.ToLower(coll)
	if strings.HasPrefix(coll, "utf8_") && !f.legacyUTF8() {
		return "utf8mb3_" + coll[len("utf8_"):]
	}
	if strings.HasPrefix(coll, "utf8mb3_") && f.legacyUTF8() {
		return "utf8_" + coll[len("utf8mb3_"):]
	}
	return coll
}

// defaultCollation is the default collation of a character set.
func (f flavour) defaultCollation(cs string) string {
	cs = f.charsetName(cs)
	if cs == "utf8mb4" {
		return f.defaultUTF8MB4()
	}
	switch cs {
	case "utf8mb3", "utf8", "ucs2", "utf16", "utf32":
		if f.mariadb && f.atLeast(11, 8) {
			return cs + "_uca1400_ai_ci"
		}
	}
	if c, ok := defaultCollations[cs]; ok {
		return c
	}
	return cs + "_general_ci"
}

// charsetOfCollation reads a character set from a collation's name.
func (f flavour) charsetOfCollation(coll string) string {
	coll = f.collationName(coll)
	if coll == "binary" {
		return "binary"
	}
	if i := strings.IndexByte(coll, '_'); i > 0 {
		return coll[:i]
	}
	return ""
}

// charColl is a character set with a collation.
type charColl struct{ cs, coll string }

// complete fills what one of the two lacks: the character set from the
// collation's name, or the collation from the character set's default.
func (f flavour) complete(cs, coll string) charColl {
	cs, coll = f.charsetName(cs), f.collationName(coll)
	if cs == "" && coll != "" {
		cs = f.charsetOfCollation(coll)
	}
	if cs != "" && coll == "" {
		coll = f.defaultCollation(cs)
	}
	return charColl{cs, coll}
}

// fallback is what a table gets when neither it nor its database says.
func (f flavour) fallback() charColl {
	return charColl{"utf8mb4", f.defaultUTF8MB4()}
}

// flavourOfLine reads a "Server version" comment line into a flavour.
func flavourOfLine(line string) (flavour, bool) {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(line), "--"), "#"))
	if !strings.HasPrefix(s, "Server version") {
		return flavour{}, false
	}
	v := strings.TrimSpace(strings.TrimLeft(s[len("Server version"):], ": 	"))
	return flavourOf(Header{ServerVersion: v, MariaDB: strings.Contains(strings.ToLower(v), "mariadb")}), true
}
