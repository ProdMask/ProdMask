package sqldump

import "strings"

// escapeValue quotes b as mysql_real_escape_string does.
func escapeValue(b []byte) string {
	var sb strings.Builder
	sb.WriteByte('\'')
	for _, c := range b {
		switch c {
		case 0:
			sb.WriteString(`\0`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\\':
			sb.WriteString(`\\`)
		case '\'':
			sb.WriteString(`\'`)
		case '"':
			sb.WriteString(`\"`)
		case 26:
			sb.WriteString(`\Z`)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('\'')
	return sb.String()
}
