package redact

import (
	"fmt"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/report"
)

// known are the server errors and warnings that get fixed words of their
// own. Any other shows its number and SQLSTATE only: a server's message can
// quote a row's value, or a stored function's SIGNAL text.
var known = map[int]string{
	1054: "a column the statement names doesn't exist; describe_table lists a table's columns",
	1146: "a table the statement names doesn't exist; list_tables lists the tables",
	1142: "this login can't read that table or column; describe_table lists what it can",
	1143: "this login can't read that table or column; describe_table lists what it can",
	1792: "the statement tried to write, and the read-only session refused it",
	3024: "the statement ran past the time limit, and the server stopped it",
	1969: "the statement ran past the time limit, and the server stopped it",
	1317: "the statement was stopped before it finished",
	1222: "the statement's SELECTs have different numbers of columns",
	1241: "an operand should be one column",
	1242: "a subquery returned more than one row",
	1248: "every derived table needs an alias",
}

// ErrorWords says why a statement failed, in fixed words. A syntax error
// shows the server's "near …" text only when that text is in the statement
// the agent sent.
func ErrorWords(number int, sqlState, message, statement string) string {
	if w, ok := known[number]; ok {
		return fmt.Sprintf("MySQL error %d: %s", number, w)
	}
	if number == 1064 {
		if near := nearText(message); near != "" && strings.Contains(statement, near) {
			return fmt.Sprintf("MySQL error 1064: a syntax error near '%s'", report.Clean(near))
		}
		return "MySQL error 1064: a syntax error, message withheld"
	}
	return fmt.Sprintf("MySQL error %d (%s), message withheld", number, sqlState)
}

// WarningWords shows a warning by the same rule, with its level: "warning
// 1292, message withheld". It drops MySQL's note 1003, the rewritten query,
// which can hold a table's values.
func WarningWords(level string, code int, message, statement string) (string, bool) {
	if code == 1003 {
		return "", false
	}
	level = strings.ToLower(report.Clean(level))
	if w, ok := known[code]; ok {
		return fmt.Sprintf("%s %d: %s", level, code, w), true
	}
	if code == 1064 {
		if near := nearText(message); near != "" && strings.Contains(statement, near) {
			return fmt.Sprintf("%s 1064: a syntax error near '%s'", level, report.Clean(near)), true
		}
	}
	return fmt.Sprintf("%s %d, message withheld", level, code), true
}

// nearText is the text of a syntax error's "near '…' at line N".
func nearText(message string) string {
	i := strings.LastIndex(message, "near '")
	if i < 0 {
		return ""
	}
	rest := message[i+len("near '"):]
	j := strings.LastIndex(rest, "' at line ")
	if j < 0 {
		return ""
	}
	return rest[:j]
}
