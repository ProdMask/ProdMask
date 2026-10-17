package dbconn

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
)

// Server error numbers for statements stopped by a time limit or killed.
const (
	errQueryInterrupted  = 1317 // ER_QUERY_INTERRUPTED
	errMariaDBStatement  = 1969 // ER_STATEMENT_TIMEOUT (max_statement_time)
	errMySQLExecution    = 3024 // ER_QUERY_TIMEOUT (max_execution_time)
	errMySQLExecutionOld = 1907 // ER_QUERY_TIMEOUT before MySQL 5.7.8
)

// ErrorText describes a failed statement without quoting the server's
// message, which can repeat bound arguments or bytes from a row. Reports and
// warnings use it for every statement that reads keys or values.
func ErrorText(err error) string {
	var my *mysql.MySQLError
	switch {
	case err == nil:
		return ""
	case IsTimeout(err):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.As(err, &my):
		return fmt.Sprintf("MySQL error %d", my.Number)
	case errors.Is(err, mysql.ErrInvalidConn), errors.Is(err, driver.ErrBadConn):
		return "lost the connection"
	}
	return "query failed"
}

// IsTimeout reports whether a statement was stopped by the client or server
// time limit.
func IsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		switch my.Number {
		case errQueryInterrupted, errMariaDBStatement, errMySQLExecution, errMySQLExecutionOld:
			return true
		}
	}
	return false
}
