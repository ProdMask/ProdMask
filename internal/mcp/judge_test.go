package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/scan"
)

// TestKeptVerdict: a table's judgement is kept unless its call was
// cancelled, or its sample failed for a reason other than the time limit.
func TestKeptVerdict(t *testing.T) {
	cut, stop := context.WithCancel(context.Background())
	stop()
	limit := &mysql.MySQLError{Number: 3024}
	for _, c := range []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"whole", context.Background(), nil, true},
		{"MySQL's time limit", context.Background(), limit, true},
		{"MariaDB's time limit", context.Background(), &mysql.MySQLError{Number: 1969}, true},
		{"a missing table", context.Background(), &mysql.MySQLError{Number: 1146}, false},
		{"a lost connection", context.Background(), errors.New("lost the connection"), false},
		{"a cancelled call", cut, nil, false},
		{"a cancelled call at the limit", cut, limit, false},
	} {
		if got := kept(c.ctx, scan.TableVerdict{SampleErr: c.err}); got != c.want {
			t.Errorf("%s: kept %v, want %v", c.name, got, c.want)
		}
	}
}
