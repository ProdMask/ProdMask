package dbconn

import (
	"errors"
	"fmt"
	"net"

	"github.com/go-sql-driver/mysql"
)

// DescribeAs renders the connection target as Describe does, but names it by
// label instead of its address: "shop as shop_ro through the unix socket from
// wp-config.php". It's for a target whose address isn't to be shown, such as a
// unix socket read from an application's configuration, whose path can hold a
// user's or a project's name. An empty label is Describe.
func DescribeAs(cfg *mysql.Config, label string) string {
	if label == "" {
		return Describe(cfg)
	}
	s := cfg.DBName
	if cfg.User != "" {
		s += " as " + cfg.User
	}
	return s + " through " + label
}

// target is how a session names what it connects to: by Describe and Address,
// or by label when one is given.
func target(cfg *mysql.Config, label string) (describe, address string) {
	if label == "" {
		return Describe(cfg), Address(cfg)
	}
	return DescribeAs(cfg, label), label
}

// quiet keeps the driver from logging for a labelled target. The driver
// writes its log to stderr itself, and a failed read's line quotes the
// network error, whose text holds the address.
func quiet(cfg *mysql.Config, label string) {
	if label != "" {
		cfg.Logger = &mysql.NopLogger{}
	}
}

// connectError wraps a failed connection. With a label, a dial error is shown
// by its cause alone, such as "connect: no such file or directory", since its
// own text quotes the address; it still unwraps to the *net.OpError.
func connectError(cfg *mysql.Config, label string, err error) error {
	describe, _ := target(cfg, label)
	var op *net.OpError
	if label != "" && errors.As(err, &op) && op.Err != nil {
		err = causeOnly{op}
	}
	return fmt.Errorf("connect to %s: %w", describe, err)
}

// causeOnly is a dial error printed without its address.
type causeOnly struct{ op *net.OpError }

func (c causeOnly) Error() string { return c.op.Err.Error() }

func (c causeOnly) Unwrap() error { return c.op }
