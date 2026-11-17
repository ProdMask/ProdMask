package dbconn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
)

const label = "the unix socket from wp-config.php"

func TestDescribeAs(t *testing.T) {
	cfg := mysql.NewConfig()
	cfg.Net, cfg.Addr, cfg.User, cfg.DBName = "unix", "/run/mysqld/mysqld.sock", "shop_ro", "shop"
	if got := DescribeAs(cfg, label); got != "shop as shop_ro through the unix socket from wp-config.php" {
		t.Errorf("DescribeAs: %q", got)
	}
	cfg.User = ""
	if got := DescribeAs(cfg, label); got != "shop through the unix socket from wp-config.php" {
		t.Errorf("DescribeAs without a user: %q", got)
	}
	if got := Describe(cfg); got != "unix(/run/mysqld/mysqld.sock)/shop" {
		t.Errorf("Describe changed: %q", got)
	}
	if got := DescribeAs(cfg, ""); got != Describe(cfg) {
		t.Errorf("DescribeAs with no label: %q", got)
	}
}

// socketConfig points at a unix socket nobody listens on, whose path holds a
// canary, as a project folder's name could.
func socketConfig(t *testing.T) (*mysql.Config, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Qz8labelCanary.sock")
	cfg := mysql.NewConfig()
	cfg.Net, cfg.Addr, cfg.User, cfg.DBName = "unix", path, "shop_ro", "shop"
	cfg.Timeout = 2 * time.Second
	return cfg, path
}

// TestOpenAsHidesAddress checks that a labelled session's failed connection
// names the label and the dial's cause, never the socket's path, and still
// unwraps to the dial error; and that without a label it reads as before.
func TestOpenAsHidesAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, path := socketConfig(t)

	_, err := OpenAs(ctx, cfg, time.Second, label)
	if err == nil {
		t.Fatal("connected to a socket nobody listens on")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "connect to shop as shop_ro through the unix socket from wp-config.php: ") ||
		strings.Contains(msg, "Qz8labelCanary") || strings.Contains(msg, filepath.Dir(path)) {
		t.Errorf("OpenAs: %q", strings.ReplaceAll(msg, path, "<path>"))
	}
	var op *net.OpError
	if !errors.As(err, &op) {
		t.Errorf("OpenAs's error doesn't unwrap to the dial error: %#v", err)
	}

	_, err = Open(ctx, cfg, time.Second)
	if err == nil || !strings.HasPrefix(err.Error(), "connect to shop_ro@unix("+path+")/shop: ") {
		t.Errorf("Open changed: %v", err)
	}
}

// logRecorder is a driver logger that keeps the lines it's given.
type logRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *logRecorder) Print(v ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprint(v...))
}

func (r *logRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	lines := r.lines
	r.lines = nil
	return lines
}

// TestLabelSilencesDriverLog checks that a labelled session keeps the driver
// from logging. The driver writes its log to stderr itself, and a
// failed read's line quotes the network error, whose text holds a socket's
// path. Without a label the driver logs as before.
func TestLabelSilencesDriverLog(t *testing.T) {
	rec := &logRecorder{}
	if err := mysql.SetLogger(rec); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mysql.SetLogger(log.New(os.Stderr, "[mysql] ", log.Ldate|log.Ltime)) })

	// A server that hangs up at once fails the driver's first read, which it
	// logs.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cfg := mysql.NewConfig() // whose logger is now the recorder
	cfg.Net, cfg.Addr, cfg.User, cfg.DBName = "tcp", ln.Addr().String(), "shop_ro", "shop"
	cfg.Timeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := OpenAs(ctx, cfg, time.Second, label); err == nil {
		t.Fatal("OpenAs connected to a server that hangs up")
	}
	if lines := rec.take(); len(lines) > 0 {
		t.Errorf("the driver logged %d line(s) for a labelled target", len(lines))
	}
	if _, err := Open(ctx, cfg, time.Second); err == nil {
		t.Fatal("Open connected to a server that hangs up")
	}
	if len(rec.take()) == 0 {
		t.Error("the driver logged nothing without a label, so this test can't see its log")
	}
}

// TestOpenAsServerAddress checks that a labelled session reports the label as
// its server's address. It needs PRODMASK_TEST_DSN; testdb.DSN skips or fails
// it without one.
func TestOpenAsServerAddress(t *testing.T) {
	cfg, err := mysql.ParseDSN(testdb.DSN(t))
	if err != nil {
		t.Fatal("PRODMASK_TEST_DSN doesn't parse")
	}
	cfg.DBName = "mysql"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := OpenAs(ctx, cfg, 10*time.Second, label)
	if err != nil {
		t.Fatalf("OpenAs: %v", err)
	}
	defer s.Close()
	if s.Server.Address != label || s.Server.User != cfg.User {
		t.Errorf("Server: address %q, user %q", s.Server.Address, s.Server.User)
	}
}
