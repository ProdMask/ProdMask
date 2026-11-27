package sqldump

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// A damaged source after the SQL mode became unknown is still an error.
func TestDrainAfterUnknownModeKeepsTheError(t *testing.T) {
	src := io.MultiReader(strings.NewReader("SET sql_mode=@x;\nINSERT INTO t VALUES (1);\n"), iotest.ErrReader(errors.New("boom")))
	_, err := Read(context.Background(), src, &rec{}, testOpts())
	if !errors.Is(err, ErrRead) {
		t.Fatalf("error = %v, want ErrRead", err)
	}
}

func TestDrainAfterUnknownModeStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	src := io.MultiReader(strings.NewReader("SET sql_mode=@x;\n"), readerFunc(func(p []byte) (int, error) {
		cancel()
		return len(p), nil
	}))
	_, err := Read(ctx, src, &rec{}, testOpts())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// Closing a reader over standard input doesn't wait for a source that is
// stalled.
func TestAheadReaderNoWaitCloseReturns(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	a := newAheadReader(readerFunc(func(p []byte) (int, error) {
		<-block
		return 0, io.EOF
	}))
	a.noWait = true
	done := make(chan struct{})
	go func() { a.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for a stalled source")
	}
}
