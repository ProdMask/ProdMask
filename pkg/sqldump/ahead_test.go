package sqldump

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
	"testing/iotest"
)

func TestAheadReaderGivesTheBytesAndTheError(t *testing.T) {
	data := make([]byte, 3<<20+17)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range data {
		data[i] = byte(rng.UintN(256))
	}
	// A source that gives its bytes in small, uneven pieces.
	a := newAheadReader(iotest.HalfReader(bytes.NewReader(data)))
	got, err := io.ReadAll(a)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read %d bytes of %d, error %v", len(got), len(data), err)
	}
	a.Close()

	boom := errors.New("boom")
	a = newAheadReader(io.MultiReader(bytes.NewReader(data[:1000]), iotest.ErrReader(boom)))
	got, err = io.ReadAll(a)
	if !errors.Is(err, boom) || !bytes.Equal(got, data[:1000]) {
		t.Fatalf("read %d bytes, error %v", len(got), err)
	}
	a.Close()
}

type endless struct{}

func (endless) Read(p []byte) (int, error) { return len(p), nil }

func TestAheadReaderCloseStopsTheGoroutine(t *testing.T) {
	a := newAheadReader(endless{})
	buf := make([]byte, 100)
	if _, err := a.Read(buf); err != nil {
		t.Fatal(err)
	}
	a.Close() // returns only when the goroutine has stopped
	a.Close()
	select {
	case <-a.done:
	default:
		t.Fatal("the goroutine is still running")
	}
}
