package sqldump

import (
	"bytes"
	"io"
	"runtime"
	"runtime/metrics"
	"sync"
	"testing"
	"time"
)

const heapMetric = "/memory/classes/heap/objects:bytes"

// peakHeap samples the live heap every 50 ms until stop is called, and
// returns the highest value seen.
func peakHeap() (stop func() uint64) {
	var (
		mu   sync.Mutex
		peak uint64
		done = make(chan struct{})
		wg   sync.WaitGroup
	)
	sample := []metrics.Sample{{Name: heapMetric}}
	take := func() {
		metrics.Read(sample)
		if sample[0].Value.Kind() != metrics.KindUint64 {
			return
		}
		mu.Lock()
		if v := sample[0].Value.Uint64(); v > peak {
			peak = v
		}
		mu.Unlock()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			take()
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	}()
	return func() uint64 {
		close(done)
		wg.Wait()
		take()
		mu.Lock()
		defer mu.Unlock()
		return peak
	}
}

// pipeOf writes head, then size bytes of fill, then tail, into a pipe.
func pipeOf(head string, fill byte, size int64, tail string) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		chunk := bytes.Repeat([]byte{fill}, 1<<20)
		io.WriteString(pw, head)
		for left := size; left > 0; {
			n := int64(len(chunk))
			if left < n {
				n = left
			}
			if _, err := pw.Write(chunk[:n]); err != nil {
				return
			}
			left -= n
		}
		io.WriteString(pw, tail)
		pw.Close()
	}()
	return pr
}

func TestStreamHugeStatements(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 4 GiB")
	}
	const size = 2 << 30
	tests := []struct {
		name       string
		head, tail string
		kind       Kind
	}{
		{"a string literal", "SET sql_mode='';\nINSERT INTO t VALUES ('", "');\nDROP TABLE a;\n", KindInsert},
		{"a string literal in a statement that is skipped", "SET sql_mode='';\nUPDATE t SET a = '", "';\nDROP TABLE a;\n", KindUpdate},
		{"a comment", "SET sql_mode='';\n/* ", " */ DROP TABLE a;\nDROP TABLE b;\n", KindDrop},
		{"a line comment", "SET sql_mode='';\n-- ", "\nDROP TABLE a;\n", KindDrop},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GC()
			stop := peakHeap()
			fill := byte('x')
			_, st := func() (*rec, Stats) {
				v := &rec{}
				st, err := Read(t.Context(), pipeOf(tc.head, fill, size, tc.tail), v, testOpts())
				if err != nil {
					t.Fatal(err)
				}
				return v, st
			}()
			peak := stop()
			if count(st, tc.kind) < 1 || count(st, KindDrop) < 1 || st.Bytes < size {
				t.Fatalf("stats: %v bytes=%d", st.ByKind, st.Bytes)
			}
			if st.Unread > 1 {
				t.Fatalf("unread = %d", st.Unread)
			}
			if peak > 64<<20 {
				t.Fatalf("peak heap %d MiB, want under 64", peak>>20)
			}
			t.Logf("peak heap %d MiB", peak>>20)
		})
	}
}
