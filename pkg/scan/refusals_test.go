package scan_test

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/ProdMask/ProdMask/internal/refusals"
)

// onPurpose counts the statements tests send that a Session must refuse.
var onPurpose atomic.Int64

// TestMain fails the run when a Session refused a statement no test sent on
// purpose. prodmask's own statements must all pass the read-only rules, and
// some paths would turn a refusal into a warning that no test reads.
func TestMain(m *testing.M) {
	code := m.Run()
	if n := refusals.Count() - onPurpose.Load(); n != 0 && code == 0 {
		fmt.Fprintf(os.Stderr, "%d of prodmask's own statements were refused by the read-only rules; the last: %s\n", n, refusals.Last())
		code = 1
	}
	os.Exit(code)
}
