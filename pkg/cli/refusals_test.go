package cli

import (
	"fmt"
	"os"
	"testing"

	"github.com/ProdMask/ProdMask/internal/refusals"
)

// TestMain fails the run when a Session refused any statement: no test here
// sends one on purpose, and the scan and the leak check would show a
// refusal only as a warning. It unsets COLUMNS first, so a test that runs a
// command never lays its report out at the width of the shell it ran in.
func TestMain(m *testing.M) {
	os.Unsetenv("COLUMNS")
	code := m.Run()
	if n := refusals.Count(); n != 0 && code == 0 {
		fmt.Fprintf(os.Stderr, "%d of prodmask's own statements were refused by the read-only rules; the last: %s\n", n, refusals.Last())
		code = 1
	}
	os.Exit(code)
}
