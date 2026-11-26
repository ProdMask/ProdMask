//go:build !linux && !darwin && !windows

package cli

import "os"

// termWidth reports no width on the other systems, such as the BSDs, so
// their reports get the report's own width unless $COLUMNS says otherwise.
func termWidth(*os.File) int { return 0 }
