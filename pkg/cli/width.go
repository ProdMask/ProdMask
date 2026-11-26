package cli

import (
	"os"
	"strconv"
)

// textWidth is the width to lay the text report out at, which the report
// clamps to its own limits: 0, the report's own width, with --out;
// otherwise $COLUMNS, when it's a positive whole number; otherwise the
// width of the terminal env.Stdout is, when it is one; otherwise 0, as for
// pipes, files and CI logs. It reads the environment and the terminal
// through env, so tests can fake both.
func textWidth(env *Env, out string) int {
	if out != "" {
		return 0
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if n, err := strconv.Atoi(getenv("COLUMNS")); err == nil && n > 0 {
		return n
	}
	if f, ok := env.Stdout.(*os.File); ok {
		width := env.TermWidth
		if width == nil {
			width = termWidth
		}
		if n := width(f); n > 0 {
			return n
		}
	}
	return 0
}
