package cli

import "testing"

// The report is laid out at the window's width, not the buffer's, which on
// Windows is often far wider.
func TestWindowColumns(t *testing.T) {
	var info consoleInfo
	info.size.x, info.size.y = 9001, 3000
	info.window.left, info.window.right = 0, 119
	if got := windowColumns(info); got != 120 {
		t.Errorf("window 0..119 in a 9001-column buffer: got %d columns, want 120", got)
	}
	info.window.left, info.window.right = 10, 89
	if got := windowColumns(info); got != 80 {
		t.Errorf("window 10..89: got %d columns, want 80", got)
	}
}
