//go:build windows

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

var getConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")

// consoleInfo is the console's CONSOLE_SCREEN_BUFFER_INFO: the buffer's
// size, the cursor, the colours, and the part of the buffer the window
// shows.
type consoleInfo struct {
	size       struct{ x, y int16 }
	cursor     struct{ x, y int16 }
	attributes uint16
	window     struct{ left, top, right, bottom int16 }
	maxWindow  struct{ x, y int16 }
}

// windowColumns is how many columns the console's window shows. The buffer
// is often far wider than the window, so its size would lay the report out
// past the window's edge.
func windowColumns(info consoleInfo) int {
	return int(info.window.right) - int(info.window.left) + 1
}

// termWidth asks the console f is for its window's width. An error, or a
// file that isn't a console, gives 0.
func termWidth(f *os.File) int {
	var info consoleInfo
	r, _, _ := getConsoleScreenBufferInfo.Call(uintptr(syscall.Handle(f.Fd())), uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return 0
	}
	return max(windowColumns(info), 0)
}
