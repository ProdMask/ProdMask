//go:build linux || darwin

// The terminal's width on Linux and macOS. The other Unix systems, such as
// the BSDs, take term_other.go's answer, which is none.

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

// termWidth asks the terminal f is for its width in columns. An error, or a
// file that isn't a terminal, gives 0.
func termWidth(f *os.File) int {
	var size struct{ rows, cols, x, y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0
	}
	return int(size.cols)
}
