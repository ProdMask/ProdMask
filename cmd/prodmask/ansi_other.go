//go:build !windows

package main

import "os"

// enableANSI reports whether colours will show; terminals outside Windows
// handle escape sequences already.
func enableANSI(*os.File) bool { return true }
