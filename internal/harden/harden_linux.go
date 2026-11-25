// Package harden keeps what a prodmask process holds in memory, such as a
// DSN's password and the rows it reads, out of core dumps and out of reach
// of another process running as the same user.
package harden

import "syscall"

// Process makes the process non-dumpable and gives it no core files: its
// environment and memory can't then be read through /proc or by a debugger
// attaching as the same user, which a coding agent runs as.
func Process() {
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	const prSetDumpable = 4
	syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
}
