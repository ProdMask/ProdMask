//go:build !linux

// Package harden keeps what a prodmask process holds in memory, such as a
// DSN's password and the rows it reads, out of core dumps and out of reach
// of another process running as the same user.
package harden

// Process has nothing to do on these systems, which write no core dumps
// unless set up to.
func Process() {}
