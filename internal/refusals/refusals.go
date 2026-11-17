// Package refusals counts the statements a scan session's checked
// connections refused, so tests can show that none of prodmask's own were:
// some paths turn an error into a warning or a fallback, where a refusal
// would otherwise pass unseen.
package refusals

import (
	"sync"
	"sync/atomic"
)

var (
	n    atomic.Int64
	mu   sync.Mutex
	last string
)

// Add counts one refused statement, and keeps why it was refused. The
// reason is the refusal's fixed words, which never quote the statement.
func Add(why string) {
	n.Add(1)
	mu.Lock()
	defer mu.Unlock()
	last = why
}

// Count returns how many statements were refused in this process.
func Count() int64 { return n.Load() }

// Last returns why the latest refused statement was refused, or "".
func Last() string {
	mu.Lock()
	defer mu.Unlock()
	return last
}
