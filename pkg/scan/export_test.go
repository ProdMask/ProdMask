package scan

import "github.com/ProdMask/ProdMask/pkg/sample"

// SetKVModeHook makes readKV tell fn the mode it chose for each table: 1 for
// a whole read, 2 for listed keys, 3 for sampled ones. It returns a function
// that removes the hook.
func SetKVModeHook(fn func(table string, mode int)) (restore func()) {
	kvModeHook = func(table string, m kvMode) { fn(table, int(m)) }
	return func() { kvModeHook = nil }
}

// DumpTap makes a dump scan tell fn what each table collected: every window
// by its limit, and the mode of its key/value read (0 for a plain table).
func DumpTap(o *DumpOptions, fn func(table string, wins map[int]*sample.Sample, kvMode int)) {
	o.limits.tap = func(table string, wins map[int]*sample.Sample, kv *kvRead) {
		m := 0
		if kv != nil {
			m = int(kv.mode)
		}
		fn(table, wins, m)
	}
}
