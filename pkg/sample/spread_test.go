package sample

import (
	"math/big"
	"math/rand/v2"
	"strings"
	"testing"
)

// picker is a seeded stand-in for the random spot in a slice.
func picker(seed uint64) func(uint64) uint64 {
	r := rand.New(rand.NewPCG(seed, seed*7+1))
	return func(n uint64) uint64 { return r.Uint64N(n) }
}

// points picks the spots of every slice of a key range.
func points(t *testing.T, first, span *big.Int, n int, pick func(uint64) uint64) []*big.Int {
	t.Helper()
	out := make([]*big.Int, n)
	for i := range out {
		p, ok := new(big.Int).SetString(slicePoint(first, span, i, n, pick), 10)
		if !ok {
			t.Fatal("a point isn't a number")
		}
		out[i] = p
	}
	return out
}

func TestSlicePointStaysInItsSlice(t *testing.T) {
	maxU, _ := new(big.Int).SetString("18446744073709551615", 10)
	for name, c := range map[string]struct{ first, last *big.Int }{
		"small":        {big.NewInt(1), big.NewInt(100000)},
		"negative":     {big.NewInt(-50000), big.NewInt(50000)},
		"unsigned":     {big.NewInt(0), maxU},
		"near the top": {new(big.Int).Sub(maxU, big.NewInt(100000)), maxU},
	} {
		span := new(big.Int).Add(new(big.Int).Sub(c.last, c.first), big.NewInt(1))
		const n = 3000
		ps := points(t, c.first, span, n, picker(1))
		for i, p := range ps {
			if p.Cmp(c.first) < 0 || p.Cmp(c.last) > 0 {
				t.Errorf("%s: point %d is outside the key range", name, i)
			}
			if i > 0 && p.Cmp(ps[i-1]) < 0 {
				t.Errorf("%s: point %d is before the one before it", name, i)
			}
		}
	}
	// Every key of a range is reachable by some slice, the first and last too.
	span := big.NewInt(20)
	seen := map[string]bool{}
	for seed := range uint64(200) {
		for _, p := range points(t, big.NewInt(1), span, 4, picker(seed)) {
			seen[p.String()] = true
		}
	}
	if len(seen) != 20 {
		t.Errorf("%d of 20 keys reachable", len(seen))
	}
}

// TestPointOdds is the sampling arithmetic at work: a scattered leak is caught
// at the table's odds, and a block far more surely, on a key range with no
// gaps, where each point is one row.
func TestPointOdds(t *testing.T) {
	const rows = 100000
	first, span := big.NewInt(1), big.NewInt(rows)
	r := rand.New(rand.NewPCG(5, 6))
	sample := func(n int, seed uint64) map[int64]bool {
		out := map[int64]bool{}
		for _, p := range points(t, first, span, n, picker(seed)) {
			out[p.Int64()] = true
		}
		return out
	}
	// 50 rows scattered, 300 sampled: about 14%. 3,000 sampled: about 78%.
	for _, c := range []struct {
		n        int
		low, top float64
	}{{300, 0.10, 0.18}, {3000, 0.73, 0.83}} {
		caught := 0
		const trials = 1500
		for trial := range trials {
			s := sample(c.n, uint64(trial))
			for range 50 {
				if s[r.Int64N(rows)+1] {
					caught++
					break
				}
			}
		}
		if rate := float64(caught) / trials; rate < c.low || rate > c.top {
			t.Errorf("%d sampled caught 50 scattered rows %.0f%% of the time", c.n, rate*100)
		}
	}
	// 3,000 slices of 100,000 keys are 33.3 wide, so an unbroken run of 67 rows
	// holds a whole slice, wherever it starts, and can't be missed.
	for trial := range 500 {
		s := sample(3000, uint64(1000+trial))
		start := r.Int64N(rows-67) + 1
		hit := false
		for k := start; k < start+67; k++ {
			hit = hit || s[k]
		}
		if !hit {
			t.Fatalf("a run of 67 rows from %d was missed", start)
		}
	}
}

func TestClustered(t *testing.T) {
	span := big.NewInt(2_500_000_000)
	near := make([]float64, 2000)
	far := make([]float64, 2000)
	for i := range near {
		near[i] = float64(i%20000) * 0.7 // about the keys' spacing of 10,000
		far[i] = 500000
	}
	if clustered(near, span, 250000) {
		t.Error("rows near their points")
	}
	if !clustered(far, span, 250000) {
		t.Error("rows far from their points")
	}
	if clustered(far, span, 0) || clustered(nil, span, 250000) {
		t.Error("with no estimate or no rows, it can't tell")
	}
	if got := keyDistance("500", "120"); got != 380 {
		t.Errorf("distance %v", got)
	}
	if got := keyDistance("18446744073709551615", "18446744073709551610"); got != 5 {
		t.Errorf("distance near the top %v", got)
	}
	if got := keyDistance("-5", "-20"); got != 15 {
		t.Errorf("negative keys %v", got)
	}
}

func TestSpreadStatementHasNoText(t *testing.T) {
	// A point is a number, whatever the picker gives.
	if s := slicePoint(big.NewInt(-5), big.NewInt(10), 0, 2, func(uint64) uint64 { return 3 }); s != "-2" {
		t.Errorf("point %s", s)
	}
	if s := slicePoint(big.NewInt(1), big.NewInt(1), 0, 1, func(uint64) uint64 { return 0 }); s != "1" || strings.ContainsAny(s, "'\" ") {
		t.Errorf("point %s", s)
	}
}
