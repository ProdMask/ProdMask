package leak

import (
	"math"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// chanceSpace is the rough, cautious size of the space a masking tool's
// made-up phone number or ID is drawn from.
const chanceSpace = 1e8

// CatchChance is the chance that a sample of n values out of N catches at
// least one of real real values: close to 1 - (1 - n/N)^real.
func CatchChance(n, N, real float64) float64 {
	if N <= 0 || n >= N {
		return 1
	}
	return 1 - math.Pow(1-n/N, real)
}

// ShownAt95 is how many real values a sample of n out of N shows 95% of the
// time.
func ShownAt95(n, N float64) float64 {
	if N <= 0 || n >= N {
		return 0
	}
	return math.Log(0.05) / math.Log(1-n/N)
}

// fillOdds works out what a column's numbers say. All of it assumes a leak
// that is spread evenly or in blocks, so reports say "about" and "roughly".
func fillOdds(c *model.LeakColumn) {
	n, N, M := float64(c.Sampled), float64(c.EstimatedValues), float64(c.Values)
	if c.Kind == model.LeakPhone || c.Kind == model.LeakNationalID {
		if ch := n * M / chanceSpace; ch >= 0.5 {
			c.ChanceMatches = ch
		}
	}
	if c.State != model.LeakRead {
		return
	}
	switch c.Sample {
	case model.SampleFirstRows, model.SampleThin, model.SampleCut:
		return
	}
	if c.Exact || n <= 0 || N <= n {
		return
	}
	if shown := ShownAt95(n, N); shown >= 1 {
		c.ShownAt95 = shown
		if M > 0 && M < shown {
			c.CatchIfAllReal = CatchChance(n, N, M)
		}
	}
	if c.Found >= 10 && !(c.ChanceMatches > 0 && float64(c.Found) <= 2*c.ChanceMatches) {
		// N can overshoot where values repeat, so the estimate can't be more
		// than staging was seen to hold.
		c.EstimateInAll = roundTwo(min(float64(c.Found)/n*N, M))
	}
}

// roundTwo keeps two significant digits: anything more would claim too much of
// an estimate.
func roundTwo(x float64) int64 {
	if x < 100 {
		return int64(math.Round(x))
	}
	unit := math.Pow(10, math.Floor(math.Log10(x))-1)
	return int64(math.Round(x/unit) * unit)
}
