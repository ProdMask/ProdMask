package fixture

import (
	"math/big"
	"strings"
	"testing"
)

// TestSamplesIBAN checks the invented IBANs pass the mod-97 check, so a
// finder that tests check digits takes them.
func TestSamplesIBAN(t *testing.T) {
	ibans := Samples(7, 20)["iban"]
	if len(ibans) != 20 {
		t.Fatalf("%d IBANs, want 20", len(ibans))
	}
	for _, s := range ibans {
		n, ok := new(big.Int).SetString(s[4:]+"1314"+s[2:4], 10)
		if !ok || !strings.HasPrefix(s, "DE") || len(s) != 22 || new(big.Int).Mod(n, big.NewInt(97)).Int64() != 1 {
			t.Errorf("%s isn't a valid IBAN", s)
		}
	}
}
