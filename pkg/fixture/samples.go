package fixture

import (
	"fmt"
	"math/big"
)

// Samples returns n invented values of each kind a replacement must catch in
// free text, by kind: emails, phone numbers with a country or area code,
// card numbers, IBANs and secrets, from the fixture's generators and the
// seed. Tests write them into plain words and check none comes back.
func Samples(seed uint64, n int) map[string][]string {
	g := newGen(seed)
	out := map[string][]string{}
	for i := range n {
		p := g.person(i)
		out["email"] = append(out["email"], p.email)
		out["phone"] = append(out["phone"], p.phone)
		out["card"] = append(out["card"], g.cardNumber())
		out["iban"] = append(out["iban"], g.iban())
		out["secret"] = append(out["secret"], g.stripeKey("live"), g.sendgridKey())
	}
	return out
}

// iban returns a German IBAN with valid check digits: an invented bank code
// and account number.
func (g *gen) iban() string {
	bban := g.chars("0123456789", 18)
	// Check digits: 98 minus the BBAN, then DE00 as digits (D=13, E=14),
	// modulo 97.
	n, _ := new(big.Int).SetString(bban+"131400", 10)
	check := 98 - new(big.Int).Mod(n, big.NewInt(97)).Int64()
	return fmt.Sprintf("DE%02d%s", check, bban)
}
