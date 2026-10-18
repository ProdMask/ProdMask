package detect

import (
	"encoding/hex"
	"net/netip"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// hashedWords mark a column that holds a hash, a key or an anonymised form
// of an IP address rather than the address.
var hashedWords = words("hash hashed md5 sha sha1 sha256 hmac digest key salt token nonce anon anonymized")

// BinaryIPColumn reports whether a binary column's name says it holds IP
// addresses, so its bytes are worth reading: the name matches the IP rule
// and has no word of a hash or a key. visitor_ip_hash isn't read, and keeps
// its finding by name.
func BinaryIPColumn(table, column string) bool {
	tokens := NameWords(column)
	if anyIn(tokens, hashedWords) {
		return false
	}
	// Tokens splits md5 into md and 5; join them back to check.
	for i := 0; i+1 < len(tokens); i++ {
		if isDigits(tokens[i+1]) && !isDigits(tokens[i]) && hashedWords[tokens[i]+tokens[i+1]] {
			return false
		}
	}
	m := MatchName(tokens, Tokens(table), tBin)
	return m != nil && m.Category == model.CatIPAddress
}

// BinaryIP decodes the hex of a value from a binary IP column. empty reports
// no bytes or all zero bytes, as unset addresses are stored (MyBB's default
// is an empty string). ok reports an address in a form it knows: printable text
// that parses as an IP; 4 bytes, or 4 followed by 12 zero bytes as a
// BINARY(16) pads them; 16 bytes that are an IPv4-mapped address or fall in
// the global (2000::/3), unique-local (fc00::/7) or link-local (fe80::/10)
// IPv6 ranges. Random bytes, such as a hash, land there about 13% of the
// time. The address only ever reaches a Profile.
func BinaryIP(hexValue string) (ip string, empty, ok bool) {
	b, err := hex.DecodeString(hexValue)
	if err != nil {
		return "", false, false
	}
	if allZero(b) {
		return "", true, true
	}
	text := b
	for len(text) > 0 && text[len(text)-1] == 0 {
		text = text[:len(text)-1]
	}
	if printable(text) {
		if a, err := netip.ParseAddr(string(text)); err == nil {
			return a.String(), false, true
		}
	}
	switch {
	case len(b) == 4:
		return netip.AddrFrom4([4]byte(b)).String(), false, true
	case len(b) == 16 && allZero(b[4:]):
		return netip.AddrFrom4([4]byte(b[:4])).String(), false, true
	case len(b) == 16:
		a := netip.AddrFrom16([16]byte(b))
		if a.Is4In6() {
			return a.Unmap().String(), false, true
		}
		if b[0]&0xE0 == 0x20 || b[0]&0xFE == 0xFC || (b[0] == 0xFE && b[1]&0xC0 == 0x80) {
			return a.String(), false, true
		}
	}
	return "", false, false
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(b) > 0
}
