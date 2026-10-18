package detect

import (
	"encoding/hex"
	"math/rand/v2"
	"net/netip"
	"testing"
)

func TestBinaryIPColumn(t *testing.T) {
	for _, c := range []struct {
		table, column string
		want          bool
	}{
		{"mybb_users", "regip", true},
		{"mybb_users", "lastip", true},
		{"mybb_posts", "ipaddress", true},
		{"blocked_visitors", "ip", true},
		{"visitors", "visitor_ip_hash", false},
		{"visitors", "ip_md5", false},
		{"devices", "device_uuid", false},
		{"users", "avatar", false},
	} {
		if got := BinaryIPColumn(c.table, c.column); got != c.want {
			t.Errorf("BinaryIPColumn(%s, %s) = %v, want %v", c.table, c.column, got, c.want)
		}
	}
}

func TestBinaryIP(t *testing.T) {
	hexOf := func(b []byte) string { return hex.EncodeToString(b) }
	v4 := netip.MustParseAddr("192.0.2.10").As4()
	v6 := netip.MustParseAddr("2001:db8::7").As16()
	mapped := netip.MustParseAddr("::ffff:198.51.100.3").As16()
	padded := append(v4[:], make([]byte, 12)...)
	cases := []struct {
		name, hex, ip string
		empty, ok     bool
	}{
		{"4 bytes", hexOf(v4[:]), "192.0.2.10", false, true},
		{"4 bytes padded", hexOf(padded), "192.0.2.10", false, true},
		{"IPv6", hexOf(v6[:]), "2001:db8::7", false, true},
		{"IPv4-mapped", hexOf(mapped[:]), "198.51.100.3", false, true},
		{"zeros", hexOf(make([]byte, 16)), "", true, true},
		{"no bytes", "", "", true, true},
		{"text", hexOf([]byte("203.0.113.9")), "203.0.113.9", false, true},
		{"8 bytes", hexOf([]byte{1, 2, 3, 4, 5, 6, 7, 8}), "", false, false},
		{"bad hex", "zz", "", false, false},
	}
	for _, c := range cases {
		ip, empty, ok := BinaryIP(c.hex)
		if ip != c.ip || empty != c.empty || ok != c.ok {
			t.Errorf("%s: got %q, %v, %v; want %q, %v, %v", c.name, ip, empty, ok, c.ip, c.empty, c.ok)
		}
	}
	// Hashes stored in 16 bytes rarely read as addresses: well under half.
	r := rand.New(rand.NewPCG(1, 2))
	hits := 0
	for i := 0; i < 1000; i++ {
		var b [16]byte
		for j := range b {
			b[j] = byte(r.IntN(256))
		}
		if _, _, ok := BinaryIP(hexOf(b[:])); ok {
			hits++
		}
	}
	if hits > 200 {
		t.Errorf("%d of 1000 random values read as addresses", hits)
	}
}

// IP names that end in a webhook word still match the IP rule first.
func TestBinaryIPColumnWebhookNames(t *testing.T) {
	for _, c := range []string{"ip_webhook", "client_ip_hook_url"} {
		if !BinaryIPColumn("integrations", c) {
			t.Errorf("%s isn't read as hex", c)
		}
	}
}
