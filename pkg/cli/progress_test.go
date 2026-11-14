package cli

import "testing"

// TestProgressLine checks that a progress line writes a table's name with ?
// for each character that could steer the terminal, that compare's adds the
// rows read, and that a line with no table clears it.
func TestProgressLine(t *testing.T) {
	// A title change, a bell, a carriage return and a right-to-left override.
	steering := "\x1b]0;pwned\x07\r\xe2\x80\xae"
	for _, c := range []struct{ name, got, want string }{
		{"scan", progressLine("Scanning", 0, 3, "orders"+steering), "\r\x1b[KScanning 1/3 orders?]0;pwned???"},
		{"scan, no table", progressLine("Scanning", 2, 3, ""), "\r\x1b[K"},
		{"compare", readingLine(1, 4, "wp_users"+steering, 12345), "\r\x1b[KReading 2/4 wp_users?]0;pwned???: 12,345 rows"},
		{"compare, no table", readingLine(3, 4, "", 12345), "\r\x1b[K"},
	} {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
}
