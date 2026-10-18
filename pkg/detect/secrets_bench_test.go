package detect

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// benchCorpora builds synthetic values of the kinds a scan reads. Only the
// last corpus holds secrets, assembled from pieces at run time.
func benchCorpora() map[string][]string {
	r := rand.New(rand.NewPCG(7, 11))
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	chars := func(set string, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = set[r.IntN(len(set))]
		}
		return string(b)
	}
	words := strings.Fields("order shipping customer basic plan product review delivery pattern compatible path " +
		"address billing note status pending complete refund coupon cart price stock bearer token session")
	sentence := func(n int) string {
		w := make([]string, n)
		for i := range w {
			w[i] = words[r.IntN(len(words))]
		}
		return strings.Join(w, " ")
	}
	repeat := func(n int, f func() string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f()
		}
		return out
	}
	grow := func(size int, f func() string) func() string {
		return func() string {
			var b strings.Builder
			for b.Len() < size {
				b.WriteString(f())
			}
			return b.String()
		}
	}
	short := repeat(1000, func() string {
		switch r.IntN(8) {
		case 0:
			return fmt.Sprint(r.IntN(100000))
		case 1:
			return "yes"
		case 2:
			return chars("abcdefghij", 6) + "@mail.fixture.gr"
		case 3:
			return fmt.Sprintf("2026-%02d-%02d 10:%02d:00", 1+r.IntN(12), 1+r.IntN(28), r.IntN(60))
		case 4:
			return strings.ReplaceAll(sentence(4), " ", "-")
		case 5:
			return chars("0123456789abcdef", 32)
		case 6:
			return sentence(3)
		}
		return chars(alnum, 12)
	})
	serialized := repeat(200, grow(1024, func() string {
		k, v := chars("abcdefghij_", 10), sentence(3)
		return fmt.Sprintf("s:%d:\"%s\";s:%d:\"%s\";", len(k), k, len(v), v)
	}))
	escaped := repeat(200, grow(1024, func() string {
		return fmt.Sprintf("{\"url\":\"https:\\/\\/shop.fixture.gr\\/%s\",\"note\":\"%s\"} ", chars("abcdef", 8), sentence(4))
	}))
	html := repeat(100, grow(4096, func() string {
		return fmt.Sprintf("<p>%s <a href=\"https://shop.fixture.gr/%s\">%s</a></p>\n", sentence(12), chars("abcdef", 6), sentence(2))
	}))
	svg := repeat(100, grow(4096, func() string {
		return fmt.Sprintf("<svg viewBox=\"0 0 24 24\"><path d=\"M%d %dL%d %dZ\"/></svg><span>Basic plan, %s</span>\n",
			r.IntN(24), r.IntN(24), r.IntN(24), r.IntN(24), sentence(5))
	}))
	logs := repeat(100, grow(4096, func() string {
		return fmt.Sprintf("2026-10-18 10:%02d:%02d 198.51.100.%d GET /%s?page=%d 200 Mozilla/5.0 (X11; Linux x86_64)\n",
			r.IntN(60), r.IntN(60), r.IntN(255), chars("abcdef/", 12), r.IntN(9))
	}))
	headers := repeat(100, grow(4096, func() string {
		return fmt.Sprintf("HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: sid=%s; path=/; HttpOnly\nCache-Control: no-cache\n",
			chars(alnum, 26))
	}))
	blobs := repeat(100, func() string {
		b := make([]byte, 3072)
		for i := range b {
			if r.IntN(3) == 0 {
				b[i] = byte(r.IntN(256))
			}
		}
		return base64.StdEncoding.EncodeToString(b)
	})
	secrets := repeat(200, func() string {
		switch r.IntN(4) {
		case 0:
			return "sk_" + "live_" + chars(alnum, 24)
		case 1:
			return "AK" + "IA" + chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 16)
		case 2:
			return "use " + "gh" + "p_" + chars(alnum, 36) + " for the deploy"
		}
		return "eyJ" + chars(alnum, 20) + ".eyJ" + chars(alnum, 30) + "." + chars(alnum, 20)
	})
	return map[string][]string{"short": short, "serialized": serialized, "escaped_json": escaped, "html": html,
		"html_svg": svg, "log": logs, "log_headers": headers, "base64": blobs, "secrets": secrets}
}

func BenchmarkFindSecrets(b *testing.B) {
	corpora := benchCorpora()
	for _, name := range []string{"short", "serialized", "escaped_json", "html", "html_svg", "log", "log_headers", "base64", "secrets"} {
		values := corpora[name]
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				for _, v := range values {
					FindSecrets(v)
				}
			}
		})
	}
}
