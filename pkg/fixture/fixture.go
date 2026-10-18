// Package fixture builds fake WordPress/WooCommerce, Magento 2 and Laravel
// databases for tests, and a generic one no preset knows. All data is
// invented: names from short lists, streets and cities mixed at random,
// phone numbers in the 555-01xx range reserved for fiction, IP addresses
// from the documentation ranges. Secret-looking strings are assembled at
// run time so that none sits in the repository.
package fixture

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

var (
	//go:embed sql/wordpress.sql
	wordpressSQL string
	//go:embed sql/magento2.sql
	magentoSQL string
	//go:embed sql/laravel.sql
	laravelSQL string
	//go:embed sql/generic.sql
	genericSQL string
)

// Platforms lists the fixtures Build can make.
var Platforms = []string{"wordpress", "magento2", "laravel", "generic"}

// Options for Build.
type Options struct {
	// Canary is placed inside several stored values. Reports must never
	// contain it.
	Canary string
	// Planted, when set, receives the secrets the fixture plants, for leak
	// tests. It stays in memory.
	Planted *Planted
}

// Build drops and recreates the database and fills it with fake data for
// the platform. admin needs multiStatements=true and the right to create
// databases.
func Build(ctx context.Context, admin *sql.DB, platform, database string, opts Options) error {
	ddl := map[string]string{"wordpress": wordpressSQL, "magento2": magentoSQL, "laravel": laravelSQL,
		"generic": genericSQL}[platform]
	if ddl == "" {
		return fmt.Errorf("unknown fixture %q", platform)
	}
	if opts.Canary == "" {
		opts.Canary = "nocanary"
	}
	qdb := "`" + strings.ReplaceAll(database, "`", "``") + "`"
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+qdb); err != nil {
		return err
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+qdb+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		return err
	}
	conn, err := admin.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "USE "+qdb); err != nil {
		return err
	}
	// Magento's admin store has ID 0, which needs this mode to insert.
	if _, err := conn.ExecContext(ctx, "SET SESSION sql_mode = CONCAT(@@sql_mode, ',NO_AUTO_VALUE_ON_ZERO')"); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("create %s tables: %w", platform, err)
	}
	f := &filler{ctx: ctx, conn: conn, g: newGen(42), canary: opts.Canary, planted: opts.Planted}
	switch platform {
	case "wordpress":
		f.wordpress()
	case "magento2":
		f.magento()
	case "laravel":
		f.laravel()
	case "generic":
		f.generic()
	}
	return f.err
}

// filler inserts rows and remembers the first error.
type filler struct {
	ctx     context.Context
	conn    *sql.Conn
	g       *gen
	canary  string
	planted *Planted
	err     error
}

// insert adds rows in batches of multi-row INSERTs.
func (f *filler) insert(table string, cols []string, rows [][]any) {
	if f.err != nil || len(rows) == 0 {
		return
	}
	const batch = 200
	for start := 0; start < len(rows); start += batch {
		end := min(start+batch, len(rows))
		var b strings.Builder
		fmt.Fprintf(&b, "INSERT INTO `%s` (`%s`) VALUES ", table, strings.Join(cols, "`, `"))
		one := "(" + strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ") + ")"
		var args []any
		for i, r := range rows[start:end] {
			if len(r) != len(cols) {
				f.err = fmt.Errorf("%s: row has %d values for %d columns", table, len(r), len(cols))
				return
			}
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(one)
			args = append(args, r...)
		}
		if _, err := f.conn.ExecContext(f.ctx, b.String(), args...); err != nil {
			f.err = fmt.Errorf("insert into %s: %w", table, err)
			return
		}
	}
}

// gen makes deterministic fake data.
type gen struct{ r *rand.Rand }

func newGen(seed uint64) *gen { return &gen{rand.New(rand.NewPCG(seed, seed*7919+1))} }

func (g *gen) intn(n int) int            { return g.r.IntN(n) }
func (g *gen) pick(list []string) string { return list[g.r.IntN(len(list))] }
func (g *gen) chance(p float64) bool     { return g.r.Float64() < p }

const (
	alnumChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	cryptChars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func (g *gen) chars(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[g.r.IntN(len(set))]
	}
	return string(b)
}

func (g *gen) alnum(n int) string { return g.chars(alnumChars, n) }
func (g *gen) hex(n int) string   { return g.chars("0123456789abcdef", n) }

func (g *gen) date(from, to int) time.Time {
	start := time.Date(from, 1, 1, 0, 0, 0, 0, time.UTC)
	span := time.Date(to, 12, 31, 0, 0, 0, 0, time.UTC).Sub(start)
	return start.Add(time.Duration(g.r.Int64N(int64(span)))).Truncate(time.Second)
}

func ts(t time.Time) string { return t.Format("2006-01-02 15:04:05") }

var (
	firstNames = []string{"Maria", "Eleni", "Katerina", "Sofia", "Georgia", "Nikos", "Giorgos", "Dimitris",
		"Kostas", "Yannis", "Anna", "Laura", "James", "Emma", "Lucas", "Mia", "Noah", "Olivia", "Leon", "Clara"}
	lastNames = []string{"Papadopoulou", "Georgiou", "Nikolaidis", "Ioannou", "Konstantinou", "Smith", "Jensen",
		"Moreau", "Rossi", "Novak", "Keller", "Fischer", "Murphy", "Silva", "Kowalski"}
	streets = []string{"Ermou", "Akadimias", "Panepistimiou", "Tsimiski", "Egnatias", "Main Street",
		"Station Road", "Rue de la Paix", "Via Roma", "Hauptstrasse"}
	places = []struct{ city, postcode, country, region string }{
		{"Athens", "105 57", "GR", "Attica"}, {"Thessaloniki", "546 23", "GR", "Central Macedonia"},
		{"Patras", "262 21", "GR", "Western Greece"}, {"Lyon", "69002", "FR", "Auvergne-Rhone-Alpes"},
		{"Munich", "80331", "DE", "Bavaria"}, {"Dublin", "D02 X285", "IE", "Leinster"},
		{"Milan", "20121", "IT", "Lombardy"}, {"Springfield", "62701", "US", "IL"},
	}
	domains   = []string{"fixture-mail.gr", "post.fixture-shop.net", "inbox-fixture.com", "mail.fixture.eu"}
	companies = []string{"Kafeneio Ltd", "Blue Harbour SA", "Olive Grove Co", "Northwind Traders", "Acme Fixtures"}
	agents    = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
	}
	words = strings.Fields("the quick order arrived on time and the packaging was good thanks again for the " +
		"fast delivery colour size fits well would buy again lovely shop friendly service gift for my sister")
)

// person is one invented customer.
type person struct {
	first, last, email, phone, street, city, postcode, country, region, company, ip, agent string
}

func (g *gen) person(i int) person {
	p := places[g.intn(len(places))]
	first, last := g.pick(firstNames), g.pick(lastNames)
	return person{
		first: first, last: last,
		email:  fmt.Sprintf("%s.%s%d@%s", strings.ToLower(first), strings.ToLower(last), i, g.pick(domains)),
		phone:  g.phone(),
		street: fmt.Sprintf("%s %d", g.pick(streets), 1+g.intn(180)),
		city:   p.city, postcode: p.postcode, country: p.country, region: p.region,
		company: g.pick(companies), ip: g.ip(), agent: g.pick(agents),
	}
}

// phone returns a number in the 555-0100..0199 range reserved for fiction.
func (g *gen) phone() string {
	area := []string{"202", "312", "415", "617"}[g.intn(4)]
	if g.chance(0.5) {
		return fmt.Sprintf("+1 %s-555-01%02d", area, g.intn(100))
	}
	return fmt.Sprintf("(%s) 555-01%02d", area, g.intn(100))
}

// ip returns an address from the documentation ranges (RFC 5737, RFC 3849).
func (g *gen) ip() string {
	switch g.intn(4) {
	case 0:
		return fmt.Sprintf("192.0.2.%d", 1+g.intn(254))
	case 1:
		return fmt.Sprintf("198.51.100.%d", 1+g.intn(254))
	case 2:
		return fmt.Sprintf("203.0.113.%d", 1+g.intn(254))
	}
	return fmt.Sprintf("2001:db8::%x", 1+g.intn(0xfffe))
}

func (g *gen) sentence(n int) string {
	w := make([]string, n)
	for i := range w {
		w[i] = g.pick(words)
	}
	s := strings.Join(w, " ")
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

// cardNumber returns a Luhn-valid Visa number that is not a published test
// card.
func (g *gen) cardNumber() string {
	d := "4" + g.chars("0123456789", 14)
	for c := byte('0'); c <= '9'; c++ {
		s := d + string(c)
		sum, double := 0, false
		for i := len(s) - 1; i >= 0; i-- {
			n := int(s[i] - '0')
			if double {
				if n *= 2; n > 9 {
					n -= 9
				}
			}
			sum += n
			double = !double
		}
		if sum%10 == 0 {
			return s
		}
	}
	return d + "0"
}

func (g *gen) phpass() string   { return "$P$B" + g.chars(cryptChars, 30) }
func (g *gen) bcrypt() string   { return "$2y$10$" + g.chars(cryptChars, 53) }
func (g *gen) wpBcrypt() string { return "$wp$2y$10$" + g.chars(cryptChars, 53) }

// Secret-looking values, assembled from pieces at run time.
func (g *gen) stripeKey(mode string) string { return "sk_" + mode + "_" + g.alnum(24) }
func (g *gen) sendgridKey() string          { return "SG" + "." + g.alnum(22) + "." + g.alnum(43) }
func (g *gen) awsKeyID() string             { return "AK" + "IA" + g.chars(upperChars, 16) }

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// magentoEncrypted looks like a value encrypted with Magento's crypt key.
func (g *gen) magentoEncrypted() string {
	return "0:3:" + base64.StdEncoding.EncodeToString([]byte(g.alnum(36)))
}

func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
