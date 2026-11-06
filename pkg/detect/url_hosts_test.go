package detect

import (
	"strings"
	"testing"
)

// The starts of the tests' URLs, kept apart from their passwords, so that no
// line here reads as a URL with a password.
const (
	appURL  = "mysql://" + "app:"
	shopURL = "https://shop.fixture.gr:"
)

// urlHostCounted returns URLs whose password counts, whatever surrounds its
// host: an IPv6 host or none, a later address at a reserved host, and a name
// that only looks reserved.
func urlHostCounted(pw string) []string {
	url := appURL + pw
	out := []string{
		// An IPv6 host, or none, as some socket URLs have it.
		url + "@[2001:db8::5]:3306/shop",
		url + "@[2001:db8::5]/shop",
		url + "@[::1]:3306/shop",
		url + "@[fe80::1%25eth0]:3306/shop",
		url + "@/shop",
		url + "@:3306/shop",
		url + "@?socket=/run/mysqld.sock",
		url + "@",
		"dsn " + url + "@ and more",
		"postgres://app:" + pw + "@%2Fvar%2Frun%2Fpostgresql/shop",
		`{"dsn":"mysql:\/\/app:` + pw + `@[2001:db8::5]:3306\/shop"}`,
		`{"dsn":"mysql:\/\/app:` + pw + `@\/shop"}`,
		url + "@tcp(127.0.0.1:3306)/shop",
		url + "@(localhost)/shop",
		// A template's host doesn't make its password an example.
		url + "@${DB_HOST}:3306/shop",
		url + "@<host>:3306/shop",
		url + "@{host}:3306/shop",
		url + "@$HOST/shop",
		url + "@%HOST%:3306/shop",
		// An @ may end the password at a real host, whatever a later or an earlier
		// @ is at, with or without a delimiter.
		url + "@db.internal.shop:3306,ops@example.com",
		"smtp://mailer:" + pw + "@mail.internal.shop:587;from=noreply@example.org",
		url + "@db.internal.shop@example.com",
		url + "@db.example.com@db.internal.shop",
		url + "@db.internal.shop:3306,ops@acme-widgets.gr",
		url + "@db.internal.shop:3306,ops@example.com,dev@example.org",
		url + "@db.internal.shop,db2.example.com:3306/shop",
		url + "@db,ops@example.com",
		url + "@db:3306,ops@example.com",
		url + "@db:587;from=noreply@example.org",
		appURL + "ab@cd.ef@db.example.com/shop",
		// Only a whole placeholder word in parentheses reads as an example.
		appURL + "(" + pw + ")@db.internal.shop/x",
		appURL + "($" + pw + ")@db.internal.shop/x",
		appURL + ")$" + pw + "@db.internal.shop/x",
		appURL + "secret)@db.internal.shop/x",
		appURL + "(password@db.internal.shop/x",
		appURL + "(passwordX@db.internal.shop/x",
		appURL + "xpassword)@db.internal.shop/x",
		// The longest scheme and user.
		"abcdefghijklmnop://app:" + pw + "@db.internal.shop/x",
		"mysql://" + strings.Repeat("u", 64) + ":" + pw + "@db.internal.shop/x",
		// Only a host and a port with nothing after the @ read as no password.
		appURL + "12345@/shop",
		shopURL + "8443@db.internal.shop/x",
		shopURL + "123456@/cart",
		shopURL + "ab12@/cart",
		// What only starts like a reserved host, or holds one after what DNS
		// doesn't allow.
		url + "@db.test_env:3306/shop",
		url + "@db.example.com_prod.lan/",
		url + "@db.example.com_prod.lan",
		url + "@db.test%2Fshop",
		url + "@db.test~1/shop",
		url + "@db.test\xc3\xa9/shop",
		url + "@db.test\xff/shop",
		url + "@db.test-env/shop",
		url + "@db.example.com.shop.lan/shop",
		url + "@notexample.com/shop",
		url + "@db.internal.shop%2Cdb2.example.com",
		url + "@db.internal.shop%40mail.example.com",
		url + "@db.internal.shop~db2.example.com:3306",
		url + "@db.internal.shop_svc.example.com",
		url + "@db.\xc4\xb0nvalid",
		url + "@db_1.example.com",
		// The next fields of a MessagePack value, after the URL in one.
		url + "@db.internal.shop\xa3cdn\xafsvc.example.com",
		url + "@db.internal.shop\xa4smtp\xa9mail.test",
		url + "@db.example.com\xa1n\x01",
	}
	for _, d := range strings.Split(",;|&=!*$^()[]{}:~`+-._%", "") {
		out = append(out, url+"@db.internal.shop:3306"+d+"ops@example.com", url+"@db.internal.shop"+d+"ops@example.com")
	}
	return out
}

// urlHostExamples returns URLs that hold a password the scan doesn't count,
// for a copy to clear: its host is reserved for examples, or it reads as an
// example itself, however the host reads.
func urlHostExamples(pw string) []string {
	url := appURL + pw
	out := []string{
		url + "@db.example.com:3306/shop",
		url + "@db.example.com/shop",
		"https://app:" + pw + "@EXAMPLE.ORG./x",
		"smtp://mailer:" + pw + "@mail.shop.invalid",
		url + "@shop.test",
		url + "@db.test:3306",
		url + "@x.example",
		"(" + url + "@db.test)",
		url + "@db.test,",
		url + "@db.test;x=1",
		url + "@db.example.com:587;from=noreply",
		url + "@db.example.com,db2.example.org:3306/shop",
		url + "@db.example.com,active",
		"dev," + url + "@db.example.com,active",
		url + "@db.example.com,ops@example.org",
		"smtp://mailer:" + pw + "@mail.example.com:587;from=noreply@example.org",
		url + "@db.test|ops@example.net",
		// Punctuation ends a host name.
		"\xe2\x80\x9c" + url + "@db.example.com\xe2\x80\x9d",
		url + "@db.example.com\xe2\x80\x93sample",
		url + "@db.example.com\xc2\xa0sample",
		url + "@db.example.com\xe2\x80\xa6",
		url + "@db.test+x",
		// A password that holds an @, at a reserved host.
		appURL + "Admin@123@db.example.com:3306/shop",
		appURL + "ab@cd@db.example.com/shop",
		appURL + "ab%40cd@db.example.com/shop",
		// Only the first host of a list is read.
		url + "@db.example.com,db2.internal.shop:3306/shop",
		// A password that reads as an example.
		appURL + "password@/shop",
		appURL + "$" + pw + "@[2001:db8::5]/shop",
		appURL + "{password}@",
		"mysql://root:root@/shop",
		"mysql://${user}:${pass}@${host}/${db}",
		appURL + "password@db.internal.shop:3306,ops@example.com",
		appURL + "$" + pw + "@db.internal.shop:3306,ops@acme-widgets.gr",
		"mysql://root:root@db.internal.shop,ops@example.com",
		"smtp://jane%40corp.gr:jane@corp.gr@mail.internal.shop:587",
		// A format's description, not a URL.
		"driver://[username[:password]@][protocol[(host[:port])]][/[schema|database][?options]]",
		"mysql://[user[:" + pw + "]@]host[:port]/db",
		"http://(user:" + pw + "@)shop.fixture.gr",
		"mysql://{user:" + pw + "@}host/db",
		"mysql://(user):(password)@(host)/db",
		"mysql://(user):(PassWord)@db.internal.shop/db",
		// A host and a port, with nothing after the @.
		shopURL + "8443@/cart",
		shopURL + "65535@/cart",
	}
	for _, d := range strings.Split(",;|&=", "") {
		out = append(out, url+"@db.example.com"+d+"ops@example.org")
	}
	return out
}

// urlNoPassword returns text that looks close to a URL with a password but
// has none.
func urlNoPassword() []string {
	return []string{
		"https://[2001:db8::5]:8443/cart",
		"https://[2001:db8::5]:8443/u@x",
		"ssh://git@[2001:db8::5]:22/shop.git",
		"http://[2001:db8::5]/?to=jane@mail.fixture.gr",
		shopURL + "8443/@jane",
		shopURL + "8443/cart@home",
		"http://shop.fixture.gr:8080/logo@2x.png",
		"http://shop.fixture.gr:80/",
		"http://jane@shop.fixture.gr/",
		"https://jane@mail.fixture.gr:8443/account",
		"ssh://git@git.fixture-host.gr:2222/shop.git",
		`"http://shop.fixture.gr:80" ops@acme-widgets.gr`,
		"http://shop.fixture.gr:80 ops@acme-widgets.gr",
		"see https://shop.fixture.gr:8443, or write to ops@acme-widgets.gr",
		"git+ssh://git@git.fixture-host.gr:shop/app.git@v1.2",
		"ftp://anonymous:@ftp.fixture-host.gr/x",
		// Past the longest scheme and user, and no URL at a word's start.
		"abcdefghijklmnopq://app:aZ7aZ8aZ9aZ0@db.internal.shop/x",
		"mysql://" + strings.Repeat("u", 65) + ":aZ7aZ8aZ9aZ0@db.internal.shop/x",
		"_mysql://app:aZ7aZ8aZ9aZ0@db.internal.shop/x",
	}
}

func urlPasswordSpans(v string) []Span {
	var out []Span
	for _, sp := range FindSpans(v, SpanFinders()) {
		if sp.Kind == SpanURLPassword {
			out = append(out, sp)
		}
	}
	return out
}

// leftOf returns what the built-in finders leave of a value.
func leftOf(v string) string {
	left, last := "", 0
	for _, sp := range FindSpans(v, SpanFinders()) {
		left += v[last:sp.Start]
		last = sp.End
	}
	return left + v[last:]
}

func TestFindSecretsURLHosts(t *testing.T) {
	pw := newTokGen(61).mixed(tAlnum, 14)
	for _, v := range urlHostCounted(pw) {
		if got := hitsString(FindSecrets(v)); got != "password in a URL (live)" {
			t.Errorf("%q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 1 || sp[0].Detail != "" || strings.Contains(v, pw) && !strings.Contains(v[sp[0].Start:sp[0].End], pw) {
			t.Errorf("%q: spans %+v", v, sp)
		}
	}
	for _, v := range urlHostExamples(pw) {
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 1 || sp[0].Detail != "placeholder" {
			t.Errorf("%q: spans %+v", v, sp)
		}
	}
	for _, v := range urlNoPassword() {
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 0 {
			t.Errorf("%q: spans %+v", v, sp)
		}
		// The finder itself gives no span, empty or not, for callers that use it
		// without FindSpans.
		for _, f := range SpanFinders() {
			if f.Kind == SpanURLPassword {
				if sp := f.Find(v); len(sp) != 0 {
					t.Errorf("%q: the finder's spans %+v", v, sp)
				}
			}
		}
	}
}

// TestFindSecretsURLEscapedAt checks that the scan doesn't read %40 as the @ that
// ends a password or starts a host, which it can't be in a real URL, though a
// TextView reads it as one for the span finder. A copy clears these either way.
func TestFindSecretsURLEscapedAt(t *testing.T) {
	pw := newTokGen(68).mixed(tAlnum, 14)
	for _, c := range []struct{ in, want, span string }{
		{"smtp://mailer:jane%40corp.gr@mail.example.com", "", "jane%40corp.gr"},
		{appURL + "ab%40cd.ef@db.example.com/shop", "", "ab%40cd.ef"},
		{appURL + pw + "@db%40example.com", "password in a URL (live)", pw + "@db"},
	} {
		if got := hitsString(FindSecrets(c.in)); got != c.want {
			t.Errorf("%q: got [%s]", c.in, got)
		}
		if sp := urlPasswordSpans(c.in); len(sp) != 1 || c.in[sp[0].Start:sp[0].End] != c.span {
			t.Errorf("%q: spans %+v", c.in, sp)
		}
	}
}

// TestURLStops checks that each byte that ends a URL's password does, and that
// the same ones end its user.
func TestURLStops(t *testing.T) {
	pw := newTokGen(67).mixed(tAlnum, 14)
	for i := 0; i < len(urlStops); i++ {
		v := appURL + pw + string(urlStops[i]) + "x@db.internal.shop/shop"
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 0 {
			t.Errorf("%q: spans %+v", v, sp)
		}
	}
	for c := byte(1); c < 0x80; c++ {
		if stops := strings.IndexByte(urlStops, c) >= 0; urlHead.MatchString("ab://u"+string(c)+"v:") == stops {
			t.Errorf("%q in a user: stops %t", c, !stops)
		}
	}
}

// TestFindSecretsURLPasswordLength checks that the longest password is counted
// in characters, and that past it a copy still clears the password, though it
// doesn't count, unless an earlier @ gives a reading that does.
func TestFindSecretsURLPasswordLength(t *testing.T) {
	pw := newTokGen(64).mixed(tAlnum, 14)
	long := strings.Repeat("aZ7", 43)
	greek := strings.Repeat("\xce\xb1\xce\xb2", 65)
	for _, c := range []string{long[:128], greek[:256]} {
		if got := hitsString(FindSecrets(appURL + c + "@db.internal.shop/shop")); got != "password in a URL (live)" {
			t.Errorf("%.20q: got [%s]", c, got)
		}
	}
	for _, c := range []string{long, greek[:258]} {
		v := appURL + c + "@db.internal.shop/shop"
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%.20q: got [%s]", c, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 1 || sp[0].Detail != "placeholder" || v[sp[0].Start:sp[0].End] != c {
			t.Errorf("%.20q: spans %+v", c, sp)
		}
	}
	v := appURL + pw + "@db.internal.shop:3306," + long + "@db/shop"
	if got := hitsString(FindSecrets(v)); got != "password in a URL (live)" {
		t.Errorf("a long password after a short reading: got [%s]", got)
	}
}

// TestSpanURLHosts checks where a password's span ends: at the last @ before
// the URL ends, or, past an earlier @, before an address the email finder takes.
func TestSpanURLHosts(t *testing.T) {
	g := newTokGen(62)
	pw := g.mixed(tAlnum, 14)
	url := appURL + pw
	checkSpans(t, SpanURLPassword, map[string][]string{
		url + "@[2001:db8::5]:3306/shop": {pw},
		url + "@/shop":                   {pw},
		url + "@":                        {pw},
		url + "@db.test_env:3306/shop":   {pw},
		url + "@db.internal.shop:3306":   {pw},
		// An address after the URL has its own span, at any host.
		url + "@db.internal.shop:3306,ops@acme-widgets.gr":                         {pw + "@db.internal.shop:3306"},
		url + "@db.internal.shop:3306,ops@example.com":                             {pw + "@db.internal.shop:3306"},
		url + "@db.internal.shop:3306,ops@acme-widgets.gr/shop":                    {pw + "@db.internal.shop:3306"},
		url + "@db.internal.shop:3306,ops@acme-widgets.gr;tz=UTC":                  {pw + "@db.internal.shop:3306"},
		url + "@db.internal.shop:3306,ops@acme-widgets.gr,dev@acme-widgets.gr":     {pw + "@db.internal.shop:3306"},
		url + "@db.internal.shop:3306,m\xc3\xbcller@acme-widgets.gr":               {pw + "@db.internal.shop:3306"},
		url + "@db.internal.shop:3306\xe2\x82\xacops@acme-widgets.gr":              {pw + "@db.internal.shop:3306"},
		"smtp://mailer:" + pw + "@mail.internal.shop:587;from=noreply@example.org": {pw + "@mail.internal.shop:587;from"},
		// Text between two addresses may be the password's, so it goes with the
		// first address, and the email finder has only the last.
		url + "@db.internal.shop:3306,ops@acme-widgets.gr;tz,dev@acme-widgets.gr": {pw + "@db.internal.shop:3306,ops@acme-widgets.gr;tz"},
		// So does what the email finder doesn't take as an address.
		url + "@db.internal.shop:3306,logo@cdn2x.png":     {pw + "@db.internal.shop:3306,logo"},
		url + "@db.internal.shop:3306,m\xc3\xbc@acme.gr":  {pw + "@db.internal.shop:3306,m\xc3\xbc"},
		url + "@db.internal.shop:3306,ops@db:3306/x":      {pw + "@db.internal.shop:3306,ops"},
		url + "@db.internal.shop:3306,@acme-widgets.gr/x": {pw + "@db.internal.shop:3306,"},
		// The first @ stays the password's, even in an address.
		url + ",ops@acme-widgets.gr,dev@acme-widgets.gr": {pw + ",ops@acme-widgets.gr"},
		// A password that holds an @ or a delimiter stays whole when what follows
		// isn't an address.
		appURL + "ab@" + pw + "@db/shop":               {"ab@" + pw},
		appURL + "ab@" + pw + "@db.internal-host.gr/x": {"ab@" + pw},
		appURL + "ab@" + pw + ",cd@db/shop":            {"ab@" + pw + ",cd"},
		appURL + "ab,cd@" + pw + "@db/shop":            {"ab,cd@" + pw},
		appURL + "ab@cd@" + pw + "@db/shop":            {"ab@cd@" + pw},
		appURL + "ab@cd@ef@" + pw + "@db":              {"ab@cd@ef@" + pw},
		appURL + pw + ",cd@db/shop":                    {pw + ",cd"},
		appURL + pw + ",cd@db:3306/shop":               {pw + ",cd"},
		appURL + "%40" + pw + "@db.internal-host.gr/x": {"%40" + pw},
		appURL + "ab%40" + pw + "@db.internal-host.gr": {"ab%40" + pw},
		appURL + pw + ",ops@acme-widgets.gr":           {pw + ",ops"},
		appURL + pw + ",ops%40acme-widgets.gr":         {pw + ",ops"},
		appURL + "pass!word@db.fixture.gr/shop":        {"pass!word"},
		appURL + "pass\xc2\xa3word@db.fixture.gr":      {"pass\xc2\xa3word"},
		appURL + "pa$$=w;o,r|d@db.fixture.gr:3306/x":   {"pa$$=w;o,r|d"},
		appURL + "12345@db.fixture.gr/shop":            {"12345"},
		appURL + "12345,ops@db.fixture.gr/shop":        {"12345,ops"},
		shopURL + "8443,ops@acme-widgets.gr":           {"8443,ops"},
	})
	checkSpans(t, SpanEmail, map[string][]string{
		url + "@db.internal.shop:3306,ops@acme-widgets.gr":                        {"ops@acme-widgets.gr"},
		url + "@db.internal.shop:3306,ops@example.com":                            {"ops@example.com"},
		url + "@db.internal.shop:3306,ops@acme-widgets.gr/shop":                   {"ops@acme-widgets.gr"},
		url + "@db.internal.shop:3306,ops@acme-widgets.gr,dev@acme-widgets.gr":    {"ops@acme-widgets.gr", "dev@acme-widgets.gr"},
		url + "@db.internal.shop:3306,ops@acme-widgets.gr;tz,dev@acme-widgets.gr": {"dev@acme-widgets.gr"},
		url + "@db.internal.shop:3306,m\xc3\xbcller@acme-widgets.gr":              {"m\xc3\xbcller@acme-widgets.gr"},
		url + "@db.internal.shop:3306\xe2\x82\xacops@acme-widgets.gr":             {"ops@acme-widgets.gr"},
		"smtp://mailer:" + pw + "@mail.internal.shop:587;from=noreply@acme.gr":    {"noreply@acme.gr"},
		url + "%40db.internal.shop:3306,ops%40acme-widgets.gr":                    {"ops%40acme-widgets.gr"},
		// With a single @, it's the password's, however like an address what
		// surrounds it reads.
		appURL + pw + ",ops@acme-widgets.gr":    nil,
		appURL + "pass!word@db.fixture.gr/shop": nil,
		shopURL + "8443,ops@acme-widgets.gr":    nil,
	})
}

// TestURLsInOneValue checks that one URL's password doesn't hide the next's,
// whatever joins them and however the first reads.
func TestURLsInOneValue(t *testing.T) {
	g := newTokGen(65)
	a, b, c := g.mixed(tAlnum, 14), g.mixed(tAlnum, 14), g.mixed(tAlnum, 14)
	for _, sep := range []string{",", ";", "|", "&", " ", ", ", "\n", "\x00", "\xc2\xa0"} {
		for _, f := range []struct {
			v       string
			spans   []string
			details []string
		}{
			{"https://u:" + a + "@es1:9200" + sep + "https://u:" + b + "@es2:9200", []string{a, b}, []string{"", ""}},
			{appURL + a + "@db1" + sep + appURL + b + "@db2/x", []string{a, b}, []string{"", ""}},
			{"redis://:" + a + "@h1:6379" + sep + "redis://:" + b + "@h2:6379", []string{a, b}, []string{"", ""}},
			{appURL + a + "@db1.internal.shop" + sep + appURL + b + "@db2.internal.shop/x", []string{a, b}, []string{"", ""}},
			{appURL + a + "@db1" + sep + appURL + b + "@db2" + sep + appURL + c + "@db3", []string{a, b, c}, []string{"", "", ""}},
			{appURL + "password@db1.internal.shop" + sep + appURL + b + "@db2/shop", []string{"password", b}, []string{"placeholder", ""}},
			{appURL + a + "@db.test" + sep + appURL + b + "@db2/x", []string{a, b}, []string{"placeholder", ""}},
			{appURL + a + "@db1" + sep + appURL + "password@db2/x", []string{a, "password"}, []string{"", "placeholder"}},
			// A URL with no password before one with, or between two.
			{"http://es1" + sep + "http://u:" + b + "@es2:9200", []string{b}, []string{""}},
			{"https://shop.fixture.gr" + sep + appURL + b + "@db2/x", []string{b}, []string{""}},
			{shopURL + "8443" + sep + appURL + b + "@db2/x", []string{b}, []string{""}},
			{"mysql://a:" + a + "@h" + sep + "https://x.gr" + sep + "mysql://b:" + b + "@h2/y", []string{a, b}, []string{"", ""}},
		} {
			sp := urlPasswordSpans(f.v)
			var spans, details []string
			for _, s := range sp {
				spans, details = append(spans, f.v[s.Start:s.End]), append(details, s.Detail)
			}
			if strings.Join(spans, "|") != strings.Join(f.spans, "|") || strings.Join(details, "|") != strings.Join(f.details, "|") {
				t.Errorf("%q: spans %q, details %q", f.v, spans, details)
			}
			if got := hitsString(FindSecrets(f.v)); got != "password in a URL (live)" {
				t.Errorf("%q: got [%s]", f.v, got)
			}
			if !strings.Contains(f.v, "password") && strings.Contains(leftOf(f.v), a) {
				t.Errorf("%q: left %q", f.v, leftOf(f.v))
			}
		}
	}
	// Past the scan's cap of 8, the span finder goes on.
	v := strings.Repeat(appURL+""+a+"@db,", 12)
	if sp := urlPasswordSpans(v); len(sp) != 12 {
		t.Errorf("twelve URLs: %d spans", len(sp))
	}
	if n := len(urlPasswords{}.FindAllStringSubmatchIndex(v, 8)); n != 8 {
		t.Errorf("twelve URLs, capped at 8: %d matches", n)
	}
}

// TestSpanURLPasswordNotLeft checks that the spans leave no part of a password
// that holds an @ or a delimiter in the text, whichever way it reads: what the
// password's span doesn't take, the email finder does.
func TestSpanURLPasswordNotLeft(t *testing.T) {
	g := newTokGen(63)
	a, b, c := g.mixed(tAlnum, 12), g.mixed(tAlnum, 12), g.mixed(tAlnum, 12)
	for _, v := range []string{
		appURL + a + "@" + b + "@db.internal-host.gr/shop",
		appURL + a + "@" + b + "," + c + "@db.internal-host.gr/shop",
		appURL + a + "@" + b + "," + c + "@db/shop",
		appURL + a + "," + b + "@db.internal-host.gr/shop",
		appURL + a + "," + b + "@db/shop",
		appURL + a + "," + b + "@" + c + "@db/shop",
		appURL + a + "%40" + b + "," + c + "@db.internal-host.gr:3306/shop",
		appURL + a + ";" + b + "=" + c + "@db.internal-host.gr/shop",
		appURL + a + "!" + b + "@db.internal-host.gr/shop",
		appURL + a + "@" + b + "@[2001:db8::5]:3306/shop",
		appURL + a + "," + b + "@[2001:db8::5]:3306/shop",
		appURL + a + "," + b + "@/shop",
		// Text between addresses, and what the email finder refuses.
		appURL + a + "@cd,x@y.zz!" + b + ",u@db.internal.shop/x",
		appURL + "12345!" + b + "@cache.zip/x",
		appURL + "12345!" + b + "\xc3\xa9@db.internal.shop/x",
		appURL + "P%40ss," + b + "@db.acme.zip/x",
		appURL + "123," + b + "@db.acme.zip/x",
		appURL + "Ab@Cd," + b + "\xc3\xbc@db.internal.shop/x",
		appURL + "Ab%40Cd,Ef%40gh.ij!" + b + ",Kl@db.internal.shop:3306/x",
		"smtp://jane@corp-mail.gr:" + "Ab@Cd," + b + "@db.acme.zip:587",
	} {
		left := leftOf(v)
		for _, part := range []string{a, b, c} {
			if strings.Contains(left, part) {
				t.Errorf("%q: left %q", v, left)
			}
		}
	}
	// The same, for passwords made at random of what the cases above hold.
	seps := []string{"@", "@", "@", ",", ";", "|", "!", "=", "&", "~", "$", "(", ")", ":", "+", "\xc2\xa0", "\xe2\x82\xac", "%40"}
	ends := []string{"", "", ".gr", ".fixture.gr", ".zip", "\xc3\xbc", "_x", "%41"}
	hosts := []string{"db", "db.internal-host.gr", "db.acme.zip", "db.example.com", "[2001:db8::5]:3306", "", "db.test_env:3306"}
	for range 5000 {
		var pw strings.Builder
		var parts []string
		for n := 1 + g.r.IntN(5); n > 0; n-- {
			part := g.mixed(tAlnum, 10)
			parts = append(parts, part)
			pw.WriteString(part + ends[g.r.IntN(len(ends))])
			if n > 1 {
				pw.WriteString(seps[g.r.IntN(len(seps))])
			}
		}
		v := appURL + pw.String() + "@" + hosts[g.r.IntN(len(hosts))] + "/shop"
		left := leftOf(v)
		for _, part := range parts {
			if strings.Contains(left, part) {
				t.Fatalf("%q: left %q", v, left)
			}
		}
	}
}
