package detect

import (
	"strings"
	"testing"
	"time"
)

// goDSNCounted returns Go driver DSNs with no scheme whose password counts.
func goDSNCounted(pw string) []string {
	dsn := "app:" + pw
	return []string{
		dsn + "@tcp(db:3306)/shop",
		dsn + "@tcp(db.internal.shop:3306)/shop?parseTime=true",
		dsn + "@tcp(127.0.0.1:3306)/",
		dsn + "@tcp(localhost)/shop",
		dsn + "@tcp([2001:db8::5]:3306)/shop",
		dsn + "@tcp()/shop",
		dsn + "@tcp4(db:3306)/shop",
		dsn + "@tcp6([2001:db8::5]:3306)/shop",
		dsn + "@unix(/run/mysqld.sock)/shop",
		dsn + "@unix(/cloudsql/project:region:instance)/shop",
		// No network named, which only its bracket says.
		dsn + "@(db:3306)/shop",
		dsn + "@([2001:db8::5]:3306)/",
		// Cut short, by the characters the scan reads or by a column.
		dsn + "@tcp(db:33",
		dsn + "@tcp(",
		dsn + "@unix(/run/my",
		// No user, and a user with an @.
		":" + pw + "@tcp(db:3306)/shop",
		"jane@corp.gr:" + pw + "@tcp(db:3306)/shop",
		// What may come before one.
		"DSN=" + dsn + "@tcp(db:3306)/shop",
		"--mysql_uri=" + dsn + "@tcp(db:3306)/shop",
		"dsn: " + dsn + "@tcp(db:3306)/shop",
		`{"dsn":"` + dsn + `@tcp(db:3306)\/shop"}`,
		`s:44:"` + dsn + `@tcp(db:3306)/shop";`,
		"'" + dsn + "@tcp(db:3306)/shop'",
		"`" + dsn + "@tcp(db:3306)/shop`",
		"Open(" + dsn + "@tcp(db:3306)/shop)",
		"https://shop.fixture.gr/cart " + dsn + "@tcp(db:3306)/shop",
		"https://shop.fixture.gr/x?dsn=" + dsn + "@tcp(db:3306)/shop",
		"https://shop.fixture.gr:8443/x," + dsn + "@tcp(db:3306)/shop",
		"<td>" + dsn + "@tcp(db:3306)/shop</td>",
		// A colon far before it doesn't make its password too long to count, or a
		// label before that a label for it.
		"§created´2024-01-02T12:30:45Z¤tagsÙ" + strings.Repeat("x", 128) + "£dsnÙ." + dsn + "@tcp(db:3306)/shop",
		"a:b;" + strings.Repeat("k=v;", 33) + "dsn=" + dsn + "@tcp(db:3306)/shop",
		"https://shop.fixture.gr:8443/" + strings.Repeat("x", 130) + "," + dsn + "@tcp(db:3306)/shop",
		// What comes after one.
		dsn + "@tcp(db:3306)/shop,ops@example.com",
		dsn + "@tcp(db:3306)/shop?loc=ops@example.com",
		// A password may hold what a URL's can't, up to the last @ before the
		// network.
		"app:a/" + pw + "@tcp(db:3306)/shop",
		"app:a?" + pw + "@tcp(db:3306)/shop",
		"app:a#" + pw + "@tcp(db:3306)/shop",
		"app:a:" + pw + "@tcp(db:3306)/shop",
		"app:" + pw + ":p@tcp(db:3306)/shop",
		"app:" + pw + ":@tcp(db:3306)/shop",
		"app:" + pw + ":pass@tcp(db:3306)/shop",
		"app:" + pw + ":{x@tcp(db:3306)/shop",
		"app:" + pw + ":12,ab@tcp(db:3306)/shop",
		// A label before it isn't its user.
		"mysql:app:" + pw + "@tcp(db:3306)/shop",
		"dsn:app:" + pw + "@tcp(db:3306)/shop",
		"dsnmaster:" + pw + "@tcp(db:3306)/shop",
		// A driver's name can be a user's.
		"mysql:" + pw + "@tcp(db:3306)/shop",
		"mariadb:" + pw + "@tcp(db:3306)/shop",
		// Digits and another sort of punctuation are a password's.
		"app:12!" + pw + "@tcp(db:3306)/shop",
		"app:12-" + pw + "@tcp(db:3306)/shop",
		"app:a@" + pw + "@tcp(db:3306)/shop",
		"app:a(" + pw + ")@tcp(db:3306)/shop",
		"app:a=" + pw + "&b;c,d@tcp(db:3306)/shop",
		"app:/" + pw + "@tcp(db:3306)/shop",
		"app:a<" + pw + "@tcp(db:3306)/shop",
		"app:a>" + pw + "@tcp(db:3306)/shop",
		"app:a" + `\` + pw + "@tcp(db:3306)/shop",
		"app:a>b:" + pw + "@tcp(db:3306)/shop",
		// A name that only looks reserved, and a network that isn't one, whose
		// name the driver gets from the application.
		dsn + "@tcp(db.test_env:3306)/shop",
		dsn + "@tcp(db.example.com.shop.lan)/shop",
		"mysql://" + dsn + "@mydial(db.example.com:3306)/shop",
	}
}

// goDSNExamples returns DSNs that hold a password the scan doesn't count, for a
// copy to clear.
func goDSNExamples(pw string) []string {
	dsn := "app:" + pw
	return []string{
		"user:password@tcp(127.0.0.1:3306)/db",
		"user:pass@tcp(host:3306)/dbname?tls=true",
		"id:password@unix(/cloudsql/project:region:instance)/db",
		"%s:%s@tcp(%s:%d)/%s",
		"%s:%s@unix(%s)/%s?timeout=30s",
		"${DB_USER}:${DB_PASSWORD}@tcp(${DB_HOST}:3306)/${DB_NAME}",
		"{user}:{password}@tcp({host})/{db}",
		"(user):(password)@tcp(host)/db",
		"<user>:<password>@tcp(<host>:3306)/db",
		"[user]:[password]@tcp([host]:3306)/db",
		"root:" + "\xe2\x80\xa6" + "@tcp(127.0.0.1:3306)/",
		"trillian:" + `\$(MYSQL_PASSWORD)` + "@tcp(${MYSQL_IP}:3306)/trillian",
		// A password equal to its user.
		"root:root@tcp(db:3306)/shop",
		"Root:rOOT@tcp(db:3306)/shop",
		"DSN=root:root@tcp(db:3306)/shop",
		"x;root:root@tcp(db:3306)/shop",
		"'root:root@tcp(db:3306)/shop'",
		"`root:root@tcp(db:3306)/shop`",
		"Open(root:root@tcp(db:3306)/shop)",
		"<td>root:root@tcp(db:3306)/shop</td>",
		"x:root:root@tcp(db:3306)/shop",
		// What follows a scheme's colon isn't a password.
		"app:ab://" + pw + "@tcp(db:3306)/shop",
		"Format:user:password@tcp(host:3306)/dbname",
		"dsn:user:password@tcp(host:3306)/dbname",
		"mysql:app1:password@tcp(host:3306)/dbname",
		// Text before a DSN with no password, which a copy clears with the rest.
		"dsn:root@tcp(db:3306)/shop",
		"DB_DSN:root@tcp(db:3306)/shop",
		"mydsn:root@tcp(db:3306)/shop",
		"db-dsn:" + pw + "@tcp(db:3306)/shop",
		"Dsn:root@tcp(db:3306)/shop",
		"{DataSourceName:root@tcp(db:3306)/shop}",
		"map[datasource:root@tcp(db:3306)/shop]",
		"dsn:mysql://root@tcp(db:3306)/shop",
		"{Driver:mysql DSN:root@tcp(db:3306)/shop MaxOpen:10}",
		"{MasterDSN:root@tcp(db:3306)/shop}",
		"{Driver:mysql Source:root@tcp(db:3306)/shop}",
		"url:root@tcp(db:3306)/shop",
		"uri:root@tcp(db:3306)/shop",
		"link:root@tcp(db:3306)/shop",
		"<td>db:3306</td><td>root@tcp(db:3306)/shop</td>",
		"12:30:45.123|root@tcp(db:3306)/shop",
		"a:3306,b:4306,root@tcp(db:3306)/shop",
		"docker:1.25/x,root@tcp(db:3306)/shop",
		"map[dsn:root@unix(/run/mysqld.sock)/shop]",
		"host=db:3306;dsn=root@tcp(db:3306)/shop",
		"12:30:45,root@tcp(db:3306)/shop",
		"https://shop.fixture.gr:8443/x?dsn=root@tcp(db:3306)/shop",
		// A label before a DSN, whose password is what's after the last colon.
		"mysql:root:@tcp(127.0.0.1:3306)/test",
		"mysql:user:password@tcp(127.0.0.1:3306)/test",
		"mysql:root:root@tcp(127.0.0.1:3306)/test",
		// A host reserved for examples.
		dsn + "@tcp(db.example.com:3306)/shop",
		dsn + "@tcp(db.example.com)/shop",
		dsn + "@tcp(shop.test:3306)/shop",
		dsn + "@tcp4(x.invalid:3306)/shop",
		dsn + "@(db.example.com:3306)/shop",
		"mysql://" + dsn + "@(db.example.com:3306)/shop",
		"mysql://" + dsn + "@tcp(db.example.com:3306)/shop",
		"app:Admin@123@tcp(db.example.com:3306)/shop",
	}
}

// goDSNNoPassword returns text close to a DSN that has no password.
func goDSNNoPassword() []string {
	var out []string
	for _, stop := range strings.Split("\t\n\f\r \"'`", "") {
		out = append(out, "host:3306"+stop+"root@tcp(db:3306)/shop", "aZ7aZ8:aZ7aZ8"+stop+"root@tcp(db:3306)/shop")
	}
	return append(out,
		"root@tcp(db:3306)/shop",
		"root:@tcp(db:3306)/shop",
		"root@unix(/run/mysqld.sock)/shop",
		"@tcp(db:3306)/shop",
		"tcp(db:3306)/shop",
		"dsn: root@tcp(db:3306)/shop",
		`{"dsn":"root@tcp(db:3306)/shop"}`,
		"{dsn:'root@tcp(db:3306)/shop'}",
		"{dsn:`root@tcp(db:3306)/shop`}",
		`"app:"+pw+"@tcp(db:3306)/shop"`,
		"a b:c d@tcp(db:3306)/shop",
		// Other words after the @.
		"aZ7aZ8:aZ7aZ8aZ9aZ0@tcp",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@tcp/shop",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@tcp5(db:3306)/shop",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@tcpx(db:3306)/shop",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@mytcp(db:3306)/shop",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@TCP(db:3306)/shop",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@unixx(/run/x)/shop",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@deprecated(reason)",
		// A bracket with no network, not closed before a slash.
		"aZ7aZ8:aZ7aZ8aZ9aZ0@(db:3306)",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@(db:3306",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@(db:3306),x",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@(a@b)/x",
		"note:see aZ7aZ8@(below)/x",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@()/x",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@(db)/x",
		"aZ7aZ8:aZ7aZ8aZ9aZ0@(:)/x",
		"SKU:123@(2.50)/pc",
		"Author:J.Smith@(MIT)/Harvard",
		"Meet 12:30@(office)/home",
		"C:/Photos@(2019)/x.jpg",
		"lint:src/@(a|b)/**",
		"background:url(@(Model.BaseUrl)/hero.png)",
	)
}

// TestPlaceholderOneCharacter checks that a password of one character repeated
// reads as an example past ASCII too, as an ellipsis or a form's dots do, and
// that two characters, or bytes that aren't text, don't.
func TestPlaceholderOneCharacter(t *testing.T) {
	for _, pw := range []string{"\xe2\x80\xa6", "\xe2\x80\xa6\xe2\x80\xa6", "\xe2\x80\xa2\xe2\x80\xa2\xe2\x80\xa2", "\xce\xb1\xce\xb1", "\xff\xff", "aAaA", "***"} {
		if !placeholder(pw) {
			t.Errorf("%q: not a placeholder", pw)
		}
		v := appURL + pw + "@db.internal.shop/x"
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 1 || sp[0].Detail != "placeholder" {
			t.Errorf("%q: spans %+v", v, sp)
		}
	}
	for _, pw := range []string{"\xce\xb1\xce\xb2", "\xe2\x80\xa6x", "x\xe2\x80\xa6", "\xff\xfe", "\xce\xb1\xce", "ab"} {
		if placeholder(pw) {
			t.Errorf("%q: a placeholder", pw)
		}
	}
}

// urlSchemeCounted returns URLs under the schemes that no earlier version read.
func urlSchemeCounted(pw string) []string {
	var out []string
	for _, scheme := range []string{"MYSQL", "Mysql", "mySQL", "HTTP", "my_sql", "pdo_mysql", "MY_SQL", "a_b", "mysql_connector", "abcdefghij_klmno", "ABCDEFGHIJKLMNOP"} {
		out = append(out, scheme+"://app:"+pw+"@db.internal.shop/x", "dsn "+scheme+"://:"+pw+"@db/x")
	}
	return out
}

// urlLongUsers returns URLs whose user is longer than any earlier version read.
func urlLongUsers(pw string) []string {
	// The longest user that may hold anything, as a short one may, in characters.
	out := []string{
		"mysql://" + strings.Repeat("u", 63) + ",:" + pw + "@db.internal.shop/x",
		"mysql://" + strings.Repeat("\xce\xb1", 33) + ",b:" + pw + "@db.internal.shop/x",
	}
	for _, n := range []int{65, 129, 300, 5000} {
		out = append(out, "mysql://"+strings.Repeat("u", n)+":"+pw+"@db.internal.shop/x")
	}
	return append(out, "mysql://long-service-account-name@long-project-name-123456.iam.gserviceaccount.com:"+pw+"@db.internal.shop/x",
		"amqp://"+strings.Repeat("aB3+", 16)+"==:"+pw+"@db.internal.shop/x")
}

// urlStopsCounted returns URLs whose password holds a stop.
func urlStopsCounted(pw string) []string {
	var out []string
	for _, stop := range strings.Split(passwordStops, "") {
		a := "ab" + stop + pw
		out = append(out,
			appURL+a+"@db/x",
			appURL+a+"@db:3306/x",
			appURL+a+"@db.internal.shop:3306/x",
			appURL+a+"@db.test_env/x",
			appURL+a+"@[2001:db8::5]:3306/x",
			appURL+a+"@/x",
			appURL+a+"@",
			appURL+a+"@${DB_HOST}/x",
			appURL+a+"@tcp(db:3306)/x",
			appURL+a+"@db/x?mail=ops@example.com",
			appURL+a+"@db:3306,ops@example.com/x",
			"redis://:"+a+"@cache:6379",
			"mysql+pymysql://app:"+a+"@db/x",
			"MY_SQL://app:"+a+"@db/x",
			"dsn "+appURL+a+"@db/x",
			appURL+"12a"+stop+pw+"@db/x",
			appURL+"12!"+stop+pw+"@db/x",
			appURL+"portal"+stop+pw+"@db/x",
			"smtp://jane@corp.gr:"+a+"@db/x",
			"smtp://jane%40corp.gr:"+a+"@db/x",
			"mysql://admin@myserver:"+a+"@db/x",
			"mysql://admin%40myserver:"+a+"@db/x",
			appURL+"!a"+stop+pw+"@db/x",
			appURL+"(a"+stop+pw+"@db/x",
		)
	}
	return append(out,
		appURL+"a/b/c/"+pw+"@db/x",
		appURL+"a/b?c#"+pw+"@db/x",
		appURL+"a'b/c?"+pw+"@db/x",
		appURL+"a/b@"+pw+"@db/x",
		appURL+"Ab3/+x="+pw+"@db/x",
		// A web link or a repository's URL may hold a quote.
		"https://app:ab'"+pw+"@shop.fixture.gr/x",
		"git+ssh://app:ab'"+pw+"@git.fixture-host.gr/x",
		`{"dsn":"mysql:\/\/`+`app:ab\/`+pw+`@db\/x"}`,
		`{"dsn":"mysql:\/\/`+`app:ab?`+pw+`@db\/x"}`,
		"it's "+appURL+"ab/"+pw+"@db/x",
	)
}

// urlStopsExamples returns URLs whose password holds a stop and reads as an
// example, for a copy to clear.
func urlStopsExamples(pw string) []string {
	return []string{
		appURL + "$P/" + pw + "@db/x",
		appURL + "{p}/" + pw + "@db/x",
		appURL + "%P%/" + pw + "@db/x",
		appURL + "ab/" + pw + "@db.example.com/x",
		appURL + "ab/" + pw + "@shop.test",
		appURL + "ab/" + pw + "@db.example.com,ops@example.org",
		"mysql://ab%2Fcd:ab/cd@db/x",
		"mysql://AB%3Fcd:ab?CD@db/x",
		appURL + "ab/" + strings.Repeat("aZ7", 43) + "@db/x",
	}
}

// urlStopsRefused returns text with a stop before an @ that holds no password
// the finder takes: it reads as a URL followed by text.
func urlStopsRefused(pw string) []string {
	out := []string{
		// A port.
		"http://shop:8080/u@acme-widgets.gr",
		appURL + "'" + pw + "'@db/x",
		// A user that's a host.
		"mysql://first.last:ab/" + pw + "@db/x",
		"rsync://mirror.corp.gr:module/pkg@1.2.tar",
		"webdav://files.corp.gr:share/jane@acme-widgets.gr",
		"oci://ghcr.io:org/chart@1.2.3",
		"docker://registry.corp.gr:org/app@sha256:ab12ab12",
		"jdbc:mysql://db.corp.gr:shop/x?user=jane@corp.gr",
		"smtp://mail.acme-widgets.gr:submission?from=jane@acme-widgets.gr",
		// A version isn't a password's start.
		"docker://nginx:1.25/app@sha256:ab12ab12",
		// A /, ? or # in a web link or a repository's URL, whatever its case.
		"http://foo:" + pw + "/u@acme-widgets.gr",
		"http://foo:" + pw + "?email=jane@acme-widgets.gr",
		"https://foo:" + pw + "#jane@acme-widgets.gr",
		"HTTPS://foo:" + pw + "/u@acme-widgets.gr",
		"wss://foo:" + pw + "/u@acme-widgets.gr",
		"http://localhost:xxxx/api/users?email=jane@acme-widgets.gr",
		"http://localhost:your_port/api/users?email=jane@acme-widgets.gr",
		"https://git.fixture-host.gr:org/repo.git@v1.2",
		"git+ssh://git@git.fixture-host.gr:org/repo.git@v1.2",
		"git+ssh://gitlab:org/repo.git@v1.2",
		"git+https://gitlab:org/repo.git@v1.2",
		"ssh://git@gitlab:org/repo.git@main",
		"svn+ssh://server:repo/trunk@1234",
		"bzr+ssh://server:repo/trunk@1234",
		"scp://server:backup/db@2024.tar",
		"rsync://server:module/pkg@1.2.tar",
		"hg+https://server:repo/x@tip",
		"sftp://server:upload/jane@acme-widgets.gr/file.txt",
		"ftp://server:upload/jane@acme-widgets.gr",
		"file://server:share/jane@acme-widgets.gr",
		"https://shop.fixture.gr:" + pw + "/u@acme-widgets.gr",
		"https://social:" + pw + "/@jane",
		// A colon.
		"at://did:plc:asdf123/com.atproto.feed.p@st",
		"http://[2001:db8::5]/?to=jane@mail.fixture.gr",
		"https://[2001:db8::5]:8443/u@acme-widgets.gr",
		"http://[::1]/x@acme-widgets.gr",
		appURL + "ab/c:" + pw + "@db/x",
		"http://foo:" + pw + ",https://shop.fixture.gr/u@acme-widgets.gr",
		"http://foo:" + pw + "/x,https://shop.fixture.gr/u@acme-widgets.gr",
		// Two quotes.
		"'http://foo:" + pw + "','jane@acme-widgets.gr'",
		"{'url':'http://foo:" + pw + "','email':'jane@acme-widgets.gr'}",
		appURL + "a'b'" + pw + "@db/x",
		// A stop right before the @.
		"npm://registry:" + pw + "/@scope/pkg@1.2",
		"'mysql://root:" + pw + "'@db/x",
		appURL + pw + "?@db/x",
		appURL + pw + "#@db/x",
		appURL + "ab/" + pw + "/@db/x",
		// Nowhere near a host.
		appURL + "ab/" + pw,
		appURL + "ab/" + pw + "/shop",
	}
	// A stop no password holds.
	for _, stop := range strings.Split("\t\n\f\r \"<>"+`\\`, "") {
		out = append(out, appURL+"ab/"+pw+stop+"x@db/y")
		out = append(out, appURL+"ab"+stop+"x/"+pw+"@db/y")
	}
	// A /, ? or # in each of the schemes that can't hold one.
	for _, scheme := range strings.Fields("http https ws wss ftp ftps sftp scp rsync smb nfs ssh git svn hg bzr cvs file git+ssh svn+https hg+http bzr+ssh") {
		for _, stop := range []string{"/", "?", "#"} {
			out = append(out, scheme+"://foo:"+pw+stop+"u@acme-widgets.gr")
		}
	}
	// A port, where the scheme alone doesn't refuse it.
	for _, port := range []string{"6379", "", "6379,", "6379;", "6379|", "6379&", "6379)", "6379:", "1.25", "6379<", "port", "PORT", "Port"} {
		out = append(out, "redis://cache:"+port+"/0@acme-widgets.gr", "redis://cache:"+port+"?owner=jane@acme-widgets.gr", "redis://cache:"+port+"#jane@acme-widgets.gr")
	}
	return out
}

// secretValues counts the values with a secret in a profile and its paths.
func secretValues(p *Profile) int {
	n := p.SecretValues
	for _, leaf := range p.Paths {
		n += secretValues(leaf)
	}
	return n
}

func TestFindSecretsURLForms(t *testing.T) {
	pw := newTokGen(71).mixed(tAlnum, 14)
	var counted []string
	counted = append(counted, goDSNCounted(pw)...)
	counted = append(counted, urlSchemeCounted(pw)...)
	counted = append(counted, urlLongUsers(pw)...)
	counted = append(counted, urlStopsCounted(pw)...)
	for _, v := range counted {
		if got := hitsString(FindSecrets(v)); got != "password in a URL (live)" {
			t.Errorf("%.100q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 1 || sp[0].Detail != "" || !strings.Contains(v[sp[0].Start:sp[0].End], pw) {
			t.Errorf("%.100q: spans %+v", v, sp)
		}
		if strings.Contains(leftOf(v), pw) {
			t.Errorf("%.100q: left %q", v, leftOf(v))
		}
		// The scan reads it too, as a cell or a leaf of one.
		profile := NewProfile()
		profile.Add(v)
		if got := secretValues(profile); got != 1 {
			t.Errorf("%.100q: %d values with a secret in a column's profile", v, got)
		}
	}
	for _, v := range append(goDSNExamples(pw), urlStopsExamples(pw)...) {
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 1 || sp[0].Detail != "placeholder" {
			t.Errorf("%q: spans %+v", v, sp)
		}
	}
	// Only a plain word between two colons is a user after a label.
	if got := hitsString(FindSecrets("app:ab,cd:pass" + "@tcp(db:3306)/shop")); got != "password in a URL (live)" {
		t.Errorf("punctuation between two colons: got [%s]", got)
	}
	// A shell's escaped variable is a template only in a DSN.
	if got := hitsString(FindSecrets("Authorization: Basic " + b64(`deploy:\$`+pw))); got != "password in a Basic Authorization header (live)" {
		t.Errorf("an escaped dollar in a Basic credential: got [%s]", got)
	}
	// Digits alone are a password, as in a URL.
	if got := hitsString(FindSecrets("app:12345678" + "@tcp(db:3306)/shop")); got != "password in a URL (live)" {
		t.Errorf("digits alone: got [%s]", got)
	}
	// A port or a time, then another field, is text before a DSN.
	for _, field := range strings.Split(",;/?&|).<"+`\\`, "") {
		v := "a:3306" + field + "admin@tcp(db:3306)/shop"
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 1 || sp[0].Detail != "placeholder" {
			t.Errorf("%q: spans %+v", v, sp)
		}
	}
	// So is one before an escape of a stop, in text the scan reads as it is.
	if got := hitsString(FindSecrets(`DB_HOST=db:3306\nDB_DSN=root@tcp(db:3306)/shop`)); got != "" {
		t.Errorf("an escaped newline: got [%s]", got)
	}
	// What can come before a DSN isn't its user's.
	for _, before := range strings.Split("=,;&?/([{|<>"+`\\`, "") {
		v := "x" + before + "admin:admin@tcp(db:3306)/shop"
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%q: got [%s]", v, got)
		}
	}
	none := append(goDSNNoPassword(), urlStopsRefused(pw)...)
	none = append(none,
		// Still no URL: a scheme too long, or none at a word's start.
		"abcdefghij_klmnop://app:"+pw+"@db.internal.shop/x",
		"ABCDEFGHIJKLMNOPQ://app:"+pw+"@db.internal.shop/x",
		"_mysql://app:"+pw+"@db.internal.shop/x",
		"1mysql://app:"+pw+"@db.internal.shop/x",
	)
	none = append(none, "mysql://"+strings.Repeat("u", 64)+",:"+pw+"@db.internal.shop/x")
	// A long row of fields isn't a user, though its first colon is in a time.
	for _, d := range strings.Split(",;|&~^ ", "") {
		fields := "shop.fixture.gr" + d + "1001" + d + "Jane" + d + "Doe" + d + "Main-St-12" + d + "Athens" + d + "GR" + d + "Attica" + d + "12345" + d
		none = append(none, "https://"+fields+"2024-01-02T12:30:45"+d+"jane@acme-widgets.gr")
	}
	for _, v := range none {
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 0 {
			t.Errorf("%q: spans %+v", v, sp)
		}
		// The finder itself gives no span, empty or not.
		if loc := (urlPasswords{}).FindAllStringSubmatchIndex(v, -1); len(loc) != 0 {
			t.Errorf("%q: the finder's matches %v", v, loc)
		}
	}
}

// TestSpanGoDSN checks what a DSN's span covers: from the first colon to the @
// before the network. What comes before the DSN may go with it, and no part of
// the password is left.
func TestSpanGoDSN(t *testing.T) {
	pw := newTokGen(72).mixed(tAlnum, 14)
	checkSpans(t, SpanURLPassword, map[string][]string{
		"app:" + pw + "@tcp(db:3306)/shop":                                    {pw},
		"app:" + pw + "@unix(/run/mysqld.sock)/shop":                          {pw},
		":" + pw + "@tcp(db:3306)/shop":                                       {pw},
		"DSN=app:" + pw + "@tcp(db:3306)/shop":                                {pw},
		`{"dsn":"app:` + pw + `@tcp(db:3306)\/shop"}`:                         {pw},
		"app:a/" + pw + "@tcp(db:3306)/shop":                                  {"a/" + pw},
		"app:a:" + pw + "@tcp(db:3306)/shop":                                  {"a:" + pw},
		"app:a@" + pw + "@tcp(db:3306)/shop":                                  {"a@" + pw},
		"app:ab://" + pw + "@tcp(db:3306)/shop":                               {"ab://" + pw},
		"app:" + pw + "@tcp(db:3306)/shop,ops@acme-widgets.gr":                {pw},
		"mysql://app:" + pw + "@tcp(db:3306)/shop":                            {pw},
		"dsn:app:" + pw + "@tcp(db:3306)/shop":                                {"app:" + pw},
		"dsn:root@tcp(db:3306)/shop":                                          {"root"},
		"12:30:45,root@tcp(db:3306)/shop":                                     {"30:45,root"},
		"app:ab>cd:" + pw + "@tcp(db:3306)/shop":                              {"ab>cd:" + pw},
		"<td>app:" + pw + "@tcp(db:3306)/shop</td>":                           {pw},
		"app:" + pw + "@(db:3306)/shop":                                       {pw},
		"mysql://app:" + pw + "@(db:3306)/shop":                               {pw},
		"https://shop.fixture.gr/x?dsn=app:" + pw + "@tcp(db)/x":              {pw},
		"https://shop.fixture.gr:8443/x,app:" + pw + "@tcp(db)/x":             {"8443/x,app:" + pw},
		"https://jane:" + pw + "@shop.fixture.gr/x,app@tcp(db)/x":             {pw},
		"a:" + pw + "@tcp(h:3306)/d,b:" + pw + "x@tcp(h2:3306)/e":             {pw, pw + "x"},
		"a:" + pw + "@tcp(h:3306)/d,mysql://b:" + pw + "x@h2:3306":            {pw, pw + "x"},
		"mysql://b:" + pw + "x@h2/d,a:" + pw + "@tcp(h:3306)":                 {pw + "x", pw},
		"mysql://b:" + pw + "x@h2:3306/d,a:" + pw + "@tcp(h:3306)":            {pw + "x", "3306/d,a:" + pw},
		"https://jane:" + pw + "@shop.fixture.gr,app:a/" + pw + "x@tcp(db)/x": {pw, "a/" + pw + "x"},
		// A cut-short address ends at a stop, so the next line's DSN is read.
		"root@tcp(db" + "\n" + "app:a)" + pw + "@tcp(h)/x": {"a)" + pw},
		// A bracket that makes no DSN may be a password's.
		"app:a@(b)c" + pw + "@tcp(db:3306)/shop": {"a@(b)c" + pw},
		// An address cut short may hold what the next DSN's password starts with.
		"root@tcp(db:3306,b:" + pw + "@tcp(h2)/e":     {"3306,b:" + pw},
		"a:" + pw + "@tcp(h:3306)/d b@tcp(h2:3306)/e": {pw},
	})
	checkSpans(t, SpanEmail, map[string][]string{
		"jane@corp.gr:" + pw + "@tcp(db:3306)/shop":            {"jane@corp.gr"},
		"app:" + pw + "@tcp(db:3306)/shop,ops@acme-widgets.gr": {"ops@acme-widgets.gr"},
	})
	// A URL after a DSN's network is still read, however the network reads.
	for _, v := range []string{
		"@unix(mysql://app:" + pw + "@db/x",
		"@tcp(mysql://app:" + pw + "@db/x)/y",
		"x@tcp(mysql://app:" + pw + "@db/x)/y",
	} {
		if sp := urlPasswordSpans(v); len(sp) != 1 || v[sp[0].Start:sp[0].End] != pw {
			t.Errorf("%q: spans %+v", v, sp)
		}
	}
	// A real backslash is a password's, in a value or a JSON string. A TextView reads
	// an escape as the stop it stands for, as the driver wouldn't, so the scan counts
	// what a copy leaves, and the column is flagged all the same.
	for _, c := range []struct{ in, span string }{
		{`app:a\\n` + pw + `@tcp(db:3306)/shop`, `a\\n` + pw},
		{`{"dsn":"app:a\\n` + pw + `@tcp(db:3306)/shop"}`, `a\\n` + pw},
		{`app:a\n` + pw + `@tcp(db:3306)/shop`, ""},
		{`app:a\t` + pw + `@tcp(db:3306)/shop`, ""},
	} {
		if got := hitsString(FindSecrets(c.in)); got != "password in a URL (live)" {
			t.Errorf("%q: got [%s]", c.in, got)
		}
		got := ""
		for _, sp := range urlPasswordSpans(c.in) {
			got = c.in[sp.Start:sp.End]
		}
		if got != c.span {
			t.Errorf("%q: span %q, want %q", c.in, got, c.span)
		}
	}
	// Past the scan's cap of 8, the span finder goes on.
	v := strings.Repeat("app:"+pw+"@tcp(db)/x ", 12)
	if sp := urlPasswordSpans(v); len(sp) != 12 {
		t.Errorf("twelve DSNs: %d spans", len(sp))
	}
	if n := len(urlPasswords{}.FindAllStringSubmatchIndex(v, 8)); n != 8 {
		t.Errorf("twelve DSNs, capped at 8: %d matches", n)
	}
}

// TestURLFormsLongValues checks that a value made of what the finder looks for
// can't slow a scan or a copy.
func TestURLFormsLongValues(t *testing.T) {
	const size = 1 << 17
	for _, part := range []string{
		"x:y@tcp(", "@tcp(", "x@tcp(y)", "@unix(", "@(", "@(y)/", "x:y@(y)/", "x:y@tcp(y)/z,", "ab://b:c@tcp(", "ab://b:c/", "ab://b:c'",
		"ab://b:c/d" + "@", "ab://", "://", ":", "@", "a:", "'", "/",
	} {
		v := strings.Repeat(part, size/len(part))
		for _, value := range []string{v, "ab://b:" + v, "a:b" + v + "@tcp(", v + "@", v + " @", v + "@tcp("} {
			start := time.Now()
			FindSecrets(value)
			FindSpans(value, SpanFinders()[:2])
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("%q, %d bytes: took %v", part, len(value), d)
			}
		}
	}
}

// TestSpanURLStops checks what the span of a password that holds a stop covers:
// up to the last @ of the part of the URL that the first @ is in, stopping before
// an address after it, as with any password.
func TestSpanURLStops(t *testing.T) {
	pw := newTokGen(74).mixed(tAlnum, 14)
	checkSpans(t, SpanURLPassword, map[string][]string{
		appURL + "ab/" + pw + "@db/x":                                  {"ab/" + pw},
		appURL + "ab?" + pw + "@db/x":                                  {"ab?" + pw},
		appURL + "ab#" + pw + "@db/x":                                  {"ab#" + pw},
		appURL + "ab'" + pw + "@db/x":                                  {"ab'" + pw},
		appURL + "a/b/c/" + pw + "@db:3306/x":                          {"a/b/c/" + pw},
		appURL + "a/b@" + pw + "@db/x":                                 {"a/b@" + pw},
		appURL + "ab/" + pw + "@db/x?mail=ops@acme-widgets.gr":         {"ab/" + pw},
		appURL + "ab/" + pw + "@db:3306,ops@acme-widgets.gr/x":         {"ab/" + pw + "@db:3306"},
		appURL + "ab/" + pw + "@db/x," + appURL + "cd/" + pw + "@e/y":  {"ab/" + pw, "cd/" + pw},
		appURL + pw + "@db/x," + appURL + "cd/" + pw + "@e/y":          {pw, "cd/" + pw},
		"http://shop:8080/u," + appURL + "cd/" + pw + "@e/y":           {"cd/" + pw},
		"https://shop.fixture.gr:ab/u," + appURL + "cd/" + pw + "@e/y": {"cd/" + pw},
		`{"dsn":"mysql:\/\/app:ab\/` + pw + `@db\/x"}`:                 {`ab\/` + pw},
		// An @ before the first stop ends the URL at its host, so what's past the
		// stop is a path, however it reads.
		appURL + "ab@cd/" + pw + "@db/x":             {"ab"},
		appURL + "ab@cd?" + pw + "@db/x":             {"ab"},
		"smtp://jane@corp.gr:ab/" + pw + "@db/x":     {"ab/" + pw},
		"smtp://jane%40corp.gr:ab/" + pw + "@db/x":   {"ab/" + pw},
		"mysql://jane%40corp:ab/" + pw + "@db:3306/": {"ab/" + pw},
		appURL + "$P/" + pw + "@db/x":                {"$P/" + pw},
		// A refused reading doesn't hide a DSN's.
		appURL + "ab:cd/" + pw + "@tcp(db:3306)/x": {"ab:cd/" + pw},
	})
	checkSpans(t, SpanEmail, map[string][]string{
		appURL + "ab/" + pw + "@db/x?mail=ops@acme-widgets.gr":   {"ops@acme-widgets.gr"},
		appURL + "ab/" + pw + "@db:3306,ops@acme-widgets.gr/x":   {"ops@acme-widgets.gr"},
		"http://shop:8080/u@acme-widgets.gr":                     {"u@acme-widgets.gr"},
		"https://git.fixture-host.gr:org/jane@acme-widgets.gr":   {"jane@acme-widgets.gr"},
		"at://did:plc:asdf123/jane@acme-widgets.gr":              {"jane@acme-widgets.gr"},
		"https://shop.fixture.gr:8443/x?to=jane@acme-widgets.gr": {"jane@acme-widgets.gr"},
	})
	// An escaped @ ends a URL for a TextView, so it ends the scan's reading too, and
	// the scan doesn't count what a copy leaves.
	for _, v := range []string{
		appURL + "ab?%40" + pw + "@db/x",
		appURL + "ab%40cd/" + pw + "@db/x",
		appURL + "ab/%40" + pw + "@db/x",
	} {
		if got := hitsString(FindSecrets(v)); got != "" {
			t.Errorf("%q: got [%s]", v, got)
		}
	}
	checkSpans(t, SpanURLPassword, map[string][]string{
		appURL + "ab?%40" + pw + "@db/x":   nil,
		appURL + "ab%40cd/" + pw + "@db/x": {"ab"},
		appURL + "ab/%40" + pw + "@db/x":   nil,
	})
	// In the user it's only a user's.
	for _, v := range []string{"mysql://admin%40myserver:ab/" + pw + "@db/x", "mysql://admin@myserver:ab/" + pw + "@db/x"} {
		if got := hitsString(FindSecrets(v)); got != "password in a URL (live)" {
			t.Errorf("%q: got [%s]", v, got)
		}
		if sp := urlPasswordSpans(v); len(sp) != 1 || v[sp[0].Start:sp[0].End] != "ab/"+pw {
			t.Errorf("%q: spans %+v", v, sp)
		}
	}
	// A password's escapes are read before it's judged, as in any URL.
	if got := hitsString(FindSecrets(appURL + "%24P/" + pw + "@db/x")); got != "" {
		t.Errorf("an escaped template: got [%s]", got)
	}
	// The longest password is counted in characters, past ASCII too.
	greek := strings.Repeat("\xce\xb1\xce\xb2", 64)
	if got := hitsString(FindSecrets(appURL + "ab/" + greek[:250] + "@db/x")); got != "password in a URL (live)" {
		t.Errorf("a long password: got [%s]", got)
	}
	if got := hitsString(FindSecrets(appURL + "ab/" + greek + "\xce\xb1\xce\xb2@db/x")); got != "" {
		t.Errorf("a password too long: got [%s]", got)
	}
}

// TestGeneratedPasswords checks passwords as a generator makes them, with the
// punctuation it may use, in the shapes that can hold it: all of it is cleared,
// and the scan counts it.
func TestGeneratedPasswords(t *testing.T) {
	g := newTokGen(75)
	const dsnSet, urlSet = tAlnum + "!#$%&()*+,-./:;<=>?@[]^_{|}~", tAlnum + "!#$%&()*+,-./;=?[]^_{|}~"
	for range 20000 {
		pw := g.of(dsnSet, 8+g.r.IntN(25))
		if strings.Contains(pw, "@(") || strings.HasPrefix(pw, "//") {
			continue // what may read as this DSN's own end, or as a URL
		}
		v := "app:" + pw + "@tcp(db:3306)/shop"
		if left := leftOf(v); left != "app:@tcp(db:3306)/shop" {
			t.Fatalf("%q: left %q", v, left)
		}
		if strings.IndexByte(pw, ':') < 0 && strings.Trim(pw[:1], "{<$%[0123456789") != "" {
			if got := hitsString(FindSecrets(v)); got != "password in a URL (live)" {
				t.Fatalf("%q: got [%s]", v, got)
			}
		}
		pw = "aZ7" + g.of(urlSet, 8+g.r.IntN(25)) + "x"
		if strings.Contains(pw, "%40") {
			continue // an @ before the first stop ends a URL, however it's written
		}
		v = appURL + pw + "@db.internal.shop:3306/x"
		if left := leftOf(v); left != appURL+"@db.internal.shop:3306/x" {
			t.Fatalf("%q: left %q", v, left)
		}
		if got := hitsString(FindSecrets(v)); got != "password in a URL (live)" {
			t.Fatalf("%q: got [%s]", v, got)
		}
	}
}

// TestSpanKeyInURLPassword checks that a known key inside a longer password
// doesn't hide the rest of it from a copy, and how the whole reads.
func TestSpanKeyInURLPassword(t *testing.T) {
	g := newTokGen(73)
	pw, other := g.mixed(tAlnum, 14), g.mixed(tAlnum, 14)
	live, test := "sk_"+"live_"+g.of(tAlnum, 24), "sk_"+"test_"+g.of(tAlnum, 24)
	gh := "gh" + "p_" + g.of(tAlnum, 36)
	labelled := "acme_" + "live_api" + "key_" + g.mixed(tAlnum, 24)
	const stripe, url = "Stripe secret key", urlPasswordKind
	for _, c := range []struct{ in, span, detail, mode string }{
		{"smtp://jane@corp.gr:" + pw + "," + live + "@db.internal.shop:587", pw + "," + live, stripe, "live"},
		{"mysql://app:" + live + "," + pw + "@db.internal.shop/x", live + "," + pw, stripe, "live"},
		{"mysql://app:" + pw + "," + live + "," + other + "@db/x", pw + "," + live + "," + other, stripe, "live"},
		{"mysql://app:" + live + "," + gh + "@db/x", live + "," + gh, stripe, "live"},
		{"mysql://app:" + gh + "," + live + "@db/x", gh + "," + live, stripe, "live"},
		{"app:" + pw + "," + live + "@tcp(db:3306)/shop", pw + "," + live, stripe, "live"},
		{"mysql://app:" + pw + "/" + live + "@db/x", pw + "/" + live, stripe, "live"},
		{`{"dsn":"mysql:\/\/app:` + pw + "," + live + `@db\/x"}`, pw + "," + live, stripe, "live"},
		// A test key beside more of a password may be beside what works.
		{"mysql://app:" + pw + "," + test + "@db/x", pw + "," + test, stripe, "live"},
		{"mysql://app:" + test + "," + pw + "@db/x", test + "," + pw, stripe, "live"},
		{"mysql://app:$" + pw + "," + test + "@db.internal.shop/x", "$" + pw + "," + test, stripe, "live"},
		{"mysql://app:" + test + "," + strings.Repeat("aZ7", 43) + "@db.internal.shop/x", test + "," + strings.Repeat("aZ7", 43), stripe, "live"},
		// No credential works at a host reserved for examples, so it reads as the key.
		{"mysql://app:" + test + "," + pw + "@db.example.com/x", test + "," + pw, stripe, "test"},
		{"mysql://app:" + live + "," + pw + "@db.example.com/x", live + "," + pw, stripe, "live"},
		// A fallback's key has no name of its own to give the whole.
		{"mysql://app:" + pw + "," + labelled + "@db/x", pw + "," + labelled, url, "live"},
		// A key that is the whole password keeps its name and its mode.
		{"mysql://app:" + live + "@db/x", live, stripe, "live"},
		{"mysql://app:" + test + "@db/x", test, stripe, "test"},
		{"app:" + test + "@tcp(db:3306)/shop", test, stripe, "test"},
	} {
		sp := FindSpans(c.in, SpanFinders())
		if len(sp) != 1 && !strings.Contains(c.in, "jane@") || len(sp) == 0 {
			t.Errorf("%q: spans %+v", c.in, sp)
			continue
		}
		s := sp[len(sp)-1]
		if c.in[s.Start:s.End] != c.span || s.Kind != SpanSecret || s.Detail != c.detail || s.Mode != c.mode {
			t.Errorf("%q: span %q, %+v", c.in, c.in[s.Start:s.End], s)
		}
	}
	// The secret finder reads the same alone, for callers without FindSpans.
	v := "mysql://app:" + pw + "," + live + "@db/x"
	if got := findSecretSpans(NewTextView(v)); len(got) != 1 || v[got[0].Start:got[0].End] != pw+","+live {
		t.Errorf("the finder alone: %+v", got)
	}
	// A key beside the password, not in it, doesn't change either.
	v = "mysql://" + live + ":" + pw + "@db/x"
	if got := covered(v, FindSpans(v, SpanFinders())); strings.Join(got, " ") != SpanSecret+"="+live+" "+SpanURLPassword+"="+pw {
		t.Errorf("a key as the user: %q", got)
	}
	// A secret that runs past the password takes it whole, the user too.
	tg := "7" + g.of(tDigit, 9) + ":A" + "A" + g.of(tB64U, 33)
	v = "https://" + tg + "," + other + "@host.internal-shop.gr/x"
	if left := leftOf(v); strings.Contains(left, other) || strings.Contains(left, "A"+"A") {
		t.Errorf("a key across the colon: left %q", left)
	}
	// The scan's hits don't change: the key, and the password.
	if got := hitsString(FindSecrets("mysql://app:" + pw + "," + live + "@db/x")); got != "Stripe secret key (live), password in a URL (live)" {
		t.Errorf("the scan: got [%s]", got)
	}
}
