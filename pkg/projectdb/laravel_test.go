package projectdb

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// laravelCanary marks every value in the .env files below. No refusal may
// hold it.
const laravelCanary = "Qz8"

// laravelBase is a .env readLaravel reads as laravelWant.
var laravelBase = []string{
	"DB_CONNECTION=mysql",
	"DB_HOST=db-Qz8.example.test",
	"DB_PORT=3307",
	"DB_DATABASE=shop_Qz8",
	"DB_USERNAME=user_Qz8",
	"DB_PASSWORD=pw-Qz8",
}

var laravelWant = settings{user: "user_Qz8", password: "pw-Qz8", database: "shop_Qz8", host: "db-Qz8.example.test", port: 3307}

// laravelSet gives a key's new line in laravelEnv, or "" to drop it.
type laravelSet = map[string]string

// laravelEnv is laravelBase with the lines of the keys in set replaced, and
// more lines after it.
func laravelEnv(set laravelSet, more ...string) string {
	var lines []string
	for _, line := range laravelBase {
		key, _, _ := strings.Cut(line, "=")
		if repl, ok := set[key]; ok {
			if repl == "" {
				continue
			}
			line = repl
		}
		lines = append(lines, line)
	}
	return laravelFile(append(lines, more...)...)
}

// laravelSameKeys are separate keys naming the database
// mysql://url_Qz8:urlpw_Qz8@url-Qz8.example.test:3308/urlshop_Qz8 names, with
// the DB_PASSWORD line given.
func laravelSameKeys(password string) laravelSet {
	return laravelSet{
		"DB_HOST": "DB_HOST=url-Qz8.example.test", "DB_PORT": "DB_PORT=3308", "DB_DATABASE": "DB_DATABASE=urlshop_Qz8",
		"DB_USERNAME": "DB_USERNAME=url_Qz8", "DB_PASSWORD": password,
	}
}

// laravelFile ends each line with "\n".
func laravelFile(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

// laravelRefusalText checks that err is a refusal whose text is in Messages
// and holds no canary, and returns the text.
func laravelRefusalText(t *testing.T, name string, err error) string {
	t.Helper()
	var refusal *Error
	if !errors.As(err, &refusal) {
		t.Fatalf("%s: not a refusal: %#v", name, err)
	}
	text := refusal.Error()
	if !slices.Contains(Messages(), text) {
		t.Errorf("%s: not in Messages: %q", name, text)
	}
	if strings.Contains(text, laravelCanary) {
		t.Errorf("%s: holds a value: %q", name, text)
	}
	return text
}

// TestReadLaravel checks what readLaravel reads: each value form phpdotenv
// and env() agree on, the socket winning, and URLs with their gaps filled.
func TestReadLaravel(t *testing.T) {
	with := func(change func(*settings)) settings {
		s := laravelWant
		change(&s)
		return s
	}
	socket := settings{user: "user_Qz8", password: "pw-Qz8", database: "shop_Qz8", socket: "/run/mysqld/mysqld-Qz8.sock"}
	const dbURL = "mysql://url_Qz8:urlpw_Qz8@url-Qz8.example.test:3308/urlshop_Qz8"
	fromURL := settings{user: "url_Qz8", password: "urlpw_Qz8", host: "url-Qz8.example.test", port: 3308, database: "urlshop_Qz8"}
	urlWith := func(change func(*settings)) settings {
		s := fromURL
		change(&s)
		return s
	}
	// urls sets both URL keys alike, which every config/database.php reads,
	// so the separate keys don't need to name the URL's database.
	urls := func(set laravelSet, url string, more ...string) string {
		return laravelEnv(set, append([]string{"DB_URL=" + url, "DATABASE_URL=" + url}, more...)...)
	}
	sameKeys := laravelSameKeys("DB_PASSWORD=urlpw_Qz8")
	for _, c := range []struct {
		name string
		env  string
		want settings
	}{
		{"plain values", laravelEnv(nil), laravelWant},
		{"mariadb", laravelEnv(laravelSet{"DB_CONNECTION": "DB_CONNECTION=mariadb"}), laravelWant},
		{"export", laravelEnv(laravelSet{
			"DB_HOST":     "export DB_HOST=db-Qz8.example.test",
			"DB_PORT":     "export\tDB_PORT=3307",
			"DB_DATABASE": "export \v DB_DATABASE=shop_Qz8",
		}), laravelWant},
		{"spaces around the key and =", laravelEnv(laravelSet{
			"DB_HOST": "  DB_HOST = db-Qz8.example.test",
			"DB_PORT": "\tDB_PORT\t=\t3307\t",
		}), laravelWant},
		{"single quotes, read literally", laravelEnv(laravelSet{"DB_PASSWORD": `DB_PASSWORD='p w#"$x${y}\z Qz8'`}),
			with(func(s *settings) { s.password = `p w#"$x${y}\z Qz8` })},
		{"double quotes", laravelEnv(laravelSet{"DB_PASSWORD": `DB_PASSWORD="p w#'$x Qz8"`}),
			with(func(s *settings) { s.password = `p w#'$x Qz8` })},
		{"comments after closing quotes", laravelEnv(laravelSet{
			"DB_HOST":     "DB_HOST='db-Qz8.example.test'#the primary",
			"DB_PASSWORD": `DB_PASSWORD="pw Qz8" # it's "quoted"`,
		}), with(func(s *settings) { s.password = "pw Qz8" })},
		{"comment and blank lines", laravelFile(
			"# DB_HOST=evil-Qz8", "", "   # indented", "\t",
			laravelEnv(nil), "#DB_PASSWORD=evil-Qz8",
		), laravelWant},
		{"no DB_PORT", laravelEnv(laravelSet{"DB_PORT": ""}), with(func(s *settings) { s.port = 0 })},
		{"a port with a leading zero", laravelEnv(laravelSet{"DB_PORT": "DB_PORT=03307"}), laravelWant},
		{"no DB_PASSWORD", laravelEnv(laravelSet{"DB_PASSWORD": ""}), with(func(s *settings) { s.password = "" })},
		{"an empty password", laravelEnv(laravelSet{"DB_PASSWORD": "DB_PASSWORD="}), with(func(s *settings) { s.password = "" })},
		{"an empty password in double quotes", laravelEnv(laravelSet{"DB_PASSWORD": `DB_PASSWORD=""`}),
			with(func(s *settings) { s.password = "" })},
		{"an empty password in single quotes", laravelEnv(laravelSet{"DB_PASSWORD": `DB_PASSWORD=''`}),
			with(func(s *settings) { s.password = "" })},
		{"an empty host, which is localhost", laravelEnv(laravelSet{"DB_HOST": "DB_HOST="}), with(func(s *settings) { s.host = "" })},
		{"a value quoted on one side", laravelEnv(laravelSet{"DB_PASSWORD": `DB_PASSWORD='"pw-Qz8'`}),
			with(func(s *settings) { s.password = `"pw-Qz8` })},
		{"UTF-8 in a value", laravelEnv(laravelSet{"DB_PASSWORD": "DB_PASSWORD=\"p\xc3\xa4ss-Qz8\""}),
			with(func(s *settings) { s.password = "p\xc3\xa4ss-Qz8" })},
		{"a semicolon in the user and password, which PDO gets apart", laravelEnv(laravelSet{
			"DB_USERNAME": `DB_USERNAME="user;Qz8"`,
			"DB_PASSWORD": `DB_PASSWORD="pw;Qz8"`,
		}), with(func(s *settings) { s.user, s.password = "user;Qz8", "pw;Qz8" })},
		{"the socket wins", laravelEnv(nil, "DB_SOCKET=/run/mysqld/mysqld-Qz8.sock"), socket},
		{"a socket and no host or port", laravelEnv(laravelSet{"DB_HOST": "", "DB_PORT": ""}, "DB_SOCKET=/run/mysqld/mysqld-Qz8.sock"), socket},
		{"a socket beside a port that isn't one", laravelEnv(laravelSet{"DB_PORT": "DB_PORT=none-Qz8"}, "DB_SOCKET=/run/mysqld/mysqld-Qz8.sock"), socket},
		{"an empty socket", laravelEnv(nil, "DB_SOCKET="), laravelWant},
		{"a socket of 0, which PHP's empty() takes as none", laravelEnv(nil, "DB_SOCKET=0"), laravelWant},
		{"an empty MYSQL_ATTR_SSL_CA", laravelEnv(nil, "MYSQL_ATTR_SSL_CA=", `MYSQL_ATTR_SSL_CA=""`, "export MYSQL_ATTR_SSL_CA"), laravelWant},
		{"other keys in any shape", laravelEnv(nil,
			"APP_NAME=My Shop Qz8",
			"APP_KEY=base64:"+strings.Repeat("Qz8x", 11),
			`MAIL_FROM_NAME="${APP_NAME}"`,
			"BROKEN LINE Qz8",
			"=Qz8",
			`"QUOTED"=Qz8`,
			"export",
			"X='unclosed Qz8",
			"db_host=evil-Qz8",
			"DB_HOSTS=evil-Qz8",
			"MYSQL_ATTR_SSL_KEY=/etc/ssl/key-Qz8.pem",
		), laravelWant},
		{"a multi-line value on another key hides the lines in it", laravelEnv(nil,
			`PRIVATE_KEY="-----BEGIN Qz8`, "DB_HOST=evil-Qz8", "DB_PASSWORD=evil-Qz8", `-----END Qz8"`,
		), laravelWant},
		{"a lone quote closes a multi-line value", `CERT="Qz8` + "\nDB_HOST=evil-Qz8\n\"\n" + laravelEnv(nil), laravelWant},
		{"a quote in a comment before other keys", laravelEnv(nil, `# APP_NAME="Shop Qz8`, "APP_DEBUG=true", `MAIL_FROM_NAME="Qz8"`), laravelWant},
		{"an unclosed value on another key after the database's", laravelEnv(nil, `APP_NAME="Shop Qz8`), laravelWant},
		{"lone CR line ends", strings.Join(laravelBase, "\r"), laravelWant},

		{"a URL's parts win", urls(nil, dbURL), fromURL},
		{"URLs in quotes", laravelEnv(nil, `DB_URL="`+dbURL+`"`, `DATABASE_URL='`+dbURL+`'`), fromURL},
		{"a URL takes DB_PORT", urls(nil, "mysql://url_Qz8:urlpw_Qz8@url-Qz8.example.test/urlshop_Qz8"),
			urlWith(func(s *settings) { s.port = 3307 })},
		{"a URL with an empty port takes DB_PORT", urls(nil, "mysql://url_Qz8:urlpw_Qz8@url-Qz8.example.test:/urlshop_Qz8"),
			urlWith(func(s *settings) { s.port = 3307 })},
		{"a URL with no port and no DB_PORT", urls(laravelSet{"DB_PORT": ""}, "mysql://url_Qz8:urlpw_Qz8@url-Qz8.example.test/urlshop_Qz8"),
			urlWith(func(s *settings) { s.port = 0 })},
		{"a URL takes DB_PASSWORD", urls(nil, "mysql://url_Qz8@url-Qz8.example.test:3308/urlshop_Qz8"),
			urlWith(func(s *settings) { s.password = "pw-Qz8" })},
		{"a URL's empty password wins", urls(nil, "mysql://url_Qz8:@url-Qz8.example.test:3308/urlshop_Qz8"),
			urlWith(func(s *settings) { s.password = "" })},
		{"DB_URL alone, when the separate keys name the same database", laravelEnv(sameKeys, "DB_URL="+dbURL), fromURL},
		{"DATABASE_URL alone, when the separate keys name the same database", laravelEnv(sameKeys, "DATABASE_URL="+dbURL), fromURL},
		{"DB_URL alone, naming what a config/database.php from before Laravel 11 defaults to",
			laravelFile("DB_CONNECTION=mysql", "DB_URL=mysql://forge@127.0.0.1/forge"),
			settings{user: "forge", host: "127.0.0.1", database: "forge"}},
		{"DATABASE_URL alone, naming what one from Laravel 11 on defaults to",
			laravelFile("DB_CONNECTION=mysql", "DATABASE_URL=mysql://root@127.0.0.1:3306/laravel"),
			settings{user: "root", host: "127.0.0.1", port: 3306, database: "laravel"}},
		{"an empty DB_URL", laravelEnv(nil, "DB_URL="), laravelWant},
		{"empty URLs", laravelEnv(nil, "DB_URL=", "DATABASE_URL="), laravelWant},
		{"a URL beside an empty socket", urls(nil, dbURL, "DB_SOCKET="), fromURL},
		{"a URL beside a socket of 0", urls(nil, dbURL, "DB_SOCKET=0"), fromURL},
		{"a mariadb URL", urls(nil, "mariadb://url_Qz8:urlpw_Qz8@url-Qz8.example.test:3308/urlshop_Qz8"), fromURL},
		{"a URL with a fragment", urls(nil, `"`+dbURL+`#Qz8"`), fromURL},
		{"escapes in a URL", urls(nil, "mysql://url%40Qz8:pw%3Aw%2Fd@url-Qz8.example.test:3308/shop%2DQz8"),
			urlWith(func(s *settings) { s.user, s.password, s.database = "url@Qz8", "pw:w/d", "shop-Qz8" })},
		{"an IPv6 host", urls(nil, "mysql://url_Qz8:urlpw_Qz8@[::1]:3308/urlshop_Qz8"),
			urlWith(func(s *settings) { s.host = "::1" })},
		{"a password that is a whole number, which json_decode gives back alike", urls(nil, "mysql://url_Qz8:123456@url-Qz8.example.test:3308/urlshop_Qz8"),
			urlWith(func(s *settings) { s.password = "123456" })},
		{"URLs with no other key", laravelFile("DB_CONNECTION=mysql",
			"DB_URL=mysql://url_Qz8:urlpw_Qz8@url-Qz8.example.test/urlshop_Qz8", "DATABASE_URL=mysql://url_Qz8:urlpw_Qz8@url-Qz8.example.test/urlshop_Qz8"),
			urlWith(func(s *settings) { s.port = 0 })},
	} {
		s, err := readLaravel([]byte(c.env))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		} else if *s != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, *s, c.want)
		}
	}
}

// TestLaravelRefusals checks each refusal's exact text, that it's in
// Messages, and that it holds no value from the file.
func TestLaravelRefusals(t *testing.T) {
	const (
		missing     = "isn't set"
		empty       = "is empty"
		twice       = "is set twice"
		form        = "isn't in a form prodmask reads (it isn't shown)"
		notMySQL    = "isn't mysql or mariadb"
		expands     = "uses ${...}, which prodmask doesn't expand"
		backslash   = "holds a backslash inside double quotes"
		lines       = "runs over several lines"
		rewrites    = "is one of Laravel's special words, or quoted twice, which env() rewrites"
		notPort     = "isn't a port number"
		noUser      = "names no user"
		noDatabase  = "names no database"
		differs     = "differs from the other URL"
		oldURL      = "doesn't match the separate keys, which a config/database.php from Laravel 11 on reads in its place"
		newURL      = "doesn't match the separate keys, which a config/database.php from before Laravel 11 reads in its place"
		besideSock  = "is set beside DB_SOCKET"
		options     = "has options after ?, which Laravel reads as its own settings"
		noParse     = "doesn't parse"
		notUTF8     = "isn't valid UTF-8, which phpdotenv rewrites"
		json        = "has a user, password or host that Laravel decodes as JSON"
		semicolon   = "holds a semicolon, which PDO reads as a separator"
		tls         = ".env asks for TLS settings prodmask doesn't read; pass --dsn with ?tls=true instead"
		versions    = "can't read the database from .env: phpdotenv versions differ on where a quoted value in it ends; pass --dsn instead"
		urlParts    = "url_Qz8:urlpw_Qz8@url-Qz8.example.test"
		urlDatabase = "/urlshop_Qz8"
	)
	key := func(key, reason string) string {
		return "can't read the database from .env: " + key + " " + reason + "; pass --dsn instead"
	}
	unquoted := func(key string) string {
		return "can't read the database from .env: " + key + " holds #, whitespace or a quote outside quotes; quote it, or pass --dsn"
	}
	password := func(line string) string { return laravelEnv(laravelSet{"DB_PASSWORD": line}) }
	port := func(line string) string { return laravelEnv(laravelSet{"DB_PORT": line}) }
	dbURL := func(url string) string { return laravelEnv(nil, "DB_URL="+url) }
	noHost := func(more ...string) string { return laravelEnv(laravelSet{"DB_HOST": ""}, more...) }
	cases := []struct {
		name, env, want string
	}{
		{"no DB_CONNECTION", laravelEnv(laravelSet{"DB_CONNECTION": ""}), key("DB_CONNECTION", missing)},
		{"DB_CONNECTION in a comment", laravelEnv(laravelSet{"DB_CONNECTION": "# DB_CONNECTION=mysql"}), key("DB_CONNECTION", missing)},
		{"sqlite", laravelEnv(laravelSet{"DB_CONNECTION": "DB_CONNECTION=sqlite"}), key("DB_CONNECTION", notMySQL)},
		{"mysql in capitals", laravelEnv(laravelSet{"DB_CONNECTION": "DB_CONNECTION=MySQL"}), key("DB_CONNECTION", notMySQL)},
		{"an empty DB_CONNECTION", laravelEnv(laravelSet{"DB_CONNECTION": "DB_CONNECTION="}), key("DB_CONNECTION", notMySQL)},
		{"DB_CONNECTION twice", laravelEnv(nil, "DB_CONNECTION=mysql"), key("DB_CONNECTION", twice)},
		{"another database before a bad key", laravelEnv(laravelSet{
			"DB_CONNECTION": "DB_CONNECTION=pgsql", "DB_PASSWORD": "DB_PASSWORD=pw Qz8",
		}), key("DB_CONNECTION", notMySQL)},
		{"DB_CONNECTION's form before an earlier bad key", laravelFile(
			"DB_HOST=db Qz8", "DB_CONNECTION=mysql # Qz8", "DB_DATABASE=shop_Qz8", "DB_USERNAME=user_Qz8",
		), unquoted("DB_CONNECTION")},
		{"the first bad key in the file", laravelEnv(laravelSet{
			"DB_HOST": "DB_HOST=db Qz8", "DB_PASSWORD": "DB_PASSWORD=pw Qz8",
		}), unquoted("DB_HOST")},
		{"a bad form before a missing key", laravelEnv(laravelSet{
			"DB_DATABASE": "", "DB_PASSWORD": "DB_PASSWORD=pw Qz8",
		}), unquoted("DB_PASSWORD")},

		{"no DB_DATABASE", laravelEnv(laravelSet{"DB_DATABASE": ""}), key("DB_DATABASE", missing)},
		{"an empty DB_DATABASE", laravelEnv(laravelSet{"DB_DATABASE": "DB_DATABASE="}), key("DB_DATABASE", empty)},
		{"an empty quoted DB_DATABASE", laravelEnv(laravelSet{"DB_DATABASE": `DB_DATABASE=""`}), key("DB_DATABASE", empty)},
		{"no DB_USERNAME", laravelEnv(laravelSet{"DB_USERNAME": ""}), key("DB_USERNAME", missing)},
		{"an empty DB_USERNAME", laravelEnv(laravelSet{"DB_USERNAME": "DB_USERNAME=''"}), key("DB_USERNAME", empty)},
		{"no DB_HOST", noHost(), key("DB_HOST", missing)},
		{"no DB_HOST and an empty socket", noHost("DB_SOCKET="), key("DB_HOST", missing)},
		{"no DB_HOST and a socket of 0", noHost("DB_SOCKET=0"), key("DB_HOST", missing)},

		{"port 0", port("DB_PORT=0"), key("DB_PORT", notPort)},
		{"port 65536", port("DB_PORT=65536"), key("DB_PORT", notPort)},
		{"a six-digit port", port("DB_PORT=003307"), key("DB_PORT", notPort)},
		{"a port with a sign", port("DB_PORT=+3307"), key("DB_PORT", notPort)},
		{"a negative port", port("DB_PORT=-1"), key("DB_PORT", notPort)},
		{"a port with a fraction", port("DB_PORT=3307.0"), key("DB_PORT", notPort)},
		{"a port in hex", port("DB_PORT=0xCEB"), key("DB_PORT", notPort)},
		{"a port that's a word", port("DB_PORT=port-Qz8"), key("DB_PORT", notPort)},
		{"an empty port", port("DB_PORT="), key("DB_PORT", notPort)},
		{"a port with a space in quotes", port(`DB_PORT=" 3307"`), key("DB_PORT", notPort)},

		{"an unquoted space", password("DB_PASSWORD=pw Qz8"), unquoted("DB_PASSWORD")},
		{"an unquoted tab", password("DB_PASSWORD=pw\tQz8"), unquoted("DB_PASSWORD")},
		{"an unquoted vertical tab", password("DB_PASSWORD=pw\vQz8"), unquoted("DB_PASSWORD")},
		{"an unquoted form feed", password("DB_PASSWORD=pw\fQz8"), unquoted("DB_PASSWORD")},
		{"a form feed after the value, which trim keeps", password("DB_PASSWORD=pw-Qz8\f"), unquoted("DB_PASSWORD")},
		{"an unquoted #", password("DB_PASSWORD=pw#Qz8"), unquoted("DB_PASSWORD")},
		{"a comment after an unquoted value", password("DB_PASSWORD=pw-Qz8 # Qz8"), unquoted("DB_PASSWORD")},
		{"an unquoted value that starts with #", password("DB_PASSWORD=#Qz8"), unquoted("DB_PASSWORD")},
		{"only a comment after =", password("DB_PASSWORD= # Qz8"), unquoted("DB_PASSWORD")},
		{"an unquoted single quote", password("DB_PASSWORD=it's-Qz8"), unquoted("DB_PASSWORD")},
		{"an unquoted double quote", laravelEnv(laravelSet{"DB_HOST": `DB_HOST=db"Qz8`}), unquoted("DB_HOST")},

		{"${ unquoted", password("DB_PASSWORD=${APP_KEY}Qz8"), key("DB_PASSWORD", expands)},
		{"${ in double quotes", password(`DB_PASSWORD="pw-${Qz8}"`), key("DB_PASSWORD", expands)},
		{"a lone ${ in double quotes", password(`DB_PASSWORD="pw-Qz8${"`), key("DB_PASSWORD", expands)},
		{`\n in double quotes`, password(`DB_PASSWORD="pw\nQz8"`), key("DB_PASSWORD", backslash)},
		{`\" in double quotes`, password(`DB_PASSWORD="pw\"Qz8"`), key("DB_PASSWORD", backslash)},
		{`\\ in double quotes`, password(`DB_PASSWORD="pw\\Qz8"`), key("DB_PASSWORD", backslash)},
		{"an escaped closing quote, so the value runs on", password(`DB_PASSWORD="pw-Qz8\"`), key("DB_PASSWORD", lines)},

		{"an unclosed single quote", password("DB_PASSWORD='pw-Qz8"), key("DB_PASSWORD", form)},
		{"an unclosed double quote after a space", password(`DB_PASSWORD= "pw-Qz8`), key("DB_PASSWORD", form)},
		{"text after a double-quoted value", password(`DB_PASSWORD="pw"Qz8`), key("DB_PASSWORD", form)},
		{"text after a single-quoted value", password("DB_PASSWORD='pw' Qz8"), key("DB_PASSWORD", form)},
		{"two single-quoted strings", password("DB_PASSWORD='pw''Qz8'"), key("DB_PASSWORD", form)},
		{"two double-quoted strings", password(`DB_PASSWORD="pw" "Qz8"`), key("DB_PASSWORD", form)},
		{"a double-quoted name", laravelEnv(laravelSet{"DB_HOST": `"DB_HOST"=db-Qz8.example.test`}), key("DB_HOST", form)},
		{"a single-quoted name", password("'DB_PASSWORD'=pw-Qz8"), key("DB_PASSWORD", form)},
		{"a name alone, which unsets it", password("DB_PASSWORD"), key("DB_PASSWORD", form)},
		{"export and a name alone", password("export DB_PASSWORD"), key("DB_PASSWORD", form)},
		{"a form feed after export, which phpdotenv before 5.6.4 keeps", password("export\fDB_PASSWORD=pw-Qz8"), key("DB_PASSWORD", form)},

		{"a double-quoted value over two lines", password("DB_PASSWORD=\"pw\nQz8\""), key("DB_PASSWORD", lines)},
		{`a single-quoted value with =", which phpdotenv runs on`, password(`DB_PASSWORD='pw="Qz8'`) + "APP_NAME=\"Shop\"\n", key("DB_PASSWORD", lines)},
		{"a double-quoted value open at the end", password(`DB_PASSWORD="pw-Qz8`), key("DB_PASSWORD", lines)},
		{"an unclosed value on another key swallows the lines after it", laravelFile(
			"DB_CONNECTION=mysql", "DB_HOST=db-Qz8.example.test", `APP_NAME="Shop Qz8`,
			"DB_DATABASE=shop_Qz8", "DB_USERNAME=user_Qz8", "DB_PASSWORD=pw-Qz8",
		), key("DB_DATABASE", missing)},

		{"true", password("DB_PASSWORD=true"), key("DB_PASSWORD", rewrites)},
		{"FALSE", password("DB_PASSWORD=FALSE"), key("DB_PASSWORD", rewrites)},
		{"Null", password("DB_PASSWORD=Null"), key("DB_PASSWORD", rewrites)},
		{"(empty)", password("DB_PASSWORD=(empty)"), key("DB_PASSWORD", rewrites)},
		{"(null) in double quotes", password(`DB_PASSWORD="(null)"`), key("DB_PASSWORD", rewrites)},
		{"(TRUE) in single quotes", laravelEnv(laravelSet{"DB_HOST": "DB_HOST='(TRUE)'"}), key("DB_HOST", rewrites)},
		{"empty as a user", laravelEnv(laravelSet{"DB_USERNAME": "DB_USERNAME=empty"}), key("DB_USERNAME", rewrites)},
		{"double quotes in single quotes", password(`DB_PASSWORD='"pw-Qz8"'`), key("DB_PASSWORD", rewrites)},
		{"single quotes in double quotes", password(`DB_PASSWORD="'pw-Qz8'"`), key("DB_PASSWORD", rewrites)},
		{"two quotes in single quotes", password(`DB_PASSWORD='""'`), key("DB_PASSWORD", rewrites)},

		{"DB_HOST twice", laravelEnv(nil, "DB_HOST=db-Qz8.example.test"), key("DB_HOST", twice)},
		{"DB_PASSWORD twice, once with export", laravelEnv(nil, "export DB_PASSWORD=pw-Qz8"), key("DB_PASSWORD", twice)},

		{"a byte that isn't UTF-8 in quotes", password("DB_PASSWORD=\"pw-Qz8\xff\""), key("DB_PASSWORD", notUTF8)},
		{"a Latin-1 byte unquoted", password("DB_PASSWORD=pw\xe9Qz8"), key("DB_PASSWORD", notUTF8)},

		{"a CA file", laravelEnv(nil, "MYSQL_ATTR_SSL_CA=/etc/ssl/ca-Qz8.pem"), tls},
		{"a quoted CA file", laravelEnv(nil, `MYSQL_ATTR_SSL_CA="/etc/ssl/ca Qz8.pem"`), tls},
		{"a CA file with export", laravelEnv(nil, "export MYSQL_ATTR_SSL_CA=/etc/ssl/ca-Qz8.pem"), tls},
		{"a CA file after an empty one", laravelEnv(nil, "MYSQL_ATTR_SSL_CA=", "MYSQL_ATTR_SSL_CA=/etc/ssl/ca-Qz8.pem"), tls},
		{"a CA file of null", laravelEnv(nil, "MYSQL_ATTR_SSL_CA=null"), tls},
		{"a CA file in a form prodmask doesn't read", laravelEnv(nil, "MYSQL_ATTR_SSL_CA=ca Qz8.pem"), tls},
		{"a CA file with a quoted name", laravelEnv(nil, `"MYSQL_ATTR_SSL_CA"=`), tls},
		{"a bad key before a CA file", laravelEnv(laravelSet{"DB_PASSWORD": "DB_PASSWORD=pw Qz8"}, "MYSQL_ATTR_SSL_CA=/etc/ssl/ca-Qz8.pem"), unquoted("DB_PASSWORD")},

		{"a semicolon in the host", laravelEnv(laravelSet{"DB_HOST": `DB_HOST="db-Qz8;port=3306"`}), key("DB_HOST", semicolon)},
		{"a semicolon in the database", laravelEnv(laravelSet{"DB_DATABASE": `DB_DATABASE="shop;host=evil-Qz8"`}), key("DB_DATABASE", semicolon)},
		{"a semicolon in the socket", laravelEnv(nil, `DB_SOCKET="/run/my;Qz8.sock"`), key("DB_SOCKET", semicolon)},
		{"a relative socket, which PHP resolves from its own folder", laravelEnv(nil, "DB_SOCKET=var/mysql-Qz8.sock"), key("DB_SOCKET", form)},

		{"two URLs that differ", laravelEnv(nil, "DB_URL=mysql://"+urlParts+urlDatabase, "DATABASE_URL=mysql://"+urlParts+"/other_Qz8"),
			key("DATABASE_URL", differs)},
		{"DATABASE_URL alone, which a config from Laravel 11 on ignores for other separate keys", laravelEnv(nil, "DATABASE_URL=mysql://"+urlParts+urlDatabase),
			key("DATABASE_URL", oldURL)},
		{"DATABASE_URL alone, with the defaults of a config from Laravel 11 on", laravelEnv(laravelSet{
			"DB_HOST": "", "DB_PORT": "", "DB_DATABASE": "", "DB_USERNAME": "", "DB_PASSWORD": "",
		}, "DATABASE_URL=mysql://"+urlParts+urlDatabase), key("DATABASE_URL", oldURL)},
		{"DATABASE_URL alone, naming what a config from before Laravel 11 defaults to", laravelFile("DB_CONNECTION=mysql",
			"DATABASE_URL=mysql://forge@127.0.0.1/forge"), key("DATABASE_URL", oldURL)},
		{"DB_URL alone, which a config from before Laravel 11 ignores for other separate keys", laravelEnv(nil, "DB_URL=mysql://"+urlParts+urlDatabase),
			key("DB_URL", newURL)},
		{"DB_URL alone, with the defaults of a config from before Laravel 11", laravelEnv(laravelSet{
			"DB_HOST": "", "DB_PORT": "", "DB_DATABASE": "", "DB_USERNAME": "", "DB_PASSWORD": "",
		}, "DB_URL=mysql://"+urlParts+urlDatabase), key("DB_URL", newURL)},
		{"DB_URL alone, naming what a config from Laravel 11 on defaults to", laravelFile("DB_CONNECTION=mysql",
			"DB_URL=mysql://root@127.0.0.1/laravel"), key("DB_URL", newURL)},
		{"DB_URL alone, with another password", laravelEnv(laravelSameKeys("DB_PASSWORD=other-Qz8"), "DB_URL=mysql://"+urlParts+":3308"+urlDatabase),
			key("DB_URL", newURL)},
		{"an empty DB_URL beside DATABASE_URL", laravelEnv(nil, "DB_URL=", "DATABASE_URL=mysql://"+urlParts+urlDatabase), key("DATABASE_URL", differs)},
		{"DB_URL twice", laravelEnv(nil, "DB_URL=mysql://"+urlParts+urlDatabase, "DB_URL=mysql://"+urlParts+urlDatabase), key("DB_URL", twice)},
		{"DB_URL beside DB_SOCKET", laravelEnv(nil, "DB_URL=mysql://"+urlParts+urlDatabase, "DB_SOCKET=/run/mysqld/mysqld-Qz8.sock"),
			key("DB_URL", besideSock)},
		{"DATABASE_URL beside DB_SOCKET", laravelEnv(nil, "DATABASE_URL=mysql://"+urlParts+urlDatabase, "DB_SOCKET=/run/mysqld/mysqld-Qz8.sock"),
			key("DATABASE_URL", besideSock)},
		{"options after ?", dbURL("mysql://" + urlParts + urlDatabase + "?sslmode=require"), key("DB_URL", options)},
		{"an empty query", dbURL("mysql://" + urlParts + urlDatabase + "?"), key("DB_URL", options)},
		{"DB_URL of null", dbURL("null"), key("DB_URL", rewrites)},
		{"DB_URL quoted twice", dbURL(`'"mysql://` + urlParts + urlDatabase + `"'`), key("DB_URL", rewrites)},
		{"a postgres URL", dbURL("postgres://" + urlParts + urlDatabase), key("DB_URL", noParse)},
		{"a scheme in capitals", dbURL("MYSQL://" + urlParts + urlDatabase), key("DB_URL", noParse)},
		{"Laravel's mysql2 alias", dbURL("mysql2://" + urlParts + urlDatabase), key("DB_URL", noParse)},
		{"a Go DSN", dbURL("url_Qz8:urlpw_Qz8@tcp(url-Qz8.example.test:3306)/urlshop_Qz8"), key("DB_URL", noParse)},
		{"a space before the scheme", dbURL(`" mysql://` + urlParts + urlDatabase + `"`), key("DB_URL", noParse)},
		{"a space in the user", dbURL(`"mysql://url Qz8:urlpw_Qz8@url-Qz8.example.test/urlshop_Qz8"`), key("DB_URL", noParse)},
		{"a bad escape", dbURL("mysql://url_Qz8:pw%zzQz8@url-Qz8.example.test/urlshop_Qz8"), key("DB_URL", noParse)},
		{"an @ after the host", dbURL("mysql://" + urlParts + "/shop@Qz8"), key("DB_URL", noParse)},
		{"no host", dbURL("mysql://url_Qz8:urlpw_Qz8@/urlshop_Qz8"), key("DB_URL", noParse)},
		{"a port and no host", dbURL("mysql://url_Qz8:urlpw_Qz8@:3308/urlshop_Qz8"), key("DB_URL", noParse)},
		{"URL port 0", dbURL("mysql://" + urlParts + ":0" + urlDatabase), key("DB_URL", noParse)},
		{"URL port 65536", dbURL("mysql://" + urlParts + ":65536" + urlDatabase), key("DB_URL", noParse)},
		{"a six-digit URL port", dbURL("mysql://" + urlParts + ":003308" + urlDatabase), key("DB_URL", noParse)},
		{"a URL with no user", dbURL("mysql://url-Qz8.example.test/urlshop_Qz8"), key("DB_URL", noUser)},
		{"a URL with an empty user", dbURL("mysql://:urlpw_Qz8@url-Qz8.example.test/urlshop_Qz8"), key("DB_URL", noUser)},
		{"a URL with only an @", laravelEnv(nil, "DATABASE_URL=mysql://@url-Qz8.example.test/urlshop_Qz8"), key("DATABASE_URL", noUser)},
		{"a URL with no path", dbURL("mysql://" + urlParts), key("DB_URL", noDatabase)},
		{"a URL with an empty path", dbURL("mysql://" + urlParts + "/"), key("DB_URL", noDatabase)},
		{"a user of null", dbURL("mysql://null:urlpw_Qz8@url-Qz8.example.test/urlshop_Qz8"), key("DB_URL", json)},
		{"a password of true", dbURL("mysql://url_Qz8:true@url-Qz8.example.test/urlshop_Qz8"), key("DB_URL", json)},
		{"a password in exponent form", dbURL("mysql://url_Qz8:1e3@url-Qz8.example.test/urlshop_Qz8"), key("DB_URL", json)},
		{"a password of -0", dbURL("mysql://url_Qz8:-0@url-Qz8.example.test/urlshop_Qz8"), key("DB_URL", json)},
		{"a password past int64", dbURL("mysql://url_Qz8:12345678901234567890@url-Qz8.example.test/urlshop_Qz8"), key("DB_URL", json)},
		{"a password that is a JSON string", dbURL("mysql://url_Qz8:%22Qz8%22@url-Qz8.example.test/urlshop_Qz8"), key("DB_URL", json)},
		{"a host that is a number", dbURL("mysql://url_Qz8:urlpw_Qz8@1.5/urlshop_Qz8"), key("DB_URL", json)},
		{"a semicolon in the URL's database", dbURL("mysql://" + urlParts + "/shop%3BQz8"), key("DB_URL", semicolon)},
		{"a semicolon in the URL's host", dbURL("mysql://url_Qz8:urlpw_Qz8@url;Qz8" + urlDatabase), key("DB_URL", semicolon)},
		{"a bad DB_PORT under a URL with no port", laravelEnv(laravelSet{"DB_PORT": "DB_PORT=port-Qz8"}, "DB_URL=mysql://"+urlParts+urlDatabase),
			key("DB_PORT", notPort)},

		// Lines phpdotenv versions group differently.
		{"a quote in a comment, which starts a value before 5.7", laravelEnv(laravelSet{"DB_HOST": ""},
			`# APP_NAME="Shop Qz8`, "DB_HOST=db-Qz8.example.test", `# "`), versions},
		{"a quote opening a line, which ends a value from 5.8", laravelEnv(laravelSet{"DB_HOST": ""},
			`APP_NAME="Shop`, `"Qz8`, "DB_HOST=db-Qz8.example.test", `"`), versions},
		{`a line inside a value with =", which starts another before 5.5`, laravelEnv(laravelSet{"DB_HOST": ""},
			`CERT="Qz8`, `X="y`, "DB_HOST=db-Qz8.example.test", `"`), versions},
	}
	var wants []string
	for _, c := range cases {
		wants = append(wants, c.want)
		_, err := readLaravel([]byte(c.env))
		if err == nil {
			t.Errorf("%s: no refusal", c.name)
			continue
		}
		if got := laravelRefusalText(t, c.name, err); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// Every reason the lists hold has a row above.
	for _, reason := range append(slices.Clone(laravelReasons), laravelFileReasons...) {
		if !slices.ContainsFunc(wants, func(w string) bool { return strings.HasSuffix(w, " "+reason+"; pass --dsn instead") }) {
			t.Errorf("no row refuses with %q", reason)
		}
	}
}

// TestLaravelCanary cuts a .env whose values all hold the canary at every
// byte, puts a quote, a #, a backslash or a line end in place of each byte,
// and drops each line in turn: whatever readLaravel refuses on the way, it
// says in fixed words from Messages.
func TestLaravelCanary(t *testing.T) {
	file := laravelFile(
		"# Qz8 in a comment",
		`APP_NAME="Shop Qz8"`,
		"APP_KEY=base64:"+strings.Repeat("Qz8x", 11),
		"DB_CONNECTION=mysql",
		"DB_HOST='db-Qz8.example.test' # the primary",
		"DB_PORT=3307",
		`DB_DATABASE="shop Qz8"`,
		"export DB_USERNAME=user_Qz8",
		`DB_PASSWORD="pw Qz8 #'$"`,
		"DB_URL=",
		"DATABASE_URL=",
		`PRIVATE_KEY="-----BEGIN Qz8`,
		"DB_HOST=evil-Qz8",
		`-----END Qz8"`,
		"MYSQL_ATTR_SSL_CA=",
	)
	if _, err := readLaravel([]byte(file)); err != nil {
		t.Fatalf("the whole file: %v", err)
	}
	check := func(name, data string) {
		if _, err := readLaravel([]byte(data)); err != nil {
			laravelRefusalText(t, name, err)
		}
	}
	for i := range len(file) {
		check(fmt.Sprintf("cut at %d", i), file[:i])
		for _, b := range []string{`"`, "'", "#", `\`, "\n", " ", "=", "$", "{"} {
			check(fmt.Sprintf("%q at %d", b, i), file[:i]+b+file[i+1:])
		}
	}
	lines := strings.Split(file, "\n")
	for i := range lines {
		check(fmt.Sprintf("without line %d", i), strings.Join(slices.Delete(slices.Clone(lines), i, i+1), "\n"))
	}
	// A URL alone in its place, naming the database the separate keys name so
	// that it's read, with each byte of it changed.
	const urlLine = "DB_URL=mysql://user_Qz8:pw%20Qz8%20%23%27%24@db-Qz8.example.test:3307/shop%20Qz8"
	withURL := strings.NewReplacer("DB_URL=\n", urlLine+"\n", "DATABASE_URL=\n", "").Replace(file)
	if _, err := readLaravel([]byte(withURL)); err != nil {
		t.Fatalf("the file with a URL: %v", err)
	}
	start := strings.Index(withURL, "DB_URL=")
	for i := start; i < start+len(urlLine); i++ {
		for _, b := range []string{"@", ":", "/", "?", "%", "[", "]", ";", "#", "x"} {
			check(fmt.Sprintf("URL with %q at %d", b, i), withURL[:i]+b+withURL[i+1:])
		}
	}
}

// TestReadLaravelProject reads .env through Read: with a BOM and CRLF line
// ends, through a socket or to localhost, and a refusal that names no path.
func TestReadLaravelProject(t *testing.T) {
	for _, c := range []struct {
		env               string
		net, addr         string
		socket, localhost bool
	}{
		{"\xef\xbb\xbfDB_CONNECTION=mysql\r\nDB_SOCKET=/run/mysqld/mysqld.sock\r\nDB_DATABASE=shop\r\nDB_USERNAME=shop_ro\r\nDB_PASSWORD='pw Qz8'\r\n",
			"unix", "/run/mysqld/mysqld.sock", true, false},
		{"DB_CONNECTION=mariadb\nDB_HOST=localhost\nDB_DATABASE=shop\nDB_USERNAME=shop_ro\nDB_PASSWORD='pw Qz8'\n",
			"tcp", "localhost:3306", false, true},
	} {
		dir := secretDir(t)
		write(t, dir, "artisan", []byte("x"))
		write(t, dir, Laravel, []byte(c.env))
		p, err := Read(dir)
		if err != nil {
			t.Errorf("%s: %v", c.addr, err)
			continue
		}
		cfg := p.Config
		if p.File != Laravel || cfg.Net != c.net || cfg.Addr != c.addr || p.Socket != c.socket || p.Localhost != c.localhost ||
			cfg.DBName != "shop" || cfg.User != "shop_ro" || cfg.Passwd != "pw Qz8" || cfg.TLS != nil || cfg.TLSConfig != "" {
			t.Errorf("%s: read %s %s %s/%s, socket %v, localhost %v", c.addr, p.File, cfg.Net, cfg.Addr, cfg.DBName, p.Socket, p.Localhost)
		}
	}

	dir := secretDir(t)
	write(t, dir, "artisan", []byte("x"))
	write(t, dir, Laravel, []byte("DB_CONNECTION=mysql\nDB_HOST=db\nDB_DATABASE=shop\nDB_USERNAME=shop_ro\nDB_PASSWORD=pw Qz8\n"))
	want := "can't read the database from .env: DB_PASSWORD holds #, whitespace or a quote outside quotes; quote it, or pass --dsn"
	if _, err := Read(dir); err == nil {
		t.Error("an unquoted space: no refusal")
	} else if got := refusalText(t, dir, err); got != want {
		t.Errorf("an unquoted space: %q, want %q", got, want)
	}
}
