package projectdb

import (
	"errors"
	"testing"
)

// fuzzReader runs one reader on fuzzed input: it must not panic, and it must
// either return settings or a refusal whose text is in Messages, so no input
// byte can reach an error.
func fuzzReader(t *testing.T, read func([]byte) (*settings, error), data []byte) {
	s, err := read(data)
	if err == nil {
		if s == nil {
			t.Fatal("no settings and no error")
		}
		return
	}
	var refusal *Error
	if !errors.As(err, &refusal) {
		t.Fatalf("not a refusal: %T", err)
	}
	if !messageSet()[refusal.Error()] {
		t.Fatalf("a refusal outside Messages: %q", refusal.Error())
	}
}

func FuzzWordPress(f *testing.F) {
	for _, seed := range []string{
		"",
		"<?php\ndefine('DB_NAME', 'shop');\ndefine('DB_USER', 'ro');\ndefine('DB_PASSWORD', 'p\\'w');\ndefine('DB_HOST', 'localhost:/run/mysqld.sock');\n",
		"<?php\n// define('DB_NAME', 'old');\n/* define('DB_HOST', 'prod') */\n# define('DB_USER', 'x')\ndefine('DB_NAME', \"shop\");",
		"<?php if (true): define('DB_NAME', 'a'); endif; define('DB_NAME', 'b');",
		"<?php\n$x = <<<EOT\ndefine('DB_NAME', 'in a heredoc');\nEOT;\ndefine('DB_HOST', '[::1]:3307');",
		"<?php require 'local.php'; define('DB_NAME', getenv('DB_NAME'));",
		"<?php\n#[Attr]\nDEFINE('DB_USER', 'u'); \\define('DB_PASSWORD', '');",
		"<?php /* unterminated",
		"text before <?php define('DB_HOST', 'p:db'); ?> after",
	} {
		f.Add([]byte(seed))
	}
	for _, c := range append(wpReads(), wpRefusals()...) {
		f.Add([]byte(c.src))
	}
	f.Fuzz(func(t *testing.T, data []byte) { fuzzReader(t, readWordPress, data) })
}

func FuzzLaravel(f *testing.F) {
	for _, seed := range []string{
		"",
		"DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=shop\nDB_USERNAME=ro\nDB_PASSWORD='p#w'\n",
		"export DB_CONNECTION=\"mariadb\"\nDB_SOCKET=/run/mysqld.sock\nDB_DATABASE=shop\nDB_USERNAME=ro\n",
		"APP_KEY=\"unterminated\nDB_HOST=prod\n\"\nDB_CONNECTION=mysql\n",
		"DB_CONNECTION=mysql\nDB_URL=mysql://ro:pw@db:3307/shop\nDB_PASSWORD=x\n",
		"DB_PASSWORD=${OTHER}\nDB_HOST=a b\nDB_USERNAME=(null)\nDB_DATABASE='\"q\"'\n",
		"# comment\nMYSQL_ATTR_SSL_CA=/etc/ca.pem\n",
		laravelEnv(nil),
		laravelEnv(nil, "DB_URL=mysql://u:p@[::1]:3308/db", "MYSQL_ATTR_SSL_CA="),
		laravelEnv(nil, `CERT="a`, `"b`, `X="y`, "DB_HOST=x", `"`, `# c="d`),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) { fuzzReader(t, readLaravel, data) })
}

func FuzzMagento(f *testing.F) {
	for _, seed := range []string{
		"",
		"<?php\nreturn [\n    'db' => [\n        'connection' => [\n            'default' => [\n                'host' => 'localhost:3307',\n" +
			"                'dbname' => 'shop',\n                'username' => 'ro',\n                'password' => 'p\\'w',\n" +
			"                'driver_options' => [1014 => false]\n            ]\n        ]\n    ],\n];\n",
		"<?php return array('db' => array('connection' => array('default' => array('host' => '/run/mysqld.sock', 'dbname' => 's', 'username' => 'u'))));",
		"<?php return ['db' => ['connection' => ['default' => ['host' => 'h', 'port' => '3307', 'dbname' => 's', 'username' => 'u']]]];",
		"<?php return ['db' => ['connection' => ['default' => ['host' => getenv('H'), 'dbname' => 's', 'username' => 'u', 'driver_options' => [1009 => '/ca.pem']]]]];",
		"<?php // ['db' => ...]\nreturn ['crypt' => ['key' => 'x'], /* 'db' */ 'db' => ['connection' => ['default' => []]]];",
		"<?php return [",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) { fuzzReader(t, readMagento, data) })
}
