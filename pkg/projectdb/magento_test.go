package projectdb

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// magentoCanary is in the password and in values readMagento doesn't read:
// no refusal may show it.
var magentoCanary = "Qz8" + "magentoCanary"

// magentoPassword is the password the test files set.
var magentoPassword = "pw-" + magentoCanary

// magentoRest is db.connection.default's entries besides host.
var magentoRest = "'dbname' => 'shop', 'username' => 'shop_ro', 'password' => '" + magentoPassword + "'"

// magentoDB is a db entry for the returned array.
var magentoDB = "'db' => ['connection' => ['default' => ['host' => 'db.example.test', " + magentoRest + "]]]"

// magentoWrap returns an env.php that returns an array of entries.
func magentoWrap(entries string) string {
	return "<?php\nreturn [\n" + entries + "\n];\n"
}

// magentoEnv returns an env.php whose db.connection.default holds entries,
// beside a crypt key with the canary in it.
func magentoEnv(entries string) string {
	return magentoWrap("    'crypt' => ['key' => '" + magentoCanary + "'],\n" +
		"    'db' => [\n        'table_prefix' => '',\n        'connection' => [\n" +
		"            'default' => [\n                " + entries + "\n            ],\n        ],\n    ],")
}

// magentoInstalled is app/etc/env.php as Magento 2.4's installer writes it,
// here with Redis for the cache and the sessions and RabbitMQ for the queue,
// each with a host, a port and a password of its own.
func magentoInstalled() string {
	crypt := "base64" + "Qz8" + "cryptCanary" + "q0Ld8vXh" + "2NcRk5Tz" + "W9mYp3Jb" + "="
	salt := "Qz8" + "saltCanary" + "Lk4Ne8Rt" + "Vb2Xc6Zq"
	return `<?php
return [
    'backend' => [
        'frontName' => 'admin_qz8front'
    ],
    'remote_storage' => [
        'driver' => 'file'
    ],
    'cache' => [
        'graphql' => [
            'id_salt' => '` + salt + `'
        ],
        'frontend' => [
            'default' => [
                'id_prefix' => '40d_',
                'backend' => 'Magento\\Framework\\Cache\\Backend\\Redis',
                'backend_options' => [
                    'server' => 'redis.example.test',
                    'database' => '0',
                    'port' => '6379',
                    'password' => '` + magentoCanary + `',
                    'compress_data' => '1',
                    'compression_lib' => ''
                ]
            ],
            'page_cache' => [
                'id_prefix' => '40d_'
            ]
        ],
        'allow_parallel_generation' => false
    ],
    'config' => [
        'async' => 0
    ],
    'queue' => [
        'amqp' => [
            'host' => 'rabbitmq.example.test',
            'port' => '5672',
            'user' => 'magento',
            'password' => '` + magentoCanary + `',
            'virtualhost' => '/'
        ],
        'consumers_wait_for_messages' => 1
    ],
    'crypt' => [
        'key' => '` + crypt + `'
    ],
    'db' => [
        'table_prefix' => '',
        'connection' => [
            'default' => [
                'host' => 'db.example.test:3307',
                'dbname' => 'magento',
                'username' => 'magento',
                'password' => '` + magentoPassword + `',
                'model' => 'mysql4',
                'engine' => 'innodb',
                'initStatements' => 'SET NAMES utf8;',
                'active' => '1',
                'driver_options' => [
                    1014 => false
                ]
            ]
        ]
    ],
    'resource' => [
        'default_setup' => [
            'connection' => 'default'
        ]
    ],
    'x-frame-options' => 'SAMEORIGIN',
    'MAGE_MODE' => 'production',
    'session' => [
        'save' => 'redis',
        'redis' => [
            'host' => 'redis.example.test',
            'port' => '6379',
            'password' => '` + magentoCanary + `',
            'timeout' => '2.5',
            'persistent_identifier' => '',
            'database' => '2',
            'compression_threshold' => '2048',
            'compression_library' => 'gzip',
            'log_level' => '1',
            'max_concurrency' => '6',
            'break_after_frontend' => '5',
            'break_after_adminhtml' => '30',
            'first_lifetime' => '600',
            'bot_first_lifetime' => '60',
            'bot_lifetime' => '7200',
            'disable_locking' => '0',
            'min_lifetime' => '60',
            'max_lifetime' => '2592000',
            'sentinel_master' => '',
            'sentinel_servers' => '',
            'sentinel_connect_retries' => '5',
            'sentinel_verify_master' => '0'
        ]
    ],
    'lock' => [
        'provider' => 'db'
    ],
    'directories' => [
        'document_root_is_pub' => true
    ],
    'cache_types' => [
        'config' => 1,
        'layout' => 1,
        'block_html' => 1,
        'collections' => 1,
        'reflection' => 1,
        'db_ddl' => 1,
        'compiled_config' => 1,
        'eav' => 1,
        'customer_notification' => 1,
        'config_integration' => 1,
        'config_integration_api' => 1,
        'graphql_query_resolver_result' => 1,
        'full_page' => 1,
        'config_webservice' => 1,
        'translate' => 1
    ],
    'downloadable_domains' => [
        'shop.example.test'
    ],
    'install' => [
        'date' => 'Wed, 13 Nov 2024 09:12:33 +0000'
    ]
];
`
}

// magentoExported is app/etc/env.php as Magento 2.0 and 2.1 wrote it, with
// var_export: array ( and a comma after every entry.
func magentoExported() string {
	return `<?php
return array (
  'backend' =>
  array (
    'frontName' => 'admin_qz8front',
  ),
  'crypt' =>
  array (
    'key' => '` + magentoCanary + `',
  ),
  'db' =>
  array (
    'table_prefix' => '',
    'connection' =>
    array (
      'default' =>
      array (
        'host' => 'localhost',
        'dbname' => 'shop',
        'username' => 'shop_ro',
        'password' => '` + magentoPassword + `',
        'active' => '1',
      ),
    ),
  ),
  'install' =>
  array (
    'date' => 'Mon, 01 Aug 2016 10:00:00 +0000',
  ),
);
`
}

// TestMagentoReads checks every form readMagento reads: the files Magento's
// installers write, each form of host and of string, comments and keyword
// case, keys and values it skips, driver options it ignores, and db entries
// in comments and strings, which it never reads.
func TestMagentoReads(t *testing.T) {
	shop := func(s settings) settings {
		s.user, s.password, s.database = "shop_ro", magentoPassword, "shop"
		return s
	}
	db := shop(settings{host: "db.example.test"})
	host := func(h string) string { return magentoEnv("'host' => '" + h + "', " + magentoRest) }
	good := "'host' => 'db.example.test', " + magentoRest
	password := func(p string) settings {
		return settings{user: "shop_ro", password: p, database: "shop", host: "db.example.test"}
	}
	withPassword := func(p string) string {
		return magentoEnv("'host' => 'db.example.test', 'dbname' => 'shop', 'username' => 'shop_ro', 'password' => " + p)
	}
	evil := "'db' => ['connection' => ['default' => ['host' => 'evil.example.test', 'dbname' => 'evil', 'username' => 'evil']]]"
	for _, c := range []struct {
		name string
		env  string
		want settings
	}{
		{"Magento 2.4's installer", magentoInstalled(),
			settings{user: "magento", password: magentoPassword, database: "magento", host: "db.example.test", port: 3307}},
		{"Magento 2.1's var_export", magentoExported(), shop(settings{host: "localhost"})},

		// The host, as Magento's adapter splits it.
		{"a name", host("db.example.test"), db},
		{"localhost", host("localhost"), shop(settings{host: "localhost"})},
		{"a name and a port", host("db.example.test:3307"), shop(settings{host: "db.example.test", port: 3307})},
		{"an address and a port", host("10.0.0.5:3306"), shop(settings{host: "10.0.0.5", port: 3306})},
		{"the lowest port", host("db:1"), shop(settings{host: "db", port: 1})},
		{"the highest port", host("db:65535"), shop(settings{host: "db", port: 65535})},
		{"a port with leading zeros", host("db:03307"), shop(settings{host: "db", port: 3307})},
		{"a socket", host("/run/mysqld/mysqld.sock"), shop(settings{socket: "/run/mysqld/mysqld.sock"})},
		{"a socket with a colon", host("/run/my:sql.sock"), shop(settings{socket: "/run/my:sql.sock"})},
		{"a / after a leading /, which makes it all a socket", host("/run/db.example.test:3306/x"), shop(settings{socket: "/run/db.example.test:3306/x"})},

		// Strings.
		{"no password", magentoEnv("'host' => 'db.example.test', 'dbname' => 'shop', 'username' => 'shop_ro'"), password("")},
		{"an empty password", withPassword("''"), password("")},
		{"escapes in single quotes", withPassword(`'it\'s \\ and \n and \x'`), password(`it's \ and \n and \x`)},
		{"double quotes", magentoEnv(`"host" => "db.example.test", "dbname" => "shop", "username" => "shop_ro", "password" => "it's {plain} 'text'"`),
			password("it's {plain} 'text'")},
		{"bytes that aren't UTF-8", withPassword("'p\xe9\xff'"), password("p\xe9\xff")},
		{"comment and tag marks in a string", withPassword("'// # /* ?> <?php #['"), password("// # /* ?> <?php #[")},
		{"a lone CR in a string, which Read keeps", withPassword("'a\rb'"), password("a\rb")},

		// The file's syntax.
		{"keywords in any case", "<?PHP\nRETURN ARRAY('db' => Array('connection' => aRRay('default' => [" + good + "])));\n", db},
		{"comments everywhere", "<?php /* a */ // b\n# c\n/** d */\nreturn /* e */ [ // f\n" +
			"    'db' /* g */ => # h\n    [ 'connection' => [ 'default' => [ 'host' /**/ => /**/ 'db.example.test', // i\n" +
			"    " + magentoRest + " # j\n    ] ] ] ] /* k */ ; // l\n# m\n", db},
		{"a closing tag", magentoWrap(magentoDB) + "?>\n", db},
		{"a closing tag after a comment", strings.TrimSuffix(magentoWrap(magentoDB), "\n") + " // the end ?>", db},
		{"comments after ;", magentoWrap(magentoDB) + "// the end\n/* really */\n", db},
		{"a comma after every entry", "<?php\nreturn [\n'db' => [\n'connection' => [\n'default' => [\n" + good + ",\n],\n],\n],\n];\n", db},
		{"no spaces and no last newline", "<?php return['db'=>['connection'=>['default'=>[" + good + "]]]];", db},
		{"comments before array's (", "<?php\treturn array /* x */ ('db' => array // y\n('connection' => array # z\n" +
			"('default' => array ('host' => 'db.example.test', " + magentoRest + "))));\n", db},

		// Keys and values it skips.
		{"numbers and bare values beside the keys", "<?php\nreturn ['first', 7 => 'x', 0x1F => 'y', 1_000 => 'z', 1.5 => 'w', " +
			"'db' => ['connection' => [0 => 'a', 'default' => ['b', 0b11 => 'c', " + good + "]]]];\n", db},
		{"keys it doesn't read, twice", "<?php\nreturn [\n'cache' => [],\n'cache' => [],\n" +
			"'db' => ['table_prefix' => '', 'table_prefix' => 'x_', 'connection' => [\n" +
			"'indexer' => ['host' => 'indexer.example.test', 'host' => 'twice', 'dbname' => 'idx'],\n" +
			"'default' => ['host' => 'db.example.test', 'model' => 'mysql4', 'model' => 'mysql4', " + magentoRest + "],\n" +
			"'checkout' => ['host' => 'checkout.example.test', 'port' => '3307'],\n]],\n];\n", db},
		{"other settings of the connection", magentoEnv(good + ", 'model' => 'mysql4', 'engine' => 'innodb', " +
			"'initStatements' => 'SET NAMES utf8;', 'active' => '1', 'persistent' => null, 'profiler' => ['enabled' => true]"), db},
		{"settings with semicolons that name no server", magentoEnv(good + ", " +
			"'initStatements' => 'SET NAMES utf8; SET time_zone = \"+00:00\";', 'charset' => 'utf8mb4', 'active' => true, " +
			"'model' => null, 'x' => 1.5, 3 => 'y', 'options' => getenv('OPTIONS'), 'profiler' => array('host=x' => ';host=y')"), db},
		{"a db entry inside another", magentoWrap("'system' => [" + evil + "],\n" + magentoDB), db},
		{"values of every shape", magentoWrap("'closure' => function ($a) use ($b) { echo 'a', 'b'; return [1, 2]; },\n" +
			"'arrow' => fn($x) => [$x, 'db' => 1],\n" +
			"'static' => static fn() => ['db' => 2],\n" +
			"'match' => match (PHP_OS_FAMILY) { 'Linux' => ['db' => 3], default => 'x' },\n" +
			"'class' => new class { public $db = ['db' => 4]; },\n" +
			"'call' => getenv('DB_HOST') ?: 'db',\n" +
			"'concat' => 'a' . \"b\" . PHP_EOL,\n" +
			"'const' => \\PDO::ATTR_ERRMODE,\n" +
			"'spread' => [...$defaults, 'db' => 5],\n" +
			"'interpolated' => \"$x and $y[0] and {braces} and \\\"quotes\\\" and \\$\",\n" +
			"'shell' => `echo 'db'`,\n" +
			"'heredoc' => <<<EOT\n    ]) 'db' => [\" with $x\n      EOTX is no end\n    EOT,\n" +
			"'nowdoc' => <<< 'EOT'\n{$not} ${code} \\'\nEOT\n,\n" +
			"'empty' => <<<\"EOT\"\nEOT,\n" +
			"'compare' => 1 <=> 2,\n" +
			"1 <=> 2,\n" +
			"'numbers' => [1.5e3, .5, 0b101, 0o17, 0x1F, 1_000],\n" +
			"'binary' => b'bytes',\n" +
			"'names' => [ünïcode => \\Ns\\Name::class],\n" +
			"'ternary' => $a ? [1] : (2),\n" +
			"'reference' => &$x,\n" +
			"'cast' => (string) 1,\n" +
			"'backslash' => <<<TXT\n    a line that ends in a backslash \\\n    TXT,\n" +
			magentoDB), db},

		// db entries it must not read.
		{"db entries in comments", magentoWrap("// " + evil + ",\n# " + evil + ",\n/* " + evil + ", */\n/** " + evil + " */\n" +
			magentoDB + "\n// , " + evil), db},
		{"db entries in strings", magentoWrap("'a' => \"" + evil + "\",\n'b' => '" + strings.ReplaceAll(evil, "'", `\'`) + "',\n" +
			"'c' => \"\\\", " + evil + ", \\\"\",\n" + magentoDB), db},
		{"db entries in a heredoc and a nowdoc", magentoWrap("'a' => <<<EOT\nEOTX\n, " + evil + ",\nEOT,\n" +
			"'b' => <<<'EOT'\nEOT_\n, " + evil + "\n];\nEOT,\n" + magentoDB), db},
		{"a db entry in backquotes", magentoWrap("'a' => `echo \"" + evil + "\"`,\n" + magentoDB), db},
		{"a // comment ended by a lone CR", magentoWrap("// a note\r" + magentoDB), db},
		{"a # comment ended by a lone CR", magentoWrap("# a note\r" + magentoDB), db},

		// Driver options set to false.
		{"no driver options", magentoEnv(good + ", 'driver_options' => []"), db},
		{"no driver options in array()", magentoEnv(good + ", 'driver_options' => array()"), db},
		{"options set to false, however keyed", magentoEnv(good + ", 'driver_options' => [\\PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => FALSE, " +
			"1014 => False, PDO::ATTR_EMULATE_PREPARES => false, 'x' => fAlSe, [1, 2][0] => false, false,]"), db},
	} {
		s, err := readMagento([]byte(c.env))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if *s != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, *s, c.want)
		}
	}
}

// TestMagentoRefusals checks every refusal readMagento gives, by its exact
// text, which must be in Messages and show nothing from the file: no canary,
// and no line of it. Between them the rows use every key and reason the
// reader lists.
func TestMagentoRefusals(t *testing.T) {
	const (
		prefix  = "can't read the database from app/etc/env.php: "
		suffix  = "; pass --dsn instead"
		file    = prefix + "it doesn't return an array of plain values" + suffix
		options = "app/etc/env.php sets driver options prodmask doesn't read; pass --dsn instead (with ?tls=true if they ask for TLS)"
		port    = prefix + "port is set, which Magento itself refuses" + suffix
		unset   = prefix + "db.connection.default isn't set" + suffix
		server  = prefix + "db.connection.default has a setting Magento passes to PDO that could name another server" + suffix
	)
	semicolon := func(key string) string {
		return prefix + key + " holds a semicolon, which PDO reads as a separator" + suffix
	}
	lines := func(key string) string { return prefix + key + " runs over several lines" + suffix }
	missing := func(key string) string { return prefix + key + " isn't set" + suffix }
	empty := func(key string) string { return prefix + key + " is empty" + suffix }
	twice := func(key string) string { return prefix + key + " is set twice" + suffix }
	notPlain := func(key string) string { return prefix + key + " isn't one plain string (it isn't shown)" + suffix }
	form := func(key string) string {
		return prefix + key + " isn't in a form prodmask reads (it isn't shown)" + suffix
	}

	db, top, def := magentoDB, magentoWrap, magentoEnv
	good := "'host' => 'db.example.test', " + magentoRest
	host := func(v string) string { return def("'host' => " + v + ", " + magentoRest) }
	with := func(old, new string) string { return def(strings.Replace(good, old, new, 1)) }
	evil := "'db' => ['connection' => ['default' => ['host' => 'evil.example.test', 'dbname' => 'evil', 'username' => 'evil']]]"
	cases := []struct{ name, env, want string }{
		// The file's shape.
		{"an empty file", "", file},
		{"no <?php", "return [" + db + "];\n", file},
		{"a line before <?php", "\n" + def(good), file},
		{"<?php run into return", "<?phpreturn [" + db + "];", file},
		{"a short tag", "<? return [" + db + "];", file},
		{"an echo tag", "<?= [" + db + "];", file},
		{"code before return", "<?php\n$prefix = 'x';\nreturn [" + db + "];\n", file},
		{"declare before return", "<?php\ndeclare(strict_types=1);\nreturn [" + db + "];\n", file},
		{"use before return", "<?php\nuse Magento\\Framework\\Config;\nreturn [" + db + "];\n", file},
		{"a variable returned", "<?php\n$env = [" + db + "];\nreturn $env;\n", file},
		{"a call returned", "<?php\nreturn array_merge([" + db + "], []);\n", file},
		{"an include returned", "<?php\nreturn include __DIR__ . '/env.local.php';\n", file},
		{"an array added to", "<?php\nreturn [" + db + "] + ['x' => 1];\n", file},
		{"an array indexed", "<?php\nreturn [[" + db + "]][0];\n", file},
		{"an array in parentheses", "<?php\nreturn ([" + db + "]);\n", file},
		{"no ;", "<?php\nreturn [" + db + "]\n", file},
		{"?> for ;", "<?php\nreturn [" + db + "] ?>\n", file},
		{"code after ;", top(db) + "$x = 1;\n", file},
		{"a second return", top(db) + "return [];\n", file},
		{"text after ?>", top(db) + "?>\n<p>shop</p>\n", file},
		{"?> in a // comment", top("// " + evil + " ?>\n" + db), file},
		{"?> in a # comment", top("# ?> " + evil + "\n" + db), file},
		{"#[", top("#[Deprecated]\n" + db), file},
		{"an open string", "<?php\nreturn [" + db + ", 'crypt' => 'x];\n", file},
		{"an open double-quoted string", "<?php\nreturn [" + db + ", 'crypt' => \"x];\n", file},
		{"an open backquote", "<?php\nreturn [" + db + ", 'crypt' => `x];\n", file},
		{"an open comment", "<?php\nreturn [" + db + "]; /* note\n", file},
		{"an open heredoc", "<?php\nreturn [" + db + ", 'x' => <<<EOT\nbody\n];\n", file},
		{"an open nowdoc", "<?php\nreturn [" + db + ", 'x' => <<<'EOT'\nbody\n];\n", file},
		{"a heredoc label not alone", "<?php\nreturn [" + db + ", 'x' => <<<EOT body\nEOT\n];\n", file},
		{"a heredoc with no label", "<?php\nreturn [" + db + ", 'x' => <<<\nEOT\n];\n", file},
		{"a heredoc label's quotes unmatched", "<?php\nreturn [" + db + ", 'x' => <<<\"EOT'\nbody\nEOT\n];\n", file},
		{"{$ in a string", top("'x' => \"{$a['b']}\",\n" + db), file},
		{"${ in a string", top("'x' => \"${a}\",\n" + db), file},
		{"{$ in a heredoc", top("'x' => <<<EOT\n{$a}\nEOT,\n" + db), file},
		{"${ in backquotes", top("'x' => `${a}`,\n" + db), file},
		{"a bracket left open", "<?php\nreturn [" + db + ", 'x' => (1];\n", file},
		{"a bracket closed twice", "<?php\nreturn [" + db + "]];\n", file},
		{"an empty entry", top("'x' => 1,,\n" + db), file},
		{"only a comma", "<?php\nreturn [,];\n", file},
		{"a key with no value", top("'x' =>,\n" + db), file},
		{"a value with no key", top("=> 'x',\n" + db), file},
		{"a key from code", top("'d' . 'b' => ['connection' => []],\n" + db), file},
		{"a constant key", top("DB => [],\n" + db), file},
		{"a key with an escape", top("\"d\\x62\" => [],\n" + db), file},
		{"a negative key", top("-1 => 'x',\n" + db), file},
		{"a spread", top(db + ",\n...$overrides"), file},

		// The path to db.connection.default.
		{"no db", top("'crypt' => ['key' => '" + magentoCanary + "']"), unset},
		{"no connection", top("'db' => ['table_prefix' => '']"), unset},
		{"no default", top("'db' => ['connection' => ['indexer' => [" + good + "]]]"), unset},
		{"db only in comments", top("// " + evil + "\n# " + evil + "\n/* " + evil + " */\n'crypt' => []"), unset},
		{"db only in strings", top("'a' => \"" + evil + "\",\n'b' => '\\'db\\' => []'"), unset},
		{"db only in a heredoc and a nowdoc", top("'a' => <<<EOT\n" + evil + "\nEOT,\n'b' => <<<'EOT'\n" + evil + "\nEOT\n"), unset},
		{"db under another key", top("'system' => [" + db + "]"), unset},
		{"DB in capitals", top(strings.Replace(db, "'db'", "'DB'", 1)), unset},
		{"db as a bare value", top("[" + db + "]"), unset},
		{"db twice", top(db + ",\n" + db), twice("db")},
		{"db twice, once in double quotes", top(db + ",\n" + strings.Replace(db, "'db'", `"db"`, 1)), twice("db")},
		{"connection twice", top("'db' => ['connection' => [], 'connection' => ['default' => [" + good + "]]]"), twice("db.connection")},
		{"default twice", top("'db' => ['connection' => ['default' => [], 'default' => [" + good + "]]]"), twice("db.connection.default")},
		{"db null", top("'db' => null"), form("db")},
		{"db from a call", top("'db' => getenv('DB')"), form("db")},
		{"db added to", top("'db' => ['connection' => []] + []"), form("db")},
		{"db a string", top("'db' => 'mysql'"), form("db")},
		{"connection null", top("'db' => ['connection' => null]"), form("db.connection")},
		{"default from a call", top("'db' => ['connection' => ['default' => array_merge([" + good + "], [])]]"), form("db.connection.default")},
		{"default a string", top("'db' => ['connection' => ['default' => 'mysql']]"), form("db.connection.default")},
		{"an empty entry in db", top("'db' => ['connection' => ['default' => [" + good + "]],,]"), form("db")},
		{"a key from code in db", top("'db' => ['connection' => ['default' => [" + good + "]], \\Foo::CONNECTION => []]"), form("db")},
		{"a spread in connection", top("'db' => ['connection' => ['default' => [" + good + "], ...$more]]"), form("db.connection")},
		{"a key from code in default", def(good + ", 'ho' . 'st' => 'evil.example.test'"), form("db.connection.default")},
		{"a key with an escape in default", def(good + ", \"h\\x6fst\" => 'evil.example.test'"), form("db.connection.default")},
		{"a nowdoc key in default", def(good + ", <<<'K'\nhost\nK => 'evil.example.test'"), form("db.connection.default")},
		{"a constant key in default", def(good + ", HOST => 'evil.example.test'"), form("db.connection.default")},
		{"true as a key in default", def(good + ", true => 'evil.example.test'"), form("db.connection.default")},
		{"a spread in default", def(good + ", ...$override"), form("db.connection.default")},
		{"an empty entry in default", def(good + ",, 'model' => 'mysql4'"), form("db.connection.default")},
		{"a value with no key in default", def(good + ", => 'mysql4'"), form("db.connection.default")},

		// host.
		{"no host", def(magentoRest), missing("host")},
		{"an empty host", host("''"), empty("host")},
		{"host from getenv", host("getenv('DB_HOST')"), notPlain("host")},
		{"host joined", host("'db.example' . '.test'"), notPlain("host")},
		{"host null", host("null"), notPlain("host")},
		{"host a number", host("127"), notPlain("host")},
		{"host an array", host("['db.example.test']"), notPlain("host")},
		{"host in parentheses", host("('db.example.test')"), notPlain("host")},
		{"host in a heredoc", host("<<<EOT\ndb.example.test\nEOT"), notPlain("host")},
		{"host in a nowdoc", host("<<<'EOT'\ndb.example.test\nEOT"), notPlain("host")},
		{"host with \\ in double quotes", host(`"db\x2eexample.test"`), notPlain("host")},
		{"host with $ in double quotes", host(`"db$suffix"`), notPlain("host")},
		{"host in backquotes", host("`hostname`"), notPlain("host")},
		{"host a binary string", host("b'db.example.test'"), notPlain("host")},
		{"host twice", def(good + ", \"host\" => 'evil.example.test'"), twice("host")},
		{"an IPv6 address", host("'::1'"), form("host")},
		{"an IPv6 address and a port", host("'[::1]:3306'"), form("host")},
		{"two colons", host("'db:3306:1'"), form("host")},
		{"no port after the colon", host("'db:'"), form("host")},
		{"no host before the colon", host("':3306'"), form("host")},
		{"port 0", host("'db:0'"), form("host")},
		{"port 65536", host("'db:65536'"), form("host")},
		{"a port with a sign", host("'db:+3306'"), form("host")},
		{"a negative port", host("'db:-1'"), form("host")},
		{"a port with letters", host("'db:33a'"), form("host")},
		{"a space before the port", host("'db: 3306'"), form("host")},
		{"a port too long", host("'db:99999999999999999999'"), form("host")},
		{"a Windows path", host(`'C:\mysql\mysql.sock'`), form("host")},

		// dbname, username and password.
		{"no dbname", with("'dbname' => 'shop', ", ""), missing("dbname")},
		{"an empty dbname", with("'shop'", "''"), empty("dbname")},
		{"dbname from getenv", with("'shop'", "getenv('DB_NAME')"), notPlain("dbname")},
		{"dbname twice", def(good + ", 'dbname' => 'other'"), twice("dbname")},
		{"no username", with("'username' => 'shop_ro', ", ""), missing("username")},
		{"an empty username", with("'shop_ro'", "''"), empty("username")},
		{"username null", with("'shop_ro'", "null"), notPlain("username")},
		{"username twice", def(good + ", 'username' => 'other'"), twice("username")},
		{"password null", with("'"+magentoPassword+"'", "null"), notPlain("password")},
		{"password from getenv", with("'"+magentoPassword+"'", "getenv('DB_PASSWORD')"), notPlain("password")},
		{"password with $ in double quotes", with("'"+magentoPassword+"'", `"pw$`+magentoCanary+`"`), notPlain("password")},
		{"password twice", def(good + ", 'password' => 'other'"), twice("password")},
		{"a password over two lines, whose CRLF Read made LF", with("'"+magentoPassword+"'", "'pw\n"+magentoCanary+"'"), lines("password")},
		{"a host over two lines", host("'db.example.test\n'"), lines("host")},

		// port.
		{"a port", def(good + ", 'port' => '3306'"), port},
		{"a port as a number", def(good + ", 'port' => 3306"), port},
		{"a port of null", def(good + ", 'port' => null"), port},
		{"a port twice", def(good + ", 'port' => '3306', 'port' => '3307'"), port},
		{"a port beside a host's port", def("'host' => 'db.example.test:3307', 'port' => '3307', " + magentoRest), port},

		// driver_options.
		{"driver options null", def(good + ", 'driver_options' => null"), options},
		{"driver options false", def(good + ", 'driver_options' => false"), options},
		{"driver options a string", def(good + ", 'driver_options' => '1014'"), options},
		{"driver options from a call", def(good + ", 'driver_options' => getenv('OPTIONS')"), options},
		{"driver options added to", def(good + ", 'driver_options' => [1014 => false] + []"), options},
		{"a CA file", def(good + ", 'driver_options' => [\\PDO::MYSQL_ATTR_SSL_CA => '/etc/ssl/ca.pem']"), options},
		{"a CA file by number", def(good + ", 'driver_options' => [1012 => '/etc/ssl/ca.pem']"), options},
		{"verification on", def(good + ", 'driver_options' => [1014 => true]"), options},
		{"verification off as 0", def(good + ", 'driver_options' => [1014 => 0]"), options},
		{"false as a string", def(good + ", 'driver_options' => [1014 => 'false']"), options},
		{"false with a namespace", def(good + ", 'driver_options' => [1014 => \\false]"), options},
		{"false with a long s, which Unicode folds to s", def(good + ", 'driver_options' => [1014 => fal\xc5\xbfe]"), options},
		{"false in parentheses", def(good + ", 'driver_options' => [1014 => (false)]"), options},
		{"an option of null", def(good + ", 'driver_options' => [1014 => null]"), options},
		{"an init command", def(good + ", 'driver_options' => [1002 => 'SET NAMES utf8mb4']"), options},
		{"a spread of options", def(good + ", 'driver_options' => [...$options]"), options},
		{"false, then a CA file", def(good + ", 'driver_options' => [1014 => false, 1012 => '/ca.pem']"), options},
		{"an empty option", def(good + ", 'driver_options' => [1014 => false,,]"), options},
		{"driver options twice", def(good + ", 'driver_options' => [], 'driver_options' => []"), twice("driver_options")},
		{"a unix_socket key, which PDO's DSN would take", def(good + ", 'unix_socket' => '/run/mysqld/mysqld.sock'"),
			prefix + "unix_socket is set, which prodmask doesn't read" + suffix},
		{"a relative socket path", host("'var/mysql.sock'"), form("host")},
		{"a / anywhere in a relative host, which Magento reads as a socket", host("'db.example.test:3306/x'"), form("host")},

		// What PDO's DSN would read as another server: Magento writes each
		// entry but the user, password and options into it as key=value,
		// joined by ;, and PDO takes the last of each key.
		{"a semicolon in the host", host("'db.example.test;port=3307'"), semicolon("host")},
		{"a semicolon in a socket's path", host("'/run/my;sql.sock'"), semicolon("host")},
		{"a semicolon in dbname", with("'shop'", "'shop;host=evil.example.test'"), semicolon("dbname")},
		{"initStatements naming another host", def(good + ", 'initStatements' => 'SET NAMES utf8;host=evil.example.test'"), server},
		{"a port after spaces and a doubled ;", def(good + ", 'model' => 'mysql4; ;; port=3307'"), server},
		{"a key naming another database", def(good + ", 'x;dbname=evil' => 1"), server},
		{"a key of host after a space", def(good + ", ' host' => 'evil.example.test'"), server},
		{"a key of dbname after a tab", def(good + ", '\tdbname' => 'evil'"), server},
		{"a key that sets host itself", def(good + ", 'host=evil.example.test;x' => 'y'"), server},
		{"a charset naming a socket", def(good + ", 'charset' => 'utf8;unix_socket=/tmp/evil.sock'"), server},
		{"a setting from getenv", def(good + ", 'initStatements' => getenv('INIT')"), server},
		{"a setting with an escape in double quotes", def(good + ", 'initStatements' => \"SET NAMES utf8\\x3bhost=evil\""), server},
		{"a setting from a constant", def(good + ", 'engine' => ENGINE"), server},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		_, err := readMagento([]byte(c.env))
		var refusal *Error
		if !errors.As(err, &refusal) {
			t.Errorf("%s: not a refusal: %v", c.name, err)
			continue
		}
		text := refusal.Error()
		seen[text] = true
		if text != c.want {
			t.Errorf("%s: %q, want %q", c.name, text, c.want)
		}
		if !slices.Contains(Messages(), text) {
			t.Errorf("%s: not in Messages: %q", c.name, text)
		}
		if strings.Contains(text, "Qz8") {
			t.Errorf("%s: shows the canary: %q", c.name, text)
		}
		for _, line := range strings.Split(c.env, "\n") {
			if line = strings.TrimSpace(line); len(line) >= 8 && strings.Contains(text, line) {
				t.Errorf("%s: shows the line %q: %q", c.name, line, text)
			}
		}
	}

	used := func(match func(string) bool) bool {
		for text := range seen {
			if match(text) {
				return true
			}
		}
		return false
	}
	for _, key := range magentoKeys {
		if !used(func(s string) bool { return strings.HasPrefix(s, prefix+key+" ") }) {
			t.Errorf("no row refuses %s", key)
		}
	}
	for _, reason := range magentoReasons {
		if !used(func(s string) bool { return strings.HasSuffix(s, " "+reason+suffix) }) {
			t.Errorf("no row refuses for %q", reason)
		}
	}
	for _, reason := range magentoFileReasons {
		if !seen[prefix+reason+suffix] {
			t.Errorf("no row refuses the file for %q", reason)
		}
	}
	if !seen[options] {
		t.Errorf("no row refuses driver options")
	}
}

// TestMagentoRead reads env.php through Read, with a BOM and CRLF line ends,
// which Read takes off first, into each kind of connection; and refuses one
// through Read without naming the folder.
func TestMagentoRead(t *testing.T) {
	for _, c := range []struct {
		host, net, addr   string
		socket, localhost bool
	}{
		{"db.example.test:3307", "tcp", "db.example.test:3307", false, false},
		{"localhost", "tcp", "localhost:3306", false, true},
		{"/run/mysqld/mysqld.sock", "unix", "/run/mysqld/mysqld.sock", true, false},
	} {
		dir := secretDir(t)
		env := magentoEnv("'host' => '" + c.host + "', " + magentoRest)
		write(t, dir, Magento, []byte("\xef\xbb\xbf"+strings.ReplaceAll(env, "\n", "\r\n")))
		p, err := Read(dir)
		if err != nil {
			t.Errorf("%s: %v", c.host, err)
			continue
		}
		cfg := p.Config
		if p.File != Magento || cfg.Net != c.net || cfg.Addr != c.addr || p.Socket != c.socket || p.Localhost != c.localhost ||
			cfg.User != "shop_ro" || cfg.Passwd != magentoPassword || cfg.DBName != "shop" {
			t.Errorf("%s: %s %s, socket %v, localhost %v, user %s, database %s",
				c.host, cfg.Net, cfg.Addr, p.Socket, p.Localhost, cfg.User, cfg.DBName)
		}
	}
	dir := secretDir(t)
	write(t, dir, Magento, []byte(magentoEnv(magentoRest)))
	want := "can't read the database from app/etc/env.php: host isn't set; pass --dsn instead"
	if _, err := Read(dir); err == nil || refusalText(t, dir, err) != want {
		t.Errorf("no host: %v", err)
	}
}

// TestMagentoTruncated reads every prefix of the installer's env.php short of
// its last ;, and each one refuses in words from Messages.
func TestMagentoTruncated(t *testing.T) {
	env := magentoInstalled()
	for i := 0; i <= strings.LastIndex(env, ";"); i++ {
		_, err := readMagento([]byte(env[:i]))
		var refusal *Error
		if !errors.As(err, &refusal) || !messageSet()[refusal.Error()] {
			t.Fatalf("cut after %d bytes: %v", i, err)
		}
	}
}
