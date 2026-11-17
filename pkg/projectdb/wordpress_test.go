package projectdb

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Canary values, built from pieces. No refusal may show one.
var (
	wpName = "shop" + "Qz8" + "db"
	wpUser = "app" + "Qz8" + "user"
	wpPass = "pw" + "Qz8" + "secret"
	wpHost = "db-" + "Qz8" + ".example.test"
	wpWant = settings{user: wpUser, password: wpPass, database: wpName, host: wpHost}
)

// wpDB is the four database defines, one a line, with the canary values.
func wpDB() string {
	return "define('DB_NAME', '" + wpName + "');\n" +
		"define('DB_USER', '" + wpUser + "');\n" +
		"define('DB_PASSWORD', '" + wpPass + "');\n" +
		"define('DB_HOST', '" + wpHost + "');\n"
}

// wpWith is a config whose define for key is replaced by line, or dropped
// when line is empty.
func wpWith(key, line string) string {
	var out []string
	for _, l := range strings.SplitAfter(wpDB(), "\n") {
		if strings.Contains(l, "'"+key+"'") {
			l = line
		}
		out = append(out, l)
	}
	return "<?php\n" + strings.Join(out, "")
}

type wpCase struct {
	name, src string
	want      settings // for a config that's read
	text      string   // for a refusal: its exact text
}

// wpReads are configs that are read.
func wpReads() []wpCase {
	db, std := wpDB(), wpWant
	fake := "define('DB_NAME', '" + "Qz8" + "fake');"
	pass := func(p string) settings { s := wpWant; s.password = p; return s }
	value := func(v string) string { return wpWith("DB_PASSWORD", "define('DB_PASSWORD', "+v+");\n") }
	call := func(form string) string { return "<?php\n" + strings.ReplaceAll(db, "define(", form) }
	return []wpCase{
		// Comments, strings and the text outside the tags hide a define.
		{name: "a // comment", src: "<?php\n// " + fake + "\n" + db, want: std},
		{name: "a # comment", src: "<?php\n# " + fake + "\n" + db, want: std},
		{name: "a /* */ comment", src: "<?php\n/* " + fake + " */\n" + db, want: std},
		{name: "a docblock over lines", src: "<?php\n/**\n * " + fake + "\n */\n" + db, want: std},
		{name: "quotes inside comments", src: "<?php\n// it's\n# don't\n/* that's all */\n" + db, want: std},
		{name: "?> inside a block comment", src: "<?php\n/* ?> " + fake + " */\n" + db, want: std},
		{name: "?> ends a // comment", src: "<?php // a comment ?>\n" + fake + "\n<?php\n" + db, want: std},
		{name: "?> ends a # comment", src: "<?php # a comment ?>" + fake + "<?php " + db, want: std},
		{name: "a lone CR ends a // comment", src: "<?php\n// a comment\r" + db, want: std},
		{name: "# [ with a space is a comment", src: "<?php\n# [Attr] " + fake + "\n" + db, want: std},
		{name: "text around the tags", src: fake + "\n<?php\n" + db + "?>\n" + fake + "\n", want: std},
		{name: "a single-quoted string", src: "<?php\n$a = '" + strings.ReplaceAll(fake, "'", `\'`) + "';\n" + db, want: std},
		{name: "a double-quoted string", src: "<?php\n$a = \"" + fake + "\";\n" + db, want: std},
		{name: "an escaped double quote", src: "<?php\n$a = \"\\\" " + fake + " \\\"\";\n" + db, want: std},
		{name: "a backtick string", src: "<?php\n$a = `" + fake + "`;\n" + db, want: std},
		{name: "a heredoc", src: "<?php\n$a = <<<EOT\n" + fake + "\nEOT;\n" + db, want: std},
		{name: "a quoted heredoc", src: "<?php\n$a = <<<\"EOT\"\n" + fake + "\nEOT;\n" + db, want: std},
		{name: "a nowdoc", src: "<?php\n$a = <<<'EOT'\n" + fake + "\nEOT;\n" + db, want: std},
		{name: "an indented closing name", src: "<?php\n$a = <<<EOT\n    " + fake + "\n    EOT;\n" + db, want: std},
		{name: "the heredoc's name mid-line or longer", src: "<?php\n$a = <<<EOT\nnot EOT;\nEOTX\n" + fake + "\nEOT;\n" + db, want: std},
		{name: "a quote inside an interpolation", src: "<?php\n$a = \"{$b[\"]); " + fake + " //\"]}\";\n" + db, want: std},
		{name: "an interpolation over lines in a heredoc", src: "<?php\n$a = <<<EOT\n{$b[\nEOT\n]} ${c} $d[e]\nEOT;\n" + db, want: std},
		{name: "__halt_compiler and data after it", src: "<?php\n" + db + "__halt_compiler();\n'" + fake + " /* {$", want: std},

		// The forms of define, and the values' quotes.
		{name: "DEFINE in capitals", src: call("DEFINE("), want: std},
		{name: "Define, spaced", src: call("Define ( "), want: std},
		{name: "a leading backslash", src: call(`\define(`), want: std},
		{name: "a backslash and mixed case", src: call(`\DeFiNe(`), want: std},
		{name: "comments inside the call", src: call("define /* c */ ( # c\n"), want: std},
		{name: "double quotes", src: "<?php\n" + strings.ReplaceAll(db, "'", `"`), want: std},
		{name: "a trailing comma", src: "<?php\n" + strings.ReplaceAll(db, "');", "',);"), want: std},
		{name: "?> ending a define", src: "<?php " + strings.ReplaceAll(db, ";\n", " ?>\n<p>between</p>\n<?php "), want: std},
		{name: "an escaped quote", src: value(`'it\'s'`), want: pass("it's")},
		{name: "an escaped backslash", src: value(`'a\\b'`), want: pass(`a\b`)},
		{name: "a backslash before the closing quote", src: value(`'end\\'`), want: pass(`end\`)},
		{name: "other backslashes stay", src: value(`'a\nb\t\x41\$c\"'`), want: pass(`a\nb\t\x41\$c\"`)},
		{name: "an empty password", src: value(`''`), want: pass("")},
		{name: "double quotes with no backslash or dollar", src: value(`"it's {plain}"`), want: pass("it's {plain}")},
		{name: "bytes that aren't UTF-8", src: value("'\xff\xfe'"), want: pass("\xff\xfe")},
		{name: "a lone CR in a value", src: value("'a\rb'"), want: pass("a\rb")},

		// Other statements, in any shape, are skipped.
		{name: "other defines in any shape", src: "<?php\ndefine('WP_DEBUG', getenv('WP_DEBUG'));\n" +
			"define('WP_HOME', 'https://' . $_SERVER['HTTP_HOST']);\ndefine('AUTH_KEY', $_ENV['KEY'] ?? 'x');\n" +
			"define('WP_A', 1, true);\n@define('WP_B', 'b');\nconst WP_C = 'c', WP_D = ['e' => 1];\n" + db, want: std},
		{name: "other keys in blocks and conditions", src: "<?php\nif (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/');\n" +
			"if (getenv('X')): define('WP_DEBUG', true); endif;\nfunction f() { define('WP_A', 1); }\n" +
			"defined('WP_B') || define('WP_B', 2);\n" + db, want: std},
		{name: "blocks before the defines", src: "<?php\nif ($a) { $b = 1; } elseif ($c) { $d = 2; } else { $e = 3; }\n" +
			"if ($a): $b = 1; elseif ($c): $d = 2; else: $e = 3; endif;\nwhile (false): endwhile;\n" +
			"foreach ($a as $b) $c = $b;\nfor ($i = 0; $i < 2; $i++): endfor;\nif ($a) if ($b) $c = 1; else $c = 2;\n" +
			"switch ($a) { case 1: break; default: $b = 1; }\nswitch ($a): case B::C: break; endswitch;\n" +
			"declare(strict_types=1);\ndo { $a--; } while ($a > 0);\n" +
			"try { $a = 1; } catch (Exception $e) { $a = 2; } finally { $a = 3; }\n" +
			"$f = function () use ($a) { return $a; };\n$g = fn($x) => $x * 2;\n$h = match ($a) { 1 => 'x', default => 'y' };\n" +
			"start:\n" + db, want: std},
		{name: "methods and classes called define or include", src: "<?php\nclass C { public function define($k, $v) {} " +
			"public function include() {} }\n$o = new C();\n$o->define('DB_NAME', 'x');\n$o?->include();\n" +
			"C::define('DB_USER', 'y');\n" + db, want: std},
		{name: "includes and eval after the defines", src: "<?php\n" + db + "include __DIR__ . '/extra.php';\n" +
			"eval('$a = 1;');\nrequire_once ABSPATH . 'wp-settings.php';\n", want: std},
		{name: "goto and calls through variables after the defines", src: "<?php\n" + db + "$f('x');\n$a['f']();\n" +
			"call_user_func('wp_x');\ngoto end;\nend:\n", want: std},
		{name: "a use statement that imports a class", src: "<?php\nuse Site\\Config;\n" + db, want: std},
		{name: "keywords as named arguments' labels", src: "<?php\nf(namespace: 1, goto: 2, include: 3, eval: 4);\n" + db, want: std},
		{name: "a statement in brackets after a block", src: "<?php\nif ($a) { $b = 1; }\n($c = 2);\n" + db, want: std},
		{name: "MYSQL_CLIENT_FLAGS only in a comment or a string", src: "<?php\n// define('MYSQL_CLIENT_FLAGS', 1);\n" +
			"$a = 'MYSQL_CLIENT_FLAGS';\nif (defined('MYSQL_CLIENT_FLAGS')) {}\n" + db, want: std},
		{name: "the echo tag and an uppercase open tag", src: "<?= 'hi' ?>\n<?PHP\n" + db, want: std},
		{name: "the keys in another order", src: "<?php\n" + strings.Join(reversed(strings.SplitAfter(db, "\n")), ""), want: std},
		{name: "a realistic wp-config.php", src: wpRealistic(), want: settings{user: wpUser, password: wpPass, database: wpName, host: "localhost"}},
	}
}

func reversed(s []string) []string {
	s = slices.Clone(s)
	slices.Reverse(s)
	return s
}

// wpRealistic is a wp-config.php as WordPress's installer and a host's
// panel leave it.
func wpRealistic() string {
	salt := "put your unique " + "phrase here"
	return `<?php
/**
 * The base configuration for WordPress.
 *
 * It's written by the installer; you can edit it by hand too.
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', '` + wpName + `' );

/** Database username */
define( 'DB_USER', '` + wpUser + `' );

/** Database password */
define( 'DB_PASSWORD', '` + wpPass + `' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 */
define( 'AUTH_KEY',         '` + salt + `' );
define( 'SECURE_AUTH_KEY',  '` + salt + `' );
define( 'NONCE_SALT',       '` + salt + `' );
/**#@-*/

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );
define( 'WP_DEBUG_LOG', getenv( 'WP_DEBUG_LOG' ) === 'true' );

/* Add any custom values between this line and the "stop editing" line. */
if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && 'https' === $_SERVER['HTTP_X_FORWARDED_PROTO'] ) {
	$_SERVER['HTTPS'] = 'on';
}
define( 'WP_HOME', 'https://' . $_SERVER['HTTP_HOST'] );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
`
}

// TestReadWordPress checks the configs that are read, and what is read from
// them.
func TestReadWordPress(t *testing.T) {
	for _, c := range wpReads() {
		s, err := readWordPress([]byte(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if *s != c.want {
			t.Errorf("%s: read %+v, want %+v", c.name, *s, c.want)
		}
	}
}

// wpRefusalText checks that err is a refusal whose text is in Messages and
// holds no canary, and returns the text.
func wpRefusalText(t *testing.T, name string, err error) string {
	t.Helper()
	var refusal *Error
	if !errors.As(err, &refusal) {
		t.Fatalf("%s: not a refusal: %#v", name, err)
	}
	text := refusal.Error()
	if !slices.Contains(Messages(), text) {
		t.Errorf("%s: not in Messages: %q", name, text)
	}
	if strings.Contains(strings.ToLower(text), "qz8") {
		t.Errorf("%s: shows a canary: %q", name, text)
	}
	return text
}

// wpKey and wpFile are the exact texts of a key's and the file's refusals.
func wpKey(key, reason string) string {
	return "can't read the database from wp-config.php: " + key + " " + reason + "; pass --dsn instead"
}

func wpFile(reason string) string {
	return "can't read the database from wp-config.php: " + reason + "; pass --dsn instead"
}

// wpRefusals are configs that are refused, each with its exact text.
func wpRefusals() []wpCase {
	db := wpDB()
	c := "Qz8" + "canary"
	q := "'" + c + "'"
	before := func(stmt string) string { return "<?php\n" + stmt + "\n" + db }
	flags := "wp-config.php sets MYSQL_CLIENT_FLAGS, which prodmask doesn't read; pass --dsn instead (with ?tls=true if it asks for TLS)"
	unended := wpFile("it ends inside a comment, a string or a heredoc")
	short := wpFile("it has a short open tag, which PHP reads as code only with short_open_tag on")
	include := wpFile("it includes another file before its database settings")
	dynamic := wpFile("it calls define with a name prodmask can't read")
	computed := wpFile("it calls a function through a variable or call_user_func before its database settings")
	attribute := wpFile("it has #[, which PHP 7 reads as a comment and PHP 8 as an attribute")
	namespace := wpFile("it declares a namespace or imports a function, so its define may not be PHP's")
	inBlock := func(key string) string { return wpKey(key, "is set inside a block or a condition") }
	notPlain := wpKey("DB_PASSWORD", "isn't one plain string (it isn't shown)")
	form := func(key string) string { return wpKey(key, "isn't in a form prodmask reads (it isn't shown)") }
	password := func(v string) string { return wpWith("DB_PASSWORD", "define('DB_PASSWORD', "+v+");\n") }
	return []wpCase{
		// The file can't be split into PHP's tokens.
		{name: "an unended /* comment", src: "<?php\n" + db + "/* " + c, text: unended},
		{name: "an unended single-quoted string", src: "<?php\n" + db + "$a = '" + c, text: unended},
		{name: "an escaped closing quote", src: "<?php\n" + db + "$a = '" + c + `\';`, text: unended},
		{name: "an unended double-quoted string", src: "<?php\n" + db + "$a = \"" + c, text: unended},
		{name: "an unended backtick", src: "<?php\n" + db + "$a = `" + c, text: unended},
		{name: "an unended heredoc", src: "<?php\n" + db + "$a = <<<EOT\n" + c + "\n", text: unended},
		{name: "an unended nowdoc", src: "<?php\n" + db + "$a = <<<'EOT'\n" + c + "\nEOTX;\n", text: unended},
		{name: "a heredoc's name at the very end", src: "<?php\n" + db + "$a = <<<EOT\n" + c + "\nEOT", text: unended},
		{name: "an unended interpolation", src: "<?php\n" + db + "$a = \"{$b[" + q, text: unended},
		{name: "?> inside an interpolation", src: "<?php\n" + db + "$a = \"{$b ?> " + c + "\";", text: unended},
		{name: "a short open tag", src: "<? define('DB_NAME', " + q + "); ?>\n<?php\n" + db, text: short},
		{name: "<?php run into a name", src: "<?phpinfo(); ?>\n<?php\n" + db, text: short},
		{name: "an attribute", src: before("#[A] define('DB_NAME', " + q + ");"), text: attribute},
		{name: "#[ hiding the defines from PHP 7", src: "<?php\n#[]; /*\n" + db + "// */\n", text: attribute},
		{name: "#[ after the defines", src: "<?php\n" + db + "#[Attr]\nfunction f() {}\n", text: attribute},

		// What could set a key before the defines, or set any key.
		{name: "an include before", src: before("include 'db-" + c + ".php';"), text: include},
		{name: "require_once in a condition before", src: before("if (file_exists($f)) { require_once $f; }"), text: include},
		{name: "REQUIRE between the defines", src: wpWith("DB_USER", "REQUIRE 'x.php';\ndefine('DB_USER', '"+wpUser+"');\n"), text: include},
		{name: "eval before", src: before("eval($code);"), text: wpFile("it runs eval before its database settings")},
		{name: "goto over the defines", src: "<?php\ngoto skip;\n" + db + "skip:\nrequire 'db-" + c + ".php';\n",
			text: wpFile("it uses goto before its database settings")},
		{name: "a call through a variable", src: before("$f('DB_NAME', " + q + ");"), text: computed},
		{name: "a call through an array element", src: before("$fns['d']('DB_NAME', " + q + ");"), text: computed},
		{name: "a call through ${}", src: before("${'f'}('DB_NAME', " + q + ");"), text: computed},
		{name: "call_user_func with a joined name", src: before("call_user_func('def' . 'ine', 'DB_NAME', " + q + ");"), text: computed},
		{name: "\\call_user_func_array", src: before("\\call_user_func_array($f, ['DB_NAME', " + q + "]);"), text: computed},
		{name: "a namespace with its own define", src: "<?php\nnamespace Site;\nfunction define($k, $v) {}\n" + db, text: namespace},
		{name: "a namespace after the defines", src: "<?php\n" + db + "namespace Site;\n", text: namespace},
		{name: "use function", src: before("use function Site\\define;"), text: namespace},
		{name: "a group use that imports a function", src: before("use Site\\{Config, function define};"), text: namespace},
		{name: "settings from another file", src: "<?php\nif (is_readable($f) && !defined('DB_USER')) {\n\trequire_once($f);\n}\n" +
			"require_once ABSPATH . 'wp-settings.php';\n", text: include},
		{name: "a define with a variable name", src: before("define($k, " + q + ");"), text: dynamic},
		{name: "a define with a joined name", src: before("define('DB_' . 'NAME', " + q + ");"), text: dynamic},
		{name: "a define with named arguments", src: before("define(constant_name: 'DB_NAME', value: " + q + ");"), text: dynamic},
		{name: "define as a callback", src: before("array_map('define', $keys, $values);"), text: dynamic},
		{name: "\\DEFINE as a callback", src: before(`call_user_func('\\DEFINE', 'DB_NAME', ` + q + ");"), text: dynamic},
		{name: "a variable define after the defines", src: "<?php\n" + db + "foreach ($env as $k => $v) define($k, $v);\n", text: dynamic},
		{name: "MYSQL_CLIENT_FLAGS", src: before("define('MYSQL_CLIENT_FLAGS', MYSQLI_CLIENT_SSL);"), text: flags},
		{name: "MYSQL_CLIENT_FLAGS in a condition after", src: "<?php\n" + db + "if ($tls) define('MYSQL_CLIENT_FLAGS', 2048);\n", text: flags},
		{name: "MYSQL_CLIENT_FLAGS with const", src: before("const MYSQL_CLIENT_FLAGS = 2048;"), text: flags},
		{name: "MYSQL_CLIENT_FLAGS in another case", src: before(`\define("mysql_client_flags", '2048');`), text: flags},

		// One key, set where or how it isn't read.
		{name: "set twice", src: "<?php\n" + db + "define('DB_NAME', " + q + ");", text: wpKey("DB_NAME", "is set twice")},
		{name: "set twice, once with a backslash", src: "<?php\n" + db + `\define('DB_USER', ` + q + ");", text: wpKey("DB_USER", "is set twice")},
		{name: "inside braces", src: before("{ define('DB_NAME', " + q + "); }"), text: inBlock("DB_NAME")},
		{name: "a braceless if", src: before("if ($x) define('DB_USER', " + q + ");"), text: inBlock("DB_USER")},
		{name: "else", src: before("if ($x) {} else define('DB_PASSWORD', " + q + ");"), text: inBlock("DB_PASSWORD")},
		{name: "elseif", src: before("if ($x) {} elseif ($y) define('DB_HOST', " + q + ");"), text: inBlock("DB_HOST")},
		{name: "else if", src: before("if ($x) {} else if ($y) define('DB_NAME', " + q + ");"), text: inBlock("DB_NAME")},
		{name: "defined() ||", src: before("defined('DB_NAME') || define('DB_NAME', " + q + ");"), text: inBlock("DB_NAME")},
		{name: "or", src: before("defined('DB_NAME') or define('DB_NAME', " + q + ");"), text: inBlock("DB_NAME")},
		{name: "a ternary", src: before("$x ? define('DB_NAME', " + q + ") : null;"), text: inBlock("DB_NAME")},
		{name: "an assignment", src: before("$ok = define('DB_NAME', " + q + ");"), text: inBlock("DB_NAME")},
		{name: "an alternative-syntax if", src: before("if ($x): define('DB_NAME', " + q + "); endif;"), text: inBlock("DB_NAME")},
		{name: "an alternative-syntax else", src: before("if ($x): else: define('DB_NAME', " + q + "); endif;"), text: inBlock("DB_NAME")},
		{name: "an alternative-syntax elseif", src: before("if ($x): elseif ($y): define('DB_NAME', " + q + "); endif;"), text: inBlock("DB_NAME")},
		{name: "a nested alternative syntax", src: before("if ($x): while ($y): endwhile; define('DB_NAME', " + q + "); endif;"), text: inBlock("DB_NAME")},
		{name: "a while body", src: before("while ($x) define('DB_NAME', " + q + ");"), text: inBlock("DB_NAME")},
		{name: "a for body", src: before("for ($i = 0; $i < 1; $i++) define('DB_NAME', " + q + ");"), text: inBlock("DB_NAME")},
		{name: "a foreach block", src: before("foreach ($a as $b): define('DB_NAME', " + q + "); endforeach;"), text: inBlock("DB_NAME")},
		{name: "a switch", src: before("switch ($x) { case 1: define('DB_NAME', " + q + "); }"), text: inBlock("DB_NAME")},
		{name: "an alternative-syntax switch", src: before("switch ($x): case 1: define('DB_NAME', " + q + "); endswitch;"), text: inBlock("DB_NAME")},
		{name: "a declare body", src: before("declare(ticks=1) define('DB_NAME', " + q + ");"), text: inBlock("DB_NAME")},
		{name: "a do body", src: before("do define('DB_NAME', " + q + "); while (false);"), text: inBlock("DB_NAME")},
		{name: "a try block", src: before("try { define('DB_NAME', " + q + "); } catch (Error $e) {}"), text: inBlock("DB_NAME")},
		{name: "a function body", src: before("function f() { define('DB_NAME', " + q + "); }"), text: inBlock("DB_NAME")},
		{name: "a closure", src: before("$f = function () { define('DB_NAME', " + q + "); };"), text: inBlock("DB_NAME")},
		{name: "an arrow function", src: before("$f = fn() => define('DB_NAME', " + q + ");"), text: inBlock("DB_NAME")},
		{name: "inside an interpolation", src: before("$a = \"{$b[define('DB_NAME', " + q + ")]}\";"), text: inBlock("DB_NAME")},
		{name: "a braced namespace", src: before("namespace { define('DB_NAME', " + q + "); }"), text: namespace},
		{name: "const", src: before("const DB_PASSWORD = " + q + ";"), text: wpKey("DB_PASSWORD", "is set with const")},
		{name: "const in a list", src: before("const A = [1, 2], DB_HOST = " + q + ";"), text: wpKey("DB_HOST", "is set with const")},
		{name: "a class constant", src: before("class C { const DB_USER = " + q + "; }"), text: wpKey("DB_USER", "is set with const")},
		{name: "@define", src: before("@define('DB_NAME', " + q + ");"), text: wpKey("DB_NAME", "is set with @define")},
		{name: "a third argument", src: wpWith("DB_HOST", "define('DB_HOST', "+q+", true);\n"), text: wpKey("DB_HOST", "has a third argument")},
		{name: "getenv()", src: password("getenv(" + q + ")"), text: notPlain},
		{name: "getenv_docker()", src: password("getenv_docker('WORDPRESS_DB_PASSWORD', " + q + ")"), text: notPlain},
		{name: "$_ENV", src: password("$_ENV[" + q + "]"), text: notPlain},
		{name: "a constant", src: password(strings.ToUpper(c)), text: notPlain},
		{name: "concatenation", src: password("'a' . " + q), text: notPlain},
		{name: "a number", src: password("3306"), text: notPlain},
		{name: "a heredoc value", src: password("<<<EOT\n" + c + "\nEOT\n"), text: notPlain},
		{name: "a nowdoc value", src: password("<<<'EOT'\n" + c + "\nEOT\n"), text: notPlain},
		{name: "double quotes holding a backslash", src: password(`"` + c + `\n"`), text: notPlain},
		{name: "double quotes holding $", src: password(`"$` + c + `"`), text: notPlain},
		{name: "a backtick value", src: password("`" + c + "`"), text: notPlain},
		{name: "a binary string", src: password("b" + q), text: notPlain},
		{name: "brackets around the value", src: password("(" + q + ")"), text: notPlain},
		{name: "a fallback", src: password("$x ?: " + q), text: notPlain},
		{name: "a value over several lines", src: password("'a\n" + c + "'"), text: wpKey("DB_PASSWORD", "runs over several lines")},
		{name: "no value", src: wpWith("DB_NAME", "define('DB_NAME');\n"), text: form("DB_NAME")},
		{name: "more after the call", src: wpWith("DB_NAME", "define('DB_NAME', "+q+") or die();\n"), text: form("DB_NAME")},
		{name: "a namespaced define", src: wpWith("DB_NAME", `Foo\define('DB_NAME', `+q+");\n"), text: form("DB_NAME")},
		{name: "namespace\\define", src: wpWith("DB_NAME", `namespace\define('DB_NAME', `+q+");\n"), text: form("DB_NAME")},
		{name: "a lowercase lookalike", src: before("define('db_name', " + q + ");"), text: form("DB_NAME")},
		{name: "a backslashed lookalike", src: before(`define('\\DB_NAME', ` + q + ");"), text: form("DB_NAME")},
		{name: "a host prodmask doesn't read", src: wpWith("DB_HOST", "define('DB_HOST', 'p:"+c+"');\n"), text: form("DB_HOST")},

		// A key that's missing or empty.
		{name: "no DB_NAME", src: wpWith("DB_NAME", ""), text: wpKey("DB_NAME", "isn't set")},
		{name: "no DB_USER", src: wpWith("DB_USER", ""), text: wpKey("DB_USER", "isn't set")},
		{name: "no DB_PASSWORD", src: wpWith("DB_PASSWORD", ""), text: wpKey("DB_PASSWORD", "isn't set")},
		{name: "no DB_HOST", src: wpWith("DB_HOST", ""), text: wpKey("DB_HOST", "isn't set")},
		{name: "an empty file", src: "", text: wpKey("DB_NAME", "isn't set")},
		{name: "no PHP tags", src: db, text: wpKey("DB_NAME", "isn't set")},
		{name: "__halt_compiler before", src: before("__halt_compiler();"), text: wpKey("DB_NAME", "isn't set")},
		{name: "an empty DB_NAME", src: wpWith("DB_NAME", "define('DB_NAME', '');\n"), text: wpKey("DB_NAME", "is empty")},
		{name: "an empty DB_USER", src: wpWith("DB_USER", "define('DB_USER', \"\");\n"), text: wpKey("DB_USER", "is empty")},
	}
}

// TestReadWordPressRefusals checks each refusal's exact text, that it's in
// Messages and shows no canary, and that some config gives every reason
// wp-config.php lists.
func TestReadWordPressRefusals(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range wpRefusals() {
		s, err := readWordPress([]byte(c.src))
		if err == nil {
			t.Errorf("%s: read %+v, want a refusal", c.name, *s)
			continue
		}
		text := wpRefusalText(t, c.name, err)
		if text != c.text {
			t.Errorf("%s: %q, want %q", c.name, text, c.text)
		}
		seen[text] = true
	}
	for _, reason := range wordpressFileReasons {
		if !seen[wpFile(reason)] {
			t.Errorf("no config gives %q", reason)
		}
	}
	for _, reason := range wordpressReasons {
		given := false
		for _, key := range wordpressKeys {
			given = given || seen[wpKey(key, reason)]
		}
		if !given {
			t.Errorf("no config gives %q", reason)
		}
	}
}

// TestWordPressHost checks DB_HOST's forms, read as wpdb::parse_db_host and
// mysqli read them, and the ones refused.
func TestWordPressHost(t *testing.T) {
	sock := "/var/run/mysqld/mysqld.sock"
	for _, c := range []struct {
		v      string
		host   string
		port   int
		socket string
		ok     bool
	}{
		{"localhost", "localhost", 0, "", true},
		{"", "", 0, "", true},
		{"db.example.test", "db.example.test", 0, "", true},
		{"db.example.test:3307", "db.example.test", 3307, "", true},
		{"127.0.0.1", "127.0.0.1", 0, "", true},
		{"127.0.0.1:03307", "127.0.0.1", 3307, "", true},
		{"localhost:3307", "localhost", 3307, "", true},
		{":3307", "", 3307, "", true},
		{"0", "", 0, "", true},
		{"0:3307", "", 3307, "", true},
		{"db:0", "db", 0, "", true},
		{"db:00", "db", 0, "", true},
		{"db:65535", "db", 65535, "", true},
		{":" + sock, "", 0, sock, true},
		{"localhost:" + sock, "", 0, sock, true},
		{"LocalHost:" + sock, "", 0, sock, true},
		{"localhost:3307:" + sock, "", 0, sock, true},
		{"0:" + sock, "", 0, sock, true},
		{"localhost:/a:/b", "", 0, "/a:/b", true},
		{"127.0.0.1:" + sock, "127.0.0.1", 0, "", true},
		{"db.example.test:3307:" + sock, "db.example.test", 3307, "", true},
		{"[::1]", "::1", 0, "", true},
		{"[::1]:3307", "::1", 3307, "", true},
		{"::1", "::1", 0, "", true},
		{"fe80::1", "fe80::1", 0, "", true},
		{"[2001:DB8::1]:3307", "2001:DB8::1", 3307, "", true},
		{"[::1]:" + sock, "::1", 0, "", true},
		{"[::1]:3307:" + sock, "::1", 3307, "", true},
		{"::1:" + sock, "::1", 0, "", true},
		{"::1:3307", "::1:3307", 0, "", true}, // an address, as WordPress reads it, not a port

		{"p:localhost", "", 0, "", false},
		{"P:db.example.test", "", 0, "", false},
		{"p:3306", "", 0, "", false},
		{"db:", "", 0, "", false},
		{"db:abc", "", 0, "", false},
		{"db:3306abc", "", 0, "", false},
		{"db:+3306", "", 0, "", false},
		{"db:-1", "", 0, "", false},
		{"db:65536", "", 0, "", false},
		{"db:0000065536", "", 0, "", false},
		{"db:99999999999999999999", "", 0, "", false},
		{"db/x", "", 0, "", false},
		{"[db]", "", 0, "", false},
		{"[db]:3306", "", 0, "", false},
		{"[]", "", 0, "", false},
		{"[::1", "", 0, "", false},
		{"::1]", "", 0, "", false},
		{"[::1]x", "", 0, "", false},
		{"[::1]:", "", 0, "", false},
		{"[::1]:x", "", 0, "", false},
		{"[::1]:65536", "", 0, "", false},
		{"1:2:3", "", 0, "", false},
		{"db:3306:x", "", 0, "", false},
		{"db.example.test:3306:", "", 0, "", false},
		{"fe80::1%eth0", "", 0, "", false},
		{"::ffff:1.2.3.4", "", 0, "", false},
		{"[::1]:3306abc", "", 0, "", false},
	} {
		host, port, socket, ok := wordpressHost(c.v)
		if host != c.host || port != c.port || socket != c.socket || ok != c.ok {
			t.Errorf("%q: %q %d %q %v, want %q %d %q %v", c.v, host, port, socket, ok, c.host, c.port, c.socket, c.ok)
		}
	}

	// Through the reader, a socket and an IPv6 address reach the settings.
	for v, want := range map[string]settings{
		"localhost:" + sock: {socket: sock},
		"[::1]:3307":        {host: "::1", port: 3307},
	} {
		s, err := readWordPress([]byte(wpWith("DB_HOST", "define('DB_HOST', '"+v+"');\n")))
		if err != nil || s.host != want.host || s.port != want.port || s.socket != want.socket {
			t.Errorf("%q: %+v, %v", v, s, err)
		}
	}
}
