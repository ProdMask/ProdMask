package projectdb

import (
	"strings"
	"sync"
)

// Error is a refusal: fixed words that name the configuration file and the
// key it read, never a value, a line or a path. Every text it can hold is in
// Messages.
type Error struct{ text string }

func (e *Error) Error() string { return e.text }

// folder is how every message names the folder given to --project, which is
// never printed.
const folder = "the folder given to --project"

// Reasons several readers give for refusing a key, after its name.
const (
	reasonMissing   = "isn't set"
	reasonEmpty     = "is empty"
	reasonTwice     = "is set twice"
	reasonNotPlain  = "isn't one plain string (it isn't shown)"
	reasonForm      = "isn't in a form prodmask reads (it isn't shown)"
	reasonSemicolon = "holds a semicolon, which PDO reads as a separator"
	// reasonLines refuses a value over several lines: Read made the file's
	// CRLF line ends LF, so it may not be the value PHP reads.
	reasonLines = "runs over several lines"
)

// The texts of refusals that aren't about one key.
const (
	textNoFolder = "can't read " + folder
	textNone     = folder + " has no wp-config.php, app/etc/env.php or Laravel .env " +
		"(WordPress can keep wp-config.php one folder up; pass that folder)"
	textClientFlags = "wp-config.php sets MYSQL_CLIENT_FLAGS, which prodmask doesn't read; " +
		"pass --dsn instead (with ?tls=true if it asks for TLS)"
	textDriverOptions = "app/etc/env.php sets driver options prodmask doesn't read; pass --dsn instead (with ?tls=true if they ask for TLS)"
)

func errNoFolder() *Error { return &Error{textNoFolder} }

func errNone() *Error { return &Error{textNone} }

// errSeveral refuses a folder that holds more than one configuration, in
// files' fixed order.
func errSeveral(files []string) *Error {
	return refuse("", severalText(files))
}

func severalText(files []string) string {
	list := strings.Join(files, " and ")
	if len(files) > 2 {
		list = strings.Join(files[:len(files)-1], ", ") + " and " + files[len(files)-1]
	}
	return folder + " has " + list + "; pass --dsn instead"
}

func errUnreadable(file string) *Error {
	return refuse(file, "can't read "+file+" in "+folder)
}

func errTooBig(file string) *Error {
	return refuse(file, file+" is over 1 MiB, which is more than a config holds; pass --dsn instead")
}

func errNUL(file string) *Error {
	return refuse(file, file+" holds a NUL byte, so it isn't a config prodmask reads; pass --dsn instead")
}

// keyError refuses one key of a file for a reason, both from that file's
// lists.
func keyError(file, key, reason string) *Error {
	return refuse(file, keyText(file, key, reason))
}

func keyText(file, key, reason string) string {
	return "can't read the database from " + file + ": " + key + " " + reason + "; pass --dsn instead"
}

// fileError refuses a whole file for a reason from that file's list.
func fileError(file, reason string) *Error {
	return refuse(file, fileText(file, reason))
}

func fileText(file, reason string) string {
	return "can't read the database from " + file + ": " + reason + "; pass --dsn instead"
}

// errTLS refuses a configuration that asks for TLS settings.
func errTLS(file string) *Error {
	return refuse(file, tlsText(file))
}

func tlsText(file string) string {
	return file + " asks for TLS settings prodmask doesn't read; pass --dsn with ?tls=true instead"
}

// errUnquoted refuses a .env value that phpdotenv and Laravel could read
// differently: #, whitespace or a quote outside quotes.
func errUnquoted(key string) *Error {
	return refuse(Laravel, unquotedText(key))
}

func unquotedText(key string) string {
	return "can't read the database from .env: " + key + " holds #, whitespace or a quote outside quotes; quote it, or pass --dsn"
}

// fallbackText is what a refusal says when its own text isn't in Messages:
// a mistake in a reader, which then still shows nothing but fixed words.
func fallbackText(file string) string {
	if file == "" {
		return "can't read the database from " + folder + "; pass --dsn instead"
	}
	return "can't read the database from " + file + "; pass --dsn instead"
}

// refuse returns a refusal with text, when it's in Messages, and file's
// fallback otherwise, so no text outside the closed set can be returned.
func refuse(file, text string) *Error {
	if !messageSet()[text] {
		return &Error{fallbackText(file)}
	}
	return &Error{text}
}

var messageSet = sync.OnceValue(func() map[string]bool {
	set := map[string]bool{}
	for _, m := range Messages() {
		set[m] = true
	}
	return set
})

// The keys, key reasons and file reasons each file's refusals use. Each
// reader lists its own.
func refusalWords(file string) (keys, reasons, fileReasons []string) {
	switch file {
	case WordPress:
		return wordpressKeys, wordpressReasons, wordpressFileReasons
	case Laravel:
		return laravelKeys, laravelReasons, laravelFileReasons
	case Magento:
		return magentoKeys, magentoReasons, magentoFileReasons
	}
	return nil, nil, nil
}

// Messages returns every text a refusal from Read can hold. Each is built
// from fixed parts only: the three file names, the keys each reader knows,
// and fixed reasons.
func Messages() []string {
	files := []string{WordPress, Magento, Laravel}
	out := []string{textNoFolder, textNone, textClientFlags, textDriverOptions, fallbackText("")}
	for _, set := range [][]string{
		{WordPress, Magento}, {WordPress, Laravel}, {Magento, Laravel}, {WordPress, Magento, Laravel},
	} {
		out = append(out, severalText(set))
	}
	for _, file := range files {
		out = append(out,
			"can't read "+file+" in "+folder,
			file+" is over 1 MiB, which is more than a config holds; pass --dsn instead",
			file+" holds a NUL byte, so it isn't a config prodmask reads; pass --dsn instead",
			tlsText(file),
			fallbackText(file),
		)
		keys, reasons, fileReasons := refusalWords(file)
		for _, key := range keys {
			for _, reason := range reasons {
				out = append(out, keyText(file, key, reason))
			}
			if file == Laravel {
				out = append(out, unquotedText(key))
			}
		}
		for _, reason := range fileReasons {
			out = append(out, fileText(file, reason))
		}
	}
	return out
}
