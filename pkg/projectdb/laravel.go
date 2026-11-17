package projectdb

import (
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
)

// The keys .env's refusals name, and the reasons they give.
var (
	laravelKeys = []string{
		"DB_CONNECTION", "DB_HOST", "DB_PORT", "DB_DATABASE", "DB_USERNAME", "DB_PASSWORD", "DB_SOCKET",
		"DB_URL", "DATABASE_URL",
	}
	laravelReasons = []string{
		reasonMissing, reasonEmpty, reasonTwice, reasonForm,
		laravelNotMySQL, laravelExpands, laravelBackslash, reasonLines, laravelRewrites, laravelNotPort,
		laravelNoUser, laravelNoDatabase, laravelURLsDiffer, laravelBesideSocket, laravelOptions, laravelNoParse,
		laravelNotUTF8, laravelJSON, reasonSemicolon, laravelOldURL, laravelNewURL,
	}
	laravelFileReasons = []string{laravelVersions}
)

// The reasons only .env gives.
const (
	laravelNotMySQL     = "isn't mysql or mariadb"
	laravelExpands      = "uses ${...}, which prodmask doesn't expand"
	laravelBackslash    = "holds a backslash inside double quotes"
	laravelRewrites     = "is one of Laravel's special words, or quoted twice, which env() rewrites"
	laravelNotPort      = "isn't a port number"
	laravelNoUser       = "names no user"
	laravelNoDatabase   = "names no database"
	laravelURLsDiffer   = "differs from the other URL"
	laravelBesideSocket = "is set beside DB_SOCKET"
	laravelOptions      = "has options after ?, which Laravel reads as its own settings"
	laravelNoParse      = "doesn't parse"
	laravelNotUTF8      = "isn't valid UTF-8, which phpdotenv rewrites"
	laravelJSON         = "has a user, password or host that Laravel decodes as JSON"
	laravelVersions     = "phpdotenv versions differ on where a quoted value in it ends"
	laravelOldURL       = "doesn't match the separate keys, which a config/database.php from Laravel 11 on reads in its place"
	laravelNewURL       = "doesn't match the separate keys, which a config/database.php from before Laravel 11 reads in its place"
)

// laravelSSL is the key whose CA file Laravel's mysql and mariadb connections
// hand PDO. Anything in it but an empty value is refused with errTLS, which
// names no key, so it isn't in laravelKeys.
const laravelSSL = "MYSQL_ATTR_SSL_CA"

// readLaravel reads .env's database settings for the mysql and mariadb
// connections of Laravel's config/database.php, as phpdotenv 5.0 to 5.8 and
// env() hand them over. Where those versions could read the file differently,
// it refuses.
func readLaravel(data []byte) (*settings, error) {
	// phpdotenv ends a line at \r\n, \n or \r; the core has made \r\n into \n.
	lines := strings.Split(strings.ReplaceAll(string(data), "\r", "\n"), "\n")
	entries := dotenvEntries(lines, dotenv58)
	vals, err := laravelValues(entries)
	if err != nil {
		return nil, err
	}
	checked := dotenvChecked(entries)
	for _, v := range []dotenvVersion{dotenv50, dotenv55, dotenv57} {
		if !slices.Equal(dotenvChecked(dotenvEntries(lines, v)), checked) {
			return nil, fileError(Laravel, laravelVersions)
		}
	}
	// Laravel 11 on defaults to SQLite.
	if _, ok := vals["DB_CONNECTION"]; !ok {
		return nil, keyError(Laravel, "DB_CONNECTION", reasonMissing)
	}

	// A config/database.php from Laravel 11 on reads DB_URL, and one from
	// before DATABASE_URL, so the two must agree when both are in the file,
	// even empty.
	urlKey, rawURL := "DB_URL", vals["DB_URL"]
	_, hasNew := vals["DB_URL"]
	oldURL, hasOld := vals["DATABASE_URL"]
	switch {
	case !hasNew:
		urlKey, rawURL = "DATABASE_URL", oldURL
	case hasOld && oldURL != rawURL:
		return nil, keyError(Laravel, "DATABASE_URL", laravelURLsDiffer)
	}
	// MySqlConnector takes a socket that isn't empty() in PHP, and "0" is.
	socket := vals["DB_SOCKET"]
	if socket == "0" {
		socket = ""
	}
	if rawURL != "" {
		if socket != "" {
			return nil, keyError(Laravel, urlKey, laravelBesideSocket)
		}
		s, err := laravelURL(urlKey, rawURL, vals)
		if err != nil {
			return nil, err
		}
		// With one URL key alone, a config that reads the other key finds no
		// URL and reads the separate keys, with its own defaults. prodmask
		// can't tell which config the app has, so both must name the same
		// database.
		switch {
		case !hasOld && !laravelSameTarget(s, laravelSeparate(vals, "forge", "forge")):
			return nil, keyError(Laravel, "DB_URL", laravelNewURL)
		case !hasNew && !laravelSameTarget(s, laravelSeparate(vals, "laravel", "root")):
			return nil, keyError(Laravel, "DATABASE_URL", laravelOldURL)
		}
		return s, nil
	}

	s := &settings{socket: socket, password: vals["DB_PASSWORD"]}
	if socket != "" {
		switch {
		case strings.Contains(socket, ";"):
			return nil, keyError(Laravel, "DB_SOCKET", reasonSemicolon)
		case !absolute(socket):
			return nil, keyError(Laravel, "DB_SOCKET", reasonForm)
		}
	} else {
		host, ok := vals["DB_HOST"]
		switch {
		case !ok:
			return nil, keyError(Laravel, "DB_HOST", reasonMissing)
		case strings.Contains(host, ";"):
			return nil, keyError(Laravel, "DB_HOST", reasonSemicolon)
		}
		if s.port, err = laravelPort(vals); err != nil {
			return nil, err
		}
		s.host = host
	}
	for _, key := range []string{"DB_DATABASE", "DB_USERNAME"} {
		v, ok := vals[key]
		switch {
		case !ok:
			return nil, keyError(Laravel, key, reasonMissing)
		case v == "":
			return nil, keyError(Laravel, key, reasonEmpty)
		case key == "DB_DATABASE" && strings.Contains(v, ";"):
			return nil, keyError(Laravel, key, reasonSemicolon)
		}
	}
	s.database, s.user = vals["DB_DATABASE"], vals["DB_USERNAME"]
	return s, nil
}

// laravelValues reads the checked keys' values from phpdotenv's entries. A
// refusal about DB_CONNECTION comes first, so that an app on another database
// hears that before anything else; then the first in the file's order.
func laravelValues(entries []string) (map[string]string, error) {
	vals := map[string]string{}
	var connErr, firstErr error
	for _, entry := range entries {
		key, value, err := laravelDefine(entry)
		if key == "" {
			continue
		}
		if err == nil && key != laravelSSL {
			if _, ok := vals[key]; ok {
				err = keyError(Laravel, key, reasonTwice)
			}
			vals[key] = value
		}
		if err != nil && key == "DB_CONNECTION" && connErr == nil {
			connErr = err
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if connErr != nil {
		return nil, connErr
	}
	if conn, ok := vals["DB_CONNECTION"]; ok && conn != "mysql" && conn != "mariadb" {
		return nil, keyError(Laravel, "DB_CONNECTION", laravelNotMySQL)
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return vals, nil
}

// laravelDefine reads one entry. It returns the checked key the entry sets,
// with its value or its refusal, or "" for any other entry, which is skipped
// whatever its shape.
func laravelDefine(entry string) (key, value string, err error) {
	name, oldName, raw, hasValue := dotenvParts(entry)
	if !laravelChecked(name) {
		return "", "", nil
	}
	// A quoted name, or a form feed after "export", which phpdotenv before
	// 5.6.4 doesn't trim, makes the two names differ.
	plain := name == oldName
	lines := strings.Contains(entry, "\n")
	if name == laravelSSL {
		// A bare name unsets it, and env() hands an empty value on as empty.
		if v, err := dotenvValue(name, raw); plain && !lines && err == nil && v == "" {
			return name, "", nil
		}
		return name, "", errTLS(Laravel)
	}
	switch {
	case !plain || !hasValue:
		return name, "", keyError(Laravel, name, reasonForm)
	case lines:
		return name, "", keyError(Laravel, name, reasonLines)
	}
	value, err = dotenvValue(name, raw)
	return name, value, err
}

func laravelChecked(name string) bool {
	return name == laravelSSL || slices.Contains(laravelKeys, name)
}

// laravelSpecial reports a value env() rewrites: true, false, empty and null,
// bare or in brackets and in any case, or a value still in matching quotes.
func laravelSpecial(v string) bool {
	switch strings.ToLower(v) {
	case "true", "(true)", "false", "(false)", "empty", "(empty)", "null", "(null)":
		return true
	}
	return len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0]
}

// laravelURL reads the database from a URL as ConfigurationUrlParser does:
// its parts win over the separate keys, which fill in its port and password.
// PHP's parse_url refuses a URL with a user and no host, so that is refused
// here too, rather than filled in from DB_HOST.
func laravelURL(key, raw string, vals map[string]string) (*settings, error) {
	refuse := func(reason string) (*settings, error) { return nil, keyError(Laravel, key, reason) }
	// Laravel takes the driver from the scheme as it's written.
	if !strings.HasPrefix(raw, "mysql://") && !strings.HasPrefix(raw, "mariadb://") {
		return refuse(laravelNoParse)
	}
	if strings.Contains(raw, "?") {
		return refuse(laravelOptions)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return refuse(laravelNoParse)
	case u.User.Username() == "":
		return refuse(laravelNoUser)
	case u.Path == "" || u.Path == "/":
		return refuse(laravelNoDatabase)
	}
	if _, err := dbconn.ParseDSN(raw, ""); err != nil || u.Hostname() == "" {
		return refuse(laravelNoParse)
	}
	s := &settings{user: u.User.Username(), password: vals["DB_PASSWORD"], host: u.Hostname(), database: u.Path[1:]}
	password, hasPassword := u.User.Password()
	if hasPassword {
		s.password = password
	}
	if port := u.Port(); port != "" {
		n, ok := laravelPortNumber(port)
		if !ok {
			return refuse(laravelNoParse)
		}
		s.port = n
	} else if s.port, err = laravelPort(vals); err != nil {
		return nil, err
	}
	// json_decode sees parse_url's host, which keeps an IPv6 address's brackets.
	host := strings.TrimSuffix(u.Host, ":"+u.Port())
	if laravelDecodesJSON(s.user) || hasPassword && laravelDecodesJSON(password) || laravelDecodesJSON(host) {
		return refuse(laravelJSON)
	}
	if strings.Contains(s.host, ";") || strings.Contains(s.database, ";") {
		return refuse(reasonSemicolon)
	}
	return s, nil
}

// laravelSeparate is the connection config/database.php makes of the
// separate keys, with its defaults for the ones .env doesn't set. The
// database and user default to forge and forge in a config from before
// Laravel 11, and to laravel and root in one from 11 on; the rest to
// 127.0.0.1, 3306 and an empty password in both.
func laravelSeparate(vals map[string]string, database, user string) *settings {
	get := func(key, fallback string) string {
		if v, ok := vals[key]; ok {
			return v
		}
		return fallback
	}
	s := &settings{
		host: get("DB_HOST", "127.0.0.1"), database: get("DB_DATABASE", database),
		user: get("DB_USERNAME", user), password: get("DB_PASSWORD", ""),
	}
	if n, ok := laravelPortNumber(get("DB_PORT", "3306")); ok {
		s.port = n
	} else {
		s.port = -1 // a port no URL has, so the two never agree on it
	}
	return s
}

// laravelSameTarget reports whether two readings name the same connection.
func laravelSameTarget(a, b *settings) bool {
	port := func(p int) int {
		if p == 0 {
			return 3306
		}
		return p
	}
	return strings.EqualFold(a.host, b.host) && port(a.port) == port(b.port) && a.socket == b.socket &&
		a.user == b.user && a.password == b.password && a.database == b.database
}

// laravelDecodesJSON reports a URL part that ConfigurationUrlParser's
// json_decode changes: anything JSON reads but an integer written as PHP
// writes it back.
func laravelDecodesJSON(s string) bool {
	if !json.Valid([]byte(s)) {
		return false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return err != nil || strconv.FormatInt(n, 10) != s
}

// laravelPort reads DB_PORT, or 0, MySQL's default, when it isn't set.
func laravelPort(vals map[string]string) (int, error) {
	p, ok := vals["DB_PORT"]
	if !ok {
		return 0, nil
	}
	n, isPort := laravelPortNumber(p)
	if !isPort {
		return 0, keyError(Laravel, "DB_PORT", laravelNotPort)
	}
	return n, nil
}

// laravelPortNumber reads a port of one to five digits from 1 to 65535, which
// PHP's parse_url and PDO read alike.
func laravelPortNumber(p string) (int, bool) {
	n, err := strconv.Atoi(p)
	return n, err == nil && len(p) <= 5 && strings.Trim(p, "0123456789") == "" && n >= 1 && n <= 65535
}

// dotenvVersion picks how dotenvEntries groups lines, as phpdotenv's
// Lines::process has done since 5.0.
type dotenvVersion int

const (
	dotenv50 dotenvVersion = iota // 5.0 to 5.4: a line inside a value can start another
	dotenv55                      // 5.5 to 5.6
	dotenv57                      // 5.7: a # before =" starts nothing
	dotenv58                      // 5.8: a quote opening a line counts, and a value open at the end is kept
)

// dotenvTrim is what PHP's trim() takes off by default, and what phpdotenv
// passes it.
const dotenvTrim = " \t\n\r\x00\v"

// dotenvEntries groups lines into entries as Lines::process does. A line with
// =" and no closing quote starts a value that runs to the next line with a
// quote, and those lines make one entry, joined by "\n". Comment and blank
// lines are dropped only after that, so before 5.7 a quote in a comment can
// swallow lines too. A value still open at the end of the file is dropped with
// its lines, except by 5.8, which keeps it as the last entry.
func dotenvEntries(lines []string, v dotenvVersion) []string {
	var entries, value []string
	for _, line := range lines {
		starts := (value == nil || v == dotenv50) && dotenvStarts(line, v)
		if starts || value != nil {
			value = append(value, line)
			if !dotenvStops(line, starts, v) {
				continue
			}
			line, value = strings.Join(value, "\n"), nil
		}
		if t := strings.Trim(line, dotenvTrim); t != "" && t[0] != '#' {
			entries = append(entries, line)
		}
	}
	if value != nil && v == dotenv58 {
		entries = append(entries, strings.Join(value, "\n"))
	}
	return entries
}

// dotenvStarts is Lines::looksLikeMultilineStart.
func dotenvStarts(line string, v dotenvVersion) bool {
	at := strings.Index(line, `="`)
	if at < 0 {
		return false
	}
	if hash := strings.IndexByte(line, '#'); v >= dotenv57 && hash >= 0 && hash < at {
		return false
	}
	return !dotenvStops(line, true, v)
}

// dotenvStops is Lines::looksLikeMultilineStop: with each \\ taken out, the
// line has a quote with no backslash before it, or more than one on the line
// that started the value. Before 5.8 a quote opening the line doesn't count,
// though a line of just a quote stops.
func dotenvStops(line string, started bool, v dotenvVersion) bool {
	if line == `"` {
		return true
	}
	s := strings.ReplaceAll(line, `\\`, "")
	n := 0
	for i := range len(s) {
		if s[i] == '"' && (i > 0 && s[i-1] != '\\' || i == 0 && v == dotenv58) {
			n++
		}
	}
	if started {
		return n > 1
	}
	return n >= 1
}

// dotenvChecked returns the entries that set a checked key.
func dotenvChecked(entries []string) []string {
	var out []string
	for _, entry := range entries {
		if name, _, _, _ := dotenvParts(entry); laravelChecked(name) {
			out = append(out, entry)
		}
	}
	return out
}

// dotenvParts splits an entry as EntryParser does: at its first =, both sides
// trimmed, or all of it the name when it has no =. It returns the name as
// phpdotenv 5.6.4 on reads it, without "export" and quotes, and as earlier
// versions read it, which trim no form feed after "export"; it returns that
// one still quoted, so that the two differ for a quoted name too.
func dotenvParts(entry string) (name, oldName, raw string, hasValue bool) {
	name = entry
	if before, after, ok := strings.Cut(entry, "="); ok {
		name, raw, hasValue = strings.Trim(before, dotenvTrim), strings.Trim(after, dotenvTrim), true
	}
	oldName = name
	if len(name) > 6 && name[:6] == "export" && strings.IndexByte(" \t\n\r\v\f", name[6]) >= 0 {
		name, oldName = strings.TrimLeft(name[6:], " \t\n\r\v\f"), strings.TrimLeft(name[6:], dotenvTrim)
	}
	if len(name) >= 3 && (name[0] == '"' || name[0] == '\'') && name[len(name)-1] == name[0] {
		name = name[1 : len(name)-1]
	}
	return name, oldName, raw, hasValue
}

// dotenvValue reads a checked key's value, raw being its entry's text after
// the =, trimmed. It takes only the forms every phpdotenv 5 reads alike and
// env() hands on unchanged: unquoted with no #, whitespace or quote; single
// quotes, read literally; double quotes with no backslash. After a closing
// quote only whitespace and a comment may follow.
func dotenvValue(key, raw string) (string, error) {
	value, rest, expands := raw, "", true
	switch {
	case raw == "":
	case raw[0] == '\'':
		end := strings.IndexByte(raw[1:], '\'')
		if end < 0 {
			return "", keyError(Laravel, key, reasonForm)
		}
		value, rest, expands = raw[1:1+end], raw[2+end:], false
	case raw[0] == '"':
		end := strings.IndexAny(raw[1:], `"\`)
		switch {
		case end < 0:
			return "", keyError(Laravel, key, reasonForm)
		case raw[1+end] == '\\':
			return "", keyError(Laravel, key, laravelBackslash)
		}
		value, rest = raw[1:1+end], raw[2+end:]
	case strings.ContainsAny(raw, "#'\" \t\v\f"):
		return "", errUnquoted(key)
	}
	if rest = strings.TrimLeft(rest, " \t\v\f"); rest != "" && rest[0] != '#' {
		return "", keyError(Laravel, key, reasonForm)
	}
	switch {
	case expands && strings.Contains(value, "${"):
		return "", keyError(Laravel, key, laravelExpands)
	case !utf8.ValidString(value):
		// phpdotenv converts the file to UTF-8 first, so invalid bytes change.
		return "", keyError(Laravel, key, laravelNotUTF8)
	case laravelSpecial(value):
		return "", keyError(Laravel, key, laravelRewrites)
	}
	return value, nil
}
