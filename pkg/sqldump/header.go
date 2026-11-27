package sqldump

import "strings"

const maxFactLen = 40

var producerPrefixes = []string{
	"MySQL dump", "MariaDB dump", "phpMyAdmin SQL Dump", "Adminer",
	"Sequel Ace", "Sequel Pro",
}

// validFact reports whether s matches ^[A-Za-z0-9._-]{1,40}$, with spaces
// allowed too when spaces is set.
func validFact(s string, spaces bool) bool {
	if len(s) == 0 || len(s) > maxFactLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
		case c == ' ' && spaces:
		default:
			return false
		}
	}
	return true
}

// onComment is the lexer's hook for the comments at the top of the file.
func (r *reader) onComment(text []byte, line int) {
	if r.hdrSent || line > maxHeaderComment {
		return
	}
	parseHeaderLine(string(text), &r.hdr)
	if !r.flSet {
		r.fl, r.flSet = flavourOfLine(string(text))
	}
}

// sendHeader hands the header facts to the visitor, once.
func (r *reader) sendHeader() {
	if r.hdrSent {
		return
	}
	r.hdrSent = true
	r.lx.onComment = nil
	r.v.Header(r.hdr)
}

// parseHeaderLine reads one comment line for the facts it holds. A fact is
// kept only if it passes validFact; the first one found wins.
func parseHeaderLine(line string, h *Header) {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(line), "--"), "#"))
	if h.Producer == "" {
		for _, p := range producerPrefixes {
			if strings.HasPrefix(s, p) {
				if v := shortProducer(s); validFact(v, true) {
					h.Producer = v
				}
				break
			}
		}
		if strings.HasPrefix(s, "mysqldump-php") {
			h.Producer = "mysqldump-php"
		}
	}
	if h.Database == "" {
		if i := strings.Index(s, "Database:"); i >= 0 {
			if v := strings.Trim(strings.TrimSpace(s[i+len("Database:"):]), "`"); validFact(v, false) {
				h.Database = v
			}
		}
	}
	if h.ServerVersion == "" && strings.HasPrefix(s, "Server version") {
		if v := strings.TrimSpace(strings.TrimLeft(s[len("Server version"):], ": 	")); validFact(v, false) {
			h.ServerVersion = v
			h.MariaDB = strings.Contains(strings.ToLower(v), "mariadb")
		}
	}
}

// shortProducer gives the short form of a producer line: "mysqldump 8.4.3"
// for "MySQL dump 10.13  Distrib 8.4.3, for Linux", "mariadb-dump 11.8.2" for
// MariaDB's, and "phpMyAdmin" for "phpMyAdmin SQL Dump". A line without a
// distribution's version, from another tool, is its name and a version.
func shortProducer(s string) string {
	switch {
	case strings.HasPrefix(s, "phpMyAdmin SQL Dump"):
		return "phpMyAdmin"
	case strings.HasPrefix(s, "MySQL dump"), strings.HasPrefix(s, "MariaDB dump"):
		name := "mysqldump"
		if strings.HasPrefix(s, "MariaDB") {
			name = "mariadb-dump"
		}
		if i := strings.Index(s, "Distrib "); i >= 0 {
			v := s[i+len("Distrib "):]
			if j := strings.IndexAny(v, ", \t"); j >= 0 {
				v = v[:j]
			}
			if j := strings.Index(v, "-MariaDB"); j >= 0 {
				v = v[:j]
			}
			return name + " " + v
		}
		// MariaDB's own build writes "MariaDB dump 10.20-11.8.9-MariaDB".
		if name == "mariadb-dump" {
			if f := strings.Fields(s); len(f) >= 3 {
				if _, v, ok := strings.Cut(f[2], "-"); ok {
					v = strings.TrimSuffix(strings.TrimRight(v, ","), "-MariaDB")
					return name + " " + v
				}
			}
		}
	}
	// Any other producer is its name from the list and one version token; the
	// rest of the line is never kept.
	for _, p := range producerPrefixes {
		if !strings.HasPrefix(s, p) {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(s, p))
		if len(f) > 0 {
			if v := strings.TrimRight(f[0], ","); v != "" && v[0] >= '0' && v[0] <= '9' && validFact(v, false) {
				return p + " " + v
			}
		}
		return p
	}
	return ""
}
