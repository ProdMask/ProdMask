package detect

// Run-together names such as regip or loginkey: a lead word and a data
// word written without a separator. Tokens already splits a few common ones
// through compounds (ipaddress, useragent); these lists cover the rest.
var (
	// splitData lists the words that end a run-together name.
	splitData = words("ip ips email emails mail name names phone phones login pass password key token secret " +
		"salt addr agent number")
	// splitLead lists the words that may come before them.
	splitLead = words(
		// people and roles
		"user member poster author admin visitor sender summoner player account contact customer company client " +
			"consumer root " +
			// time and order
			"reg signup last first current new old " +
			// where from
			"origin source src dst dest real remote home billing shipping " +
			// access
			"login auth api access app session device " +
			// services
			"smtp mail email ftp sftp ssh proxy imap pop db cc")
)

// ruleWords holds the words the naming rules already know: every word of
// their alternatives, and the compounds. They are never split.
var ruleWords = func() map[string]bool {
	m := map[string]bool{}
	for _, r := range nameRules {
		if r.keepOut {
			continue
		}
		for _, alt := range r.alts {
			for _, w := range alt {
				m[w] = true
			}
		}
	}
	for k := range compounds {
		m[k] = true
	}
	return m
}()

// NameWords splits a name that is being judged into words, as Tokens does,
// and also splits run-together words: regip (reg, ip), loginkey (login,
// key), lastloginip (last, login, ip). Only judged names go through it;
// table names, path context, key templates and relationship inference keep
// the words Tokens gives.
func NameWords(name string) []string {
	toks := Tokens(name)
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		out = append(out, splitRunTogether(t)...)
	}
	return out
}

// splitRunTogether splits a word of 5 or more letters that no rule knows
// into lead words and a final data word, two or three parts in all.
func splitRunTogether(t string) []string {
	if len(t) < 5 || ruleWords[t] || !lowerLetters(t) {
		return []string{t}
	}
	for i := 1; i < len(t); i++ {
		if splitLead[t[:i]] && splitData[t[i:]] {
			return []string{t[:i], t[i:]}
		}
	}
	for i := 1; i < len(t); i++ {
		if !splitLead[t[:i]] {
			continue
		}
		for j := i + 1; j < len(t); j++ {
			if splitLead[t[i:j]] && splitData[t[j:]] {
				return []string{t[:i], t[i:j], t[j:]}
			}
		}
	}
	return []string{t}
}

func lowerLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return s != ""
}
