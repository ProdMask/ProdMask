package detect

import (
	"regexp"
	"strings"
)

// Value shapes that back or rule out a name: hardware IDs, email addresses
// inside URLs, URLs and paths, cryptocurrency addresses, and template tags.

var (
	reUUIDValue = regexp.MustCompile(`^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$`)
	reHexGroups = regexp.MustCompile(`^[0-9a-fA-F]+(?:[-:][0-9a-fA-F]+)*$`)
	reIMEI      = regexp.MustCompile(`^\d{14,16}$`)
	reB64Token  = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,}$`)

	reBitcoin  = regexp.MustCompile(`^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})$`)
	reEthereum = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

	// Merge tags: the fields form and mail plugins fill in. [word-word],
	// [_word], {word}, {{word}} and %word% always are; a bare [word] is
	// unless the value also closes it as BBCode does ([b]…[/b]).
	reMergeTag  = regexp.MustCompile(`\[[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)+\]|\[_[A-Za-z0-9_]+\]|\{\{\s*[\w.-]+\s*\}\}|\{[\w.-]+\}|%[\w.-]+%`)
	reBareTag   = regexp.MustCompile(`\[([A-Za-z0-9]+)\]`)
	rePercent40 = regexp.MustCompile(`(?i)%40`)
)

// opaque reports whether a value looks like a hardware or device ID: a
// UUID or GUID, 12 or more hex digits in groups or not, an IMEI's 14 to 16
// digits, a base64 token mixing letters and digits, or such parts joined
// by |.
func opaque(t string) bool {
	if strings.Contains(t, "|") {
		parts := strings.Split(t, "|")
		for _, p := range parts {
			if !opaque(p) {
				return false
			}
		}
		return len(parts) > 1
	}
	switch {
	case reUUIDValue.MatchString(t), reIMEI.MatchString(t):
		return true
	case reHexGroups.MatchString(t) && countHex(t) >= 12:
		return true
	case reB64Token.MatchString(t):
		return countLetters(t) >= 3 && countDigits(t) >= 3
	}
	return false
}

// Push notification tokens: Firebase Cloud Messaging registration tokens
// and Expo push tokens. They name one app on one device.
var (
	reFCMToken  = regexp.MustCompile(`^[A-Za-z0-9_-]{11,}:APA91b[A-Za-z0-9_-]{100,}$`)
	reExpoToken = regexp.MustCompile(`^Expo(?:nent)?PushToken\[[A-Za-z0-9_-]{20,}\]$`)
)

func pushToken(t string) bool {
	return strings.Contains(t, ":APA91b") && reFCMToken.MatchString(t) ||
		strings.HasPrefix(t, "Expo") && reExpoToken.MatchString(t)
}

func countHex(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			n++
		}
	}
	return n
}

// urlLike reports whether a value is a URL or a path.
func urlLike(t string) bool {
	l := strings.ToLower(t)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "www.") ||
		strings.HasPrefix(t, "/") || strings.Contains(t, "://")
}

// cryptoAddress reports whether a value is a Bitcoin or Ethereum address.
func cryptoAddress(t string) bool { return reBitcoin.MatchString(t) || reEthereum.MatchString(t) }

// mailtoEmail returns the address of a mailto: link that holds one.
func mailtoEmail(t string) (string, bool) {
	if len(t) > 7 && strings.EqualFold(t[:7], "mailto:") && IsEmail(t[7:]) {
		return t[7:], true
	}
	return "", false
}

// inlineEmail reports whether a value with no spaces, which isn't itself an
// email address, carries one: after the host of a URL (in its path, query
// or fragment), in a query string, or in a path. User info before a host
// (mysql://app:pw@db.example.com, ssh://git@host) isn't one, nor are
// scp-style git@github.com:org/repo.git and message IDs.
func inlineEmail(t string) bool {
	if strings.ContainsAny(t, " \t\n") || !strings.Contains(t, "@") && !rePercent40.MatchString(t) {
		return false
	}
	t = rePercent40.ReplaceAllString(t, "@")
	if i := strings.Index(t, "://"); i >= 0 {
		rest := t[i+3:]
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			return false
		}
		return containsEmail(rest[end:])
	}
	if strings.HasPrefix(t, "/") || strings.HasPrefix(t, "?") || strings.Contains(t, "=") {
		return containsEmail(t)
	}
	return false
}

// mergeTag reports whether a value holds a template's merge tag.
func mergeTag(t string) bool {
	if reMergeTag.MatchString(t) {
		return true
	}
	lower := strings.ToLower(t)
	for _, m := range reBareTag.FindAllStringSubmatch(t, 16) {
		if !strings.Contains(lower, "[/"+strings.ToLower(m[1])+"]") {
			return true
		}
	}
	return false
}
