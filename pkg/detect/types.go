package detect

import (
	"regexp"
	"strings"
)

// HiddenType stands for a polymorphic link's type value that can't be shown.
const HiddenType = "(type hidden)"

// Type values that reports may show: a class name or a plain word, such as
// App\Models\User, Admin::User or post. A dot doesn't join words, so a host
// name or a login such as john.smith never reads as one.
var reShownType = regexp.MustCompile(`^\\?[A-Za-z_][A-Za-z0-9_]*(?:(?:\\|::)[A-Za-z_][A-Za-z0-9_]*)*$`)

// ShowType is how a polymorphic link's type value, which is sampled from the
// data, may appear in reports and configs: as stored when it reads as a
// class name or a plain word and no part of it looks like data, and as
// HiddenType otherwise, such as for a URL that ends in a table's name. An
// empty value, a link with no type, stays empty.
func ShowType(v string) string {
	if v == "" {
		return ""
	}
	if len(v) > 128 || !reShownType.MatchString(v) {
		return HiddenType
	}
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == '\\' || r == ':' }) {
		if Template(part).Pattern != part {
			return HiddenType
		}
	}
	return v
}
