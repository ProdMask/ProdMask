package fixture

import (
	"fmt"
	"sort"
	"strings"
)

// php serializes Go values the way PHP's serialize() does: strings, ints,
// bools, nil, ordered maps (kv) and lists.
func php(v any) string {
	switch x := v.(type) {
	case nil:
		return "N;"
	case bool:
		if x {
			return "b:1;"
		}
		return "b:0;"
	case int:
		return fmt.Sprintf("i:%d;", x)
	case int64:
		return fmt.Sprintf("i:%d;", x)
	case float64:
		return fmt.Sprintf("d:%g;", x)
	case string:
		return fmt.Sprintf("s:%d:\"%s\";", len(x), x)
	case []any:
		var b strings.Builder
		fmt.Fprintf(&b, "a:%d:{", len(x))
		for i, e := range x {
			b.WriteString(php(i))
			b.WriteString(php(e))
		}
		b.WriteString("}")
		return b.String()
	case kv:
		var b strings.Builder
		fmt.Fprintf(&b, "a:%d:{", len(x)/2)
		for i := 0; i+1 < len(x); i += 2 {
			b.WriteString(php(x[i]))
			b.WriteString(php(x[i+1]))
		}
		b.WriteString("}")
		return b.String()
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(kv, 0, 2*len(keys))
		for _, k := range keys {
			ordered = append(ordered, k, x[k])
		}
		return php(ordered)
	}
	panic(fmt.Sprintf("php: unsupported %T", v))
}

// kv is an ordered PHP array: key, value, key, value...
type kv []any
