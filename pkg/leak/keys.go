package leak

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// lookupOf turns a shown key into a lookup: a name, or a pattern with one *,
// at its end. Other patterns can't use the key's index.
func lookupOf(metaKey string) (sample.Lookup, bool) {
	switch n := strings.Count(metaKey, "*"); {
	case n == 0:
		return sample.Lookup{Key: metaKey, Limit: thinKey}, true
	case n == 1 && strings.HasSuffix(metaKey, "*"):
		return sample.Lookup{Key: strings.TrimSuffix(metaKey, "*"), Prefix: true, Limit: thinKey}, true
	}
	return sample.Lookup{}, false
}

// keyedExprs builds the select list that reads only flagged keys' values. The
// filter sits in the select list, not in WHERE, so each statement reads exactly
// the rows its LIMIT says and a rare key can't turn one into a long scan. Keys
// are bound arguments.
func keyedExprs(keyCol, valCol *model.Column, chars int, keys []string) (keyExpr, valueExpr string, args []any) {
	k := sample.QuoteIdent(keyCol.Name)
	var conds, inList []string
	var inArgs, likeArgs []any
	for _, key := range keys {
		if strings.Contains(key, "*") {
			conds = append(conds, k+" LIKE ? ESCAPE '!'")
			likeArgs = append(likeArgs, likePattern(key))
		} else {
			inList = append(inList, "?")
			inArgs = append(inArgs, key)
		}
	}
	if len(inList) > 0 {
		conds = append(conds, k+" IN ("+strings.Join(inList, ", ")+")")
	}
	cond := strings.Join(conds, " OR ")
	once := append(likeArgs, inArgs...)
	args = append(slices.Clone(once), once...)
	return fmt.Sprintf("IF(%s, %s, NULL)", cond, k),
		fmt.Sprintf("IF(%s, %s, NULL)", cond, sample.ValueExpr(valCol, chars)), args
}

// likePattern turns a shown pattern into LIKE ... ESCAPE '!'.
func likePattern(p string) string {
	return strings.ReplaceAll(strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(p), "*", "%")
}

func metaKeys(keys []*source) []string {
	out := make([]string, len(keys))
	for i, s := range keys {
		out[i] = s.metaKey
	}
	return out
}

// keyMatcher finds which of a list of shown keys a stored key is: by name, as
// the usual case-insensitive collations compare, or by a pattern.
type keyMatcher struct {
	exact    map[string]int
	patterns []keyPattern
}

type keyPattern struct {
	re       *regexp.Regexp
	i        int
	literals int
	text     string
}

func newKeyMatcher(keys []string) *keyMatcher {
	m := &keyMatcher{exact: map[string]int{}}
	for i, key := range keys {
		if !strings.Contains(key, "*") {
			m.exact[foldKey(key)] = i
			continue
		}
		parts := strings.Split(key, "*")
		for j, part := range parts {
			parts[j] = regexp.QuoteMeta(part)
		}
		m.patterns = append(m.patterns, keyPattern{regexp.MustCompile("(?is)^" + strings.Join(parts, ".*") + "$"), i,
			len(strings.ReplaceAll(key, "*", "")), key})
	}
	// The most literal pattern wins, whatever order the list came in: hash and
	// compare must give a stored key to the same one, and the lists' orders
	// differ, the findings' by severity and the file's by name.
	sort.Slice(m.patterns, func(a, b int) bool {
		if m.patterns[a].literals != m.patterns[b].literals {
			return m.patterns[a].literals > m.patterns[b].literals
		}
		return m.patterns[a].text < m.patterns[b].text
	})
	return m
}

func foldKey(k string) string { return strings.ToLower(strings.TrimRight(k, " ")) }

// match returns a stored key's place in the list, or -1.
func (m *keyMatcher) match(key string) int {
	if i, ok := m.exact[foldKey(key)]; ok {
		return i
	}
	for _, p := range m.patterns {
		if p.re.MatchString(key) {
			return p.i
		}
	}
	return -1
}
