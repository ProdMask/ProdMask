package detect

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// Hint is what a platform preset knows about a column or meta key.
type Hint struct {
	Category model.Category
	Severity model.Severity // zero means the category default
	Mask     string
	Rows     []model.RowMask // other masks for some rows of the column
	Note     string
	Source   string // e.g. "preset:woocommerce"
	Ignore   bool   // known not to hold personal data
}

// Subject is one column, or one key of a key/value table, to judge.
type Subject struct {
	Table    string
	Column   string
	MetaKey  string
	Name     string   // the name to judge: the column name or the meta key
	DataType string   // information_schema DATA_TYPE; empty for meta keys
	Context  []string // words of the table name
	Hint     *Hint
	Sampled  bool // false when values were not read (--no-samples)
}

// maxPathFindings caps the findings reported for paths inside one column.
const maxPathFindings = 25

// Analyze judges one subject from its name and the profile of its sampled
// values. p is nil when no values were read.
func Analyze(sub Subject, p *Profile) []model.Finding {
	if sub.Hint != nil && sub.Hint.Ignore {
		return nil
	}
	tc := tStr
	if sub.DataType != "" {
		tc = classOf(sub.DataType)
	}
	tokens := Tokens(sub.Name)
	var nm *NameMatch
	source := "name"
	if h := sub.Hint; h != nil && h.Category != "" {
		nm = &NameMatch{Category: h.Category, Severity: h.Severity, Note: h.Note}
		source = h.Source
	} else {
		nm = MatchName(tokens, sub.Context, tc)
	}
	base := model.Finding{Table: sub.Table, Column: sub.Column, MetaKey: sub.MetaKey}
	out := judge(base, nm, source, tokens, p, sub.Sampled, sub.Hint)
	if p != nil && len(p.Paths) > 0 {
		paths := judgePaths(base, sub.Context, p)
		// When the values are mostly JSON or serialized data, the paths
		// say more than the column name; keep only what a preset knows.
		if len(paths) > 0 && sub.Hint == nil && p.Structured*2 >= p.NonEmpty {
			kept := out[:0]
			for _, f := range out {
				if f.Source != "name" {
					kept = append(kept, f)
				}
			}
			out = kept
		}
		out = append(out, paths...)
	}
	return out
}

// Categories judged by name alone that numbers or code identifiers cannot be.
var textual = map[model.Category]bool{
	model.CatPersonName: true, model.CatUsername: true, model.CatAddress: true, model.CatCity: true,
	model.CatRegion: true, model.CatCountry: true, model.CatCompany: true, model.CatWebsite: true,
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

func pickSeverity(override model.Severity, c model.Category) model.Severity {
	if override != model.SeverityNone {
		return override
	}
	return c.Info().Severity
}

func appendNote(note, more string) string {
	if more == "" {
		return note
	}
	if note == "" {
		return more
	}
	return note + "; " + more
}

// support says how many sampled values back up a category, and whether
// the category can be checked from values at all.
func support(nm *NameMatch, p *Profile) (int, bool) {
	switch nm.Category {
	case model.CatEmail:
		return p.Email, true
	case model.CatPhone:
		return p.Phone, true
	case model.CatIPAddress:
		return p.IP, true
	case model.CatCardNumber:
		return p.Card, true
	case model.CatPasswordHash:
		return p.Hash + p.HexDigest, true
	case model.CatUserAgent:
		return p.UserAgent, true
	case model.CatBankAccount:
		if nm.Words == "iban" {
			return p.IBAN, true
		}
	}
	return 0, false
}

// valueCheck finds a category from values alone, with no help from the name.
type valueCheck struct {
	cat  model.Category
	n    func(p *Profile) int
	min  float64
	minN int
	what string
}

var valueChecks = []valueCheck{
	{model.CatCardNumber, func(p *Profile) int { return p.Card }, 0.5, 1, "payment card numbers"},
	{model.CatEmail, func(p *Profile) int { return p.Email }, 0.3, 2, "email addresses"},
	{model.CatBankAccount, func(p *Profile) int { return p.IBAN }, 0.3, 1, "IBANs"},
	{model.CatPasswordHash, func(p *Profile) int { return p.Hash }, 0.5, 2, "password hashes"},
	{model.CatIPAddress, func(p *Profile) int { return p.IP }, 0.5, 3, "IP addresses"},
	{model.CatPhone, func(p *Profile) int { return p.PhoneStrict }, 0.6, 3, "phone numbers"},
	{model.CatUserAgent, func(p *Profile) int { return p.UserAgent }, 0.5, 2, "browser user agents"},
	{model.CatPaymentToken, func(p *Profile) int { return p.PaymentID }, 0.5, 2, "payment provider IDs"},
}

func judge(base model.Finding, nm *NameMatch, source string, tokens []string, p *Profile, sampled bool, hint *Hint) []model.Finding {
	var out []model.Finding
	named := -1

	if nm != nil {
		f := base
		f.Category = nm.Category
		f.Severity = pickSeverity(nm.Severity, nm.Category)
		f.Mask = maskFor(nm.Category, tokens)
		if hint != nil && hint.Mask != "" {
			f.Mask = hint.Mask
		}
		if hint != nil {
			f.RowMasks = slices.Clone(hint.Rows)
		}
		f.Source = source
		f.Note = nm.Note
		if nm.Words != "" {
			f.Reasons = []string{fmt.Sprintf("name contains %q", nm.Words)}
		} else {
			f.Reasons = []string{"known field (" + strings.TrimPrefix(source, "preset:") + " preset)"}
		}
		label := nm.Category.Label()
		switch {
		case nm.Category == model.CatFreeText && sampled && (p == nil || p.NonEmpty == 0):
			f.Confidence = model.ConfidenceLow
			f.Note = appendNote(f.Note, "no non-empty values in the sample")
		case !sampled:
			f.Confidence = model.ConfidenceMedium
			f.Reasons = append(f.Reasons, "values not sampled")
		case p == nil || p.NonEmpty == 0:
			f.Confidence = model.ConfidenceMedium
			f.Note = appendNote(f.Note, "no non-empty values in the sample")
		default:
			f.Sampled = p.NonEmpty
			m, checkable := support(nm, p)
			if checkable {
				f.Matched = m
				r := ratio(m, p.NonEmpty)
				switch {
				case r >= 0.5:
					f.Confidence = model.ConfidenceHigh
					f.Source += "+value"
				case m > 0:
					f.Confidence = model.ConfidenceMedium
					f.Source += "+value"
				case hint == nil:
					f.Confidence = model.ConfidenceLow
					f.Note = appendNote(f.Note, "sampled values don't match the "+label+" format")
				default:
					// A preset knows the column even when its values are
					// encrypted or encoded.
					f.Confidence = model.ConfidenceMedium
				}
				if m > 0 {
					f.Reasons = append(f.Reasons, fmt.Sprintf("%d of %d sampled values match the %s format", m, p.NonEmpty, label))
				}
			} else if hint != nil {
				f.Confidence = model.ConfidenceHigh
			} else {
				f.Confidence = model.ConfidenceMedium
				if textual[nm.Category] {
					switch {
					case p.Numeric == p.NonEmpty:
						f.Confidence = model.ConfidenceLow
						f.Note = appendNote(f.Note, "sampled values are all numbers")
					case ratio(p.CodeLike, p.NonEmpty) >= 0.5:
						f.Confidence = model.ConfidenceLow
						f.Note = appendNote(f.Note, "sampled values look like code identifiers")
					}
				}
			}
		}
		out = append(out, f)
		named = len(out) - 1
	}

	if p == nil || p.NonEmpty == 0 {
		return out
	}

	for _, c := range valueChecks {
		n := c.n(p)
		if named >= 0 && out[named].Category == c.cat {
			continue
		}
		// Tokens are often stored hashed; a hash there is still a token.
		if named >= 0 && out[named].Category == model.CatSecret && c.cat == model.CatPasswordHash {
			continue
		}
		r := ratio(n, p.NonEmpty)
		if n < c.minN || r < c.min {
			continue
		}
		f := base
		f.Category = c.cat
		f.Severity = c.cat.Info().Severity
		f.Mask = maskFor(c.cat, tokens)
		f.Source = "value"
		f.Sampled, f.Matched = p.NonEmpty, n
		f.Confidence = model.ConfidenceMedium
		if r >= 0.8 {
			f.Confidence = model.ConfidenceHigh
		}
		f.Reasons = []string{fmt.Sprintf("%d of %d sampled values look like %s", n, p.NonEmpty, c.what)}
		if c.cat == model.CatPaymentToken {
			f.Severity = model.SeverityMedium
		}
		out = append(out, f)
	}

	for i := range out {
		refine(&out[i], p)
	}

	if p.Secrets != nil {
		live, test, unknown := p.SecretTotals()
		sev := model.SeverityMedium
		switch {
		case live > 0:
			sev = model.SeverityCritical
		case unknown > 0:
			sev = model.SeverityHigh
		}
		var kinds []string
		for _, k := range p.SecretKinds() {
			kinds = append(kinds, k+" ("+modeSummary(p.Secrets[k])+")")
		}
		reason := "secret formats found: " + strings.Join(kinds, ", ")
		if named >= 0 && out[named].Category == model.CatSecret {
			f := &out[named]
			if sev > f.Severity {
				f.Severity = sev
			}
			f.Confidence = model.ConfidenceHigh
			f.Matched = live + test + unknown
			f.Source += "+value"
			f.Reasons = append(f.Reasons, reason)
		} else {
			f := base
			f.Category = model.CatSecret
			f.Severity = sev
			f.Confidence = model.ConfidenceHigh
			f.Mask = model.CatSecret.Info().Mask
			f.Source = "value"
			f.Sampled, f.Matched = p.NonEmpty, live+test+unknown
			f.Reasons = []string{reason}
			out = append(out, f)
		}
		if live == 0 && unknown == 0 {
			last := len(out) - 1
			if named >= 0 && out[named].Category == model.CatSecret {
				last = named
			}
			out[last].Note = appendNote(out[last].Note, "test-mode keys only")
		}
	}

	embedded := p.TextEmail + p.TextPhone + p.TextCard + p.TextIP
	switch {
	case p.Text > 0 && embedded > 0:
		var parts []string
		for _, x := range []struct {
			n    int
			what string
		}{{p.TextEmail, "email addresses"}, {p.TextPhone, "phone numbers"}, {p.TextCard, "card-like numbers"}, {p.TextIP, "IP addresses"}} {
			if x.n > 0 {
				parts = append(parts, fmt.Sprintf("%d contain %s", x.n, x.what))
			}
		}
		top := max(p.TextEmail, p.TextPhone, p.TextCard, p.TextIP)
		conf := model.ConfidenceLow
		switch r := ratio(top, p.Text); {
		case r >= 0.2:
			conf = model.ConfidenceHigh
		case r >= 0.05 || top >= 3:
			conf = model.ConfidenceMedium
		}
		reason := fmt.Sprintf("of %d sampled text values, %s", p.Text, strings.Join(parts, ", "))
		sev := model.SeverityMedium
		note := ""
		if p.TextCard > 0 {
			sev = model.SeverityHigh
			note = "possible card numbers typed into free text"
		}
		// A preset's field already names the data; text evidence just backs it.
		if named >= 0 && hint != nil && out[named].Category != model.CatFreeText {
			f := &out[named]
			f.Reasons = append(f.Reasons, reason)
			f.Note = appendNote(f.Note, note)
		} else if named >= 0 && out[named].Category == model.CatFreeText {
			f := &out[named]
			f.Confidence, f.Severity = conf, max(f.Severity, sev)
			f.Matched = top
			f.Source += "+value"
			f.Reasons = append(f.Reasons, reason)
			f.Note = appendNote(f.Note, note)
		} else {
			f := base
			f.Category = model.CatFreeText
			f.Severity, f.Confidence = sev, conf
			f.Mask = model.CatFreeText.Info().Mask
			f.Source = "value"
			f.Sampled, f.Matched = p.Text, top
			f.Reasons = []string{reason}
			f.Note = note
			out = append(out, f)
		}
	case named >= 0 && out[named].Category == model.CatFreeText:
		out[named].Confidence = model.ConfidenceLow
		out[named].Note = appendNote(out[named].Note, "no personal data spotted in the sampled text")
	}
	return out
}

// refine adjusts a finding using details of the values: test card numbers,
// reserved email domains, password hash formats.
func refine(f *model.Finding, p *Profile) {
	switch f.Category {
	case model.CatCardNumber:
		if p.Card > 0 && p.CardTest == p.Card {
			f.Severity = model.SeverityMedium
			f.Note = appendNote(f.Note, "only published test card numbers")
		}
	case model.CatEmail:
		if p.Email > 0 && float64(p.EmailReserved) >= 0.9*float64(p.Email) {
			f.Severity = model.SeverityLow
			f.Note = appendNote(f.Note, "addresses use reserved example/test domains; this looks masked already")
		}
	case model.CatPasswordHash:
		if len(p.HashFormats) > 0 {
			var fs []string
			for name, n := range p.HashFormats {
				fs = append(fs, fmt.Sprintf("%s %d", name, n))
			}
			sort.Strings(fs)
			f.Reasons = append(f.Reasons, "hash formats: "+strings.Join(fs, ", "))
		}
	}
}

func modeSummary(c *SecretCount) string {
	var parts []string
	if c.Live > 0 {
		parts = append(parts, fmt.Sprintf("%d live", c.Live))
	}
	if c.Test > 0 {
		parts = append(parts, fmt.Sprintf("%d test", c.Test))
	}
	if c.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d", c.Unknown))
	}
	return strings.Join(parts, ", ")
}

func judgePaths(base model.Finding, ctx []string, p *Profile) []model.Finding {
	var out []model.Finding
	for _, name := range p.PathNames() {
		sub := p.Paths[name]
		if sub.NonEmpty == 0 {
			continue
		}
		keys := p.pathKeys[name]
		last := -1
		for i := len(keys) - 1; i >= 0; i-- {
			if keys[i] != "[]" && keys[i] != "*" {
				last = i
				break
			}
		}
		var (
			nm     *NameMatch
			tokens []string
		)
		if last >= 0 {
			tokens = Tokens(keys[last])
			pathCtx := append([]string(nil), ctx...)
			for _, k := range keys[:last] {
				pathCtx = append(pathCtx, Tokens(k)...)
			}
			nm = MatchName(tokens, pathCtx, tStr|tJSON)
		}
		b := base
		b.Path = name
		for _, f := range judge(b, nm, "name", tokens, sub, true, nil) {
			if f.Confidence > model.ConfidenceLow {
				out = append(out, f)
			}
		}
	}
	SortFindings(out)
	if len(out) > maxPathFindings {
		out = out[:maxPathFindings]
	}
	return out
}

func maskFor(c model.Category, tokens []string) string {
	if c == model.CatPersonName {
		switch {
		case anyIn(tokens, words("first given fname")):
			return "fake_first_name"
		case anyIn(tokens, words("last surname family lname maiden")):
			return "fake_last_name"
		}
	}
	return c.Info().Mask
}

// SortFindings orders findings by severity (worst first), then location.
func SortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.MetaKey != b.MetaKey {
			return a.MetaKey < b.MetaKey
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Category < b.Category
	})
}
