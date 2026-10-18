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
	// Delete marks a cache the platform rebuilds, such as WordPress
	// transients: a copy should delete these rows whatever they hold. A
	// hint with Delete and no Category doesn't say what the data is, so
	// the subject is judged as if there were no hint.
	Delete bool
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

	Keys        int    // keys a pattern stands for, copied to the findings
	KeysPartial bool   // Keys is a lower bound
	Where       string // the subject is these rows only, copied to the findings
	// Setting marks a key of a settings table, which holds one value; an
	// empty value then means nothing is stored.
	Setting bool
	// Skipped marks a key left without values by a sampling limit; name
	// matches on it stay weak.
	Skipped bool
	// Labels marks a key of a translation table: it names a UI string, not
	// a field, so only its values are judged.
	Labels bool
}

// maxPathFindings caps the findings reported for paths inside one column.
const maxPathFindings = 25

// Analyze judges one subject from its name and the profile of its sampled
// values. p is nil when no values were read.
func Analyze(sub Subject, p *Profile) []model.Finding {
	if sub.Hint != nil && sub.Hint.Ignore {
		return nil
	}
	// Only a hint with a category says what the data is.
	hint := sub.Hint
	if hint != nil && hint.Category == "" {
		hint = nil
	}
	tc := tStr
	if sub.DataType != "" {
		tc = classOf(sub.DataType)
	}
	tokens := NameWords(sub.Name)
	var nm *NameMatch
	source := "name"
	switch {
	case hint != nil:
		nm = &NameMatch{Category: hint.Category, Severity: hint.Severity, Note: hint.Note}
		source = hint.Source
	case !sub.Labels:
		nm = MatchName(tokens, sub.Context, tc)
	}
	base := model.Finding{Table: sub.Table, Column: sub.Column, MetaKey: sub.MetaKey,
		Keys: sub.Keys, KeysPartial: sub.KeysPartial, Where: sub.Where}
	st := state{sampled: sub.Sampled, setting: sub.Setting, skipped: sub.Skipped, table: sub.Context, tc: tc}
	out := judge(base, nm, source, tokens, p, st, hint)
	if p != nil && len(p.Paths) > 0 {
		paths := judgePaths(base, sub.Context, Tokens(sub.Name), p)
		// When the values are mostly JSON or serialized data, the paths
		// say more than the column name; keep only what a preset knows.
		if len(paths) > 0 && hint == nil && p.Structured*2 >= p.NonEmpty {
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
	if sub.Hint != nil && sub.Hint.Delete {
		out = deleteFinding(out, sub.Hint)
	}
	return out
}

// deleteFinding folds the findings of a cache into one that suggests
// deleting it: the worst of them, with the other kinds of data it holds in
// its reasons, and no paths, since the rows go away.
func deleteFinding(fs []model.Finding, h *Hint) []model.Finding {
	if len(fs) == 0 {
		return nil
	}
	worst := 0
	for i, f := range fs {
		if better(f, fs[worst]) {
			worst = i
		}
	}
	f := fs[worst]
	var also []string
	seen := map[model.Category]bool{f.Category: true}
	for _, g := range fs {
		if g.Confidence > model.ConfidenceLow && !seen[g.Category] {
			seen[g.Category] = true
			also = append(also, g.Category.Label())
		}
	}
	sort.Strings(also)
	f.Reasons = append([]string(nil), f.Reasons...)
	if f.Path != "" && len(f.Reasons) > 0 {
		// The finding now stands for the whole key: say where its reasons apply.
		f.Reasons[0] = f.Path + ": " + f.Reasons[0]
	}
	if len(also) > 0 {
		f.Reasons = append(f.Reasons, "also holds: "+strings.Join(also, ", "))
	}
	f.Path, f.Mask, f.RowMasks = "", "delete", nil
	f.Note = appendNote(f.Note, h.Note)
	return []model.Finding{f}
}

// better reports whether finding a is worth more attention than b: a
// confident one over a weak one, then the more severe, then the surer.
func better(a, b model.Finding) bool {
	if (a.Confidence == model.ConfidenceLow) != (b.Confidence == model.ConfidenceLow) {
		return b.Confidence == model.ConfidenceLow
	}
	if a.Severity != b.Severity {
		return a.Severity > b.Severity
	}
	return a.Confidence > b.Confidence
}

// state is what judge needs to know about how the values were read, and
// where the subject sits.
type state struct {
	sampled bool // values were read
	setting bool // a single-value setting
	skipped bool // values were left unread by a sampling limit
	path    bool // a path inside a JSON or serialized value
	table   []string
	near    []string // for a path: the words of its column or meta key, and of the keys above it
	tc      typeClass
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
	case model.CatDeviceID:
		return p.Opaque + p.Push, true
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
	{model.CatDeviceID, func(p *Profile) int { return p.Push }, 0.5, 1, "push notification tokens"},
}

// oneValue lists the categories for which one matching value is enough
// when every sampled value matches: settings hold a single value, and
// these formats can't be mistaken for anything else.
var oneValue = map[model.Category]bool{model.CatEmail: true, model.CatPasswordHash: true, model.CatPaymentToken: true}

// flagOK lists the categories whose values may legitimately be on/off flags.
var flagOK = map[model.Category]bool{model.CatGender: true, model.CatCountry: true, model.CatRegion: true, model.CatCardMeta: true}

// needsDigits gives, for categories whose values always contain digits,
// how many at least one value must hold: an ID or account number, or a
// birth date or year, has four or more; a postcode may have one (SW1A 1AA).
var needsDigits = map[model.Category]int{model.CatNationalID: 4, model.CatBankAccount: 4,
	model.CatDateOfBirth: 4, model.CatPostcode: 1}

// identity lists name and login categories: email-shaped values there
// mean the column holds email addresses too.
var identity = map[model.Category]bool{model.CatUsername: true, model.CatPersonName: true}

func judge(base model.Finding, nm *NameMatch, source string, tokens []string, p *Profile, st state, hint *Hint) []model.Finding {
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
		// A day, month or year of birth on its own, in a number column or
		// as whole numbers: a fake date wouldn't fit, so the parts are
		// emptied together. So is a whole date stored as a number, such as
		// YYYYMMDD or a Unix time.
		numeric := nm.Category == model.CatDateOfBirth && hint == nil &&
			(st.tc&tInt != 0 || (p != nil && p.Whole > 0 && p.Whole == p.NonEmpty))
		part := numeric && (p == nil || p.MaxDigits <= 4)
		switch {
		case part:
			f.Mask = "null"
			f.Note = appendNote(f.Note, "one part of a split birth date: mask the day, month and year together")
		case numeric:
			f.Mask = "null"
			f.Note = appendNote(f.Note, "a birth date stored as a number, which a fake date wouldn't fit")
		}
		label := nm.Category.Label()
		switch {
		case nm.Category == model.CatFreeText && st.sampled && (p == nil || p.NonEmpty == 0):
			f.Confidence = model.ConfidenceLow
			f.Note = appendNote(f.Note, "no non-empty values in the sample")
		case !st.sampled && st.skipped:
			f.Confidence = model.ConfidenceLow
			f.Note = appendNote(f.Note, "not sampled: over the per-table limit")
		case !st.sampled:
			f.Confidence = model.ConfidenceMedium
			f.Reasons = append(f.Reasons, "values not sampled")
		case p == nil || p.NonEmpty == 0:
			f.Confidence = model.ConfidenceMedium
			f.Note = appendNote(f.Note, "no non-empty values in the sample")
			if st.setting && p != nil && p.Values > 0 {
				f.Confidence = model.ConfidenceLow // an empty setting stores nothing, whatever a preset says
			}
		default:
			f.Sampled = p.NonEmpty
			if hint == nil && nm.Password && judgePassword(&f, nm, tokens, p, st) {
				break
			}
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
				switch {
				case !flagOK[nm.Category] && p.Flag == p.NonEmpty:
					f.Confidence = model.ConfidenceLow
					f.Note = appendNote(f.Note, "sampled values are all on/off flags")
				case textual[nm.Category] && p.Numeric == p.NonEmpty:
					f.Confidence = model.ConfidenceLow
					f.Note = appendNote(f.Note, "sampled values are all numbers")
				case textual[nm.Category] && ratio(p.CodeLike, p.NonEmpty) >= 0.5:
					f.Confidence = model.ConfidenceLow
					f.Note = appendNote(f.Note, "sampled values look like code identifiers")
				case textual[nm.Category] && nm.Category != model.CatWebsite && ratio(p.URL, p.NonEmpty) >= 0.5:
					f.Confidence = model.ConfidenceLow
					f.Note = appendNote(f.Note, "sampled values look like URLs or paths")
				case textual[nm.Category] && ratio(p.Crypto, p.NonEmpty) >= 0.5:
					f.Confidence = model.ConfidenceLow
					f.Note = appendNote(f.Note, "sampled values look like cryptocurrency addresses")
				case labelLike(nm.Category, p):
					f.Confidence = model.ConfidenceLow
					f.Note = appendNote(f.Note, "sampled values look like field names, placeholders or flags")
				case needsDigits[nm.Category] > 0 && !part && p.leafMaxDigits() < needsDigits[nm.Category]:
					f.Confidence = model.ConfidenceLow
					f.Note = appendNote(f.Note, "sampled values have too few digits for a "+label)
				}
			}
		}
		out = append(out, f)
		named = len(out) - 1
	}

	if p == nil || p.NonEmpty == 0 {
		return lowIsLow(out)
	}

	keysLeaf := strings.HasSuffix(base.Path, keysPath)
	ident := named >= 0 && identity[out[named].Category]
	before := len(out)
	for _, c := range valueChecks {
		n := c.n(p)
		if named >= 0 && out[named].Category == c.cat {
			continue
		}
		// Tokens are often stored hashed; a hash there is still a token.
		// Push tokens under a token's name back the secret finding.
		if named >= 0 && out[named].Category == model.CatSecret && (c.cat == model.CatPasswordHash || c.cat == model.CatDeviceID) {
			continue
		}
		r := ratio(n, p.NonEmpty)
		all := n > 0 && n == p.NonEmpty
		minRatio, minN := c.min, c.minN
		identEmail := c.cat == model.CatEmail && ident
		if identEmail {
			minRatio, minN = 0.05, 2 // logins and names typed as email addresses
		}
		// Every value matches, and there may be only one: settings, and
		// the keys of a map keyed by IP (version numbers parse as IPv4,
		// so IPs get this only there).
		one := all && (oneValue[c.cat] || (c.cat == model.CatIPAddress && keysLeaf) || identEmail)
		if !one && (n < minN || r < minRatio) {
			continue
		}
		f := base
		f.Category = c.cat
		f.Severity = c.cat.Info().Severity
		f.Mask = maskFor(c.cat, tokens)
		f.Source = "value"
		f.Sampled, f.Matched = p.NonEmpty, n
		f.Confidence = model.ConfidenceMedium
		if r >= 0.8 && n >= c.minN {
			f.Confidence = model.ConfidenceHigh
		}
		f.Reasons = []string{fmt.Sprintf("%d of %d sampled values look like %s", n, p.NonEmpty, c.what)}
		if c.cat == model.CatPaymentToken {
			f.Severity = model.SeverityMedium
		}
		if c.cat == model.CatDeviceID {
			f.Note = "staging could send push notifications to real devices"
		}
		if identEmail {
			f.Confidence = model.ConfidenceMedium
			if r >= 0.5 {
				f.Confidence = model.ConfidenceHigh
			} else {
				// A mixed column keeps its own mask; most values aren't addresses.
				f.Mask = out[named].Mask
				f.Note = fmt.Sprintf("%d of %d values are email addresses; keep them email-shaped when masking", n, p.NonEmpty)
			}
		}
		out = append(out, f)
	}
	valueFound := len(out) > before

	for i := range out {
		refine(&out[i], p)
	}

	if p.Secrets != nil {
		live, _, unknown := p.SecretTotals()
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
			f.Matched = p.SecretValues
			f.Source += "+value"
			f.Reasons = append(f.Reasons, reason)
		} else {
			f := base
			f.Category = model.CatSecret
			f.Severity = sev
			f.Confidence = model.ConfidenceHigh
			f.Mask = model.CatSecret.Info().Mask
			f.Source = "value"
			f.Sampled, f.Matched = p.NonEmpty, p.SecretValues
			f.Reasons = []string{reason}
			out = append(out, f)
		}
		last := len(out) - 1
		if named >= 0 && out[named].Category == model.CatSecret {
			last = named
		}
		if live == 0 && unknown == 0 {
			out[last].Note = appendNote(out[last].Note, "test-mode keys only")
		}
		out[last].Note = appendNote(out[last].Note, secretKindNotes(p.SecretKinds()))
	}

	// Messages between people: prose is enough, since names and addresses
	// typed into them can't be detected.
	messages := nm != nil && nm.Messages && named >= 0 && out[named].Category == model.CatFreeText
	prose := p.Spaced >= 3 && ratio(p.Spaced, p.NonEmpty) >= 0.3
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
			if messages {
				conf = max(conf, model.ConfidenceMedium)
			}
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
	case messages && prose:
		out[named].Confidence = model.ConfidenceMedium
		out[named].Note = appendNote(out[named].Note, "messages between people: names and addresses typed into them can't be detected")
	case named >= 0 && out[named].Category == model.CatFreeText:
		// Emails inside values may raise it again below.
		out[named].Confidence = model.ConfidenceLow
		if p.Inline == 0 {
			out[named].Note = appendNote(out[named].Note, nothingSpotted)
		}
	}

	if p.Inline > 0 {
		out = inlineEmails(out, base, p)
	}

	// A column of identifiers of more than one kind, such as a ban list of
	// email and IP addresses, which no single value check reports.
	kinds := 0
	for _, n := range []int{p.Email, p.IP, p.PhoneStrict} {
		if n > 0 {
			kinds++
		}
	}
	if !valueFound && kinds >= 2 && p.NonEmpty >= 2 && p.Email+p.IP+p.PhoneStrict == p.NonEmpty {
		const reason = "every sampled value is an email address, an IP address or a phone number"
		switch {
		case named < 0:
			f := base
			f.Category = model.CatFreeText
			f.Severity, f.Confidence = model.SeverityMedium, model.ConfidenceMedium
			f.Mask = model.CatFreeText.Info().Mask
			f.Source = "value"
			f.Sampled, f.Matched = p.NonEmpty, p.NonEmpty
			f.Reasons = []string{reason}
			out = append(out, f)
		case out[named].Category == model.CatFreeText:
			f := &out[named]
			f.Confidence = max(f.Confidence, model.ConfidenceMedium)
			f.Matched = p.NonEmpty
			if !strings.Contains(f.Source, "value") {
				f.Source += "+value"
			}
			f.Reasons = append(f.Reasons, reason)
			f.Note = dropNote(f.Note, nothingSpotted)
		}
	}
	return lowIsLow(out)
}

// nothingSpotted is the note on free text whose sampled values show no
// personal data.
const nothingSpotted = "no personal data spotted in the sampled text"

// dropNote removes one part from a note that appendNote built.
func dropNote(note, part string) string {
	parts := strings.Split(note, "; ")
	return strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == part }), "; ")
}

// inlineEmails reports values that carry email addresses inside them, such
// as URLs with an address in their query string, as free text: on a free
// text finding already there, or on a new one.
func inlineEmails(out []model.Finding, base model.Finding, p *Profile) []model.Finding {
	conf := model.ConfidenceLow
	switch r := ratio(p.Inline, p.NonEmpty); {
	case r >= 0.2:
		conf = model.ConfidenceHigh
	case r >= 0.05 || p.Inline >= 3:
		conf = model.ConfidenceMedium
	}
	reason := fmt.Sprintf("%d of %d sampled values have email addresses inside, such as in URLs", p.Inline, p.NonEmpty)
	if i := slices.IndexFunc(out, func(f model.Finding) bool { return f.Category == model.CatFreeText }); i >= 0 {
		f := &out[i]
		f.Confidence = max(f.Confidence, conf)
		f.Matched = max(f.Matched, p.Inline)
		if !strings.Contains(f.Source, "value") {
			f.Source += "+value"
		}
		f.Reasons = append(f.Reasons, reason)
		return out
	}
	f := base
	f.Category = model.CatFreeText
	f.Severity, f.Confidence = model.SeverityMedium, conf
	f.Mask = model.CatFreeText.Info().Mask
	f.Source = "value"
	f.Sampled, f.Matched = p.NonEmpty, p.Inline
	f.Reasons = []string{reason}
	return append(out, f)
}

// labelLike reports whether sampled values name fields rather than hold
// data: the field's own name, placeholders and field names, making up at
// least half of the values, or all of them together with on/off flags, as
// in an import plugin's column mappings. Usernames, profile handles and
// secrets can be words joined by _ or - (jane-doe-1a2b3c,
// correct-horse-battery-staple), so for those field names don't count.
func labelLike(cat model.Category, p *Profile) bool {
	names := p.Echo + p.Placeholder
	switch cat {
	case model.CatUsername, model.CatWebsite, model.CatSecret:
	default:
		names += p.FieldName
	}
	if names == 0 {
		return false
	}
	flags := 0
	if !flagOK[cat] {
		flags = p.Flag
	}
	return ratio(names, p.NonEmpty) >= 0.5 || names+flags == p.NonEmpty
}

// lowIsLow gives weak findings low severity: a name match whose values
// don't fit says little about how much harm the data could do.
func lowIsLow(fs []model.Finding) []model.Finding {
	for i := range fs {
		if fs[i].Confidence == model.ConfidenceLow {
			fs[i].Severity = model.SeverityLow
		}
	}
	return fs
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
		if len(p.HashFormats) > 0 && !slices.ContainsFunc(f.Reasons, func(r string) bool {
			return strings.HasPrefix(r, "hash formats: ")
		}) {
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

// judgePaths judges the paths inside a column's or key's JSON or serialized
// values. A path's name is judged in the context of the table's words
// (ctx), the words of the column or key holding it (field), and the keys
// above it, so updraft_ftp's settings.*.pass sees ftp.
func judgePaths(base model.Finding, ctx, field []string, p *Profile) []model.Finding {
	var out []model.Finding
	for _, name := range p.PathNames() {
		sub := p.Paths[name]
		if sub.NonEmpty == 0 {
			continue
		}
		keys := p.pathKeys[name]
		last := lastName(keys)
		var (
			nm     *NameMatch
			tokens []string
			near   = append([]string(nil), field...)
		)
		if last >= 0 {
			tokens = NameWords(keys[last])
			for _, k := range keys[:last] {
				near = append(near, Tokens(k)...)
			}
			nm = MatchName(tokens, append(append([]string(nil), ctx...), near...), tStr|tJSON)
		}
		b := base
		b.Path = name
		st := state{sampled: true, path: true, table: ctx, near: near, tc: tStr | tJSON}
		for _, f := range judge(b, nm, "name", tokens, sub, st, nil) {
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
		if a.Where != b.Where {
			return a.Where < b.Where
		}
		return a.Category < b.Category
	})
}

// secretKindNotes says what a copy of these kinds of secret would do on
// staging.
func secretKindNotes(kinds []string) string {
	var chat, workflow bool
	for _, k := range kinds {
		switch secretNotes[k] {
		case noteChat:
			chat = true
		case noteWorkflow:
			workflow = true
		}
	}
	var notes []string
	if chat {
		notes = append(notes, "a copy would post to real chat channels")
	}
	if workflow {
		notes = append(notes, "a copy would trigger the real workflow")
	}
	return strings.Join(notes, "; ")
}
