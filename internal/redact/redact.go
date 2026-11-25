// Package redact decides what of a query's result prodmask mcp shows an
// agent: the scan's own verdicts on the columns a result
// ties to, the result's own values, key/value rows by their keys, spans in
// free text, and accounts in SHOW output, replaced by tokens; what can't be
// checked is withheld. It never claims more than it does: what it doesn't
// recognise shows as stored.
package redact

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/scan"
)

// The caps on what a result shows.
const (
	// ResultCap is where a result's JSON stops.
	ResultCap = 256 << 10
	// ValueChars is where a value shown is cut, after replacement.
	ValueChars = 1000
)

// Withheld stands for a value the agent doesn't see.
const Withheld = "[withheld]"

// Column is a result column as the driver gives it: its label, with the
// table's alias and a dot before it under ColumnsWithAlias, and its type's
// name.
type Column struct{ Name, Type string }

// Value is a result value: its bytes, NULL, or a value withheld unread
// because of its size.
type Value struct {
	Bytes    []byte
	Null     bool
	Withheld int
}

// Source is what the verdicts come from: the schema, the presets, and each
// table's judgement, which the caller reads on its tools' session and
// caches per connection.
type Source struct {
	Schema  *model.Schema
	Presets *preset.Result
	Judge   func(ctx context.Context, t *model.Table) scan.TableVerdict
}

// Redactor shows results. Its token key is the process's, so equal values
// get equal tokens within one run and nothing links runs.
type Redactor struct {
	src     Source
	copy    bool
	key     []byte
	finders []detect.SpanFinder
}

// New returns a Redactor. checkedCopy marks a checked --copy: values show as
// stored except secrets, passwords in URLs and password hashes; binary
// values still show as tokens, and accounts in DEFINER and CONNECTION
// clauses and a SHOW's Definer as placeholders. key is the token key, 32
// random bytes made at start and never written anywhere.
func New(src Source, checkedCopy bool, key []byte) *Redactor {
	if src.Presets == nil {
		src.Presets = &preset.Result{}
	}
	if src.Schema == nil {
		src.Schema = &model.Schema{}
	}
	return &Redactor{src: src, copy: checkedCopy, key: key, finders: finders(checkedCopy)}
}

// ShownColumn is a result column as the agent sees it.
type ShownColumn struct {
	Label string `json:"label"`
	Table string `json:"table,omitempty"`
	Type  string `json:"type"`
}

// Shown is a result as the agent sees it.
type Shown struct {
	Columns []ShownColumn
	Rows    [][]any
	// Notes say, by column, how many values were replaced or withheld and
	// why, never the values.
	Notes              []string
	Replaced, Withheld int
	// Stopped marks a result cut at ResultCap.
	Stopped bool
}

// Token is a value's token: its kind and the first 12 hex digits of
// HMAC-SHA-256 over the kind and the value.
func (r *Redactor) Token(kind string, value []byte) string {
	return "[" + kind + " " + r.mac(kind, value) + "]"
}

func (r *Redactor) mac(kind string, value []byte) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write(value)
	return hex.EncodeToString(m.Sum(nil))[:12]
}

// binaryToken is a binary value's token, with its size, so binary keys
// still join.
func (r *Redactor) binaryToken(value []byte) string {
	return fmt.Sprintf("[binary %d bytes %s]", len(value), r.mac("binary", value))
}

// verdict is what replaces a whole column's values: its category, how bad,
// and the note's reason.
type verdict struct {
	cat  model.Category
	sev  model.Severity
	conf model.Confidence
	why  string
}

func (v *verdict) worse(o *verdict) bool {
	switch {
	case o == nil:
		return false
	case v == nil:
		return true
	case o.sev != v.sev:
		return o.sev > v.sev
	}
	return o.conf > v.conf
}

// plan is how one result column's values are shown.
type plan struct {
	col      ShownColumn
	class    string
	binary   bool
	withhold string
	whole    *verdict
	paths    map[string]model.Category
	kv       *kvPlan
	definer  bool
	words    []string // the table's name words, for profiling
	table    string
}

// kvPlan judges a key/value table's value column by its row's key.
type kvPlan struct {
	keyIndex int
	value    string // the value column's name
	// byValues are verdicts from the result's own values, by stored key.
	byValues map[string]model.Finding
	table    *model.Table
	meta     *preset.MetaTable
	exact    map[string]model.Finding
	families []model.Finding
}

// Result shows a statement's result.
func (r *Redactor) Result(ctx context.Context, statement string, cols []Column, rows [][]Value) Shown {
	plans, unsampled := r.plans(ctx, statement, cols, rows)
	out := Shown{Rows: [][]any{}}
	for _, p := range plans {
		out.Columns = append(out.Columns, p.col)
	}
	tally := map[string]int{}
	var order []string
	count := func(i int, what string) {
		key := plans[i].col.Label + ": " + what
		if tally[key] == 0 {
			order = append(order, key)
		}
		tally[key]++
	}
	size := 0
	for _, row := range rows {
		shownRow := make([]any, len(row))
		for i, v := range row {
			shown, outcome := r.value(plans[i], v, row)
			shownRow[i] = shown
			switch {
			case strings.HasPrefix(outcome, "withheld"):
				out.Withheld++
				count(i, outcome)
			case outcome != "":
				out.Replaced++
				count(i, outcome)
			}
		}
		b, _ := json.Marshal(shownRow)
		if size += len(b) + 1; size > ResultCap {
			out.Stopped = true
			break
		}
		out.Rows = append(out.Rows, shownRow)
	}
	for _, key := range order {
		label, what, _ := strings.Cut(key, ": ")
		n := tally[key]
		noun := "values"
		if n == 1 {
			noun = "value"
		}
		verb, why, _ := strings.Cut(what, " ")
		out.Notes = append(out.Notes, fmt.Sprintf("%s: %d %s %s %s", label, n, noun, verb, why))
	}
	for _, name := range unsampled {
		out.Notes = append(out.Notes, report.Clean(name)+" couldn't be sampled: its columns are judged by their names, the presets' hints and the result's values")
	}
	if out.Stopped {
		out.Notes = append(out.Notes, "the result stopped at 256 KB")
	}
	return out
}

// plans decides how each column is shown, and names the tables whose
// sample failed.
func (r *Redactor) plans(ctx context.Context, statement string, cols []Column, rows [][]Value) ([]*plan, []string) {
	aliases := dbconn.StatementAliases(statement)
	show := dbconn.LeadingWord(statement) == "SHOW"
	// A SHOW's or information_schema's result is metadata: names and
	// comments, which list_tables and describe_table show too. Only the
	// span finders and the account rules apply to it.
	meta := show || aliases.InformationSchemaOnly && !r.namesTable(aliases.Names)
	judged := map[string]scan.TableVerdict{}
	var unsampled []string
	judge := func(t *model.Table) scan.TableVerdict {
		if v, ok := judged[t.Name]; ok {
			return v
		}
		v := r.src.Judge(ctx, t)
		judged[t.Name] = v
		if v.SampleErr != nil {
			unsampled = append(unsampled, t.Name)
		}
		return v
	}
	plans := make([]*plan, len(cols))
	for i, c := range cols {
		p := &plan{class: typeClass(c.Type)}
		plans[i] = p
		alias, label, dotted := strings.Cut(c.Name, ".")
		if !dotted {
			alias, label = "", c.Name
		}
		p.col = ShownColumn{Label: report.Clean(label), Table: report.Clean(alias), Type: c.Type}
		p.binary = p.class == "binary"
		if show && strings.EqualFold(label, "Definer") {
			p.definer = true
		}
		if r.copy || p.binary || p.definer || meta {
			continue
		}
		t := r.tied(aliases, alias, label)
		switch {
		case t == nil:
			r.computed(p, label, aliases, judge)
		case t.IsView():
			p.table, p.words = t.Name, detect.Tokens(t.Name)
			p.whole = byName(t.Name, label, p.class, "a view's column: judged by its name and values")
		default:
			r.base(p, t, label, alias, cols, judge(t))
		}
	}
	if r.copy || meta {
		return plans, unsampled
	}
	// The result's own values can only add: a key/value column's by key,
	// the others' by column.
	for i, p := range plans {
		if p.kv != nil && p.withhold == "" {
			r.profileKeys(p.kv, i, rows)
		}
		if p.binary || p.definer || p.withhold != "" || p.kv != nil {
			continue
		}
		prof := detect.NewProfileNamed(p.col.Label).WithContext(p.words)
		n := 0
		for _, row := range rows {
			if v := row[i]; !v.Null && v.Withheld == 0 && utf8.Valid(v.Bytes) {
				prof.Add(accounts(string(v.Bytes)))
				n++
			}
		}
		if n == 0 {
			continue
		}
		sub := detect.Subject{Table: p.table, Column: p.col.Label, Name: p.col.Label, DataType: dataType(cols[i].Type),
			Context: p.words, Sampled: true}
		if v := worst(detect.Analyze(sub, prof), "judged by its values"); p.whole.worse(v) {
			p.whole = v
		}
	}
	return plans, unsampled
}

// namesTable reports whether a name the statement holds is one of the
// session's tables or views: then its result may hold their values, and
// isn't taken as metadata, whatever form the alias walk read.
func (r *Redactor) namesTable(names map[string]bool) bool {
	if r.src.Schema == nil {
		return len(names) > 0
	}
	for _, t := range r.src.Schema.Tables {
		if names[strings.ToLower(t.Name)] {
			return true
		}
	}
	return false
}

// tied returns the base table or view a column's alias names, or nil when
// the column can't be placed: no alias, one defined twice, a label with
// another dot, a derived table or CTE, or a name the schema doesn't hold.
func (r *Redactor) tied(al dbconn.Aliases, alias, label string) *model.Table {
	key := strings.ToLower(alias)
	if alias == "" || strings.Contains(label, ".") || al.Twice[key] {
		return nil
	}
	name, ok := al.Tables[key]
	if !ok || name == "" {
		return nil
	}
	return r.table(name)
}

// table finds a table by name, as the server matches it here.
func (r *Redactor) table(name string) *model.Table {
	if t := r.src.Schema.Table(name); t != nil {
		return t
	}
	for _, t := range r.src.Schema.Tables {
		if strings.EqualFold(t.Name, name) {
			return t
		}
	}
	return nil
}

// base plans a column of a base table: its own verdict when the label is one
// of the table's columns of the same type class, else the worst verdict
// among its columns of that class, as a rename.
func (r *Redactor) base(p *plan, t *model.Table, label, alias string, cols []Column, tv scan.TableVerdict) {
	p.table, p.words = t.Name, detect.Tokens(t.Name)
	col := t.Column(label)
	same := col != nil && typeClass(col.DataType) == p.class
	if tv.Summary.Kind == "key/value" {
		valueCol := t.Column(tv.Summary.ValueColumn)
		switch {
		case same && valueCol != nil && col == valueCol:
			r.kvValue(p, t, tv, alias, cols)
			return
		case !same && p.class == "string":
			p.withhold = fmt.Sprintf("withheld (renamed: a key/value table's text column; select %s and %s by their own names)",
				tv.Summary.KeyColumn, tv.Summary.ValueColumn)
			return
		}
	}
	if same {
		p.whole, p.paths = columnVerdict(tv, col.Name, "")
		if tv.SampleErr != nil && p.whole != nil {
			p.whole.why = "by name, as the table couldn't be sampled"
		}
		return
	}
	var w *verdict
	for _, c := range t.Columns {
		if typeClass(c.DataType) != p.class {
			continue
		}
		if v, _ := columnVerdict(tv, c.Name, "renamed: judged as its table's columns of this type"); w.worse(v) {
			w = v
		}
	}
	p.whole = w
}

// kvValue plans a key/value table's value column: each value is judged by
// its row's key, which must be in the result beside it, from the same
// table alias.
func (r *Redactor) kvValue(p *plan, t *model.Table, tv scan.TableVerdict, alias string, cols []Column) {
	keyIndex := -1
	for j, c := range cols {
		a, l, ok := strings.Cut(c.Name, ".")
		if ok && strings.EqualFold(a, alias) && strings.EqualFold(l, tv.Summary.KeyColumn) {
			if keyIndex >= 0 {
				p.withhold = "withheld (two key columns; select one " + tv.Summary.KeyColumn + ")"
				return
			}
			keyIndex = j
		}
	}
	if keyIndex < 0 {
		p.withhold = fmt.Sprintf("withheld (select %s beside %s)", tv.Summary.KeyColumn, tv.Summary.ValueColumn)
		return
	}
	kp := &kvPlan{keyIndex: keyIndex, value: tv.Summary.ValueColumn, table: t, meta: scan.KeyValueTable(t, r.src.Presets),
		exact: map[string]model.Finding{}}
	// The scan reports a key by its shown form (detect.ShowKey of its label),
	// a family by its pattern, and a key whose name may hold data as
	// detect.HiddenKey: a row's key is looked up the same way.
	for _, f := range tv.Findings {
		if f.MetaKey == "" || f.KeyName || f.Confidence < model.ConfidenceMedium ||
			!strings.EqualFold(f.Column, tv.Summary.ValueColumn) {
			continue
		}
		if f.MetaKey != detect.HiddenKey && strings.Contains(f.MetaKey, "*") {
			kp.families = append(kp.families, f)
		} else if old, ok := kp.exact[strings.ToLower(f.MetaKey)]; !ok || f.Severity > old.Severity {
			kp.exact[strings.ToLower(f.MetaKey)] = f
		}
	}
	p.kv = kp
}

// computed plans a column tied to no base table: every base table the
// statement reads is a candidate. A label that is a column of a candidate
// takes the worst such verdict; otherwise the label is judged by name
// against each candidate, the worst winning.
func (r *Redactor) computed(p *plan, label string, al dbconn.Aliases, judge func(*model.Table) scan.TableVerdict) {
	const why = "computed: judged by its name and values"
	var cands []*model.Table
	for _, name := range al.Read {
		if t := r.table(name); t != nil && t.IsData() {
			cands = append(cands, t)
		}
	}
	var w *verdict
	for _, t := range cands {
		if c := t.Column(label); c != nil {
			if v, _ := columnVerdict(judge(t), c.Name, why); w.worse(v) {
				w = v
			}
		}
	}
	if w == nil {
		for _, t := range cands {
			if v := byName(t.Name, label, p.class, why); w.worse(v) {
				w = v
			}
		}
		if len(cands) == 0 {
			w = byName("", label, p.class, why)
		}
	}
	if len(cands) == 1 {
		p.table, p.words = cands[0].Name, detect.Tokens(cands[0].Name)
	}
	p.whole = w
}

// columnVerdict is a column's verdict from its table's findings: the worst
// finding on the whole column at medium confidence or higher, and the
// paths flagged inside its JSON or serialized values. An empty why says
// how the finding was made: by name, or by the sampled values.
func columnVerdict(tv scan.TableVerdict, column, why string) (*verdict, map[string]model.Category) {
	var w *verdict
	var paths map[string]model.Category
	for _, f := range tv.Findings {
		if !strings.EqualFold(f.Column, column) || f.MetaKey != "" || f.KeyName || f.Confidence < model.ConfidenceMedium {
			continue
		}
		if f.Path != "" {
			if paths == nil {
				paths = map[string]model.Category{}
			}
			paths[f.Path] = f.Category
			continue
		}
		how := why
		if how == "" {
			how = "by name"
			if f.Matched > 0 {
				how = "by its values"
			}
		}
		if v := (&verdict{f.Category, f.Severity, f.Confidence, how}); w.worse(v) {
			w = v
		}
	}
	return w, paths
}

// byName judges a label by the scan's name rules alone.
func byName(table, label, class, why string) *verdict {
	sub := detect.Subject{Table: table, Column: label, Name: label, DataType: classType(class), Context: detect.Tokens(table)}
	return worst(detect.Analyze(sub, nil), why)
}

// worst is the worst finding on the whole value at medium confidence or
// higher.
func worst(fs []model.Finding, why string) *verdict {
	var w *verdict
	for _, f := range fs {
		if f.Path != "" || f.Confidence < model.ConfidenceMedium {
			continue
		}
		if v := (&verdict{f.Category, f.Severity, f.Confidence, why}); w.worse(v) {
			w = v
		}
	}
	return w
}

// value shows one value, and says what happened to it: "" for shown as
// stored, "replaced (…)" or "withheld (…)".
func (r *Redactor) value(p *plan, v Value, row []Value) (any, string) {
	switch {
	case v.Null:
		return nil, ""
	case v.Withheld > 0:
		return Withheld, "withheld (over 1 MiB)"
	case p.binary:
		return r.binaryToken(v.Bytes), "replaced (binary, as tokens)"
	case p.withhold != "":
		return Withheld, p.withhold
	case !utf8.Valid(v.Bytes):
		return Withheld, "withheld (not valid UTF-8)"
	case p.definer:
		return "[account]", "replaced (accounts)"
	case p.whole != nil:
		return r.Token(string(p.whole.cat), v.Bytes), "replaced (" + string(p.whole.cat) + ", " + p.whole.why + ")"
	}
	paths := p.paths
	if p.kv != nil {
		if f, ok := r.keyVerdict(p.kv, row[p.kv.keyIndex]); ok {
			if f.Path == "" {
				return r.Token(string(f.Category), v.Bytes), "replaced (" + string(f.Category) + ", by its row's key)"
			}
			paths = map[string]model.Category{f.Path: f.Category}
		}
	}
	out, edited, err := r.text(string(v.Bytes), paths)
	switch {
	case err != nil:
		return Withheld, "withheld (a structured value prodmask couldn't edit)"
	case edited:
		return cut(out), "replaced (found in the text)"
	}
	return cut(out), ""
}

// profileKeys profiles each key's values in the result, as the scan
// profiles a key's sampled values, so a key the table's judgement didn't
// sample is still judged by what the result holds under it.
func (r *Redactor) profileKeys(kp *kvPlan, col int, rows [][]Value) {
	byKey := map[string][]string{}
	var order []string
	for _, row := range rows {
		k, v := row[kp.keyIndex], row[col]
		if k.Null || v.Null || k.Withheld > 0 || v.Withheld > 0 || !utf8.Valid(k.Bytes) || !utf8.Valid(v.Bytes) {
			continue
		}
		key := string(k.Bytes)
		if _, ok := byKey[key]; !ok {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], string(v.Bytes))
	}
	words := detect.Tokens(kp.table.Name)
	for _, key := range order {
		label := key
		if kp.meta != nil && kp.meta.Label != nil {
			label = kp.meta.Label(key)
		}
		prof := detect.NewProfileNamed(label).WithContext(words)
		for _, v := range byKey[key] {
			prof.Add(v)
		}
		sub := detect.Subject{Table: kp.table.Name, Column: kp.value, MetaKey: key, Name: label, Context: words, Sampled: true}
		for _, f := range detect.Analyze(sub, prof) {
			if f.Confidence < model.ConfidenceMedium {
				continue
			}
			if old, ok := kp.byValues[key]; !ok || f.Severity > old.Severity {
				if kp.byValues == nil {
					kp.byValues = map[string]model.Finding{}
				}
				kp.byValues[key] = f
			}
		}
	}
}

// keyVerdict judges a key/value row by its key: the table's findings for the
// key, a key family's, the result's own values under the key, then the
// presets' hint and the key's name.
func (r *Redactor) keyVerdict(kp *kvPlan, key Value) (model.Finding, bool) {
	if key.Null || key.Withheld > 0 || !utf8.Valid(key.Bytes) {
		return model.Finding{}, false
	}
	k := string(key.Bytes)
	label := k
	var hint *detect.Hint
	shown := detect.ShowKey(k)
	if kp.meta != nil {
		if kp.meta.Label != nil {
			label = kp.meta.Label(k)
			shown = detect.ShowKey(label)
		}
		if kp.meta.Guard && detect.FreeTextKey(k) {
			shown = detect.HiddenKey
		}
		if h := kp.meta.Keys[k]; h != nil {
			hint = h
		} else if kp.meta.HintFor != nil {
			hint = kp.meta.HintFor(k)
		}
	}
	// The table's verdict and the result's own values each count; a verdict
	// on the whole value beats one on a path inside it, then severity.
	var best *model.Finding
	consider := func(f model.Finding) {
		if best == nil || (f.Path == "") != (best.Path == "") && f.Path == "" ||
			(f.Path == "") == (best.Path == "") && f.Severity > best.Severity {
			best = &f
		}
	}
	if f, ok := kp.exact[strings.ToLower(shown)]; ok {
		consider(f)
	}
	for _, f := range kp.families {
		if globMatch(strings.ToLower(f.MetaKey), strings.ToLower(label)) {
			consider(f)
		}
	}
	if f, ok := kp.byValues[k]; ok {
		consider(f)
	}
	if best != nil {
		return *best, true
	}
	sub := detect.Subject{Table: kp.table.Name, Column: kp.value, MetaKey: k, Name: label,
		Context: detect.Tokens(kp.table.Name), Hint: hint}
	var w *model.Finding
	for _, f := range detect.Analyze(sub, nil) {
		if f.Confidence >= model.ConfidenceMedium && (w == nil || f.Severity > w.Severity) {
			w = &f
		}
	}
	if w == nil {
		return model.Finding{}, false
	}
	return *w, true
}

// globMatch matches a key against a family's pattern, where * stands for
// any run of characters.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i, part := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(s, part)
		}
		j := strings.Index(s, part)
		if j < 0 {
			return false
		}
		s = s[j+len(part):]
	}
	return true
}

// text shows a text value: accounts in SHOW output, then a JSON or PHP-
// serialized value edited leaf by leaf, or spans in plain text. An error
// means the value is withheld.
func (r *Redactor) text(s string, paths map[string]model.Category) (string, bool, error) {
	s0 := s
	s = accounts(s)
	out, edited, err := detect.EditStructured(s, func(l detect.Leaf) (string, bool) {
		path := detect.JoinPath(l.Path)
		switch l.Kind {
		case detect.LeafKey:
			if l.DataKey && !r.copy {
				return r.Token(r.keyKind(l.Key), []byte(l.Key)), true
			}
		case detect.LeafString, detect.LeafNumber:
			// A number can't hold a token: its edit fails, and the whole
			// value is withheld.
			if cat, ok := paths[path]; ok {
				return r.Token(string(cat), []byte(l.Value)), true
			}
			if key := lastKey(l.Path); !r.copy && key != "" {
				if nm := detect.MatchName(detect.NameWords(key), nil, detect.TypeString); nm != nil {
					return r.Token(string(nm.Category), []byte(l.Value)), true
				}
			}
			if l.Kind == detect.LeafString {
				if t := r.spans(l.Value); t != l.Value {
					return t, true
				}
			}
		}
		return "", false
	})
	switch {
	case err == nil:
		return out, edited || out != s0, nil
	case errors.Is(err, detect.ErrNotStructured):
		t := r.spans(s)
		return t, t != s0, nil
	}
	return "", false, err
}

// lastKey is the name a leaf sits under: its path's last segment that is a
// key, past array elements ("[]") and keys that are data ("*", "{}").
func lastKey(path []string) string {
	for i := len(path) - 1; i >= 0; i-- {
		switch path[i] {
		case "[]", "*", "{}":
			continue
		}
		return path[i]
	}
	return ""
}

// keyKind is the token kind of a key that is itself data.
func (r *Redactor) keyKind(key string) string {
	if spans := detect.FindSpans(key, r.finders); len(spans) > 0 {
		return spans[0].Kind
	}
	return "data_key"
}

// spans replaces the spans the finders find by their kind's token.
func (r *Redactor) spans(s string) string {
	spans := detect.FindSpans(s, r.finders)
	if len(spans) == 0 {
		return s
	}
	var b strings.Builder
	at := 0
	for _, sp := range spans {
		b.WriteString(s[at:sp.Start])
		b.WriteString(r.Token(sp.Kind, []byte(s[sp.Start:sp.End])))
		at = sp.End
	}
	b.WriteString(s[at:])
	return b.String()
}

// Text shows a text from the schema, such as a comment: accounts and spans
// replaced, withheld if it isn't valid UTF-8.
func (r *Redactor) Text(s string) string {
	if !utf8.ValidString(s) {
		return Withheld
	}
	return report.Clean(cut(r.spans(accounts(s))))
}

// finders are the span finders: under --copy, secrets, passwords in URLs
// and password hashes only; otherwise every built-in one but loose phone
// numbers, with the keep-list (reserved example emails, published test
// cards, and loopback, unspecified and documentation addresses) shown as
// stored. Both add the * and 40 hex hash, which the built-in finder doesn't
// read.
func finders(checkedCopy bool) []detect.SpanFinder {
	var out []detect.SpanFinder
	for _, f := range detect.SpanFinders() {
		switch f.Kind {
		case detect.SpanSecret, detect.SpanURLPassword, detect.SpanPasswordHash:
			out = append(out, f)
		case detect.SpanLoosePhone:
		default:
			if !checkedCopy {
				out = append(out, f.Keep(keep))
			}
		}
	}
	return append(out, detect.SpanFinder{Kind: detect.SpanPasswordHash, Find: nativeHashes})
}

// keep reports whether a span is replaced: not when it's on the keep-list.
func keep(text string, sp detect.Span) bool {
	switch sp.Kind {
	case detect.SpanEmail:
		return sp.Detail != "reserved"
	case detect.SpanCard:
		return sp.Detail != "test"
	case detect.SpanIP:
		addr, err := netip.ParseAddr(strings.Trim(text[sp.Start:sp.End], "[]"))
		return err != nil || !documentation(addr.Unmap())
	}
	return true
}

var docPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32"),
}

// documentation reports a loopback, unspecified or documentation address.
func documentation(a netip.Addr) bool {
	if a.IsLoopback() || a.IsUnspecified() {
		return true
	}
	for _, p := range docPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// nativeHash is MySQL's mysql_native_password hash: * and 40 hex digits.
var nativeHash = regexp.MustCompile(`\*[0-9A-Fa-f]{40}`)

func nativeHashes(s string) []detect.Span {
	var out []detect.Span
	for _, loc := range nativeHash.FindAllStringIndex(s, -1) {
		if loc[1] < len(s) && isHex(s[loc[1]]) {
			continue
		}
		out = append(out, detect.Span{Start: loc[0], End: loc[1], Kind: detect.SpanPasswordHash, Detail: "mysql_native_password"})
	}
	return out
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// Accounts and connections in SHOW output: a view's, trigger's or
// routine's definer, and a FEDERATED table's connection string.
var (
	definerClause = regexp.MustCompile("(?i)\\bDEFINER\\s*=\\s*(`[^`]*`|'[^']*'|\"[^\"]*\"|[^\\s@]+)\\s*@\\s*(`[^`]*`|'[^']*'|\"[^\"]*\"|[^\\s*/]+)")
	connClause    = regexp.MustCompile(`(?i)\bCONNECTION\s*=\s*'(?:[^'\\]|\\.|'')*'`)
)

func accounts(s string) string {
	if !strings.Contains(strings.ToUpper(s), "DEFINER") && !strings.Contains(strings.ToUpper(s), "CONNECTION") {
		return s
	}
	s = definerClause.ReplaceAllString(s, "DEFINER=[account]")
	return connClause.ReplaceAllString(s, "CONNECTION='[redacted]'")
}

// tokenText finds the tokens in a value shown, so a cut never splits one.
var tokenText = regexp.MustCompile(`\[(?:[a-z_]+ [0-9a-f]{12}|binary \d+ bytes [0-9a-f]{12}|account|redacted|withheld)\]`)

// cut cuts a value shown at ValueChars characters, never inside a token.
func cut(s string) string {
	n := utf8.RuneCountInString(s)
	if n <= ValueChars {
		return s
	}
	at, i := 0, 0
	for at = range s {
		if i == ValueChars {
			break
		}
		i++
	}
	for _, loc := range tokenText.FindAllStringIndex(s, -1) {
		if loc[0] < at && at < loc[1] {
			at = loc[0]
			break
		}
	}
	return s[:at] + "…(" + thousands(utf8.RuneCountInString(s[at:])) + " more characters)"
}

func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// typeClass is a result or schema column type's class: string, number,
// date and time, or binary (BLOB, VARBINARY, BINARY, BIT and GEOMETRY).
func typeClass(t string) string {
	t = strings.TrimPrefix(strings.ToUpper(t), "UNSIGNED ")
	switch {
	case strings.Contains(t, "BLOB") || strings.Contains(t, "BINARY") || t == "BIT" || t == "GEOMETRY":
		return "binary"
	case strings.Contains(t, "INT") || t == "DECIMAL" || t == "NUMERIC" || t == "FLOAT" || t == "DOUBLE" || t == "REAL" ||
		t == "NEWDECIMAL" || t == "DEC" || t == "FIXED":
		return "number"
	case t == "DATE" || t == "DATETIME" || t == "TIMESTAMP" || t == "TIME" || t == "YEAR" || t == "NEWDATE":
		return "date"
	}
	return "string"
}

// dataType is a result column's type as information_schema's DATA_TYPE
// would give it, for the name rules.
func dataType(t string) string {
	return strings.ToLower(strings.TrimPrefix(strings.ToUpper(t), "UNSIGNED "))
}

// classType is a type of the class, for judging a label by name.
func classType(class string) string {
	switch class {
	case "number":
		return "int"
	case "date":
		return "datetime"
	case "binary":
		return "blob"
	}
	return "varchar"
}
