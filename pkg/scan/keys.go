package scan

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// Limits for reading key/value tables. A small table is read whole; a
// bigger one has its keys listed and each key looked up; a table too big
// to list is sampled as before, plus probes for the keys presets know.
const (
	wholeRows        = 20000     // rows a table may have to be read whole
	wholeBytes       = 32 << 20  // and bytes of data
	listMaxBytes     = 256 << 20 // data a table may hold to be listed with a full scan
	maxListedKeys    = 200000
	tableKeys        = 3000     // keys looked up per table
	tableBytes       = 32 << 20 // value bytes read per table, whole, by lookups and by probes
	scanKeys         = 30000    // keys looked up per scan
	scanBytes        = 256 << 20
	scanListBytes    = 1 << 30 // full-scan listings and probe scans per scan
	familySample     = 20      // members of a family looked up
	probeRows        = 20      // rows per prefix probe
	settingsValueLen = 65536   // values read from a settings table
)

type kvMode int

const (
	modeWhole  kvMode = iota + 1 // the whole table in one read
	modeList                     // list the keys, then look each up
	modeSample                   // a window of rows, plus probes
)

// budget is what a scan has left to spend on key/value tables. Tables draw
// on it in planning order and are charged what they actually read.
type budget struct {
	keys      int
	bytes     int64
	listBytes int64
}

func newBudget() *budget { return &budget{keys: scanKeys, bytes: scanBytes, listBytes: scanListBytes} }

// tableFacts is what the choice of a mode depends on.
type tableFacts struct {
	rows, bytes   int64 // information_schema estimates
	index         model.IndexUse
	serverTimeout bool
	sampleOnly    bool
}

func factsOf(t *model.Table, meta *preset.MetaTable, sess *dbconn.Session, opts Options) tableFacts {
	return tableFacts{rows: t.RowsEstimate, bytes: t.DataBytes, index: t.KeyIndex(meta.Key),
		serverTimeout: sess.ServerTimeout, sampleOnly: opts.SampleKeysOnly}
}

// chooseMode picks how to read a key/value table. The estimates only pick
// the first mode: a whole read checks the rows it gets and falls back.
func chooseMode(f tableFacts, b *budget) kvMode {
	switch {
	case f.sampleOnly:
		return modeSample
	case f.rows <= wholeRows && f.bytes <= wholeBytes && b.bytes >= max(f.bytes, 1):
		return modeWhole
	case canList(f, b):
		return modeList
	}
	return modeSample
}

// canList reports whether a table's keys may be listed: through a full
// index at any size, or with a full scan of at most listMaxBytes; always
// under a server-side timeout.
func canList(f tableFacts, b *budget) bool {
	if !f.index.Found || !f.serverTimeout || b.keys <= 0 || b.bytes <= 0 {
		return false
	}
	return f.index.Full || (f.bytes <= listMaxBytes && b.listBytes >= f.bytes)
}

// fallbackMode picks the mode after a whole read fell short: listing the
// keys, unless the read timed out and listing would scan the same table.
func fallbackMode(err error, f tableFacts, b *budget) kvMode {
	if err != nil && dbconn.IsTimeout(err) && !f.index.Full {
		return modeSample
	}
	if canList(f, b) {
		return modeList
	}
	return modeSample
}

// sampleReason says why a table's keys were sampled rather than listed.
func sampleReason(f tableFacts, b *budget, kv *kvRead) string {
	switch {
	case kv.why != "":
		return kv.why
	case f.sampleOnly:
		return "listing was turned off"
	case !f.index.Found:
		return "its key column has no index"
	case !f.serverTimeout:
		return "the server has no statement timeout"
	case b.keys <= 0 || b.bytes <= 0:
		return "the scan's key or byte budget was spent"
	case !f.index.Full && f.bytes <= listMaxBytes:
		return "the scan's budget for full scans was spent"
	}
	return "the table is too large to list them"
}

// How a table's probes run.
type probeKind int

const (
	probeNone        probeKind = iota
	probeBatch                 // indexed lookups
	probeScan                  // one pass over a small table
	probeScanCharged           // one pass over a bigger one, charged to the full-scan budget
)

// probeHow picks how to probe a table: indexed lookups, or one pass over a
// table whose key column has no index. The pass runs on a small table, or
// on a bigger one when the server enforces the statement timeout and the
// full-scan budget allows. big says a whole read found the table bigger
// than its estimates. The reason says what stopped the probes otherwise.
func probeHow(f tableFacts, big bool, bytesLeft int64, b *budget) (probeKind, string) {
	small := !big && f.rows <= wholeRows && f.bytes <= wholeBytes
	switch {
	case bytesLeft <= 0:
		return probeNone, "the byte budget was spent"
	case f.index.Found:
		return probeBatch, ""
	case small:
		return probeScan, ""
	case !f.serverTimeout:
		return probeNone, "its key column has no index, and the server has no statement timeout"
	case b.listBytes < f.bytes:
		return probeNone, "its key column has no index, and the scan's budget for full scans was spent"
	}
	return probeScanCharged, ""
}

// planOrder puts the key/value tables first: the main site's and shared
// preset tables, then the other preset tables (multisite sub-sites), then
// generic ones, each group by name; then every other table by name.
func planOrder(tables []*model.Table, metas map[string]*preset.MetaTable) []*model.Table {
	tier := func(t *model.Table) int {
		m := metas[t.Name]
		switch {
		case m == nil:
			return 4
		case m.Primary:
			return 1
		case m.Platform != "":
			return 2
		}
		return 3
	}
	out := append([]*model.Table(nil), tables...)
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := tier(out[i]), tier(out[j]); a != b {
			return a < b
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// keySubject is one key, or one family of keys, to judge.
type keySubject struct {
	label   string // what the key is judged as
	shown   string // how reports show it
	keys    []string
	family  *detect.KeyFamily
	hint    *detect.Hint
	tier    int      // lookup order: lower first
	lookups []string // keys to look up for values
	skipped bool     // left without lookups by a limit
}

// Lookup tiers.
const (
	tierPreset = iota + 1 // keys, probes and families a preset knows
	tierNamed             // keys whose names match a rule
	tierSingle            // other single keys
	tierFamily            // families found by shape
	tierCache             // keys and families with a delete hint
)

// subjects groups the known keys of a table into single keys and families
// and orders them for lookups. In a table the key-shape guard reads, keys
// that read as free text are shown as HiddenKey, whenever they were found.
func subjects(t *model.Table, meta *preset.MetaTable, keys []string) []*keySubject {
	words := detect.Tokens(t.Name)
	hide := func(k string) bool { return meta.Guard && detect.FreeTextKey(k) }
	probe := map[string]bool{}
	for _, k := range meta.Probe {
		probe[k] = true
	}
	var out []*keySubject
	addSingle := func(k string) {
		label := k
		if meta.Label != nil {
			label = meta.Label(k)
		}
		s := &keySubject{label: label, shown: detect.ShowKey(label), keys: []string{k}, lookups: []string{k}, hint: meta.Hint(k)}
		if hide(k) {
			s.shown = detect.HiddenKey
		}
		switch {
		case meta.Keys[k] != nil || probe[k]:
			s.tier = tierPreset
		case s.hint != nil && s.hint.Delete && s.hint.Category == "":
			s.tier = tierCache
		case !meta.Labels && detect.MatchName(detect.NameWords(label), words, detect.TypeString) != nil:
			s.tier = tierNamed
		default:
			s.tier = tierSingle
		}
		out = append(out, s)
	}
	if meta.Label != nil { // Magento EAV: keys are attribute IDs, never grouped
		for _, k := range keys {
			addSingle(k)
		}
		return sortSubjects(out)
	}
	exact := func(k string) bool { return meta.Keys[k] != nil || probe[k] }
	singles, families := detect.GroupKeys(keys, meta.Families, exact)
	for _, k := range singles {
		addSingle(k)
	}
	for i := range families {
		f := &families[i]
		s := &keySubject{label: f.Pattern, shown: detect.ShowPattern(f.Pattern), keys: f.Keys, family: f,
			hint: f.Hint, lookups: spread(f.Keys, familySample)}
		if slices.ContainsFunc(f.Keys, hide) {
			s.shown = detect.HiddenKey
		}
		if s.hint == nil {
			s.hint = meta.Hint(f.Keys[0])
		}
		switch {
		case f.Known():
			s.tier = tierPreset
		case s.hint != nil && s.hint.Delete:
			s.tier = tierCache
		default:
			s.tier = tierFamily
		}
		out = append(out, s)
	}
	return sortSubjects(out)
}

func sortSubjects(s []*keySubject) []*keySubject {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].tier != s[j].tier {
			return s[i].tier < s[j].tier
		}
		return s[i].label < s[j].label
	})
	return s
}

// spread picks up to n keys spread over a sorted list.
func spread(keys []string, n int) []string {
	if len(keys) <= n {
		return append([]string(nil), keys...)
	}
	out := make([]string, n)
	for i := range out {
		out[i] = keys[i*len(keys)/n]
	}
	return out
}

// planLookups keeps the lookups of the subjects that fit within limit
// keys, in their order, and marks the rest as skipped.
func planLookups(subs []*keySubject, limit int) (lookups []string) {
	for _, s := range subs {
		if len(s.lookups) == 0 {
			continue
		}
		if len(lookups)+len(s.lookups) > limit {
			s.lookups, s.skipped = nil, true
			continue
		}
		lookups = append(lookups, s.lookups...)
	}
	return lookups
}

// kvRead is what was read from one key/value table.
type kvRead struct {
	mode      kvMode
	keys      []string               // every key known, in its stored spelling
	known     map[string]bool        // the keys in keys
	values    map[string][]sample.KV // values per key, from whole reads, lookups and probes
	pks       map[string]bool        // primary keys of the rows in values
	read      map[string]bool        // keys whose values were looked for
	partial   map[string]bool        // family prefixes whose probe hit its limit
	probed    map[string]bool        // family prefixes whose probe ran to its end
	truncated bool                   // the listing stopped at maxListedKeys
	big       bool                   // a whole read found more than the estimates said
	why       string                 // why the keys weren't listed, when that isn't plain from the facts
	left      int64                  // value bytes this table may still read
	subjects  []*keySubject
	rows      int // rows read besides the window
	warnings  []string
	failed    []string // the warnings about statements that failed or timed out
	// The key-shape guard's verdict on a table found without a preset:
	// keyed by data, so judged as a plain table; and how many of its keys
	// look like people's names.
	demoted bool
	people  int
}

// guard applies the key-shape guard to the keys read so far, when the
// table's shape needs it. It reports whether the table turned out to be
// keyed by data.
func (kv *kvRead) guard(meta *preset.MetaTable) bool {
	if meta.Guard {
		kv.people, kv.demoted = guardKeys(kv.keys)
	}
	return kv.demoted
}

// guardKeys counts the keys of a generic key/value table that look like
// people's names, and reports whether that is half or more, which makes the
// table keyed by data. They are free-text keys (with a space, and not read
// as labels) with no known word (Jane Doe), and families of five or more
// that share their known words around two or more unknown ones (<first>
// <last> phone). Free-text keys are never shown, whatever the verdict.
func guardKeys(keys []string) (people int, demote bool) {
	families := map[string]int{}
	for _, k := range keys {
		if !detect.FreeTextKey(k) {
			continue
		}
		switch kw := detect.ReadKey(k); {
		case len(kw.Known) == 0:
			people++
		case kw.Unknown >= 2:
			families[strings.Join(kw.Known, " ")]++
		}
	}
	for _, n := range families {
		if n >= 5 {
			people += n
		}
	}
	return people, len(keys) > 0 && people*2 >= len(keys)
}

// failures returns the warnings about statements that failed or timed out,
// which stay when a table turns out not to be a key/value table.
func (kv *kvRead) failures() []string { return kv.failed }

// demotedKeyFinding reports the key column of a table the key-shape guard
// demoted, at low confidence: its keys may be the people's names the guard
// read, which the column's own name doesn't show, or text such as survey
// questions, so the starter config only suggests a rule. A translation
// table's keys are its source strings, never people's names: no finding.
func demotedKeyFinding(t *model.Table, meta *preset.MetaTable, kv *kvRead) *model.Finding {
	if meta.Labels {
		return nil
	}
	return &model.Finding{
		Table: t.Name, Column: meta.Key, Category: model.CatPersonName, Severity: model.SeverityLow,
		Confidence: model.ConfidenceLow, Sampled: len(kv.keys), Matched: kv.people, Mask: "hash", Source: "value",
		Reasons: []string{fmt.Sprintf("%d of %d keys may be people's names, alone or beside a field word", kv.people, len(kv.keys))},
		Note: "shaped like a key/value table, but keyed by data, so judged as a plain table; " +
			"hash keeps the keys distinct, if they are names",
	}
}

func newKVRead() *kvRead {
	return &kvRead{known: map[string]bool{}, values: map[string][]sample.KV{}, pks: map[string]bool{},
		read: map[string]bool{}, partial: map[string]bool{}, probed: map[string]bool{}, left: tableBytes}
}

func (kv *kvRead) warn(s string) { kv.warnings = append(kv.warnings, s) }

// fail warns about a statement that failed or timed out.
func (kv *kvRead) fail(s string) {
	kv.warn(s)
	kv.failed = append(kv.failed, s)
}

func (kv *kvRead) addKey(k string) {
	if !kv.known[k] {
		kv.known[k] = true
		kv.keys = append(kv.keys, k)
	}
}

// addRows keeps the rows read for a key, skipping rows already kept under
// another read, and marks the key read.
func (kv *kvRead) addRows(k string, rows []sample.KV) {
	for _, r := range rows {
		if r.PK != "" {
			if kv.pks[r.PK] {
				continue
			}
			kv.pks[r.PK] = true
		}
		kv.values[k] = append(kv.values[k], r)
		kv.rows++
	}
	kv.read[k] = true
}

// limit is what the next read of the table may spend: what is left of the
// table's and the scan's byte budgets.
func (kv *kvRead) limit(b *budget) int64 { return min(kv.left, b.bytes) }

func (kv *kvRead) spend(n int64, b *budget) {
	kv.left -= n
	b.bytes -= n
}

// kvColumns returns the key and value columns of a key/value table, or
// nils when either is missing or binary: binary values are never read.
func kvColumns(t *model.Table, meta *preset.MetaTable) (key, value *model.Column) {
	key, value = t.Column(meta.Key), t.Column(meta.Value)
	if key == nil || value == nil || !sample.Sampleable(key) || !sample.Sampleable(value) {
		return nil, nil
	}
	return key, value
}

func valueLenOf(sm *sample.Sampler, t *model.Table, meta *preset.MetaTable) int {
	if meta.Settings || t.KeyIndex(meta.Key).Unique {
		return settingsValueLen
	}
	return sm.MaxValueLen
}

// keyRows is how many rows a lookup reads per key: one in a settings table.
func keyRows(t *model.Table, meta *preset.MetaTable, opts Options) int {
	if meta.Settings || t.KeyIndex(meta.Key).Unique {
		return 1
	}
	return max(opts.KeySampleRows, 1)
}

// readKV reads a key/value table in mode W or L, or decides on S. In S
// the window comes first, and sampleKV probes afterwards.
func readKV(ctx context.Context, sess *dbconn.Session, sm *sample.Sampler, t *model.Table, meta *preset.MetaTable, opts Options, b *budget) *kvRead {
	kv := newKVRead()
	keyCol, valueCol := kvColumns(t, meta)
	if keyCol == nil {
		kv.mode = modeSample
		return kv
	}
	facts := factsOf(t, meta, sess, opts)
	valueLen := valueLenOf(sm, t, meta)
	kv.mode = chooseMode(facts, b)
	if kv.mode == modeWhole {
		rows, complete, read, err := sm.WholeTable(ctx, t, keyCol, valueCol, valueLen, wholeRows, kv.limit(b))
		kv.spend(read, b)
		kv.wholeRows(rows, opts.KeySampleRows)
		if err == nil && complete {
			kv.guard(meta)
			return kv
		}
		// A stale estimate, the byte limit or an error. The rows read so
		// far stay; the keys are listed for the rest.
		kv.big = true
		if err != nil {
			kv.fail(fmt.Sprintf("could not read %s whole (%s)", t.Name, dbconn.ErrorText(err)))
			if dbconn.IsTimeout(err) {
				kv.why = "reading it whole timed out"
			}
		}
		if kv.guard(meta) {
			return kv
		}
		kv.mode = fallbackMode(err, facts, b)
	}
	if kv.mode == modeList {
		if !facts.index.Full {
			b.listBytes -= t.DataBytes
		}
		keys, more, err := sm.Keys(ctx, t, keyCol, maxListedKeys)
		if err != nil {
			kv.fail(fmt.Sprintf("could not list the keys of %s (%s); sampled its rows instead", t.Name, dbconn.ErrorText(err)))
			kv.mode = modeSample
			kv.why = "listing them failed"
			return kv
		}
		for _, k := range keys {
			kv.addKey(k)
		}
		sort.Strings(kv.keys)
		kv.truncated = more
		if more {
			kv.warn(fmt.Sprintf("%s has more than %d keys; the first %d by name were listed, and the keys presets know were probed",
				t.Name, maxListedKeys, maxListedKeys))
		}
		// Before any value is looked up.
		if kv.guard(meta) {
			return kv
		}
		kv.lookup(ctx, sm, t, meta, keyCol, valueCol, valueLen, opts, b)
		if more {
			kv.probe(ctx, sm, t, meta, keyCol, valueCol, valueLen, facts, opts, b)
		}
	}
	return kv
}

// wholeRows keeps up to n values per key: half from the oldest rows, half
// from the newest.
func (kv *kvRead) wholeRows(rows []sample.KV, n int) {
	first := max(n/2, 1)
	type ring struct {
		head []sample.KV
		tail []sample.KV
		next int
	}
	by := map[string]*ring{}
	var order []string
	for _, r := range rows {
		g := by[r.Key]
		if g == nil {
			g = &ring{}
			by[r.Key] = g
			order = append(order, r.Key)
		}
		if len(g.head) < first {
			g.head = append(g.head, r)
			continue
		}
		if len(g.tail) < n-first {
			g.tail = append(g.tail, r)
			continue
		}
		if n-first > 0 {
			g.tail[g.next] = r
			g.next = (g.next + 1) % (n - first)
		}
	}
	for _, k := range order {
		g := by[k]
		kv.addKey(k)
		kv.addRows(k, append(g.head, g.tail...))
	}
	sort.Strings(kv.keys)
}

// lookup plans and runs the lookups of a listed table.
func (kv *kvRead) lookup(ctx context.Context, sm *sample.Sampler, t *model.Table, meta *preset.MetaTable,
	keyCol, valueCol *model.Column, valueLen int, opts Options, b *budget) {
	kv.subjects = subjects(t, meta, kv.keys)
	// Keys a whole read that fell short already has need no lookup.
	for _, s := range kv.subjects {
		s.lookups = slices.DeleteFunc(s.lookups, func(k string) bool { return kv.read[k] })
	}
	keys := planLookups(kv.subjects, min(tableKeys, b.keys))
	if len(keys) == 0 {
		return
	}
	perKey := keyRows(t, meta, opts)
	lookups := make([]sample.Lookup, len(keys))
	for i, k := range keys {
		lookups[i] = sample.Lookup{Key: k, Limit: perKey}
	}
	var (
		got sample.Batch
		err error
	)
	if kv.limit(b) > 0 {
		got, err = sm.KeyValuesBatch(ctx, t, keyCol, valueCol, lookups, valueLen, kv.limit(b))
		kv.spend(got.Bytes, b)
	}
	b.keys -= kv.settle(t, keys, got, err)
}

// settle keeps the rows of each lookup and marks the keys whose lookups
// ran, returning how many ran. Subjects whose lookups the byte limits left
// unrun count as skipped, as if they had never fit; after an error, the
// rest are judged by name.
func (kv *kvRead) settle(t *model.Table, keys []string, got sample.Batch, err error) (ran int) {
	for i, k := range keys {
		rows := got.Rows[i]
		if len(rows) == 0 && (i >= len(got.Complete) || !got.Complete[i]) {
			continue
		}
		kv.addRows(k, rows)
		ran++
	}
	if err != nil {
		kv.fail(fmt.Sprintf("stopped reading the keys of %s (%s); the rest are judged by name", t.Name, dbconn.ErrorText(err)))
		return ran
	}
	for _, s := range kv.subjects {
		if len(s.lookups) > 0 && !slices.ContainsFunc(s.lookups, func(k string) bool { return kv.read[k] }) {
			s.skipped = true
		}
	}
	return ran
}

// probe reads the keys a preset knows, and the families it knows by
// prefix, when the table's keys weren't all listed. Keys already read,
// whether whole, by lookup or in the window, aren't probed again.
func (kv *kvRead) probe(ctx context.Context, sm *sample.Sampler, t *model.Table, meta *preset.MetaTable,
	keyCol, valueCol *model.Column, valueLen int, facts tableFacts, opts Options, b *budget) {
	lookups := probeLookups(meta, keyCol, keyRows(t, meta, opts), func(k string) bool { return kv.read[k] })
	if len(lookups) == 0 {
		return
	}
	how, why := probeHow(facts, kv.big, kv.limit(b), b)
	var (
		got sample.Batch
		err error
	)
	switch how {
	case probeBatch:
		got, err = sm.KeyValuesBatch(ctx, t, keyCol, valueCol, lookups, valueLen, kv.limit(b))
	case probeScan, probeScanCharged:
		if how == probeScanCharged {
			b.listBytes -= facts.bytes
		}
		got, err = sm.ProbeScan(ctx, t, keyCol, valueCol, lookups, valueLen, kv.limit(b))
	default:
		kv.warn(fmt.Sprintf("the keys presets know were not probed in %s: %s", t.Name, why))
		return
	}
	kv.spend(got.Bytes, b)
	if err != nil {
		kv.fail(fmt.Sprintf("stopped probing the keys of %s (%s)", t.Name, dbconn.ErrorText(err)))
	}
	before := maps.Clone(kv.read) // without primary keys, rows of these keys can't be told apart
	for i, l := range lookups {
		rows := got.Rows[i]
		if !l.Prefix {
			if len(rows) > 0 {
				kv.addKey(l.Key)
				kv.addRows(l.Key, rows)
			}
			continue
		}
		// A family's count is exact only when its probe ran to its end
		// with room to spare.
		if got.Complete[i] {
			kv.probed[l.Key] = true
		}
		if len(rows) >= l.Limit {
			kv.partial[l.Key] = true
		}
		byKey := map[string][]sample.KV{}
		var order []string
		for _, r := range rows {
			if r.PK == "" && before[r.Key] {
				continue
			}
			if _, ok := byKey[r.Key]; !ok {
				order = append(order, r.Key)
			}
			byKey[r.Key] = append(byKey[r.Key], r)
		}
		for _, k := range order {
			kv.addKey(k)
			kv.addRows(k, byKey[k])
		}
	}
	sort.Strings(kv.keys)
}

// probeLookups lists a table's probes: the keys its preset knows, one row
// each in a settings table; and, on a text key column, the prefixes of the
// families the preset knows, plus the known data prefixes on WordPress
// tables. A LIKE on a numeric key column could use no index.
func probeLookups(meta *preset.MetaTable, keyCol *model.Column, perKey int, done func(string) bool) []sample.Lookup {
	exact := append(append([]string(nil), meta.Probe...), presetKeys(meta)...)
	sort.Strings(exact)
	var out []sample.Lookup
	for _, k := range slices.Compact(exact) {
		if !done(k) {
			out = append(out, sample.Lookup{Key: k, Limit: perKey})
		}
	}
	if !sample.IsText(keyCol) {
		return out
	}
	for _, p := range familyPrefixes(meta) {
		out = append(out, sample.Lookup{Key: p, Prefix: true, Limit: probeRows})
	}
	return out
}

func presetKeys(meta *preset.MetaTable) []string {
	out := make([]string, 0, len(meta.Keys))
	for k := range meta.Keys {
		out = append(out, k)
	}
	return out
}

// familyPrefixes lists the prefixes of the families a preset knows, and on
// WordPress tables the known data prefixes, which plugins for it use.
func familyPrefixes(meta *preset.MetaTable) []string {
	var out []string
	for _, f := range meta.Families {
		out = append(out, f.Prefix)
	}
	if meta.Platform == "wordpress" {
		out = append(out, detect.DataPrefixes()...)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// sampleKV completes mode S: the window's rows, then probes for what the
// window missed.
func (kv *kvRead) sampleKV(ctx context.Context, sm *sample.Sampler, sess *dbconn.Session, t *model.Table,
	meta *preset.MetaTable, s *sample.Sample, opts Options, b *budget) {
	keyCol, valueCol := kvColumns(t, meta)
	if keyCol == nil {
		return
	}
	rows := 0
	if s != nil {
		rows = len(s.Rows)
		if ki := s.Index(meta.Key); ki >= 0 {
			for _, r := range s.Rows {
				if r[ki].Valid {
					kv.addKey(r[ki].String)
					kv.read[r[ki].String] = true
				}
			}
		}
	}
	sort.Strings(kv.keys)
	if kv.guard(meta) {
		return
	}
	facts := factsOf(t, meta, sess, opts)
	kv.warn(fmt.Sprintf("the keys of %s were sampled, not listed (%s): only the keys in %d sampled rows and those presets know were checked",
		t.Name, sampleReason(facts, b, kv), rows))
	kv.probe(ctx, sm, t, meta, keyCol, valueCol, valueLenOf(sm, t, meta), facts, opts, b)
}

// analyzeKV judges every key and family of a key/value table. hidden counts
// the keys shown as HiddenKey that hold confident findings.
func analyzeKV(t *model.Table, s *sample.Sample, meta *preset.MetaTable, kv *kvRead) (out []model.Finding, hidden int) {
	// Values from whole reads, lookups and probes win over the window's
	// copy of the same row, which is cut shorter. Without a primary key to
	// tell rows apart, the window adds nothing to keys read another way.
	looked := map[string]bool{}
	values := map[string][]string{}
	for k, rows := range kv.values {
		looked[k] = true
		for _, r := range rows {
			if !r.Null {
				values[k] = append(values[k], r.Value)
			}
		}
	}
	if s != nil {
		ki, vi := s.Index(meta.Key), s.Index(meta.Value)
		pi := -1
		if pk := t.SinglePK(); pk != nil {
			pi = s.Index(pk.Name)
		}
		if ki >= 0 && vi >= 0 {
			for _, r := range s.Rows {
				if !r[ki].Valid {
					continue
				}
				k := r[ki].String
				switch {
				case pi >= 0 && kv.pks[r[pi].String]:
					continue
				case pi < 0 && looked[k]:
					continue
				}
				if r[vi].Valid {
					values[k] = append(values[k], r[vi].String)
				}
				kv.read[k] = true
			}
		}
	}
	// Keys found after the lookups were planned (probes, and window rows
	// whose spelling the listing folded away) are judged too.
	covered := map[string]bool{}
	for _, s := range kv.subjects {
		for _, k := range s.keys {
			covered[k] = true
		}
	}
	var extra []string
	for _, k := range kv.keys {
		if !covered[k] {
			covered[k] = true
			extra = append(extra, k)
		}
	}
	for k := range values {
		if !covered[k] {
			covered[k] = true
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		kv.subjects = append(kv.subjects, subjects(t, meta, extra)...)
	}
	setting := meta.Settings || t.KeyIndex(meta.Key).Unique
	words := detect.Tokens(t.Name)
	for _, sub := range kv.subjects {
		p := detect.NewProfileNamed(sub.label).WithContext(words)
		sampled := false
		for _, k := range sub.keys {
			if kv.read[k] {
				sampled = true
			}
			for _, v := range values[k] {
				p.Add(v)
			}
		}
		partial := false
		if sub.family != nil && (kv.mode == modeSample || kv.truncated) {
			// Sampled or cut-off keys only show part of a family, unless its
			// probe ran to its end with fewer rows than it asked for.
			prefix := strings.TrimSuffix(sub.family.Pattern, "*")
			partial = kv.partial[prefix] || !kv.probed[prefix]
		}
		keys := 0
		if sub.family != nil {
			keys = len(sub.keys)
		}
		ds := detect.Subject{
			Table: t.Name, Column: meta.Value, MetaKey: sub.shown, Name: sub.label, Context: words,
			Hint: sub.hint, Sampled: sampled, Skipped: !sampled && sub.skipped,
			Keys: keys, KeysPartial: partial, Setting: setting, Labels: meta.Labels,
		}
		var prof *detect.Profile
		if sampled {
			prof = p
		}
		fs := detect.Analyze(ds, prof)
		if sub.shown == detect.HiddenKey {
			// The words a rule matched are words of the key, which isn't
			// shown; a path's are words of the path, which is.
			for i := range fs {
				if fs[i].Path != "" {
					continue
				}
				for j, r := range fs[i].Reasons {
					if strings.HasPrefix(r, "name contains ") {
						fs[i].Reasons[j] = "the key's name matches a naming rule"
					}
				}
			}
			if slices.ContainsFunc(fs, func(f model.Finding) bool { return f.Confidence > model.ConfidenceLow }) {
				hidden += max(len(sub.keys), 1)
			}
		}
		out = append(out, fs...)
		if sub.family != nil && sub.family.Carries != "" {
			out = append(out, detect.KeyNameFinding(t.Name, meta.Key, sub.shown, sub.family, partial))
		}
	}
	return out, hidden
}

// skippedSummary counts the keys a limit left without values, and how
// many of them match a naming rule. Keys the window sampled don't count,
// and a translation table's keys never match.
func skippedSummary(t *model.Table, meta *preset.MetaTable, kv *kvRead) (skipped, named int) {
	words := detect.Tokens(t.Name)
	for _, s := range kv.subjects {
		if !s.skipped || slices.ContainsFunc(s.keys, func(k string) bool { return kv.read[k] }) {
			continue
		}
		skipped += len(s.keys)
		if !meta.Labels && detect.MatchName(detect.NameWords(s.label), words, detect.TypeString) != nil {
			named += len(s.keys)
		}
	}
	return
}
