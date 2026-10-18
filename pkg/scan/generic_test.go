package scan

import (
	"database/sql"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

func col(name, dataType string) *model.Column { return &model.Column{Name: name, DataType: dataType} }

// Key/value shapes found without a preset, and the names that keep a table
// plain.
func TestGenericMetaShapes(t *testing.T) {
	cases := []struct {
		name, table   string
		cols          []*model.Column
		key           string
		labels, guard bool
	}{
		{"param and value in a settings table", "setting", []*model.Column{col("id", "int"), col("param", "varchar"), col("value", "text")},
			"param", false, false},
		{"param and value elsewhere", "orders", []*model.Column{col("param", "varchar"), col("value", "text")}, "", false, false},
		{"setting_name", "settings", []*model.Column{col("setting_name", "varchar"), col("setting_value", "text")},
			"setting_name", false, true},
		{"field_name", "cf7dbplugin_submits", []*model.Column{col("field_name", "varchar"), col("field_value", "longtext")},
			"field_name", false, true},
		{"X_name with no entry word", "stats", []*model.Column{col("stat_name", "varchar"), col("stat_value", "text")}, "", false, false},
		{"X_name with an integer value", "settings", []*model.Column{col("setting_name", "varchar"), col("setting_value", "int")},
			"", false, false},
		{"a person's name", "customers", []*model.Column{col("customer_name", "varchar"), col("customer_value", "text")},
			"", false, false},
		{"a contact's name", "contacts", []*model.Column{col("contact_name", "varchar"), col("contact_value", "text")},
			"", false, false},
		{"members in a settings table", "member_settings", []*model.Column{col("member_name", "varchar"), col("member_value", "text")},
			"", false, false},
		{"users' keys", "user_settings", []*model.Column{col("user_key", "varchar"), col("user_value", "text")}, "", false, false},
		{"licence keys", "licenses", []*model.Column{col("license_key", "varchar"), col("license_value", "text")}, "", false, false},
		{"message keys stay", "aiowps_message_store", []*model.Column{col("message_key", "varchar"), col("message_value", "text")},
			"message_key", false, true},
		{"key and value", "kv", []*model.Column{col("key", "varchar"), col("value", "text")}, "key", false, true},
		{"a translation table", "ab_language_definitions",
			[]*model.Column{col("language_key", "varchar"), col("language_value", "text")}, "language_key", true, true},
		{"i18n", "app_i18n", []*model.Column{col("key", "varchar"), col("value", "text")}, "key", true, true},
		{"language preferences are settings", "user_language_preferences",
			[]*model.Column{col("pref_key", "varchar"), col("pref_value", "text")}, "pref_key", false, true},
	}
	for _, c := range cases {
		m := genericMeta(&model.Table{Name: c.table, Columns: c.cols}, &preset.Result{})
		got := ""
		if m != nil {
			got = m.Key
		}
		if got != c.key || (m != nil && (m.Labels != c.labels || m.Guard != c.guard)) {
			t.Errorf("%s: got %+v, want key %q, labels %v, guard %v", c.name, m, c.key, c.labels, c.guard)
		}
	}
}

func TestGuardKeys(t *testing.T) {
	names := []string{"Jane Doe", "John Roe", "Maria Papadopoulou", "Kostas Ioannou", "Helen Smith", "theme"}
	if people, demote := guardKeys(names); !demote || people != 5 {
		t.Errorf("a table keyed by people's names: %d people, demoted %v", people, demote)
	}
	labels := []string{"Your Name", "Emergency contact", "Phone number", "Gift message", "VAT number", "shipping method",
		"Date of birth", "Bank account", "billing_email", "Jane Doe phone"}
	if _, demote := guardKeys(labels); demote {
		t.Error("a table keyed by labels is demoted")
	}
	for _, k := range labels {
		if free := detect.FreeTextKey(k); free != (k == "Jane Doe phone") {
			t.Errorf("%q: free text %v", k, free)
		}
	}
	titles := []string{"Date Of Birth", "Next Of Kin", "Shoe Size", "Marital Status", "Tax ID", "Phone Number", "Email"}
	if _, demote := guardKeys(titles); demote {
		t.Error("a title-case form table is demoted")
	}
	var family []string
	for _, n := range []string{"Jane Doe", "John Roe", "Ann Lee", "Bob Ray", "Tim Fox", "Maria Day"} {
		family = append(family, n+" phone", n+" email")
	}
	// Maria Day holds a known word, so her two keys form families too small
	// to count.
	if people, demote := guardKeys(family); !demote || people != len(family)-2 {
		t.Errorf("a table keyed by <first> <last> phone: %d people, demoted %v", people, demote)
	}
}

// A demoted table's key column is a weak person-name match, never a rule
// to apply; a translation table's source strings aren't names at all.
func TestDemotedKeyFinding(t *testing.T) {
	kv := newKVRead()
	for _, k := range []string{"Jane Doe", "John Roe", "theme"} {
		kv.addKey(k)
	}
	kv.people, kv.demoted = guardKeys(kv.keys)
	f := demotedKeyFinding(&model.Table{Name: "kv"}, &preset.MetaTable{Key: "key", Value: "value", Guard: true}, kv)
	if f == nil || f.Column != "key" || f.Category != model.CatPersonName || f.Confidence != model.ConfidenceLow ||
		f.Severity != model.SeverityLow || f.Mask != "hash" || f.Matched != 2 || f.Sampled != 3 {
		t.Errorf("got %+v", f)
	}
	if f := demotedKeyFinding(&model.Table{Name: "ltm_translations"},
		&preset.MetaTable{Key: "key", Value: "value", Labels: true, Guard: true}, kv); f != nil {
		t.Errorf("translation table: got %+v", f)
	}
}

// A table that turns out not to be a key/value table keeps the warnings
// about failed or timed-out statements, and only those.
func TestKVFailures(t *testing.T) {
	kv := newKVRead()
	kv.fail("could not read kv whole (statement timed out)")
	kv.warn("kv has more than 200000 keys; the first 200000 by name were listed, and the keys presets know were probed")
	kv.fail("stopped reading the keys of kv (statement timed out); the rest are judged by name")
	kv.warn("the keys of kv were sampled, not listed (listing was turned off): only the keys in 30 sampled rows and those presets know were checked")
	got := kv.failures()
	if len(got) != 2 || !strings.HasPrefix(got[0], "could not") || !strings.HasPrefix(got[1], "stopped") || len(kv.warnings) != 4 {
		t.Errorf("got %q of %d warnings", got, len(kv.warnings))
	}
}

// The sampler reads short binary columns named like IP addresses as hex,
// unless a preset judges the column; hashes of addresses aren't decoded.
func TestHexColumn(t *testing.T) {
	pr := &preset.Result{Columns: map[string]map[string]*detect.Hint{"wp_users": {"user_ip": {Category: model.CatIPAddress}}}}
	pick := hexColumn(pr)
	for _, c := range []struct {
		table, column string
		want          bool
	}{
		{"mybb_users", "regip", true},
		{"mybb_sessions", "ip", true},
		{"members", "poster_ip", true},
		{"members", "ip_hash", false},
		{"members", "ip_md5", false},
		{"members", "device_uuid", false},
		{"wp_users", "user_ip", false},
	} {
		if got := pick(&model.Table{Name: c.table}, col(c.column, "varbinary")); got != c.want {
			t.Errorf("%s.%s: got %v", c.table, c.column, got)
		}
	}
}

// A key/value table's window: the plain table's size after a whole read or
// a demotion, the bigger one beside listed or sampled keys.
func TestWindowRows(t *testing.T) {
	opts := Options{SampleRows: 30, MetaSampleRows: 300}
	for _, c := range []struct {
		name string
		kv   *kvRead
		want int
	}{
		{"a plain table", nil, 30},
		{"a whole read", &kvRead{mode: modeWhole}, 30},
		{"listed keys", &kvRead{mode: modeList}, 300},
		{"sampled keys", &kvRead{mode: modeSample}, 300},
		{"demoted after listing", &kvRead{mode: modeList, demoted: true}, 30},
	} {
		if got := windowRows(opts, c.kv); got != c.want {
			t.Errorf("%s: %d rows, want %d", c.name, got, c.want)
		}
	}
}

// A translation table's keys are judged by value only; a free-text key is
// shown as hidden and counted when it holds a finding.
func TestAnalyzeKVLabelsAndHiddenKeys(t *testing.T) {
	tbl := &model.Table{Name: "ab_language_definitions"}
	meta := &preset.MetaTable{Key: "language_key", Value: "language_value", Labels: true, Guard: true}
	kv := newKVRead()
	kv.mode = modeWhole
	for k, v := range map[string]string{"entry_email_address": "E-Mail Address:", "text_api_key": "API key:"} {
		kv.addKey(k)
		kv.addRows(k, []sample.KV{{Key: k, Value: v}})
	}
	fs, hidden := analyzeKV(tbl, nil, meta, kv)
	for _, f := range fs {
		if f.Confidence > model.ConfidenceLow {
			t.Errorf("label key judged by name: %+v", f)
		}
	}
	if hidden != 0 {
		t.Errorf("hidden %d", hidden)
	}

	tbl = &model.Table{Name: "form_entries"}
	meta = &preset.MetaTable{Key: "field_key", Value: "field_value", Guard: true}
	kv = newKVRead()
	kv.mode = modeWhole
	for k, v := range map[string]string{"Jane Doe phone": "+30 210 555 0123", "Phone number": "+30 210 555 0199"} {
		kv.addKey(k)
		kv.addRows(k, []sample.KV{{Key: k, Value: v}})
	}
	kv.guard(meta)
	fs, hidden = analyzeKV(tbl, nil, meta, kv)
	shown := map[string]bool{}
	for _, f := range fs {
		if f.Confidence > model.ConfidenceLow {
			shown[f.MetaKey] = true
		}
	}
	if !shown[detect.HiddenKey] || !shown["Phone number"] || shown["Jane Doe phone"] || hidden != 1 {
		t.Errorf("shown %v, hidden %d", shown, hidden)
	}
	for _, f := range fs {
		if f.MetaKey == detect.HiddenKey && strings.Contains(strings.Join(f.Reasons, "; "), "name contains") {
			t.Errorf("a hidden key's reason quotes its words: %q", f.Reasons)
		}
	}

	// A spelling the listing folded away, first seen in the window after the
	// lookups were planned, is hidden too.
	kv = newKVRead()
	kv.mode = modeList
	for _, k := range []string{"Jane Doe phone", "Phone number"} {
		kv.addKey(k)
	}
	kv.guard(meta)
	kv.subjects = subjects(tbl, meta, kv.keys)
	for _, k := range kv.keys {
		kv.addRows(k, []sample.KV{{Key: k, Value: "+30 210 555 0123"}})
	}
	window := &sample.Sample{Columns: []*model.Column{col("field_key", "varchar"), col("field_value", "text")}}
	for _, k := range []string{"JANE DOE PHONE", "Phone number"} {
		window.Rows = append(window.Rows, []sql.NullString{{String: k, Valid: true}, {String: "+30 210 555 0177", Valid: true}})
	}
	fs, hidden = analyzeKV(tbl, window, meta, kv)
	shown = map[string]bool{}
	for _, f := range fs {
		if f.Confidence > model.ConfidenceLow {
			shown[f.MetaKey] = true
		}
	}
	if !shown[detect.HiddenKey] || !shown["Phone number"] || shown["JANE DOE PHONE"] || hidden != 2 {
		t.Errorf("window key: shown %v, hidden %d", shown, hidden)
	}
}

func TestCacheTables(t *testing.T) {
	for name, want := range map[string]bool{"content_cache_posts": true, "cache_store": true, "skin_cache": true,
		"core_like_cache": true, "cachet_incidents": false, "posts": false} {
		if got := cacheTable(&model.Table{Name: name}); got != want {
			t.Errorf("cacheTable(%s) = %v", name, got)
		}
	}
	s := &sample.Sample{Columns: []*model.Column{col("id", "int"), col("cache_content", "mediumtext")},
		Rows: [][]sql.NullString{{{String: "1", Valid: true}, {String: "", Valid: true}}}}
	if holdsText(s, nil) {
		t.Error("an empty text value counted")
	}
	s.Rows = append(s.Rows, []sql.NullString{{String: "2", Valid: true}, {String: "<p>post</p>", Valid: true}})
	if !holdsText(s, nil) {
		t.Error("a filled text value didn't count")
	}
}

// Binary IP columns are decoded in memory; values that decode to nothing
// leave the column as if unread.
func TestAddBinaryIPs(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.10").As4()
	hexes := []string{hex.EncodeToString(v4[:]), hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8})}
	s := &sample.Sample{Columns: []*model.Column{col("regip", "varbinary")}, Hex: []bool{true}}
	for _, h := range hexes {
		s.Rows = append(s.Rows, []sql.NullString{{String: h, Valid: true}})
	}
	p := detect.NewProfileNamed("regip")
	if !addBinaryIPs(p, s, 0) || p.IP != 1 || p.NonEmpty != 2 {
		t.Errorf("decoded: IP %d, non-empty %d", p.IP, p.NonEmpty)
	}
	s.Rows = s.Rows[1:]
	if addBinaryIPs(detect.NewProfileNamed("regip"), s, 0) {
		t.Error("an 8-byte value decoded")
	}
}

// A device ID that a relationship joins to a parent's primary key named id
// is a reference.
func TestWeakenDeviceReferences(t *testing.T) {
	machines := func(pk string) *model.Schema {
		return &model.Schema{Tables: []*model.Table{{Name: "machines", Columns: []*model.Column{col("id", "int"),
			col("hwid", "varchar")}, PrimaryKey: []string{pk}}}}
	}
	res := &model.Result{
		Tables: []model.TableSummary{{Name: "jobs", Findings: 1, Highest: model.SeverityMedium}},
		Findings: []model.Finding{{Table: "jobs", Column: "machine_id", Category: model.CatDeviceID,
			Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh}},
		Relationships: []model.Relationship{{ChildTable: "jobs", ChildColumns: []string{"machine_id"},
			ParentTable: "machines", ParentColumns: []string{"id"}, Status: model.RelConfirmed}},
	}
	weakenDeviceReferences(res, machines("id"))
	f := res.Findings[0]
	if f.Confidence != model.ConfidenceLow || !strings.Contains(f.Note, "machines.id") {
		t.Errorf("got %+v", f)
	}
	if ts := res.Tables[0]; ts.Findings != 0 || ts.Highest != model.SeverityNone {
		t.Errorf("table counts not redone: %+v", ts)
	}
	// Joined to an id that isn't the parent's primary key: still a device ID.
	res.Findings[0].Confidence, res.Findings[0].Note = model.ConfidenceHigh, ""
	weakenDeviceReferences(res, machines("hwid"))
	if res.Findings[0].Confidence != model.ConfidenceHigh {
		t.Errorf("joined to an id that isn't the key: got %+v", res.Findings[0])
	}
	// Joined to a column that holds the IDs themselves: still a device ID.
	res.Relationships[0].ParentColumns = []string{"hwid"}
	weakenDeviceReferences(res, machines("hwid"))
	if res.Findings[0].Confidence != model.ConfidenceHigh {
		t.Errorf("joined to hwid: got %+v", res.Findings[0])
	}
}
