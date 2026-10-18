package scan

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/detect"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/preset"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

func TestChooseMode(t *testing.T) {
	prefix := model.IndexUse{Found: true}
	full := model.IndexUse{Found: true, Full: true}
	unique := model.IndexUse{Found: true, Full: true, Unique: true}
	cases := []struct {
		name string
		f    tableFacts
		b    budget
		want kvMode
	}{
		{"small options", tableFacts{rows: 2468, bytes: 10 << 20, index: unique, serverTimeout: true}, *newBudget(), modeWhole},
		{"small without an index", tableFacts{rows: 500, bytes: 1 << 20}, *newBudget(), modeWhole},
		{"postmeta, prefix index", tableFacts{rows: 34850, bytes: 50 << 20, index: prefix, serverTimeout: true}, *newBudget(), modeList},
		{"big postmeta", tableFacts{rows: 5000000, bytes: 3 << 30, index: prefix, serverTimeout: true}, *newBudget(), modeSample},
		{"big EAV, full index", tableFacts{rows: 10000000, bytes: 2 << 30, index: full, serverTimeout: true}, *newBudget(), modeList},
		{"no server timeout", tableFacts{rows: 34850, bytes: 50 << 20, index: prefix}, *newBudget(), modeSample},
		{"no index", tableFacts{rows: 100000, bytes: 50 << 20, serverTimeout: true}, *newBudget(), modeSample},
		{"sampling only", tableFacts{rows: 10, bytes: 16 << 10, index: unique, serverTimeout: true, sampleOnly: true}, *newBudget(), modeSample},
		// A stale estimate after a restore: one 16 KB page. The read itself
		// finds out and falls back.
		{"stale estimate", tableFacts{rows: 0, bytes: 16 << 10, index: prefix, serverTimeout: true}, *newBudget(), modeWhole},
		{"value budget spent", tableFacts{rows: 2468, bytes: 10 << 20, index: unique, serverTimeout: true},
			budget{keys: scanKeys, bytes: 0, listBytes: scanListBytes}, modeSample},
		{"listing budget spent", tableFacts{rows: 34850, bytes: 50 << 20, index: prefix, serverTimeout: true},
			budget{keys: scanKeys, bytes: scanBytes, listBytes: 10 << 20}, modeSample},
		{"listing budget spent, full index", tableFacts{rows: 34850, bytes: 50 << 20, index: full, serverTimeout: true},
			budget{keys: scanKeys, bytes: scanBytes, listBytes: 0}, modeList},
	}
	for _, c := range cases {
		b := c.b
		if got := chooseMode(c.f, &b); got != c.want {
			t.Errorf("%s: mode %d, want %d", c.name, got, c.want)
		}
	}
}

func TestPlanOrder(t *testing.T) {
	var tables []*model.Table
	for _, n := range []string{"wp_posts", "wp_usermeta", "custom_settings", "wp_10_options", "wp_options", "wp_10_postmeta"} {
		tables = append(tables, &model.Table{Name: n})
	}
	metas := map[string]*preset.MetaTable{
		"wp_options":      {Platform: "wordpress", Primary: true},
		"wp_usermeta":     {Platform: "wordpress", Primary: true},
		"wp_10_options":   {Platform: "wordpress"},
		"wp_10_postmeta":  {Platform: "wordpress"},
		"custom_settings": {},
	}
	var got []string
	for _, t := range planOrder(tables, metas) {
		got = append(got, t.Name)
	}
	want := "wp_options,wp_usermeta,wp_10_options,wp_10_postmeta,custom_settings,wp_posts"
	if strings.Join(got, ",") != want {
		t.Errorf("order %v, want %s", got, want)
	}
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func optionsMeta() *preset.MetaTable {
	return &preset.MetaTable{
		Key: "option_name", Value: "option_value", Platform: "wordpress",
		Keys:  map[string]*detect.Hint{"secret_key": {Category: model.CatSecret, Source: "preset:wordpress"}},
		Probe: []string{"admin_email"},
		HintFor: func(k string) *detect.Hint {
			if strings.HasPrefix(k, "_transient_") {
				return &detect.Hint{Delete: true}
			}
			return nil
		},
		Families: []detect.FamilyRule{{Prefix: "um_cache_userdata_", Hint: &detect.Hint{Delete: true}}},
		Settings: true,
	}
}

func TestSubjectsOrder(t *testing.T) {
	keys := []string{"aaa_plain", "admin_email", "secret_key", "zz_api_key", "_transient_doing_cron",
		"feed_" + md5hex("a"), "feed_" + md5hex("b")}
	for i := 1; i <= 30; i++ {
		keys = append(keys, fmt.Sprintf("um_cache_userdata_%d", i))
	}
	subs := subjects(&model.Table{Name: "wp_options"}, optionsMeta(), keys)
	var got []string
	for _, s := range subs {
		got = append(got, fmt.Sprintf("%s:%d", s.label, s.tier))
	}
	want := []string{"admin_email:1", "secret_key:1", "um_cache_userdata_*:1", "zz_api_key:2", "aaa_plain:3",
		"feed_*:4", "_transient_doing_cron:5"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("subjects %v, want %v", got, want)
	}
	for _, s := range subs {
		if s.label == "um_cache_userdata_*" && (len(s.keys) != 30 || len(s.lookups) != familySample) {
			t.Errorf("family: %d keys, %d lookups", len(s.keys), len(s.lookups))
		}
	}
}

func TestPlanLookups(t *testing.T) {
	var keys []string
	for i := 0; i < 10; i++ {
		keys = append(keys, fmt.Sprintf("plain_%c", 'a'+i))
	}
	keys = append(keys, "zz_secret_token", "secret_key")
	subs := subjects(&model.Table{Name: "wp_options"}, optionsMeta(), keys)
	// Room for four lookups: the preset key, the name match, then two
	// plain keys; the rest are left for their names alone.
	got := planLookups(subs, 4)
	if strings.Join(got, ",") != "secret_key,zz_secret_token,plain_a,plain_b" {
		t.Errorf("lookups %v", got)
	}
	skipped := 0
	for _, s := range subs {
		if s.skipped {
			skipped++
		}
	}
	kv := &kvRead{subjects: subs}
	n, named := skippedSummary(&model.Table{Name: "wp_options"}, optionsMeta(), kv)
	if skipped != 8 || n != 8 || named != 0 {
		t.Errorf("skipped %d (summary %d, %d named)", skipped, n, named)
	}
}

func TestWholeRows(t *testing.T) {
	var rows []sample.KV
	for i := 1; i <= 100; i++ {
		rows = append(rows, sample.KV{Key: "busy", PK: fmt.Sprint(i), Value: "v"})
	}
	rows = append(rows, sample.KV{Key: "rare", PK: "101", Value: "v"})
	kv := newKVRead()
	kv.wholeRows(rows, 20)
	var pks []string
	for _, r := range kv.values["busy"] {
		pks = append(pks, r.PK)
	}
	// The ring keeps the newest ten, in the order they wrapped around.
	if len(pks) != 20 || pks[0] != "1" || pks[9] != "10" || !strings.Contains(strings.Join(pks[10:], ","), "100") {
		t.Errorf("busy key kept %v", pks)
	}
	if len(kv.values["rare"]) != 1 || strings.Join(kv.keys, ",") != "busy,rare" || kv.rows != 21 {
		t.Errorf("rare key: %+v, keys %v, rows %d", kv.values["rare"], kv.keys, kv.rows)
	}
}

func TestGenericMeta(t *testing.T) {
	table := func(name string, cols ...string) *model.Table {
		t := &model.Table{Name: name}
		for _, c := range cols {
			typ := "longtext"
			if strings.HasSuffix(c, "_key") || c == "name" || c == "key" {
				typ = "varchar"
			}
			t.Columns = append(t.Columns, &model.Column{Name: c, DataType: typ})
		}
		return t
	}
	blob := table("app_settings", "id", "setting_key", "setting_value")
	blob.Columns[2].DataType = "longblob"
	cases := []struct {
		t    *model.Table
		want string
	}{
		{table("wp_um_metadata", "umeta_id", "user_id", "um_key", "um_value"), "um_key"},
		{table("aiowps_message_store", "id", "message_key", "message_value", "created"), "message_key"},
		{table("wp_woocommerce_sessions", "session_id", "session_key", "session_value", "session_expiry"), ""},
		{table("app_settings", "id", "name", "value"), "name"},
		{table("products", "id", "name", "value"), ""},
		{table("wp_custom", "id", "cache_key", "cache_value"), ""}, // a preset describes these columns
		{blob, ""}, // binary values are never read
	}
	pr := &preset.Result{Columns: map[string]map[string]*detect.Hint{
		"wp_custom": {"cache_value": {Category: model.CatSessionData}},
	}}
	for _, c := range cases {
		m := genericMeta(c.t, pr)
		got := ""
		if m != nil {
			got = m.Key
		}
		if got != c.want {
			t.Errorf("%s: key column %q, want %q", c.t.Name, got, c.want)
		}
	}
}

// Values read by key win over the window's copy of the same row, which the
// window cuts at 4 KB.
func TestAnalyzeKVPrecedence(t *testing.T) {
	tbl := &model.Table{Name: "wp_options", PrimaryKey: []string{"option_id"}, Columns: []*model.Column{
		{Name: "option_id", DataType: "bigint"}, {Name: "option_name", DataType: "varchar"}, {Name: "option_value", DataType: "longtext"},
	}}
	secret := "AI" + "za" + strings.Repeat("Bx3_", 8) + "Bx3"
	long := `{"admin_email":"jane@mail.fixture.gr","pad":"` + strings.Repeat("x", 5000) + `","facebook_secret":"` + secret + `"}`
	kv := newKVRead()
	kv.mode = modeWhole
	kv.addKey("rank-math-options-titles")
	kv.addRows("rank-math-options-titles", []sample.KV{{Key: "rank-math-options-titles", PK: "7", Value: long}})
	s := &sample.Sample{Columns: tbl.Columns, Rows: [][]sql.NullString{{
		{String: "7", Valid: true}, {String: "rank-math-options-titles", Valid: true}, {String: long[:4096], Valid: true},
	}}}
	fs, _ := analyzeKV(tbl, s, optionsMeta(), kv)
	var secretPath *model.Finding
	for i := range fs {
		if fs[i].Path == "facebook_secret" && fs[i].Category == model.CatSecret {
			secretPath = &fs[i]
		}
	}
	if secretPath == nil || secretPath.Sampled != 1 {
		t.Fatalf("got %+v", fs)
	}
	// The window's copy is not counted a second time.
	for _, f := range fs {
		if f.Path == "admin_email" && f.Category == model.CatEmail && f.Sampled != 1 {
			t.Errorf("admin_email sampled %d times", f.Sampled)
		}
	}
}

func TestFallbackMode(t *testing.T) {
	prefix := tableFacts{rows: 100, bytes: 16 << 10, index: model.IndexUse{Found: true}, serverTimeout: true}
	full := prefix
	full.index.Full = true
	timeout := &mysql.MySQLError{Number: 1969}
	cases := []struct {
		name string
		err  error
		f    tableFacts
		want kvMode
	}{
		{"more rows than estimated", nil, prefix, modeList},
		{"timed out: listing would scan the table again", timeout, prefix, modeSample},
		{"timed out, but a full index lists cheaply", timeout, full, modeList},
		{"another error", &mysql.MySQLError{Number: 1105}, prefix, modeList},
		{"no index", nil, tableFacts{rows: 100, bytes: 16 << 10, serverTimeout: true}, modeSample},
	}
	for _, c := range cases {
		if got := fallbackMode(c.err, c.f, newBudget()); got != c.want {
			t.Errorf("%s: mode %d, want %d", c.name, got, c.want)
		}
	}
}

func TestProbeHow(t *testing.T) {
	small := tableFacts{rows: 500, bytes: 1 << 20}
	big := tableFacts{rows: 5000000, bytes: 100 << 20, serverTimeout: true}
	cases := []struct {
		name      string
		f         tableFacts
		big       bool
		bytesLeft int64
		b         budget
		want      probeKind
		why       string
	}{
		{"indexed", tableFacts{rows: 5000000, index: model.IndexUse{Found: true}}, false, 1 << 20, *newBudget(), probeBatch, ""},
		{"small", small, false, 1 << 20, *newBudget(), probeScan, ""},
		// The estimates said small, but a whole read found more rows.
		{"stale estimate", small, true, 1 << 20, *newBudget(), probeNone, "no statement timeout"},
		{"big", big, false, 1 << 20, *newBudget(), probeScanCharged, ""},
		{"full-scan budget spent", big, false, 1 << 20, budget{keys: scanKeys, bytes: scanBytes, listBytes: 1 << 20}, probeNone, "full scans"},
		{"byte budget spent", tableFacts{index: model.IndexUse{Found: true}}, false, 0, *newBudget(), probeNone, "byte budget"},
	}
	for _, c := range cases {
		b := c.b
		got, why := probeHow(c.f, c.big, c.bytesLeft, &b)
		if got != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: %d %q, want %d %q", c.name, got, why, c.want, c.why)
		}
	}
}

func TestProbeLookups(t *testing.T) {
	meta := optionsMeta()
	text := &model.Column{Name: "option_name", DataType: "varchar"}
	got := probeLookups(meta, text, 1, func(k string) bool { return k == "admin_email" })
	var parts []string
	for _, l := range got {
		parts = append(parts, fmt.Sprintf("%s/%v/%d", l.Key, l.Prefix, l.Limit))
	}
	want := "secret_key/false/1,um_cache_userdata_/true/20,um_email_as_username_/true/20"
	if strings.Join(parts, ",") != want {
		t.Errorf("lookups %v, want %s", parts, want)
	}
	// A LIKE on a numeric key column can use no index.
	numeric := &model.Column{Name: "attribute_id", DataType: "smallint"}
	if got := probeLookups(meta, numeric, 1, func(string) bool { return false }); len(got) != 2 || got[0].Prefix || got[1].Prefix {
		t.Errorf("numeric key column: %+v", got)
	}
	// The data prefixes belong to WordPress plugins.
	other := &preset.MetaTable{Key: "path", Value: "value", Platform: "magento2"}
	if got := probeLookups(other, text, 20, func(string) bool { return false }); len(got) != 0 {
		t.Errorf("Magento table: %+v", got)
	}
}

// Lookups that the byte limit cut or never ran are not read: their keys
// count as skipped, not as sampled without values.
func TestSettleByteCap(t *testing.T) {
	tbl := &model.Table{Name: "wp_usermeta"}
	keys := []string{"aa_email", "bb_email", "cc_email", "dd_email"}
	kv := newKVRead()
	for _, k := range keys {
		kv.addKey(k)
	}
	kv.subjects = subjects(tbl, &preset.MetaTable{Key: "meta_key", Value: "meta_value"}, kv.keys)
	planned := planLookups(kv.subjects, 10)
	got := sample.Batch{
		Rows:     map[int][]sample.KV{0: {{Key: "aa_email", PK: "1", Value: "a"}}, 1: {{Key: "bb_email", PK: "2", Value: "b"}}},
		Complete: []bool{true, false, false, false},
	}
	if ran := kv.settle(tbl, planned, got, nil); ran != 2 {
		t.Errorf("%d lookups ran, want 2", ran)
	}
	if !kv.read["aa_email"] || !kv.read["bb_email"] || kv.read["cc_email"] || kv.read["dd_email"] {
		t.Errorf("read %v", kv.read)
	}
	if n, _ := skippedSummary(tbl, &preset.MetaTable{}, kv); n != 2 {
		t.Errorf("%d keys skipped, want 2", n)
	}
}

func TestAddRowsOnce(t *testing.T) {
	kv := newKVRead()
	kv.addRows("a", []sample.KV{{Key: "a", PK: "1"}, {Key: "a", PK: "2"}})
	kv.addRows("a", []sample.KV{{Key: "a", PK: "2"}, {Key: "a", PK: "3"}})
	if len(kv.values["a"]) != 3 || kv.rows != 3 {
		t.Errorf("kept %d rows (%d counted)", len(kv.values["a"]), kv.rows)
	}
}

// Without a primary key, the window adds nothing to a key read another
// way, but all of its rows count for the keys only it sampled.
func TestAnalyzeKVWindowWithoutPK(t *testing.T) {
	tbl := &model.Table{Name: "app_meta", Columns: []*model.Column{
		{Name: "meta_key", DataType: "varchar"}, {Name: "meta_value", DataType: "text"},
	}}
	meta := &preset.MetaTable{Key: "meta_key", Value: "meta_value"}
	kv := newKVRead()
	kv.mode = modeList
	for _, k := range []string{"billing_email", "contact_email"} {
		kv.addKey(k)
	}
	kv.subjects = subjects(tbl, meta, kv.keys)
	kv.addRows("billing_email", []sample.KV{{Key: "billing_email", Value: "jane@mail.fixture.gr"}})
	row := func(k, v string) []sql.NullString {
		return []sql.NullString{{String: k, Valid: true}, {String: v, Valid: true}}
	}
	s := &sample.Sample{Columns: tbl.Columns}
	for i := 0; i < 5; i++ {
		s.Rows = append(s.Rows, row("contact_email", fmt.Sprintf("contact%d@mail.fixture.gr", i)))
	}
	s.Rows = append(s.Rows, row("billing_email", "jane@mail.fixture.gr"), row("billing_email", "john@mail.fixture.gr"))
	sampled := map[string]int{}
	fs, _ := analyzeKV(tbl, s, meta, kv)
	for _, f := range fs {
		if f.Category == model.CatEmail {
			sampled[f.MetaKey] = f.Sampled
		}
	}
	if sampled["contact_email"] != 5 || sampled["billing_email"] != 1 {
		t.Errorf("sampled %v", sampled)
	}
}

// A family's count is exact only when its probe ran to its end with fewer
// rows than it asked for.
func TestAnalyzeKVFamilyPartial(t *testing.T) {
	tbl := &model.Table{Name: "wp_usermeta"}
	meta := &preset.MetaTable{Key: "meta_key", Value: "meta_value", Platform: "wordpress"}
	partial := func(mode kvMode, truncated, probed bool) bool {
		kv := newKVRead()
		kv.mode, kv.truncated = mode, truncated
		for _, u := range []string{"jane", "john"} {
			k := "um_email_as_username_" + u + "mailfixturegr"
			kv.addKey(k)
			kv.addRows(k, []sample.KV{{Key: k, Value: "x"}})
		}
		kv.probed["um_email_as_username_"] = probed
		fs, _ := analyzeKV(tbl, nil, meta, kv)
		for _, f := range fs {
			if f.KeyName {
				return f.KeysPartial
			}
		}
		t.Fatal("no key-name finding")
		return false
	}
	if !partial(modeSample, false, false) || partial(modeSample, false, true) {
		t.Error("sampled table: a probe that didn't finish must leave the count partial")
	}
	if !partial(modeList, true, false) || partial(modeList, false, false) {
		t.Error("listed table: only a cut-off listing leaves the count partial")
	}
}

// A binary value column is never read: the table is sampled like any other.
func TestReadKVBinaryValues(t *testing.T) {
	tbl := &model.Table{Name: "wp_options", Columns: []*model.Column{
		{Name: "option_name", DataType: "varchar"}, {Name: "option_value", DataType: "longblob"},
	}}
	kv := readKV(context.Background(), &dbconn.Session{}, nil, tbl, optionsMeta(), Options{}, newBudget())
	if kv.mode != modeSample || len(kv.keys) != 0 {
		t.Errorf("mode %d, keys %v", kv.mode, kv.keys)
	}
}

// A key that ends in a webhook word is looked up with the named keys; no
// other key changes tier.
func TestSubjectsWebhookTier(t *testing.T) {
	subs := subjects(&model.Table{Name: "wp_options"}, optionsMeta(), []string{"aaa_plain", "discord_webhook", "webhook_status"})
	for _, s := range subs {
		want := tierSingle
		if s.label == "discord_webhook" {
			want = tierNamed
		}
		if s.tier != want {
			t.Errorf("%s: tier %d, want %d", s.label, s.tier, want)
		}
	}
}
