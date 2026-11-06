package leak

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// shapeRun is the pieces most tests here need.
type shapeRun struct {
	ctx   context.Context
	admin *sql.DB
	cfg   *mysql.Config
	key   Key
}

func newShapeRun(t *testing.T) *shapeRun {
	t.Helper()
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	return &shapeRun{ctx, admin, cfg, testKey(t)}
}

func leftOutOf(f *File, loc string) *model.LeakLeftOut {
	for i := range f.LeftOut {
		if f.LeftOut[i].Location == loc {
			return &f.LeftOut[i]
		}
	}
	return nil
}

func fileColumn(f *File, loc string, kind model.LeakKind) *FileColumn {
	for i, c := range f.Columns {
		if model.LeakLocation(c.Table, c.Column, c.MetaKey) == loc && c.Kind == kind {
			return &f.Columns[i]
		}
	}
	return nil
}

// metaTable makes a key/value table with the given index on its key column.
func metaTable(ctx context.Context, t *testing.T, admin *sql.DB, db, table, keyIndex string) {
	t.Helper()
	exec(ctx, t, admin, fmt.Sprintf("CREATE TABLE `%s`.`%s` (meta_id bigint unsigned NOT NULL PRIMARY KEY, owner_id bigint NOT NULL, "+
		"meta_key varchar(255), meta_value longtext%s) ENGINE=InnoDB", db, table, keyIndex))
}

// TestOverlappingKeyPatterns: a stored key matching two patterns must go to the
// same one on both sides, whatever order the lists came in, or a full copy
// reads as zero. Both patterns here hold emails, so both are in the file.
func TestOverlappingKeyPatterns(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_forms_prod")
	metaTable(r.ctx, t, r.admin, prod, "form_meta", ", KEY meta_key (meta_key(191))")
	insertBatches(r.ctx, t, r.admin, "`"+prod+"`.form_meta", "meta_id, owner_id, meta_key, meta_value", idRange(1, 4000), func(id int64) string {
		form := (id + 1) / 2
		if id%2 == 1 {
			return fmt.Sprintf("(%d,%d,'form_%d','The customer asked about the parcel, reachable at note.%d@%s.')", id, form, 1000+form, form, fakeDomain)
		}
		return fmt.Sprintf("(%d,%d,'form_%d_email','%s')", id, form, 1000+form, fakeEmail(form))
	})
	exec(r.ctx, t, r.admin, "ANALYZE TABLE `"+prod+"`.form_meta")
	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{})
	narrow, wide := "form_meta.meta_value[form_*_email]", "form_meta.meta_value[form_*]"
	if fileColumn(f, narrow, model.LeakEmail) == nil || fileColumn(f, wide, model.LeakEmail) == nil {
		t.Fatalf("both patterns should hold emails: %+v", f.Columns)
	}
	db := stagingOf(r.ctx, t, r.admin, "prodmask_fixture_leak_forms_stag", prod, "form_meta", "")
	res := compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{})
	for _, loc := range []string{narrow, wide} {
		if c := columnOf(t, res, loc, model.LeakEmail); c.Found != c.Sampled || c.Sampled == 0 {
			t.Errorf("%s: found %d of %d on a full copy: %q", loc, c.Found, c.Sampled, c.Line)
		}
	}
	// Only the notes masked: the other pattern's emails still turn up.
	exec(r.ctx, t, r.admin, "UPDATE `"+db+"`.form_meta SET meta_value = 'masked' WHERE meta_key NOT LIKE '%email'")
	res = compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{})
	if hits, _ := Gate(res, model.SeverityHigh); hits != 1 {
		t.Errorf("%d columns with hits", hits)
	}
}

// TestLookupRowsGoToTheirOwner: a pattern's lookup can read keys a narrower
// pattern owns. Those keep their spread sample, untouched by its oldest rows.
func TestLookupRowsGoToTheirOwner(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_route_prod")
	metaTable(r.ctx, t, r.admin, prod, "form_meta", ", KEY meta_key (meta_key(191))")
	insertBatches(r.ctx, t, r.admin, "`"+prod+"`.form_meta", "meta_id, owner_id, meta_key, meta_value", idRange(1, 90000), func(id int64) string {
		switch {
		case id%1200 == 0:
			return fmt.Sprintf("(%d,%d,'form_%d','The customer asked about the parcel, reachable at note.%d@%s.')", id, id, 1000+id, id, fakeDomain)
		case id%30 == 0:
			return fmt.Sprintf("(%d,%d,'form_%d_email','%s')", id, id, 1000+id, fakeEmail(id))
		}
		return fmt.Sprintf("(%d,%d,'flag_%d','on')", id, id, id%10)
	})
	exec(r.ctx, t, r.admin, "ANALYZE TABLE `"+prod+"`.form_meta")
	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{})
	narrow := fileColumn(f, "form_meta.meta_value[form_*_email]", model.LeakEmail)
	if narrow == nil || narrow.Sample != model.SampleSpread {
		t.Fatalf("the narrow pattern: %+v", narrow)
	}
	// Every value came from the points: none of the wide lookup's oldest rows.
	if int64(narrow.Values) != narrow.RowsRead {
		t.Errorf("%d values from %d rows picked at the points", narrow.Values, narrow.RowsRead)
	}
	if wide := fileColumn(f, "form_meta.meta_value[form_*]", model.LeakEmail); wide != nil && wide.Sample == model.SampleSpread {
		t.Errorf("the wide pattern's lookup should mark it: %+v", wide)
	}
}

// TestRareKeys: a key past the first rows gets a lookup where its column is
// indexed, and the lookup says whether it read all of the key.
func TestRareKeys(t *testing.T) {
	r := newShapeRun(t)
	// A composite primary key, so its first rows are the only cheap read, and
	// the rare keys sit past them.
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_rare_prod")
	exec(r.ctx, t, r.admin, "CREATE TABLE `"+prod+"`.user_settings (user_id bigint NOT NULL, setting_key varchar(100) NOT NULL, "+
		"setting_value varchar(190), PRIMARY KEY (user_id, setting_key), KEY setting_key (setting_key)) ENGINE=InnoDB")
	insertBatches(r.ctx, t, r.admin, "`"+prod+"`.user_settings", "user_id, setting_key, setting_value", idRange(1, 50000), func(id int64) string {
		k, v := fmt.Sprintf("flag_%d", id%10), "on"
		switch {
		case id > 49750 && id%10 == 0:
			k, v = "recovery_email", fakeEmail(id)
		case id > 40000 && id%10 == 1:
			k, v = "backup_email", fakeEmail(id)
		}
		return fmt.Sprintf("(%d,'%s','%s')", id/10, k, v)
	})
	exec(r.ctx, t, r.admin, "ANALYZE TABLE `"+prod+"`.user_settings")

	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{})
	rare := "user_settings.setting_value[recovery_email]"
	col := fileColumn(f, rare, model.LeakEmail)
	if col == nil {
		t.Fatalf("the rare key has no sample: %+v\n%+v", f.Columns, f.LeftOut)
	}
	if col.Sample != model.SampleAllRows || !col.Exact || col.Values != 25 {
		t.Errorf("an exhausted lookup: %s, exact %v, %d values", col.Sample, col.Exact, col.Values)
	}
	thin := "user_settings.setting_value[backup_email]"
	col = fileColumn(f, thin, model.LeakEmail)
	if col == nil || col.Sample != model.SampleFirstRows || col.Exact || col.Values != thinKey {
		t.Fatalf("a lookup that stopped at its limit: %+v", col)
	}
	db := stagingOf(r.ctx, t, r.admin, "prodmask_fixture_leak_rare_stag", prod, "user_settings", "")
	res := compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{})
	for _, loc := range []string{rare, thin} {
		if c := columnOf(t, res, loc, model.LeakEmail); c.Found != c.Sampled {
			t.Errorf("%s: found %d of %d", loc, c.Found, c.Sampled)
		}
	}
}

// TestNoFullScanForALookup: with no index on the key column, a rare key gets no
// lookup, since that would be a full scan of production. The scan flagged it
// from its own windows, so if the points miss it, it fails a gate rather than
// vanishing.
func TestNoFullScanForALookup(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_noindex_prod")
	customers(r.ctx, t, r.admin, prod, "customers", idRange(1, 100))
	metaTable(r.ctx, t, r.admin, prod, "contact_meta", "")
	// Slices start every 33 rows or so, and a point at the slice's start reads
	// its first 10 rows: these rows are between them, but in the scan's window.
	rare := map[int64]bool{20: true, 25: true, 53: true, 56: true}
	const rows = 100000
	insertBatches(r.ctx, t, r.admin, "`"+prod+"`.contact_meta", "meta_id, owner_id, meta_key, meta_value", idRange(1, rows), func(id int64) string {
		if rare[id] {
			return fmt.Sprintf("(%d,%d,'legacy_email','%s')", id, id, fakeEmail(id))
		}
		return fmt.Sprintf("(%d,%d,'flag_%d','on')", id, id, id%10)
	})
	exec(r.ctx, t, r.admin, "ANALYZE TABLE `"+prod+"`.contact_meta")
	sess := openSession(r.ctx, t, r.cfg, prod)
	sm := &sample.Sampler{DB: sess.DB, MaxValueLen: 4096, Timeout: time.Minute}
	table := &model.Table{Name: "contact_meta", Type: "BASE TABLE", RowsEstimate: rows, PrimaryKey: []string{"meta_id"},
		Columns: []*model.Column{{Name: "meta_id", DataType: "bigint"}, {Name: "meta_key", DataType: "varchar"}, {Name: "meta_value", DataType: "longtext"}}}
	before := handlerReads(r.ctx, t, sess)
	res, err := sm.Spread(r.ctx, table, []string{"`meta_key`"}, nil, DefaultSampleRows, kvRowsPerPoint, func(uint64) uint64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	if read := handlerReads(r.ctx, t, sess) - before; read > 3*DefaultSampleRows*kvRowsPerPoint {
		t.Errorf("the server read %d rows for %d rows of keys", read, len(res.Rows))
	}

	before = handlerReads(r.ctx, t, sess)
	f, _, err := Hash(r.ctx, sess, r.key, HashOptions{Preset: "auto", Version: "test", Pick: func(uint64) uint64 { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	if read := handlerReads(r.ctx, t, sess) - before; read >= rows {
		t.Errorf("the server read %d rows of a table of %d: a full scan", read, rows)
	}
	if col := fileColumn(f, "contact_meta.meta_value[legacy_email]", model.LeakEmail); col != nil {
		t.Errorf("the points shouldn't have read these rows: %+v", col)
	}
	left := leftOutOf(f, "contact_meta.meta_value[legacy_email]")
	if left == nil || !left.NotRead || !strings.Contains(left.Why, "couldn't reach") {
		t.Fatalf("left out: %+v", f.LeftOut)
	}
	db := stagingOf(r.ctx, t, r.admin, "prodmask_fixture_leak_noindex_stag", prod, "customers", "",
		"UPDATE {t} SET email = CONCAT('someone.', id, '@elsewhere.prodmask-fixture.dev')", maskPhone)
	lr := compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{})
	if hits, unchecked := Gate(lr, model.SeverityHigh); hits != 0 || unchecked != 1 {
		t.Errorf("gate: %d hits, %d unchecked", hits, unchecked)
	}
	if !strings.Contains(text(t, lr), "a rare key the sample couldn't reach on production") {
		t.Errorf("report:\n%s", text(t, lr))
	}
}

func handlerReads(ctx context.Context, t *testing.T, sess *dbconn.Session) int64 {
	t.Helper()
	rows, err := sess.DB.QueryContext(ctx, "SHOW SESSION STATUS LIKE 'Handler_read%'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var total int64
	for rows.Next() {
		var name string
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			t.Fatal(err)
		}
		total += n
	}
	return total
}

// TestClusteredKeys: every point can find a row of its own and all of them be
// first in their cluster, which says nothing of the rest.
func TestClusteredKeys(t *testing.T) {
	r := newShapeRun(t)
	var ids []int64
	for tenant := int64(1); tenant <= 2500; tenant++ {
		for seq := int64(0); seq < 20; seq++ {
			ids = append(ids, tenant*1_000_000+seq)
		}
	}
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_tenants_prod")
	customers(r.ctx, t, r.admin, prod, "customers", ids)
	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{})
	if c := fileColumn(f, "customers.email", model.LeakEmail); c == nil || c.Sample != model.SampleThin {
		t.Errorf("%+v", c)
	}
}

// TestKeysBesidePlainColumns: a key/value table can have flagged plain columns.
func TestKeysBesidePlainColumns(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_mixed_prod")
	exec(r.ctx, t, r.admin, "CREATE TABLE `"+prod+"`.member_meta (meta_id bigint NOT NULL PRIMARY KEY, member_email varchar(190), "+
		"meta_key varchar(100), meta_value text, KEY meta_key (meta_key)) ENGINE=InnoDB")
	insertBatches(r.ctx, t, r.admin, "`"+prod+"`.member_meta", "meta_id, member_email, meta_key, meta_value", idRange(1, 60000), func(id int64) string {
		if id%20 == 0 {
			return fmt.Sprintf("(%d,'%s','billing_phone','%s')", id, fakeEmail(id), fakePhone(id))
		}
		return fmt.Sprintf("(%d,'%s','flag_%d','on')", id, fakeEmail(id), id%20)
	})
	exec(r.ctx, t, r.admin, "ANALYZE TABLE `"+prod+"`.member_meta")
	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{})
	plain := fileColumn(f, "member_meta.member_email", model.LeakEmail)
	if plain == nil || plain.Sample != model.SampleSpread || plain.Values < 2900 {
		t.Fatalf("the plain column: %+v", plain)
	}
	if plain.EstimatedValues < 30000 || plain.EstimatedValues > 120000 {
		t.Errorf("estimated %d", plain.EstimatedValues)
	}
	keyed := fileColumn(f, "member_meta.meta_value[billing_phone]", model.LeakPhone)
	if keyed == nil || keyed.Sample != model.SampleSpread {
		t.Fatalf("the key: %+v", keyed)
	}
	db := stagingOf(r.ctx, t, r.admin, "prodmask_fixture_leak_mixed_stag", prod, "member_meta", "")
	res := compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{})
	for _, c := range res.Columns {
		if c.Found != c.Sampled {
			t.Errorf("%s: found %d of %d", c.Location(), c.Found, c.Sampled)
		}
	}
}

// TestThinnedAndCutSamples uses a small sample size, as tests can, to reach a
// table read whole with more of a key than the sample, and a column with more
// distinct values than it.
func TestThinnedAndCutSamples(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_small_prod")
	metaTable(r.ctx, t, r.admin, prod, "contact_meta", ", KEY meta_key (meta_key)")
	insertBatches(r.ctx, t, r.admin, "`"+prod+"`.contact_meta", "meta_id, owner_id, meta_key, meta_value", idRange(1, 500), func(id int64) string {
		return fmt.Sprintf("(%d,%d,'billing_email','%s')", id, id, fakeEmail(id))
	})
	exec(r.ctx, t, r.admin, "CREATE TABLE `"+prod+"`.tickets (id bigint NOT NULL PRIMARY KEY, message text) ENGINE=InnoDB")
	insertBatches(r.ctx, t, r.admin, "`"+prod+"`.tickets", "id, message", idRange(1, 40), func(id int64) string {
		var b strings.Builder
		for j := int64(0); j < 5; j++ {
			fmt.Fprintf(&b, "Please write to %s about this. ", fakeEmail(id*10+j))
		}
		return fmt.Sprintf("(%d,'%s')", id, b.String())
	})
	exec(r.ctx, t, r.admin, "ANALYZE TABLE `"+prod+"`.contact_meta, `"+prod+"`.tickets")
	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{SampleRows: 100})
	thinned := fileColumn(f, "contact_meta.meta_value[billing_email]", model.LeakEmail)
	if thinned == nil || thinned.Sample != model.SampleSpread || thinned.Exact || thinned.Values != 100 {
		t.Errorf("a key with more rows than the sample: %+v", thinned)
	}
	if thinned != nil && (thinned.EstimatedValues < 400 || thinned.EstimatedValues > 600) {
		t.Errorf("estimated %d values of a key on 500 rows", thinned.EstimatedValues)
	}
	cut := fileColumn(f, "tickets.message", model.LeakEmail)
	if cut == nil || cut.Exact || cut.Values != 100 {
		t.Fatalf("a column with more distinct values than the sample: %+v", cut)
	}
	if cut.EstimatedValues != 200 {
		t.Errorf("estimated %d values, 200 were found", cut.EstimatedValues)
	}
	db := stagingOf(r.ctx, t, r.admin, "prodmask_fixture_leak_small_stag", prod, "tickets", "")
	exec(r.ctx, t, r.admin, "CREATE TABLE `"+db+"`.contact_meta LIKE `"+prod+"`.contact_meta")
	exec(r.ctx, t, r.admin, "INSERT INTO `"+db+"`.contact_meta SELECT * FROM `"+prod+"`.contact_meta")
	res := compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{})
	if c := columnOf(t, res, "tickets.message", model.LeakEmail); c.Found != 100 || c.Values != 200 {
		t.Errorf("found %d, %d values", c.Found, c.Values)
	}
}

func TestNothingToHash(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_none_prod")
	exec(r.ctx, t, r.admin, "CREATE TABLE `"+prod+"`.products (id bigint NOT NULL PRIMARY KEY, title varchar(100), price decimal(10,2)) ENGINE=InnoDB")
	exec(r.ctx, t, r.admin, "INSERT INTO `"+prod+"`.products VALUES (1, 'Blue mug', 9.50), (2, 'Red mug', 9.50)")
	sess := openSession(r.ctx, t, r.cfg, prod)
	f, _, err := Hash(r.ctx, sess, r.key, HashOptions{Preset: "auto", Version: "test"})
	if !errors.Is(err, ErrNothingToHash) || f != nil {
		t.Errorf("file %v, error %v", f, err)
	}
	// A flagged table that goes away before its sample is another matter.
	customers(r.ctx, t, r.admin, prod, "customers", idRange(1, 200))
	f, _, err = Hash(r.ctx, sess, r.key, HashOptions{Preset: "auto", Version: "test", Progress: func(done, total int, table string) {
		if table == "customers" {
			exec(r.ctx, t, r.admin, "DROP TABLE `"+prod+"`.customers")
		}
	}})
	if !errors.Is(err, ErrNothingSampled) || f != nil {
		t.Errorf("file %v, error %v", f, err)
	}
}

// TestALookupThatFindsNothingCounted: a rare key the lookup reached, with no
// counted value in it, isn't one the sample couldn't reach.
func TestALookupThatFindsNothingCounted(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_seven_prod")
	exec(r.ctx, t, r.admin, "CREATE TABLE `"+prod+"`.user_settings (user_id bigint NOT NULL, setting_key varchar(100) NOT NULL, "+
		"setting_value varchar(190), PRIMARY KEY (user_id, setting_key), KEY setting_key (setting_key)) ENGINE=InnoDB")
	customers(r.ctx, t, r.admin, prod, "customers", idRange(1, 100))
	insertBatches(r.ctx, t, r.admin, "`"+prod+"`.user_settings", "user_id, setting_key, setting_value", idRange(1, 50000), func(id int64) string {
		if id > 46000 && id%10 == 0 {
			return fmt.Sprintf("(%d,'emergency_phone','555 %04d')", id/10, id%10000)
		}
		return fmt.Sprintf("(%d,'flag_%d','on')", id/10, id%10)
	})
	exec(r.ctx, t, r.admin, "ANALYZE TABLE `"+prod+"`.user_settings")
	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{})
	left := leftOutOf(f, "user_settings.setting_value[emergency_phone]")
	if left == nil || left.NotRead || strings.Contains(left.Why, "couldn't reach") {
		t.Errorf("left out: %+v", f.LeftOut)
	}
}

// TestPlanSampleLeftOuts covers what can't be staged on a real server: a scan
// that couldn't read a table says so, and what the plan leaves out says why.
func TestPlanSampleLeftOuts(t *testing.T) {
	table := &model.Table{Name: "t", Type: "BASE TABLE", PrimaryKey: []string{"id"}, Columns: []*model.Column{
		{Name: "id", DataType: "bigint"}, {Name: "email", DataType: "varchar"}, {Name: "ip", DataType: "varbinary"},
		{Name: "attribute_id", DataType: "smallint"}, {Name: "value", DataType: "varchar"}}}
	schema := &model.Schema{Tables: []*model.Table{table}}
	res := &model.Result{
		Tables: []model.TableSummary{{Name: "t", KeyColumn: "attribute_id", ValueColumn: "value"}, {Name: "broken", Error: "timed out"}, {Name: "partly", ReadFailed: true}},
		Findings: []model.Finding{
			{Table: "t", Column: "email", Category: model.CatEmail, Confidence: model.ConfidenceLow},
			{Table: "t", Column: "value", MetaKey: "um_*", KeyName: true, Category: model.CatEmail, Confidence: model.ConfidenceHigh},
			{Table: "t", Column: "value", Where: "x = 1", Category: model.CatEmail, Confidence: model.ConfidenceHigh},
			{Table: "t", Column: "value", MetaKey: "(key hidden)", Category: model.CatEmail, Confidence: model.ConfidenceHigh},
			{Table: "t", Column: "ip", Category: model.CatIPAddress, Confidence: model.ConfidenceHigh},
			{Table: "t", Column: "value", MetaKey: "telephone", Category: model.CatPhone, Confidence: model.ConfidenceHigh},
			{Table: "gone", Column: "email", Category: model.CatEmail, Confidence: model.ConfidenceHigh},
		},
	}
	plans, left := planSample(res, schema)
	if len(plans) != 0 {
		t.Errorf("%d plans: a low-confidence finding isn't one", len(plans))
	}
	want := map[string]bool{ // location to whether it's not read
		"broken": true, "partly": true, "gone.email": true,
		"t.value[um_*]": false, "t.value": false, "t.value[(key hidden)]": false, "t.ip": false, "t.value[telephone]": false,
	}
	for _, l := range left {
		notRead, ok := want[l.Location]
		if !ok || notRead != l.NotRead {
			t.Errorf("%+v", l)
		}
		delete(want, l.Location)
	}
	if len(want) != 0 {
		t.Errorf("not left out: %v", want)
	}
}

// TestWholeValueRulesFollowTheFinding: only a finding with no path, and for a
// secret only at high or above, says a whole value may be a kind.
func TestWholeValueRulesFollowTheFinding(t *testing.T) {
	table := &model.Table{Name: "t", Type: "BASE TABLE", PrimaryKey: []string{"id"}, Columns: []*model.Column{
		{Name: "id", DataType: "bigint"}, {Name: "a", DataType: "text"}, {Name: "b", DataType: "text"}, {Name: "c", DataType: "text"}, {Name: "d", DataType: "text"}}}
	res := &model.Result{Findings: []model.Finding{
		{Table: "t", Column: "a", Category: model.CatSecret, Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh},
		{Table: "t", Column: "b", Path: "x.y", Category: model.CatSecret, Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh},
		{Table: "t", Column: "c", Category: model.CatSecret, Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh},
		{Table: "t", Column: "d", Path: "phone", Category: model.CatPhone, Confidence: model.ConfidenceHigh},
	}}
	plans, _ := planSample(res, &model.Schema{Tables: []*model.Table{table}})
	if len(plans) != 1 || len(plans[0].plain) != 4 {
		t.Fatalf("%+v", plans)
	}
	got := map[string]*wants{}
	for _, s := range plans[0].plain {
		got[s.column] = &s.wants
	}
	if len(got["a"].whole) != 0 || len(got["b"].whole) != 0 || len(got["c"].whole) != 1 || got["d"].loosePhone {
		t.Errorf("%+v %+v %+v %+v", got["a"], got["b"], got["c"], got["d"])
	}
}

// TestAllowlistWarning: a domain that takes a large share of a column is called
// out in the report, whichever step it was given on.
func TestAllowlistWarning(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_share_prod")
	customers(r.ctx, t, r.admin, prod, "customers", idRange(1, 2000))
	exec(r.ctx, t, r.admin, "UPDATE `"+prod+"`.customers SET email = CONCAT('user.', id, '@public-mail.prodmask-fixture.dev') WHERE id MOD 2 = 0")
	wide, err := NewAllowlist([]string{"public-mail.prodmask-fixture.dev"})
	if err != nil {
		t.Fatal(err)
	}
	warned := func(list []string) bool {
		return strings.Contains(strings.Join(list, "\n"), "kept out more than a fifth of the values in customers.email")
	}

	// On hash: the warning travels in the file.
	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{Allow: wide})
	if !warned(f.Warnings) {
		t.Errorf("file warnings: %q", f.Warnings)
	}
	db := stagingOf(r.ctx, t, r.admin, "prodmask_fixture_leak_share_stag", prod, "customers", "")
	res := compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{})
	if !warned(res.Warnings) {
		t.Errorf("report warnings: %q", res.Warnings)
	}

	// On compare alone.
	f = hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{})
	res = compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{Allow: wide})
	if !warned(res.Warnings) {
		t.Errorf("report warnings: %q", res.Warnings)
	}
	if c := columnOf(t, res, "customers.email", model.LeakEmail); c.ValuesSkipped != 1000 || c.Values != 1000 {
		t.Errorf("%d skipped, %d read", c.ValuesSkipped, c.Values)
	}

	// A whole column allowed says so, not that there was nothing to read.
	exec(r.ctx, t, r.admin, "UPDATE `"+db+"`.customers SET email = CONCAT('user.', id, '@public-mail.prodmask-fixture.dev')")
	res = compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{Allow: wide})
	if c := columnOf(t, res, "customers.email", model.LeakEmail); !strings.Contains(c.Line, "skipped by --allow-email") {
		t.Errorf("line %q", c.Line)
	}
}

// TestStagingStates covers what staging's schema alone settles.
func TestStagingStates(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_states_prod")
	customers(r.ctx, t, r.admin, prod, "customers", idRange(1, 200))
	customers(r.ctx, t, r.admin, prod, "buyers", idRange(1, 200))
	metaTable(r.ctx, t, r.admin, prod, "contact_meta", ", KEY meta_key (meta_key)")
	insertBatches(r.ctx, t, r.admin, "`"+prod+"`.contact_meta", "meta_id, owner_id, meta_key, meta_value", idRange(1, 200), func(id int64) string {
		return fmt.Sprintf("(%d,%d,'billing_email','%s')", id, id, fakeEmail(id))
	})
	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{})

	db := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_states_stag")
	// A view in place of a table; a column made binary; a key column renamed.
	exec(r.ctx, t, r.admin, "CREATE TABLE `"+db+"`.real_customers LIKE `"+prod+"`.customers")
	exec(r.ctx, t, r.admin, "CREATE VIEW `"+db+"`.customers AS SELECT * FROM `"+db+"`.real_customers")
	exec(r.ctx, t, r.admin, "CREATE TABLE `"+db+"`.buyers (id bigint NOT NULL PRIMARY KEY, email varbinary(190), phone varchar(32))")
	exec(r.ctx, t, r.admin, "CREATE TABLE `"+db+"`.contact_meta (meta_id bigint unsigned NOT NULL PRIMARY KEY, owner_id bigint NOT NULL, "+
		"the_key varchar(255), meta_value longtext)")
	res := compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{})
	for loc, state := range map[string]string{
		"customers.email":                        model.LeakUnreadable,
		"buyers.email":                           model.LeakUnreadable,
		"buyers.phone":                           model.LeakRead,
		"contact_meta.meta_value[billing_email]": model.LeakNotOnStaging,
	} {
		for _, c := range res.Columns {
			if c.Location() == loc && c.State != state {
				t.Errorf("%s: %s, want %s", loc, c.State, state)
			}
		}
	}
	if _, unchecked := Gate(res, model.SeverityHigh); unchecked < 3 {
		t.Errorf("%d unchecked", unchecked)
	}
	// A key column that is now a number.
	exec(r.ctx, t, r.admin, "ALTER TABLE `"+db+"`.contact_meta CHANGE the_key meta_key int")
	res = compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{})
	if c := columnOf(t, res, "contact_meta.meta_value[billing_email]", model.LeakEmail); c.State != model.LeakUnreadable {
		t.Errorf("state %s", c.State)
	}
}

// TestTimeLimits: a statement timeout on a table with no key stops it with the
// rows read so far, and the time limit leaves the tables after it not read.
func TestTimeLimits(t *testing.T) {
	r := newShapeRun(t)
	prod := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_time_prod")
	customers(r.ctx, t, r.admin, prod, "customers", idRange(1, 60000))
	customers(r.ctx, t, r.admin, prod, "buyers", idRange(1, 80000))
	f := hashDB(r.ctx, t, r.cfg, prod, r.key, HashOptions{})

	db := emptyDB(r.ctx, t, r.admin, "prodmask_fixture_leak_time_stag")
	for _, table := range []string{"customers", "buyers"} {
		exec(r.ctx, t, r.admin, fmt.Sprintf("CREATE TABLE `%s`.%s (id bigint NOT NULL, email varchar(190), phone varchar(32)) ENGINE=InnoDB", db, table))
		exec(r.ctx, t, r.admin, fmt.Sprintf("INSERT INTO `%s`.%s SELECT * FROM `%s`.%s", db, table, prod, table))
	}
	exec(r.ctx, t, r.admin, "ANALYZE TABLE `"+db+"`.customers, `"+db+"`.buyers")

	// The session's own statement limit, set low once the schema's been read.
	sess := openSession(r.ctx, t, r.cfg, db)
	limit := "SET SESSION max_statement_time = 0.001"
	if sess.Flavor() == "mysql" {
		limit = "SET SESSION max_execution_time = 1"
	}
	res, err := Compare(r.ctx, sess, f, r.key, CompareOptions{Progress: func(done, total int, table string, rows int64) {
		if table != "" && rows == 0 {
			if _, err := sess.DB.ExecContext(r.ctx, limit); err != nil {
				t.Errorf("set the limit: %v", err)
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := columnOf(t, res, "customers.email", model.LeakEmail)
	if c.State != model.LeakStopped || c.StoppedBy != "timed out" || c.RowsRead >= 60000 {
		t.Errorf("state %s by %q after %d rows", c.State, c.StoppedBy, c.RowsRead)
	}
	if !strings.Contains(text(t, res), "a longer --timeout may read more") {
		t.Errorf("report:\n%s", text(t, res))
	}
	if hits, unchecked := Gate(res, model.SeverityHigh); hits+unchecked == 0 {
		t.Error("a stopped column must fail a gate")
	}

	// The time limit runs out during the smallest table: the other isn't read.
	res = compareDB(r.ctx, t, r.cfg, db, f, r.key, CompareOptions{MaxTime: 30 * time.Millisecond, Progress: func(done, total int, table string, rows int64) {
		if table != "" && rows == 0 && done == 0 {
			time.Sleep(60 * time.Millisecond)
		}
	}})
	first := columnOf(t, res, "customers.email", model.LeakEmail)
	second := columnOf(t, res, "buyers.email", model.LeakEmail)
	if first.State != model.LeakStopped || first.StoppedBy != "--max-time" {
		t.Errorf("the first table: %s by %q", first.State, first.StoppedBy)
	}
	if second.State != model.LeakNotRead || !strings.Contains(second.Line, "--max-time came first") {
		t.Errorf("the second table: %s, %q", second.State, second.Line)
	}
	if hits, unchecked := Gate(res, model.SeverityHigh); hits+unchecked == 0 {
		t.Error("a gate must not pass with tables not read")
	}
	if !strings.Contains(text(t, res), "not read: --max-time came first") {
		t.Errorf("report:\n%s", text(t, res))
	}
}
