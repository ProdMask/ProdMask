package leak

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
	"github.com/ProdMask/ProdMask/pkg/sample"
)

// All data here is invented, at a domain that doesn't exist. The phone numbers
// are in the shape of real ones, but no one has them.

const fakeDomain = "mailbox.prodmask-fixture.dev"
const staffDomain = "shop.prodmask-fixture.dev"

func fakeEmail(i int64) string {
	if i%100 == 0 {
		return fmt.Sprintf("staff.%d@%s", i, staffDomain)
	}
	return fmt.Sprintf("customer.%d@%s", i, fakeDomain)
}

func fakePhone(i int64) string { return fmt.Sprintf("+30 69 %d", 10000000+i) }

// insertBatches inserts rows in multi-row INSERTs: row writes one row's
// parenthesised values, made only of numbers and the invented text above.
func insertBatches(ctx context.Context, t *testing.T, admin *sql.DB, table, cols string, ids []int64, row func(id int64) string) {
	t.Helper()
	for start := 0; start < len(ids); start += 2000 {
		var b strings.Builder
		fmt.Fprintf(&b, "INSERT INTO %s (%s) VALUES ", table, cols)
		for i, id := range ids[start:min(start+2000, len(ids))] {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(row(id))
		}
		exec(ctx, t, admin, b.String())
	}
}

func idRange(from, to int64) []int64 {
	out := make([]int64, 0, to-from+1)
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func customerRow(id int64) string {
	return fmt.Sprintf("(%d,'%s','%s')", id, fakeEmail(id), fakePhone(id))
}

// customers makes a table of people in a database.
func customers(ctx context.Context, t *testing.T, admin *sql.DB, db, table string, ids []int64) {
	t.Helper()
	exec(ctx, t, admin, fmt.Sprintf("CREATE TABLE `%s`.`%s` (id bigint NOT NULL PRIMARY KEY, email varchar(190), phone varchar(32)) ENGINE=InnoDB", db, table))
	insertBatches(ctx, t, admin, "`"+db+"`.`"+table+"`", "id, email, phone", ids, customerRow)
	exec(ctx, t, admin, fmt.Sprintf("ANALYZE TABLE `%s`.`%s`", db, table))
}

// stagingOf makes a staging database holding a copy of one production table's
// rows, then runs changes on it.
func stagingOf(ctx context.Context, t *testing.T, admin *sql.DB, name, prod, table, where string, changes ...string) string {
	t.Helper()
	db := emptyDB(ctx, t, admin, name)
	exec(ctx, t, admin, fmt.Sprintf("CREATE TABLE `%s`.`%s` LIKE `%s`.`%s`", db, table, prod, table))
	exec(ctx, t, admin, fmt.Sprintf("INSERT INTO `%s`.`%s` SELECT * FROM `%s`.`%s`%s", db, table, prod, table, where))
	for _, c := range changes {
		exec(ctx, t, admin, strings.ReplaceAll(c, "{t}", "`"+db+"`.`"+table+"`"))
	}
	exec(ctx, t, admin, fmt.Sprintf("ANALYZE TABLE `%s`.`%s`", db, table))
	return db
}

const maskEmail = "UPDATE {t} SET email = CONCAT('user.', id, '@example.test')"
const maskPhone = "UPDATE {t} SET phone = CONCAT('+1 202 555 ', LPAD(id MOD 10000, 4, '0'))"

func text(t *testing.T, res *model.LeakResult) string {
	t.Helper()
	var b bytes.Buffer
	if err := report.LeakText(&b, res, false); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestGeneratedTable(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	key := testKey(t)

	const rows = 100000
	prod := emptyDB(ctx, t, admin, "prodmask_fixture_leak_gen_prod")
	customers(ctx, t, admin, prod, "customers", idRange(1, rows))
	f := hashDB(ctx, t, cfg, prod, key, HashOptions{})
	emailCol := func() FileColumn {
		for _, c := range f.Columns {
			if c.Table == "customers" && c.Column == "email" {
				return c
			}
		}
		t.Fatal("no email column in the file")
		return FileColumn{}
	}()
	if emailCol.Sample != model.SampleSpread || emailCol.Exact {
		t.Errorf("sample %s, exact %v", emailCol.Sample, emailCol.Exact)
	}
	if emailCol.Values < 2900 || emailCol.Values > DefaultSampleRows {
		t.Errorf("%d values sampled", emailCol.Values)
	}
	if emailCol.EstimatedValues < 50000 || emailCol.EstimatedValues > 200000 {
		t.Errorf("estimated %d values on production", emailCol.EstimatedValues)
	}
	email, phone := "customers.email", "customers.phone"

	compare := func(t *testing.T, db string, opts CompareOptions) *model.LeakResult {
		t.Helper()
		return compareDB(ctx, t, cfg, db, f, key, opts)
	}

	t.Run("a full copy", func(t *testing.T) {
		res := compare(t, stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_full", prod, "customers", ""), CompareOptions{})
		c := columnOf(t, res, email, model.LeakEmail)
		if c.Found != c.Sampled || c.Rows != int64(c.Found) || c.RowsRead != rows {
			t.Errorf("found %d of %d, on %d rows, %d rows read", c.Found, c.Sampled, c.Rows, c.RowsRead)
		}
		if c.EstimateInAll < 50000 || !strings.Contains(c.Line, "roughly") {
			t.Errorf("estimate %d, line %q", c.EstimateInAll, c.Line)
		}
	})

	t.Run("a real subset of the newest rows", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_newest", prod, "customers", " WHERE id > 95000")
		c := columnOf(t, compare(t, db, CompareOptions{}), email, model.LeakEmail)
		if c.Found < 90 || c.Found > 210 {
			t.Errorf("found %d of %d, about 150 expected", c.Found, c.Sampled)
		}
		if c.EstimateInAll < 3000 || c.EstimateInAll > 7500 {
			t.Errorf("estimate %d in all, about 5,000 expected: %q", c.EstimateInAll, c.Line)
		}
	})

	t.Run("a block from the middle, the rest masked", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_block", prod, "customers", "",
			maskEmail+" WHERE id NOT BETWEEN 50000 AND 50097", maskPhone)
		c := columnOf(t, compare(t, db, CompareOptions{}), email, model.LeakEmail)
		if c.Found < 1 {
			t.Errorf("a block of 98 rows spans two slices, so it can't be missed: %q", c.Line)
		}
	})

	t.Run("half masked", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_half", prod, "customers", "", maskEmail+" WHERE id MOD 2 = 0")
		c := columnOf(t, compare(t, db, CompareOptions{}), email, model.LeakEmail)
		if c.Found < 1300 || c.Found > 1700 {
			t.Errorf("found %d of %d, about half expected", c.Found, c.Sampled)
		}
	})

	t.Run("masked", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_masked", prod, "customers", "",
			"UPDATE {t} SET email = CONCAT('someone.', id, '@elsewhere.prodmask-fixture.dev')", maskPhone)
		res := compare(t, db, CompareOptions{})
		c := columnOf(t, res, email, model.LeakEmail)
		if c.Found != 0 || c.Values != rows {
			t.Errorf("found %d, %d values read", c.Found, c.Values)
		}
		if !strings.Contains(c.Line, "real values would show 95% of the time; fewer may not") {
			t.Errorf("line %q", c.Line)
		}
		if p := columnOf(t, res, phone, model.LeakPhone); p.Found != 0 || p.Values != rows {
			t.Errorf("phones: found %d, %d values read", p.Found, p.Values)
		}
		if hits, unchecked := Gate(res, model.SeverityHigh); hits != 0 || unchecked != 0 {
			t.Errorf("gate: %d hits, %d unchecked", hits, unchecked)
		}
		out := text(t, res)
		if !strings.Contains(out, "0 of ") || !strings.Contains(out, "That isn't proof that none are there.") {
			t.Errorf("report:\n%s", out)
		}
	})

	t.Run("masked by a reserved domain and cleared phones", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_cleared", prod, "customers", "", maskEmail, "UPDATE {t} SET phone = NULL")
		res := compare(t, db, CompareOptions{})
		if c := columnOf(t, res, email, model.LeakEmail); c.Found != 0 || c.Values != 0 ||
			!strings.Contains(c.Line, "no values of this kind in what was read") {
			t.Errorf("email: %+v", c)
		}
		if c := columnOf(t, res, phone, model.LeakPhone); c.Found != 0 || c.Values != 0 {
			t.Errorf("phone: %+v", c)
		}
	})

	t.Run("a small staging table", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_small", prod, "customers", " WHERE id <= 40",
			"UPDATE {t} SET email = CONCAT('someone.', id, '@elsewhere.prodmask-fixture.dev')", maskPhone)
		c := columnOf(t, compare(t, db, CompareOptions{}), email, model.LeakEmail)
		if c.Found != 0 || c.Values != 40 || !strings.Contains(c.Line, "even if all 40 values here were real") {
			t.Errorf("found %d, %d values: %q", c.Found, c.Values, c.Line)
		}
		if want := CatchChance(float64(c.Sampled), float64(c.EstimatedValues), 40); c.CatchIfAllReal != want || want > 0.9 {
			t.Errorf("catch %f, want %f", c.CatchIfAllReal, want)
		}
	})

	t.Run("staff kept, allowed on hash", func(t *testing.T) {
		allow, err := NewAllowlist([]string{staffDomain})
		if err != nil {
			t.Fatal(err)
		}
		fa := hashDB(ctx, t, cfg, prod, key, HashOptions{Allow: allow})
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_staff1", prod, "customers", "",
			"UPDATE {t} SET email = CONCAT('someone.', id, '@elsewhere.prodmask-fixture.dev') WHERE id MOD 100 <> 0", maskPhone)
		res := compareDB(ctx, t, cfg, db, fa, key, CompareOptions{})
		if c := columnOf(t, res, email, model.LeakEmail); c.Found != 0 {
			t.Errorf("found %d staff addresses", c.Found)
		}
		if len(res.Allowed.Domains) != 1 || res.Allowed.ValuesSkipped == 0 {
			t.Errorf("allowed: %+v", res.Allowed)
		}
		if out := text(t, res); !strings.Contains(out, "Allowed by --allow-email: "+staffDomain) {
			t.Errorf("report:\n%s", out)
		}
	})

	t.Run("staff kept, allowed on compare", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_staff2", prod, "customers", "",
			"UPDATE {t} SET email = CONCAT('someone.', id, '@elsewhere.prodmask-fixture.dev') WHERE id MOD 100 <> 0", maskPhone)
		if c := columnOf(t, compare(t, db, CompareOptions{}), email, model.LeakEmail); c.Found == 0 {
			t.Error("staff addresses in the sample should turn up without an allowlist")
		}
		allow, err := NewAllowlist([]string{staffDomain})
		if err != nil {
			t.Fatal(err)
		}
		if c := columnOf(t, compare(t, db, CompareOptions{Allow: allow}), email, model.LeakEmail); c.Found != 0 {
			t.Errorf("found %d allowed addresses", c.Found)
		}
	})

	t.Run("an exact address is allowed and never written", func(t *testing.T) {
		addr := fakeEmail(100)
		allow, err := NewAllowlist([]string{addr})
		if err != nil {
			t.Fatal(err)
		}
		fa := hashDB(ctx, t, cfg, prod, key, HashOptions{Allow: allow})
		var file bytes.Buffer
		if err := fa.Write(&file); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(file.String(), addr) || fa.AllowedAddresses != 1 || len(fa.AllowDomains) != 0 {
			t.Errorf("addresses %d, domains %v, in the file: %v", fa.AllowedAddresses, fa.AllowDomains, strings.Contains(file.String(), addr))
		}
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_addr", prod, "customers", " WHERE id = 100")
		res := compareDB(ctx, t, cfg, db, fa, key, CompareOptions{Allow: allow})
		var out bytes.Buffer
		report.LeakJSON(&out, res)
		report.LeakText(&out, res, false)
		if strings.Contains(out.String(), addr) || res.Allowed.Addresses != 2 {
			t.Errorf("addresses %d, in the report: %v", res.Allowed.Addresses, strings.Contains(out.String(), addr))
		}
		if c := columnOf(t, res, email, model.LeakEmail); c.Found != 0 || c.Values != 0 || c.ValuesSkipped != 1 {
			t.Errorf("found %d, %d values read, %d skipped", c.Found, c.Values, c.ValuesSkipped)
		}
		// And without the list, it does count, so the test proves something.
		res = compareDB(ctx, t, cfg, db, f, key, CompareOptions{})
		if c := columnOf(t, res, email, model.LeakEmail); c.Values != 1 {
			t.Errorf("%d values read with no list", c.Values)
		}
	})

	t.Run("a renamed column fails the gate unless excepted", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_renamed", prod, "customers", "",
			"ALTER TABLE {t} CHANGE email contact_email varchar(190)", maskPhone)
		res := compare(t, db, CompareOptions{})
		if c := columnOf(t, res, email, model.LeakEmail); c.State != model.LeakNotOnStaging {
			t.Errorf("state %s", c.State)
		}
		if hits, unchecked := Gate(res, model.SeverityHigh); hits != 0 || unchecked != 1 {
			t.Errorf("gate: %d hits, %d unchecked", hits, unchecked)
		}
		res = compare(t, db, CompareOptions{FailExcept: []string{"CUSTOMERS.email"}})
		if hits, unchecked := Gate(res, model.SeverityHigh); hits != 0 || unchecked != 0 {
			t.Errorf("excepted gate: %d hits, %d unchecked", hits, unchecked)
		}
		if out := text(t, res); !strings.Contains(out, "not on staging") || !strings.Contains(out, "excepted from --fail-on") {
			t.Errorf("report:\n%s", out)
		}
		res = compare(t, db, CompareOptions{FailExcept: []string{"no_such_table"}})
		if len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, "\n"), "--fail-except value 1 matches no column") {
			t.Errorf("warnings: %q", res.Warnings)
		}
	})

	t.Run("an excepted column's hit can't fail the gate", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_except", prod, "customers", "", maskPhone)
		res := compare(t, db, CompareOptions{FailExcept: []string{email}})
		if c := columnOf(t, res, email, model.LeakEmail); c.Found == 0 || !c.Excepted {
			t.Errorf("found %d, excepted %v", c.Found, c.Excepted)
		}
		if hits, _ := Gate(res, model.SeverityHigh); hits != 0 {
			t.Errorf("%d hits", hits)
		}
	})

	t.Run("nothing on staging", func(t *testing.T) {
		db := emptyDB(ctx, t, admin, "prodmask_fixture_leak_gen_nothing")
		res := compare(t, db, CompareOptions{})
		if !res.NothingRead() {
			t.Errorf("summary: %+v", res.Summary)
		}
		if _, unchecked := Gate(res, model.SeverityHigh); unchecked == 0 {
			t.Error("a gate must not pass on nothing read")
		}
		if out := text(t, res); !strings.Contains(out, "Nothing was read on this staging database") || strings.Contains(out, "sampled values found") {
			t.Errorf("report:\n%s", out)
		}
	})

	t.Run("an error part-way stops a table", func(t *testing.T) {
		db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gen_error", prod, "customers", "")
		res := compare(t, db, CompareOptions{Progress: func(done, total int, table string, rows int64) {
			if table != "" && rows == 0 {
				exec(ctx, t, admin, "DROP TABLE `"+db+"`.`customers`")
			}
		}})
		c := columnOf(t, res, email, model.LeakEmail)
		if c.State != model.LeakStopped || !strings.Contains(c.StoppedBy, "MySQL error") {
			t.Errorf("state %s, stopped by %q", c.State, c.StoppedBy)
		}
		if _, unchecked := Gate(res, model.SeverityHigh); unchecked == 0 {
			t.Error("a gate must not pass on a stopped column")
		}
		if out := text(t, res); !strings.Contains(out, "stopped after 0 of ~") || !strings.Contains(out, "MySQL error") || strings.Contains(out, "--timeout may") {
			t.Errorf("report:\n%s", out)
		}
	})
}

// TestSmallTableUsesPoints: a table a little bigger than the sample must not be
// judged by its oldest rows, or a copy of its newest would read as zero.
func TestSmallTableUsesPoints(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	key := testKey(t)
	prod := emptyDB(ctx, t, admin, "prodmask_fixture_leak_five_prod")
	customers(ctx, t, admin, prod, "customers", idRange(1, 5000))
	f := hashDB(ctx, t, cfg, prod, key, HashOptions{})
	db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_five_stag", prod, "customers", " WHERE id > 3000")
	c := columnOf(t, compareDB(ctx, t, cfg, db, f, key, CompareOptions{}), "customers.email", model.LeakEmail)
	if c.Sample != model.SampleSpread || c.Exact {
		t.Errorf("sample %s, exact %v", c.Sample, c.Exact)
	}
	if c.Found < 800 {
		t.Errorf("found %d of %d: about 40%% expected", c.Found, c.Sampled)
	}
	// Under the sample, every value is read, and a count is exact.
	small := emptyDB(ctx, t, admin, "prodmask_fixture_leak_tiny_prod")
	customers(ctx, t, admin, small, "customers", idRange(1, 2000))
	f = hashDB(ctx, t, cfg, small, key, HashOptions{})
	db = stagingOf(ctx, t, admin, "prodmask_fixture_leak_tiny_stag", small, "customers", "",
		"UPDATE {t} SET email = CONCAT('someone.', id, '@elsewhere.prodmask-fixture.dev')", maskPhone)
	c = columnOf(t, compareDB(ctx, t, cfg, db, f, key, CompareOptions{}), "customers.email", model.LeakEmail)
	if c.Sample != model.SampleAllRows || !c.Exact || !strings.Contains(c.Line, "every value of this kind on production was sampled") {
		t.Errorf("%+v", c)
	}
}

// TestThinKey: tight batches of keys with huge gaps leave the points with few
// rows of their own, all first after a gap, and no odds can be drawn from them.
func TestThinKey(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	key := testKey(t)
	var ids []int64
	for batch := int64(1); batch <= 100; batch++ {
		for j := int64(0); j < 100; j++ {
			ids = append(ids, batch*1_000_000_000+j)
		}
	}
	prod := emptyDB(ctx, t, admin, "prodmask_fixture_leak_gaps_prod")
	customers(ctx, t, admin, prod, "customers", ids)
	sess := openSession(ctx, t, cfg, prod)
	f, warnings, err := Hash(ctx, sess, key, HashOptions{Preset: "auto", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "large gaps") {
		t.Errorf("warnings: %q", warnings)
	}
	db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_gaps_stag", prod, "customers", "",
		"UPDATE {t} SET email = CONCAT('someone.', id, '@elsewhere.prodmask-fixture.dev')", maskPhone)
	c := columnOf(t, compareDB(ctx, t, cfg, db, f, key, CompareOptions{}), "customers.email", model.LeakEmail)
	if c.Sample != model.SampleThin || c.ShownAt95 != 0 || !strings.Contains(c.Line, "from part of the table only") {
		t.Errorf("%+v", c)
	}
}

// TestNegativeKeys: the whole read has no lower bound to begin with, and goes
// on past a chunk.
func TestNegativeKeys(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	key := testKey(t)
	ids := idRange(-4000, 3000)
	prod := emptyDB(ctx, t, admin, "prodmask_fixture_leak_neg_prod")
	customers(ctx, t, admin, prod, "customers", ids)
	f := hashDB(ctx, t, cfg, prod, key, HashOptions{})
	db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_neg_stag", prod, "customers", "")
	c := columnOf(t, compareDB(ctx, t, cfg, db, f, key, CompareOptions{}), "customers.email", model.LeakEmail)
	if c.RowsRead != int64(len(ids)) || c.Found != c.Sampled {
		t.Errorf("%d rows read, found %d of %d", c.RowsRead, c.Found, c.Sampled)
	}
}

// TestKeyValueTable: flagged keys are sampled evenly, a rare key gets its
// lookup, and the read filters in the select list.
func TestKeyValueTable(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	key := testKey(t)
	prod := emptyDB(ctx, t, admin, "prodmask_fixture_leak_kv_prod")
	exec(ctx, t, admin, "CREATE TABLE `"+prod+"`.customer_meta (meta_id bigint unsigned NOT NULL PRIMARY KEY, customer_id bigint NOT NULL, "+
		"meta_key varchar(255), meta_value longtext, KEY meta_key (meta_key(191))) ENGINE=InnoDB")
	const customersN, perCustomer = 10000, 30
	keyOf := func(id int64) (string, string) {
		c := (id - 1) / perCustomer
		switch n := (id - 1) % perCustomer; {
		case n == 0:
			return "billing_email", fakeEmail(c + 1)
		case n == 1:
			return "billing_phone", fakePhone(c + 1)
		case n == 2 && c%10 == 0:
			return "contact_email", "contact." + fmt.Sprint(c) + "@" + fakeDomain
		case n == 3 && c < 5:
			return "rare_email", "rare." + fmt.Sprint(c) + "@" + fakeDomain
		default:
			return fmt.Sprintf("plain_setting_%02d", n), fmt.Sprintf("value %d", n)
		}
	}
	insertBatches(ctx, t, admin, "`"+prod+"`.customer_meta", "meta_id, customer_id, meta_key, meta_value", idRange(1, customersN*perCustomer), func(id int64) string {
		k, v := keyOf(id)
		return fmt.Sprintf("(%d,%d,'%s','%s')", id, (id-1)/perCustomer+1, k, v)
	})
	exec(ctx, t, admin, "ANALYZE TABLE `"+prod+"`.customer_meta")
	f := hashDB(ctx, t, cfg, prod, key, HashOptions{})
	byKey := map[string]FileColumn{}
	for _, c := range f.Columns {
		byKey[c.MetaKey] = c
	}
	if c := byKey["billing_email"]; c.Sample != model.SampleSpread || c.Values < 500 || c.Values > 1500 {
		t.Errorf("billing_email: %s, %d values, about 1,000 expected", c.Sample, c.Values)
	}
	if c := byKey["contact_email"]; c.Sample != model.SampleFirstRows || c.Values < 300 {
		t.Errorf("contact_email, on one row in 300: %s, %d values", c.Sample, c.Values)
	}
	if c := byKey["rare_email"]; c.Sample != model.SampleAllRows || !c.Exact || c.Values != 5 {
		t.Errorf("rare_email, on 5 rows: %s, exact %v, %d values", c.Sample, c.Exact, c.Values)
	}
	if c := byKey["billing_email"]; c.EstimatedValues < customersN/2 || c.EstimatedValues > customersN*2 {
		t.Errorf("billing_email: estimated %d values, about %d expected", c.EstimatedValues, customersN)
	}
	if c := byKey["billing_email"]; c.KeyColumn != "meta_key" || c.Column != "meta_value" {
		t.Errorf("billing_email: key column %q, column %q", c.KeyColumn, c.Column)
	}

	res := compareDB(ctx, t, cfg, stagingOf(ctx, t, admin, "prodmask_fixture_leak_kv_full", prod, "customer_meta", ""), f, key, CompareOptions{})
	for _, c := range res.Columns {
		if c.Found != c.Sampled || c.State != model.LeakRead {
			t.Errorf("%s: %s, found %d of %d", c.Location(), c.State, c.Found, c.Sampled)
		}
	}
	if c := columnOf(t, res, "customer_meta.meta_value[billing_email]", model.LeakEmail); c.Rows != int64(c.Found) || c.RowsRead != customersN*perCustomer {
		t.Errorf("billing_email: on %d rows, %d rows read", c.Rows, c.RowsRead)
	}

	db := stagingOf(ctx, t, admin, "prodmask_fixture_leak_kv_masked", prod, "customer_meta", "",
		"UPDATE {t} SET meta_value = CONCAT('someone.', meta_id, '@elsewhere.prodmask-fixture.dev') WHERE meta_key LIKE '%email'",
		"UPDATE {t} SET meta_value = CONCAT('+1 202 555 ', LPAD(meta_id MOD 10000, 4, '0')) WHERE meta_key LIKE '%phone'")
	res = compareDB(ctx, t, cfg, db, f, key, CompareOptions{})
	for _, c := range res.Columns {
		if c.Found != 0 {
			t.Errorf("%s: found %d", c.Location(), c.Found)
		}
	}
	if c := columnOf(t, res, "customer_meta.meta_value[contact_email]", model.LeakEmail); !strings.Contains(c.Line, "from part of the table only") {
		t.Errorf("contact_email: %q", c.Line)
	}
	if c := columnOf(t, res, "customer_meta.meta_value[rare_email]", model.LeakEmail); !strings.Contains(c.Line, "every value of this kind") {
		t.Errorf("rare_email: %q", c.Line)
	}
}

// TestSampleCutShort: a sample a statement error stops part-way is kept, with
// no odds, and with no hit it fails a gate; a table that gives nothing goes on
// the list of what wasn't read.
func TestSampleCutShort(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	key := testKey(t)
	prod := emptyDB(ctx, t, admin, "prodmask_fixture_leak_cut_prod")
	customers(ctx, t, admin, prod, "customers", idRange(1, 20000))
	customers(ctx, t, admin, prod, "buyers", idRange(1, 20000))

	// The table goes away after the first statement of points.
	picks := 0
	sess := openSession(ctx, t, cfg, prod)
	f, warnings, err := Hash(ctx, sess, key, HashOptions{Preset: "auto", Version: "test", Pick: func(n uint64) uint64 {
		picks++
		if picks == 60 {
			exec(ctx, t, admin, "DROP TABLE `"+prod+"`.`buyers`")
		}
		return n / 2
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "could not sample all of buyers") {
		t.Errorf("warnings: %q", warnings)
	}
	var buyers *FileColumn
	for i, c := range f.Columns {
		if c.Table == "buyers" && c.Column == "email" {
			buyers = &f.Columns[i]
		}
	}
	if buyers == nil || buyers.Sample != model.SampleCut || buyers.Values == 0 || buyers.Exact {
		t.Fatalf("buyers: %+v", buyers)
	}
	db := emptyDB(ctx, t, admin, "prodmask_fixture_leak_cut_stag")
	customers(ctx, t, admin, db, "buyers", idRange(100000, 100100))
	customers(ctx, t, admin, db, "customers", idRange(100000, 100100))
	res := compareDB(ctx, t, cfg, db, f, key, CompareOptions{})
	c := columnOf(t, res, "buyers.email", model.LeakEmail)
	if c.Found != 0 || c.ShownAt95 != 0 || !strings.Contains(c.Line, "from part of the table only") {
		t.Errorf("%+v", c)
	}
	if _, unchecked := Gate(res, model.SeverityHigh); unchecked == 0 {
		t.Error("a cut sample with no hit must fail a gate")
	}

	// The table goes away before its sample starts.
	prod2 := emptyDB(ctx, t, admin, "prodmask_fixture_leak_cut_prod2")
	customers(ctx, t, admin, prod2, "customers", idRange(1, 20000))
	customers(ctx, t, admin, prod2, "buyers", idRange(1, 20000))
	sess2 := openSession(ctx, t, cfg, prod2)
	f, _, err = Hash(ctx, sess2, key, HashOptions{Preset: "auto", Version: "test", Progress: func(done, total int, table string) {
		if table == "buyers" {
			exec(ctx, t, admin, "DROP TABLE `"+prod2+"`.`buyers`")
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	notRead := false
	for _, l := range f.LeftOut {
		if strings.HasPrefix(l.Location, "buyers.") && l.NotRead && l.Why == "could not be sampled" {
			notRead = true
		}
	}
	if !notRead {
		t.Errorf("left out: %+v", f.LeftOut)
	}
	res = compareDB(ctx, t, cfg, db, f, key, CompareOptions{})
	if _, unchecked := Gate(res, model.SeverityHigh); unchecked == 0 {
		t.Error("a table production couldn't sample must fail a gate")
	}
	if out := text(t, res); !strings.Contains(out, "could not be sampled on production") {
		t.Errorf("report:\n%s", out)
	}
	res = compareDB(ctx, t, cfg, db, f, key, CompareOptions{FailExcept: []string{"buyers"}})
	if _, unchecked := Gate(res, model.SeverityHigh); unchecked != 0 {
		t.Errorf("excepted: %d unchecked", unchecked)
	}
}

// TestSampleReadsStayBounded counts the rows the server reads for a sample, on
// the session's one connection.
func TestSampleReadsStayBounded(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	prod := emptyDB(ctx, t, admin, "prodmask_fixture_leak_reads_prod")
	customers(ctx, t, admin, prod, "customers", idRange(1, 100000))
	sess := openSession(ctx, t, cfg, prod)
	handlers := func() int64 {
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
	table := &model.Table{Name: "customers", Type: "BASE TABLE", RowsEstimate: 100000, PrimaryKey: []string{"id"}, Columns: []*model.Column{
		{Name: "id", DataType: "bigint"}, {Name: "email", DataType: "varchar"}}}
	sm := &sample.Sampler{DB: sess.DB, MaxValueLen: 4096, Timeout: time.Minute}
	before := handlers()
	res, err := sm.Spread(ctx, table, []string{"LEFT(`email`, 4096)"}, nil, DefaultSampleRows, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	read := handlers() - before
	if len(res.Rows) < 2900 {
		t.Errorf("%d rows", len(res.Rows))
	}
	// Each point is one seek and one row; the rest is MIN, MAX and the status
	// statements themselves.
	if read > 10*DefaultSampleRows {
		t.Errorf("the server read %d rows for a sample of %d", read, DefaultSampleRows)
	}
}

// TestSelectOnlyUser runs both steps as a user that can only read.
func TestSelectOnlyUser(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	key := testKey(t)
	prod := emptyDB(ctx, t, admin, "prodmask_fixture_leak_ro_prod")
	customers(ctx, t, admin, prod, "customers", idRange(1, 8000))
	staging := stagingOf(ctx, t, admin, "prodmask_fixture_leak_ro_stag", prod, "customers", "")

	const user, password = "prodmask_leak_ro", "fixture-only-" + "Zq7x2Lm9"
	exec(ctx, t, admin, "DROP USER IF EXISTS '"+user+"'@'%'")
	exec(ctx, t, admin, "CREATE USER '"+user+"'@'%' IDENTIFIED BY '"+password+"'")
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP USER IF EXISTS '"+user+"'@'%'") })
	for _, db := range []string{prod, staging} {
		exec(ctx, t, admin, "GRANT SELECT, SHOW VIEW ON `"+db+"`.* TO '"+user+"'@'%'")
	}
	ro := cfg.Clone()
	ro.User, ro.Passwd = user, password
	ro.AllowCleartextPasswords = false

	sess := openSession(ctx, t, ro, prod)
	var only string
	if err := sess.DB.QueryRowContext(ctx, "SELECT @@SESSION.transaction_read_only").Scan(&only); err == nil && only != "1" {
		t.Errorf("transaction_read_only is %s", only)
	}
	if _, err := sess.DB.ExecContext(ctx, "UPDATE customers SET phone = NULL WHERE id = 1"); err == nil {
		t.Error("a write went through")
	}
	f, _, err := Hash(ctx, sess, key, HashOptions{Preset: "auto", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	res := compareDB(ctx, t, ro, staging, f, key, CompareOptions{})
	if c := columnOf(t, res, "customers.email", model.LeakEmail); c.Found != c.Sampled || c.Found == 0 {
		t.Errorf("found %d of %d", c.Found, c.Sampled)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "can change") {
			t.Errorf("warning: %s", w)
		}
	}
}
