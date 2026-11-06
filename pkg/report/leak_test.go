package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/model"
)

func leakFixture() *model.LeakResult {
	limits := LeakLimits(3000)
	return &model.LeakResult{
		Tool: "prodmask", Version: "1.2.3", Database: "shop",
		Server: model.ServerInfo{Flavor: "mariadb", Version: "11.8.9-MariaDB", Address: "staging.internal:3306", User: "ro"},
		Hashes: model.LeakHashesInfo{Database: "shop", CreatedAt: time.Date(2026, 11, 5, 16, 0, 0, 0, time.UTC), SampleRows: 3000},
		Limits: limits,
	}
}

func spreadColumn(c model.LeakColumn) model.LeakColumn {
	if c.Sample == "" {
		c.Sample = model.SampleSpread
	}
	if c.State == "" {
		c.State = model.LeakRead
	}
	if c.Severity == 0 {
		c.Severity = c.Kind.Severity()
	}
	c.Line = LeakLine(c)
	return c
}

const leakHowToRead = `How to read this
  - A zero is not proof. Only a sample of values is looked for: 3,000 sampled values out of 100,000 have about a 78% chance of catching 50 real rows, and about 14% of catching 5.
  - Only email addresses, phone numbers, IBANs, national and tax IDs, payment tokens, password hashes and secrets are counted. Real names, street addresses, cities and dates aren't looked for, because they match by chance, so they can still be there. Card numbers aren't hashed: prodmask scan on staging samples for them.
  - Only columns flagged on production are read. A value a script changed even slightly doesn't match: a real name before a swapped domain, a common home-made mask, reads as a zero. Values no longer on production, such as deleted customers, can't be sampled, so copies of them on staging aren't found.
  - Treat the hash file as personal data. Keep it as you keep production data, and delete it when you're done: https://github.com/ProdMask/ProdMask/blob/main/docs/leak-check.md

prodmask Pro, in development, will make staging copies with fake customers and check the result row by row: https://prodmask.com/leak-check
`

func TestLeakTextWithHits(t *testing.T) {
	res := leakFixture()
	res.Columns = []model.LeakColumn{
		spreadColumn(model.LeakColumn{Table: "wp_users", Column: "user_email", Kind: model.LeakEmail, Sampled: 3000, EstimatedValues: 100000,
			Found: 1860, Rows: 1860, Values: 90000, RowsRead: 100000, EstimateInAll: 62000}),
		spreadColumn(model.LeakColumn{Table: "wp_usermeta", Column: "meta_value", MetaKey: "billing_phone", Kind: model.LeakPhone, Sampled: 2233,
			EstimatedValues: 58000, Found: 1552, Rows: 1552, Values: 90000, RowsRead: 3000000, ChanceMatches: 2.01, EstimateInAll: 40000}),
		spreadColumn(model.LeakColumn{Table: "wp_wc_orders", Column: "billing_email", Kind: model.LeakEmail, Sampled: 3000, EstimatedValues: 100000,
			Values: 41220, RowsRead: 100000, ShownAt95: 98.4}),
		spreadColumn(model.LeakColumn{Table: "wp_comments", Column: "comment_content", Kind: model.LeakEmail, Sampled: 500, EstimatedValues: 100000,
			Values: 40, RowsRead: 100000, ShownAt95: 598, CatchIfAllReal: 0.182}),
		spreadColumn(model.LeakColumn{Table: "sales_order", Column: "customer_email", Kind: model.LeakEmail, Sampled: 3000, State: model.LeakStopped,
			StoppedBy: "--max-time", RowsRead: 3000000, RowsEstimate: 41000000}),
		spreadColumn(model.LeakColumn{Table: "wp_old_users", Column: "user_email", Kind: model.LeakEmail, Sampled: 500, State: model.LeakNotOnStaging}),
	}
	res.LeftOut = []model.LeakLeftOut{
		{Location: "wp_users.display_name", Why: "only kinds this check doesn't count"},
		{Location: "wp_users.first_name", Why: "only kinds this check doesn't count"},
		{Location: "wp_options.option_value[(key hidden)]", Why: "a key whose name can't be shown"},
	}
	res.Allowed = model.LeakAllowed{Domains: []string{"shop.example"}, Addresses: 1, ValuesSkipped: 412}
	res.Summary = model.LeakSummary{Columns: 6, ColumnsRead: 4, ColumnsWithHit: 2, Sampled: 8733, Found: 3412, RowsRead: 3200000, DurationMillis: 41000}
	var b bytes.Buffer
	if err := LeakText(&b, res, false); err != nil {
		t.Fatal(err)
	}
	want := `prodmask leak-check · shop · MariaDB 11.8.9 at staging.internal:3306
Compared with values sampled from shop on 2026-11-05 · 4 of 6 columns read · 3,200,000 rows · 41.0 s

Sampled production values found on this staging database
  3,412 of 8,733 sampled values found, in 2 of the 4 columns read.

  HIGH     wp_users.user_email                    email address           1,860 of 3,000 (62%) · on 1,860 rows · roughly 62,000 values in all
  HIGH     wp_usermeta.meta_value[billing_phone]  phone number            1,552 of 2,233 (70%) · on 1,552 rows · roughly 40,000 values in all · up to about 2 of these could be chance, if a masking tool makes up realistic numbers

Nothing found in these, which isn't proof that none are there
  wp_wc_orders.billing_email   email address           0 of 3,000: about 98 real values would show 95% of the time; fewer may not
  wp_comments.comment_content  email address           0 of 500: even if all 40 values here were real, this would catch it about 18% of the time

Not read, so nothing is known about these
  sales_order.customer_email  stopped by --max-time after 3,000,000 of ~41,000,000 rows
  wp_old_users.user_email     not on staging

Left out on production (--format json lists them): 1, a key whose name can't be shown; 2, only kinds this check doesn't count.

Allowed by --allow-email: shop.example and 1 address. 412 values skipped.

` + leakHowToRead
	if got := b.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestLeakTextWithNoHits(t *testing.T) {
	res := leakFixture()
	res.Columns = []model.LeakColumn{
		spreadColumn(model.LeakColumn{Table: "users", Column: "email", Kind: model.LeakEmail, Sampled: 3000, EstimatedValues: 100000,
			Values: 100000, RowsRead: 100000, ShownAt95: 98.4}),
	}
	res.Summary = model.LeakSummary{Columns: 1, ColumnsRead: 1, Sampled: 3000, RowsRead: 100000, DurationMillis: 900}
	var b bytes.Buffer
	if err := LeakText(&b, res, false); err != nil {
		t.Fatal(err)
	}
	want := `prodmask leak-check · shop · MariaDB 11.8.9 at staging.internal:3306
Compared with values sampled from shop on 2026-11-05 · 1 of 1 columns read · 100,000 rows · 900 ms

Sampled production values found on this staging database
  0 of 3,000 sampled values found, in the 1 columns read.
  That isn't proof that none are there. This looked for a sample of values, and only some kinds of data.

Nothing found in these, which isn't proof that none are there
  users.email  email address           0 of 3,000: about 98 real values would show 95% of the time; fewer may not

` + leakHowToRead
	if got := b.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestLeakTextWithNothingRead(t *testing.T) {
	res := leakFixture()
	res.Columns = []model.LeakColumn{
		spreadColumn(model.LeakColumn{Table: "users", Column: "email", Kind: model.LeakEmail, Sampled: 3000, State: model.LeakNotOnStaging}),
	}
	res.Summary = model.LeakSummary{Columns: 1, NothingRead: true}
	var b bytes.Buffer
	if err := LeakText(&b, res, false); err != nil {
		t.Fatal(err)
	}
	want := `prodmask leak-check · shop · MariaDB 11.8.9 at staging.internal:3306
Compared with values sampled from shop on 2026-11-05 · 0 of 1 columns read · 0 rows · 0 ms

Nothing was read on this staging database, so nothing is known about it.
  None of the 1 columns in the hash file could be read. Check the database name, the user's rights and the list below.

Not read, so nothing is known about these
  users.email  not on staging

` + leakHowToRead
	if got := b.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestLeakLine(t *testing.T) {
	email := model.LeakColumn{Kind: model.LeakEmail, State: model.LeakRead, Sample: model.SampleSpread, Sampled: 3000}
	phone := email
	phone.Kind = model.LeakPhone
	mk := func(base model.LeakColumn, change func(*model.LeakColumn)) string {
		change(&base)
		return LeakLine(base)
	}
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"a big hit", mk(email, func(c *model.LeakColumn) { c.Found, c.Rows, c.EstimateInAll = 1860, 2000, 62000 }),
			"1,860 of 3,000 (62%) · on 2,000 rows · roughly 62,000 values in all"},
		{"a few hits", mk(email, func(c *model.LeakColumn) { c.Found, c.Rows = 3, 1 }),
			"3 of 3,000 (under 1%) · on 1 row · at least 3"},
		{"exact hits", mk(email, func(c *model.LeakColumn) { c.Found, c.Rows, c.Exact, c.Sampled = 60, 60, true, 60 }),
			"60 of 60 (100%) · on 60 rows · every value of this kind on production was sampled"},
		{"all could be chance", mk(phone, func(c *model.LeakColumn) { c.Found, c.Rows, c.ChanceMatches = 30, 30, 30 }),
			"30 of 3,000 · on 30 rows · all of these could be chance, if a masking tool makes up realistic numbers; if no tool made them, they're real"},
		{"some could be chance", mk(phone, func(c *model.LeakColumn) { c.Found, c.Rows, c.ChanceMatches, c.EstimateInAll = 900, 900, 30, 30000 }),
			"900 of 3,000 (30%) · on 900 rows · roughly 30,000 values in all · up to about 30 of these could be chance, if a masking tool makes up realistic numbers"},
		{"hits read in part", mk(email, func(c *model.LeakColumn) { c.Found, c.Rows, c.State = 40, 40, model.LeakStopped }),
			"40 of 3,000 (1%) · on 40 rows · at least 40 · read in part"},
		{"exact, read in part", mk(email, func(c *model.LeakColumn) { c.Found, c.Rows, c.State, c.Exact = 40, 40, model.LeakStopped, true }),
			"40 of 3,000 (1%) · on 40 rows · at least 40 · read in part"},
		{"exact zero", mk(email, func(c *model.LeakColumn) { c.Exact, c.Values = true, 40 }),
			"0 of 3,000: every value of this kind on production was sampled"},
		{"no values", mk(email, func(c *model.LeakColumn) { c.Values, c.ShownAt95 = 0, 98 }),
			"0 of 3,000: no values of this kind in what was read"},
		{"no odds", mk(email, func(c *model.LeakColumn) { c.Values = 100 }),
			"0 of 3,000, from part of the table only: a copy of other rows reads as zero"},
		{"small staging", mk(email, func(c *model.LeakColumn) { c.Values, c.ShownAt95, c.CatchIfAllReal = 5, 98, 0.141 }),
			"0 of 3,000: even if all 5 values here were real, this would catch it about 14% of the time"},
		{"big staging", mk(email, func(c *model.LeakColumn) { c.Values, c.ShownAt95 = 100000, 98.4 }),
			"0 of 3,000: about 98 real values would show 95% of the time; fewer may not"},
		{"stopped zero", mk(email, func(c *model.LeakColumn) {
			c.State, c.StoppedBy, c.Values, c.RowsRead, c.RowsEstimate = model.LeakStopped, "--max-time", 100, 5000, 41000
		}), "stopped by --max-time after 5,000 of ~41,000 rows"},
		{"not on staging", mk(email, func(c *model.LeakColumn) { c.State = model.LeakNotOnStaging }), "not on staging"},
		{"not read", mk(email, func(c *model.LeakColumn) { c.State = model.LeakNotRead }), "not read: --max-time came first"},
		{"unreadable", mk(email, func(c *model.LeakColumn) { c.State = model.LeakUnreadable }), "can't be read on staging: a view, or now binary"},
		{"allowed away", mk(email, func(c *model.LeakColumn) { c.Values, c.ValuesSkipped, c.ShownAt95 = 0, 40, 98 }),
			"0 of 3,000: every value of this kind here was skipped by --allow-email"},
		{"chance, read in part", mk(phone, func(c *model.LeakColumn) { c.Found, c.Rows, c.ChanceMatches, c.State = 3, 3, 30, model.LeakStopped }),
			"3 of 3,000 · on 3 rows · all of these could be chance, if a masking tool makes up realistic numbers; if no tool made them, they're real · read in part"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
}

func TestLeakStoppedLine(t *testing.T) {
	c := model.LeakColumn{RowsRead: 5000, RowsEstimate: 41000}
	cases := map[string]string{
		"--max-time":       "stopped by --max-time after 5,000 of ~41,000 rows",
		"timed out":        "stopped after 5,000 of ~41,000 rows (timed out); a longer --timeout may read more",
		"MySQL error 1146": "stopped after 5,000 of ~41,000 rows (MySQL error 1146)",
	}
	for by, want := range cases {
		c.StoppedBy = by
		if got := stoppedLine(c); got != want {
			t.Errorf("%s: %q", by, got)
		}
	}
}

func TestLeakReportWarnsOfNotReadAndExcepted(t *testing.T) {
	res := leakFixture()
	res.Columns = []model.LeakColumn{
		spreadColumn(model.LeakColumn{Table: "a", Column: "x", Kind: model.LeakEmail, Sampled: 10, Found: 2, Rows: 2, Excepted: true}),
		spreadColumn(model.LeakColumn{Table: "a", Column: "y", Kind: model.LeakEmail, Sampled: 10, Values: 1, Excepted: true}),
		spreadColumn(model.LeakColumn{Table: "b", Column: "x", Kind: model.LeakEmail, Sampled: 10, State: model.LeakNotOnStaging, Excepted: true}),
		spreadColumn(model.LeakColumn{Table: "c", Column: "x", Kind: model.LeakEmail, Sampled: 10, State: model.LeakUnreadable}),
		spreadColumn(model.LeakColumn{Table: "d", Column: "x", Kind: model.LeakEmail, Sampled: 10, State: model.LeakNotRead}),
		spreadColumn(model.LeakColumn{Table: "e", Column: "x", Kind: model.LeakEmail, Sampled: 10, State: model.LeakStopped, StoppedBy: "timed out", Found: 1, Rows: 1, RowsRead: 9}),
	}
	res.LeftOut = []model.LeakLeftOut{{Location: "big_table", Why: "could not be sampled", NotRead: true}}
	res.Warnings = []string{"--fail-except value 1 matches no column in the hash file"}
	res.Summary = model.LeakSummary{Columns: 6, ColumnsRead: 2, ColumnsWithHit: 1, Sampled: 20, Found: 2, FoundInPart: 1, RowsRead: 100}
	var b bytes.Buffer
	if err := LeakText(&b, res, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"2 of 20 sampled values found, in 1 of the 2 columns read.",
		"And 1 more in columns read only in part.",
		"a.x", "(excepted from --fail-on)",
		"not on staging (excepted from --fail-on)",
		"can't be read on staging: a view, or now binary",
		"not read: --max-time came first",
		"stopped after 9 rows (timed out); a longer --timeout may read more",
		"1 of 10 (10%) · on 1 row · at least 1 · read in part",
		"big_table  could not be sampled on production",
		"! --fail-except value 1 matches no column",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("no %q in:\n%s", want, b.String())
		}
	}
}

func TestLeakJSON(t *testing.T) {
	res := leakFixture()
	res.Columns = []model.LeakColumn{spreadColumn(model.LeakColumn{Table: "users", Column: "email", Kind: model.LeakEmail, Sampled: 3000, Found: 5, Rows: 5})}
	res.Summary = model.LeakSummary{Columns: 1, ColumnsRead: 1, Sampled: 3000, Found: 5, Highest: model.SeverityHigh}
	var b bytes.Buffer
	if err := LeakJSON(&b, res); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Limits  []string
		Summary struct {
			Highest string `json:"highest_severity"`
		}
		Columns []struct {
			Line     string
			Severity string
			Kind     string
		}
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Limits) != 4 || !strings.Contains(got.Limits[0], "A zero is not proof") {
		t.Errorf("limits: %q", got.Limits)
	}
	if len(got.Columns) != 1 || got.Columns[0].Line == "" || got.Columns[0].Severity != "high" || got.Columns[0].Kind != "email" {
		t.Errorf("columns: %+v", got.Columns)
	}
	if got.Summary.Highest != "high" {
		t.Errorf("summary: %+v", got.Summary)
	}
	if strings.Contains(b.String(), "prodmask.com") {
		t.Error("the JSON report has no footer link")
	}
}
