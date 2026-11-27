package leak

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/model"
)

// TestHashDumpOfFixture: a dump of the wordpress fixture is hashed, and the
// same dump compared finds every sampled value. A masked copy of it, as a dump,
// gives the counts the masking leaves.
func TestHashDumpOfFixture(t *testing.T) {
	admin, _ := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	key := testKey(t)
	const prod, stag = "prodmask_s9_prod", "prodmask_s9_stag"
	for _, db := range []string{prod, stag} {
		if err := fixture.Build(ctx, admin, "wordpress", db, fixture.Options{}); err != nil {
			t.Fatalf("build %s: %v", db, err)
		}
		t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS `"+db+"`") })
	}
	prodDump := dumpOf(ctx, t, admin, prod)
	f, _, err := HashDump(ctx, openOf(prodDump), key, HashDumpOptions{Preset: "auto", Version: "test", File: "prod.sql"})
	if err != nil {
		t.Fatalf("HashDump: %v", err)
	}
	if len(f.Columns) < 3 || f.Database != prod {
		t.Fatalf("%d columns in the hash file, database %q", len(f.Columns), f.Database)
	}

	// The same dump finds every sampled value.
	res, err := CompareDump(ctx, strings.NewReader(prodDump), f, key, CompareDumpOptions{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	keyed := 0
	for _, c := range res.Columns {
		if c.State != model.LeakRead || c.Found != c.Sampled || c.Sampled == 0 {
			t.Errorf("%s: %s, found %d of %d", c.Location(), c.State, c.Found, c.Sampled)
		}
		if c.Sample == model.SampleAllRows && !c.Exact {
			t.Errorf("%s: all rows, not exact", c.Location())
		}
		if strings.Contains(c.Location(), "[") {
			keyed++
		}
	}
	if keyed == 0 {
		t.Errorf("no key of a key/value table in the file: %d columns", len(res.Columns))
	}
	if res.Dump.Unread != 0 {
		t.Errorf("%d statements unread: %+v", res.Dump.Unread, res.Dump.UnreadList)
	}

	// The masking: half the users' addresses are replaced and every billing
	// phone is.
	exec(ctx, t, admin, "UPDATE `"+stag+"`.wp_users SET user_email = CONCAT('user.', ID, '@elsewhere.prodmask-fixture.dev') WHERE ID MOD 2 = 0")
	exec(ctx, t, admin, "UPDATE `"+stag+"`.wp_usermeta SET meta_value = CONCAT('+1 202 555 ', LPAD(umeta_id MOD 10000, 4, '0')) WHERE meta_key = 'billing_phone'")
	var users, kept int
	if err := admin.QueryRowContext(ctx, "SELECT COUNT(*), SUM(ID MOD 2 = 1) FROM `"+stag+"`.wp_users").Scan(&users, &kept); err != nil {
		t.Fatal(err)
	}
	if users > DefaultSampleRows || kept == 0 || kept == users {
		t.Fatalf("%d users, %d kept: the fixture can't test the masking", users, kept)
	}
	res, err = CompareDump(ctx, strings.NewReader(dumpOf(ctx, t, admin, stag)), f, key, CompareDumpOptions{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	mail := columnOf(t, res, "wp_users.user_email", model.LeakEmail)
	if mail.State != model.LeakRead || mail.Sampled != users || mail.Found != kept {
		t.Errorf("wp_users.user_email: %s, found %d of %d, want %d of %d", mail.State, mail.Found, mail.Sampled, kept, users)
	}
	for _, c := range res.Columns {
		if c.State == model.LeakRead && strings.HasSuffix(c.Location(), "[billing_phone]") && c.Found != 0 {
			t.Errorf("%s: found %d after masking", c.Location(), c.Found)
		}
	}

	// A statement of a sampled table that wasn't read: its columns are left out
	// as not read, and compare's gate counts them.
	f2, _, err := HashDump(ctx, openOf(prodDump+"INSERT INTO `wp_users` SELECT * FROM `wp_users`;\n"), key,
		HashDumpOptions{Preset: "auto", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	notRead := 0
	for _, l := range f2.LeftOut {
		if l.NotRead && strings.HasPrefix(l.Location, "wp_users") {
			notRead++
			if l.Why != stoppedTableUnread {
				t.Errorf("%s: %q", l.Location, l.Why)
			}
		}
	}
	for _, c := range f2.Columns {
		if c.Table == "wp_users" {
			t.Errorf("wp_users.%s is in the file", c.Column)
		}
	}
	res, err = CompareDump(ctx, strings.NewReader(prodDump), f2, key, CompareDumpOptions{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if hits, unchecked := Gate(res, model.SeverityHigh); notRead == 0 || unchecked < notRead || hits == 0 {
		t.Errorf("%d columns not read: gate %d hits, %d unchecked", notRead, hits, unchecked)
	}
}
