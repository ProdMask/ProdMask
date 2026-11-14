package leak

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
	"github.com/ProdMask/ProdMask/pkg/dbconn"
	"github.com/ProdMask/ProdMask/pkg/fixture"
	"github.com/ProdMask/ProdMask/pkg/model"
	"github.com/ProdMask/ProdMask/pkg/report"
)

// testServer connects to the server in PRODMASK_TEST_DSN as a user that can
// create databases, or testdb.DSN skips or fails the test.
func testServer(t *testing.T) (*sql.DB, *mysql.Config) {
	t.Helper()
	dsn := testdb.DSN(t)
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("PRODMASK_TEST_DSN doesn't parse")
	}
	cfg.MultiStatements = true
	cfg.DBName = ""
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	t.Cleanup(func() { admin.Close() })
	return admin, cfg
}

func openSession(ctx context.Context, t *testing.T, cfg *mysql.Config, database string) *dbconn.Session {
	t.Helper()
	c := cfg.Clone()
	c.MultiStatements = false
	c.DBName = database
	sess, err := dbconn.Open(ctx, c, 30*time.Second)
	if err != nil {
		t.Fatalf("open %s: %v", database, err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func testKey(t *testing.T) Key {
	t.Helper()
	k, err := ParseKey([]byte(hex.EncodeToString(bytes.Repeat([]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}, 4))))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func exec(ctx context.Context, t *testing.T, admin *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := admin.ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("statement failed: %v", err)
	}
}

// emptyDB drops and creates a database, and drops it after the test.
func emptyDB(ctx context.Context, t *testing.T, admin *sql.DB, name string) string {
	t.Helper()
	exec(ctx, t, admin, "DROP DATABASE IF EXISTS `"+name+"`")
	exec(ctx, t, admin, "CREATE DATABASE `"+name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
	t.Cleanup(func() {
		admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS `"+name+"`")
	})
	return name
}

// fixturePair builds a platform's fixture twice: the same seed, so the second
// is a full real copy of the first.
func fixturePair(ctx context.Context, t *testing.T, admin *sql.DB, platform string) (prod, staging string) {
	t.Helper()
	prod, staging = "prodmask_fixture_leak_"+platform+"_prod", "prodmask_fixture_leak_"+platform+"_stag"
	for _, db := range []string{prod, staging} {
		if err := fixture.Build(ctx, admin, platform, db, fixture.Options{}); err != nil {
			t.Fatalf("build %s: %v", db, err)
		}
		t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS `"+db+"`") })
	}
	return prod, staging
}

func hashDB(ctx context.Context, t *testing.T, cfg *mysql.Config, db string, key Key, opts HashOptions) *File {
	t.Helper()
	if opts.Preset == "" {
		opts.Preset = "auto"
	}
	opts.Version = "test"
	sess := openSession(ctx, t, cfg, db)
	f, _, err := Hash(ctx, sess, key, opts)
	if err != nil {
		t.Fatalf("hash %s: %v", db, err)
	}
	return f
}

func compareDB(ctx context.Context, t *testing.T, cfg *mysql.Config, db string, f *File, key Key, opts CompareOptions) *model.LeakResult {
	t.Helper()
	opts.Version = "test"
	sess := openSession(ctx, t, cfg, db)
	res, err := Compare(ctx, sess, f, key, opts)
	if err != nil {
		t.Fatalf("compare %s: %v", db, err)
	}
	return res
}

func columnOf(t *testing.T, res *model.LeakResult, loc string, kind model.LeakKind) model.LeakColumn {
	t.Helper()
	for _, c := range res.Columns {
		if c.Location() == loc && c.Kind == kind {
			return c
		}
	}
	t.Fatalf("no %s column at %s", kind, loc)
	return model.LeakColumn{}
}

func TestFullCopyOfEveryFixture(t *testing.T) {
	admin, cfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	key := testKey(t)
	for _, platform := range fixture.Platforms {
		t.Run(platform, func(t *testing.T) {
			prod, staging := fixturePair(ctx, t, admin, platform)
			f := hashDB(ctx, t, cfg, prod, key, HashOptions{})
			res := compareDB(ctx, t, cfg, staging, f, key, CompareOptions{})
			if testing.Verbose() {
				var b bytes.Buffer
				report.LeakText(&b, res, false)
				t.Log("\n" + b.String())
			}
			kinds := map[model.LeakKind]bool{}
			for _, c := range res.Columns {
				kinds[c.Kind] = true
				if c.State != model.LeakRead {
					t.Errorf("%s (%s): state %s", c.Location(), c.Kind, c.State)
				}
				if c.Found != c.Sampled {
					t.Errorf("%s (%s): found %d of %d on a full copy", c.Location(), c.Kind, c.Found, c.Sampled)
				}
			}
			if !kinds[model.LeakEmail] || !kinds[model.LeakSecret] {
				t.Errorf("kinds found: %v", kinds)
			}
			if res.Summary.Found != res.Summary.Sampled || res.Summary.Found == 0 {
				t.Errorf("summary: %+v", res.Summary)
			}
			if hits, unchecked := Gate(res, model.SeverityHigh); hits == 0 || unchecked != 0 {
				t.Errorf("gate: %d hits, %d unchecked", hits, unchecked)
			}
		})
	}
}
