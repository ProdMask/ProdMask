package login

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/ProdMask/ProdMask/internal/testdb"
	"github.com/ProdMask/ProdMask/pkg/model"
)

const fixtureDB = "prodmask_fixture_login"

// fixture recreates prodmask_fixture_login with a table, views, functions
// and a trigger, and returns the server's admin connection, its config and
// whether it's MariaDB.
func fixture(ctx context.Context, t *testing.T) (*sql.DB, *mysql.Config, bool) {
	t.Helper()
	cfg, err := mysql.ParseDSN(testdb.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName = ""
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := sql.OpenDB(connector)
	t.Cleanup(func() { admin.Close() })
	var version string
	if err := admin.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	run(ctx, t, admin,
		"DROP DATABASE IF EXISTS "+fixtureDB,
		"CREATE DATABASE "+fixtureDB,
		"CREATE TABLE "+fixtureDB+".t (id INT PRIMARY KEY)",
		"CREATE SQL SECURITY DEFINER VIEW "+fixtureDB+".v_def AS SELECT id FROM "+fixtureDB+".t",
		"CREATE SQL SECURITY INVOKER VIEW "+fixtureDB+".v_inv AS SELECT id FROM "+fixtureDB+".t",
		"CREATE FUNCTION "+fixtureDB+".f_def() RETURNS INT DETERMINISTIC NO SQL RETURN 1",
		"CREATE FUNCTION "+fixtureDB+".f_inv() RETURNS INT DETERMINISTIC NO SQL SQL SECURITY INVOKER RETURN 1",
		"CREATE TRIGGER "+fixtureDB+".tr BEFORE INSERT ON "+fixtureDB+".t FOR EACH ROW SET NEW.id = NEW.id")
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+fixtureDB) })
	return admin, cfg, strings.Contains(strings.ToLower(version), "mariadb")
}

// run runs each statement, and fails the test on an error, naming the
// statement up to any password.
func run(ctx context.Context, t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := db.ExecContext(ctx, q); err != nil {
			q, _, _ = strings.Cut(q, " IDENTIFIED")
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// connect opens the fixture database as the account.
func connect(t *testing.T, cfg *mysql.Config, user, password string) *sql.DB {
	t.Helper()
	cfg = cfg.Clone()
	cfg.User, cfg.Passwd, cfg.DBName = user, password, fixtureDB
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { db.Close() })
	return db
}

func randomPassword(t *testing.T) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "Pm1-" + hex.EncodeToString(b)
}

// TestReadLogins reads real accounts' privileges on the test server: one
// that can only read is served, and each that can write, drop, reach files
// or administer the server is refused with that reason, its default role's
// privileges included. Nothing read holds the account's password or, on
// MariaDB, which prints it in SHOW GRANTS, its hash.
func TestReadLogins(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, cfg, mariadb := fixture(ctx, t)
	password := randomPassword(t)
	roles := []string{"pm_role_writer", "pm_role_idle"}
	for _, r := range roles {
		admin.ExecContext(ctx, "DROP ROLE IF EXISTS '"+r+"'")
		t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP ROLE IF EXISTS '"+r+"'") })
	}
	run(ctx, t, admin,
		"CREATE ROLE 'pm_role_writer'",
		"CREATE ROLE 'pm_role_idle'",
		"GRANT INSERT ON "+fixtureDB+".* TO 'pm_role_writer'",
		"GRANT UPDATE ON "+fixtureDB+".* TO 'pm_role_idle'")
	setDefault := "SET DEFAULT ROLE 'pm_role_writer' TO %s"
	if mariadb {
		setDefault = "SET DEFAULT ROLE 'pm_role_writer' FOR %s"
	}
	cases := []struct {
		user   string
		grants []string // %s is the account
		reason string   // in the refusal; "" for a login that is served
		check  func(t *testing.T, l *model.Login)
	}{
		{"pm_login_read", []string{"GRANT SELECT, SHOW VIEW, EXECUTE ON " + fixtureDB + ".* TO %s"}, "", func(t *testing.T, l *model.Login) {
			if l.CanWrite() {
				t.Errorf("a login that can only read is refused: %+v", l)
			}
			want := []model.LoginRoute{{Kind: "view", Name: "v_def", DefinerRights: true}, {Kind: "function", Name: "f_def", DefinerRights: true}}
			for _, w := range want {
				found := false
				for _, r := range l.Routes {
					found = found || r == w
				}
				if !found {
					t.Errorf("the definer's-rights %s %s isn't listed: %+v", w.Kind, w.Name, l.Routes)
				}
			}
			for _, r := range l.Routes {
				if strings.HasSuffix(r.Name, "_inv") {
					t.Errorf("the invoker's-rights %s %s is listed", r.Kind, r.Name)
				}
			}
		}},
		{"pm_login_insert", []string{"GRANT SELECT, INSERT ON " + fixtureDB + ".* TO %s"}, "it can change `" + fixtureDB + "` (INSERT)", func(t *testing.T, l *model.Login) {
			if !slices.Contains(l.ChangeData, "INSERT") || !l.CanWrite() {
				t.Errorf("INSERT isn't found: %+v", l)
			}
		}},
		{"pm_login_drop", []string{"GRANT SELECT, DROP ON " + fixtureDB + ".* TO %s"}, "it can change `" + fixtureDB + "` (DROP)", func(t *testing.T, l *model.Login) {
			if !slices.Contains(l.Drop, "DROP") || !l.CanWrite() {
				t.Errorf("DROP isn't found: %+v", l)
			}
		}},
		{"pm_login_file", []string{"GRANT FILE ON *.* TO %s", "GRANT SELECT ON " + fixtureDB + ".* TO %s"}, "it holds FILE", func(t *testing.T, l *model.Login) {
			if l.Files != "anywhere" && l.Files != "folder" && l.Files != "off" {
				t.Errorf("FILE's reach is %q: %+v", l.Files, l)
			}
		}},
		{"pm_login_super", []string{"GRANT SUPER ON *.* TO %s", "GRANT SELECT ON " + fixtureDB + ".* TO %s"}, "it can administer the server (SUPER)", func(t *testing.T, l *model.Login) {
			if !slices.Contains(l.Admin, "SUPER") || !l.CanWrite() {
				t.Errorf("SUPER isn't found: %+v", l)
			}
		}},
		{"pm_login_role", []string{"GRANT SELECT ON " + fixtureDB + ".* TO %s", "GRANT 'pm_role_writer' TO %s", setDefault}, "it can change `" + fixtureDB + "` (INSERT)", func(t *testing.T, l *model.Login) {
			if !slices.Contains(l.ChangeData, "INSERT") || !l.CanWrite() || l.RolesNotActive != 0 {
				t.Errorf("the default role's INSERT isn't found: %+v", l)
			}
		}},
		{"pm_login_idle", []string{"GRANT SELECT ON " + fixtureDB + ".* TO %s", "GRANT 'pm_role_idle' TO %s"}, "", func(t *testing.T, l *model.Login) {
			if l.CanWrite() || l.RolesNotActive != 1 {
				t.Errorf("a role that isn't active: %+v", l)
			}
		}},
		{"pm_login_mysqlw", []string{"GRANT SELECT ON " + fixtureDB + ".* TO %s", "GRANT INSERT ON mysql.* TO %s"}, "it can administer the server (INSERT on the mysql schema)", func(t *testing.T, l *model.Login) {
			if !slices.Contains(l.Admin, "INSERT on the mysql schema") || len(l.ChangeData) > 0 {
				t.Errorf("INSERT on the mysql schema: %+v", l)
			}
		}},
		{"pm_login_radmin", []string{"GRANT SELECT ON " + fixtureDB + ".* TO %s", "GRANT 'pm_role_idle' TO %s WITH ADMIN OPTION"}, "it can administer the server (ADMIN OPTION on a role)", func(t *testing.T, l *model.Login) {
			if !slices.Contains(l.Admin, "ADMIN OPTION on a role") {
				t.Errorf("a role's ADMIN OPTION: %+v", l)
			}
		}},
	}
	hash := regexp.MustCompile(`\*[0-9A-Fa-f]{40}`)
	for _, c := range cases {
		account := "'" + c.user + "'@'%'"
		admin.ExecContext(ctx, "DROP USER IF EXISTS "+account)
		t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP USER IF EXISTS "+account) })
		run(ctx, t, admin, "CREATE USER "+account+" IDENTIFIED BY '"+password+"'")
		for _, g := range c.grants {
			run(ctx, t, admin, fmt.Sprintf(g, account))
		}
		l := Read(ctx, connect(t, cfg, c.user, password), fixtureDB)
		if len(l.NotRead) > 0 {
			t.Errorf("%s: not read: %v", c.user, l.NotRead)
		}
		c.check(t, l)
		why := Refusal(l, fixtureDB)
		switch {
		case c.reason == "" && why != "":
			t.Errorf("%s is refused: %s", c.user, why)
		case c.reason != "" && !strings.Contains(why, c.reason):
			t.Errorf("%s: the refusal %q doesn't say %q", c.user, why, c.reason)
		case strings.Contains(why, "allow-write"):
			t.Errorf("%s: the refusal names the flag: %s", c.user, why)
		case hash.MatchString(why) || strings.Contains(why, password):
			t.Errorf("%s: the refusal holds the account's password or its hash", c.user)
		}
		if Serves(l, false, false) != (c.reason == "") || !Serves(l, true, false) || !Serves(l, false, true) {
			t.Errorf("%s: served %v as it is, %v with --allow-write-login, %v as a checked copy", c.user,
				Serves(l, false, false), Serves(l, true, false), Serves(l, false, true))
		}
		out, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		text := string(out) + fmt.Sprintf("%+v", *l)
		if hash.MatchString(text) || strings.Contains(text, password) || strings.Contains(strings.ToUpper(text), "IDENTIFIED") {
			t.Errorf("%s: what the login check read holds the account's password or its hash", c.user)
		}
	}
}

// TestReadMarker reads _prodmask tables of each shape through a login that
// can only read: only Pro's one complete row, with a masking key and Pro's
// comment, holds.
func TestReadMarker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, cfg, _ := fixture(ctx, t)
	password := randomPassword(t)
	account := "'pm_login_marker'@'%'"
	admin.ExecContext(ctx, "DROP USER IF EXISTS "+account)
	t.Cleanup(func() { admin.ExecContext(context.Background(), "DROP USER IF EXISTS "+account) })
	run(ctx, t, admin, "CREATE USER "+account+" IDENTIFIED BY '"+password+"'",
		"GRANT SELECT ON "+fixtureDB+".* TO "+account)
	reader := connect(t, cfg, "pm_login_marker", password)

	// Pro's own DDL for the marker (Pro internal/copy/target.go, markerDDL).
	columns := "`run_id` varchar(12) NOT NULL, `state` varchar(16) NOT NULL, `form` varchar(16) NOT NULL, " +
		"`target` varchar(64) NOT NULL, `masking` varchar(16) NOT NULL, `liveness` varchar(8) NOT NULL, " +
		"`tool` varchar(100) NOT NULL, `started_at` datetime(6) NOT NULL, `finished_at` datetime(6) DEFAULT NULL, " +
		"PRIMARY KEY (`run_id`)"
	comment := "prodmask: this database is a prodmask copy, which prodmask may replace"
	table := func(cols, comment string) string {
		return "CREATE TABLE " + fixtureDB + "._prodmask (" + cols + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='" + comment + "'"
	}
	row := func(runID, state, masking string) string {
		return "INSERT INTO " + fixtureDB + "._prodmask VALUES ('" + runID + "', '" + state + "', 'database', 'shop_copy', '" +
			masking + "', 'off', 'prodmask Pro 1.0.0', '2026-11-18 10:00:00.123456', '2026-11-18 10:05:00.654321')"
	}
	cases := []struct {
		name         string
		setup        []string
		found, holds bool
		words        string
	}{
		{"none", nil, false, false, "no prodmask copy marker"},
		{"holds", []string{table(columns, comment), row("abcdefgh2345", "complete", "stable")}, true, true,
			"masked with a stable key, made by prodmask Pro 1.0.0 on 2026-11-18 10:05:00 UTC."},
		{"per run", []string{table(columns, comment), row("abcdefgh2345", "complete", "per-run")}, true, true,
			"masked with a key for this run only"},
		{"incomplete", []string{table(columns, comment), row("abcdefgh2345", "incomplete", "stable")}, true, false, "isn't complete"},
		{"no masking", []string{table(columns, comment), row("abcdefgh2345", "complete", "none")}, true, false, "made with no masking"},
		{"a masking it doesn't know", []string{table(columns, comment), row("abcdefgh2345", "complete", "fpe")}, true, false, "couldn't be read"},
		{"two rows", []string{table(columns, comment), row("abcdefgh2345", "complete", "stable"), row("bcdefgh23456", "complete", "stable")},
			true, false, "couldn't be read"},
		{"another run id", []string{table(columns, comment), row("ABCDEFGH2345", "complete", "stable")}, true, false, "couldn't be read"},
		{"no comment", []string{table(columns, ""), row("abcdefgh2345", "complete", "stable")}, true, false, "couldn't be read"},
		{"other columns", []string{table("`run_id` varchar(12) NOT NULL, `state` varchar(16) NOT NULL", comment),
			"INSERT INTO " + fixtureDB + "._prodmask VALUES ('abcdefgh2345', 'complete')"}, true, false, "couldn't be read"},
	}
	for _, c := range cases {
		run(ctx, t, admin, append([]string{"DROP TABLE IF EXISTS " + fixtureDB + "._prodmask"}, c.setup...)...)
		m := ReadMarker(ctx, reader, fixtureDB)
		if m.Found != c.found || m.Holds != c.holds || !strings.Contains(m.Words(), c.words) {
			t.Errorf("%s: found %v, holds %v, %q; want %v, %v, %q", c.name, m.Found, m.Holds, m.Words(), c.found, c.holds, c.words)
		}
		if strings.Contains(m.Words(), "abcdefgh2345") {
			t.Errorf("%s: the words show the run id", c.name)
		}
	}
}
