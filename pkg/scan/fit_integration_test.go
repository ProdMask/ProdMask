package scan_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestStarterFits scans tables shaped like the ones that stopped prodmask
// Pro's plan on old databases, under made-up names, and checks what the
// starter writes for them: hash, with a note that says why, where a fake
// can't fit its column or keeps too few values apart in a unique one; and
// the line commented out, leaving the rule to Pro, where a unique column is
// too short for any rule. The categories stay as the scan found them.
func TestStarterFits(t *testing.T) {
	admin, adminCfg := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	const database = "prodmask_fixture_fits"
	q := "`" + database + "`."
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.%d"
	var agents []string
	for i := range 6 {
		agents = append(agents, "('"+fmt.Sprintf(ua, i)+"')")
	}
	for _, s := range []string{
		"DROP DATABASE IF EXISTS `" + database + "`",
		"CREATE DATABASE `" + database + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		"CREATE TABLE " + q + "fraud_rules (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, rule_email char(1) NULL, " +
			"rule_amount char(1) NULL) ENGINE=InnoDB",
		"CREATE TABLE " + q + "brokers (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, user_agent varchar(255) NOT NULL, " +
			"UNIQUE KEY user_agent (user_agent)) ENGINE=InnoDB",
		"INSERT INTO " + q + "brokers (user_agent) VALUES " + strings.Join(agents, ", "),
		"CREATE TABLE " + q + "towns (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, city varchar(50) NOT NULL, " +
			"UNIQUE KEY city (city)) ENGINE=InnoDB",
		"INSERT INTO " + q + "towns (city) VALUES ('Springfield'), ('Riverton'), ('Lakeside'), ('Fairview'), ('Oakdale')",
		"CREATE TABLE " + q + "branches (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, city char(2) NOT NULL, " +
			"UNIQUE KEY city (city)) ENGINE=InnoDB",
		"INSERT INTO " + q + "branches (city) VALUES ('SP'), ('RV'), ('LK')",
		"CREATE TABLE " + q + "partners (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, api_key char(2) NOT NULL, " +
			"UNIQUE KEY api_key (api_key)) ENGINE=InnoDB",
		"INSERT INTO " + q + "partners (api_key) VALUES ('k1'), ('k2')",
		"CREATE TABLE " + q + "contacts (id int NOT NULL AUTO_INCREMENT PRIMARY KEY, email varchar(255) NOT NULL, " +
			"UNIQUE KEY email (email(10))) ENGINE=InnoDB",
		"INSERT INTO " + q + "contacts (email) VALUES ('ann@shop.example'), ('bob@shop.example'), ('cy@shop.example')",
	} {
		if _, err := admin.ExecContext(ctx, s); err != nil {
			t.Fatalf("build the tables: %v", err)
		}
	}

	res := runScan(ctx, t, openScan(ctx, t, adminCfg, database), "generic")
	outputs := render(t, res)
	var report struct {
		Findings []struct {
			Table, Column, Path, Note, Category string
			MetaKey                             string `json:"meta_key"`
			Mask                                string `json:"suggested_mask"`
		}
	}
	if err := json.Unmarshal([]byte(outputs["json"]), &report); err != nil {
		t.Fatal(err)
	}
	const leave = "leave this line commented"
	for _, c := range []struct{ table, column, category, note string }{
		{"fraud_rules", "rule_email", "email", "hash, not fake_email, since the column holds 1 character and fake_email needs 13"},
		{"brokers", "user_agent", "user_agent", "hash, not fake_user_agent, since this unique column needs more different values than fake_user_agent makes"},
		{"towns", "city", "city", "hash, not fake_city, since this unique column needs more different values than fake_city makes"},
		{"branches", "city", "city", "hash, not fake_city, since the column holds 2 characters and fake_city needs 4"},
		{"partners", "api_key", "secret", "since null would give every row of this NOT NULL unique column the same value"},
		{"contacts", "email", "email", "hash, not fake_email, since this unique column needs more different values than fake_email makes"},
	} {
		found := 0
		for _, f := range report.Findings {
			if f.Table != c.table || f.Column != c.column || f.MetaKey != "" || f.Path != "" {
				continue
			}
			found++
			// The commented line's words are the starter config's: the reports don't carry them.
			if f.Mask != "hash" || f.Category != c.category || !strings.Contains(f.Note, c.note) || strings.Contains(f.Note, leave) {
				t.Errorf("%s.%s: %s %s, note %q; want hash, %s, and a note with %q", c.table, c.column, f.Category, f.Mask, f.Note, c.category, c.note)
			}
		}
		if found != 1 {
			t.Errorf("the JSON report has %d findings for %s.%s", found, c.table, c.column)
		}
	}

	yml := outputs["yml"]
	for _, want := range []string{
		"\n  branches:\n    columns:\n      # city: hash  # ",
		"\n  partners:\n    columns:\n      # api_key: hash  # ",
		"\n  towns:\n    columns:\n      city: hash  # ",
		"\n  brokers:\n    columns:\n      user_agent: hash  # ",
	} {
		if !strings.Contains(yml, want) {
			t.Errorf("the starter config is missing %q:\n%s", want, yml)
		}
	}
	for _, line := range strings.Split(yml, "\n") {
		commented := strings.HasPrefix(strings.TrimSpace(line), "# city: hash") || strings.HasPrefix(strings.TrimSpace(line), "# api_key: hash")
		if commented != strings.HasSuffix(line, leave) {
			t.Errorf("a line of the starter config, commented %v, ends otherwise: %q", commented, line)
		}
	}
	checkConfigTables(t, yml)
}
