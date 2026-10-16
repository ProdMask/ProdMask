package dbconn

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseDSN(t *testing.T) {
	cases := []struct {
		in, password                  string
		user, pass, net, addr, dbname string
	}{
		{"mysql://shop:p%40ss@db.internal:3307/shop", "", "shop", "p@ss", "tcp", "db.internal:3307", "shop"},
		{"mysql://ro@db.internal/shop", "fromenv", "ro", "fromenv", "tcp", "db.internal:3306", "shop"},
		{"mariadb://ro:x@[2001:db8::1]:3306/shop", "", "ro", "x", "tcp", "[2001:db8::1]:3306", "shop"},
		{"mysql://root@localhost/wp?socket=/run/mysqld/mysqld.sock", "", "root", "", "unix", "/run/mysqld/mysqld.sock", "wp"},
		{"shop:secret@tcp(10.0.0.5:3306)/shop", "ignored", "shop", "secret", "tcp", "10.0.0.5:3306", "shop"},
		{"ro@tcp(db:3306)/shop?tls=skip-verify", "pw", "ro", "pw", "tcp", "db:3306", "shop"},
	}
	for _, c := range cases {
		cfg, err := ParseDSN(c.in, c.password)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		got := []string{cfg.User, cfg.Passwd, cfg.Net, cfg.Addr, cfg.DBName}
		want := []string{c.user, c.pass, c.net, c.addr, c.dbname}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %q, want %q", c.in, got, want)
		}
	}
}

func TestParseDSNTLS(t *testing.T) {
	cfg, err := ParseDSN("mysql://ro:pw@db.example.net:3306/shop?tls=true", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSConfig != "true" || cfg.TLS != nil {
		t.Errorf("TLS settings: %q %v; want them rebuilt for the real host on connect", cfg.TLSConfig, cfg.TLS)
	}
}

func TestParseDSNErrors(t *testing.T) {
	for _, in := range []string{"", "mysql://ro:pw@db:3306/", "postgres://u@h/db", "mysql://ro:pw@db:notaport/shop"} {
		_, err := ParseDSN(in, "")
		if err == nil {
			t.Errorf("%q: expected an error", in)
			continue
		}
		if strings.Contains(err.Error(), "pw") {
			t.Errorf("%q: error repeats the password: %v", in, err)
		}
	}
}

func TestDescribeHidesPassword(t *testing.T) {
	cfg, _ := ParseDSN("mysql://ro:topsecret@db:3306/shop", "")
	if d := Describe(cfg); d != "ro@db:3306/shop" {
		t.Errorf("Describe = %q", d)
	}
}

func TestWritePrivileges(t *testing.T) {
	grants := []string{
		"GRANT USAGE ON *.* TO `ro`@`%`",
		"GRANT SELECT, SHOW VIEW ON `shop`.* TO `ro`@`%`",
	}
	if got := WritePrivileges(grants, "shop"); len(got) != 0 {
		t.Errorf("read-only user flagged: %v", got)
	}
	grants = []string{
		"GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` IDENTIFIED VIA mysql_native_password USING '*0000' WITH GRANT OPTION",
		"GRANT `app_role` TO `root`@`localhost`",
	}
	if got := WritePrivileges(grants, "shop"); !reflect.DeepEqual(got, []string{"ALL PRIVILEGES"}) {
		t.Errorf("root: %v", got)
	}
	grants = []string{
		"GRANT SELECT, INSERT, UPDATE (status, note) ON `shop\\_%`.* TO `app`@`%`",
		"GRANT DELETE ON `other`.* TO `app`@`%`",
	}
	if got := WritePrivileges(grants, "shop_prod"); !reflect.DeepEqual(got, []string{"INSERT", "UPDATE"}) {
		t.Errorf("wildcard grant: %v", got)
	}
	if got := WritePrivileges(grants, "shopprod"); len(got) != 0 {
		t.Errorf("escaped underscore matched any character: %v", got)
	}
}
