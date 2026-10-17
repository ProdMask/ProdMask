package sample

import (
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// The prefix conditions come first in the statement, so their arguments
// must too, whatever the order of the lookups.
func TestProbeQueryArguments(t *testing.T) {
	key := &model.Column{Name: "option_name", DataType: "varchar"}
	value := &model.Column{Name: "option_value", DataType: "longtext"}
	tbl := &model.Table{Name: "wp_options", PrimaryKey: []string{"option_id"},
		Columns: []*model.Column{{Name: "option_id", DataType: "bigint"}, key, value}}
	lookups := []Lookup{
		{Key: "auth_key", Limit: 1},
		{Key: "secret_key", Limit: 1},
		{Key: "um_cache_userdata_", Prefix: true, Limit: 20},
	}
	q, args := probeQuery(tbl, key, value, lookups, 4096)
	want := "SELECT `option_name`, `option_id` FROM `wp_options` WHERE `option_name` LIKE ? ESCAPE '!' OR `option_name` IN (?, ?)"
	if q != want {
		t.Fatalf("query\n%s\nwant\n%s", q, want)
	}
	if strings.Count(q, "?") != len(args) {
		t.Fatalf("%d placeholders, %d arguments", strings.Count(q, "?"), len(args))
	}
	if args[0] != "um!_cache!_userdata!_%" || args[1] != "auth_key" || args[2] != "secret_key" {
		t.Errorf("arguments %q", args)
	}
	// Without a single primary key, the pass reads the values itself.
	tbl.PrimaryKey = nil
	if q, _ := probeQuery(tbl, key, value, lookups, 4096); !strings.HasPrefix(q, "SELECT `option_name`, '', LEFT(`option_value`, 4096) FROM") {
		t.Errorf("query without a primary key: %s", q)
	}
}
