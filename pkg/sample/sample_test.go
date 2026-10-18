package sample

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// Short binary columns are read, as hex, only when Hex picks them; other
// binary columns, such as a UUID or a hashed IP, are never read.
func TestSelectListHex(t *testing.T) {
	tbl := &model.Table{Name: "mybb_users", Columns: []*model.Column{
		{Name: "uid", DataType: "int"},
		{Name: "regip", DataType: "varbinary", MaxLength: 16},
		{Name: "device_uuid", DataType: "binary", MaxLength: 16},
		{Name: "ip_hash", DataType: "binary", MaxLength: 16},
		{Name: "avatar", DataType: "blob", MaxLength: 65535},
		{Name: "username", DataType: "varchar", MaxLength: 120},
	}}
	sm := &Sampler{MaxValueLen: 4096}
	s, exprs := sm.selectList(tbl)
	if want := []string{"`uid`", "LEFT(`username`, 4096)"}; !reflect.DeepEqual(exprs, want) {
		t.Errorf("without Hex: %q, want %q", exprs, want)
	}
	if len(s.Hex) != len(s.Columns) {
		t.Fatalf("%d hex marks for %d columns", len(s.Hex), len(s.Columns))
	}
	sm.Hex = func(_ *model.Table, c *model.Column) bool { return c.Name == "regip" || c.Name == "avatar" }
	s, exprs = sm.selectList(tbl)
	if want := []string{"`uid`", "HEX(`regip`)", "LEFT(`username`, 4096)"}; !reflect.DeepEqual(exprs, want) {
		t.Errorf("with Hex: %q, want %q", exprs, want)
	}
	if want := []bool{false, true, false}; !reflect.DeepEqual(s.Hex, want) {
		t.Errorf("hex marks %v, want %v", s.Hex, want)
	}
	if strings.Contains(strings.Join(exprs, ","), "uuid") || strings.Contains(strings.Join(exprs, ","), "ip_hash") {
		t.Errorf("a binary column Hex didn't pick was read: %q", exprs)
	}
}
