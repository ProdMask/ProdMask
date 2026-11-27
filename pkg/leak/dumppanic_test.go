package leak

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/sqldump"
)

// A fault after the read becomes the reader's fixed error, with the line of
// the last row and nothing from the file.
func TestCompareDumpPanicIsAFixedError(t *testing.T) {
	key := testKey(t)
	f := hashFile(t, key, email("users", "email", mailA))
	sql := dumpTop + usersTable + "INSERT INTO `users` VALUES (1,'" + mailA + "');\n"
	res, err := CompareDump(context.Background(), strings.NewReader(sql), f, key, CompareDumpOptions{panicAfterRead: true})
	var pe *sqldump.PanicError
	if res != nil || !errors.As(err, &pe) || pe.Line == 0 {
		t.Fatalf("result %v, error %v", res, err)
	}
	if strings.Contains(err.Error(), "test panic") || strings.Contains(err.Error(), "alice") {
		t.Fatalf("the error holds a value: %v", err)
	}
}

func TestHashDumpPanicIsAFixedError(t *testing.T) {
	text := prodHead + tableOf("people") + mailRows("people", 1, 5)
	f, warns, err := hashDump(t, text, HashDumpOptions{panicAfterRead: true})
	var pe *sqldump.PanicError
	if f != nil || warns != nil || !errors.As(err, &pe) || pe.Line == 0 {
		t.Fatalf("file %v, error %v", f, err)
	}
	if strings.Contains(err.Error(), "test panic") || strings.Contains(err.Error(), "person.") {
		t.Fatalf("the error holds a value: %v", err)
	}
}
