package sqldump

import (
	"strings"
	"testing"
)

func BenchmarkReadInserts(b *testing.B) {
	row := "(1,'alice@example.com','a longer text value with \\'escapes\\' and a newline\\n',NULL,12.5,0x4142),"
	sql := "SET sql_mode='';\nINSERT INTO t VALUES " + strings.Repeat(row, 100000) + "(1,'x',NULL,NULL,1,0x41);\n"
	b.SetBytes(int64(len(sql)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Read(b.Context(), strings.NewReader(sql), nil, testOpts()); err != nil {
			b.Fatal(err)
		}
	}
}
