package sqldump

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.Bytes()
}

func slurp(t *testing.T, rc io.ReadCloser) string {
	t.Helper()
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestOpenPlain(t *testing.T) {
	p := writeFile(t, "d.sql", []byte("DROP TABLE a;"))
	rc, info, err := Open(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := slurp(t, rc); got != "DROP TABLE a;" {
		t.Fatalf("read %q", got)
	}
	fi, _ := os.Stat(p)
	if info.Compression != "" || info.Size != 13 || !info.ModTime.Equal(fi.ModTime()) || info.BytesRead() != 13 {
		t.Fatalf("info = %+v read %d", info, info.BytesRead())
	}
}

func TestOpenGzip(t *testing.T) {
	data := gz(t, "DROP TABLE a;")
	p := writeFile(t, "d.sql.gz", data)
	rc, info, err := Open(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := slurp(t, rc); got != "DROP TABLE a;" {
		t.Fatalf("read %q", got)
	}
	if info.Compression != "gzip" || info.Size != int64(len(data)) || info.BytesRead() != int64(len(data)) {
		t.Fatalf("info = %+v read %d", info, info.BytesRead())
	}
	// the name doesn't matter, the magic bytes do
	p = writeFile(t, "plain.sql", data)
	rc, _, err = Open(p, false)
	if err != nil || slurp(t, rc) != "DROP TABLE a;" {
		t.Fatalf("gzip under a plain name: %v", err)
	}
}

func TestOpenMultiMemberGzip(t *testing.T) {
	data := append(gz(t, "DROP TABLE a;\n"), gz(t, "DROP TABLE b;\n")...)
	data = append(data, gz(t, "DROP TABLE c;\n")...)
	rc, _, err := Open(writeFile(t, "m.gz", data), false)
	if err != nil {
		t.Fatal(err)
	}
	got := slurp(t, rc)
	if got != "DROP TABLE a;\nDROP TABLE b;\nDROP TABLE c;\n" {
		t.Fatalf("read %q", got)
	}
}

func TestOpenCutGzip(t *testing.T) {
	data := gz(t, strings.Repeat("DROP TABLE a;\n", 2000))
	rc, _, err := Open(writeFile(t, "cut.gz", data[:len(data)/2]), false)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Read(t.Context(), rc, nil, testOpts())
	rc.Close()
	if err != ErrRead || count(st, KindDrop) == 0 {
		t.Fatalf("err = %v, drops = %d", err, count(st, KindDrop))
	}
}

func TestOpenBadGzipHeader(t *testing.T) {
	_, _, err := Open(writeFile(t, "bad.gz", []byte{0x1f, 0x8b, 0xff}), false)
	if err != ErrBadGzip {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenRefusedMagic(t *testing.T) {
	tests := []struct {
		name  string
		magic []byte
		err   error
		hint  string
	}{
		{"zstd", []byte{0x28, 0xb5, 0x2f, 0xfd, 1, 2}, ErrZstd, "zstd -d"},
		{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00, 1}, ErrXZ, "xz -d"},
		{"bzip2", []byte("BZh91AY"), ErrBzip2, "bzip2 -d"},
		{"zip", []byte{'P', 'K', 3, 4, 1}, ErrZip, "unzip"},
		{"7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0}, Err7z, "7z x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, "secretname-"+tc.name+".sql", tc.magic)
			_, _, err := Open(p, false)
			if err != tc.err {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if !strings.Contains(err.Error(), tc.hint) || !strings.Contains(err.Error(), "first") {
				t.Fatalf("the error doesn't say how to decompress: %q", err)
			}
			if strings.Contains(err.Error(), "secretname") || strings.Contains(err.Error(), filepath.Dir(p)) {
				t.Fatalf("the error holds the path: %q", err)
			}
		})
	}
}

func TestOpenBOM(t *testing.T) {
	rc, _, err := Open(writeFile(t, "bom.sql", []byte("\xEF\xBB\xBFDROP TABLE a;")), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := slurp(t, rc); got != "DROP TABLE a;" {
		t.Fatalf("read %q", got)
	}
	rc, _, err = Open(writeFile(t, "bom.gz", gz(t, "\xEF\xBB\xBFDROP TABLE a;")), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := slurp(t, rc); got != "DROP TABLE a;" {
		t.Fatalf("gzip read %q", got)
	}
}

func TestOpenDirectoryAndMissing(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Open(dir, false); err != ErrDirectory || strings.Contains(err.Error(), dir) {
		t.Fatalf("directory: %v", err)
	}
	missing := filepath.Join(dir, "nonesuch-secret.sql")
	_, _, err := Open(missing, false)
	if err != ErrNotFound || strings.Contains(err.Error(), "secret") {
		t.Fatalf("missing: %v", err)
	}
}

func TestOpenStdin(t *testing.T) {
	if _, _, err := Open("-", false); err != ErrStdin {
		t.Fatalf("stdin not allowed: %v", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	go func() {
		w.WriteString("DROP TABLE a;")
		w.Close()
	}()
	rc, info, err := Open("-", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := slurp(t, rc); got != "DROP TABLE a;" || info.Size != -1 {
		t.Fatalf("stdin read %q, info %+v", got, info)
	}
	if _, err := os.Stdin.Stat(); err != nil {
		t.Fatal("closing the dump closed standard input")
	}
}
