package cli

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// fakeEnv is an Env whose environment holds only COLUMNS, and whose
// terminals are all term columns wide, or the OS's answer when term is -1.
func fakeEnv(stdout io.Writer, columns string, term int) *Env {
	env := &Env{Stdout: stdout, Stderr: io.Discard, Getenv: func(k string) string {
		if k == "COLUMNS" {
			return columns
		}
		return ""
	}}
	if term >= 0 {
		env.TermWidth = func(*os.File) int { return term }
	}
	return env
}

func TestTextWidth(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	r, pipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer pipe.Close()
	cases := []struct {
		name    string
		stdout  io.Writer
		columns string
		term    int
		out     string
		want    int
	}{
		{"$COLUMNS wins over the terminal", devNull, "80", 77, "", 80},
		{"the terminal's width", devNull, "", 77, "", 77},
		{"a narrow terminal, unclamped", devNull, "", 30, "", 30},
		{"a wide terminal, unclamped", devNull, "", 150, "", 150},
		{"$COLUMNS that isn't a positive number", devNull, "0", 77, "", 77},
		{"$COLUMNS that isn't a number", devNull, "wide", 77, "", 77},
		{"a buffer, though the terminal says 77", &bytes.Buffer{}, "", 77, "", 0},
		{"a pipe, through the OS", pipe, "", -1, "", 0},
		{"the null device, through the OS", devNull, "", -1, "", 0},
		{"--out", devNull, "", 77, "report.txt", 0},
		{"--out over $COLUMNS", devNull, "80", 77, "report.txt", 0},
	}
	for _, c := range cases {
		if got := textWidth(fakeEnv(c.stdout, c.columns, c.term), c.out); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}
