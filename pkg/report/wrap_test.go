package report

import (
	"strings"
	"testing"

	"github.com/ProdMask/ProdMask/pkg/detect"
)

// visible is a line as the reader sees it: without colour codes.
func visible(s styled) string { return ownColours.ReplaceAllString(string(s), "") }

func lines(ss []styled) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = visible(s)
	}
	return out
}

func TestFillBreaksBetweenWords(t *testing.T) {
	// The first line starts at column 4, so it has 16 columns; the others
	// start at 6 and have 14.
	got := lines(style{}.fill(20, 4, 6, plain("one two three four five six seven")))
	want := []string{"one two three", "      four five six", "      seven"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
	for i, l := range got {
		width := runeLen(l)
		if i == 0 {
			width += 4
		}
		if width > 20 {
			t.Errorf("line %d is %d wide: %q", i, width, l)
		}
		if strings.HasSuffix(l, " ") || (i > 0 && !strings.HasPrefix(l, "      ") || i > 0 && l[6] == ' ') {
			t.Errorf("line %d starts or ends wrong: %q", i, l)
		}
	}
}

// A word wider than its room keeps a line of its own, whole.
func TestFillLongWord(t *testing.T) {
	long := strings.Repeat("x", 30)
	got := lines(style{}.fill(20, 0, 2, plain("short "+long+" end")))
	want := []string{"short", "  " + long, "  end"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Names from the database are cleaned, and a line never breaks at what the
// cleaning replaced: a carriage return, a line feed, a line separator or an
// escape is a ? inside its word.
func TestFillCleans(t *testing.T) {
	for _, c := range []string{"\r", "\n", " ", "\x1b[31m"} {
		got := lines(style{}.fill(12, 0, 2, plain("aaaa bbbb"+c+"cccc dddd")))
		joined := strings.Join(got, "\n")
		if strings.ContainsAny(joined, "\r\x1b ") || strings.Count(joined, "\n") != len(got)-1 {
			t.Errorf("%q: not cleaned: %q", c, got)
		}
		found := false
		for _, l := range got {
			if strings.Contains(l, "bbbb?") {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: the word holding it was broken or not cleaned: %q", c, got)
		}
	}
}

// A no-break space and a run of spaces inside a name print as they are; a
// line breaks at neither the no-break space nor inside a word, and where it
// breaks in a run of spaces the whole run goes.
func TestFillKeepsSpaces(t *testing.T) {
	got := lines(style{}.fill(14, 0, 2, plain("my table and my  other  table")))
	want := []string{"my table and", "  my  other", "  table"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
	// Where the no-break space is the only place a line could break before
	// its width, the name goes to the next line whole.
	got = lines(style{}.fill(12, 0, 2, plain("aaaaaaaa my table")))
	want = []string{"aaaaaaaa", "  my table"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFillKeepsHiddenNamesWhole(t *testing.T) {
	for w := 10; w <= 30; w++ {
		got := lines(style{}.fill(w, 0, 2, plain("found in meta_value["+detect.HiddenKey+"] and "+detect.HiddenType+" rows")))
		joined := strings.Join(got, "\n")
		if !strings.Contains(joined, detect.HiddenKey) || !strings.Contains(joined, detect.HiddenType) {
			t.Errorf("width %d split a hidden name: %q", w, got)
		}
	}
}

// A part's colour goes on every line it reaches, and with colour off the
// text is the same.
func TestFillStyles(t *testing.T) {
	parts := []part{plain("label "), {"dim words that run over the line", "2"}}
	on := style{on: true}.fill(18, 0, 2, parts...)
	off := style{}.fill(18, 0, 2, parts...)
	if len(on) != len(off) || len(on) < 2 {
		t.Fatalf("on %q, off %q", on, off)
	}
	for i := range on {
		if visible(on[i]) != string(off[i]) {
			t.Errorf("line %d: %q with colour, %q without", i, visible(on[i]), off[i])
		}
		if i > 0 && !strings.Contains(string(on[i]), "\x1b[2m") {
			t.Errorf("line %d lost its style: %q", i, on[i])
		}
	}
}

func TestLayoutWidth(t *testing.T) {
	for in, want := range map[int]int{0: 100, -5: 100, 30: 60, 59: 60, 60: 60, 77: 77, 100: 100, 150: 100} {
		if got := layoutWidth(in); got != want {
			t.Errorf("layoutWidth(%d) = %d, want %d", in, got, want)
		}
	}
}
