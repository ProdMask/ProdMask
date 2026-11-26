package report

import (
	"strings"

	"github.com/ProdMask/ProdMask/pkg/detect"
)

// A part is a run of report text in one look, for fill: code is the ANSI
// code it's printed in, such as "2" for dim, or "" for plain.
type part struct{ text, code string }

func plain(t string) part { return part{t, ""} }

// Layout widths: the report lays out at most at maxWidth columns and at
// least at minWidth, below which the terminal wraps it.
const (
	minWidth = 60
	maxWidth = 100
	// stackBelow is the least room a column of text keeps beside a label:
	// with less, the label gets a line of its own and the text goes under it.
	stackBelow = 30
	// evidenceMin is the least room a finding row keeps for its evidence.
	evidenceMin = 16
)

// layoutWidth is the width the report lays out at: TextOptions.Width
// clamped to minWidth..maxWidth, or maxWidth when it's 0 or less.
func layoutWidth(w int) int {
	if w <= 0 {
		return maxWidth
	}
	return min(maxWidth, max(minWidth, w))
}

// noBreak stands for the space inside a phrase fill keeps whole. Clean
// turns every control character into ?, so no cleaned text holds it.
const noBreak = '\x00'

// keepWhole marks the phrases the report never breaks: the names it hides.
func keepWhole(s string) string {
	for _, p := range []string{detect.HiddenKey, detect.HiddenType} {
		s = strings.ReplaceAll(s, p, strings.Replace(p, " ", string(noBreak), 1))
	}
	return s
}

// A glyph is one rune of laid-out text and the code it's printed in.
type glyph struct {
	r    rune
	code string
}

// fill lays text, given as parts, out in lines at most width runes wide.
// The first line starts at column first, after what the caller printed
// before it, and later lines start with indent spaces. It cleans the text
// first and breaks only at a plain space (U+0020), never inside a word or a
// hidden name's "(key hidden)", so a no-break space or a cleaned control
// character never ends a line. Runs of spaces inside a line stay as they
// are; where a line breaks inside one, the whole run goes, so no line
// starts or ends with spaces. A word wider than its room gets a line of its
// own and stays whole. Each part's code is put on every line it reaches,
// after the breaking, so colour codes never count toward the width.
func (s style) fill(width, first, indent int, parts ...part) []styled {
	var cells []glyph
	for _, p := range parts {
		for _, r := range keepWhole(Clean(p.text)) {
			cells = append(cells, glyph{r, p.code})
		}
	}
	var lines [][]glyph
	var line, gap []glyph
	col := first
	for i := 0; i < len(cells); {
		j := i
		space := cells[i].r == ' '
		for j < len(cells) && (cells[j].r == ' ') == space {
			j++
		}
		run := cells[i:j]
		i = j
		if space {
			if len(line) > 0 {
				gap = run
			}
			continue
		}
		if len(line) > 0 && col+len(gap)+len(run) > width {
			lines = append(lines, line)
			line, gap, col = nil, nil, indent
		}
		line = append(append(line, gap...), run...)
		col += len(gap) + len(run)
		gap = nil
	}
	if len(line) > 0 || len(lines) == 0 {
		lines = append(lines, line)
	}
	out := make([]styled, len(lines))
	for i, l := range lines {
		var b strings.Builder
		if i > 0 {
			b.WriteString(strings.Repeat(" ", indent))
		}
		for j := 0; j < len(l); {
			k := j
			for k < len(l) && l[k].code == l[j].code {
				k++
			}
			text := make([]rune, 0, k-j)
			for _, c := range l[j:k] {
				if c.r == noBreak {
					c.r = ' '
				}
				text = append(text, c.r)
			}
			if s.on && l[j].code != "" {
				b.WriteString("\x1b[" + l[j].code + "m" + string(text) + "\x1b[0m")
			} else {
				b.WriteString(string(text))
			}
			j = k
		}
		out[i] = styled(b.String())
	}
	return out
}
