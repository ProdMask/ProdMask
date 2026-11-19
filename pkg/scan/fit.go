package scan

import (
	"fmt"
	"maps"

	"github.com/ProdMask/ProdMask/pkg/model"
)

// FakeWidth is how wide a column of text or bytes must be for one of the
// starter config's fakes, in characters, or bytes in a binary column. Fits
// is the least width the fake fits in. Apart is the least width at which
// it keeps 8,192 different values apart in a unique column, or 0 where it
// never does.
type FakeWidth struct{ Fits, Apart int }

// fakeWidths holds every fake the starter config writes on a column of text
// or bytes, measured from prodmask Pro's generators on ASCII text columns.
// Pro pins these numbers against its generators with a test, so a change to
// a generator fails Pro's tests until this table follows. A phone's and a
// card's fakes keep the original's layout, so they fit wherever it did.
var fakeWidths = map[string]FakeWidth{
	"fake_email":      {Fits: 13, Apart: 15},
	"fake_username":   {Fits: 4, Apart: 5},
	"fake_name":       {Fits: 1, Apart: 10},
	"fake_first_name": {Fits: 1},
	"fake_last_name":  {Fits: 1},
	"fake_company":    {Fits: 1, Apart: 12},
	"fake_street":     {Fits: 5, Apart: 12},
	"fake_city":       {Fits: 4},
	"fake_postcode":   {Fits: 3},
	"fake_user_agent": {Fits: 70},
	"fake_phone":      {Fits: 1, Apart: 11},
	"test_card":       {Fits: 1, Apart: 12},
	"fake_ip":         {Fits: 1, Apart: 1},
	"fake_iban":       {Fits: 1, Apart: 1},
	"fake_date":       {Fits: 1},
}

// FakeWidths returns the widths of every fake the starter config writes on
// a column of text or bytes, keyed by its mask. fake_number isn't among
// them: the scan writes it only on number columns, which a hash can't fill.
func FakeWidths() map[string]FakeWidth { return maps.Clone(fakeWidths) }

// shortUnique is the widest unique column where no hash keeps its values
// apart: a keyed hash writes 16 values a character, so 3 characters hold
// 4,096, under the 8,192 a unique column must keep apart.
const shortUnique = 3

// fitNote returns the note for a fake the copy couldn't apply to column c,
// whose width within its tightest unique prefix is uniqueWidth (0 when it
// isn't unique): one that can't fit the column, or that keeps too few
// values apart for a unique one. It returns "" for a mask that isn't a
// fake, a fake that fits, and a column a hash can't fill.
func fitNote(c *model.Column, mask string, uniqueWidth int) string {
	w, ok := fakeWidths[mask]
	if !ok || !takesHash(c) || c.MaxLength <= 0 {
		return ""
	}
	if c.MaxLength < int64(w.Fits) {
		unit := "character"
		if binary(c) {
			unit = "byte"
		}
		if c.MaxLength != 1 {
			unit += "s"
		}
		return fmt.Sprintf("hash, not %s, since the column holds %d %s and %s needs %d", mask, c.MaxLength, unit, mask, w.Fits)
	}
	if uniqueWidth > 0 && (w.Apart == 0 || uniqueWidth < w.Apart) {
		return fmt.Sprintf("hash, not %s, since this unique column needs more different values than %s makes", mask, mask)
	}
	return ""
}

// judge decides what the starter does with mask on column c, whose width
// within its tightest unique prefix is uniqueWidth (0 when it isn't
// unique). note is fitNote's: a fake the copy couldn't apply becomes hash,
// with it. short reports a unique column no wider than shortUnique under a
// mask that would leave it narrow, such as a fake fitNote rewrites, or a
// hash: neither keeps its values apart, so prodmask Pro chooses the rule.
func judge(c *model.Column, mask string, uniqueWidth int) (note string, short bool) {
	note = fitNote(c, mask, uniqueWidth)
	short = uniqueWidth > 0 && uniqueWidth <= shortUnique && takesHash(c) && (mask == "hash" || note != "")
	return note, short
}

// fitFakes runs after hashUnique, on the same findings. A fake the copy
// couldn't apply becomes hash, with a note that says why: one that can't
// fit its column, and one that keeps too few values apart for a unique
// column; row masks are rewritten the same way. On a unique column of text
// or bytes no wider than shortUnique, within its tightest unique prefix, a
// finding whose mask, or a row mask, would leave the column narrow is
// marked ProChooses: the starter config writes its line commented out and
// leaves the rule to prodmask Pro. The category never changes. Findings
// about a path inside a value, or about keys' names, are left alone, as
// hashUnique leaves them; a key's finding is its value column's.
func fitFakes(t *model.Table, findings []model.Finding) {
	widths := uniqueWidths(t)
	for i := range findings {
		f := &findings[i]
		c := t.Column(f.Column)
		if f.Path != "" || f.KeyName || c == nil || !takesHash(c) {
			continue
		}
		width := widths[c]
		note, short := judge(c, f.Mask, width)
		if note != "" {
			f.Mask, f.Note = "hash", addNote(f.Note, note)
		}
		for j := range f.RowMasks {
			rm := &f.RowMasks[j]
			note, s := judge(c, rm.Mask, width)
			short = short || s
			if note != "" {
				rm.Mask, rm.Note = "hash", addNote(rm.Note, note)
			}
		}
		if short {
			f.ProChooses = true
		}
	}
}

// uniqueWidths gives each column of a table's primary key and unique
// indexes, but no generated column, the width of the tightest prefix of
// those indexes it's in: the prefix's length, or the column's own where an
// index takes it whole. An index part on an expression names no column.
// Its keys are the columns hashUnique treats as unique.
func uniqueWidths(t *model.Table) map[*model.Column]int {
	out := map[*model.Column]int{}
	add := func(name string, sub int) {
		c := t.Column(name)
		if name == "" || c == nil || generated(c) {
			return
		}
		w := int(c.MaxLength)
		if sub > 0 && (w <= 0 || sub < w) {
			w = sub
		}
		if old, ok := out[c]; !ok || w < old {
			out[c] = w
		}
	}
	for _, name := range t.PrimaryKey {
		add(name, 0)
	}
	for _, ix := range t.Indexes {
		if !ix.Unique {
			continue
		}
		for k, name := range ix.Columns {
			sub := 0
			if k < len(ix.SubParts) {
				sub = ix.SubParts[k]
			}
			add(name, sub)
		}
	}
	return out
}
