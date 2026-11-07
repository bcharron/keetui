package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sahilm/fuzzy"
)

// filter is the always-on search prompt shown at the top of the list
// page: every printable key extends the query and narrows the list
// live; backspace edits. Navigation keys (arrows, pgup/pgdown, enter,
// esc) are not consumed here and fall through to the page.
type filter struct {
	q string
}

func (f *filter) empty() bool { return f.q == "" }

// update consumes keys for the query. It returns true when the key was
// used by the filter and must not reach normal navigation.
func (f *filter) update(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "backspace":
		if f.q != "" {
			f.q = f.q[:len(f.q)-1]
		}
		return true
	default:
		s := msg.String()
		if len(s) == 1 && s[0] >= 0x20 && s[0] != 0x7f {
			f.q += s
			return true
		}
		return false
	}
}

// positions returns the matched rune indices in s for a contiguous
// case-insensitive substring match (used for highlighting); nil when
// the query is empty or only matches fuzzily.
func (f *filter) positions(s string) []int {
	if f.q == "" {
		return nil
	}
	ls := []rune(strings.ToLower(s))
	qs := []rune(strings.ToLower(f.q))
	for i := 0; i+len(qs) <= len(ls); i++ {
		match := true
		for j := range qs {
			if ls[i+j] != qs[j] {
				match = false
				break
			}
		}
		if match {
			pos := make([]int, len(qs))
			for j := range pos {
				pos[j] = i + j
			}
			return pos
		}
	}
	return nil
}

// match reports whether s matches the query: case-insensitive substring
// or, failing that, a fuzzy match via sahilm/fuzzy.
func (f *filter) match(s string) bool {
	if f.q == "" {
		return true
	}
	if f.positions(s) != nil {
		return true
	}
	return len(fuzzy.Find(strings.ToLower(f.q), []string{strings.ToLower(s)})) > 0
}

// stringSource adapts a string slice to fuzzy.Source.
type stringSource []string

func (s stringSource) String(i int) string { return s[i] }
func (s stringSource) Len() int            { return len(s) }

// rank returns the indices of titles matching the query, best match
// first (fuzzy-ranked); an empty query returns all indices in order.
func (f *filter) rank(titles []string) []int {
	if f.q == "" {
		idx := make([]int, len(titles))
		for i := range idx {
			idx[i] = i
		}
		return idx
	}
	lowered := make([]string, len(titles))
	for i, t := range titles {
		lowered[i] = strings.ToLower(t)
	}
	ms := fuzzy.FindFrom(strings.ToLower(f.q), stringSource(lowered))
	out := make([]int, len(ms))
	for i, m := range ms {
		out[i] = m.Index
	}
	return out
}

// view renders the prompt line: "> query▌".
func (f *filter) view() string {
	return hintKeyStyle.Render(">") + " " + valStyle.Render(f.q) + "▌"
}

// highlight styles the matched runes inside name, rendering the rest in
// the base style.
func (f *filter) highlight(name string, base lipgloss.Style) string {
	pos := f.positions(name)
	if len(pos) == 0 {
		return base.Render(name)
	}
	matched := make(map[int]bool, len(pos))
	for _, p := range pos {
		matched[p] = true
	}
	var b strings.Builder
	seg := ""
	segMatch := false
	flush := func() {
		if seg == "" {
			return
		}
		if segMatch {
			b.WriteString(selStyle.Render(seg))
		} else {
			b.WriteString(base.Render(seg))
		}
		seg = ""
	}
	for i, r := range []rune(name) {
		m := matched[i]
		if m != segMatch && seg != "" {
			flush()
		}
		segMatch = m
		seg += string(r)
	}
	flush()
	return b.String()
}
