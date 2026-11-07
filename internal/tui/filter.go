package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

// match reports whether s matches the query (case-insensitive
// substring).
func (f *filter) match(s string) bool {
	if f.q == "" {
		return true
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(f.q))
}

// view renders the prompt line: "> query▌".
func (f *filter) view() string {
	return hintKeyStyle.Render(">") + " " + valStyle.Render(f.q) + "▌"
}

// highlight styles the query match inside name, rendering the rest in
// the base style.
func (f *filter) highlight(name string, base lipgloss.Style) string {
	if f.q == "" {
		return base.Render(name)
	}
	i := strings.Index(strings.ToLower(name), strings.ToLower(f.q))
	if i < 0 {
		return base.Render(name)
	}
	return base.Render(name[:i]) + selStyle.Render(name[i:i+len(f.q)]) + base.Render(name[i+len(f.q):])
}
