package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// listPage is the shared skeleton of the app's filterable list page:
// the ">" prompt on the first line narrowing the list live, cursor
// navigation with pgup/pgdown, and enter opening the selected item. A
// page embeds it and supplies the items, the row rendering and the
// enter action as function fields.
type listPage[T any] struct {
	filt     filter
	cur, off int
	w, h     int

	// items is the full, unfiltered list (for the empty check);
	// visible is the filter-narrowed list.
	items   func() []T
	visible func() []T
	// row renders one list row without the trailing newline; sel asks
	// for the highlighted selection bar.
	row func(item T, sel bool) string
	// onEnter opens the selected item.
	onEnter func(item T) tea.Cmd

	// title is the styled column-header line above the list, with the
	// item count appended (listInfo).
	title string
	// noun names the items in the count ("entries").
	noun string
	// headLines is the number of lines above the list rows: filter
	// line, title and a blank line (3).
	headLines int
	// emptyText is shown when the database itself has no items.
	emptyText string
}

// resize records the content-area dimensions.
func (l *listPage[T]) resize(w, h int) { l.w, l.h = w, h }

// Typing always reports true: the ">" prompt is always capturing.
func (l *listPage[T]) Typing() bool { return true }

// rows is the number of list rows that fit the content area.
func (l *listPage[T]) rows() int {
	return max(l.h-l.headLines, 1)
}

// updateKeys handles the shared list keys: esc clears the query (or
// quits when it is already empty), the filter captures printable keys,
// and the rest is cursor movement and enter.
func (l *listPage[T]) updateKeys(msg tea.KeyMsg) tea.Cmd {
	if msg.String() == "esc" {
		if l.filt.q != "" {
			l.filt.q = ""
			l.cur, l.off = 0, 0
			return nil
		}
		return tea.Quit
	}
	if l.filt.update(msg) {
		l.cur, l.off = 0, 0
		return nil
	}
	vis := l.visible()
	switch msg.String() {
	case "up":
		if l.cur > 0 {
			l.cur--
		}
	case "down":
		if l.cur < len(vis)-1 {
			l.cur++
		}
	case "pgup":
		l.cur = pageJump(l.cur, l.rows(), len(vis), false)
	case "pgdown":
		l.cur = pageJump(l.cur, l.rows(), len(vis), true)
	case "enter":
		if l.onEnter != nil && l.cur < len(vis) {
			return l.onEnter(vis[l.cur])
		}
	}
	return nil
}

// View renders the list page: the ">" prompt line, the column header
// with the item count, a blank line, and the windowed rows.
func (l *listPage[T]) View() string {
	var b strings.Builder
	b.WriteString(l.filt.view() + "\n")
	if len(l.items()) == 0 {
		b.WriteString(l.title + "\n\n")
		b.WriteString(dimStyle.Render(l.emptyText))
		return strings.TrimRight(b.String(), "\n")
	}
	vis := l.visible()
	if len(vis) == 0 {
		b.WriteString(l.title + listInfo(0, 0, 0, l.noun) + "\n\n")
		b.WriteString(dimStyle.Render("(no matches)"))
		return strings.TrimRight(b.String(), "\n")
	}
	rows := l.rows()
	l.cur, l.off = window(l.cur, l.off, len(vis), rows)
	b.WriteString(l.title + listInfo(l.cur, len(vis), rows, l.noun) + "\n")
	b.WriteString("\n")
	for i := l.off; i < min(l.off+rows, len(vis)); i++ {
		b.WriteString(l.row(vis[i], i == l.cur) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// window(cur, off, n, rows) scrolls a fixed-size window over n items
// keeping cur visible.
func window(cur, off, n, rows int) (int, int) {
	if rows < 1 {
		rows = 1
	}
	if cur < off {
		off = cur
	}
	if cur >= off+rows {
		off = cur - rows + 1
	}
	if off > n-rows {
		off = n - rows
	}
	if off < 0 {
		off = 0
	}
	return cur, off
}

// pageJump moves cur by one page of rows, clamped to [0, n-1]; the
// pgup/pgdown navigation of the list page.
func pageJump(cur, rows, n int, down bool) int {
	if rows < 1 {
		rows = 1
	}
	if n < 1 {
		return 0
	}
	if down {
		return min(cur+rows, n-1)
	}
	return max(cur-rows, 0)
}
