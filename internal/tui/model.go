package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bcharron/keetui/internal/kdbx"
)

// Page is one screen of the TUI. Update returns the (possibly replaced)
// page, mirroring tea.Model semantics. Typing reports whether the page
// currently captures arbitrary key input (a text field); while true the
// app does not intercept q/esc.
type Page interface {
	Init() tea.Cmd
	Update(tea.Msg) (Page, tea.Cmd)
	View() string
	Header() string
	Hints() string
	Typing() bool
}

// App is the root model: it owns the page stack (unlock page, entries
// list, entry detail) and the global chrome (top bar with the database
// path, content box, footer with key hints).
type App struct {
	path  string
	db    *kdbx.Database
	stack []Page
	w, h  int
}

// New builds the app for the database file at path. The master
// password is asked for on the first page.
func New(path string) App {
	return App{path: path, stack: []Page{newPasswordPage(path)}}
}

func (a App) top() Page { return a.stack[len(a.stack)-1] }

func (a App) Init() tea.Cmd { return a.top().Init() }

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.w, a.h = msg.Width, msg.Height
		return a.broadcast(a.dims())

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return a, tea.Quit
		case "ctrl+l":
			// full repaint, for when something else scribbled on the
			// terminal or the display drifted
			return a, tea.ClearScreen
		case "q":
			if !a.top().Typing() {
				return a, tea.Quit
			}
		case "esc":
			if !a.top().Typing() {
				if len(a.stack) > 1 {
					a.stack = a.stack[:len(a.stack)-1]
					return a, nil
				}
				return a, tea.Quit
			}
		}
		var cmd tea.Cmd
		a.stack[len(a.stack)-1], cmd = a.top().Update(msg)
		return a, cmd

	case pushMsg:
		a.stack = append(a.stack, msg.page)
		var cmd tea.Cmd
		msg.page, cmd = msg.page.Update(a.dims())
		return a, tea.Batch(cmd, msg.page.Init())

	case popMsg:
		if len(a.stack) > 1 {
			a.stack = a.stack[:len(a.stack)-1]
		}
		return a, nil

	case unlockMsg:
		if msg.err != nil {
			// wrong password or unreadable file: hand the error to
			// the unlock page, which stays on top
			return a.broadcast(msg)
		}
		a.db = msg.db
		a.stack = []Page{newEntriesPage(msg.db)}
		return a.broadcast(a.dims())

	default:
		// data messages go to every page in the stack
		return a.broadcast(msg)
	}
}

func (a App) broadcast(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := make([]tea.Cmd, len(a.stack))
	for i := range a.stack {
		a.stack[i], cmds[i] = a.stack[i].Update(msg)
	}
	return a, tea.Batch(cmds...)
}

// dims returns the current content-area dimensions: the terminal minus
// the top bar and footer lines, minus the content box's border and
// padding, falling back to a sane default before the first
// WindowSizeMsg arrives.
func (a App) dims() resizeMsg {
	w, h := a.w, a.h-2
	if w <= 0 {
		w = 80
	}
	if h < 1 {
		h = 22
	}
	return resizeMsg{max(w-4, 1), max(h-2, 1)}
}

// header renders the full-width top bar: app name and database path
// on the left (with the entry count once unlocked), the current page's
// breadcrumb on the right.
func (a App) header() string {
	w := a.w
	if w <= 0 {
		w = 80
	}
	left := topBarStyle.Render("keetui") + topBarInfo.Render(" "+a.path)
	if a.db != nil {
		left += topBarInfo.Render(fmt.Sprintf("  %d %s", len(a.db.Entries), plural(len(a.db.Entries), "entries")))
	}
	right := topBarCrumb.Render(a.top().Header())
	pad := w - lipgloss.Width(left) - lipgloss.Width(right) - 1
	if pad < 1 {
		return left + topBarBg.Render(" ") + right
	}
	return left + topBarBg.Render(strings.Repeat(" ", pad)) + right + topBarBg.Render(" ")
}

func (a App) View() string {
	header := a.header()
	content := contentStyle.Height(max(a.h-4, 1)).Render(a.top().View())
	footer := bottomStyle.Render(renderHints(a.top().Hints()))
	return header + "\n" + content + "\n" + footer
}
