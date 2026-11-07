package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/bcharron/keetui/internal/kdbx"
)

// resizeMsg carries the content-area dimensions (width x height) to
// every page whenever the terminal is resized.
type resizeMsg struct{ w, h int }

// pushMsg/popMsg drive the navigation stack.
type pushMsg struct{ page Page }
type popMsg struct{}

// unlockMsg carries the result of opening the database with the
// password typed into the unlock page.
type unlockMsg struct {
	db  *kdbx.Database
	err error
}

// Push returns a command that navigates onto a new page.
func Push(p Page) tea.Cmd { return func() tea.Msg { return pushMsg{p} } }

// Pop returns a command that navigates back one page.
func Pop() tea.Cmd { return func() tea.Msg { return popMsg{} } }
