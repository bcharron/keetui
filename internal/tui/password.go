package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/bcharron/keetui/internal/kdbx"
)

// passwordPage is the first screen: a masked master-password prompt in
// a box, asked once. Enter unlocks the database (asynchronously, so the
// Argon2 work does not block the UI); a wrong password shows an error
// and lets the user retry. Esc/ctrl+c quits.
type passwordPage struct {
	path    string
	ti      textinput.Model
	err     error
	loading bool
	w, h    int
}

func newPasswordPage(path string) *passwordPage {
	ti := textinput.New()
	ti.Prompt = "> "
	ti.PromptStyle = hintKeyStyle
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.Focus()
	ti.CharLimit = 512
	return &passwordPage{path: path, ti: ti}
}

func (p *passwordPage) Init() tea.Cmd { return textinput.Blink }

func (p *passwordPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	switch msg := msg.(type) {
	case resizeMsg:
		p.w, p.h = msg.w, msg.h
	case unlockMsg:
		p.loading = false
		if msg.err != nil {
			p.err = msg.err
			p.ti.SetValue("")
		}
	case tea.KeyMsg:
		if msg.String() == "enter" && !p.loading {
			p.loading = true
			p.err = nil
			pw := p.ti.Value()
			path := p.path
			return p, func() tea.Msg {
				db, err := kdbx.Open(path, pw)
				return unlockMsg{db: db, err: err}
			}
		}
		var cmd tea.Cmd
		p.ti, cmd = p.ti.Update(msg)
		return p, cmd
	}
	return p, nil
}

func (p *passwordPage) View() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("  " + titleStyle.Render("unlock database") + "\n\n")
	b.WriteString("  " + dimStyle.Render(p.path) + "\n\n")
	b.WriteString("  " + p.ti.View() + "\n")
	if p.loading {
		b.WriteString("\n  " + loadingStyle.Render("unlocking ..."))
	} else if p.err != nil {
		b.WriteString("\n  " + errStyle.Render("error: "+p.err.Error()))
	}
	return b.String()
}

func (p *passwordPage) Header() string { return "unlock" }

func (p *passwordPage) Typing() bool { return true }

func (p *passwordPage) Hints() string {
	return "enter unlock  esc quit  ctrl+c quit"
}
