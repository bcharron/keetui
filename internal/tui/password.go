package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bcharron/keetui/internal/kdbx"
)

// modalStyle frames the centered unlock dialog; the border uses the
// same purple as the top bar.
var modalStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(lipgloss.Color("62")).
	Padding(1, 3)

// overlayBg is the dimmed background painted behind the modal.
var overlayBg = lipgloss.Color("236")

// passwordPage is the first screen: a centered modal dialog asking for
// the master password once. Enter unlocks the database (asynchronously,
// so the Argon2 work does not block the UI); a wrong password shows an
// error inside the dialog and lets the user retry. Esc/ctrl+c quits.
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
		if msg.String() == "esc" {
			return p, tea.Quit
		}
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

// dialog renders the modal's inner content.
func (p *passwordPage) dialog() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("unlock database") + "\n\n")
	b.WriteString(dimStyle.Render(p.path) + "\n\n")
	b.WriteString(p.ti.View() + "\n")
	switch {
	case p.loading:
		b.WriteString("\n" + loadingStyle.Render("unlocking ..."))
	case p.err != nil:
		b.WriteString("\n" + errStyle.Render("error: "+p.err.Error()))
	}
	return b.String()
}

// View renders the dimmed overlay with the modal centered in it.
func (p *passwordPage) View() string {
	w, h := p.w, p.h
	if w < 1 {
		w = 80
	}
	if h < 1 {
		h = 22
	}
	box := modalStyle.Render(p.dialog())
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, box,
		lipgloss.WithWhitespaceBackground(overlayBg))
}

func (p *passwordPage) Header() string { return "unlock" }

func (p *passwordPage) Typing() bool { return true }

func (p *passwordPage) Hints() string {
	return "enter unlock  esc quit  ctrl+c quit"
}
