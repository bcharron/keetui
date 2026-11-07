package tui

import (
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/bcharron/keetui/internal/kdbx"
)

// entryPage is the per-entry detail view: a scrollable, wrapped
// document of the entry's fields. The password stays masked until "x"
// toggles visibility. Esc/q goes back to the list.
type entryPage struct {
	e      kdbx.Entry
	showPw bool
	vp     viewport.Model
	w, h   int
}

func newEntryPage(e kdbx.Entry) *entryPage {
	return &entryPage{e: e, vp: viewport.New(0, 0)}
}

func (p *entryPage) Init() tea.Cmd { return nil }

func (p *entryPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	switch msg := msg.(type) {
	case resizeMsg:
		p.w, p.h = msg.w, msg.h
		p.layout()
	case tea.KeyMsg:
		if msg.String() == "x" {
			p.showPw = !p.showPw
			p.layout()
			return p, nil
		}
		p.vp, _ = p.vp.Update(msg)
	}
	return p, nil
}

func (p *entryPage) layout() {
	p.vp.Width = p.w
	h := p.h - 2 // title line plus blank separator
	if h < 1 {
		h = 1
	}
	p.vp.Height = h
	p.vp.SetContent(wrapText(entryDoc(p.e, p.showPw), p.w))
}

func (p *entryPage) View() string { return p.vp.View() }

func (p *entryPage) Header() string { return "entries / " + truncate(p.e.Title, 60) }

func (p *entryPage) Typing() bool { return false }

func (p *entryPage) Hints() string {
	return "x toggle password  up/down scroll  esc back  ctrl+l redraw  q quit"
}
