package tui

import (
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/bcharron/keetui/internal/kdbx"
)

// entryPage is the per-entry detail view: a scrollable, wrapped
// document of the entry's fields. The password stays masked until "x"
// toggles visibility; "v" opens the entry's history versions.
// Esc/q goes back to the list.
type entryPage struct {
	e      kdbx.Entry
	sub    string // extra breadcrumb segment, e.g. the version's time
	showPw bool
	vp     viewport.Model
	w, h   int
}

func newEntryPage(e kdbx.Entry) *entryPage {
	return &entryPage{e: e, vp: viewport.New(0, 0)}
}

// newVersionPage opens a history version of an entry.
func newVersionPage(v kdbx.Entry, parentTitle string) *entryPage {
	return &entryPage{e: v, sub: v.Modified, vp: viewport.New(0, 0)}
}

func (p *entryPage) Init() tea.Cmd { return nil }

func (p *entryPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	switch msg := msg.(type) {
	case resizeMsg:
		p.w, p.h = msg.w, msg.h
		p.layout()
	case tea.KeyMsg:
		switch msg.String() {
		case "x":
			p.showPw = !p.showPw
			p.layout()
			return p, nil
		case "v":
			if len(p.e.Versions) > 0 {
				return p, Push(newVersionsPage(p.e))
			}
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

func (p *entryPage) Header() string {
	h := "entries / " + truncate(p.e.Title, 60)
	if p.sub != "" {
		h += " / " + p.sub
	}
	return h
}

func (p *entryPage) Typing() bool { return false }

func (p *entryPage) Hints() string {
	h := "x toggle password  up/down scroll  esc back  ctrl+l redraw  q quit"
	if len(p.e.Versions) > 0 {
		h = "v versions  " + h
	}
	return h
}
