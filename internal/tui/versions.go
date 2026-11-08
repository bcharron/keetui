package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bcharron/keetui/internal/kdbx"
)

// versionsPage lists an entry's history versions (newest first), opened
// with "v" from the entry detail. Enter opens the selected version.
type versionsPage struct {
	parent kdbx.Entry
	listPage[kdbx.Entry]
}

func newVersionsPage(parent kdbx.Entry) *versionsPage {
	p := &versionsPage{parent: parent}
	p.items = func() []kdbx.Entry { return p.parent.Versions }
	p.visible = func() []kdbx.Entry {
		titles := make([]string, len(p.parent.Versions))
		for i, v := range p.parent.Versions {
			titles[i] = v.Title
		}
		var out []kdbx.Entry
		for _, idx := range p.filt.rank(titles) {
			out = append(out, p.parent.Versions[idx])
		}
		return out
	}
	p.row = func(v kdbx.Entry, sel bool) string {
		plain := fmt.Sprintf("  %-20s %s", v.Modified, v.Title)
		if sel {
			return selBar(p.w, plain)
		}
		return fmt.Sprintf("  %s %s",
			dimStyle.Render(fmt.Sprintf("%-20s", v.Modified)),
			p.filt.highlight(v.Title, itemStyle))
	}
	p.onEnter = func(v kdbx.Entry) tea.Cmd {
		return Push(newVersionPage(v, p.parent.Title))
	}
	p.title = dimStyle.Render(fmt.Sprintf("  %-20s %s", "MODIFIED", "TITLE"))
	p.noun = "versions"
	p.headLines = 3
	p.emptyText = "(no history)"
	p.escQuits = false
	return p
}

func (p *versionsPage) Init() tea.Cmd { return nil }

func (p *versionsPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	switch msg := msg.(type) {
	case resizeMsg:
		p.resize(msg.w, msg.h)
	case tea.KeyMsg:
		return p, p.updateKeys(msg)
	}
	return p, nil
}

func (p *versionsPage) View() string { return p.listPage.View() }

func (p *versionsPage) Header() string {
	return fmt.Sprintf("entries / %s / versions", truncate(p.parent.Title, 40))
}

func (p *versionsPage) Hints() string {
	return "type to filter  up/down select  enter open version  esc back  ctrl+l redraw  ctrl+c quit"
}
