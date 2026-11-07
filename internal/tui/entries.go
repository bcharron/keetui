package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bcharron/keetui/internal/kdbx"
)

// entriesPage is the main list: every entry of the database, narrowed
// live by the ">" prompt matching titles. Enter opens the entry's
// detail page.
type entriesPage struct {
	db *kdbx.Database
	listPage[kdbx.Entry]
}

func newEntriesPage(db *kdbx.Database) *entriesPage {
	p := &entriesPage{db: db}
	p.items = func() []kdbx.Entry { return p.db.Entries }
	p.visible = func() []kdbx.Entry {
		if p.filt.empty() {
			return p.db.Entries
		}
		var out []kdbx.Entry
		for _, e := range p.db.Entries {
			if p.filt.match(e.Title) {
				out = append(out, e)
			}
		}
		return out
	}
	p.row = func(e kdbx.Entry, sel bool) string {
		title := e.Title
		if e.InRecycleBin {
			title = "[bin] " + title
		}
		tw, uw := titleWidth(p.w), userWidth(p.w)
		pathW := max(p.w-2-tw-1-uw-1, 4)
		plain := fmt.Sprintf("  %-*s %-*s %s", tw, truncate(title, tw), uw, truncate(e.UserName, uw), truncate(e.GroupPath, pathW))
		if sel {
			return selBar(p.w, plain)
		}
		return fmt.Sprintf("  %s %s %s",
			p.filt.highlight(fmt.Sprintf("%-*s", tw, truncate(title, tw)), itemStyle),
			dimStyle.Render(fmt.Sprintf("%-*s", uw, truncate(e.UserName, uw))),
			dimStyle.Render(truncate(e.GroupPath, pathW)))
	}
	p.onEnter = func(e kdbx.Entry) tea.Cmd {
		return Push(newEntryPage(e))
	}
	p.title = dimStyle.Render(fmt.Sprintf("  %-*s %-*s %s", titleWidth(80), "TITLE", userWidth(80), "USERNAME", "GROUP"))
	p.noun = "entries"
	p.headLines = 3
	p.emptyText = "(no entries in database)"
	return p
}

func titleWidth(w int) int { return max(min(40, w-40), 10) }
func userWidth(w int) int  { return max(min(24, w/3), 8) }

func (p *entriesPage) Init() tea.Cmd { return nil }

func (p *entriesPage) Update(msg tea.Msg) (Page, tea.Cmd) {
	switch msg := msg.(type) {
	case resizeMsg:
		p.resize(msg.w, msg.h)
	case tea.KeyMsg:
		return p, p.updateKeys(msg)
	}
	return p, nil
}

func (p *entriesPage) View() string { return p.listPage.View() }

func (p *entriesPage) Header() string { return "entries" }

func (p *entriesPage) Hints() string {
	return "type to filter  up/down select  pgup/pgdown page  enter open  esc clear/quit  ctrl+l redraw  ctrl+c quit"
}
