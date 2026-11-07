package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Palette mirrors vaultui: purple top bar and selection bar (230 on
// 62), bright items (252), dim secondary text (241), accent (117),
// selection text (213), errors (203).
var (
	topBarStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Padding(0, 1)

	// Header bar segment styles. Each carries the bar background
	// explicitly: embedded ANSI resets would drop a wrapping
	// background after the first styled segment.
	topBarInfo  = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Background(lipgloss.Color("62"))
	topBarCrumb = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Background(lipgloss.Color("62"))
	topBarBg    = lipgloss.NewStyle().Background(lipgloss.Color("62"))

	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	bottomStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	itemStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	selStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213"))
	errStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	loadingStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("117"))

	// selBarStyle paints the selected list row as a highlight bar.
	selBarStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62"))

	// contentStyle frames the page content area.
	contentStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240")).Padding(0, 1)

	hintKeyStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("117"))
	hintDescStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	// Document (entry field) colors.
	keyStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))  // field keys
	valStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252")) // values
)

// selBar renders a selected list row as a bar padded to the content
// width so the highlight spans the full line.
func selBar(w int, row string) string {
	if w > 0 {
		return selBarStyle.Width(w).MaxWidth(w).Render(row)
	}
	return selBarStyle.Render(row)
}

// listInfo renders the dim trailing count shown next to a list title:
// "12 entries", or "3/12 entries" once the list is taller than one
// screen.
func listInfo(cur, total, rows int, noun string) string {
	if total <= 0 {
		return ""
	}
	s := fmt.Sprintf("%d %s", total, plural(total, noun))
	if rows > 0 && total > rows {
		s = fmt.Sprintf("%d/%d %s", cur+1, total, plural(total, noun))
	}
	return "  " + dimStyle.Render(s)
}

// plural returns the singular form of noun when n is 1
// ("entries" -> "entry").
func plural(n int, noun string) string {
	if n == 1 {
		if strings.HasSuffix(noun, "ies") {
			return noun[:len(noun)-3] + "y"
		}
		return strings.TrimSuffix(noun, "s")
	}
	return noun
}

// renderHints styles a key-hint string of the form
// "key desc  key desc" (groups separated by two spaces): key chords
// stand out, descriptions stay dim.
func renderHints(hints string) string {
	var out []string
	for _, g := range strings.Split(hints, "  ") {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		key, desc, _ := strings.Cut(g, " ")
		s := hintKeyStyle.Render(key)
		if desc != "" {
			s += " " + hintDescStyle.Render(desc)
		}
		out = append(out, s)
	}
	return strings.Join(out, "  ")
}

func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}
