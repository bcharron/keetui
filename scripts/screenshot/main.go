// Command screenshot renders the keetui TUI (driven against the
// testdata fixture) to an HTML file, for screenshotting with a headless
// browser, e.g.:
//
//	go run ./scripts/screenshot /tmp/keetui.html
//	chromium --headless=new --no-sandbox --disable-gpu \
//	  --screenshot=screenshot.png --window-size=920,720 file:///tmp/keetui.html
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/bcharron/keetui/internal/tui"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: screenshot <out.html>")
		os.Exit(2)
	}
	lipgloss.SetColorProfile(termenv.TrueColor)

	var m tea.Model = tui.New("testdata/test-aes.kdbx")
	send := func(msgs ...tea.Msg) tea.Cmd {
		var cmd tea.Cmd
		for _, msg := range msgs {
			m, cmd = m.Update(msg)
		}
		return cmd
	}
	keys := func(s string) []tea.Msg {
		var out []tea.Msg
		for _, r := range s {
			out = append(out, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		}
		return out
	}

	send(tea.WindowSizeMsg{Width: 100, Height: 30})
	send(keys("test-password")...)
	cmd := send(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		send(cmd()) // unlockMsg
	}
	send(keys("g")...) // filter query, fuzzy-matched

	if err := os.WriteFile(os.Args[1], []byte(page(m.View())), 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", os.Args[1])
}

func page(view string) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><style>")
	b.WriteString("body{margin:0;background:#11111b;padding:18px;display:inline-block}")
	b.WriteString("pre{font:14px/1.25 'DejaVu Sans Mono',Menlo,monospace;color:#cdd6f4;margin:0}")
	b.WriteString("</style></head><body><pre>")
	b.WriteString(ansiToHTML(view))
	b.WriteString("</pre></body></html>")
	return b.String()
}

// ansiToHTML converts SGR color/bold sequences to styled spans.
func ansiToHTML(s string) string {
	var b strings.Builder
	fg, bg := "", ""
	bold := false
	spanOpen := false
	var text []byte

	closeSpan := func() {
		if spanOpen {
			b.WriteString("</span>")
			spanOpen = false
		}
	}
	flush := func() {
		if len(text) > 0 {
			closeSpan()
			style := ""
			if fg != "" {
				style += "color:" + fg + ";"
			}
			if bg != "" {
				style += "background-color:" + bg + ";"
			}
			if bold {
				style += "font-weight:bold;"
			}
			if style != "" {
				b.WriteString("<span style=\"" + style + "\">")
				spanOpen = true
			}
			b.WriteString(htmlEscape(string(text)))
			text = nil
		}
	}
	apply := func(params string) {
		flush()
		parts := strings.Split(params, ";")
		for i := 0; i < len(parts); i++ {
			p, _ := strconv.Atoi(parts[i])
			switch {
			case p == 0:
				fg, bg, bold = "", "", false
			case p == 1:
				bold = true
			case p == 22:
				bold = false
			case p == 39:
				fg = ""
			case p == 49:
				bg = ""
			case p == 38 && i+4 < len(parts) && parts[i+1] == "2":
				fg = rgb(parts[i+2], parts[i+3], parts[i+4])
				i += 4
			case p == 48 && i+4 < len(parts) && parts[i+1] == "2":
				bg = rgb(parts[i+2], parts[i+3], parts[i+4])
				i += 4
			case p == 38 && i+2 < len(parts) && parts[i+1] == "5":
				fg = xterm256(parts[i+2])
				i += 2
			case p == 48 && i+2 < len(parts) && parts[i+1] == "5":
				bg = xterm256(parts[i+2])
				i += 2
			case p >= 30 && p <= 37:
				fg = xterm256(strconv.Itoa(p - 30))
			case p >= 90 && p <= 97:
				fg = xterm256(strconv.Itoa(p - 90 + 8))
			case p >= 40 && p <= 47:
				bg = xterm256(strconv.Itoa(p - 40))
			case p >= 100 && p <= 107:
				bg = xterm256(strconv.Itoa(p - 100 + 8))
			}
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				apply(s[i+2 : j])
				i = j
				continue
			}
		}
		if c == '\r' {
			continue
		}
		if c == '\n' {
			flush()
			b.WriteString("\n")
			continue
		}
		text = append(text, c)
	}
	flush()
	closeSpan()
	return b.String()
}

func rgb(r, g, bl string) string {
	a, _ := strconv.Atoi(r)
	b2, _ := strconv.Atoi(g)
	c, _ := strconv.Atoi(bl)
	return fmt.Sprintf("#%02x%02x%02x", a, b2, c)
}

// xterm256 maps an xterm-256 palette index to a hex color.
func xterm256(s string) string {
	n, _ := strconv.Atoi(s)
	if n < 16 {
		basic := []string{"#000000", "#800000", "#008000", "#808000", "#000080", "#800080", "#008080", "#c0c0c0",
			"#808080", "#ff0000", "#00ff00", "#ffff00", "#0000ff", "#ff00ff", "#00ffff", "#ffffff"}
		return basic[n]
	}
	if n < 232 {
		n -= 16
		r, g, b := n/36, (n/6)%6, n%6
		cv := func(c int) int {
			if c == 0 {
				return 0
			}
			return 55 + 40*c
		}
		return fmt.Sprintf("#%02x%02x%02x", cv(r), cv(g), cv(b))
	}
	v := 8 + (n-232)*10
	return fmt.Sprintf("#%02x%02x%02x", v, v, v)
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
