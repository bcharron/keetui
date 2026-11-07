package tui

import (
	"fmt"
	"strings"

	"github.com/bcharron/keetui/internal/kdbx"
	"github.com/muesli/reflow/wordwrap"
)

// maskedPassword is shown in place of the password until "x" toggles
// visibility.
const maskedPassword = "••••••••"

// entryDoc renders one entry as a key: value document for the detail
// page. The password field is masked unless showPw is set.
func entryDoc(e kdbx.Entry, showPw bool) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(e.Title) + "\n\n")
	for _, f := range e.Fields {
		val := f.Value
		if f.Key == "Password" && !showPw {
			val = maskedPassword
		}
		fmt.Fprintf(&b, "%s%s %s\n", keyStyle.Render(f.Key), dimStyle.Render(":"), valStyle.Render(val))
	}
	if e.GroupPath != "" {
		fmt.Fprintf(&b, "%s%s %s\n", keyStyle.Render("Group"), dimStyle.Render(":"), valStyle.Render(e.GroupPath))
	}
	if e.Tags != "" {
		fmt.Fprintf(&b, "%s%s %s\n", keyStyle.Render("Tags"), dimStyle.Render(":"), valStyle.Render(e.Tags))
	}
	if e.Expires != "" {
		fmt.Fprintf(&b, "%s%s %s\n", keyStyle.Render("Expires"), dimStyle.Render(":"), valStyle.Render(e.Expires))
	}
	if e.Created != "" {
		fmt.Fprintf(&b, "%s%s %s\n", keyStyle.Render("Created"), dimStyle.Render(":"), dimStyle.Render(e.Created))
	}
	if e.Modified != "" {
		fmt.Fprintf(&b, "%s%s %s\n", keyStyle.Render("Modified"), dimStyle.Render(":"), dimStyle.Render(e.Modified))
	}
	if len(e.Attachments) > 0 {
		b.WriteString(keyStyle.Render("Attachments") + dimStyle.Render(":") + "\n")
		for _, a := range e.Attachments {
			fmt.Fprintf(&b, "  %s\n", dimStyle.Render(a))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func wrapText(s string, w int) string {
	if s == "" {
		return ""
	}
	if w < 20 {
		w = 20
	}
	return wordwrap.String(s, w)
}
