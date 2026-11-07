package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bcharron/keetui/internal/tui"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: keetui <database.kdbx>")
		os.Exit(2)
	}
	path := os.Args[1]
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keetui:", err)
		os.Exit(1)
	}
	if fi.IsDir() {
		fmt.Fprintln(os.Stderr, "keetui:", path, "is a directory")
		os.Exit(1)
	}
	p := tea.NewProgram(tui.New(path), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "keetui:", err)
		os.Exit(1)
	}
}
