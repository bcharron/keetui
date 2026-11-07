package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "pgup":
		return tea.KeyMsg{Type: tea.KeyPgUp}
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

// send feeds messages through the model and returns the resulting
// model plus the last command produced.
func send(m tea.Model, msgs ...tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	for _, msg := range msgs {
		m, cmd = m.Update(msg)
	}
	return m, cmd
}

// typeKeys sends each character of s as its own key press.
func typeKeys(m tea.Model, s string) tea.Model {
	for _, r := range s {
		m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return m
}

func unlock(t *testing.T, m tea.Model, password string) tea.Model {
	t.Helper()
	m, _ = send(m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m = typeKeys(m, password)
	m, cmd := send(m, keyMsg("enter"))
	if cmd == nil {
		t.Fatal("enter produced no command")
	}
	m, _ = send(m, cmd())
	return m
}

func topPage(m tea.Model) Page {
	return m.(App).top()
}

func TestUnlockShowsEntries(t *testing.T) {
	m := unlock(t, New("../../testdata/test-aes.kdbx"), "test-password")
	p := topPage(m)
	if _, ok := p.(*entriesPage); !ok {
		t.Fatalf("after unlock, top page is %T, want *entriesPage", p)
	}
	v := p.View()
	for _, want := range []string{"GitHub", "gmail", "VPN gateway", "[bin] Old bank", "7 entries"} {
		if !strings.Contains(v, want) {
			t.Errorf("list view missing %q:\n%s", want, v)
		}
	}
	// top bar shows the file and the count
	av := m.(App).View()
	if !strings.Contains(av, "test-aes.kdbx") || !strings.Contains(av, "7 entries") {
		t.Errorf("top bar missing path/count:\n%s", av)
	}
}

func TestUnlockArgon2ChaChaFixture(t *testing.T) {
	m := unlock(t, New("../../testdata/test-argon2-chacha.kdbx"), "test-password")
	if _, ok := topPage(m).(*entriesPage); !ok {
		t.Fatalf("argon2/chacha fixture did not unlock, top is %T", topPage(m))
	}
}

func TestWrongPasswordStaysOnUnlock(t *testing.T) {
	m := unlock(t, New("../../testdata/test-aes.kdbx"), "nope")
	p := topPage(m)
	pp, ok := p.(*passwordPage)
	if !ok {
		t.Fatalf("wrong password left %T, want *passwordPage", p)
	}
	if pp.err == nil {
		t.Error("expected error on password page")
	}
	if !strings.Contains(pp.View(), "wrong master password") {
		t.Errorf("error not shown:\n%s", pp.View())
	}
	// retry with the right password works
	m = typeKeys(m, "test-password")
	m, cmd := send(m, keyMsg("enter"))
	m, _ = send(m, cmd())
	if _, ok := topPage(m).(*entriesPage); !ok {
		t.Fatalf("retry did not unlock, top is %T", topPage(m))
	}
}

func TestFilterNarrowsByTitle(t *testing.T) {
	m := unlock(t, New("../../testdata/test-aes.kdbx"), "test-password")
	m = typeKeys(m, "git")
	v := topPage(m).View()
	if !strings.Contains(v, "GitHub") {
		t.Errorf("filter 'git' should keep GitHub:\n%s", v)
	}
	if strings.Contains(v, "gmail") || strings.Contains(v, "Jira") {
		t.Errorf("filter 'git' should drop others:\n%s", v)
	}
	if !strings.Contains(v, "1 entry") {
		t.Errorf("count should be '1 entry':\n%s", v)
	}
	// no matches
	m = typeKeys(m, "zzz")
	if !strings.Contains(topPage(m).View(), "(no matches)") {
		t.Errorf("expected (no matches):\n%s", topPage(m).View())
	}
	// esc clears the query
	m, _ = send(m, keyMsg("esc"))
	v = topPage(m).View()
	if !strings.Contains(v, "7 entries") {
		t.Errorf("esc should clear filter back to all entries:\n%s", v)
	}
	// backspace edits the query
	m = typeKeys(m, "gm")
	m, _ = send(m, keyMsg("backspace"))
	v = topPage(m).View()
	if !strings.Contains(v, "gmail") || !strings.Contains(v, "GitHub") {
		t.Errorf("query 'g' should match GitHub and gmail:\n%s", v)
	}
}

func TestEnterDetailAndTogglePassword(t *testing.T) {
	m := unlock(t, New("../../testdata/test-aes.kdbx"), "test-password")
	// first entry sorted by title is "GitHub"
	m, cmd := send(m, keyMsg("enter"))
	if cmd == nil {
		t.Fatal("enter on list produced no command")
	}
	m, _ = send(m, cmd()) // pushMsg
	p := topPage(m)
	dp, ok := p.(*entryPage)
	if !ok {
		t.Fatalf("top page is %T, want *entryPage", p)
	}
	v := dp.View()
	if !strings.Contains(v, "octocat") || !strings.Contains(v, "https://github.com") {
		t.Errorf("detail missing fields:\n%s", v)
	}
	if !strings.Contains(v, maskedPassword) {
		t.Errorf("password should be masked:\n%s", v)
	}
	if strings.Contains(v, "ghp_secret123") {
		t.Errorf("password leaked before toggle:\n%s", v)
	}
	// x reveals
	m, _ = send(m, keyMsg("x"))
	if !strings.Contains(topPage(m).View(), "ghp_secret123") {
		t.Errorf("x should reveal password:\n%s", topPage(m).View())
	}
	// x hides again
	m, _ = send(m, keyMsg("x"))
	if strings.Contains(topPage(m).View(), "ghp_secret123") {
		t.Errorf("second x should hide password:\n%s", topPage(m).View())
	}
	// esc goes back to the list
	m, _ = send(m, keyMsg("esc"))
	if _, ok := topPage(m).(*entriesPage); !ok {
		t.Fatalf("esc should return to list, top is %T", topPage(m))
	}
}

func TestNavigation(t *testing.T) {
	m := unlock(t, New("../../testdata/test-aes.kdbx"), "test-password")
	ep := topPage(m).(*entriesPage)
	m, _ = send(m, keyMsg("down"), keyMsg("down"))
	if ep.cur != 2 {
		t.Errorf("after 2x down cur=%d, want 2", ep.cur)
	}
	m, _ = send(m, keyMsg("pgdown"))
	if ep.cur != len(ep.visible())-1 {
		t.Errorf("pgdown should jump to last, cur=%d", ep.cur)
	}
	m, _ = send(m, keyMsg("pgup"))
	if ep.cur != 0 {
		t.Errorf("pgup should jump to first, cur=%d", ep.cur)
	}
	m, _ = send(m, keyMsg("up"))
	if ep.cur != 0 {
		t.Errorf("up at top should stay, cur=%d", ep.cur)
	}
}

func TestCtrlUClearsQuery(t *testing.T) {
	m := unlock(t, New("../../testdata/test-aes.kdbx"), "test-password")
	m = typeKeys(m, "git")
	if !strings.Contains(topPage(m).View(), "1 entry") {
		t.Fatalf("expected filtered view")
	}
	m, _ = send(m, keyMsg("ctrl+u"))
	v := topPage(m).View()
	if !strings.Contains(v, "7 entries") {
		t.Errorf("ctrl+u should clear the query back to all entries:\n%s", v)
	}
}

func TestFuzzyFilter(t *testing.T) {
	m := unlock(t, New("../../testdata/test-aes.kdbx"), "test-password")
	// "gth" is not a substring of "GitHub" but is a subsequence
	m = typeKeys(m, "gth")
	v := topPage(m).View()
	if !strings.Contains(v, "GitHub") {
		t.Errorf("fuzzy query 'gth' should match GitHub:\n%s", v)
	}
	if strings.Contains(v, "gmail") {
		t.Errorf("fuzzy query 'gth' should not match gmail:\n%s", v)
	}
	// scattered but in-order
	m, _ = send(m, keyMsg("ctrl+u"))
	m = typeKeys(m, "vpngw")
	if !strings.Contains(topPage(m).View(), "VPN gateway") {
		t.Errorf("fuzzy query 'vpngw' should match 'VPN gateway'")
	}
	// out of order does not match
	m, _ = send(m, keyMsg("ctrl+u"))
	m = typeKeys(m, "bgth")
	if strings.Contains(topPage(m).View(), "GitHub") {
		t.Errorf("out-of-order query 'bgth' should not match GitHub")
	}
}

func TestEscOnEmptyQueryQuits(t *testing.T) {
	m := unlock(t, New("../../testdata/test-aes.kdbx"), "test-password")
	_, cmd := send(m, keyMsg("esc"))
	if cmd == nil {
		t.Fatal("esc on empty query should quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("esc on empty query should quit, got %T", cmd())
	}
}
