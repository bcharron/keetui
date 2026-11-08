package kdbx

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func openFixture(t *testing.T, path string) *Database {
	t.Helper()
	db, err := Open(path, "test-password")
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	return db
}

func findEntry(t *testing.T, db *Database, title string) Entry {
	t.Helper()
	for _, e := range db.Entries {
		if e.Title == title {
			return e
		}
	}
	t.Fatalf("entry %q not found (have %d entries)", title, len(db.Entries))
	return Entry{}
}

// checkFixture runs the shared assertions against either fixture
// (AES-KDF+AES v4.0 or Argon2id+ChaCha20 v4.1).
func checkFixture(t *testing.T, path string) {
	db := openFixture(t, path)
	if db.Name != "keetui test database" {
		t.Errorf("Name = %q", db.Name)
	}
	// entries sorted by title case-insensitively:
	got := make([]string, len(db.Entries))
	for i, e := range db.Entries {
		got[i] = e.Title
	}
	wantSorted := []string{"GitHub", "gmail", "Jira", "Old bank", "Router admin", "SSH key backup", "VPN gateway"}
	if len(got) != len(wantSorted) {
		t.Fatalf("got %d entries %v, want %d", len(got), got, len(wantSorted))
	}
	for i := range wantSorted {
		if got[i] != wantSorted[i] {
			t.Fatalf("entry order: got %v, want %v", got, wantSorted)
		}
	}

	gh := findEntry(t, db, "GitHub")
	if gh.Password != "ghp_secret123" {
		t.Errorf("GitHub password = %q", gh.Password)
	}
	if gh.UserName != "octocat" || gh.URL != "https://github.com" || gh.Notes != "main account" {
		t.Errorf("GitHub fields wrong: %+v", gh)
	}
	if gh.Tags != "dev, web" {
		t.Errorf("GitHub tags = %q", gh.Tags)
	}
	if gh.GroupPath != "" {
		t.Errorf("GitHub (root-level) group path = %q, want empty", gh.GroupPath)
	}
	jira := findEntry(t, db, "Jira")
	if jira.GroupPath != "TestDB/Work" {
		t.Errorf("Jira group path = %q", jira.GroupPath)
	}
	vpn := findEntry(t, db, "VPN gateway")
	if vpn.Password != "vpn-secret-789" {
		t.Errorf("VPN password = %q", vpn.Password)
	}
	if vpn.GroupPath != "TestDB/Work/VPN" {
		t.Errorf("VPN group path = %q", vpn.GroupPath)
	}
	old := findEntry(t, db, "Old bank")
	if !old.InRecycleBin {
		t.Errorf("Old bank should be marked as recycle bin")
	}
	if old.Password != "old-pass-000" {
		t.Errorf("Old bank password = %q", old.Password)
	}
	ssh := findEntry(t, db, "SSH key backup")
	if ssh.Expires != "2030-01-01 00:00:00 UTC" {
		t.Errorf("SSH expires = %q", ssh.Expires)
	}
	if !ssh.ExpiresSet {
		t.Errorf("SSH ExpiresSet should be true")
	}
	gh2 := findEntry(t, db, "GitHub")
	if gh2.ExpiresSet || gh2.Expires != "" {
		t.Errorf("GitHub should have no expiry, got %q (set=%v)", gh2.Expires, gh2.ExpiresSet)
	}
	if len(ssh.Attachments) != 1 || ssh.Attachments[0] != "id_rsa_backup.tar.gz" {
		t.Errorf("SSH attachments = %v", ssh.Attachments)
	}
	// protected flag preserved on the Password field
	prot := false
	for _, f := range gh.Fields {
		if f.Key == "Password" {
			prot = f.Protected
		}
	}
	if !prot {
		t.Errorf("Password field not marked protected")
	}
	// history: two versions, newest first, passwords decrypted, and
	// history entries must NOT appear as top-level entries
	if len(gh.Versions) != 2 {
		t.Fatalf("GitHub versions = %d, want 2", len(gh.Versions))
	}
	if gh.Versions[0].Password != "old-password-2" || gh.Versions[1].Password != "old-password-1" {
		t.Errorf("version passwords = %q, %q", gh.Versions[0].Password, gh.Versions[1].Password)
	}
	if gh.Versions[0].Modified <= gh.Versions[1].Modified {
		t.Errorf("versions not newest-first: %q then %q", gh.Versions[0].Modified, gh.Versions[1].Modified)
	}
	if gh.Versions[0].UserName != "octocat-old" {
		t.Errorf("version username = %q", gh.Versions[0].UserName)
	}
	for _, e := range db.Entries {
		if e.UUID == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || e.UUID == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
			t.Errorf("history entry %s leaked into top-level list", e.UUID)
		}
	}
}

func TestOpenAESKDFAES(t *testing.T) {
	checkFixture(t, "../../testdata/test-aes.kdbx")
}

func TestOpenArgon2ChaCha(t *testing.T) {
	checkFixture(t, "../../testdata/test-argon2-chacha.kdbx")
}

func TestOpenV3(t *testing.T) {
	checkFixture(t, "../../testdata/test-v3.kdbx")
}

func TestOpenWrongPassword(t *testing.T) {
	for _, f := range []string{"../../testdata/test-aes.kdbx", "../../testdata/test-argon2-chacha.kdbx", "../../testdata/test-v3.kdbx"} {
		_, err := Open(f, "wrong-password")
		if !errors.Is(err, errWrongPassword) {
			t.Errorf("%s: wrong password gave err=%v, want errWrongPassword", f, err)
		}
	}
}

func TestOpenNotKDBX(t *testing.T) {
	_, err := Open("kdbx_test.go", "x")
	if err == nil {
		t.Fatal("expected error for non-kdbx file")
	}
}

// writeTestFile writes raw bytes to a temp file and returns its path.
func writeTestFile(t *testing.T, b []byte) string {
	t.Helper()
	p := t.TempDir() + "/f.kdbx"
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLegacyKDBDetected(t *testing.T) {
	// KeePass 1.x .kdb: sig1 0x9AA2D903, sig2 0xB54BFB66 (KDBX uses
	// 0xB54BFB67), then a version word.
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[0:4], 0x9AA2D903)
	binary.LittleEndian.PutUint32(b[4:8], 0xB54BFB66)
	_, err := Open(writeTestFile(t, b), "toto")
	if err == nil || !strings.Contains(err.Error(), "legacy KeePass 1.x") {
		t.Fatalf("err = %v, want legacy KDB message", err)
	}
}

func TestKDBX3HeaderAccepted(t *testing.T) {
	// A bare KDBX 3.1 header must pass the version check and fail later
	// (no payload), not with a version error.
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[0:4], 0x9AA2D903)
	binary.LittleEndian.PutUint32(b[4:8], 0xB54BFB67)
	binary.LittleEndian.PutUint32(b[8:12], 0x00030001) // KDBX 3.1
	_, err := Open(writeTestFile(t, b), "toto")
	if err == nil || strings.Contains(err.Error(), "unsupported KDBX version") {
		t.Fatalf("err = %v, want a non-version error", err)
	}
}

func TestKDBX2Rejected(t *testing.T) {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[0:4], 0x9AA2D903)
	binary.LittleEndian.PutUint32(b[4:8], 0xB54BFB67)
	binary.LittleEndian.PutUint32(b[8:12], 0x00020000) // KDBX 2.x
	_, err := Open(writeTestFile(t, b), "toto")
	if err == nil || !strings.Contains(err.Error(), "version 2.0") {
		t.Fatalf("err = %v, want 'version 2.0'", err)
	}
}

func TestTwofishRejected(t *testing.T) {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[0:4], 0x9AA2D903)
	binary.LittleEndian.PutUint32(b[4:8], 0xB54BFB67)
	binary.LittleEndian.PutUint32(b[8:12], 0x00030001)
	// field 2 (cipher ID) with the Twofish UUID
	twofish, _ := hex.DecodeString("ad68f29f576f4bb9a36ad47af965346c")
	pos := 12
	b[pos] = 2
	binary.LittleEndian.PutUint16(b[pos+1:], uint16(len(twofish)))
	copy(b[pos+3:], twofish)
	_, err := Open(writeTestFile(t, b), "toto")
	if err == nil || !strings.Contains(err.Error(), "Twofish") {
		t.Fatalf("err = %v, want Twofish message", err)
	}
}
