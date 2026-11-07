package kdbx

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/argon2"
)

// RFC 9106 Appendix B test vectors: password 32x0x01, salt 16x0x02,
// secret 8x0x03, associated data 12x0x04, m=32 KiB, t=3, p=4, tag 32,
// version 19.
func TestArgon2RFC9106(t *testing.T) {
	password := bytes.Repeat([]byte{0x01}, 32)
	salt := bytes.Repeat([]byte{0x02}, 16)
	secret := bytes.Repeat([]byte{0x03}, 8)
	data := bytes.Repeat([]byte{0x04}, 12)
	vectors := []struct {
		variant argon2Variant
		want    string
	}{
		{argon2d, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"},
		{argon2i, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"},
		{argon2id, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"},
	}
	for _, v := range vectors {
		got := argon2Key(v.variant, 0x13, password, salt, secret, data, 3, 32, 4, 32)
		want, _ := hex.DecodeString(v.want)
		if !bytes.Equal(got, want) {
			t.Errorf("variant %d: got %x, want %x", v.variant, got, want)
		}
	}
}

// Cross-check the i and id variants against x/crypto's reference
// implementation on pseudo-random inputs (version 1.3, no secret).
func TestArgon2AgainstXCrypto(t *testing.T) {
	password := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	for _, c := range []struct {
		time, mem uint32
		threads   uint8
	}{
		{1, 64, 1},
		{3, 32, 4},
		{2, 256, 2},
	} {
		wantI := argon2.Key(password, salt, c.time, c.mem, c.threads, 32)
		gotI := argon2Key(argon2i, 0x13, password, salt, nil, nil, c.time, c.mem, c.threads, 32)
		if !bytes.Equal(wantI, gotI) {
			t.Errorf("argon2i mismatch at %+v: got %x want %x", c, gotI, wantI)
		}
		wantID := argon2.IDKey(password, salt, c.time, c.mem, c.threads, 32)
		gotID := argon2Key(argon2id, 0x13, password, salt, nil, nil, c.time, c.mem, c.threads, 32)
		if !bytes.Equal(wantID, gotID) {
			t.Errorf("argon2id mismatch at %+v: got %x want %x", c, gotID, wantID)
		}
	}
}
