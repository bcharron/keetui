package kdbxstream

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/salsa20"
)

// The block function at counter 0 must match x/crypto's salsa20.
func TestSalsa20AgainstXCrypto(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i * 7)
	}
	mine := block(&key, SalsaIV[:], 0)
	ref := make([]byte, 64)
	salsa20.XORKeyStream(ref, make([]byte, 64), SalsaIV[:], &key)
	if !bytes.Equal(mine[:], ref) {
		t.Fatalf("block mismatch:\nmine %x\nref  %x", mine, ref)
	}
}

// The stream must continue across calls (keystream block 1 onward).
func TestSalsa20Continuous(t *testing.T) {
	var key [32]byte
	copy(key[:], "stream-key-material-32-bytes!")
	s := &Stream{bufPos: 64}
	copy(s.key[:], key[:])
	// 200 bytes of keystream = blocks 0..2 plus 8 bytes of block 3
	src := make([]byte, 200)
	dst := make([]byte, 200)
	s.XOR(dst, src)
	var want [200]byte
	for b := 0; b < 3; b++ {
		blk := block(&key, SalsaIV[:], uint64(b))
		copy(want[b*64:], blk[:])
	}
	last := block(&key, SalsaIV[:], 3)
	copy(want[192:], last[:8])
	if !bytes.Equal(dst, want[:]) {
		t.Fatal("continuous keystream mismatch")
	}
}
