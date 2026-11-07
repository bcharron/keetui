// Package kdbxstream provides the seekable Salsa20 keystream used for
// KDBX inner random streams: KeePass encrypts every protected value
// with one continuous Salsa20 stream (fixed nonce, block counter
// incrementing across the whole document), so decryption must consume
// the keystream in document order. x/crypto's salsa20.XORKeyStream
// always restarts the counter, so the block function is implemented
// here with an explicit counter.
package kdbxstream

import (
	"crypto/sha256"
	"encoding/binary"
)

// SalsaIV is the fixed IV KeePass uses for the Salsa20 inner stream.
var SalsaIV = [8]byte{0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A}

// Stream is a continuous Salsa20 keystream. The cipher key is
// SHA-256 of the stream key stored in the KDBX inner header.
type Stream struct {
	key     [32]byte
	counter uint64
	buf     [64]byte
	bufPos  int
}

// NewSalsaStream creates a stream from the raw inner-header stream key.
func NewSalsaStream(streamKey []byte) *Stream {
	h := sha256.Sum256(streamKey)
	s := &Stream{bufPos: 64} // force refill on first use
	copy(s.key[:], h[:])
	return s
}

// XOR consumes the next len(src) keystream bytes into dst.
func (s *Stream) XOR(dst, src []byte) {
	for len(src) > 0 {
		if s.bufPos == 64 {
			s.buf = block(&s.key, SalsaIV[:], s.counter)
			s.counter++
			s.bufPos = 0
		}
		n := copy(dst, s.buf[s.bufPos:])
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ s.buf[s.bufPos+i]
		}
		s.bufPos += n
		dst = dst[n:]
		src = src[n:]
	}
}

func block(key *[32]byte, nonce []byte, counter uint64) [64]byte {
	var s, orig [16]uint32
	s[0], s[5], s[10], s[15] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i := 0; i < 4; i++ {
		s[1+i] = binary.LittleEndian.Uint32(key[i*4:])
		s[11+i] = binary.LittleEndian.Uint32(key[16+i*4:])
	}
	s[6] = binary.LittleEndian.Uint32(nonce[0:4])
	s[7] = binary.LittleEndian.Uint32(nonce[4:8])
	s[8] = uint32(counter)
	s[9] = uint32(counter >> 32)
	orig = s

	qr := func(a, b, c, d int) {
		s[b] ^= rotl(s[a]+s[d], 7)
		s[c] ^= rotl(s[b]+s[a], 9)
		s[d] ^= rotl(s[c]+s[b], 13)
		s[a] ^= rotl(s[d]+s[c], 18)
	}
	for i := 0; i < 10; i++ {
		qr(0, 4, 8, 12)
		qr(5, 9, 13, 1)
		qr(10, 14, 2, 6)
		qr(15, 3, 7, 11)
		qr(0, 1, 2, 3)
		qr(5, 6, 7, 4)
		qr(10, 11, 8, 9)
		qr(15, 12, 13, 14)
	}
	var out [64]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], s[i]+orig[i])
	}
	return out
}

func rotl(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }
