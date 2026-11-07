package kdbx

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
)

// compositeKey is the composite key for a password-only database:
// SHA-256 of the SHA-256 of the UTF-8 password (KeePass hashes the
// password once as the "password key", then hashes all key components
// again into the composite key). No key files are supported.
func compositeKey(password string) []byte {
	inner := sha256.Sum256([]byte(password))
	h := sha256.Sum256(inner[:])
	return h[:]
}

// aesKdfTransform runs the KeePass AES-KDF: the 32-byte key is
// encrypted with AES-256 in ECB mode (no IV, no padding) once per
// round under the seed, and the result is hashed once with SHA-256.
func aesKdfTransform(seed, key []byte, rounds uint64) ([]byte, error) {
	if len(seed) != 32 {
		return nil, errors.New("AES-KDF seed must be 32 bytes")
	}
	c, err := aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}
	block := append([]byte(nil), key...)
	for i := uint64(0); i < rounds; i++ {
		for off := 0; off+aes.BlockSize <= len(block); off += aes.BlockSize {
			c.Encrypt(block[off:off+aes.BlockSize], block[off:off+aes.BlockSize])
		}
	}
	h := sha256.Sum256(block)
	return h[:], nil
}

// deriveKeys derives the two KDBX4 stream keys from the master seed and
// the KDF-transformed composite key:
//
//	finalKey = SHA-256(masterSeed || transformed)   (32 bytes, cipher key)
//	hmacKey  = SHA-512(masterSeed || transformed || 0x01)  (64 bytes, "K")
func deriveKeys(masterSeed, transformed []byte) (finalKey, hmacKey []byte) {
	fh := sha256.New()
	fh.Write(masterSeed)
	fh.Write(transformed)
	finalKey = fh.Sum(nil)

	kh := sha512.New()
	kh.Write(masterSeed)
	kh.Write(transformed)
	kh.Write([]byte{0x01})
	hmacKey = kh.Sum(nil)
	return finalKey, hmacKey
}

// blockHmacKey computes the per-block HMAC key Ki = SHA-512(LE64(i) || K).
func blockHmacKey(hmacKey []byte, index uint64) []byte {
	var iB [8]byte
	binary.LittleEndian.PutUint64(iB[:], index)
	h := sha512.New()
	h.Write(iB[:])
	h.Write(hmacKey)
	return h.Sum(nil)
}

// headerHmacKey is the key for the header's HMAC: Ki with i = 2^64-1.
func headerHmacKey(hmacKey []byte) []byte {
	return blockHmacKey(hmacKey, ^uint64(0))
}

// kdfCandidates applies the file's KDF to the composite key and returns
// candidate transformed keys, most likely first. The candidates are
// produced lazily so the caller can stop at the first one that
// verifies, instead of paying for every Argon2 variant up front.
//
// For Argon2 the KDF UUID names the variant (d or id); the others are
// kept as fallbacks for writers that mislabel it.
func kdfCandidates(h *header, composite []byte) ([]func() []byte, error) {
	if h.major == 3 {
		// KDBX 3 always uses AES-KDF; seed and rounds are header fields.
		if len(h.transformSeed) != 32 {
			return nil, errors.New("missing or bad transform seed in header")
		}
		seed, rounds := h.transformSeed, h.transformRounds
		return []func() []byte{func() []byte {
			t, err := aesKdfTransform(seed, composite, rounds)
			if err != nil {
				return nil
			}
			return t
		}}, nil
	}
	switch h.kdf {
	case kdfAES:
		seed, ok := h.kdfParams.bytes("S")
		if !ok {
			return nil, errors.New("AES-KDF parameters missing seed S")
		}
		rounds, ok := h.kdfParams.u64("R")
		if !ok {
			return nil, errors.New("AES-KDF parameters missing rounds R")
		}
		return []func() []byte{func() []byte {
			t, err := aesKdfTransform(seed, composite, rounds)
			if err != nil {
				return nil
			}
			return t
		}}, nil
	case kdfArgon2D, kdfArgon2ID:
		salt, ok := h.kdfParams.bytes("S")
		if !ok {
			return nil, errors.New("Argon2 parameters missing salt S")
		}
		iters, ok := h.kdfParams.u64("I")
		if !ok {
			return nil, errors.New("Argon2 parameters missing iterations I")
		}
		memBytes, ok := h.kdfParams.u64("M")
		if !ok {
			return nil, errors.New("Argon2 parameters missing memory M")
		}
		threads, ok := h.kdfParams.u32("P")
		if !ok {
			return nil, errors.New("Argon2 parameters missing parallelism P")
		}
		version, ok := h.kdfParams.u32("V")
		if !ok {
			version = 0x13
		}
		if version != 0x10 && version != 0x13 {
			return nil, fmt.Errorf("unsupported Argon2 version %d", version)
		}
		if threads < 1 || threads > 255 {
			return nil, fmt.Errorf("bad Argon2 parallelism %d", threads)
		}
		// The file stores the memory size in bytes; Argon2 takes KiB.
		memKiB := memBytes / 1024
		if memKiB > 1<<24 {
			return nil, fmt.Errorf("Argon2 memory %d bytes unreasonably large", memBytes)
		}
		var variants []argon2Variant
		if h.kdf == kdfArgon2D {
			variants = []argon2Variant{argon2d, argon2id, argon2i}
		} else {
			variants = []argon2Variant{argon2id, argon2d, argon2i}
		}
		out := make([]func() []byte, len(variants))
		for i, v := range variants {
			v := v
			out[i] = func() []byte {
				return argon2Key(v, version, composite, salt, nil, nil,
					uint32(iters), uint32(memKiB), uint8(threads), 32)
			}
		}
		return out, nil
	}
	return nil, errors.New("no KDF parameters in header")
}

func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad removes and validates PKCS#7 padding; on invalid padding
// the data is returned unchanged (the content hashes already
// authenticated it).
func pkcs7Unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	pad := int(b[len(b)-1])
	if pad < 1 || pad > 16 || pad > len(b) {
		return b
	}
	for _, c := range b[len(b)-pad:] {
		if int(c) != pad {
			return b
		}
	}
	return b[:len(b)-pad]
}
