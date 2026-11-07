package kdbx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

// errWrongPassword is returned when the header HMAC does not verify,
// which for a well-formed file means the master password was wrong.
var errWrongPassword = errors.New("wrong master password or corrupted file")

// decryptPayload verifies the header hash/HMAC and the HMAC block
// stream of a KDBX4 file, decrypts the payload and returns it.
//
// Layout after the header fields: SHA-256(header), HMAC-SHA-256 of the
// header (keyed with the block key for index 2^64-1), then blocks of
// [32-byte HMAC][4-byte LE size][size bytes ciphertext] until a block
// with size 0. The ciphertext blocks form one continuous cipher
// stream.
func decryptPayload(raw []byte, off int, h *header, transformed []byte) ([]byte, error) {
	finalKey, hmacKey := deriveKeys(h.masterSeed, transformed)

	headerData := raw[:off]
	if off+64 > len(raw) {
		return nil, errors.New("truncated header checksum")
	}
	headerHash := sha256.Sum256(headerData)
	if !hmac.Equal(headerHash[:], raw[off:off+32]) {
		return nil, errors.New("header SHA-256 mismatch (file corrupted)")
	}
	headerMac := hmacSHA256(headerHmacKey(hmacKey), headerData)
	if !hmac.Equal(headerMac, raw[off+32:off+64]) {
		return nil, errWrongPassword
	}

	// Walk the HMAC block stream, verifying each block.
	pos := off + 64
	var cipherAll []byte
	for index := uint64(0); ; index++ {
		if pos+36 > len(raw) {
			return nil, errors.New("truncated block header")
		}
		mac := raw[pos : pos+32]
		size := binary.LittleEndian.Uint32(raw[pos+32 : pos+36])
		if pos+36+int(size) > len(raw) {
			return nil, errors.New("truncated block data")
		}
		data := raw[pos+36 : pos+36+int(size)]

		var iB [8]byte
		binary.LittleEndian.PutUint64(iB[:], index)
		msg := make([]byte, 0, 12+len(data))
		msg = append(msg, iB[:]...)
		msg = append(msg, raw[pos+32:pos+36]...)
		msg = append(msg, data...)
		if !hmac.Equal(mac, hmacSHA256(blockHmacKey(hmacKey, index), msg)) {
			return nil, fmt.Errorf("block %d HMAC mismatch (file corrupted)", index)
		}
		cipherAll = append(cipherAll, data...)
		pos += 36 + int(size)
		if size == 0 {
			break
		}
	}

	// Decrypt the continuous cipher stream.
	plain := make([]byte, len(cipherAll))
	switch h.cipher {
	case cipherAES256:
		if len(h.encIV) != aes.BlockSize {
			return nil, errors.New("bad AES encryption IV length")
		}
		if len(cipherAll)%aes.BlockSize != 0 {
			return nil, errors.New("AES payload not a multiple of the block size")
		}
		c, err := aes.NewCipher(finalKey)
		if err != nil {
			return nil, err
		}
		cipher.NewCBCDecrypter(c, h.encIV).CryptBlocks(plain, cipherAll)
		plain = pkcs7Unpad(plain)
	case cipherChaCha20:
		if len(h.encIV) != 12 {
			return nil, errors.New("bad ChaCha20 nonce length")
		}
		c, err := chacha20.NewUnauthenticatedCipher(finalKey, h.encIV)
		if err != nil {
			return nil, err
		}
		c.XORKeyStream(plain, cipherAll)
	default:
		return nil, errors.New("unknown cipher")
	}
	return plain, nil
}

// decryptPayloadV3 decrypts a KDBX 3.1 payload. Layout: one continuous
// AES-CBC stream (finalKey = SHA-256(masterSeed || transformed), IV
// from the header). The first 32 plaintext bytes must equal the
// header's StreamStartBytes (this is the password check); the rest is
// a hashed block stream of [4-byte LE index][32-byte SHA-256 of the
// block's plaintext][4-byte LE size][data], ending with a size-0 block
// whose hash is 32 zero bytes.
func decryptPayloadV3(raw []byte, off int, h *header, transformed []byte) ([]byte, error) {
	if h.cipher != cipherAES256 {
		return nil, errors.New("KDBX 3 supports only AES-256 here (Twofish unsupported)")
	}
	if len(h.encIV) != aes.BlockSize {
		return nil, errors.New("bad AES encryption IV length")
	}
	payload := raw[off:]
	if len(payload)%aes.BlockSize != 0 {
		return nil, errors.New("AES payload not a multiple of the block size")
	}
	finalKey := sha256.Sum256(append(append([]byte{}, h.masterSeed...), transformed...))
	c, err := aes.NewCipher(finalKey[:])
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(payload))
	cipher.NewCBCDecrypter(c, h.encIV).CryptBlocks(plain, payload)

	if len(plain) < 32 || !bytes.Equal(plain[:32], h.streamStartBytes) {
		return nil, errWrongPassword
	}

	pos := 32
	var out []byte
	for index := uint32(0); ; index++ {
		if pos+40 > len(plain) {
			return nil, errors.New("truncated block header")
		}
		idx := binary.LittleEndian.Uint32(plain[pos : pos+4])
		hash := plain[pos+4 : pos+36]
		size := binary.LittleEndian.Uint32(plain[pos+36 : pos+40])
		if idx != index {
			return nil, fmt.Errorf("block index mismatch: got %d, want %d", idx, index)
		}
		if pos+40+int(size) > len(plain) {
			return nil, errors.New("truncated block data")
		}
		data := plain[pos+40 : pos+40+int(size)]
		pos += 40 + int(size)
		if size == 0 {
			break // final block; its hash is 32 zero bytes
		}
		sum := sha256.Sum256(data)
		if !bytes.Equal(sum[:], hash) {
			return nil, fmt.Errorf("content hash mismatch in block %d", index)
		}
		out = append(out, data...)
	}
	return out, nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
