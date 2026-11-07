package kdbx

// Argon2 (RFC 9106) as used by the KDBX4 KDF. Implemented here rather
// than via golang.org/x/crypto/argon2 because KDBX files in the wild
// predominantly use Argon2d, which x/crypto does not expose. Only the
// Blake2b primitive is taken from x/crypto; the Argon2 construction
// itself is written out below.

import (
	"encoding/binary"
	"math/bits"
	"sync"

	"golang.org/x/crypto/blake2b"
)

type argon2Variant uint32

const (
	argon2d  argon2Variant = 0
	argon2i  argon2Variant = 1
	argon2id argon2Variant = 2
)

const (
	argon2Qwords     = 128 // one 1024-byte block as 128 uint64 words
	argon2SyncPoints = 4
)

type argon2Block [argon2Qwords]uint64

// argon2Key derives keyLen bytes of key material. memory is in KiB,
// version is 0x10 (1.0) or 0x13 (1.3). secret and data are the optional
// Argon2 inputs KeePass leaves empty; they exist for RFC test vectors.
func argon2Key(variant argon2Variant, version uint32, password, salt, secret, data []byte, iterations, memory uint32, threads uint8, keyLen uint32) []byte {
	if iterations < 1 || threads < 1 {
		panic("argon2: bad cost parameters")
	}
	p := uint32(threads)

	// H0 = Blake2b-512 of the little-endian parameter block.
	h, _ := blake2b.New512(nil)
	le32 := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		h.Write(b[:])
	}
	le32(p)
	le32(keyLen)
	le32(memory)
	le32(iterations)
	le32(version)
	le32(uint32(variant))
	le32(uint32(len(password)))
	h.Write(password)
	le32(uint32(len(salt)))
	h.Write(salt)
	le32(uint32(len(secret)))
	h.Write(secret)
	le32(uint32(len(data)))
	h.Write(data)
	var h0 [64]byte
	h.Sum(h0[:0])

	// Memory size adjustments per RFC 9106 section 3.2.
	if memory < 2*argon2SyncPoints*p {
		memory = 2 * argon2SyncPoints * p
	}
	memory = memory / (argon2SyncPoints * p) * (argon2SyncPoints * p)
	laneLen := memory / p
	segLen := laneLen / argon2SyncPoints

	B := make([]argon2Block, memory)
	var tmp [1024]byte
	for lane := uint32(0); lane < p; lane++ {
		for j := uint32(0); j < 2; j++ {
			var in [72]byte
			copy(in[:64], h0[:])
			binary.LittleEndian.PutUint32(in[64:68], j)
			binary.LittleEndian.PutUint32(in[68:72], lane)
			blake2bHashLong(tmp[:], in[:])
			for i := 0; i < argon2Qwords; i++ {
				B[lane*laneLen+j][i] = binary.LittleEndian.Uint64(tmp[i*8:])
			}
		}
	}

	// Lanes within a slice are independent (references only reach
	// other lanes' already-finished segments), so they run in parallel.
	for pass := uint32(0); pass < iterations; pass++ {
		for slice := uint32(0); slice < argon2SyncPoints; slice++ {
			var wg sync.WaitGroup
			for lane := uint32(0); lane < p; lane++ {
				wg.Add(1)
				go func(lane uint32) {
					defer wg.Done()
					argon2FillSegment(B, pass, slice, lane, memory, laneLen, segLen, iterations, p, variant, version)
				}(lane)
			}
			wg.Wait()
		}
	}

	// Final block: XOR of the last block of every lane.
	final := B[memory-1]
	for lane := uint32(0); lane+1 < p; lane++ {
		last := B[lane*laneLen+laneLen-1]
		for i := range final {
			final[i] ^= last[i]
		}
	}
	for i, v := range final {
		binary.LittleEndian.PutUint64(tmp[i*8:], v)
	}
	key := make([]byte, keyLen)
	blake2bHashLong(key, tmp[:])
	return key
}

func argon2FillSegment(B []argon2Block, pass, slice, lane, memory, laneLen, segLen, passes, p uint32, variant argon2Variant, version uint32) {
	dataIndependent := variant == argon2i || (variant == argon2id && pass == 0 && slice < argon2SyncPoints/2)

	var in, addresses, zero argon2Block
	if dataIndependent {
		in[0] = uint64(pass)
		in[1] = uint64(lane)
		in[2] = uint64(slice)
		in[3] = uint64(memory)
		in[4] = uint64(passes)
		in[5] = uint64(variant)
	}

	index := uint32(0)
	if pass == 0 && slice == 0 {
		index = 2 // first two blocks of each lane are pre-filled
		if dataIndependent {
			in[6]++
			argon2Compress(&addresses, &in, &zero, false)
			argon2Compress(&addresses, &addresses, &zero, false)
		}
	}

	offset := lane*laneLen + slice*segLen + index
	for ; index < segLen; index, offset = index+1, offset+1 {
		prev := offset - 1
		if index == 0 && slice == 0 {
			prev += laneLen // wrap to the last block of the lane
		}
		var rnd uint64
		if dataIndependent {
			if index%argon2Qwords == 0 {
				in[6]++
				argon2Compress(&addresses, &in, &zero, false)
				argon2Compress(&addresses, &addresses, &zero, false)
			}
			rnd = addresses[index%argon2Qwords]
		} else {
			rnd = B[prev][0]
		}
		ref := argon2IndexAlpha(rnd, laneLen, segLen, p, pass, slice, lane, index, version)
		// From pass 1 on, blocks already hold a value: the compression
		// result is XORed into the existing block.
		argon2Compress(&B[offset], &B[prev], &B[ref], pass > 0)
	}
}

func argon2IndexAlpha(rand uint64, laneLen, segLen, p, pass, slice, lane, index uint32, version uint32) uint32 {
	refLane := uint32(rand>>32) % p
	if pass == 0 && slice == 0 {
		refLane = lane
	}
	m, s := uint64(3*segLen), uint64(((slice+1)%argon2SyncPoints)*segLen)
	if lane == refLane {
		m += uint64(index)
	}
	if pass == 0 {
		m, s = uint64(slice*segLen), 0
		if slice == 0 || lane == refLane {
			m += uint64(index)
		}
	}
	// Version 1.3 additionally excludes the current block when the
	// reference stays in the same lane; 1.0 only did so at segment start.
	if index == 0 || (version == 0x13 && lane == refLane) {
		m--
	}
	// phi: square the low 32 bits, scale into [0, m), mirror around m.
	low := rand & 0xFFFFFFFF
	low = (low * low) >> 32
	low = (low * m) >> 32
	return refLane*laneLen + uint32((s+m-(low+1))%uint64(laneLen))
}

// argon2Compress is the Argon2 compression function G:
// out = x ^ y ^ P(x ^ y), where P applies one Blake2b round to each
// row and then to each column of the 8x16 word matrix. With xor set,
// the result is XORed into out instead of overwriting it (used from
// pass 1 on, where blocks already hold a value).
func argon2Compress(out, x, y *argon2Block, xor bool) {
	var t argon2Block
	for i := range t {
		t[i] = x[i] ^ y[i]
	}
	for i := 0; i < argon2Qwords; i += 16 {
		argon2Round((*[16]uint64)(t[i:]))
	}
	for i := 0; i < 16; i += 2 {
		var col [16]uint64
		for j := 0; j < 8; j++ {
			col[2*j] = t[i+16*j]
			col[2*j+1] = t[i+1+16*j]
		}
		argon2Round(&col)
		for j := 0; j < 8; j++ {
			t[i+16*j] = col[2*j]
			t[i+1+16*j] = col[2*j+1]
		}
	}
	if xor {
		for i := range out {
			out[i] ^= x[i] ^ y[i] ^ t[i]
		}
	} else {
		for i := range out {
			out[i] = x[i] ^ y[i] ^ t[i]
		}
	}
}

// argon2Round applies one Blake2b round (column + diagonal G steps)
// with the Argon2 "blamka" multiplication tweak to 16 words.
func argon2Round(v *[16]uint64) {
	g := func(a, b, c, d int) {
		v[a] += v[b] + 2*uint64(uint32(v[a]))*uint64(uint32(v[b]))
		v[d] ^= v[a]
		v[d] = bits.RotateLeft64(v[d], -32)
		v[c] += v[d] + 2*uint64(uint32(v[c]))*uint64(uint32(v[d]))
		v[b] ^= v[c]
		v[b] = bits.RotateLeft64(v[b], -24)
		v[a] += v[b] + 2*uint64(uint32(v[a]))*uint64(uint32(v[b]))
		v[d] ^= v[a]
		v[d] = bits.RotateLeft64(v[d], -16)
		v[c] += v[d] + 2*uint64(uint32(v[c]))*uint64(uint32(v[d]))
		v[b] ^= v[c]
		v[b] = bits.RotateLeft64(v[b], -63)
	}
	g(0, 4, 8, 12)
	g(1, 5, 9, 13)
	g(2, 6, 10, 14)
	g(3, 7, 11, 15)
	g(0, 5, 10, 15)
	g(1, 6, 11, 12)
	g(2, 7, 8, 13)
	g(3, 4, 9, 14)
}

// blake2bHashLong is the variable-length hash H' from the Argon2
// reference: Blake2b over LE32(len(out)) || in, chained in 64-byte
// blocks, emitting 32 bytes per block, with the final partial block
// hashed at its own digest length.
func blake2bHashLong(out, in []byte) {
	var lb [4]byte
	binary.LittleEndian.PutUint32(lb[:], uint32(len(out)))
	if len(out) <= 64 {
		h, _ := blake2b.New(len(out), nil)
		h.Write(lb[:])
		h.Write(in)
		h.Sum(out[:0])
		return
	}
	h, _ := blake2b.New512(nil)
	h.Write(lb[:])
	h.Write(in)
	var v [64]byte
	h.Sum(v[:0])
	n := copy(out, v[:32])
	for len(out)-n > 64 {
		h.Reset()
		h.Write(v[:])
		h.Sum(v[:0])
		n += copy(out[n:], v[:32])
	}
	hf, _ := blake2b.New(len(out)-n, nil)
	hf.Write(v[:])
	// Sum appends; copy explicitly since out[n:] may lack spare capacity.
	copy(out[n:], hf.Sum(nil))
}
