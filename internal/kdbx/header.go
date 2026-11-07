package kdbx

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// KDBX on-disk constants.
const (
	kdbxSignature1 = 0x9AA2D903
	kdbxSignature2 = 0xB54BFB67

	// Second signature of the legacy KeePass 1.x .kdb format, which
	// differs from KDBX's in the last bit.
	legacyKDBSignature2 = 0xB54BFB66

	// Twofish cipher UUID (KDBX 3 only): not supported, the cipher is
	// in neither the stdlib nor x/crypto.
	uuidTwofish = "ad68f29f-576f-4bb9-a36a-d47af965346c"

	// KDBX 3 header fields absent in KDBX 4 (which moves them into the
	// KDF parameters / inner header instead).
	fieldTransformSeed       = 0x05
	fieldTransformRounds     = 0x06
	fieldProtectedStreamKey  = 0x08
	fieldStreamStartBytes    = 0x09
	fieldInnerRandomStreamID = 0x0A

	fieldEndOfHeader      = 0x00
	fieldCipherID         = 0x02
	fieldCompressionFlags = 0x03
	fieldMasterSeed       = 0x04
	fieldEncryptionIV     = 0x07
	fieldKdfParameters    = 0x0B
)

// Known UUIDs in canonical (RFC 4122) form, as defined by KeePassXC's
// KeePass2.cpp. KDBX files store the 16 raw bytes; KeePass writes them
// in string order, but some writers use the .NET Guid mixed-endian
// order, so both are recognized.
var knownUUIDs = map[string]string{
	"31c1f2e6-bf71-4350-be58-05216afc5aff": "cipher-aes256",
	"d6038a2b-8b6f-4cb5-a524-339a31dbb59a": "cipher-chacha20",
	"ad68f29f-576f-4bb9-a36a-d47af965346c": "cipher-twofish",
	"7c02bb82-79a7-4ac0-927d-114a00648238": "kdf-aes", // KDBX4
	"c9d9f39a-628a-4460-bf74-0d08c18a4fea": "kdf-aes", // KDBX3 spelling, accepted too
	"ef636ddf-8c29-444b-91f7-a9a403e30a0c": "kdf-argon2d",
	"9e298b19-56db-4773-b23d-fc3ec6f0a1e6": "kdf-argon2id",
}

type cipherKind int

const (
	cipherUnknown cipherKind = iota
	cipherAES256
	cipherChaCha20
)

type kdfKind int

const (
	kdfUnknown kdfKind = iota
	kdfAES
	kdfArgon2D
	kdfArgon2ID
)

type header struct {
	major       uint16
	minor       uint16
	cipher      cipherKind
	compression uint32
	masterSeed  []byte
	encIV       []byte
	kdf         kdfKind
	kdfParams   variantDict

	// KDBX 3 only.
	transformSeed      []byte
	transformRounds    uint64
	protectedStreamKey []byte
	streamStartBytes   []byte
	innerStreamID      int
}

// normalizeUUID converts the 16 raw UUID bytes to a canonical string,
// accepting both big-endian (RFC 4122) and .NET Guid byte order.
func normalizeUUID(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	be := uuidString(raw)
	if _, ok := knownUUIDs[be]; ok {
		return be
	}
	sw := make([]byte, 16)
	copy(sw, raw)
	reverseBytes(sw[0:4])
	reverseBytes(sw[4:6])
	reverseBytes(sw[6:8])
	return uuidString(sw)
}

func uuidString(b []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// parseHeader reads the signature, version and header fields of a
// KDBX file and returns the parsed header plus the offset of the
// encrypted payload.
func parseHeader(data []byte) (*header, int, error) {
	if len(data) < 12 {
		return nil, 0, errors.New("file too short for a KDBX header")
	}
	if binary.LittleEndian.Uint32(data[0:4]) != kdbxSignature1 {
		return nil, 0, errors.New("not a KDBX file (bad signature 1)")
	}
	sig2 := binary.LittleEndian.Uint32(data[4:8])
	if sig2 == legacyKDBSignature2 {
		return nil, 0, errors.New("legacy KeePass 1.x .kdb format, not supported (only KDBX 3.1 and 4.x)")
	}
	if sig2 != kdbxSignature2 {
		return nil, 0, errors.New("not a KDBX file (bad signature 2)")
	}
	version := binary.LittleEndian.Uint32(data[8:12])
	major := version >> 16
	minor := version & 0xFFFF
	if (major != 3 && major != 4) || minor > 1 {
		return nil, 0, fmt.Errorf("unsupported KDBX version %d.%d (only 3.1 and 4.x are supported)", major, minor)
	}

	h := &header{major: uint16(major), minor: uint16(minor)}
	pos := 12 // two 4-byte signatures + 4-byte version, then the fields
	// KDBX 3 header fields are 1-byte type + 2-byte length; KDBX 4 uses
	// a 4-byte length.
	v3 := major == 3
	for {
		hdrLen := 5
		var length uint32
		if v3 {
			hdrLen = 3
			if pos+3 > len(data) {
				return nil, 0, errors.New("truncated header field")
			}
			length = uint32(binary.LittleEndian.Uint16(data[pos+1 : pos+3]))
		} else {
			if pos+5 > len(data) {
				return nil, 0, errors.New("truncated header field")
			}
			length = binary.LittleEndian.Uint32(data[pos+1 : pos+5])
		}
		typ := data[pos]
		pos += hdrLen
		if pos+int(length) > len(data) {
			return nil, 0, errors.New("truncated header field value")
		}
		val := data[pos : pos+int(length)]
		pos += int(length)
		switch typ {
		case fieldEndOfHeader:
			return h, pos, nil
		case fieldCipherID:
			switch normalizeUUID(val) {
			case "31c1f2e6-bf71-4350-be58-05216afc5aff":
				h.cipher = cipherAES256
			case "d6038a2b-8b6f-4cb5-a524-339a31dbb59a":
				h.cipher = cipherChaCha20
			case uuidTwofish:
				return nil, 0, errors.New("Twofish cipher is not supported (only AES-256 and ChaCha20)")
			default:
				return nil, 0, fmt.Errorf("unsupported cipher UUID %s", uuidString(val))
			}
		case fieldCompressionFlags:
			if len(val) != 4 {
				return nil, 0, errors.New("bad compression flags field")
			}
			h.compression = binary.LittleEndian.Uint32(val)
		case fieldMasterSeed:
			h.masterSeed = append([]byte(nil), val...)
		case fieldEncryptionIV:
			h.encIV = append([]byte(nil), val...)
		case fieldTransformSeed:
			h.transformSeed = append([]byte(nil), val...)
		case fieldTransformRounds:
			if len(val) != 8 {
				return nil, 0, errors.New("bad transform rounds field")
			}
			h.transformRounds = binary.LittleEndian.Uint64(val)
		case fieldProtectedStreamKey:
			h.protectedStreamKey = append([]byte(nil), val...)
		case fieldStreamStartBytes:
			h.streamStartBytes = append([]byte(nil), val...)
		case fieldInnerRandomStreamID:
			if len(val) != 4 {
				return nil, 0, errors.New("bad inner random stream ID field")
			}
			h.innerStreamID = int(binary.LittleEndian.Uint32(val))
		case fieldKdfParameters:
			vd, err := parseVariantDict(val)
			if err != nil {
				return nil, 0, fmt.Errorf("KDF parameters: %w", err)
			}
			h.kdfParams = vd
			uuidVal, ok := vd.bytes("$UUID")
			if !ok {
				return nil, 0, errors.New("KDF parameters missing $UUID")
			}
			switch normalizeUUID(uuidVal) {
			case "7c02bb82-79a7-4ac0-927d-114a00648238", "c9d9f39a-628a-4460-bf74-0d08c18a4fea":
				h.kdf = kdfAES
			case "ef636ddf-8c29-444b-91f7-a9a403e30a0c":
				h.kdf = kdfArgon2D
			case "9e298b19-56db-4773-b23d-fc3ec6f0a1e6":
				h.kdf = kdfArgon2ID
			default:
				return nil, 0, fmt.Errorf("unsupported KDF UUID %s", uuidString(uuidVal))
			}
		}
	}
}

// VariantDictionary entry types (KeePass VariantDictionary.cs).
const (
	vdUInt32    = 0x04
	vdUInt64    = 0x05
	vdBool      = 0x08
	vdString    = 0x18
	vdByteArray = 0x42
)

type vdEntry struct {
	typ byte
	val []byte
}

type variantDict map[string]vdEntry

func parseVariantDict(b []byte) (variantDict, error) {
	if len(b) < 2 {
		return nil, errors.New("variant dictionary too short")
	}
	if v := binary.LittleEndian.Uint16(b[:2]); v != 0x0100 {
		return nil, fmt.Errorf("unsupported variant dictionary version %#04x", v)
	}
	pos := 2
	d := variantDict{}
	for {
		if pos >= len(b) {
			return nil, errors.New("unterminated variant dictionary")
		}
		typ := b[pos]
		pos++
		if typ == 0x00 {
			return d, nil
		}
		if pos+4 > len(b) {
			return nil, errors.New("truncated variant dictionary name length")
		}
		nl := binary.LittleEndian.Uint32(b[pos:])
		pos += 4
		if pos+int(nl)+4 > len(b) {
			return nil, errors.New("truncated variant dictionary name")
		}
		name := string(b[pos : pos+int(nl)])
		pos += int(nl)
		vl := binary.LittleEndian.Uint32(b[pos:])
		pos += 4
		if pos+int(vl) > len(b) {
			return nil, errors.New("truncated variant dictionary value")
		}
		d[name] = vdEntry{typ: typ, val: append([]byte(nil), b[pos:pos+int(vl)]...)}
		pos += int(vl)
	}
}

func (d variantDict) bytes(key string) ([]byte, bool) {
	e, ok := d[key]
	if !ok || e.typ != vdByteArray {
		return nil, false
	}
	return e.val, true
}

func (d variantDict) u32(key string) (uint32, bool) {
	e, ok := d[key]
	if !ok || e.typ != vdUInt32 || len(e.val) != 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(e.val), true
}

func (d variantDict) u64(key string) (uint64, bool) {
	e, ok := d[key]
	if !ok || e.typ != vdUInt64 || len(e.val) != 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(e.val), true
}
