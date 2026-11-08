// Command genfixture writes synthetic KDBX4 test databases into
// testdata/. It is a throwaway writer used only to produce fixtures for
// the reader's tests; the keetui program itself never writes KDBX files.
//
// Usage: go run ./scripts/genfixture
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"

	"github.com/bcharron/keetui/internal/kdbxstream"
)

const password = "test-password"

var (
	uuidAES    = mustHex("31c1f2e6bf714350be5805216afc5aff")
	uuidChaCha = mustHex("d6038a2b8b6f4cb5a524339a31dbb59a")
	uuidAESKDF = mustHex("7c02bb8279a74ac0927d114a00648238") // KDBX4 AES-KDF
	uuidArgon2 = mustHex("9e298b1956db4773b23dfc3ec6f0a1e6") // KDBX4 Argon2id
)

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &out[i])
	}
	return out
}

type field struct {
	key, value string
	protected  bool
}

type entry struct {
	uuid     string
	tags     string
	expires  string
	bins     []string
	fields   []field
	history  []entry // previous versions, written inside <History>
	created  string  // kdbxTime(...) values; empty = default
	modified string
}

func main() {
	dir := "testdata"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	// v4.0, AES-KDF + AES-256-CBC, inner stream Salsa20
	if err := write(filepath.Join(dir, "test-aes.kdbx"), 0, uuidAES, "aes-kdf", false, 2); err != nil {
		panic(err)
	}
	// v4.1, Argon2id + ChaCha20, inner stream ChaCha20
	if err := write(filepath.Join(dir, "test-argon2-chacha.kdbx"), 1, uuidChaCha, "argon2", true, 3); err != nil {
		panic(err)
	}
	// v3.1, AES-KDF + AES-256-CBC, Salsa20 inner stream
	if err := writeV3(filepath.Join(dir, "test-v3.kdbx")); err != nil {
		panic(err)
	}
	fmt.Println("wrote", dir)
}

// writeV3 writes a KDBX 3.1 fixture: 2-byte header field lengths,
// AES-KDF params in header fields, hashed block stream (SHA-256 of
// plaintext per block), 32 stream-start bytes as the password check,
// Salsa20 inner stream from header field 8.
func writeV3(path string) error {
	psk := make([]byte, 32)
	rand.Read(psk)
	st := kdbxstream.NewSalsaStream(psk)
	protect := func(s string) string {
		ct := make([]byte, len(s))
		st.XOR(ct, []byte(s))
		return base64.StdEncoding.EncodeToString(ct)
	}

	root := fixtureEntries(protect)
	jira := entry{
		uuid: "55555555555555555555555555555555",
		fields: []field{
			{"Title", "Jira", false}, {"UserName", "octo", false},
			{"Password", protect("jira-pass"), true},
			{"URL", "https://jira.example.com", false},
		},
	}
	vpn := entry{
		uuid: "44444444444444444444444444444444",
		fields: []field{
			{"Title", "VPN gateway", false}, {"UserName", "vpnuser", false},
			{"Password", protect("vpn-secret-789"), true},
			{"URL", "https://vpn.example.com", false},
		},
	}
	oldBank := entry{
		uuid: "66666666666666666666666666666666",
		fields: []field{
			{"Title", "Old bank", false}, {"UserName", "old", false},
			{"Password", protect("old-pass-000"), true},
		},
	}

	var x bytes.Buffer
	x.WriteString("<KeePassFile><Meta>")
	fmt.Fprintf(&x, "<Generator>keetui-genfixture</Generator>")
	fmt.Fprintf(&x, "<DatabaseName>keetui test database</DatabaseName>")
	x.WriteString("</Meta><Root><Group>")
	fmt.Fprintf(&x, "<UUID>%s</UUID><Name>TestDB</Name>", base64.StdEncoding.EncodeToString([]byte("rootrootrootroot")))
	for _, e := range root {
		writeEntry(&x, e)
	}
	x.WriteString("<Group><Name>Work</Name>")
	writeEntry(&x, jira)
	x.WriteString("<Group><Name>VPN</Name>")
	writeEntry(&x, vpn)
	x.WriteString("</Group></Group>")
	x.WriteString("<Group><Name>Recycle Bin</Name>")
	writeEntry(&x, oldBank)
	x.WriteString("</Group>")
	x.WriteString("</Group></Root></KeePassFile>")

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(x.Bytes())
	zw.Close()
	xmlData := gz.Bytes()

	masterSeed := make([]byte, 32)
	rand.Read(masterSeed)
	transformSeed := make([]byte, 32)
	rand.Read(transformSeed)
	iv := make([]byte, 16)
	rand.Read(iv)
	startBytes := make([]byte, 32)
	rand.Read(startBytes)
	rounds := uint64(1000)

	inner := sha256.Sum256([]byte(password))
	composite := sha256.Sum256(inner[:])
	transformed := aesKdf(transformSeed, composite[:], rounds)
	finalKey := sha256.Sum256(append(append([]byte{}, masterSeed...), transformed...))

	// header with 2-byte field lengths
	var out bytes.Buffer
	writeLE32(&out, 0x9AA2D903)
	writeLE32(&out, 0xB54BFB67)
	writeLE32(&out, 0x00030001)
	writeField16 := func(typ byte, val []byte) {
		out.WriteByte(typ)
		writeLE16(&out, uint16(len(val)))
		out.Write(val)
	}
	writeField16(2, uuidAES)
	writeField16(3, le32(1))
	writeField16(4, masterSeed)
	writeField16(5, transformSeed)
	writeField16(6, le64(rounds))
	writeField16(7, iv)
	writeField16(8, psk)
	writeField16(9, startBytes)
	writeField16(10, le32(2))
	writeField16(0, []byte("\r\n\r\n"))

	// decrypted stream = startBytes + hashed blocks over xmlData
	var stream bytes.Buffer
	stream.Write(startBytes)
	const blockSize = 1 << 20
	for index := uint64(0); ; index++ {
		start := int(index) * blockSize
		if start >= len(xmlData) {
			// final block: zero hash, size 0
			var hdr [40]byte
			binary.LittleEndian.PutUint32(hdr[0:4], uint32(index))
			binary.LittleEndian.PutUint32(hdr[36:40], 0)
			stream.Write(hdr[:])
			break
		}
		end := start + blockSize
		if end > len(xmlData) {
			end = len(xmlData)
		}
		data := xmlData[start:end]
		h := sha256.Sum256(data)
		var hdr [40]byte
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(index))
		copy(hdr[4:36], h[:])
		binary.LittleEndian.PutUint32(hdr[36:40], uint32(len(data)))
		stream.Write(hdr[:])
		stream.Write(data)
	}

	// CBC-encrypt the whole stream (PKCS7 pad)
	padded := pkcs7(stream.Bytes(), 16)
	c, _ := aes.NewCipher(finalKey[:])
	cipherAll := make([]byte, len(padded))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(cipherAll, padded)
	out.Write(cipherAll)
	return os.WriteFile(path, out.Bytes(), 0o644)
}

func fixtureEntries(protect func(string) string) []entry {
	mk := func(uuid, tags, expires string, bins []string, fields ...field) entry {
		return entry{uuid: uuid, tags: tags, expires: expires, bins: bins, fields: fields}
	}
	// GitHub carries two history versions; they must be protected
	// right after GitHub's own fields (the inner stream is continuous
	// in document order).
	gh := mk("11111111111111111111111111111111", "dev, web", "", nil,
		field{"Title", "GitHub", false},
		field{"UserName", "octocat", false},
		field{"Password", protect("ghp_secret123"), true},
		field{"URL", "https://github.com", false},
		field{"Notes", "main account", false},
	)
	gh.created = kdbxTime(2024, 3, 1, 10, 0, 0)
	gh.modified = kdbxTime(2024, 6, 1, 10, 0, 0)
	gh.history = []entry{
		{
			uuid:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			created:  kdbxTime(2024, 1, 1, 9, 0, 0),
			modified: kdbxTime(2024, 1, 1, 9, 0, 0),
			fields: []field{
				{"Title", "GitHub", false},
				{"UserName", "octocat", false},
				{"Password", protect("old-password-1"), true},
				{"URL", "https://github.com", false},
			},
		},
		{
			uuid:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			created:  kdbxTime(2024, 2, 1, 9, 0, 0),
			modified: kdbxTime(2024, 2, 1, 9, 0, 0),
			fields: []field{
				{"Title", "GitHub", false},
				{"UserName", "octocat-old", false},
				{"Password", protect("old-password-2"), true},
				{"URL", "https://github.com", false},
			},
		},
	}
	return []entry{
		gh,
		mk("22222222222222222222222222222222", "", "", nil,
			field{"Title", "gmail", false},
			field{"UserName", "octocat@gmail.com", false},
			field{"Password", protect("app-password-456"), true},
			field{"URL", "https://mail.google.com", false},
		),
		mk("77777777777777777777777777777777", "", "", nil,
			field{"Title", "Router admin", false},
			field{"UserName", "admin", false},
			field{"Password", protect("r00ter!pass"), true},
			field{"URL", "http://192.168.1.1", false},
			field{"Notes", "admin panel of the home router", false},
		),
		mk("33333333333333333333333333333333", "", kdbxTime(2030, 1, 1, 0, 0, 0), []string{"id_rsa_backup.tar.gz"},
			field{"Title", "SSH key backup", false},
			field{"UserName", "root", false},
			field{"Password", protect("ssh-ultra-secret"), true},
			field{"Notes", "encrypted archive of home ssh keys", false},
		),
	}
}

func write(path string, minor uint16, cipherUUID []byte, kdf string, chacha bool, innerID int) error {
	// inner random stream: continuous cipher over protected values
	psk := make([]byte, 64)
	rand.Read(psk)
	var protect func(string) string
	if innerID == 2 {
		st := kdbxstream.NewSalsaStream(psk)
		protect = func(s string) string {
			ct := make([]byte, len(s))
			st.XOR(ct, []byte(s))
			return base64.StdEncoding.EncodeToString(ct)
		}
	} else {
		h := sha512.Sum512(psk)
		c, err := chacha20.NewUnauthenticatedCipher(h[:32], h[32:44])
		if err != nil {
			return err
		}
		protect = func(s string) string {
			ct := make([]byte, len(s))
			c.XORKeyStream(ct, []byte(s))
			return base64.StdEncoding.EncodeToString(ct)
		}
	}

	// Entries are encrypted (and must be written) in document order:
	// the inner stream is continuous across protected values.
	root := fixtureEntries(protect)
	jira := entry{
		uuid: "55555555555555555555555555555555",
		fields: []field{
			{"Title", "Jira", false}, {"UserName", "octo", false},
			{"Password", protect("jira-pass"), true},
			{"URL", "https://jira.example.com", false},
		},
	}
	vpn := entry{
		uuid: "44444444444444444444444444444444",
		fields: []field{
			{"Title", "VPN gateway", false}, {"UserName", "vpnuser", false},
			{"Password", protect("vpn-secret-789"), true},
			{"URL", "https://vpn.example.com", false},
		},
	}
	oldBank := entry{
		uuid: "66666666666666666666666666666666",
		fields: []field{
			{"Title", "Old bank", false}, {"UserName", "old", false},
			{"Password", protect("old-pass-000"), true},
		},
	}

	var x bytes.Buffer
	x.WriteString("<KeePassFile><Meta>")
	fmt.Fprintf(&x, "<Generator>keetui-genfixture</Generator>")
	fmt.Fprintf(&x, "<DatabaseName>keetui test database</DatabaseName>")
	x.WriteString("</Meta><Root><Group>")
	fmt.Fprintf(&x, "<UUID>%s</UUID><Name>TestDB</Name>", base64.StdEncoding.EncodeToString([]byte("rootrootrootroot")))
	for _, e := range root {
		writeEntry(&x, e)
	}
	x.WriteString("<Group><Name>Work</Name>")
	writeEntry(&x, jira)
	x.WriteString("<Group><Name>VPN</Name>")
	writeEntry(&x, vpn)
	x.WriteString("</Group></Group>")
	x.WriteString("<Group><Name>Recycle Bin</Name>")
	writeEntry(&x, oldBank)
	x.WriteString("</Group>")
	x.WriteString("</Group></Root></KeePassFile>")

	// KDF: composite key = SHA-256(SHA-256(password))
	inner := sha256.Sum256([]byte(password))
	composite := sha256.Sum256(inner[:])
	var transformed []byte
	var kdfParams []byte
	if kdf == "aes-kdf" {
		seed := make([]byte, 32)
		rand.Read(seed)
		rounds := uint64(1000)
		transformed = aesKdf(seed, composite[:], rounds)
		kdfParams = variantDict(uuidAESKDF, []vdKV{
			{"S", 0x42, seed},
			{"R", 0x05, le64(rounds)},
		})
	} else {
		salt := make([]byte, 16)
		rand.Read(salt)
		transformed = argon2.IDKey(composite[:], salt, 2, 1024, 2, 32)
		kdfParams = variantDict(uuidArgon2, []vdKV{
			{"V", 0x04, le32(19)},
			{"S", 0x42, salt},
			{"P", 0x04, le32(2)},
			{"I", 0x05, le64(2)},
			{"M", 0x05, le64(1024 * 1024)}, // memory stored in bytes
		})
	}

	masterSeed := make([]byte, 32)
	rand.Read(masterSeed)
	ivLen := 16
	if chacha {
		ivLen = 12
	}
	iv := make([]byte, ivLen)
	rand.Read(iv)

	// header
	var out bytes.Buffer
	writeLE32(&out, 0x9AA2D903)
	writeLE32(&out, 0xB54BFB67)
	writeLE32(&out, uint32(4)<<16|uint32(minor))
	writeField(&out, 2, cipherUUID)
	writeField(&out, 3, le32(1))
	writeField(&out, 4, masterSeed)
	writeField(&out, 7, iv)
	writeField(&out, 11, kdfParams)
	writeField(&out, 0, []byte("\r\n\r\n"))
	headerData := out.Bytes()

	// stream keys: finalKey = SHA-256(seed||transformed), K = SHA-512(seed||transformed||0x01)
	fh := sha256.New()
	fh.Write(masterSeed)
	fh.Write(transformed)
	finalKey := fh.Sum(nil)
	kh := sha512.New()
	kh.Write(masterSeed)
	kh.Write(transformed)
	kh.Write([]byte{0x01})
	K := kh.Sum(nil)

	out.Write(sha256Sum(headerData))
	out.Write(hmacSHA256(blockKey(K, ^uint64(0)), headerData))

	// inner header + XML, gzipped
	var payload bytes.Buffer
	writeInnerField(&payload, 1, le32(uint32(innerID)))
	writeInnerField(&payload, 2, psk)
	writeInnerField(&payload, 0, nil)
	payload.Write(x.Bytes())
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(payload.Bytes())
	zw.Close()
	plain := gz.Bytes()

	// encrypt the whole stream
	var cipherAll []byte
	if !chacha {
		padded := pkcs7(plain, 16)
		c, _ := aes.NewCipher(finalKey)
		cipherAll = make([]byte, len(padded))
		cipher.NewCBCEncrypter(c, iv).CryptBlocks(cipherAll, padded)
	} else {
		c, _ := chacha20.NewUnauthenticatedCipher(finalKey, iv)
		cipherAll = make([]byte, len(plain))
		c.XORKeyStream(cipherAll, plain)
	}

	// blocks: [32 hmac][4 LE size][data], terminator with size 0
	const blockSize = 1 << 20
	for index := uint64(0); ; index++ {
		start := int(index) * blockSize
		if start >= len(cipherAll) {
			writeBlock(&out, K, index, nil)
			break
		}
		end := start + blockSize
		if end > len(cipherAll) {
			end = len(cipherAll)
		}
		writeBlock(&out, K, index, cipherAll[start:end])
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// writeBlock appends one HMAC block: [32 hmac][4 LE size][data].
func writeBlock(out *bytes.Buffer, K []byte, index uint64, data []byte) {
	var iB [8]byte
	binary.LittleEndian.PutUint64(iB[:], index)
	msg := append(append(iB[:], le32(uint32(len(data)))...), data...)
	out.Write(hmacSHA256(blockKey(K, index), msg))
	out.Write(le32(uint32(len(data))))
	out.Write(data)
}

// blockKey computes Ki = SHA-512(LE64(i) || K).
func blockKey(K []byte, i uint64) []byte {
	var iB [8]byte
	binary.LittleEndian.PutUint64(iB[:], i)
	h := sha512.New()
	h.Write(iB[:])
	h.Write(K)
	return h.Sum(nil)
}

func writeInnerField(b *bytes.Buffer, typ byte, val []byte) {
	b.WriteByte(typ)
	writeLE32(b, uint32(len(val)))
	b.Write(val)
}

func writeEntry(x *bytes.Buffer, e entry) {
	x.WriteString("<Entry>")
	fmt.Fprintf(x, "<UUID>%s</UUID>", base64.StdEncoding.EncodeToString([]byte(e.uuid)))
	if e.tags != "" {
		fmt.Fprintf(x, "<Tags>%s</Tags>", xmlEscape(e.tags))
	}
	for _, f := range e.fields {
		x.WriteString("<String><Key>")
		x.WriteString(xmlEscape(f.key))
		x.WriteString("</Key><Value")
		if f.protected {
			x.WriteString(` Protected="True"`)
		}
		x.WriteString(">")
		x.WriteString(xmlEscape(f.value))
		x.WriteString("</Value></String>")
	}
	for _, b := range e.bins {
		fmt.Fprintf(x, `<Binary><Key>%s</Key><Value Ref="0"/></Binary>`, xmlEscape(b))
	}
	created, modified := e.created, e.modified
	if created == "" {
		created = kdbxTime(2024, 1, 2, 3, 4, 5)
	}
	if modified == "" {
		modified = kdbxTime(2024, 6, 7, 8, 9, 10)
	}
	x.WriteString("<Times>")
	fmt.Fprintf(x, "<CreationTime>%s</CreationTime>", created)
	fmt.Fprintf(x, "<LastModificationTime>%s</LastModificationTime>", modified)
	if e.expires != "" {
		fmt.Fprintf(x, "<ExpiryTime>%s</ExpiryTime><Expires>True</Expires>", e.expires)
	} else {
		fmt.Fprintf(x, "<ExpiryTime>%s</ExpiryTime><Expires>False</Expires>", created)
	}
	x.WriteString("</Times>")
	if len(e.history) > 0 {
		x.WriteString("<History>")
		for _, h := range e.history {
			writeEntry(x, h)
		}
		x.WriteString("</History>")
	}
	x.WriteString("</Entry>")
}

// kdbxTime renders a UTC time as base64 of the 8-byte LE count of
// seconds since 0001-01-01 UTC, the KDBX XML time encoding.
func kdbxTime(y, mo, d, h, mi, s int) string {
	t := time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC)
	secs := uint64(t.Unix() + 62135596800)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], secs)
	return base64.StdEncoding.EncodeToString(b[:])
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

type vdKV struct {
	name string
	typ  byte
	val  []byte
}

func variantDict(uuid []byte, kvs []vdKV) []byte {
	var b bytes.Buffer
	writeLE16(&b, 0x0100)
	writeKV := func(name string, typ byte, val []byte) {
		b.WriteByte(typ)
		writeLE32(&b, uint32(len(name)))
		b.WriteString(name)
		writeLE32(&b, uint32(len(val)))
		b.Write(val)
	}
	writeKV("$UUID", 0x42, uuid)
	for _, kv := range kvs {
		writeKV(kv.name, kv.typ, kv.val)
	}
	b.WriteByte(0x00)
	return b.Bytes()
}

func writeField(b *bytes.Buffer, typ byte, val []byte) {
	b.WriteByte(typ)
	writeLE32(b, uint32(len(val)))
	b.Write(val)
}

func writeLE16(b *bytes.Buffer, v uint16) {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	b.Write(tmp[:])
}

func writeLE32(b *bytes.Buffer, v uint32) {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	b.Write(tmp[:])
}

func le32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

func le64(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func aesKdf(seed, key []byte, rounds uint64) []byte {
	c, _ := aes.NewCipher(seed)
	block := append([]byte(nil), key...)
	for i := uint64(0); i < rounds; i++ {
		for off := 0; off+16 <= len(block); off += 16 {
			c.Encrypt(block[off:off+16], block[off:off+16])
		}
	}
	h := sha256.Sum256(block)
	return h[:]
}

func pkcs7(b []byte, n int) []byte {
	pad := n - len(b)%n
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
