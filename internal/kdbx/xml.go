package kdbx

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20"

	"github.com/bcharron/keetui/internal/kdbxstream"
)

// Field is one <String> element of an entry, in file order.
type Field struct {
	Key       string
	Value     string
	Protected bool
}

// Entry is a decrypted KeePass entry with its group path.
type Entry struct {
	UUID         string
	Title        string
	UserName     string
	Password     string
	URL          string
	Notes        string
	Tags         string
	Created      string
	Modified     string
	Expires      string
	ExpiresSet   bool
	Fields       []Field // all string fields, standard ones included
	Attachments  []string
	GroupPath    string // e.g. "TestDB/Work/VPN"; "" for root-level entries
	InRecycleBin bool
}

// Database is the parsed content of a KDBX file. Entries are sorted
// by title (case-insensitive), then group path, then username.
type Database struct {
	Name    string
	Entries []Entry
}

// innerStream is the KDBX4 inner random stream (Salsa20 or ChaCha20)
// used to decrypt protected values. It is one continuous stream
// consumed in XML document order.
type innerStream struct {
	salsa  *kdbxstream.Stream
	chacha *chacha20.Cipher
}

func newInnerStream(id int, key []byte) (*innerStream, error) {
	switch id {
	case 2: // Salsa20: key = SHA-256(stream key), fixed IV
		return &innerStream{salsa: kdbxstream.NewSalsaStream(key)}, nil
	case 3: // ChaCha20: SHA-512(stream key) -> key[:32], nonce[32:44]
		h := sha512.Sum512(key)
		c, err := chacha20.NewUnauthenticatedCipher(h[:32], h[32:44])
		if err != nil {
			return nil, err
		}
		return &innerStream{chacha: c}, nil
	}
	return nil, fmt.Errorf("unsupported inner random stream ID %d (want 2=Salsa20 or 3=ChaCha20)", id)
}

// unprotect decrypts one base64 protected value with the next
// keystream bytes.
func (s *innerStream) unprotect(b64 string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("bad protected value: %w", err)
	}
	out := make([]byte, len(ct))
	if s.chacha != nil {
		s.chacha.XORKeyStream(out, ct)
	} else {
		s.salsa.XOR(out, ct)
	}
	return string(out), nil
}

// parseInnerHeader splits the decrypted payload into the KDBX4 inner
// binary header and the XML document. Inner header fields are
// [1-byte type][4-byte LE length][value], terminated by type 0:
// 1 = inner random stream ID (uint32), 2 = stream key, 3 = binary.
func parseInnerHeader(payload []byte) (streamID int, streamKey, xmlDoc []byte, err error) {
	pos := 0
	for {
		if pos+5 > len(payload) {
			return 0, nil, nil, errors.New("truncated inner header")
		}
		typ := payload[pos]
		length := binary.LittleEndian.Uint32(payload[pos+1 : pos+5])
		pos += 5
		if pos+int(length) > len(payload) {
			return 0, nil, nil, errors.New("truncated inner header field")
		}
		val := payload[pos : pos+int(length)]
		pos += int(length)
		switch typ {
		case 0:
			return streamID, streamKey, payload[pos:], nil
		case 1:
			if len(val) == 4 {
				streamID = int(binary.LittleEndian.Uint32(val))
			}
		case 2:
			streamKey = append([]byte(nil), val...)
		case 3:
			// attachment binary; content not needed for a read-only listing
		}
	}
}

// gframe is one open <Group> element on the XML parse stack.
type gframe struct {
	name string
	bin  bool
}

// parseXML streams the KeePass XML document into a Database. It is a
// token-stream parse (not struct unmarshal) because protected values
// must be decrypted with the inner stream in exact document order.
func parseXML(doc []byte, st *innerStream) (*Database, error) {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	db := &Database{}

	var gstack []gframe
	var entry *Entry
	var field *Field
	var binKey *string
	var capture *string
	var expiresFlag string

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bad KeePass XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "DatabaseName":
				capture = &db.Name
				db.Name = ""
			case "Group":
				gstack = append(gstack, gframe{})
			case "Name":
				if len(gstack) > 0 {
					capture = &gstack[len(gstack)-1].name
					gstack[len(gstack)-1].name = ""
				}
			case "Entry":
				entry = &Entry{}
			case "UUID":
				if entry != nil {
					capture = &entry.UUID
				}
			case "Tags":
				if entry != nil {
					capture = &entry.Tags
				}
			case "String":
				field = &Field{}
				if entry != nil {
					entry.Fields = append(entry.Fields, *field)
					field = &entry.Fields[len(entry.Fields)-1]
				}
			case "Key":
				if field != nil {
					capture = &field.Key
				} else if binKey != nil {
					capture = binKey
				}
			case "Value":
				if field != nil {
					for _, a := range t.Attr {
						if a.Name.Local == "Protected" && a.Value == "True" {
							field.Protected = true
						}
					}
					capture = &field.Value
					field.Value = ""
				}
			case "Binary":
				if entry != nil {
					binKey = new(string)
				}
			case "CreationTime":
				if entry != nil {
					capture = &entry.Created
				}
			case "LastModificationTime":
				if entry != nil {
					capture = &entry.Modified
				}
			case "ExpiryTime":
				if entry != nil {
					capture = &entry.Expires
				}
			case "Expires":
				if entry != nil {
					capture = &expiresFlag
					expiresFlag = ""
				}
			}
		case xml.CharData:
			if capture != nil {
				*capture += string(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "Value":
				if field != nil && field.Protected {
					pt, err := st.unprotect(field.Value)
					if err != nil {
						return nil, err
					}
					field.Value = pt
				}
				capture = nil
			case "Key":
				capture = nil
			case "Binary":
				if binKey != nil && entry != nil && *binKey != "" {
					entry.Attachments = append(entry.Attachments, *binKey)
				}
				binKey = nil
			case "Name":
				if len(gstack) > 0 {
					g := &gstack[len(gstack)-1]
					parentBin := len(gstack) > 1 && gstack[len(gstack)-2].bin
					g.bin = parentBin || (len(gstack) == 2 && strings.EqualFold(g.name, "Recycle Bin"))
				}
				capture = nil
			case "Entry":
				if entry != nil {
					entry.ExpiresSet = expiresFlag == "True"
					finishEntry(db, entry, gstack)
					entry = nil
				}
				field = nil
				expiresFlag = ""
			case "Group":
				if len(gstack) > 0 {
					gstack = gstack[:len(gstack)-1]
				}
			case "String":
				capture = nil
				field = nil
			case "Times", "DatabaseName", "UUID", "Tags", "CreationTime", "LastModificationTime", "ExpiryTime", "Expires":
				capture = nil
			}
		}
	}
	sortEntries(db.Entries)
	return db, nil
}

func finishEntry(db *Database, e *Entry, gstack []gframe) {
	// gstack[0] is the root group; its own name is not part of the path.
	path := ""
	bin := false
	if len(gstack) > 1 {
		names := make([]string, 0, len(gstack))
		for _, g := range gstack {
			names = append(names, g.name)
			bin = bin || g.bin
		}
		path = strings.Join(names, "/")
	}
	e.GroupPath = path
	e.InRecycleBin = bin
	e.Created = formatKDBXTime(e.Created)
	e.Modified = formatKDBXTime(e.Modified)
	if e.ExpiresSet {
		e.Expires = formatKDBXTime(e.Expires)
	} else {
		e.Expires = ""
	}
	for _, f := range e.Fields {
		switch f.Key {
		case "Title":
			e.Title = f.Value
		case "UserName":
			e.UserName = f.Value
		case "Password":
			e.Password = f.Value
		case "URL":
			e.URL = f.Value
		case "Notes":
			e.Notes = f.Value
		}
	}
	db.Entries = append(db.Entries, *e)
}

// formatKDBXTime renders a KDBX time value. KDBX4 stores times as
// base64 of an 8-byte little-endian Windows tick count (100 ns since
// 1601-01-01); ISO 8601 strings are also accepted.
func formatKDBXTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 8 {
		// seconds since 0001-01-01 UTC (.NET ticks / 10^7)
		unix := int64(binary.LittleEndian.Uint64(b)) - 62135596800
		return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return s
}

func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if la, lb := strings.ToLower(a.Title), strings.ToLower(b.Title); la != lb {
			return la < lb
		}
		if a.GroupPath != b.GroupPath {
			return a.GroupPath < b.GroupPath
		}
		return a.UserName < b.UserName
	})
}
