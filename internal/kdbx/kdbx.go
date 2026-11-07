// Package kdbx is a read-only parser for KeePass KDBX 4.0/4.1 files.
// The container format (header, key derivation, HMAC block stream,
// gzip, inner header, XML, inner stream cipher for protected values)
// is implemented here directly on top of Go's standard crypto plus
// x/crypto primitives; no KeePass library is used.
package kdbx

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
)

// Open reads and decrypts the KDBX file at path with the given master
// password. The file is only ever read, never modified.
func Open(path, password string) (*Database, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h, off, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}
	if len(h.masterSeed) != 32 {
		return nil, errors.New("missing or bad master seed in header")
	}

	candidates, err := kdfCandidates(h, compositeKey(password))
	if err != nil {
		return nil, err
	}
	var plain []byte
	for _, candidate := range candidates {
		transformed := candidate()
		if transformed == nil {
			continue
		}
		if h.major == 3 {
			plain, err = decryptPayloadV3(raw, off, h, transformed)
		} else {
			plain, err = decryptPayload(raw, off, h, transformed)
		}
		if err == nil {
			break
		}
	}
	if plain == nil {
		if errors.Is(err, errWrongPassword) {
			return nil, errWrongPassword
		}
		return nil, err
	}

	switch h.compression {
	case 0:
		// uncompressed
	case 1:
		zr, err := gzip.NewReader(bytes.NewReader(plain))
		if err != nil {
			return nil, fmt.Errorf("payload is not gzip: %w", err)
		}
		plain, err = io.ReadAll(zr)
		if err != nil {
			return nil, fmt.Errorf("gunzip: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported compression flag %d", h.compression)
	}

	var st *innerStream
	var xmlDoc []byte
	if h.major == 3 {
		// KDBX 3: no inner header; the payload is the XML document, and
		// the inner stream parameters are outer header fields.
		if h.innerStreamID != 2 {
			return nil, fmt.Errorf("unsupported inner random stream ID %d (only Salsa20=2)", h.innerStreamID)
		}
		st, err = newInnerStream(2, h.protectedStreamKey)
		if err != nil {
			return nil, err
		}
		xmlDoc = plain
	} else {
		var streamID int
		var streamKey []byte
		streamID, streamKey, xmlDoc, err = parseInnerHeader(plain)
		if err != nil {
			return nil, err
		}
		st, err = newInnerStream(streamID, streamKey)
		if err != nil {
			return nil, err
		}
	}
	return parseXML(xmlDoc, st)
}
