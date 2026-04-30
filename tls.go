package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Parsed result of a captured TLS ClientHello.
type ClientHello struct {
	Raw           []byte // full bytes including 5-byte record header
	ServerName    string
	HostnameStart int // offset in Raw where hostname bytes begin
	HostnameLen   int
}

const maxTLSRecord = 16384 + 5 // RFC 5246 max record + header

var (
	errNotTLS         = errors.New("not a TLS handshake record")
	errNotClientHello = errors.New("not a ClientHello")
	errMalformed      = errors.New("malformed ClientHello")
	errNoSNI          = errors.New("no SNI extension")
)

// ReadClientHello reads exactly one TLS handshake record from conn and
// extracts the SNI hostname.
func ReadClientHello(conn net.Conn, deadline time.Duration) (*ClientHello, error) {
	if deadline > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(deadline))
		defer conn.SetReadDeadline(time.Time{})
	}

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("read TLS header: %w", err)
	}
	if hdr[0] != 0x16 {
		return nil, errNotTLS
	}
	// hdr[1..2] = legacy version; allow anything ≥ 3.1 (TLS 1.0)
	if hdr[1] < 3 || (hdr[1] == 3 && hdr[2] < 1) {
		return nil, fmt.Errorf("TLS version too low: %d.%d", hdr[1], hdr[2])
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > maxTLSRecord-5 {
		return nil, fmt.Errorf("invalid TLS record length %d", recLen)
	}

	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("read TLS body: %w", err)
	}

	raw := make([]byte, 0, 5+recLen)
	raw = append(raw, hdr...)
	raw = append(raw, body...)

	hStart, hLen, name, err := parseClientHelloSNI(body)
	if err != nil {
		return &ClientHello{Raw: raw}, err
	}
	return &ClientHello{
		Raw:           raw,
		ServerName:    name,
		HostnameStart: 5 + hStart,
		HostnameLen:   hLen,
	}, nil
}

// parseClientHelloSNI returns offset (within body) and length of the hostname.
func parseClientHelloSNI(b []byte) (int, int, string, error) {
	pos := 0
	need := func(n int) error {
		if pos+n > len(b) {
			return errMalformed
		}
		return nil
	}
	if err := need(4); err != nil {
		return 0, 0, "", err
	}
	if b[pos] != 0x01 {
		return 0, 0, "", errNotClientHello
	}
	hsLen := int(b[pos+1])<<16 | int(b[pos+2])<<8 | int(b[pos+3])
	pos += 4
	if pos+hsLen > len(b) {
		return 0, 0, "", errMalformed
	}
	end := pos + hsLen

	// legacy_version (2) + random (32)
	if pos+34 > end {
		return 0, 0, "", errMalformed
	}
	pos += 34
	// session_id
	if pos+1 > end {
		return 0, 0, "", errMalformed
	}
	sidLen := int(b[pos])
	pos++
	if pos+sidLen > end {
		return 0, 0, "", errMalformed
	}
	pos += sidLen
	// cipher_suites
	if pos+2 > end {
		return 0, 0, "", errMalformed
	}
	csLen := int(b[pos])<<8 | int(b[pos+1])
	pos += 2
	if pos+csLen > end {
		return 0, 0, "", errMalformed
	}
	pos += csLen
	// compression_methods
	if pos+1 > end {
		return 0, 0, "", errMalformed
	}
	cmLen := int(b[pos])
	pos++
	if pos+cmLen > end {
		return 0, 0, "", errMalformed
	}
	pos += cmLen
	// extensions
	if pos == end {
		return 0, 0, "", errNoSNI
	}
	if pos+2 > end {
		return 0, 0, "", errMalformed
	}
	extLen := int(b[pos])<<8 | int(b[pos+1])
	pos += 2
	if pos+extLen > end {
		return 0, 0, "", errMalformed
	}
	extEnd := pos + extLen

	for pos+4 <= extEnd {
		extType := int(b[pos])<<8 | int(b[pos+1])
		extDataLen := int(b[pos+2])<<8 | int(b[pos+3])
		pos += 4
		if pos+extDataLen > extEnd {
			return 0, 0, "", errMalformed
		}
		if extType == 0 { // server_name
			ep := pos
			eend := pos + extDataLen
			if ep+2 > eend {
				return 0, 0, "", errMalformed
			}
			listLen := int(b[ep])<<8 | int(b[ep+1])
			ep += 2
			if ep+listLen > eend {
				return 0, 0, "", errMalformed
			}
			listEnd := ep + listLen
			for ep+3 <= listEnd {
				nameType := b[ep]
				nameLen := int(b[ep+1])<<8 | int(b[ep+2])
				ep += 3
				if ep+nameLen > listEnd {
					return 0, 0, "", errMalformed
				}
				if nameType == 0 {
					if nameLen == 0 {
						return 0, 0, "", errMalformed
					}
					return ep, nameLen, string(b[ep : ep+nameLen]), nil
				}
				ep += nameLen
			}
			return 0, 0, "", errNoSNI
		}
		pos += extDataLen
	}
	return 0, 0, "", errNoSNI
}

// WriteFragmented writes data to conn split at offset (with a small delay
// between writes) so that DPI middleboxes that pattern-match a single TCP
// segment fail to identify the SNI / payload.
//
// If the connection is *net.TCPConn we disable Nagle so that each Write
// has a better chance of producing its own segment.
func WriteFragmented(conn net.Conn, data []byte, offset int, delay time.Duration) error {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if offset <= 0 || offset >= len(data) {
		_, err := conn.Write(data)
		return err
	}
	if _, err := conn.Write(data[:offset]); err != nil {
		return err
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	_, err := conn.Write(data[offset:])
	return err
}
