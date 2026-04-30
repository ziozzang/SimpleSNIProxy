package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"strings"
	"time"
)

type Proxy struct {
	cfg    *Config
	dialer *Dialer
}

func NewProxy(cfg *Config, dialer *Dialer) *Proxy {
	return &Proxy{cfg: cfg, dialer: dialer}
}

// HandleHTTPS reads a TLS ClientHello, looks up the SNI hostname, dials the
// backend, then forwards the captured ClientHello (optionally fragmented at
// the SNI byte position) before bridging the rest.
func (p *Proxy) HandleHTTPS(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	hello, err := ReadClientHello(conn, p.cfg.HelloRdTime)
	if err != nil {
		slog.Warn("clientHello parse failed", "remote", remote, "err", err)
		return
	}
	if hello.ServerName == "" {
		slog.Warn("no SNI in ClientHello (ECH or anonymous?); cannot route", "remote", remote)
		return
	}

	slog.Info("HTTPS", "from", remote, "sni", hello.ServerName)

	dialCtx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	backend, err := p.dialer.Dial(dialCtx, hello.ServerName, 443)
	if err != nil {
		slog.Warn("dial backend failed", "host", hello.ServerName, "err", err)
		return
	}

	// Forward the captured ClientHello, fragmenting if requested.
	offset := 0
	if p.cfg.TLSFragment {
		if p.cfg.TLSFragOffset > 0 {
			offset = p.cfg.TLSFragOffset
		} else if hello.HostnameLen > 0 {
			// Split inside the hostname bytes, near the middle.
			offset = hello.HostnameStart + hello.HostnameLen/2
		} else {
			offset = 1
		}
	}
	if err := WriteFragmented(backend, hello.Raw, offset, p.cfg.TLSFragDelay); err != nil {
		slog.Warn("forward ClientHello failed", "err", err)
		backend.Close()
		return
	}

	PipeConns(conn, backend, p.cfg.IdleTimeout)
}

// HandleHTTP reads HTTP request headers, extracts Host, dials backend, and
// forwards the request with optional Host-header obfuscation and fragmented
// writes.
func (p *Proxy) HandleHTTP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	if p.cfg.HelloRdTime > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(p.cfg.HelloRdTime))
	}
	br := bufio.NewReaderSize(conn, 64*1024)

	requestLine, err := readHTTPLine(br, 16*1024)
	if err != nil {
		slog.Warn("read request line", "remote", remote, "err", err)
		return
	}
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 3 {
		slog.Warn("bad request line", "remote", remote, "line", requestLine)
		return
	}

	headers := make([][]byte, 0, 16)
	headers = append(headers, []byte(requestLine))

	host := ""
	hostIdx := -1
	totalHdr := 0
	for {
		line, err := readHTTPLine(br, 16*1024)
		if err != nil {
			slog.Warn("read header", "remote", remote, "err", err)
			return
		}
		totalHdr += len(line)
		if totalHdr > 64*1024 {
			slog.Warn("headers too large", "remote", remote)
			return
		}
		headers = append(headers, []byte(line))
		if line == "\r\n" || line == "\n" {
			break
		}
		// Case-insensitive Host detection
		if hostIdx < 0 && hasHeaderName(line, "Host") {
			host = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			hostIdx = len(headers) - 1
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	if host == "" {
		slog.Warn("no Host header", "remote", remote)
		return
	}

	// strip port if present
	connectHost := host
	port := 80
	if h, pStr, err := net.SplitHostPort(host); err == nil {
		connectHost = h
		if pStr != "" {
			fmt.Sscanf(pStr, "%d", &port)
		}
	}

	slog.Info("HTTP", "from", remote, "host", host, "method", parts[0])

	dialCtx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	backend, err := p.dialer.Dial(dialCtx, connectHost, port)
	if err != nil {
		slog.Warn("dial backend failed", "host", connectHost, "err", err)
		return
	}

	// Mutate the Host header for DPI bypass.
	if p.cfg.HTTPMutateHost && hostIdx >= 0 {
		headers[hostIdx] = mutateHostHeader(headers[hostIdx])
	}

	if tc, ok := backend.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	if p.cfg.HTTPFragment {
		// Send each header line as its own write so that the request line
		// and Host header land in separate TCP segments.
		for _, h := range headers {
			if _, err := backend.Write(h); err != nil {
				slog.Warn("forward header", "err", err)
				backend.Close()
				return
			}
			if p.cfg.HTTPFragDelay > 0 {
				time.Sleep(p.cfg.HTTPFragDelay)
			}
		}
	} else {
		buf := bytes.Join(headers, nil)
		if _, err := backend.Write(buf); err != nil {
			slog.Warn("forward headers", "err", err)
			backend.Close()
			return
		}
	}

	// Bridge: client (br has any buffered body bytes) <-> backend.
	go func() {
		// Drain anything already buffered in br first, then continue from conn.
		if buffered := br.Buffered(); buffered > 0 {
			peek, _ := br.Peek(buffered)
			if _, err := backend.Write(peek); err != nil {
				backend.Close()
				return
			}
			_, _ = br.Discard(buffered)
		}
		// Now use the underlying conn directly for the rest.
		_, _ = io.Copy(backend, conn)
		halfClose(backend)
	}()
	// backend → client
	_, _ = io.Copy(conn, backend)
	halfClose(conn)
	backend.Close()
}

// readHTTPLine reads up to and including \n, returns the line including line ending.
func readHTTPLine(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		sb.WriteByte(b)
		if b == '\n' {
			return sb.String(), nil
		}
		if sb.Len() > max {
			return "", errors.New("line too long")
		}
	}
}

// hasHeaderName checks whether line starts with name + ":" (case-insensitive).
func hasHeaderName(line, name string) bool {
	if len(line) < len(name)+1 {
		return false
	}
	if !strings.EqualFold(line[:len(name)], name) {
		return false
	}
	rest := strings.TrimLeft(line[len(name):], " \t")
	return strings.HasPrefix(rest, ":")
}

// mutateHostHeader randomizes the case of the header *name* and inserts an
// extra space after the colon, neither of which changes HTTP semantics
// (RFC 9110: header names are case-insensitive; OWS allowed after colon).
func mutateHostHeader(line []byte) []byte {
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return line
	}
	name := make([]byte, colon)
	for i := 0; i < colon; i++ {
		c := line[i]
		if rand.Intn(2) == 0 {
			if c >= 'a' && c <= 'z' {
				c -= 32
			} else if c >= 'A' && c <= 'Z' {
				c += 32
			}
		}
		name[i] = c
	}
	rest := line[colon+1:]
	rest = bytes.TrimLeft(rest, " \t")
	out := make([]byte, 0, len(line)+2)
	out = append(out, name...)
	out = append(out, ':', ' ', ' ')
	out = append(out, rest...)
	return out
}
