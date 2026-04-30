package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// TLS ClientHello parser
// -----------------------------------------------------------------------------

// captureClientHello connects (with our crypto/tls) to a listener that forwards
// the raw bytes back so we can feed them into ReadClientHello.
func captureClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	captured := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := c.Read(buf)
		captured <- append([]byte(nil), buf[:n]...)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	// Force a handshake; we expect it to fail because the server never
	// responds, but that's fine — we only need the ClientHello on the wire.
	_ = tc.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_ = tc.Handshake()
	conn.Close()

	return <-captured
}

func TestReadClientHello_ExtractsSNI(t *testing.T) {
	hello := captureClientHello(t, "example.com")
	if len(hello) == 0 {
		t.Fatal("no ClientHello captured")
	}

	// Feed it through a pipe into ReadClientHello.
	a, b := net.Pipe()
	go func() {
		_, _ = a.Write(hello)
		a.Close()
	}()

	ch, err := ReadClientHello(b, 2*time.Second)
	if err != nil {
		t.Fatalf("ReadClientHello: %v", err)
	}
	if ch.ServerName != "example.com" {
		t.Errorf("ServerName=%q want example.com", ch.ServerName)
	}
	// The hostname offset must point exactly at "example.com".
	got := string(ch.Raw[ch.HostnameStart : ch.HostnameStart+ch.HostnameLen])
	if got != "example.com" {
		t.Errorf("hostname slice=%q want example.com", got)
	}
}

func TestReadClientHello_RejectsNonTLS(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		_, _ = a.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		a.Close()
	}()
	if _, err := ReadClientHello(b, time.Second); !errors.Is(err, errNotTLS) {
		t.Errorf("err=%v want errNotTLS", err)
	}
}

func TestReadClientHello_TruncatedRecord(t *testing.T) {
	a, b := net.Pipe()
	// Valid TLS header announcing 100 body bytes but we only send 5 bytes
	// then close → io.ReadFull must fail cleanly.
	go func() {
		_, _ = a.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x64, 1, 2, 3, 4, 5})
		a.Close()
	}()
	if _, err := ReadClientHello(b, time.Second); err == nil {
		t.Error("expected error on truncated record")
	}
}

// -----------------------------------------------------------------------------
// WriteFragmented
// -----------------------------------------------------------------------------

func TestWriteFragmented_ProducesSeparateWrites(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	got := make([][]byte, 0, 2)
	var mu sync.Mutex
	done := make(chan struct{})

	go func() {
		buf := make([]byte, 64)
		for {
			n, err := b.Read(buf)
			if n > 0 {
				mu.Lock()
				got = append(got, append([]byte(nil), buf[:n]...))
				mu.Unlock()
			}
			if err != nil {
				close(done)
				return
			}
		}
	}()

	data := []byte("HELLO-WORLD")
	if err := WriteFragmented(a, data, 5, 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	a.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(got) < 2 {
		t.Fatalf("expected ≥2 reads, got %d (%q)", len(got), got)
	}
	if !bytes.Equal(got[0], []byte("HELLO")) {
		t.Errorf("first chunk=%q want HELLO", got[0])
	}
	combined := bytes.Join(got, nil)
	if !bytes.Equal(combined, data) {
		t.Errorf("combined=%q want %q", combined, data)
	}
}

func TestWriteFragmented_NoSplitWhenOffsetOutOfRange(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _ = WriteFragmented(a, []byte("abc"), 0, 0); a.Close() }()
	buf := make([]byte, 16)
	n, _ := b.Read(buf)
	if string(buf[:n]) != "abc" {
		t.Errorf("got %q", buf[:n])
	}
}

// -----------------------------------------------------------------------------
// HTTP Host mutator
// -----------------------------------------------------------------------------

func TestMutateHostHeader(t *testing.T) {
	in := []byte("Host: example.com\r\n")
	out := mutateHostHeader(in)

	// The mutated line must still parse as a Host header (case-insensitive
	// name + colon + the same value, possibly with extra whitespace).
	if !bytes.HasSuffix(out, []byte("\r\n")) {
		t.Errorf("missing CRLF: %q", out)
	}
	colon := bytes.IndexByte(out, ':')
	if colon < 0 {
		t.Fatalf("no colon: %q", out)
	}
	name := strings.ToLower(string(out[:colon]))
	if name != "host" {
		t.Errorf("name=%q want host", name)
	}
	value := strings.TrimSpace(string(out[colon+1 : len(out)-2]))
	if value != "example.com" {
		t.Errorf("value=%q want example.com", value)
	}
}

func TestHasHeaderName(t *testing.T) {
	cases := map[string]bool{
		"Host: x\r\n":   true,
		"host:x\r\n":    true,
		"hOsT : x\r\n":  true, // OWS before ':' is technically obsolete but real-world tolerated
		"X-Host: x\r\n": false,
		"Hostile: x\r\n": false,
	}
	for line, want := range cases {
		if got := hasHeaderName(line, "Host"); got != want {
			t.Errorf("hasHeaderName(%q)=%v want %v", line, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// DNS64 synthesis
// -----------------------------------------------------------------------------

func TestSynthesizeDNS64(t *testing.T) {
	prefix := netip.MustParsePrefix("64:ff9b::/96")
	v4 := netip.MustParseAddr("192.0.2.33")
	got, ok := synthesizeDNS64(prefix, v4)
	if !ok {
		t.Fatal("synthesis failed")
	}
	want := netip.MustParseAddr("64:ff9b::c000:221")
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

// -----------------------------------------------------------------------------
// SSRF guard
// -----------------------------------------------------------------------------

func TestIsDisallowed(t *testing.T) {
	disallowed := []string{
		"127.0.0.1",
		"0.0.0.0",
		"10.1.2.3",
		"192.168.1.1",
		"172.16.0.1",
		"169.254.169.254", // AWS IMDS — link-local
		"100.64.0.1",      // CGNAT
		"198.18.0.1",      // benchmark
		"203.0.113.7",     // TEST-NET-3
		"240.0.0.1",       // reserved
		"::1",
		"fe80::1",
		"fc00::1",
		"ff02::1",
	}
	for _, s := range disallowed {
		ip := netip.MustParseAddr(s)
		if !isDisallowed(ip) {
			t.Errorf("%s should be disallowed", s)
		}
	}
	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34", // example.com (legacy)
		"2606:4700:4700::1111",
		"2001:db8::1", // documentation: technically it's reserved, but our check doesn't cover it. So actually allowed by our guard.
	}
	for _, s := range allowed {
		ip := netip.MustParseAddr(s)
		if isDisallowed(ip) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

// -----------------------------------------------------------------------------
// DNS server normalization
// -----------------------------------------------------------------------------

func TestNormalizeDNSAddr(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":              "1.1.1.1:53",
		"1.1.1.1:53":           "1.1.1.1:53",
		"8.8.4.4:5353":         "8.8.4.4:5353",
		"2606:4700:4700::1111": "[2606:4700:4700::1111]:53",
		"[2606:4700:4700::1111]:53": "[2606:4700:4700::1111]:53",
	}
	for in, want := range cases {
		if got := normalizeDNSAddr(in); got != want {
			t.Errorf("normalizeDNSAddr(%q)=%q want %q", in, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// pipeConns: idle copy + half-close
// -----------------------------------------------------------------------------

func TestPipeConns_BidirectionalAndClose(t *testing.T) {
	// Two TCP pairs simulating client<->proxy<->backend
	clientL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientL.Close()
	backendL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendL.Close()

	// Backend echoes & closes
	go func() {
		c, err := backendL.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n])
	}()

	// Proxy goroutine: accept from clientL, dial backendL, run PipeConns
	go func() {
		c, err := clientL.Accept()
		if err != nil {
			return
		}
		b, err := net.Dial("tcp", backendL.Addr().String())
		if err != nil {
			c.Close()
			return
		}
		PipeConns(c, b, 2*time.Second)
	}()

	cl, err := net.Dial("tcp", clientL.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if _, err := cl.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	_ = cl.(*net.TCPConn).CloseWrite()

	buf := make([]byte, 16)
	_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := cl.Read(buf)
	if string(buf[:n]) != "PING" {
		t.Errorf("got %q want PING", buf[:n])
	}
}

// -----------------------------------------------------------------------------
// End-to-end: HTTP path
// -----------------------------------------------------------------------------

// startTestProxy boots the proxy on ephemeral ports bound to 127.0.0.1, with
// -allow-private so that the test backends (loopback) are reachable.
func startTestProxy(t *testing.T, cfg *Config) (httpAddr, httpsAddr string, stop func()) {
	t.Helper()
	dialer, err := NewDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(cfg, dialer)

	httpL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpsL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			c, err := httpL.Accept()
			if err != nil {
				return
			}
			go p.HandleHTTP(t.Context(), c)
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, err := httpsL.Accept()
			if err != nil {
				return
			}
			go p.HandleHTTPS(t.Context(), c)
		}
	}()

	stop = func() {
		close(stopCh)
		httpL.Close()
		httpsL.Close()
		wg.Wait()
	}
	return httpL.Addr().String(), httpsL.Addr().String(), stop
}

func TestEndToEnd_HTTP_HostMutationAndForwarding(t *testing.T) {
	// Backend HTTP server captures incoming bytes and returns canned reply.
	backendL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendL.Close()

	hostHeaderSeen := make(chan string, 1)
	go func() {
		c, err := backendL.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		var req bytes.Buffer
		buf := make([]byte, 1024)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				req.Write(buf[:n])
				if bytes.Contains(req.Bytes(), []byte("\r\n\r\n")) {
					break
				}
			}
			if err != nil {
				break
			}
		}
		hostHeaderSeen <- req.String()
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
	}()

	backendHost, backendPort, _ := net.SplitHostPort(backendL.Addr().String())

	cfg := &Config{
		HTTPPort: 0, HTTPSPort: 0,
		DialTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second,
		HelloRdTime: 2 * time.Second,
		PreferIPv6:  false, AllowPrivate: true,
		HTTPMutateHost: true, HTTPFragment: true, HTTPFragDelay: 1 * time.Millisecond,
		HappyEyeballsDelay: 50 * time.Millisecond,
	}
	httpAddr, _, stop := startTestProxy(t, cfg)
	defer stop()

	cl, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	req := "GET / HTTP/1.1\r\nHost: " + backendHost + ":" + backendPort + "\r\nUser-Agent: test\r\n\r\n"
	if _, err := cl.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 1024)
	_ = cl.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := cl.Read(resp)
	if !bytes.Contains(resp[:n], []byte("200 OK")) {
		t.Fatalf("response missing 200 OK: %q", resp[:n])
	}
	got := <-hostHeaderSeen
	// Host header must still be present (case-insensitive) and the value must
	// match what we sent.
	lower := strings.ToLower(got)
	if !strings.Contains(lower, "host:") {
		t.Errorf("backend never saw a Host header: %q", got)
	}
	if !strings.Contains(got, backendHost) {
		t.Errorf("backend Host value missing: %q", got)
	}
	// And — key bypass property — the forwarded line must NOT be the literal
	// "Host: " we sent (mutation must have happened).
	if strings.Contains(got, "\r\nHost: "+backendHost) {
		t.Errorf("Host header was not mutated: %q", got)
	}
}

func TestEndToEnd_SSRFGuardBlocksLoopback(t *testing.T) {
	cfg := &Config{
		HTTPPort: 0, HTTPSPort: 0,
		DialTimeout: 1 * time.Second, IdleTimeout: 1 * time.Second,
		HelloRdTime: 1 * time.Second,
		AllowPrivate: false, // GUARD ON
		HappyEyeballsDelay: 50 * time.Millisecond,
	}
	httpAddr, _, stop := startTestProxy(t, cfg)
	defer stop()

	cl, err := net.Dial("tcp", httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	_, _ = cl.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _ := cl.Read(buf)
	// Proxy should close without writing anything (no backend to talk to).
	if n > 0 {
		t.Errorf("expected no body when SSRF guard blocks; got %q", buf[:n])
	}
}
