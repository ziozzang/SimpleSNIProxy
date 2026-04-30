package main

import (
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Config struct {
	BindAddrs []string

	HTTPPort  int
	HTTPSPort int

	DialTimeout time.Duration
	IdleTimeout time.Duration
	HelloRdTime time.Duration

	// DNS / IPv6
	DNSServer   string
	DNS64Prefix string
	PreferIPv6  bool
	HappyEyeballsDelay time.Duration

	// SSRF / safety
	AllowPrivate bool

	// Bypass: TLS
	TLSFragment    bool
	TLSFragOffset  int           // bytes from start; <=0 means split inside SNI hostname
	TLSFragDelay   time.Duration

	// Bypass: HTTP
	HTTPMutateHost   bool
	HTTPFragment     bool
	HTTPFragDelay    time.Duration

	// Logging
	Verbose bool
}

func ParseFlags() (*Config, error) {
	c := &Config{}

	binds := flag.String("bind", "::,0.0.0.0",
		"Comma-separated bind addresses. Default listens on both IPv6 and IPv4.")
	flag.IntVar(&c.HTTPPort, "http", 80, "HTTP listen port (0 to disable)")
	flag.IntVar(&c.HTTPSPort, "https", 443, "HTTPS/SNI listen port (0 to disable)")

	flag.DurationVar(&c.DialTimeout, "dial-timeout", 10*time.Second, "Backend dial timeout")
	flag.DurationVar(&c.IdleTimeout, "idle-timeout", 5*time.Minute, "Idle timeout per direction (sliding)")
	flag.DurationVar(&c.HelloRdTime, "hello-timeout", 10*time.Second, "Time limit for reading initial Host header / ClientHello")

	flag.StringVar(&c.DNSServer, "dns", "",
		"Custom DNS server (e.g. 1.1.1.1, 8.8.8.8:53, 2606:4700:4700::1111). Empty = system resolver.")
	flag.StringVar(&c.DNS64Prefix, "dns64", "",
		"DNS64 NAT64 prefix /96 (e.g. 64:ff9b::/96). Synthesizes AAAA from A when no AAAA exists.")
	flag.BoolVar(&c.PreferIPv6, "prefer-ipv6", true, "Prefer IPv6 when dialing backends")
	flag.DurationVar(&c.HappyEyeballsDelay, "happy-eyeballs-delay", 250*time.Millisecond,
		"Delay before falling back to alternate IP family")

	flag.BoolVar(&c.AllowPrivate, "allow-private", false,
		"Allow proxying to private/loopback/link-local addresses (DANGEROUS — SSRF risk)")

	flag.BoolVar(&c.TLSFragment, "tls-frag", true,
		"Fragment TLS ClientHello across TCP writes to bypass SNI-based DPI")
	flag.IntVar(&c.TLSFragOffset, "tls-frag-offset", 0,
		"TLS fragmentation split offset (bytes from record start). 0 = split inside SNI hostname")
	flag.DurationVar(&c.TLSFragDelay, "tls-frag-delay", 5*time.Millisecond,
		"Delay between fragmented TLS writes")

	flag.BoolVar(&c.HTTPMutateHost, "http-mutate-host", true,
		"Mutate HTTP Host header (random case + whitespace) to bypass HTTP DPI")
	flag.BoolVar(&c.HTTPFragment, "http-frag", true,
		"Send HTTP request line and headers in fragmented writes")
	flag.DurationVar(&c.HTTPFragDelay, "http-frag-delay", 5*time.Millisecond,
		"Delay between fragmented HTTP writes")

	flag.BoolVar(&c.Verbose, "v", false, "Verbose logging")

	flag.Parse()

	for _, b := range strings.Split(*binds, ",") {
		b = strings.TrimSpace(b)
		if b != "" {
			c.BindAddrs = append(c.BindAddrs, b)
		}
	}
	if len(c.BindAddrs) == 0 {
		return nil, fmt.Errorf("at least one -bind address required")
	}

	if c.DNS64Prefix != "" {
		p, err := netip.ParsePrefix(c.DNS64Prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid -dns64 prefix: %w", err)
		}
		if !p.Addr().Is6() || p.Addr().Is4In6() {
			return nil, fmt.Errorf("-dns64 prefix must be IPv6")
		}
		if p.Bits() != 96 {
			return nil, fmt.Errorf("-dns64 only supports /96 prefixes (RFC 6052 well-known case); got /%d", p.Bits())
		}
	}
	return c, nil
}
