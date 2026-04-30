package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"
)

type Dialer struct {
	cfg      *Config
	resolver *net.Resolver
	dns64    netip.Prefix // zero value if disabled
}

func NewDialer(cfg *Config) (*Dialer, error) {
	d := &Dialer{cfg: cfg, resolver: net.DefaultResolver}

	if cfg.DNSServer != "" {
		addr := normalizeDNSAddr(cfg.DNSServer)
		nd := &net.Dialer{Timeout: 5 * time.Second}
		d.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return nd.DialContext(ctx, network, addr)
			},
		}
	}
	if cfg.DNS64Prefix != "" {
		p, err := netip.ParsePrefix(cfg.DNS64Prefix)
		if err != nil {
			return nil, err
		}
		d.dns64 = p
	}
	return d, nil
}

func normalizeDNSAddr(s string) string {
	s = strings.TrimSpace(s)
	// already host:port?
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	// bare IPv6?
	if ip, err := netip.ParseAddr(s); err == nil && ip.Is6() && !ip.Is4In6() {
		return net.JoinHostPort(s, "53")
	}
	return net.JoinHostPort(s, "53")
}

// Resolve returns IPs for the host. Honors DNS64 /96 synthesis when AAAA is missing.
func (d *Dialer) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	// IP literal short-circuit
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	addrs, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	var v4, v6 []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is6() {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}

	// DNS64 synthesis: if no AAAA but A exists and prefix configured.
	if len(v6) == 0 && len(v4) > 0 && d.dns64.IsValid() {
		for _, a := range v4 {
			if syn, ok := synthesizeDNS64(d.dns64, a); ok {
				v6 = append(v6, syn)
			}
		}
	}

	if d.cfg.PreferIPv6 {
		return append(v6, v4...), nil
	}
	return append(v4, v6...), nil
}

// synthesizeDNS64 embeds an IPv4 address into the lower 32 bits of a /96 prefix.
func synthesizeDNS64(prefix netip.Prefix, v4 netip.Addr) (netip.Addr, bool) {
	if !v4.Is4() {
		return netip.Addr{}, false
	}
	pref := prefix.Addr().As16()
	v4b := v4.As4()
	copy(pref[12:16], v4b[:])
	return netip.AddrFrom16(pref), true
}

// Dial resolves and connects with simple Happy Eyeballs (preferred family first,
// then fall back to alternate family after a short delay).
func (d *Dialer) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, d.cfg.DialTimeout)
	defer cancel()

	ips, err := d.Resolve(resolveCtx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}

	// Filter: SSRF guard
	if !d.cfg.AllowPrivate {
		filtered := ips[:0]
		for _, ip := range ips {
			if isDisallowed(ip) {
				slog.Warn("blocked private/special address", "host", host, "ip", ip.String())
				continue
			}
			filtered = append(filtered, ip)
		}
		ips = filtered
		if len(ips) == 0 {
			return nil, fmt.Errorf("all resolved addresses for %s are private/special; refusing (use -allow-private to override)", host)
		}
	}

	type result struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan result, len(ips))
	dialCtx, dialCancel := context.WithCancel(ctx)
	defer dialCancel()

	launch := func(ip netip.Addr, delay time.Duration) {
		select {
		case <-time.After(delay):
		case <-dialCtx.Done():
			resCh <- result{nil, dialCtx.Err()}
			return
		}
		var nd net.Dialer
		nd.Timeout = d.cfg.DialTimeout
		c, err := nd.DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
		resCh <- result{c, err}
	}

	// Schedule attempts: first IP at t=0, each subsequent IP staggered by happy-eyeballs delay.
	for i, ip := range ips {
		go launch(ip, time.Duration(i)*d.cfg.HappyEyeballsDelay)
	}

	var lastErr error
	for i := 0; i < len(ips); i++ {
		r := <-resCh
		if r.err == nil {
			dialCancel() // cancel pending attempts
			// Drain remaining
			go func(n int) {
				for j := 0; j < n; j++ {
					if rr := <-resCh; rr.conn != nil {
						rr.conn.Close()
					}
				}
			}(len(ips) - i - 1)
			return r.conn, nil
		}
		lastErr = r.err
	}
	if lastErr == nil {
		lastErr = errors.New("no successful dial")
	}
	return nil, fmt.Errorf("dial %s: %w", host, lastErr)
}

func isDisallowed(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsPrivate() {
		return true
	}
	// Block 100.64.0.0/10 (CGNAT) and IPv4 special-purpose ranges that Is*() may miss.
	if ip.Is4() {
		b := ip.As4()
		// 100.64.0.0/10
		if b[0] == 100 && (b[1]&0xC0) == 64 {
			return true
		}
		// 169.254.0.0/16 already link-local
		// 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4
		if b[0] == 192 && b[1] == 0 && b[2] == 0 {
			return true
		}
		if b[0] == 192 && b[1] == 0 && b[2] == 2 {
			return true
		}
		if b[0] == 198 && (b[1] == 18 || b[1] == 19) {
			return true
		}
		if b[0] == 198 && b[1] == 51 && b[2] == 100 {
			return true
		}
		if b[0] == 203 && b[1] == 0 && b[2] == 113 {
			return true
		}
		if b[0] >= 240 {
			return true
		}
	}
	// IPv6: ULA fc00::/7 → IsPrivate covers it. Also block ::1, ::, mapped/translated handled.
	return false
}
