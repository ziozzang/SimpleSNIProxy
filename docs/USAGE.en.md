# SimpleSNIProxy — User & Developer Guide (English)

> Korean version: [`USAGE.ko.md`](USAGE.ko.md)

A small, dependency-free Go-based **transparent SNI / HTTP-Host proxy** with
modern networking (IPv6, DNS64, Happy Eyeballs) and built-in DPI-evasion for
plain SNI / HTTP censorship circumvention.

---

## Table of Contents

1. [What it does](#what-it-does)
2. [How it works](#how-it-works)
3. [Quick start](#quick-start)
4. [All flags](#all-flags)
5. [DPI-evasion / SNI bypass mechanisms](#dpi-evasion--sni-bypass-mechanisms)
6. [IPv6, DNS64 and dual-stack](#ipv6-dns64-and-dual-stack)
7. [SSRF / open-proxy guard](#ssrf--open-proxy-guard)
8. [Operational notes](#operational-notes)
9. [Architecture & code layout](#architecture--code-layout)
10. [Testing](#testing)
11. [Troubleshooting](#troubleshooting)
12. [Limitations & threat model](#limitations--threat-model)
13. [License & credits](#license--credits)

---

## What it does

When a client opens a TCP connection to the proxy:

* On the **HTTP** port (`:80` by default) it parses the request line and
  headers, extracts the `Host:` header, dials that hostname, and bridges the
  two TCP streams. The Host header may be obfuscated and headers may be
  fragmented across TCP segments to defeat DPI.
* On the **HTTPS** port (`:443` by default) it parses the TLS ClientHello,
  extracts the SNI hostname, dials that hostname, replays the captured
  ClientHello (optionally split across TCP writes inside the SNI hostname),
  and bridges the two streams.

The proxy never decrypts TLS; it acts purely as a transparent L4 router
keyed on plaintext SNI / Host.

## How it works

```
            ┌──────────────────────────────────────────────────────┐
            │                  SimpleSNIProxy                      │
 client ───►│  accept │ parse SNI / Host │ dial backend │ bridge   │───► origin
            │             ▲                  │                     │
            │             │                  ▼                     │
            │     bypass mutations:    SSRF guard, IPv6+DNS64       │
            │     • TLS frag at SNI     resolver, Happy Eyeballs   │
            │     • Host case + OWS                                 │
            │     • per-line frag                                   │
            └──────────────────────────────────────────────────────┘
```

* Dialing uses a configurable resolver and synthesises AAAA records via DNS64
  when no AAAA exists for an A-only host.
* Resolved IPs are filtered against an SSRF deny-list (loopback, private,
  link-local, CGNAT, multicast, reserved).
* Bidirectional copy uses sliding idle timeouts and TCP half-close so neither
  direction is killed mid-transfer.

## Quick start

```sh
# build
git clone https://github.com/ziozzang/SimpleSNIProxy
cd SimpleSNIProxy
go build -o sniproxy .

# run on default ports (needs root or CAP_NET_BIND_SERVICE for :80/:443)
sudo ./sniproxy

# run on high ports for testing
./sniproxy -http 8080 -https 8443
```

Or with Docker:

```sh
docker build -t sniproxy .
docker run -d --name sniproxy --restart=always \
  -p 80:80 -p 443:443 sniproxy

# with custom DNS and DNS64 (IPv6-only host behind NAT64)
docker run -d --name sniproxy \
  -p 80:80 -p 443:443 sniproxy \
  -dns 2606:4700:4700::1111 -dns64 64:ff9b::/96
```

Test it without changing OS DNS:

```sh
curl --resolve example.com:8443:127.0.0.1 \
     --resolve example.com:8080:127.0.0.1 \
     -v https://example.com:8443/
```

## All flags

| Flag | Default | Description |
|---|---|---|
| `-bind` | `::,0.0.0.0` | Comma-separated bind addresses. Two listeners are created (one per family) for portable dual-stack. |
| `-http` | `80` | HTTP port (`0` disables). |
| `-https` | `443` | HTTPS / SNI port (`0` disables). |
| `-dial-timeout` | `10s` | Total backend dial timeout. |
| `-idle-timeout` | `5m` | Sliding per-direction idle timeout for the bridged TCP stream. |
| `-hello-timeout` | `10s` | Read deadline for the initial Host header / ClientHello. |
| `-dns` | *(system)* | Override system DNS, e.g. `1.1.1.1`, `8.8.8.8:53`, `2606:4700:4700::1111`. |
| `-dns64` | *(off)* | NAT64 prefix for DNS64 synthesis. **Only `/96` is supported.** Example: `64:ff9b::/96`. |
| `-prefer-ipv6` | `true` | Try IPv6 backend addresses before IPv4. |
| `-happy-eyeballs-delay` | `250ms` | Stagger between concurrent dial attempts to alternate addresses. |
| `-allow-private` | `false` | Allow proxying to private/loopback/link-local/etc. **Dangerous; see SSRF section.** |
| `-tls-frag` | `true` | Fragment the captured TLS ClientHello across TCP writes. |
| `-tls-frag-offset` | `0` | Custom split byte offset; `0` means split inside the SNI hostname. |
| `-tls-frag-delay` | `5ms` | Delay between fragmented TLS writes. |
| `-http-mutate-host` | `true` | Randomise the case of the `Host` header name and pad post-colon whitespace. |
| `-http-frag` | `true` | Send each request line / header in its own write. |
| `-http-frag-delay` | `5ms` | Delay between fragmented HTTP writes. |
| `-v` | `false` | Verbose / debug logging. |

## DPI-evasion / SNI bypass mechanisms

Plaintext SNI is the easiest TLS-handshake field to censor. Most simple DPI
boxes search for the literal hostname string inside a single TCP segment of
the first packet of a flow. The proxy attacks two assumptions:

1. **The hostname appears contiguous in one packet.** → Split across writes.
2. **The hostname appears at a known byte offset.** → Split inside the
   hostname itself.

### TLS fragmentation

After parsing, the proxy knows the exact byte offset of the SNI hostname
inside the captured ClientHello. By default it issues two `Write()` calls,
splitting at `HostnameStart + HostnameLen/2`:

```
[ TLS hdr ][ ClientHello … server_name="exam │ ple.com" … ]
   ─────── write #1 ───────                   ── write #2 ──
```

Combined with `TCP_NODELAY` and a small inter-write delay (`-tls-frag-delay`),
the two payloads typically land in two distinct TCP segments. DPI matchers
that pattern-match per packet then fail to see a complete hostname.

You can override the split offset with `-tls-frag-offset N` (bytes from the
start of the captured record). Useful when the censor is known to look at a
fixed prefix.

### HTTP Host obfuscation

* **Header-name case randomisation**: `Host:` → e.g. `hOSt:`. RFC 9110
  guarantees header names are case-insensitive, so all servers accept this.
* **Optional whitespace** after the colon (still RFC-valid OWS).
* **Per-line fragmentation**: the request line, each header, and the empty
  terminator are written individually with `-http-frag-delay` between them.

### What this does **not** do

* Stream-reassembling DPI can still see the full request/handshake. This
  proxy is best-effort.
* It does **not** rewrite an HTTP `GET http://example.com/...` absolute-form
  request target. Absolute-form requests can leak the hostname even with the
  Host header obfuscated.
* It cannot help with **Encrypted ClientHello (ECH)** — there is no
  plaintext SNI to route on. The proxy cleanly logs and closes such flows.
* It does not re-encode TLS records or pad ClientHellos.

## IPv6, DNS64 and dual-stack

### Dual-stack listening

`-bind ::,0.0.0.0` creates two explicit listeners — one `tcp6` on `[::]`,
one `tcp4` on `0.0.0.0` — instead of relying on the OS-dependent V6ONLY
default. This works identically on Linux, macOS, BSDs and Windows.

To listen on IPv6 only: `-bind ::`. To listen on IPv4 only: `-bind 0.0.0.0`.

### Custom resolver

`-dns 1.1.1.1` (or `[2606:4700:4700::1111]:53`, etc.) installs a
`*net.Resolver{PreferGo:true}` that talks directly to the given server. Bare
IPv6 literals are auto-bracketed and the default port `53` is appended when
absent.

### DNS64 synthesis (`-dns64 64:ff9b::/96`)

For each lookup the resolver returns both A and AAAA records. If AAAA is
empty but A is non-empty *and* a `/96` DNS64 prefix is configured, the proxy
synthesises AAAA records by embedding the IPv4 in the lower 32 bits of the
prefix (RFC 6052). This lets an IPv6-only host reach IPv4-only origins via a
NAT64 gateway without configuring the OS-level DNS64 resolver.

Only `/96` is supported on purpose; non-/96 prefixes are rejected at startup.

### Happy Eyeballs

When multiple addresses are returned, dial attempts are launched in
preferred order with `-happy-eyeballs-delay` between them. The first
successful connect wins and the remaining attempts are cancelled. This
tolerates IPv6 black-holes without sacrificing IPv6-by-default behaviour.

## SSRF / open-proxy guard

Because the proxy follows whatever hostname the client sent, an unprotected
deployment can become an SSRF pivot into your LAN. After resolving, every
candidate IP is checked against:

* loopback (`127.0.0.0/8`, `::1`)
* unspecified (`0.0.0.0`, `::`)
* private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`)
* link-local (`169.254/16`, `fe80::/10`)
* multicast (`224/4`, `ff00::/8`)
* CGNAT (`100.64/10`)
* benchmark (`198.18/15`)
* documentation (`192.0.2/24`, `198.51.100/24`, `203.0.113/24`)
* protocol assignment (`192.0.0/24`)
* reserved (`240/4`)

If **all** resolved addresses are disallowed, the dial fails and the request
is dropped. Set `-allow-private` to opt out (e.g. when proxying inside a
trusted lab).

## Operational notes

* Ports below 1024 require either root or
  `setcap cap_net_bind_service=+ep ./sniproxy` on Linux.
* The Docker image runs as `nonroot`. Map it through a host port (`-p 80:80`)
  or run your own reverse balancer on `:80`/`:443` in front of it.
* Logs are structured (`log/slog` text format) on stderr.
* SIGINT/SIGTERM triggers graceful shutdown: listeners close, in-flight
  connections are given up to 10 seconds to drain.
* Per-connection failures never abort the daemon (the original code used
  `log.Fatal` — that is gone).

## Architecture & code layout

```
main.go     entrypoint, listener wiring, graceful shutdown
config.go   flag definitions and validation
dial.go     resolver, DNS64 /96 synthesis, Happy Eyeballs, SSRF filter
tls.go      bounds-checked ClientHello parser + fragmenting writer
proxy.go    HTTP / HTTPS request handlers, Host header mutation
pipe.go     bidirectional copy with sliding idle timeout and half-close
proxy_test.go  unit + end-to-end tests
```

Each file is independent of the others except via small typed surfaces
(`Config`, `Dialer`, `Proxy`, `ClientHello`).

## Testing

```sh
go test ./...
go test -v -run TestEndToEnd ./...
go test -race ./...
```

The test suite covers:

* TLS ClientHello parser (extracts SNI, computes hostname offset, rejects
  non-TLS and truncated records). Real ClientHellos are produced by
  `crypto/tls`, captured off a `net.Pipe` and fed back through the parser.
* `WriteFragmented` produces multiple discrete reads on the wire.
* `mutateHostHeader` — output still parses as a `Host:` header with the
  same value but a different on-the-wire byte sequence.
* DNS64 synthesis math (`64:ff9b::/96` + `192.0.2.33` → `64:ff9b::c000:221`).
* SSRF guard accept/reject for ~14 representative addresses.
* DNS server-string normalisation (IPv4 / IPv6 / port present / port absent).
* `PipeConns` — bidirectional copy with TCP half-close.
* End-to-end HTTP through the proxy: a real backend captures the forwarded
  bytes and asserts that the Host header was *mutated* (not left as the
  literal `Host: …`) but is still semantically valid and routes correctly.
* End-to-end SSRF guard: a request for `Host: 127.0.0.1` returns no body.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `bind: permission denied` on `:80`/`:443` | Need root or `CAP_NET_BIND_SERVICE`. |
| `bind: address already in use` | Another HTTP/HTTPS server already on that port. |
| `dial backend failed: … private/special; refusing` | Backend resolves to a blocked range. Pass `-allow-private` if intentional. |
| `no SNI in ClientHello (ECH or anonymous?)` | Client uses ECH or omitted SNI. Cannot route. |
| Bypass not working against a real censor | Check that `TCP_NODELAY` is taking effect (e.g. proxy not behind a coalescing tunnel) and try increasing `-tls-frag-delay` to e.g. `30ms`. |

## Limitations & threat model

* **Best-effort DPI evasion only.** Stream-reassembling DPI defeats TCP
  segmentation tricks. This tool is intended for naïve censors that match
  inside a single packet.
* **Plaintext SNI required.** ECH cannot be routed.
* **No client authentication.** Front with a firewall, ACL, or auth proxy.
* **TLS bytes are forwarded verbatim** — the proxy never sees plaintext
  application data.
* **One TLS record** must contain the entire ClientHello (true in practice
  for every real-world client).

## License & credits

* Original SNI parser based on
  [`stupid-proxy`](https://github.com/gpjt/stupid-proxy/) by Giles Thomas.
* Original SimpleSNIProxy by Jioh L. Jung (`ziozzang@gmail.com`).
* See [`LICENSE`](../LICENSE) for terms.
