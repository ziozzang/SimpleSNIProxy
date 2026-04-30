# SimpleSNIProxy

A small Go-based transparent **SNI / HTTP Host** proxy. Originally written as
the network sub-product of *Macadamia* (a Go L4/L7 load-balancer) by
[Jioh L. Jung](mailto:ziozzang@gmail.com), and historically used to bypass
Korean ISP HTTP/SNI-based censorship.

📖 **Full documentation:** [English](docs/USAGE.en.md) · [한국어](docs/USAGE.ko.md)

This version has been heavily modernized:

* **Go 1.22**, modules, `log/slog`, contexts, sliding idle timeouts, graceful
  shutdown.
* **IPv6 + dual-stack** listening (separate `tcp4` / `tcp6` sockets).
* **Custom DNS resolver** (`-dns`) and **DNS64** `/96` prefix synthesis
  (`-dns64 64:ff9b::/96`) for IPv6-only / NAT64 networks.
* **Happy-Eyeballs**-style backend dialing with IPv6 preference.
* **SSRF / open-proxy guard**: refuses private, loopback, link-local, CGNAT
  and reserved address ranges by default.
* **DPI-evasion bypass mechanisms** for both HTTP and HTTPS, all toggleable.

> ⚠️  No authentication is built in. Run behind a firewall or a client-IP
> ACL, otherwise it can be abused as an open relay (the proxy already blocks
> private destinations by default but anyone reachable on TCP/80–443 can use
> it to reach public hosts).

## Build & run

```sh
go build -o sniproxy .
./sniproxy                                     # listens on :80 + :443, dual-stack
./sniproxy -http 8080 -https 8443 -bind ::1    # custom ports / bind
```

Or via Docker:

```sh
docker build -t sniproxy .
docker run -d --name sniproxy -p 80:80 -p 443:443 sniproxy
```

## Flags (excerpt)

| Flag | Default | Description |
| --- | --- | --- |
| `-bind` | `::,0.0.0.0` | Comma-separated bind addresses (IPv4/IPv6). |
| `-http` / `-https` | `80` / `443` | Listen ports. `0` to disable. |
| `-dns` | *(system)* | Custom DNS server, e.g. `1.1.1.1`, `2606:4700:4700::1111`, `8.8.8.8:53`. |
| `-dns64` | *(off)* | NAT64 `/96` prefix, e.g. `64:ff9b::/96`. |
| `-prefer-ipv6` | `true` | Prefer IPv6 backend addresses. |
| `-dial-timeout` | `10s` | Backend dial timeout. |
| `-idle-timeout` | `5m` | Sliding idle timeout per direction. |
| `-allow-private` | `false` | Allow proxying to private/loopback/link-local destinations. |
| `-tls-frag` | `true` | Split TLS ClientHello across TCP writes. |
| `-tls-frag-offset` | `0` | Split offset; `0` = split inside the SNI hostname. |
| `-tls-frag-delay` | `5ms` | Delay between fragmented writes. |
| `-http-mutate-host` | `true` | Randomize the case of the `Host:` header name and pad whitespace. |
| `-http-frag` | `true` | Send each request line / header in a separate write. |
| `-http-frag-delay` | `5ms` | Delay between fragmented HTTP writes. |
| `-v` | `false` | Verbose logging. |

## Bypass mechanisms

The proxy is a TCP relay; it does **not** modify TLS bytes, so all evasion
takes place at the TCP-segment / HTTP-text layer.

### TLS / SNI

When forwarding the captured ClientHello to the backend the bytes are
written in two `Write()` calls:

```
                       ┌─ split point (default: middle of SNI hostname) ─┐
[ TLS record header ][ ClientHello … server_name="exam │ ple.com" … ]
        ─────── segment 1 ────────                       ─── segment 2 ───
```

Combined with `TCP_NODELAY` and a small inter-write delay, this defeats DPI
boxes that match the literal SNI hostname inside a single packet. A custom
byte offset can be supplied via `-tls-frag-offset`.

> Note: TCP segmentation is best-effort. Sufficiently capable DPI can
> reassemble the stream and still see the SNI. Encrypted ClientHello (ECH)
> will eventually make plaintext-SNI routing impossible — the proxy logs and
> closes cleanly when no usable SNI is present.

### HTTP

* **Header-name case mutation** — `Host:` is rewritten to e.g. `hOSt:` with
  random per-byte case (HTTP header names are case-insensitive per RFC 9110,
  so all compliant servers accept it).
* **Optional whitespace** — extra space after the colon is OWS-legal.
* **Per-line fragmentation** — request line and each header are written
  individually with a small delay, so the request line and the `Host` header
  land in separate TCP segments.

### Network-layer features

* IPv6 / IPv4 dual-stack listeners.
* DNS64 `/96` synthesis when AAAA is missing — useful behind NAT64 in
  IPv6-only environments. (Other RFC 6052 prefix lengths are explicitly
  rejected at startup.)
* Happy-Eyeballs-style staggered connect across resolved addresses.
* SSRF / open-proxy guard rejecting private / loopback / link-local / CGNAT
  / TEST-NET / multicast / reserved destinations unless `-allow-private` is
  set.

## Limitations

* Plaintext SNI only (no ECH).
* One TLS record’s worth of ClientHello must contain the SNI extension
  (true in practice for all real-world clients).
* No authentication — front with a firewall.

## Credits

* Original SNI parser based on
  [`stupid-proxy`](https://github.com/gpjt/stupid-proxy/) by Giles Thomas.
* Original SimpleSNIProxy by Jioh L. Jung (`ziozzang@gmail.com`).
