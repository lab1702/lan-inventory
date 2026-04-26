# Hostname Enrichment — Design

**Status:** Approved  •  **Date:** 2026-04-26

A focused refinement on top of the v0.1.0 + color + OUI tree. Today the
Hostname column is empty for many devices because we only consult two
sources: passive mDNS service announcements (handled by the existing mDNS
worker) and PTR lookups via the system resolver (which usually fails on
home networks because upstream DNS has no PTR for RFC1918 IPs). This change
adds three new lookup paths that, in combination, cover the typical
home-LAN gaps: Windows machines, DHCP-lease names known to the router, and
mDNS-only devices that don't actively announce services.

## Goals and non-goals

**Goals**

- Hostname column populated for the majority of typical home-LAN devices.
- Multiple lookup sources tried in priority order with early-exit on first hit.
- Each new probe lives in `internal/probe/` as a stateless one-shot, testable in isolation.
- Chain runtime is bounded — a fully dead host adds at most ~2 s to its probe cycle.
- No new dependencies. Pure-Go for NBNS; stdlib `net.Resolver` for DNS variants.

**Non-goals**

- Not querying SNMP. Enterprise gear only; requires credentials.
- Not parsing router-specific DHCP lease files. Not portable.
- Not adding a configurable lookup-source list. Hardcoded chain order is enough.
- Not caching hostnames separately. The merger's device map already retains hostname across cycles.
- Not changing the existing mDNS worker's passive listening — it remains the primary source for mDNS-broadcasting devices.

## Lookup chain (priority order)

`probe.ResolveHostname(ctx, ip, gatewayIP) string` is the new entry point. It
calls four probes in sequence and returns the first non-empty answer:

1. **System rDNS** — `net.DefaultResolver.LookupAddr(ctx, ip)`. Existing behavior, unchanged. Works on networks with corporate / VPN DNS configs that include PTR records.
2. **Gateway resolver** — same `LookupAddr` but with a custom `net.Resolver` whose `Dial` targets `<gatewayIP>:53`. Most consumer routers and OpenWrt/OPNsense/pfSense run dnsmasq or equivalent and answer DHCP-lease names.
3. **NBNS** — UDP 137 Node Status Request to the device IP. Returns the device's NetBIOS name. Covers Windows boxes, NAS appliances, and Samba-equipped Linux hosts.
4. **mDNS reverse** — unicast PTR query for `<reversed-octets>.in-addr.arpa.` to the device's UDP port 5353. Apple / avahi devices answer here even when they don't actively announce services.

Each probe carries its own 500 ms timeout. The chain bounds at ~2 s per host
in the worst case (all four time out). On a typical home LAN with ~30 alive
devices, this adds ~30 s of extra probe time per scan cycle in the worst
case (all dead) — easily absorbed by the 30 s active-scan interval.

## Files touched

| Path                                    | Change | Purpose                                                |
|-----------------------------------------|--------|---------------------------------------------------------|
| `internal/probe/dns.go`                 | Modify | Add `ReverseDNSVia`, `ReverseDNSMDNS`, `ResolveHostname`. |
| `internal/probe/nbns.go`                | New    | NBNS Node Status Request probe.                         |
| `internal/probe/nbns_test.go`           | New    | Pure-function tests for `parseNBNSResponse` + query format. |
| `internal/probe/dns_test.go`            | Modify | Add chain-runtime test for `ResolveHostname` on dead IP. |
| `internal/netiface/netiface.go`         | Modify | `Info.Gateway net.IP` field.                            |
| `internal/netiface/route_linux.go`      | Modify | `defaultRouteInterface` returns gateway IP too.        |
| `internal/netiface/route_other.go`      | Modify | Stub matches new signature.                             |
| `internal/scanner/active.go`            | Modify | New `Gateway` field; `probeOne` calls `ResolveHostname`. |
| `internal/scanner/scanner.go`           | Modify | Plumb `cfg.Iface.Gateway` into `ActiveWorker`.          |

No new dependencies.

## Probe details

### Gateway resolver — `probe.ReverseDNSVia`

```go
func ReverseDNSVia(ctx context.Context, ip string, resolverIP string) string {
    if resolverIP == "" {
        return ""
    }
    r := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{Timeout: 500 * time.Millisecond}
            return d.DialContext(ctx, "udp", net.JoinHostPort(resolverIP, "53"))
        },
    }
    cctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
    defer cancel()
    names, err := r.LookupAddr(cctx, ip)
    if err != nil || len(names) == 0 {
        return ""
    }
    return strings.TrimSuffix(names[0], ".")
}
```

**`PreferGo: true`** is required — without it Go can fall back to cgo's
`getaddrinfo` and ignore the custom `Dial`. The 500 ms timeout on the
context is a defense-in-depth backup to the `Dialer.Timeout`.

### NBNS — `probe.NBNS`

The NBNS Node Status Request is a 50-byte UDP datagram on port 137:

- 12-byte DNS-style header (transaction ID `0x1234`, flags `0x0010`, 1 question).
- Encoded NetBIOS wildcard name `*<NUL bytes>` (32 bytes after each byte is split into two nibbles + 'A'), prefixed with a length byte (`0x20`) and terminated with NUL.
- Question type `0x0021` (NBSTAT), class `0x0001` (IN).

Implementation is a 50-byte `nbnsQuery` constant + a `parseNBNSResponse`
helper that walks the response. Picking the first name where the type
suffix byte is `0x00` (Workstation/Redirector — the actual machine name)
and the flags don't have the group bit set (`0x8000`). Trim trailing
spaces.

```go
func NBNS(ctx context.Context, ip string) string {
    addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: 137}
    conn, err := net.DialUDP("udp", nil, addr)
    if err != nil {
        return ""
    }
    defer conn.Close()
    deadline := time.Now().Add(500 * time.Millisecond)
    if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
        deadline = dl
    }
    _ = conn.SetDeadline(deadline)
    if _, err := conn.Write(nbnsQuery); err != nil {
        return ""
    }
    buf := make([]byte, 512)
    n, err := conn.Read(buf)
    if err != nil || n < 57 {
        return ""
    }
    return parseNBNSResponse(buf[:n])
}
```

Devices that don't speak NBNS (Linux without Samba, macOS, IoT) simply
ignore the query and we hit the read deadline. One stray UDP packet per
scan cycle per host — negligible noise.

### mDNS reverse — `probe.ReverseDNSMDNS`

Unicast (not multicast) PTR query to the device's port 5353:

```go
func ReverseDNSMDNS(ctx context.Context, ip string) string {
    r := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{Timeout: 500 * time.Millisecond}
            return d.DialContext(ctx, "udp", net.JoinHostPort(ip, "5353"))
        },
    }
    cctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
    defer cancel()
    names, err := r.LookupAddr(cctx, ip)
    if err != nil || len(names) == 0 {
        return ""
    }
    return strings.TrimSuffix(names[0], ".")
}
```

The function is structurally identical to `ReverseDNSVia` — only the
destination port differs. Two named one-liners is clearer than one
parameterised helper.

The name has "MDNS" rather than "Multicast" because the implementation
sends *unicast* to the mDNS port; "MDNS" reflects the protocol path
without misleading on transport.

### Chain — `probe.ResolveHostname`

```go
func ResolveHostname(ctx context.Context, ip string, gatewayIP net.IP) string {
    if name := ReverseDNS(ctx, ip); name != "" {
        return name
    }
    if gatewayIP != nil {
        if name := ReverseDNSVia(ctx, ip, gatewayIP.String()); name != "" {
            return name
        }
    }
    if name := NBNS(ctx, ip); name != "" {
        return name
    }
    if name := ReverseDNSMDNS(ctx, ip); name != "" {
        return name
    }
    return ""
}
```

`ReverseDNS` keeps its existing signature and behavior; `ResolveHostname`
becomes the new public entry point and `ReverseDNS` is one rung in its
ladder.

## Gateway IP plumbing

`/proc/net/route` already gives us the gateway in field 2 (hex-encoded
little-endian). We just need to keep it instead of discarding.

### `defaultRouteInterface` (Linux)

Signature changes from `() (*net.Interface, error)` to
`() (*net.Interface, net.IP, error)`. The candidate struct gains a
`gateway string` field captured during parsing. After picking the best
candidate, decode the hex string into 4 bytes and reverse for endianness:

```go
gwBytes, err := hex.DecodeString(best.gateway)
if err != nil || len(gwBytes) != 4 {
    return iface, nil, nil  // interface ok, gateway unknown — non-fatal
}
gateway := net.IPv4(gwBytes[3], gwBytes[2], gwBytes[1], gwBytes[0])
return iface, gateway, nil
```

A nil gateway is acceptable — `ResolveHostname` skips the gateway-resolver
rung when `gatewayIP == nil`.

### Other platforms

`route_other.go` stub returns `(nil, nil, error)` matching the new signature.

### `Info` struct

```go
type Info struct {
    Name    string
    Subnet  *net.IPNet
    HostIP  net.IP
    Gateway net.IP   // may be nil if /proc/net/route didn't surface a usable address
}
```

`Detect()` plumbs the gateway from `defaultRouteInterface` into the returned
`Info`.

### ActiveWorker

```go
type ActiveWorker struct {
    Subnet      *net.IPNet
    HostIPs     []net.IP
    Gateway     net.IP   // new
    Interval    time.Duration
    WorkerCount int
}
```

`probeOne` changes from `update.Hostname = probe.ReverseDNS(ctx, ip.String())`
to `update.Hostname = probe.ResolveHostname(ctx, ip.String(), w.Gateway)`.

`scanner.Run` sets `Gateway: s.cfg.Iface.Gateway` when constructing the
worker.

## Testing strategy

**Pure-function tests** in `internal/probe/nbns_test.go`:

- `TestParseNBNSResponse`: 6 table cases covering normal Workstation
  response, group-only response (returns ""), too-short buffer, empty name
  list, response with multiple names where the first is a group, response
  with trailing-space padding.
- `TestNBNSQueryFormat`: decode the first 12 bytes of `nbnsQuery` and
  assert question count, type, class match the spec.

**Integration tests against localhost** in `nbns_test.go` and `dns_test.go`:

- `TestNBNSLocalhost` and `TestReverseDNSMDNSLocalhost`: send the probe to
  `127.0.0.1`. Skip cleanly when localhost doesn't respond on those ports
  (the common case in CI). Same skip-pattern the existing `TestPingLocalhost`
  uses.

**Chain runtime test** in `dns_test.go`:

- `TestResolveHostnameDeadIP`: call `ResolveHostname(ctx, "192.0.2.1", nil)`
  (TEST-NET-1) and assert it returns `""` within 3 seconds. Verifies the
  chain bounds and doesn't hang.

**No new mock harness.** The probes are small and tested in isolation; the
chain is trivial enough that a real-network test of the dead path is the
meaningful integration check.

## Implementation phases

1. Plumb `Gateway` through `netiface` (Linux + stub).
2. Add `ReverseDNSVia` and `ReverseDNSMDNS` to `dns.go`.
3. Add `nbns.go` with `nbnsQuery`, `parseNBNSResponse`, `NBNS`, plus tests.
4. Add `ResolveHostname` chain to `dns.go` plus chain-runtime test.
5. Wire `ActiveWorker.Gateway` and switch `probeOne` to `ResolveHostname`.
6. Final lint and verify.

Single feature branch, ~6 commits.

## Risks and mitigations

- **NBNS responses vary across implementations.** Mitigation: test a couple of real-world responses in the table tests; treat any malformed response as no-answer.
- **Slow gateways stalling the chain.** Mitigation: bounded 500 ms timeout per probe.
- **`net.Resolver` cgo fallback ignoring custom Dial.** Mitigation: explicit `PreferGo: true` documented in the spec.
- **Overall scan cycle stretches under all-dead conditions.** Mitigation: alive-only — `probeOne` only enters the resolution chain when the host responded to ping. Dead hosts never reach `ResolveHostname`.

## Out of scope (non-goals reaffirmed)

- SNMP queries.
- Router-specific lease-file parsing.
- User-configurable chain order.
- Per-source caching beyond the merger's existing device map.
