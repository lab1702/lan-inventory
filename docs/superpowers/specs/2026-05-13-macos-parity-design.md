# macOS parity for lan-inventory

**Date:** 2026-05-13
**Status:** Design

## Goal

Bring the macOS build of `lan-inventory` to full feature parity with the
Linux build: passive ARP sniffing, kernel-ARP-cache seed, default-route
detection, active ICMP/TCP/NBNS probes, mDNS browsing, and the TUI. After
this work, `go build ./cmd/lan-inventory` on macOS produces a binary that
behaves the same way as the Linux build does today. Both `arm64` and
`amd64` are supported via a plain `//go:build darwin` tag.

## Non-goals

- *BSD parity. FreeBSD / OpenBSD / NetBSD remain in `_other.go`: the route
  resolver continues to return the existing "not implemented" error (hard
  startup failure) and `arp_seed_other.go` continues to no-op
  (return `nil`).
- IPv6.
- Persisting state across runs.
- Repackaging the `Makefile`. macOS users run the existing Makefile
  targets unchanged.
- VPN-aware default-route picking.
- Auto-installing ChmodBPF from the binary.

## User-facing changes

### Install

macOS users install once. Recommended path uses Wireshark's ChmodBPF
launchd helper to grant non-root BPF access, mirroring the Linux `setcap`
experience:

```bash
brew install --cask wireshark        # installs ChmodBPF launchd helper
go install github.com/lab1702/lan-inventory/cmd/lan-inventory@latest
lan-inventory
```

Alternatively, without Wireshark:

```bash
go install github.com/lab1702/lan-inventory/cmd/lan-inventory@latest
sudo lan-inventory
```

libpcap ships with macOS, so no `brew install libpcap` step is required.

### Privilege model

On macOS, the binary does not need root at runtime if ChmodBPF is
installed:

- **Packet capture** — BPF (`/dev/bpf*`) is the gate. ChmodBPF grants the
  `access_bpf` group read access to BPF devices, exactly mirroring
  Linux's setcap UX. `sudo` is an equivalent fallback.
- **ICMP** — the ping probe switches to `pro-bing`'s unprivileged mode on
  macOS, which uses `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`. macOS
  allows this for any user without setup. RTT and TTL are still reported
  (TTL via the `IP_RECVTTL` OOB control message).
- **NBNS / TCP / DNS / mDNS** — already use the standard Go `net` stack
  with no platform-specific privilege requirement.

On Linux and Windows, the privilege model is unchanged.

## Architecture

The codebase already isolates OS-specific logic via build tags
(`route_linux.go` / `route_windows.go` / `route_other.go`, similar for
ARP seed). This work adds two `_darwin.go` files and tightens the
existing `_other.go` build tags. No new packages, no new abstractions.

```
netiface/
  route_linux.go      (unchanged)
  route_windows.go    (unchanged)
  route_darwin.go     NEW  — pure-Go BSD route socket via golang.org/x/net/route
  route_other.go      MOD  — build tag becomes !linux && !windows && !darwin

scanner/
  arp_seed_linux.go    (unchanged)
  arp_seed_windows.go  (unchanged)
  arp_seed_darwin.go   NEW  — NET_RT_FLAGS sysctl via golang.org/x/net/route
  arp_seed_other.go    MOD  — build tag becomes !linux && !windows && !darwin
  arp.go               (unchanged — pcap is portable; libpcap ships with macOS)
  pcap_device_other.go (unchanged — friendly iface name `en0` works with libpcap)
  precheck.go          (unchanged)

probe/
  ping_other.go        MOD  — SetPrivileged(runtime.GOOS == "linux")
  ping.go              (unchanged)
  ping_windows.go      (unchanged)

cmd/lan-inventory/main.go
                       MOD  — add `case "darwin":` to precheck-failure switch

.github/workflows/ci.yml
                       MOD  — matrix adds macos-latest

README.md              MOD  — add macOS install section; update Limitations
Makefile               (unchanged)
go.mod                 MOD  — promote golang.org/x/net to a direct dep
```

The merger, TUI, snapshot, and OUI packages are untouched. The Darwin
code is two new files that emit the same `Update` records the
Linux/Windows variants do.

## Components

### `netiface/route_darwin.go`

`//go:build darwin`. Implements
`defaultRouteInterface() (*net.Interface, net.IP, error)` using
`golang.org/x/net/route`:

1. `route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)` —
   sysctl-dumps the IPv4 routing table.
2. `route.ParseRIB(route.RIBTypeRoute, rib)` — parses into typed
   messages.
3. Iterate `*route.RouteMessage` entries, keep those whose destination
   is the IPv4 unspecified address (`0.0.0.0`) with a missing or
   all-zero netmask — these are the default routes.
4. From each surviving message, extract: `Index` (interface index) and
   `Addrs[RTAX_GATEWAY]` cast to `*route.Inet4Addr` (the next-hop).
5. If multiple defaults exist (rare on macOS, slightly more common with
   VPN clients), pick the first one in sysctl order. This matches the
   kernel's preferred route and `netstat -rn` ordering.
6. `net.InterfaceByIndex` bridges back into Go's `net` package.
7. Wrap any sysctl/parse error so the message names the failing call.

To keep the syscall code thin and the selection logic testable, expose a
pure helper layer mirroring the Windows pattern:

```go
type routeCandidate struct {
    IfaceIndex int
    Gateway    net.IP
}

func defaultRouteCandidates(msgs []route.Message) []routeCandidate
func pickDefaultRouteCandidate(cands []routeCandidate) (*routeCandidate, error)
```

`defaultRouteInterface` wires syscall → parse → helpers →
`net.InterfaceByIndex`. The helpers are unit-tested with fabricated
`route.RouteMessage` values; the `route` package's `Inet4Addr` type is
exported and fabricable.

### `scanner/arp_seed_darwin.go`

`//go:build darwin`. Implements `SeedFromKernelARP` mirroring the
Linux/Windows contract (best-effort, returns `nil` on any error):

1. `net.InterfaceByName(ifaceName)` for the interface index.
2. `route.FetchRIB(syscall.AF_INET, route.RIBType(unix.NET_RT_FLAGS), unix.RTF_LLINFO)`
   — sysctl-dumps the ARP cache. `golang.org/x/sys/unix` exposes both
   constants on darwin.
3. `route.ParseRIB(route.RIBTypeRoute, rib)` — same parser; ARP entries
   arrive as `*route.RouteMessage` with destination = neighbor IPv4
   address and gateway = `*route.LinkAddr` carrying the MAC.
4. Project parsed messages into `arpRow` (interface index, IP, MAC).
5. Pass to `rowsToUpdates`, which filters by interface index + subnet,
   drops zero-length or all-zero MACs, and emits one
   `Update{Source: "arp-seed", ...}` per survivor with vendor populated
   via `oui.Lookup`.

Pure helper signature is identical in shape to the Windows file:

```go
type arpRow struct {
    IfaceIndex int
    IP         net.IP
    MAC        net.HardwareAddr
}

func extractARPRows(msgs []route.Message) []arpRow
func rowsToUpdates(rows []arpRow, ifaceIndex int, subnet *net.IPNet, now time.Time) []Update
```

`SeedFromKernelARP` is the syscall wrapper; `extractARPRows` and
`rowsToUpdates` are unit-tested with fabricated inputs.

### `netiface/route_other.go` (modified)

Build tag tightens to `//go:build !linux && !windows && !darwin`. Body
unchanged.

### `scanner/arp_seed_other.go` (modified)

Build tag tightens to `//go:build !linux && !windows && !darwin`. Body
unchanged (returns `nil`).

### `probe/ping_other.go` (modified)

One-line change inside `Ping`:

```go
pinger.SetPrivileged(runtime.GOOS == "linux")
```

`runtime` is added to the import list. On macOS this makes `pro-bing`
use unprivileged `SOCK_DGRAM` ICMP. TTL still propagates via the
`IP_RECVTTL` OOB control message, so `OSGuess` continues to work. On
Linux the behavior is unchanged (raw socket via setcap).

### `cmd/lan-inventory/main.go` (modified)

Add a `case "darwin":` branch to the existing `runtime.GOOS` switch in
the precheck-failure block:

```go
case "darwin":
    fmt.Fprintln(os.Stderr, "Either install Wireshark's ChmodBPF helper")
    fmt.Fprintln(os.Stderr, "(brew install --cask wireshark), or run with sudo:")
    fmt.Fprintln(os.Stderr, "    sudo lan-inventory")
```

Linux and Windows branches are unchanged.

### `.github/workflows/ci.yml` (modified)

Add `macos-latest` to the matrix:

```yaml
matrix:
  os: [ubuntu-latest, windows-latest, macos-latest]
```

No new install step. libpcap ships with macOS, and the existing
Linux-only `apt-get install libpcap-dev` and Windows-only Npcap SDK
steps already have `if: runner.os == 'Linux'` / `'Windows'` guards, so
they skip on macOS automatically. `go vet`, `staticcheck`, and
`go test ./...` run unmodified on all three platforms.

### `README.md` (modified)

- Add a `### macOS` install section under Install, parallel to the
  existing Linux and Windows sections. Covers `brew install --cask
  wireshark` (ChmodBPF, preferred) and `sudo lan-inventory` (fallback).
- Update the platform-support Limitations bullet from `Supported on
  Linux and Windows. macOS and *BSD builds compile but fail at startup`
  to `Supported on Linux, macOS, and Windows. *BSD builds compile but
  fail at startup (default-route detection is not implemented for those
  platforms).`

### `go.mod` (modified)

Promote `golang.org/x/net` from indirect to direct dep. Already present
transitively at v0.49.0 — no new external dependency.

## Data flow

Unchanged. The Darwin code adds two emitters of identical-shape records:

- `route_darwin.go` populates `netiface.Info` at startup, like
  `route_linux.go` does on Linux.
- `arp_seed_darwin.go` emits `Update{Source: "arp-seed"}` records into
  the merger at startup, identical to `arp_seed_linux.go`.

The merger has no awareness of which platform produced the seed — the
records are indistinguishable from Linux seeds.

## Error handling

- **Default route missing.** `route_darwin.go` returns the same
  `"no default route — cannot determine which subnet to scan"` error
  string as Linux and Windows. `main.go`'s existing exit-code-2 path
  handles it unchanged.
- **No BPF access.** `Precheck`'s `pcap.OpenLive` fails with
  permission-denied; `main.go` prints the new macOS hint and exits with
  code 2 (config error).
- **`FetchRIB(NET_RT_FLAGS)` failure.** `SeedFromKernelARP` returns
  `nil`. Same best-effort contract as Linux — the passive `ARPWorker`
  fills the gap once packets cross the wire.
- **Unprivileged ICMP failure.** `pro-bing` returns an error; `Ping`
  returns it; `ActiveWorker` already tolerates per-host ping failures
  and falls back to TCP probes and known-IP enrichment.

## Testing

### Unit tests

- `netiface/route_darwin_test.go` (`//go:build darwin`) — exercises
  `defaultRouteCandidates` with fabricated `route.RouteMessage` slices
  covering: single default route passes through, non-default routes
  filtered, IPv6 routes filtered, all-zero netmask treated as default,
  multiple defaults all return as candidates. Exercises
  `pickDefaultRouteCandidate` with: empty list returns the expected
  error, first-in-list wins.
- `scanner/arp_seed_darwin_test.go` (`//go:build darwin`) — exercises
  `extractARPRows` (LinkAddr with 6-byte MAC passes, missing LinkAddr
  filtered, wrong-length MAC filtered) and `rowsToUpdates` (wrong-
  interface rows filtered, out-of-subnet rows filtered, zero-MAC rows
  filtered, valid rows pass through with correct vendor lookup).
  Mirrors `arp_seed_windows_test.go`'s coverage.
- `probe/ping_test.go` — extend `TestPingLocalhost` so it does not
  `t.Skipf` on macOS; unprivileged mode should make it succeed without
  root. No new test file.

The existing platform-portable test suite (`model`, `merger`, `oui`,
`snapshot`, `tui`, `probe/dns`, `probe/nbns`, `probe/osguess`,
`probe/ports`, `probe/tcp`) runs unmodified on macos-latest.

### Manual smoke test (macOS)

1. Install Wireshark with ChmodBPF (`brew install --cask wireshark`), or
   plan to use sudo.
2. `go build ./cmd/lan-inventory`
3. From a **non-root** terminal (or `sudo` if ChmodBPF was skipped):
   - `./lan-inventory --version` — prints version.
   - `./lan-inventory --once --table` — prints device rows with IPs,
     MACs, vendors, hostnames.
   - `./lan-inventory` — TUI opens; tabs 1–4 work; `/` filter, `↑/↓`,
     `r` rescan, `q` quit all work.
4. Verify the snapshot includes MAC + vendor for hosts that stealth-drop
   ICMP (validates ARP seed populating from the kernel cache).
5. Verify at least one Linux host shows `os ~ linux/unix` and one
   Windows host shows `os ~ windows` in the snapshot (validates TTL
   propagation through unprivileged ICMP).

### CI gate

`go vet`, `staticcheck`, and `go test ./...` must pass on
`ubuntu-latest`, `windows-latest`, and `macos-latest` before the change
merges.

## Risks and mitigations

- **`unix.NET_RT_FLAGS` / `unix.RTF_LLINFO` constant availability.** The
  `golang.org/x/sys/unix` package exposes both on darwin. Mitigation:
  pin to a recent `golang.org/x/sys` (already at v0.40.0 in go.mod); if
  the constants ever move, define our own
  `const netRTFlags = 2; const rtfLLINFO = 0x400`.
- **`pro-bing` TTL in unprivileged mode on macOS.** Darwin populates
  `IP_RECVTTL` on `SOCK_DGRAM` ICMP sockets, and `pro-bing` reads it via
  OOB control message. If a future macOS release breaks `IP_RECVTTL`
  for unprivileged ICMP, `OSGuess`'s TTL bucket misclassifies but
  everything else still works. Mitigation: smoke-test TTL on at least
  one Linux host (initial 64) and one Windows host (initial 128) per
  macOS release.
- **mDNSResponder port-5353 conflict.** macOS ships mDNSResponder, which
  already binds port 5353. `grandcat/zeroconf` browses (sends queries
  from an ephemeral port), so it does not need to bind 5353.
  Mitigation: smoke-test that mDNS hostname enrichment lights up.
- **GitHub macOS runner minute cost.** Free-tier macOS minutes are 10x
  Linux. Mitigation: matrix `fail-fast: false` is already set; if cost
  becomes a problem later, downshift macOS to `push`-only. Out of scope
  for this work.
- **Multiple default routes (rare; VPN clients).** Picking the first
  sysctl entry matches `netstat -rn` ordering, which itself reflects
  kernel preference. Mitigation: smoke-test with a VPN running; if VPN
  routes interfere, add a metric-aware picker later (BSD route messages
  carry `RMX_HOPCOUNT` via `Extra`). YAGNI for now.

## Out of scope

- *BSD parity (FreeBSD / OpenBSD / NetBSD).
- IPv6.
- State persistence.
- VPN-aware default-route picking.
- Auto-installing ChmodBPF from the binary.
