# Windows parity for lan-inventory

**Date:** 2026-05-13
**Status:** Design

## Goal

Bring the Windows build of `lan-inventory` to full feature parity with the
Linux build: passive ARP sniffing, kernel-ARP-cache seed, default-route
detection, active ICMP/TCP/NBNS probes, mDNS browsing, and the TUI. After
this work, `go build ./cmd/lan-inventory` on Windows produces a binary that
behaves the same way as the Linux build does today.

## Non-goals

- macOS or *BSD parity. On those platforms `route_other.go` continues to
  return the existing "not implemented" error (a hard startup failure)
  and `arp_seed_other.go` continues to no-op (return `nil`).
- IPv6.
- Persisting state across runs.
- Repackaging the `Makefile` as a PowerShell build script. Windows users run
  `go build` directly.

## User-facing changes

### Install

Windows users install Npcap once
(<https://npcap.com/>) with the **"WinPcap API-compatible mode"** option
checked. This grants user-level packet capture so the binary runs from an
ordinary (non-elevated) terminal. After that:

```powershell
go install github.com/lab1702/lan-inventory/cmd/lan-inventory@latest
lan-inventory
```

No `setcap` analog is needed; the Npcap installer handles privilege at
install time.

### Privilege model

On Windows, the binary does not need Administrator at runtime:

- **Packet capture** — Npcap's user-mode permissions cover libpcap access.
- **ICMP** — the ping probe switches to `pro-bing`'s unprivileged mode on
  Windows, which calls `IcmpSendEcho` (`iphlpapi.dll`). RTT and TTL are
  still reported.
- **NBNS / TCP / DNS / mDNS** — already use the standard Go `net` stack
  with no platform-specific privilege requirement.

On Linux, the privilege model is unchanged: `setcap cap_net_raw,cap_net_admin`
or `sudo`, exactly as documented today.

## Architecture

The codebase already uses build-tagged files (`route_linux.go` /
`route_other.go`, `arp_seed_linux.go` / `arp_seed_other.go`) to isolate
OS-specific logic. This work adds two `_windows.go` files and tightens the
existing `_other.go` build tags. No new packages, no new abstractions.

```
netiface/
  route_linux.go      (unchanged)
  route_windows.go    NEW   — GetBestRoute2 via x/sys/windows
  route_other.go      MOD   — build tag becomes !linux && !windows

scanner/
  arp_seed_linux.go    (unchanged)
  arp_seed_windows.go  NEW  — GetIpNetTable2 via x/sys/windows
  arp_seed_other.go    MOD  — build tag becomes !linux && !windows
  arp.go               (unchanged — pcap is portable; Npcap supplies the driver)
  precheck.go          (unchanged)

probe/
  ping.go              MOD  — SetPrivileged(runtime.GOOS != "windows")

cmd/lan-inventory/main.go
                       MOD  — platform-specific precheck-failure hint

.github/workflows/ci.yml
                       MOD  — matrix: ubuntu-latest + windows-latest

README.md              MOD  — Linux + Windows install sections
Makefile               MOD  — comment that Windows uses `go build` directly
```

## Components

### `netiface/route_windows.go`

Implements `defaultRouteInterface() (*net.Interface, net.IP, error)` for the
Windows platform using `golang.org/x/sys/windows`:

1. Call `GetBestRoute2` (`iphlpapi.dll`) with destination `0.0.0.0`. This
   returns a `MIB_IPFORWARD_ROW2` for the system's best route to that
   destination — the default route by definition.
2. If `GetBestRoute2` returns no usable row, fall back to `GetIpForwardTable2`
   and pick the entry with destination prefix `0.0.0.0/0` and the lowest
   metric.
3. Convert the row's `InterfaceLuid` to an interface index via
   `ConvertInterfaceLuidToIndex`, then use `net.InterfaceByIndex` to bridge
   back into Go's `net` package.
4. Extract the next-hop IPv4 address from the row. Return `nil` for the
   gateway when it is unspecified (rare; point-to-point links). Callers
   already tolerate a `nil` gateway.
5. Wrap any syscall error so the message names the failing call.

The file is `//go:build windows` and uses no cgo.

### `scanner/arp_seed_windows.go`

Implements `SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update`
mirroring the Linux semantics: best-effort, returns `nil` on any error.

1. Look up the chosen interface's `InterfaceLuid`. Use `net.InterfaceByName`
   to obtain the interface index, then `ConvertInterfaceIndexToLuid`.
2. Call `GetIpNetTable2(AF_INET)` to read the IPv4 neighbor table.
3. For each row, keep only those where:
   - `InterfaceLuid` matches the chosen interface,
   - the IP is inside `subnet`,
   - state is one of `Reachable`, `Stale`, `Delay`, `Probe` (i.e., not
     `Unreachable` / `Incomplete`),
   - MAC is non-zero (`PhysicalAddressLength == 6` and not all-zero).
4. Emit one `Update{Source: "arp-seed", Time: now, IP, MAC, Vendor:
   oui.Lookup(mac)}` per surviving row.

To keep the platform-syscall code thin and the data-shaping logic
testable, the file exposes a pure helper:

```go
type arpRow struct {
    IP    net.IP
    MAC   net.HardwareAddr
    State uint32
    Luid  uint64
}

func rowsToUpdates(rows []arpRow, ifaceLuid uint64, subnet *net.IPNet, now time.Time) []Update
```

`SeedFromKernelARP` is the syscall wrapper; `rowsToUpdates` is unit-tested
with fabricated rows.

The file is `//go:build windows`.

### `scanner/arp_seed_other.go` (modified)

Build tag tightens to `//go:build !linux && !windows`. Body unchanged
(returns `nil`).

### `netiface/route_other.go` (modified)

Build tag tightens to `//go:build !linux && !windows`. Body unchanged.

### `probe/ping.go` (modified)

One-line change inside `Ping`:

```go
pinger.SetPrivileged(runtime.GOOS != "windows")
```

On Windows, `pro-bing` calls `IcmpSendEcho` and still populates `pkt.TTL`,
so `OSGuess` continues to work. On Linux the behavior is unchanged.

### `cmd/lan-inventory/main.go` (modified)

Replace the hardcoded `setcap` hint inside the precheck-failure branch with
a `runtime.GOOS` switch:

- `linux` — existing text, including the `sudo setcap` command.
- `windows` — `Install Npcap from https://npcap.com/ (check "WinPcap
  API-compatible mode"). The driver grants user-level capture; no per-run
  Administrator needed.`
- default — `This platform may need additional privileges to open packet
  capture. See your OS docs for how to grant raw-socket / pcap access.`

The precheck function itself does not change — only the message printed
when it fails.

### `.github/workflows/ci.yml` (modified)

Convert `jobs.test` to a matrix:

```yaml
strategy:
  fail-fast: false
  matrix:
    os: [ubuntu-latest, windows-latest]
runs-on: ${{ matrix.os }}
```

Linux-only step (unchanged):
```yaml
- if: runner.os == 'Linux'
  run: sudo apt-get update && sudo apt-get install -y libpcap-dev
```

Windows-only step (new):
```yaml
- if: runner.os == 'Windows'
  shell: pwsh
  run: |
    $sdk = "$env:RUNNER_TEMP\npcap-sdk"
    Invoke-WebRequest https://npcap.com/dist/npcap-sdk-1.13.zip -OutFile "$env:RUNNER_TEMP\sdk.zip"
    Expand-Archive "$env:RUNNER_TEMP\sdk.zip" -DestinationPath $sdk
    echo "CGO_CFLAGS=-I$sdk\Include" >> $env:GITHUB_ENV
    echo "CGO_LDFLAGS=-L$sdk\Lib\x64" >> $env:GITHUB_ENV
```

`go vet`, `staticcheck`, and `go test ./...` run unmodified on both
platforms. GitHub's `windows-latest` runner ships MinGW (`gcc`) on `PATH`,
so cgo works for `gopacket/pcap`.

The Npcap SDK version is pinned (`1.13`) to keep the build reproducible;
the README documents how to bump it.

### `README.md` (modified)

Drop the `Linux only` Limitations bullet. Add a Windows install section
covering: Npcap install (with the "WinPcap API-compatible mode" checkbox),
`go install` command, and a note that Windows does not need elevated
prompts. Keep the macOS limitation: it is still unsupported.

### `Makefile` (modified)

Add a single comment line near `build`:

```
# Windows users: run `go build ./cmd/lan-inventory` directly; the setcap
# step does not apply.
```

No PowerShell port. Windows is a Go-tooling-only workflow.

## Data flow

Unchanged. Workers emit `Update` records into the merger exactly as
before. The Windows code adds two new emitters of identical-shape records:

- `route_windows.go` populates `netiface.Info` at startup, just like
  `route_linux.go` does on Linux.
- `arp_seed_windows.go` emits `Update{Source: "arp-seed"}` records at
  startup, just like `arp_seed_linux.go` does on Linux.

The merger does not need to know which platform produced the seed — the
records are indistinguishable from Linux seeds.

## Error handling

- **Default route missing.** `route_windows.go` returns the same
  `"no default route — cannot determine which subnet to scan"` error
  string as Linux, which the main.go exit-code-2 path already handles.
- **No Npcap.** Precheck's `pcap.OpenLive` fails; main.go prints the new
  Windows-specific hint and exits with code 2 (config error). The user is
  pointed at <https://npcap.com/> in the error message.
- **GetIpNetTable2 failure.** `SeedFromKernelARP` returns `nil`. Same
  best-effort contract as Linux — the passive ARPWorker fills the gap.
- **Unprivileged ICMP failure.** `pro-bing`'s `IcmpSendEcho` returns an
  error; `Ping` returns it; `ActiveWorker` already tolerates per-host ping
  failures and falls back to TCP and known-IP enrichment.

## Testing

### Unit tests

- `scanner/arp_seed_windows_test.go` (`//go:build windows`) — exercises
  `rowsToUpdates` with fabricated rows covering: wrong-LUID rows filtered,
  out-of-subnet rows filtered, zero-MAC rows filtered,
  Unreachable/Incomplete state filtered, valid rows pass through with
  correct vendor lookup.
- `probe/ping_test.go` — assert `pinger.Privileged()` matches
  `runtime.GOOS != "windows"`.

The existing test suite remains platform-portable; nothing else needs to
change.

### Manual smoke test (Windows)

1. Install Npcap with WinPcap-API-compatible mode.
2. `go build ./cmd/lan-inventory`
3. From a **non-elevated** PowerShell:
   - `.\lan-inventory.exe --version` — prints version.
   - `.\lan-inventory.exe --once --table` — prints device rows with IPs,
     MACs, vendors, hostnames.
   - `.\lan-inventory.exe` — TUI opens; tabs 1–4 work; `/` filter, `↑/↓`,
     `r` rescan, `q` quit all work.
4. Verify the snapshot includes MAC + vendor for Windows hosts that
   stealth-drop ICMP (ARP seed populating from the kernel cache).

### CI gate

`go vet`, `staticcheck`, `go test ./...` must pass on both
`ubuntu-latest` and `windows-latest` before the change merges.

## Risks and mitigations

- **Npcap version drift.** The pinned SDK URL may go stale. Mitigation:
  document the pinned version in README and check for updates as part of
  routine maintenance.
- **cgo on Windows runners.** If GitHub removes MinGW from
  `windows-latest`, the build breaks. Mitigation: low likelihood; if it
  happens, add an explicit `msys2/setup-msys2` step.
- **`IcmpSendEcho` TTL field.** `pro-bing` does populate `pkt.TTL` in
  unprivileged mode on Windows, but the value comes from a different
  source than raw-socket TTL. OS detection rules depend on TTL; if the
  reported value differs from raw-socket TTL by more than 8 hops the
  buckets in `OSGuess` will misclassify. Mitigation: verify in the smoke
  test that TTLs match expected buckets for at least one Windows host
  (initial 128) and one Linux host (initial 64) on the LAN.

## Out of scope

- macOS / *BSD parity.
- IPv6.
- State persistence.
- A PowerShell-native Makefile replacement.
- Auto-installing Npcap from the binary.
