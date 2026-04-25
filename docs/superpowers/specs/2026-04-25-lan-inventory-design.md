# lan-inventory — Design

**Status:** Approved  •  **Date:** 2026-04-25

A user-friendly home-LAN inventory tool. A single Go binary that auto-discovers
devices on the local /24, presents a live TUI dashboard, and can also dump a
one-shot JSON or table snapshot for scripting.

## Goals and non-goals

**Goals**

- Zero-config: run the binary, see your home network.
- Continuous, low-effort visibility into ~10–50 home-LAN devices.
- Rich per-device data: IP, MAC, vendor, hostname, RTT, OS guess, open ports, mDNS services.
- Single static binary — easy to install, easy to remove.
- Both interactive (TUI) and scriptable (`--once`) modes.

**Non-goals**

- Manual entry, annotation, tagging, or notes.
- Persistence across runs. State is in-memory; quit wipes everything.
- Multi-subnet, VLAN, or routing inventory.
- Corporate-scale networks. /22 is the hard upper bound; /24 is the design target.
- Vulnerability scanning, traffic analysis, or alerting.
- Daemon/server mode or remote access.

## Target environment

- Single user, personal home lab.
- One default network interface, one IPv4 /24 (or smaller).
- Linux primary platform; macOS as a secondary target where libpcap is available.
- 10–50 active devices typical; 1024 hosts is the absolute ceiling.

## High-level architecture

A single Go process. The scanner runs continuously in goroutines, emitting events
on a channel. The TUI consumes those events to render. The non-interactive mode
runs the same scanner for one cycle, snapshots the result, and exits.

```
cmd/lan-inventory ─┬─→ internal/tui ────────┐
                   │                         │
                   └─→ internal/snapshot ────┤
                                             ▼
                                      internal/scanner ─→ internal/probe
                                             │            internal/oui
                                             └──────────→ internal/netiface
```

Dependencies are one-way. `tui` and `scanner` interact only through an event
channel and a read-only snapshot accessor — neither imports the other.

## Module layout

| Package | Responsibility |
|---|---|
| `cmd/lan-inventory` | Flag parsing, mode dispatch (TUI vs `--once`), top-level wiring. |
| `internal/netiface` | Auto-detect default interface and its IPv4 subnet. |
| `internal/scanner` | Owns the live device map. Runs ARP listener, mDNS listener, active prober. Emits `DeviceEvent`s. |
| `internal/probe` | Stateless probes: `Ping`, `ScanPorts`, `OSGuess`, `ReverseDNS`. |
| `internal/oui` | Embedded MAC-vendor database (Wireshark `manuf` baked in via `embed`). |
| `internal/model` | Pure data: `Device`, `Port`, `ServiceInst`, `Event`. No I/O. |
| `internal/tui` | Bubble Tea program. Renders the 4-tab dashboard. |
| `internal/snapshot` | Renders the current device map as JSON or text table. |

## Scanner internals

Three concurrent workers feed one merging goroutine:

**Passive ARP listener.** Uses `gopacket` + libpcap on the chosen interface.
Every observed ARP request/reply contributes `(IP, MAC, last_seen=now)`.
Gratuitous ARPs surface new devices instantly. No traffic is generated.

**Passive mDNS listener.** Joins multicast group 224.0.0.251. Listens for
service announcements (`_http._tcp`, `_airplay._tcp`, `_ssh._tcp`,
`_googlecast._tcp`, etc.). Contributes hostname plus a service list keyed by
IP/MAC. Periodically issues `_services._dns-sd._udp` queries to provoke replies.

**Active prober.** Goroutine pool, runs every 30 seconds. For each known IP and
each unseen IP in the subnet:

1. ICMP ping → liveness, RTT, TTL (TTL feeds `OSGuess`).
2. Reverse DNS lookup.
3. Common-port scan: a fixed shortlist of ~12 ports (22, 53, 80, 443, 445, 631,
   1400, 5000, 5353, 8080, 9100), parallel `net.DialTimeout` with 500 ms each.

Subnet sweep: every active cycle ICMP-pings the full /24 in parallel (worker
pool of 32). Catches devices that don't announce via ARP or mDNS — silent IoT,
manually-IP'd hosts.

**Merger.** Single goroutine owns `map[mac]*Device` (keyed by MAC when known,
otherwise IP). Receives updates from all three workers via a channel, mutates
the map, and emits `DeviceEvent{Type: joined|updated|left, Device: ...}` on an
output channel. A "left" event fires when a device hasn't been seen for 5
minutes.

## TUI structure

Bubble Tea + Lipgloss. One model owns app state; render is a pure function of
state; scanner events arrive as Bubble Tea messages.

**Persistent header**

```
lan-inventory  [1] Devices  [2] Services  [3] Subnet  [4] Events
Online: 28   Offline: 3   New (60s): 1   Subnet: 192.168.1.0/24   Avg RTT: 1.8ms
```

**Tab 1 — Devices** (default).
Sortable list: hostname, IP, MAC vendor, OS, ports, RTT, last seen. Selected
row expands a detail strip showing MAC, all open ports with service guesses,
all mDNS services, and a 10-sample RTT history (in-memory only). `/` filter,
`s` cycles sort key, `r` forces a rescan.

**Tab 2 — Services.**
Devices grouped by service type. Browse by what's on the network instead of by
host:

```
_http._tcp        3 instances  →  pi-hole.local, router, printer.local
_ssh._tcp         2 instances  →  pi-hole.local, macbook.local
_airplay._tcp     1 instance   →  living-room
22/tcp (ssh)      4 instances  →  ...
80/tcp (http)     5 instances  →  ...
```

Combines mDNS service announcements and inferred services from open ports.

**Tab 3 — Subnet.**
A grid representing the live subnet. For a /24 it's 16×16; for smaller
subnets the grid auto-shrinks (a /26 is 8×8); for larger subnets up to /22
the grid stacks per-/24 blocks vertically. Each cell colored: green (online),
yellow (recently seen), grey (never seen), red (offline within last hour).
Selecting a cell shows which device occupies it. Reveals DHCP fragmentation,
free addresses, and static-IP clusters at a glance.

**Tab 4 — Events.**
In-session ring buffer (last 200 events). Newest at top:

```
14:21:09  + iphone        192.168.1.31  joined
14:18:42  ~ thermostat    192.168.1.25  unreachable
14:14:17  + esp32-1       192.168.1.22  joined
```

Wiped on quit.

**Global keys.** `1`–`4` switch tabs. `↑/↓` navigate. `Enter` drill in. `Esc`
or `q` quit. `?` help overlay.

## Data model

Pure data types in `internal/model`. No methods that do I/O.

```go
type Device struct {
    MAC          string          // lowercase, colon-separated; "" if unknown
    IPs          []net.IP        // multiple is rare on home LANs
    Hostname     string          // mDNS > rDNS > ""
    Vendor       string          // OUI lookup; "" if unknown
    OSGuess      string          // "Linux" | "macOS" | "Windows" | "iOS/Android" | "RTOS" | ""
    OpenPorts    []Port
    Services     []ServiceInst
    RTT          time.Duration   // last successful ping
    RTTHistory   []time.Duration // capped at 10
    FirstSeen    time.Time
    LastSeen     time.Time
    Status       Status          // Online | Stale | Offline
}

type Port struct {
    Number  int
    Proto   string  // "tcp" | "udp"
    Service string  // best-guess label, e.g., "ssh", "http"
}

type ServiceInst struct {
    Type string  // e.g., "_http._tcp"
    Name string  // e.g., "Pi-hole admin"
    Port int
}

type Status int
const (
    StatusOnline  Status = iota // seen within 60s
    StatusStale                 // 60s–5min
    StatusOffline               // >5min
)

type EventType int
const (
    EventJoined  EventType = iota // first sighting (or returning after Left)
    EventUpdated                  // existing device changed (new port, new service, RTT delta, etc.)
    EventLeft                     // not seen for 5 minutes; transitions Status to Offline
)

// Event is the user-facing record shown in the Events tab and persisted in the
// in-session ring buffer. It is intentionally compact.
type Event struct {
    Time time.Time
    Type EventType
    MAC  string
    IP   net.IP
    Note string     // e.g., "unreachable", "new mDNS service: _airplay._tcp"
}

// DeviceEvent is the internal channel message emitted by the scanner merger
// to subscribers (the TUI, the snapshot writer). It carries the full updated
// Device, unlike the user-facing Event which is a compact log line.
type DeviceEvent struct {
    Type   EventType
    Device *Device
}
```

**Keying.** Devices are keyed by MAC when known. A device first observed via
ICMP only (no ARP yet — a brief window) is keyed by IP and merged into the
MAC-keyed entry once ARP catches up. Hostname change does not create a new
device; same MAC means same device.

**`--once --json` shape.** A single JSON object per invocation:

```json
{
  "scanned_at": "2026-04-25T17:51:33Z",
  "subnet": "192.168.1.0/24",
  "interface": "eth0",
  "devices": [ /* []Device */ ]
}
```

`time.Time` values serialize as RFC3339 strings. The schema is stable for v1;
no version field needed yet.

## Privileges and edge cases

**Privileges.** ARP sniffing and ICMP ping require raw sockets. The tool
**hard-fails** at startup if those sockets cannot be opened, and prints both
remediation paths:

```
lan-inventory: needs raw socket access to sniff ARP and send ICMP.
Either run with sudo, or grant capabilities once:
    sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)
```

No silent degradation: missing ARP means missing half the devices, which is a
worse failure mode than refusing to run.

**Interface selection.** Pick the interface owning the default route. With
multiple default routes, pick the lowest metric. With none, exit with: `no
default route — cannot determine which subnet to scan`.

**Subnet-size guard.** Read the netmask from the chosen interface. If the
resulting subnet is larger than /22 (~1024 hosts), refuse with `subnet /N too
large — this tool targets home-LAN /24 deployments`. Prevents accidental scans
of corporate networks.

**Probe failures.** Each probe is independent and best-effort. ICMP fail →
flag stale, do not remove. DNS fail → blank hostname. Port scan fail → empty
port list. None of these surface to the user as errors; they are simply absent
data.

**Resource limits.** Active prober pool capped at 32 concurrent goroutines.
mDNS listener has a 1 MB read buffer. Event ring buffer capped at 200. Device
map has no hard cap — the /22 guard already bounds the absolute worst case.

**Shutdown.** Ctrl-C cancels the root context. All goroutines drain within
~1 s. Bubble Tea's normal teardown restores terminal state.

## Non-interactive mode

```
lan-inventory                 # default: launch TUI
lan-inventory --once          # one full scan, JSON to stdout, exit
lan-inventory --once --table  # same content, human-readable table
lan-inventory --version
lan-inventory --help
```

**`--once` semantics.** Spins up the same `internal/scanner` for one cycle:
starts ARP and mDNS listeners, waits 8 seconds for passive signals, runs one
full active sweep, snapshots the device map, and exits. Total runtime
~10–15 s for a /24.

**`--table` output.** Same content as the Devices tab, formatted as a plain
table. Truncates long fields to fit terminal width. Color is emitted only when
stdout is a TTY.

**Exit codes.**

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime error (lost interface mid-scan, etc.) |
| 2 | Configuration / environment error (no privilege, no default route, oversized subnet) |
| 3 | No devices found — likely misconfiguration; useful for cron health-checks |

## Testing strategy

**Unit tests** carry most of the weight:

- `internal/oui` — table-driven tests against known MAC ranges.
- `internal/probe` — `OSGuess(ttl)` is pure and table-testable. `ScanPorts`
  and `Ping` test against `127.0.0.1` and a localhost listener fixture.
- `internal/model` — JSON round-trip tests on `Device` to lock the public schema.
- `internal/snapshot` — given a fixture device map, verify JSON and table
  output byte-for-byte.

**Scanner integration tests.** The merger goroutine is where bugs hide:
concurrent updates from three sources, MAC↔IP keying, "left" timing. Tests
inject synthetic ARP, mDNS, and probe events into the input channels via
testable seams (each worker is an interface; real implementations in
production, fakes in tests). Assertions cover the emitted `DeviceEvent` stream
and final map state. No real network involved.

**TUI tests.** Bubble Tea's `teatest` provides golden-output snapshots: feed
key events, render frames into a buffer, assert against checked-in `.golden`
files. Coverage: tab switching, sort cycling, filter mode, quit. Regenerated
with `go test -update`.

**No end-to-end test on a real LAN.** Too flaky and environment-dependent for
CI. Manual validation lives in a `make smoke` target that runs
`--once --table` against the developer's home network.

**CI.** Single GitHub Actions job: `go vet`, `staticcheck`, `go test ./...`.
Lint and test must pass to merge.

## Out of scope (non-goals reaffirmed)

- Manual device annotation
- Persistence between runs
- IPv6 support
- Authentication, multi-user, remote access
- Vulnerability assessment
- Multi-subnet, VLAN, routing topology
