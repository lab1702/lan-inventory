# OS Detection — Design

**Status:** Approved  •  **Date:** 2026-04-26

A focused refinement on top of the v0.1.0 + color + OUI + hostname-enrichment
tree. Today the `OSGuess` field is computed from the ICMP TTL alone, which
mislabels devices whenever the TTL is ambiguous or routed through an
intermediate that mangles it (most visibly: an Apple AirPlay host showing as
"Windows" because its TTL came back near 128). This change replaces the
TTL-only heuristic with a multi-signal priority chain that combines OUI
vendor, mDNS service types, mDNS TXT records, NBNS response, open ports,
and TTL — the strongest available signal wins.

## Goals and non-goals

**Goals**

- Five canonical labels — `Windows`, `macOS`, `iOS`, `Linux`, `Network` — covering the dominant home-LAN device classes.
- Strongest-available-signal wins. TTL is fallback only.
- Clear priority chain that is testable rule-by-rule.
- Add `model.ServiceInst.TXT` to capture the rich data mDNS announces but we discard today.
- Add `model.Device.NBNSResponded` so the OS function can use the NBNS signal.

**Non-goals**

- Not adding active TCP/IP fingerprinting (nmap-style). Too invasive.
- Not splitting Android from generic Linux. Reliable distinction needs active probing.
- Not distinguishing tvOS / watchOS from macOS (both broadcast `_airplay._tcp`; would need TXT model hints).
- Not exposing the raw signals to the user. The `OSGuess` field stays a single string label.
- Not changing the OS column visually beyond the label set.

## Label set

Five labels emit from `OSDetect`:

- `Windows`
- `macOS`
- `iOS`
- `Linux`
- `Network` — routers, switches, access points, printers, IoT appliances (Sonos, Echo, Wyze, etc.). Treated as appliances rather than computers.

Plus `""` (empty) when no signal applies — TUI renders that as dim `—`.

Android is folded into `Linux`. tvOS/watchOS/iPadOS appear as `iOS` if their
TXT model says so, otherwise as `macOS` (default for Apple OUI without
device-class hints).

## Signals available

| Signal | Source | Strength |
|---|---|---|
| **MAC vendor** (Apple, RaspberryPi, TP-Link, …) | OUI lookup, set by ARP worker | High when matched |
| **mDNS service types** (`_airplay._tcp`, `_apple-mobdev2._tcp`, `_smb._tcp`, …) | mDNS worker | High |
| **mDNS TXT model** (`model=MacBookPro18,2`, `model=iPhone14,5`) | mDNS worker, NEW | Highest |
| **NBNS responded** (active worker got a Workstation name) | active worker | High Windows signal |
| **Open ports** (22, 137, 445, 9100, 1400, 5353) | probe.ScanPorts | Moderate |
| **TTL** (32, 64, 128, 255 ± hops) | active worker | Weakest, fallback only |

## Vendor families

Vendor short-names from the Wireshark manuf table get classified into
families. The families feed the priority chain — they are not user-facing
labels.

| Family | Matches (case-insensitive `Contains`) |
|---|---|
| `Apple` | `Apple` |
| `Network` | `TP-Link`, `Netgear`, `Ubiquiti`, `Cisco`, `Aruba`, `Juniper`, `Mikrotik`, `D-Link`, `Asus`, `Linksys`, `eero`, `Sercomm`, `Arris` |
| `LinuxBoard` | `RaspberryPi`, `Synology`, `QNAP`, `Western Digital`, `Buffalo` |
| `Printer` | `HP`, `Hewlett`, `Canon`, `Brother`, `Epson`, `Xerox`, `Lexmark` |
| `IoT` | `Espressif`, `Tuya`, `Shelly`, `WyzeLabs`, `Sonos`, `Nest`, `Amazon`, `Google` |

`""` family — vendor unknown, doesn't match any list.

The implementation of each predicate (`isApple`, `isRouter`, etc.) is a
single `strings.Contains(strings.ToLower(vendor), ...)` over a small
allow-list per family.

## Priority chain

Function signature:

```go
func OSDetect(d *model.Device, nbnsResponded bool) string
```

Rules fire top-down; first match wins. The design intent: explicit signals
override inferred ones, and conflicts surface predictably.

```
fam := vendorFamily(d.Vendor)

Rule 1.   TXT model starts with "iPhone", "iPad", "iPod", "Watch"        → iOS
Rule 2.   any service.Type == "_apple-mobdev2._tcp"                      → iOS
Rule 3.   TXT model starts with "Mac"                                    → macOS
Rule 4.   fam == "Apple" && (any of: _airplay, _smb, _ssh, _device-info) → macOS
Rule 5.   NBNSResponded && fam != "LinuxBoard" && (TTL=Windows || fam=="") → Windows
Rule 6.   fam == "Apple"                                                 → macOS  (Apple-OUI fallback)
Rule 7.   TTL guess == "Windows" && (open 445/tcp || open 137)           → Windows
Rule 8.   fam == "Network"                                               → Network
Rule 9.   fam == "IoT"                                                   → Network
Rule 10.  fam == "Printer"                                               → Network
Rule 11.  fam == "LinuxBoard"                                            → Linux
Rule 12.  open 22/tcp && TTL guess == "Linux/macOS"                      → Linux
Rule 13.  any service.Type == "_workstation._tcp" && fam != "Apple"      → Linux
Rule 14.  TTL guess == "RTOS/Network"                                    → Network
Rule 15.  TTL guess == "Linux/macOS"                                     → Linux  (TTL fallback)
Rule 16.  TTL guess == "Windows"                                         → Windows  (TTL fallback)

No match                                                                  → ""
```

**Rule design notes:**

- **Rules 1, 3** are highest because TXT `model=` is the strongest signal — an explicit declaration of device class.
- **Rule 5 (NBNS)** is intentionally above Rule 6 (Apple fallback). This handles Mac running Boot Camp with Windows answering NBNS.
- **Rule 5 has a guard** so a Synology/Raspberry Pi running Samba doesn't get mislabeled as Windows.
- **Rule 6** is the Apple-OUI fallback for sleeping/silent Apple devices (ARP saw them but no other signal arrived). Default to macOS rather than Apple-generic; if the user has many iPhones we can revisit.
- **Rules 14–16** are TTL-only fallbacks. Low confidence; we still emit a label when TTL gives one.

## Where computation happens

OS guessing moves **out of the active worker** and **into the merger**.

**Why:** the active worker has TTL and (after this change) NBNSResponded, but
not vendor (set by ARP) or services (set by mDNS). The merger has all
signals because all three workers' Updates land in the same map. Computing
`OSGuess` in the merger after each `mergeUpdate` ensures every relevant
signal contributes to the label.

**Active worker → emits raw signals:**
- `Update.TTL int` (replaces the indirect `OSGuess` field)
- `Update.NBNSResponded bool`

The active worker also still calls `probe.NBNS` directly (separately from
`probe.ResolveHostname`'s internal call) so it can surface the boolean
explicitly. Mild duplication, but exposing the signal cleanly is worth it.

**Merger → derives `OSGuess`:**
After applying an Update onto a `*model.Device`, the merger calls
`probe.OSDetect(dev, dev.NBNSResponded)` and writes the result to
`dev.OSGuess`.

**TTL plumbing:** `model.Device` gains a `TTL int` field (set from
`Update.TTL`). `OSDetect` calls `probe.OSGuess(dev.TTL)` internally to
derive the TTL-based fallback label.

## Edge cases

**Apple device sleeping when active probes run.** ARP saw it (vendor=Apple),
mDNS hasn't seen anything this session, ping fails. Rule 6 fires → `macOS`.
Acceptable.

**Mac with Boot Camp / Parallels Windows answering NBNS.** Rule 5 (NBNS
guarded) fires before Rule 6 (Apple fallback) → `Windows`. Correct.

**Linux box running Samba with NBNS answering.** Rule 5's `fam !=
"LinuxBoard"` guard excludes Synology/QNAP/Pi explicitly. For a generic
Linux server (`fam == ""`) the NBNS guard requires `TTL=Windows ||
fam==""` — both are true so it would fire and label as `Windows`. That's a
mislabel for a Samba-running Linux server. Mitigation: such servers
typically also have SSH open + TTL=64; Rule 12 would have fired earlier
in priority IF it were higher than Rule 5. Decision: accept this mislabel
in v1 — Linux servers running Samba are uncommon on home LANs. Future:
Rule 5 could additionally check "and not (open 22 && TTL=64)".

**Apple TV / HomePod (tvOS).** Vendor=Apple + AirPlay broadcasting → Rule
4 → `macOS`. Technically tvOS, but the user's main concern is identifying
Apple-ness. Splitting tvOS later via TXT model (`AppleTV6,2`, etc.) is a
straightforward Rule 3-class addition.

**Conflicting signals.** Rule order is the resolution mechanism. Tests
cover the explicit scenarios; the merger recomputes after each Update so
the label converges as more signals arrive.

## Code structure

### New / modified types

**`internal/model/types.go`:**

```go
type ServiceInst struct {
    Type string            `json:"type"`
    Name string            `json:"name"`
    Port int               `json:"port"`
    TXT  map[string]string `json:"txt,omitempty"` // NEW: parsed mDNS TXT records
}

type Device struct {
    // ... existing fields ...
    TTL            int  `json:"ttl,omitempty"`            // NEW: last-observed TTL from active probe
    NBNSResponded  bool `json:"nbns_responded,omitempty"` // NEW: active worker got a NBNS reply
}
```

JSON tags use `omitempty` so existing snapshots remain forward-compatible
(absence on read = zero value).

### `internal/probe/osguess.go`

Keep the existing `OSGuess(ttl int) string` — it's the TTL-only primitive
used inside `OSDetect`.

Add:

```go
// OSDetect runs the multi-signal priority chain over a device's
// accumulated signals and returns one of "Windows", "macOS", "iOS",
// "Linux", "Network", or "" if no rule applies.
func OSDetect(d *model.Device, nbnsResponded bool) string

// vendorFamily classifies a vendor short-name into a coarse family
// ("Apple", "Network", "LinuxBoard", "Printer", "IoT") or "" for unknown.
func vendorFamily(vendor string) string

// internal predicates: isApple, isRouter, isLinuxBoard, isPrinter, isIoT
```

The TXT-model startswith checks use a small helper `txtModelStartsWith(d, prefixes...)`.

### `internal/scanner/interfaces.go`

`Update` gains:

```go
type Update struct {
    // ... existing ...
    TTL           int  // active prober only; 0 if not measured
    NBNSResponded bool // active prober only
}
```

The existing `Update.OSGuess string` is **removed** — OS guessing happens
in the merger now.

### `internal/scanner/active.go`

`probeOne` calls `probe.NBNS(ctx, ip.String())` separately from the chain
(since the Hostname chain inside `ResolveHostname` doesn't surface the
boolean). Update construction:

```go
nbns := probe.NBNS(ctx, ip.String())
update := Update{
    Source:        "active",
    Time:          time.Now(),
    IP:            ip,
    Alive:         true,
    RTT:           pingRes.RTT,
    TTL:           pingRes.TTL,
    Hostname:      probe.ResolveHostname(ctx, ip.String(), w.Gateway),
    OpenPorts:     probe.ScanPorts(ctx, ip.String(), probe.DefaultPorts(), 500*time.Millisecond),
    NBNSResponded: nbns != "",
}
```

The `Hostname` chain still calls NBNS internally — that's fine; the second
call from `probeOne` takes another ~500ms but that's parallel with the
port scan via the worker pool's natural concurrency.

Note: this *does* duplicate the NBNS call. We could pass the boolean back
out of `ResolveHostname` to avoid duplication — but that complicates the
chain's clean signature. Accepted for simplicity.

### `internal/scanner/merger.go`

`mergeUpdate` gains two new merge actions:

```go
if u.TTL > 0 {
    dev.TTL = u.TTL
}
if u.NBNSResponded {
    dev.NBNSResponded = true
}
```

After all merges, before emitting the event:

```go
dev.OSGuess = probe.OSDetect(dev, dev.NBNSResponded)
```

(The `nbnsResponded` parameter is redundant given it's also on `dev`, but
the function signature is more explicit and easier to test that way. Or
read directly from the device — see implementation choice in the plan.)

### `internal/scanner/mdns.go`

When constructing `ServiceInst`, populate `TXT`:

```go
txt := map[string]string{}
for _, kv := range e.Text {
    if i := strings.IndexByte(kv, '='); i > 0 {
        txt[strings.ToLower(kv[:i])] = kv[i+1:]
    }
}
update.Services = []model.ServiceInst{
    {Type: svc, Name: e.Instance, Port: e.Port, TXT: txt},
}
```

The lowercased key normalization is intentional — TXT keys are
case-insensitive in mDNS (RFC 6763 §6.4) but devices are inconsistent.
Storing values verbatim, keys lowercased.

## Testing strategy

**Pure-function table tests for `OSDetect`** — the bulk. ~20 rows, one per
rule plus combined-signal scenarios:

```go
cases := []struct {
    name           string
    vendor         string
    services       []model.ServiceInst
    openPorts      []model.Port
    nbnsResponded  bool
    ttl            int
    want           string
}{
    {"Apple TXT model iPhone → iOS", "Apple", svcs("model=iPhone14,5"), nil, false, 64, "iOS"},
    {"Apple + _apple-mobdev2 → iOS", "Apple", svcs("_apple-mobdev2._tcp"), nil, false, 64, "iOS"},
    {"Apple TXT model Mac → macOS", "Apple", svcs("model=MacBookPro18,2"), nil, false, 64, "macOS"},
    {"Apple + _airplay → macOS", "Apple", svcs("_airplay._tcp"), nil, false, 64, "macOS"},
    {"Apple alone, no mDNS → macOS", "Apple", nil, nil, false, 64, "macOS"},
    {"NBNS responded, no vendor → Windows", "", nil, nil, true, 128, "Windows"},
    {"NBNS responded but Synology → Linux", "Synology", nil, nil, true, 64, "Linux"},
    {"Apple OUI + Boot Camp NBNS → Windows", "Apple", nil, nil, true, 128, "Windows"},
    {"TP-Link router → Network", "TP-Link", nil, nil, false, 255, "Network"},
    {"Espressif IoT → Network", "Espressif", nil, nil, false, 64, "Network"},
    {"HP printer → Network", "HP", nil, []model.Port{{Number: 9100, Proto: "tcp"}}, false, 64, "Network"},
    {"RaspberryPi + SSH → Linux", "RaspberryPi", nil, []model.Port{{Number: 22, Proto: "tcp"}}, false, 64, "Linux"},
    {"Linux _workstation → Linux", "", svcs("_workstation._tcp"), nil, false, 64, "Linux"},
    {"TTL 128 + 445 → Windows", "", nil, []model.Port{{Number: 445, Proto: "tcp"}}, false, 128, "Windows"},
    {"TTL 64 fallback → Linux", "", nil, nil, false, 64, "Linux"},
    {"TTL 255 fallback → Network", "", nil, nil, false, 255, "Network"},
    {"No signals → empty", "", nil, nil, false, 0, ""},
    {"TXT model AppleWatch → iOS", "Apple", svcs("model=Watch6,1"), nil, false, 64, "iOS"},
    {"_companion-link without TXT → macOS (rule 4)", "Apple", svcs("_companion-link._tcp"), nil, false, 64, "macOS"},
    {"non-Apple _airplay (rare) → empty if no other signal", "Roku", svcs("_airplay._tcp"), nil, false, 64, ""},
}
```

`svcs` is a small test helper that takes either a service-type string
(e.g., `"_airplay._tcp"`) or a TXT entry (`"model=iPhone14,5"`) and
constructs `[]model.ServiceInst`.

**Pure-function test for `vendorFamily`** — table-driven, ~10 rows
covering each family plus an unknown-vendor row.

**Existing `TestOSGuess` for the TTL primitive stays unchanged.** It now
documents the TTL-only behavior used internally by `OSDetect`.

**One merger integration test** — feed updates that should yield specific
`OSGuess` on the snapshot:

```go
func TestMergerComputesOSDetect(t *testing.T) {
    // ARP brings vendor=Apple
    // mDNS brings _airplay._tcp + TXT model=MacBookPro18,2
    // Active brings TTL=128 (would normally be Windows by TTL alone)
    // Expected: OSGuess == "macOS" (rule 3: TXT model overrides TTL)
}
```

This validates the wiring: merger correctly recomputes `OSGuess` after
each merge with the right inputs.

**No tests for the mDNS TXT parsing change** beyond what comes through the
integration test fixtures. We trust zeroconf to deliver `e.Text` correctly.

## Implementation phases

1. Add `model.ServiceInst.TXT`, `model.Device.TTL`, `model.Device.NBNSResponded`.
2. Update mDNS worker to populate TXT.
3. Update active worker: emit `Update.TTL` and `Update.NBNSResponded`; remove `Update.OSGuess`.
4. Implement `vendorFamily` + `OSDetect` in `osguess.go` with table tests.
5. Wire merger to call `OSDetect` after each `mergeUpdate`; add merger integration test.
6. Final lint and verify.

Single feature branch, ~6 commits.

## Risks and mitigations

- **Vendor short-name spellings differ from spec.** `internal/oui/manuf.txt`
  uses Wireshark short names which can be inconsistent ("Hewlett" vs "HP",
  "Apple" vs "Apple, Inc."). Mitigation: each `is*` predicate uses
  `strings.Contains(strings.ToLower(...), ...)` so partial-match works
  across spelling variants.

- **Linux server running Samba mislabeled as Windows.** Documented in Edge
  Cases; v1 acceptable; future refinement possible by checking SSH+TTL=64
  before Rule 5.

- **Future label additions break existing tests.** Mitigation: each test
  case targets a specific rule; adding a new rule slots into the existing
  ordering.

- **mDNS worker TXT parsing finds non-`key=value` strings.** Mitigation:
  the parser uses `strings.IndexByte('=')` and skips entries without an
  `=` sign. Empty TXT map on parse failure.

## Out of scope

- Active TCP/IP fingerprinting.
- Splitting iOS / iPadOS / tvOS / watchOS at the label level.
- Distinguishing Android from generic Linux.
- A configurable rule chain or user-defined family lists.
- Surfacing TXT-record details in the TUI beyond the OSGuess label (the data is captured but only the label is shown).
