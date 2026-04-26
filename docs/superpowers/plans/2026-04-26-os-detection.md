# OS Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the TTL-only `OSGuess` heuristic with a multi-signal priority chain (`OSDetect`) that combines OUI vendor, mDNS service types, mDNS TXT records, NBNS response, open ports, and TTL — strongest available signal wins. Five labels: `Windows`, `macOS`, `iOS`, `Linux`, `Network` (plus empty when no signal applies).

**Architecture:** OS guessing moves out of the active worker and into the merger, since only the merger has all the signals (vendor from ARP, services from mDNS, TTL/NBNS from active probe). The mDNS worker captures TXT records into a new `ServiceInst.TXT map[string]string`. The active worker emits raw signals (`Update.TTL`, `Update.NBNSResponded`) instead of computing `OSGuess` directly. After every `mergeUpdate`, the merger calls `probe.OSDetect(dev, dev.NBNSResponded)` to derive the label.

**Tech Stack:** Go 1.24 stdlib; existing `github.com/grandcat/zeroconf` for mDNS TXT (`e.Text`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-04-26-os-detection-design.md`

---

## File structure

```
internal/model/
└── types.go                  (MOD) — Device.TTL, Device.NBNSResponded, ServiceInst.TXT

internal/probe/
├── osguess.go                (MOD) — keep OSGuess(ttl); add vendorFamily + OSDetect
└── osguess_test.go           (MOD) — keep TTL tests; add vendorFamily + OSDetect tables

internal/scanner/
├── interfaces.go             (MOD) — Update.TTL, Update.NBNSResponded; remove Update.OSGuess
├── mdns.go                   (MOD) — populate ServiceInst.TXT from e.Text
├── active.go                 (MOD) — emit TTL + NBNSResponded; stop computing OSGuess
├── merger.go                 (MOD) — merge new fields; call OSDetect after each update
└── merger_test.go            (MOD) — one new integration test
```

**Note on operator workflow:** This plan modifies committed code on master. Implementer should follow `superpowers:using-git-worktrees` to create a `feat/os-detection` worktree before starting.

---

## Task 1: Add model fields

**Files:**
- Modify: `internal/model/types.go`

Three additions: `Device.TTL int`, `Device.NBNSResponded bool`, `ServiceInst.TXT map[string]string`. All have `omitempty` JSON tags so existing snapshots are forward-compatible.

- [ ] **Step 1.1: Update `ServiceInst` and `Device` in `internal/model/types.go`**

Find this struct (existing):

```go
type ServiceInst struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Port int    `json:"port"`
}
```

Replace with:

```go
type ServiceInst struct {
	Type string            `json:"type"`
	Name string            `json:"name"`
	Port int               `json:"port"`
	TXT  map[string]string `json:"txt,omitempty"`
}
```

Find this struct (existing):

```go
type Device struct {
	MAC        string          `json:"mac"`
	IPs        []net.IP        `json:"ips"`
	Hostname   string          `json:"hostname"`
	Vendor     string          `json:"vendor"`
	OSGuess    string          `json:"os_guess"`
	OpenPorts  []Port          `json:"open_ports"`
	Services   []ServiceInst   `json:"services"`
	RTT        time.Duration   `json:"rtt_ns"`
	RTTHistory []time.Duration `json:"rtt_history_ns"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	Status     Status          `json:"status"`
}
```

Replace with:

```go
type Device struct {
	MAC           string          `json:"mac"`
	IPs           []net.IP        `json:"ips"`
	Hostname      string          `json:"hostname"`
	Vendor        string          `json:"vendor"`
	OSGuess       string          `json:"os_guess"`
	OpenPorts     []Port          `json:"open_ports"`
	Services      []ServiceInst   `json:"services"`
	RTT           time.Duration   `json:"rtt_ns"`
	RTTHistory    []time.Duration `json:"rtt_history_ns"`
	FirstSeen     time.Time       `json:"first_seen"`
	LastSeen      time.Time       `json:"last_seen"`
	Status        Status          `json:"status"`
	TTL           int             `json:"ttl,omitempty"`
	NBNSResponded bool            `json:"nbns_responded,omitempty"`
}
```

- [ ] **Step 1.2: Verify build and existing tests**

```bash
go build ./...
go test ./internal/model/ -v
go vet ./...
```

`TestDeviceJSONRoundTrip`, `TestStatusJSONString`, `TestEventTypeJSONRoundTrip` must still pass. Existing test fixtures don't populate the new fields, but the round-trip works because all three new fields are `omitempty`.

- [ ] **Step 1.3: Commit**

```bash
git add internal/model/types.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "model: TTL, NBNSResponded on Device; TXT map on ServiceInst"
```

---

## Task 2: Populate `ServiceInst.TXT` in the mDNS worker

**Files:**
- Modify: `internal/scanner/mdns.go`

The mDNS worker today builds `model.ServiceInst{Type, Name, Port}` from each zeroconf entry and discards `e.Text`. After this task, the TXT records are parsed into `map[string]string` (lowercased keys; values verbatim).

- [ ] **Step 2.1: Update `consume` in `internal/scanner/mdns.go`**

Find the `consume` function. Find the block that constructs the Update:

```go
			update := Update{
				Source:   "mdns",
				Time:     time.Now(),
				Hostname: trimDot(e.HostName),
				Services: []model.ServiceInst{
					{Type: svc, Name: e.Instance, Port: e.Port},
				},
			}
```

Replace with:

```go
			txt := map[string]string{}
			for _, kv := range e.Text {
				if i := strings.IndexByte(kv, '='); i > 0 {
					txt[strings.ToLower(kv[:i])] = kv[i+1:]
				}
			}
			update := Update{
				Source:   "mdns",
				Time:     time.Now(),
				Hostname: trimDot(e.HostName),
				Services: []model.ServiceInst{
					{Type: svc, Name: e.Instance, Port: e.Port, TXT: txt},
				},
			}
```

The lowercased key normalization is intentional — RFC 6763 §6.4 says TXT keys are case-insensitive but devices are inconsistent. Storing keys lowercased means downstream rules (`txt["model"]`) work regardless of how the device spelled it.

- [ ] **Step 2.2: Verify build**

```bash
go build ./...
go test ./...
go vet ./...
```

All packages still pass. The merger's existing `containsService` comparison ignores TXT (compares Type/Name/Port only), so dedup behavior is unchanged.

- [ ] **Step 2.3: Commit**

```bash
git add internal/scanner/mdns.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "scanner/mdns: capture TXT records into ServiceInst.TXT"
```

---

## Task 3: Active worker emits raw signals; merger merges them

**Files:**
- Modify: `internal/scanner/interfaces.go`
- Modify: `internal/scanner/active.go`
- Modify: `internal/scanner/merger.go`

The active worker stops computing `OSGuess` and instead emits `TTL` and `NBNSResponded` as raw signals. The `Update.OSGuess` field is **kept for now** — Task 6 removes it once `OSDetect` is in place. Keeping it means no behavior regression mid-plan: existing rows still show TTL-derived `OSGuess` until Task 6 swaps the source.

- [ ] **Step 3.1: Add `TTL` and `NBNSResponded` to `Update` in `internal/scanner/interfaces.go`**

Find the `Update` struct (lines 12-25 currently). Add two new fields:

```go
type Update struct {
	Source     string             // "arp" | "mdns" | "active"
	Time       time.Time          // when the observation happened
	MAC        string             // lowercase, colon-separated; "" if unknown
	IP         net.IP             // required for nearly every update
	Hostname   string             // mDNS or rDNS
	Vendor     string             // OUI lookup may have already been applied
	OSGuess    string             // active prober only
	OpenPorts  []model.Port       // active prober only; empty replaces existing
	Services   []model.ServiceInst // mDNS only; appended/deduped
	RTT        time.Duration      // active prober only
	Alive      bool               // active prober: is the device responding?
	TTL           int  // active prober only; raw TTL for OSDetect
	NBNSResponded bool // active prober only; true when probe.NBNS returned a name
}
```

(Keep all existing fields including `OSGuess` — it gets removed in Task 6.)

- [ ] **Step 3.2: Update `probeOne` in `internal/scanner/active.go`**

Find the existing `probeOne` function. Replace its body with:

```go
func (w *ActiveWorker) probeOne(ctx context.Context, ip net.IP, out chan<- Update) {
	if ctx.Err() != nil {
		return
	}
	pingRes, err := probe.Ping(ctx, ip.String())
	if err != nil || !pingRes.Alive {
		return
	}
	nbnsName := probe.NBNS(ctx, ip.String())
	update := Update{
		Source:        "active",
		Time:          time.Now(),
		IP:            ip,
		Alive:         true,
		RTT:           pingRes.RTT,
		TTL:           pingRes.TTL,
		OSGuess:       probe.OSGuess(pingRes.TTL),
		Hostname:      probe.ResolveHostname(ctx, ip.String(), w.Gateway),
		OpenPorts:     probe.ScanPorts(ctx, ip.String(), probe.DefaultPorts(), 500*time.Millisecond),
		NBNSResponded: nbnsName != "",
	}
	select {
	case out <- update:
	case <-ctx.Done():
	}
}
```

Two changes from current:
1. Calls `probe.NBNS(ctx, ip.String())` directly (separately from the chain inside `ResolveHostname`) and uses the boolean.
2. Sets `update.TTL` and `update.NBNSResponded` alongside the existing fields.

The duplicate `probe.NBNS` call (also called inside `ResolveHostname`) is intentional and documented in the spec — exposes the boolean cleanly. Adds ~500 ms in the worst case (timeout) per host but the active worker uses a 32-goroutine pool so concurrent host probing absorbs it.

- [ ] **Step 3.3: Update `mergeUpdate` in `internal/scanner/merger.go`**

Find the `mergeUpdate` function. Find this block (the field-by-field merge near the end of the function, before the `sort.Slice` call):

```go
	if u.Time.After(dev.LastSeen) {
		dev.LastSeen = u.Time
	}
	if dev.FirstSeen.IsZero() {
		dev.FirstSeen = u.Time
	}
```

Insert these two merge actions immediately before that block:

```go
	if u.TTL > 0 {
		dev.TTL = u.TTL
	}
	if u.NBNSResponded {
		dev.NBNSResponded = true
	}
```

(`NBNSResponded` is sticky once true — a device that ever answered NBNS is still NBNS-capable, so we don't reset it on a later update that didn't probe NBNS. The merger sweep handles staleness; if the device goes Offline, the boolean still reflects what it was last known for.)

- [ ] **Step 3.4: Verify**

```bash
go build ./...
go test ./...
go test -race ./...
go vet ./...
```

All packages must pass. Existing merger tests still pass because none of them assert on `OSGuess`, `TTL`, or `NBNSResponded`. The active worker still emits a TTL-derived `OSGuess`, so the field still populates as before.

- [ ] **Step 3.5: Commit**

```bash
git add internal/scanner/interfaces.go internal/scanner/active.go internal/scanner/merger.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "scanner: emit TTL and NBNSResponded as raw signals; merge them"
```

---

## Task 4: `vendorFamily` helper and predicates

**Files:**
- Modify: `internal/probe/osguess.go`
- Modify: `internal/probe/osguess_test.go`

Pure function that classifies a vendor short-name into a coarse family. Used by `OSDetect` (Task 5).

- [ ] **Step 4.1: Append `vendorFamily` and predicates to `internal/probe/osguess.go`**

After the existing `OSGuess` function, append:

```go
// vendorFamily classifies a Wireshark manuf vendor short-name into a coarse
// device-class family used by OSDetect. Returns "" if no family matches.
//
// Each predicate uses case-insensitive substring matching to tolerate
// vendor short-name spelling variations (e.g., "Hewlett" vs "HP").
func vendorFamily(vendor string) string {
	v := strings.ToLower(vendor)
	switch {
	case isApple(v):
		return "Apple"
	case isRouter(v):
		return "Network"
	case isLinuxBoard(v):
		return "LinuxBoard"
	case isPrinter(v):
		return "Printer"
	case isIoT(v):
		return "IoT"
	}
	return ""
}

func isApple(v string) bool {
	return strings.Contains(v, "apple")
}

func isRouter(v string) bool {
	for _, needle := range []string{
		"tp-link", "tplink", "netgear", "ubiquiti", "cisco", "aruba",
		"juniper", "mikrotik", "d-link", "dlink", "asus", "linksys",
		"eero", "sercomm", "arris",
	} {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func isLinuxBoard(v string) bool {
	for _, needle := range []string{
		"raspberrypi", "raspberry", "synology", "qnap",
		"western digital", "buffalo",
	} {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func isPrinter(v string) bool {
	for _, needle := range []string{
		"hp", "hewlett", "canon", "brother", "epson", "xerox", "lexmark",
	} {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func isIoT(v string) bool {
	for _, needle := range []string{
		"espressif", "tuya", "shelly", "wyzelabs", "wyze", "sonos",
		"nest", "amazon", "google",
	} {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}
```

Add `"strings"` to the import block at the top of `osguess.go` if it's not already there. (Current `osguess.go` is pure-stdlib-free; this adds the first stdlib import.)

The current `osguess.go`:

```go
package probe
```

Becomes:

```go
package probe

import "strings"
```

- [ ] **Step 4.2: Switch `osguess_test.go` to white-box package**

The new `vendorFamily` and `is*` helpers are unexported. The current test file is `package probe_test`. Switch it to `package probe` so the new tests can call them directly. Find the top of `internal/probe/osguess_test.go`:

```go
package probe_test

import (
	"testing"

	"github.com/lab1702/lan-inventory/internal/probe"
)
```

Replace with:

```go
package probe

import (
	"testing"
)
```

Then in the existing `TestOSGuess` function body, replace `probe.OSGuess(c.ttl)` with `OSGuess(c.ttl)` (drop the `probe.` prefix).

- [ ] **Step 4.3: Append `vendorFamily` table test to `internal/probe/osguess_test.go`**

Append at the end of the existing test file:

```go
func TestVendorFamily(t *testing.T) {
	cases := []struct {
		vendor string
		want   string
	}{
		{"Apple, Inc.", "Apple"},
		{"Apple", "Apple"},
		{"Raspberry Pi Foundation", "LinuxBoard"},
		{"RaspberryPiF", "LinuxBoard"},
		{"Synology Incorporated", "LinuxBoard"},
		{"TP-LINK TECHNOLOGIES CO.,LTD.", "Network"},
		{"Netgear", "Network"},
		{"Ubiquiti Networks Inc.", "Network"},
		{"Cisco Systems, Inc", "Network"},
		{"Hewlett Packard", "Printer"},
		{"HP", "Printer"},
		{"Canon Inc.", "Printer"},
		{"Espressif Inc.", "IoT"},
		{"Sonos, Inc.", "IoT"},
		{"WyzeLabs", "IoT"},
		{"", ""},
		{"SomeUnknownVendor", ""},
	}
	for _, c := range cases {
		if got := vendorFamily(c.vendor); got != c.want {
			t.Errorf("vendorFamily(%q) = %q, want %q", c.vendor, got, c.want)
		}
	}
}
```

- [ ] **Step 4.4: Verify**

```bash
go test ./internal/probe/ -v -run "TestVendorFamily|TestOSGuess"
go vet ./...
```

Both `TestOSGuess` (existing, now white-box) and `TestVendorFamily` (new) must pass.

- [ ] **Step 4.5: Commit**

```bash
git add internal/probe/osguess.go internal/probe/osguess_test.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "probe: vendorFamily helper for vendor classification"
```

---

## Task 5: `OSDetect` priority chain

**Files:**
- Modify: `internal/probe/osguess.go`
- Modify: `internal/probe/osguess_test.go`

The multi-signal priority chain that produces the final OS label.

- [ ] **Step 5.1: Append `OSDetect` to `internal/probe/osguess.go`**

Add the import for the model package at the top of `osguess.go`. The current import block is just `import "strings"`. Replace with:

```go
import (
	"strings"

	"github.com/lab1702/lan-inventory/internal/model"
)
```

Then append at the end of the file (after the family predicates from Task 4):

```go
// OSDetect runs the multi-signal priority chain over a device's accumulated
// signals and returns one of "Windows", "macOS", "iOS", "Linux", "Network",
// or "" if no rule applies.
//
// Rule order is the resolution mechanism for conflicting signals; see the
// design doc at docs/superpowers/specs/2026-04-26-os-detection-design.md.
func OSDetect(d *model.Device, nbnsResponded bool) string {
	fam := vendorFamily(d.Vendor)
	ttlGuess := OSGuess(d.TTL)

	// Rule 1: TXT model identifies an Apple mobile/wearable device.
	if hasTXTModelPrefix(d.Services, "iphone", "ipad", "ipod", "watch") {
		return "iOS"
	}
	// Rule 2: explicit iTunes pairing service (iOS only).
	if hasService(d.Services, "_apple-mobdev2._tcp") {
		return "iOS"
	}
	// Rule 3: TXT model says Mac.
	if hasTXTModelPrefix(d.Services, "mac") {
		return "macOS"
	}
	// Rule 4: Apple OUI plus a Mac-typical mDNS service.
	if fam == "Apple" && hasService(d.Services,
		"_airplay._tcp", "_smb._tcp", "_ssh._tcp", "_device-info._tcp") {
		return "macOS"
	}
	// Rule 5: NBNS responded — strong Windows signal, but guard against
	// LinuxBoard appliances running Samba (Synology, QNAP, Pi).
	if nbnsResponded && fam != "LinuxBoard" && (ttlGuess == "Windows" || fam == "") {
		return "Windows"
	}
	// Rule 6: Apple OUI fallback when no other Apple signal is present.
	if fam == "Apple" {
		return "macOS"
	}
	// Rule 7: TTL-suggested Windows reinforced by SMB or NetBIOS port.
	if ttlGuess == "Windows" && (hasOpenPort(d.OpenPorts, 445) || hasOpenPort(d.OpenPorts, 137)) {
		return "Windows"
	}
	// Rule 8-10: Network-class vendors and appliances.
	if fam == "Network" || fam == "IoT" || fam == "Printer" {
		return "Network"
	}
	// Rule 11: Linux board/NAS vendors.
	if fam == "LinuxBoard" {
		return "Linux"
	}
	// Rule 12: Linux desktop/server hint — SSH on a TTL-64 host.
	if hasOpenPort(d.OpenPorts, 22) && ttlGuess == "Linux/macOS" {
		return "Linux"
	}
	// Rule 13: Avahi default service from a non-Apple host.
	if hasService(d.Services, "_workstation._tcp") && fam != "Apple" {
		return "Linux"
	}
	// Rules 14-16: TTL-only fallbacks.
	switch ttlGuess {
	case "RTOS/Network":
		return "Network"
	case "Linux/macOS":
		return "Linux"
	case "Windows":
		return "Windows"
	}
	return ""
}

// hasService reports whether any of d.Services has Type matching one of
// the given service types.
func hasService(svcs []model.ServiceInst, types ...string) bool {
	for _, s := range svcs {
		for _, t := range types {
			if s.Type == t {
				return true
			}
		}
	}
	return false
}

// hasOpenPort reports whether any of openPorts has the given Number.
func hasOpenPort(openPorts []model.Port, port int) bool {
	for _, p := range openPorts {
		if p.Number == port {
			return true
		}
	}
	return false
}

// hasTXTModelPrefix reports whether any service's TXT["model"] begins
// (case-insensitive) with one of the given prefixes.
func hasTXTModelPrefix(svcs []model.ServiceInst, prefixes ...string) bool {
	for _, s := range svcs {
		model := strings.ToLower(s.TXT["model"])
		if model == "" {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(model, prefix) {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 5.2: Append `OSDetect` table test to `internal/probe/osguess_test.go`**

The file is already `package probe` after Task 4. Add the model import:

```go
package probe

import (
	"testing"

	"github.com/lab1702/lan-inventory/internal/model"
)
```

Then append at the end:

```go
func TestOSDetect(t *testing.T) {
	svcs := func(entries ...string) []model.ServiceInst {
		out := make([]model.ServiceInst, 0, len(entries))
		for _, e := range entries {
			if i := indexOf(e, '='); i > 0 {
				// "model=iPhone14,5" → ServiceInst with TXT
				out = append(out, model.ServiceInst{
					Type: "_device-info._tcp",
					TXT:  map[string]string{e[:i]: e[i+1:]},
				})
			} else {
				// "_airplay._tcp" → ServiceInst with just a type
				out = append(out, model.ServiceInst{Type: e})
			}
		}
		return out
	}
	port := func(n int) []model.Port {
		return []model.Port{{Number: n, Proto: "tcp"}}
	}

	cases := []struct {
		name           string
		vendor         string
		services       []model.ServiceInst
		openPorts      []model.Port
		nbnsResponded  bool
		ttl            int
		want           string
	}{
		{"Apple TXT iPhone -> iOS", "Apple", svcs("model=iPhone14,5"), nil, false, 64, "iOS"},
		{"Apple + _apple-mobdev2 -> iOS", "Apple", svcs("_apple-mobdev2._tcp"), nil, false, 64, "iOS"},
		{"Apple TXT Mac -> macOS", "Apple", svcs("model=MacBookPro18,2"), nil, false, 64, "macOS"},
		{"Apple + _airplay -> macOS", "Apple", svcs("_airplay._tcp"), nil, false, 64, "macOS"},
		{"Apple alone -> macOS", "Apple", nil, nil, false, 64, "macOS"},
		{"NBNS no vendor -> Windows", "", nil, nil, true, 128, "Windows"},
		{"NBNS Synology -> Linux", "Synology", nil, nil, true, 64, "Linux"},
		{"Apple Boot Camp NBNS -> Windows", "Apple", nil, nil, true, 128, "Windows"},
		{"TP-Link router -> Network", "TP-Link", nil, nil, false, 255, "Network"},
		{"Espressif IoT -> Network", "Espressif", nil, nil, false, 64, "Network"},
		{"HP printer -> Network", "HP", nil, port(9100), false, 64, "Network"},
		{"RaspberryPi -> Linux", "RaspberryPi", nil, port(22), false, 64, "Linux"},
		{"_workstation -> Linux", "", svcs("_workstation._tcp"), nil, false, 64, "Linux"},
		{"TTL128+445 -> Windows", "", nil, port(445), false, 128, "Windows"},
		{"TTL64 fallback -> Linux", "", nil, nil, false, 64, "Linux"},
		{"TTL255 fallback -> Network", "", nil, nil, false, 255, "Network"},
		{"No signals -> empty", "", nil, nil, false, 0, ""},
		{"Apple Watch -> iOS", "Apple", svcs("model=Watch6,1"), nil, false, 64, "iOS"},
		{"Apple _companion-link -> macOS", "Apple", svcs("_companion-link._tcp"), nil, false, 64, "macOS"},
		{"Roku _airplay -> empty (no Apple OUI)", "Roku", svcs("_airplay._tcp"), nil, false, 64, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &model.Device{
				Vendor:    c.vendor,
				Services:  c.services,
				OpenPorts: c.openPorts,
				TTL:       c.ttl,
			}
			if got := OSDetect(d, c.nbnsResponded); got != c.want {
				t.Errorf("OSDetect = %q, want %q", got, c.want)
			}
		})
	}
}

// indexOf returns the index of the first b in s, or -1 if absent.
func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
```

**Note:** the "Roku _airplay -> empty" case is a deliberate negative — non-Apple vendors that broadcast AirPlay (Roku, AppleTV-knockoffs) shouldn't be labeled macOS. The test asserts "" because no rule fires. This documents the behavior; if you want such devices labeled `Network`, add a rule.

- [ ] **Step 5.3: Verify**

```bash
go test ./internal/probe/ -v
go vet ./...
go build ./...
```

All probe tests must pass: existing `TestOSGuess`, new `TestVendorFamily`, new `TestOSDetect` (with all 20 sub-cases).

- [ ] **Step 5.4: Commit**

```bash
git add internal/probe/osguess.go internal/probe/osguess_test.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "probe: OSDetect priority chain"
```

---

## Task 6: Switch merger to OSDetect

**Files:**
- Modify: `internal/scanner/interfaces.go`
- Modify: `internal/scanner/active.go`
- Modify: `internal/scanner/merger.go`
- Modify: `internal/scanner/merger_test.go`

Final wiring: merger calls `OSDetect` after each `mergeUpdate`; `Update.OSGuess` is removed; active worker stops computing `OSGuess`.

- [ ] **Step 6.1: Remove `OSGuess` from `Update` in `internal/scanner/interfaces.go`**

Find the `Update` struct. Delete the `OSGuess` line. The struct goes from:

```go
type Update struct {
	Source     string
	Time       time.Time
	MAC        string
	IP         net.IP
	Hostname   string
	Vendor     string
	OSGuess    string             // ← remove
	OpenPorts  []model.Port
	Services   []model.ServiceInst
	RTT        time.Duration
	Alive      bool
	TTL           int
	NBNSResponded bool
}
```

to:

```go
type Update struct {
	Source     string
	Time       time.Time
	MAC        string
	IP         net.IP
	Hostname   string
	Vendor     string
	OpenPorts  []model.Port
	Services   []model.ServiceInst
	RTT        time.Duration
	Alive      bool
	TTL           int
	NBNSResponded bool
}
```

- [ ] **Step 6.2: Remove `OSGuess` from active worker's Update construction in `internal/scanner/active.go`**

Find the `Update{...}` literal in `probeOne`. Remove the `OSGuess: probe.OSGuess(pingRes.TTL),` line. The struct construction goes from:

```go
	update := Update{
		Source:        "active",
		Time:          time.Now(),
		IP:            ip,
		Alive:         true,
		RTT:           pingRes.RTT,
		TTL:           pingRes.TTL,
		OSGuess:       probe.OSGuess(pingRes.TTL),
		Hostname:      probe.ResolveHostname(ctx, ip.String(), w.Gateway),
		OpenPorts:     probe.ScanPorts(ctx, ip.String(), probe.DefaultPorts(), 500*time.Millisecond),
		NBNSResponded: nbnsName != "",
	}
```

to:

```go
	update := Update{
		Source:        "active",
		Time:          time.Now(),
		IP:            ip,
		Alive:         true,
		RTT:           pingRes.RTT,
		TTL:           pingRes.TTL,
		Hostname:      probe.ResolveHostname(ctx, ip.String(), w.Gateway),
		OpenPorts:     probe.ScanPorts(ctx, ip.String(), probe.DefaultPorts(), 500*time.Millisecond),
		NBNSResponded: nbnsName != "",
	}
```

- [ ] **Step 6.3: Remove `OSGuess` merge action and add `OSDetect` call in `internal/scanner/merger.go`**

Find this block in `mergeUpdate`:

```go
	if u.OSGuess != "" {
		dev.OSGuess = u.OSGuess
	}
```

Delete it. The TTL/NBNSResponded merges from Task 3 are still in place.

Then find the end of `mergeUpdate` — the final `sort.Slice(dev.OpenPorts, ...)` line. Replace:

```go
	dev.Status = model.StatusOnline
	sort.Slice(dev.OpenPorts, func(i, j int) bool { return dev.OpenPorts[i].Number < dev.OpenPorts[j].Number })
}
```

with:

```go
	dev.Status = model.StatusOnline
	sort.Slice(dev.OpenPorts, func(i, j int) bool { return dev.OpenPorts[i].Number < dev.OpenPorts[j].Number })
	dev.OSGuess = probe.OSDetect(dev, dev.NBNSResponded)
}
```

Add the import for `internal/probe` at the top of `merger.go`. Find the existing import block:

```go
import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)
```

Replace with:

```go
import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/probe"
)
```

- [ ] **Step 6.4: Add merger integration test in `internal/scanner/merger_test.go`**

Append at the end of `merger_test.go`:

```go
func TestMergerComputesOSDetect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan Update, 16)
	out := make(chan model.DeviceEvent, 16)
	m := NewMerger(MergerOptions{LeftAfter: time.Hour})
	go m.Run(ctx, in, out)

	// ARP brings vendor=Apple
	in <- Update{Source: "arp", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:01", IP: net.ParseIP("192.168.1.10"), Vendor: "Apple"}
	// mDNS brings _airplay._tcp + TXT model=MacBookPro18,2
	in <- Update{Source: "mdns", Time: time.Now(), IP: net.ParseIP("192.168.1.10"), Services: []model.ServiceInst{
		{Type: "_airplay._tcp", Name: "mac1", Port: 7000, TXT: map[string]string{"model": "MacBookPro18,2"}},
	}}
	// Active brings TTL=128 (would normally be Windows by TTL alone)
	in <- Update{Source: "active", Time: time.Now(), IP: net.ParseIP("192.168.1.10"), Alive: true, TTL: 128, RTT: time.Millisecond}

	collectEvents(out, 3, 300*time.Millisecond)

	devices := m.Snapshot()
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].OSGuess != "macOS" {
		t.Errorf("OSGuess = %q, want macOS (TXT model should override TTL=128)", devices[0].OSGuess)
	}
}
```

This validates the full wiring: ARP supplies vendor, mDNS supplies services + TXT, active supplies TTL — and the merger's `OSDetect` call correctly prefers the TXT model signal over the TTL.

- [ ] **Step 6.5: Verify**

```bash
go build ./...
go test ./...
go test -race ./...
go vet ./...
```

All packages pass. The new `TestMergerComputesOSDetect` passes. Existing merger tests still pass.

- [ ] **Step 6.6: Commit**

```bash
git add internal/scanner/interfaces.go internal/scanner/active.go internal/scanner/merger.go internal/scanner/merger_test.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "scanner: merger calls OSDetect; remove Update.OSGuess"
```

---

## Task 7: Final lint and verify

**Files:** none modified.

- [ ] **Step 7.1: Run vet, staticcheck, race, full test suite**

```bash
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go test ./...
go test -race ./...
```

All clean.

- [ ] **Step 7.2: Smoke build and version check**

```bash
make build
./bin/lan-inventory --version
ls -la bin/lan-inventory
rm -rf bin/
```

Expected: `lan-inventory 0.1.0`. Binary size unchanged (no new dependencies; ~150 lines net of new code).

- [ ] **Step 7.3: Commit any lint fixes (only if needed)**

```bash
git add -u
git diff --cached --quiet && echo "no changes" || git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "chore: address lint warnings after OS detection refactor"
```

---

## Done

After all 7 tasks complete:

- 6 commits on `feat/os-detection` (model fields, mDNS TXT, raw signals, vendorFamily, OSDetect, merger wiring) plus optional lint cleanup.
- `go test ./...` passes; race clean; vet clean; staticcheck clean.
- The OS column on the live TUI labels devices with the strongest available signal: Apple AirPlay hosts as `macOS` (or `iOS` if their TXT model is iPhone/iPad/Watch), Windows boxes as `Windows` (via NBNS or TTL+SMB), routers/printers/IoT as `Network`, Linux servers as `Linux`. TTL is fallback only.
- Mac mislabeled as Windows (the bug that motivated this work) now resolves to `macOS` because Rule 4 (Apple OUI + AirPlay) fires before Rule 16 (TTL=Windows fallback).
