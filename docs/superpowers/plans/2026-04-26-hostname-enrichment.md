# Hostname Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three new hostname-resolution probes (gateway-DNS, NBNS, mDNS-reverse) chained sequentially behind the existing system-resolver rDNS, so the Hostname column populates for typical home-LAN devices that don't broadcast mDNS.

**Architecture:** New `probe.ResolveHostname(ctx, ip, gatewayIP)` is the single entry point the active worker calls. It runs four probes sequentially with early-exit, each bounded by a 500 ms timeout. Gateway IP is plumbed through `netiface.Info.Gateway` and `scanner.ActiveWorker.Gateway`. NBNS is a pure-Go raw protocol implementation; gateway-DNS and mDNS-reverse use `net.Resolver` with a custom `Dial`.

**Tech Stack:** Go 1.24 stdlib (`net`, `net.Resolver`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-04-26-hostname-enrichment-design.md`

---

## File structure

```
internal/netiface/
├── netiface.go        (MOD)  — Info.Gateway field
├── route_linux.go     (MOD)  — defaultRouteInterface returns gateway too
└── route_other.go     (MOD)  — stub matches new signature

internal/probe/
├── dns.go             (MOD)  — add ReverseDNSVia, ReverseDNSMDNS, ResolveHostname
├── dns_test.go        (MOD)  — TestResolveHostnameDeadIP, TestReverseDNSMDNSLocalhost
├── nbns.go            (NEW)  — nbnsQuery, parseNBNSResponse, NBNS
└── nbns_test.go       (NEW)  — table tests for parseNBNSResponse + localhost smoke

internal/scanner/
├── active.go          (MOD)  — ActiveWorker.Gateway, probeOne calls ResolveHostname
└── scanner.go         (MOD)  — plumb cfg.Iface.Gateway into ActiveWorker
```

**Note on operator workflow:** The implementer should follow `superpowers:using-git-worktrees` to create a `feat/hostname-enrichment` worktree before starting.

---

## Task 1: Plumb gateway IP through `netiface`

**Files:**
- Modify: `internal/netiface/route_linux.go`
- Modify: `internal/netiface/route_other.go`
- Modify: `internal/netiface/netiface.go`

The current `defaultRouteInterface()` returns `(*net.Interface, error)` and discards the gateway hex from `/proc/net/route`. Change the signature to also return the gateway IP.

- [ ] **Step 1.1: Update `route_linux.go` — return gateway IP**

Replace `internal/netiface/route_linux.go` with:

```go
//go:build linux

package netiface

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// defaultRouteInterface reads /proc/net/route and returns the interface that
// owns the default route (destination 00000000 with the lowest metric), and
// the gateway IP for that route. The gateway may be nil if the field is
// unparseable; that is non-fatal — callers should treat a nil gateway as
// "unknown" and skip any features that need it.
func defaultRouteInterface() (*net.Interface, net.IP, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, nil, fmt.Errorf("open /proc/net/route: %w", err)
	}
	defer f.Close()

	type cand struct {
		iface   string
		metric  int
		gateway string
	}
	var best *cand

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		// Default route has destination 00000000 and mask 00000000
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		var metric int
		if _, err := fmt.Sscanf(fields[6], "%d", &metric); err != nil {
			continue
		}
		if best == nil || metric < best.metric {
			best = &cand{iface: fields[0], metric: metric, gateway: fields[2]}
		}
	}
	if best == nil {
		return nil, nil, fmt.Errorf("no default route — cannot determine which subnet to scan")
	}
	iface, err := net.InterfaceByName(best.iface)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s: %w", best.iface, err)
	}

	// Decode gateway hex (little-endian in /proc/net/route).
	gwBytes, err := hex.DecodeString(best.gateway)
	if err != nil || len(gwBytes) != 4 {
		return iface, nil, nil
	}
	gateway := net.IPv4(gwBytes[3], gwBytes[2], gwBytes[1], gwBytes[0])
	return iface, gateway, nil
}
```

- [ ] **Step 1.2: Update `route_other.go` — match the new signature**

Replace `internal/netiface/route_other.go` with:

```go
//go:build !linux

package netiface

import (
	"fmt"
	"net"
)

func defaultRouteInterface() (*net.Interface, net.IP, error) {
	return nil, nil, fmt.Errorf("default route detection not implemented on this platform")
}
```

- [ ] **Step 1.3: Update `netiface.go` — add `Gateway` field and plumb it**

In `internal/netiface/netiface.go`, find the `Info` struct (lines 11–16) and replace with:

```go
// Info describes the interface chosen for scanning.
type Info struct {
	Name    string
	Subnet  *net.IPNet
	HostIP  net.IP // our own IP on this interface
	Gateway net.IP // default-route gateway IP; may be nil if unparseable
}
```

Then find the `Detect` function and update the call to `defaultRouteInterface` and the returned `Info`:

```go
// Detect picks the interface owning the default IPv4 route, validates the
// subnet size, and returns Info. This function reads OS state and is not
// unit-tested; covered by manual smoke testing.
func Detect() (*Info, error) {
	defaultIface, gateway, err := defaultRouteInterface()
	if err != nil {
		return nil, err
	}
	addrs, err := defaultIface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("read addrs for %s: %w", defaultIface.Name, err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			continue
		}
		subnet := &net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: net.CIDRMask(ones, 32)}
		if err := CheckSubnetSize(subnet); err != nil {
			return nil, err
		}
		return &Info{Name: defaultIface.Name, Subnet: subnet, HostIP: ip4, Gateway: gateway}, nil
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", defaultIface.Name)
}
```

- [ ] **Step 1.4: Verify existing tests still pass**

```bash
go test ./internal/netiface/ -v
go vet ./...
go build ./...
```

`TestCheckSubnetSize` (6 sub-cases) and `TestSubnetIPs` must still pass. They don't touch `defaultRouteInterface` so they're unaffected by the signature change. The build verifies the new `Info.Gateway` field doesn't break anything else.

- [ ] **Step 1.5: Commit**

```bash
git add internal/netiface/
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "netiface: surface gateway IP from /proc/net/route in Info"
```

---

## Task 2: Add `ReverseDNSVia` and `ReverseDNSMDNS` to `dns.go`

**Files:**
- Modify: `internal/probe/dns.go`

Two structurally-identical helpers that wrap `net.Resolver` with a custom `Dial` targeting a specific resolver address.

- [ ] **Step 2.1: Replace `internal/probe/dns.go`**

Replace the entire file with:

```go
package probe

import (
	"context"
	"net"
	"strings"
	"time"
)

// ReverseDNS does a PTR lookup for ip via the system default resolver and
// returns the first result, with the trailing dot trimmed. Returns "" on
// timeout, no result, or any error.
func ReverseDNS(ctx context.Context, ip string) string {
	resolver := net.DefaultResolver
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// ReverseDNSVia performs a PTR lookup using a custom resolver IP rather than
// the system default. Used to query the LAN gateway's local DNS, which often
// knows DHCP-lease names that upstream resolvers don't. Returns "" on any
// error or empty result. Bounded by a 500 ms timeout.
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

// ReverseDNSMDNS sends a unicast PTR query to the device's UDP port 5353
// (mDNS protocol port). Some devices answer their own .local hostname here
// even when they don't actively announce services. Returns "" on any error
// or empty result. Bounded by a 500 ms timeout.
//
// The function name reflects the protocol (mDNS) but the transport is
// unicast — we send directly to the device's IP, not the multicast group.
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

- [ ] **Step 2.2: Add a localhost smoke test for `ReverseDNSMDNS`**

Append to `internal/probe/dns_test.go`:

```go
func TestReverseDNSMDNSLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	// Localhost rarely runs an mDNS responder bound to 127.0.0.1, so we
	// typically expect "". We verify the function doesn't panic or hang.
	_ = probe.ReverseDNSMDNS(ctx, "127.0.0.1")
}
```

This is a smoke test, not a behavioral verification — same pattern as the existing `TestPingLocalhost` and the new `TestNBNSLocalhostSmoke`.

- [ ] **Step 2.3: Verify build and tests**

```bash
go test ./internal/probe/ -v
go vet ./...
```

Existing `TestReverseDNS*` tests still pass; the new `TestReverseDNSMDNSLocalhost` passes (or skips cleanly without panic).

- [ ] **Step 2.4: Commit**

```bash
git add internal/probe/dns.go internal/probe/dns_test.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "probe: ReverseDNSVia and ReverseDNSMDNS for gateway and mDNS PTR lookups"
```

---

## Task 3: NBNS probe

**Files:**
- Create: `internal/probe/nbns.go`
- Create: `internal/probe/nbns_test.go`

Pure-Go NBNS Node Status Request (UDP 137). Returns the device's NetBIOS Workstation name.

- [ ] **Step 3.1: Create `internal/probe/nbns_test.go` first (TDD)**

Create with this content:

```go
package probe

import (
	"context"
	"testing"
	"time"
)

// makeNBNSResponse builds a minimal NBNS Node Status Response containing the
// given names. Each name is space-padded to 15 chars + 1 byte suffix + 2
// bytes flags. suffixes[i] is the suffix type byte (0x00 = Workstation).
// groupFlags[i] true sets the group bit in the flags field.
func makeNBNSResponse(names []string, suffixes []byte, groupFlags []bool) []byte {
	// 12-byte header: flags 0x8500 = response, recursion not desired
	hdr := []byte{
		0x12, 0x34, 0x85, 0x00,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}
	// 38-byte question section: length 32 + encoded "CK" + 30x"A" + NUL + type + class
	q := []byte{0x20, 'C', 'K'}
	for i := 0; i < 30; i++ {
		q = append(q, 'A')
	}
	q = append(q, 0x00, 0x00, 0x21, 0x00, 0x01)

	// 12-byte answer header: name pointer + type + class + TTL + RDLENGTH
	rdlen := 1 + 18*len(names)
	ans := []byte{
		0xC0, 0x0C,
		0x00, 0x21,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		byte(rdlen >> 8), byte(rdlen & 0xff),
	}

	rdata := []byte{byte(len(names))}
	for i, name := range names {
		nameBytes := make([]byte, 16)
		// pad to 15 chars with spaces
		for j := 0; j < 15; j++ {
			if j < len(name) {
				nameBytes[j] = name[j]
			} else {
				nameBytes[j] = ' '
			}
		}
		nameBytes[15] = suffixes[i]
		var flags [2]byte
		if groupFlags[i] {
			flags[0] = 0x80
		}
		rdata = append(rdata, nameBytes...)
		rdata = append(rdata, flags[:]...)
	}

	out := append([]byte{}, hdr...)
	out = append(out, q...)
	out = append(out, ans...)
	out = append(out, rdata...)
	return out
}

func TestParseNBNSResponseValid(t *testing.T) {
	resp := makeNBNSResponse(
		[]string{"DESKTOP-A"},
		[]byte{0x00},
		[]bool{false},
	)
	got := parseNBNSResponse(resp)
	if got != "DESKTOP-A" {
		t.Errorf("got %q, want %q", got, "DESKTOP-A")
	}
}

func TestParseNBNSResponseGroupSkipped(t *testing.T) {
	// A single Workstation-suffix name but with the group bit set should be skipped.
	resp := makeNBNSResponse(
		[]string{"WORKGROUP"},
		[]byte{0x00},
		[]bool{true},
	)
	got := parseNBNSResponse(resp)
	if got != "" {
		t.Errorf("group-only response should yield empty, got %q", got)
	}
}

func TestParseNBNSResponseTooShort(t *testing.T) {
	got := parseNBNSResponse([]byte{0x12, 0x34, 0x85, 0x00})
	if got != "" {
		t.Errorf("too-short buffer should yield empty, got %q", got)
	}
}

func TestParseNBNSResponseEmptyList(t *testing.T) {
	resp := makeNBNSResponse(nil, nil, nil)
	got := parseNBNSResponse(resp)
	if got != "" {
		t.Errorf("empty-list response should yield empty, got %q", got)
	}
}

func TestParseNBNSResponseSecondNameWins(t *testing.T) {
	// First name is a group, second is the unique Workstation. We should
	// skip the first and return the second.
	resp := makeNBNSResponse(
		[]string{"WORKGROUP", "MYHOST"},
		[]byte{0x00, 0x00},
		[]bool{true, false},
	)
	got := parseNBNSResponse(resp)
	if got != "MYHOST" {
		t.Errorf("got %q, want %q", got, "MYHOST")
	}
}

func TestParseNBNSResponseTrimsSpaces(t *testing.T) {
	resp := makeNBNSResponse(
		[]string{"H"},
		[]byte{0x00},
		[]bool{false},
	)
	got := parseNBNSResponse(resp)
	if got != "H" {
		t.Errorf("got %q, want %q (spaces should be trimmed)", got, "H")
	}
}

func TestNBNSQueryFormat(t *testing.T) {
	if len(nbnsQuery) != 50 {
		t.Fatalf("nbnsQuery length: got %d, want 50", len(nbnsQuery))
	}
	// Header: QDCOUNT must be 1.
	if nbnsQuery[4] != 0x00 || nbnsQuery[5] != 0x01 {
		t.Errorf("QDCOUNT: got %#x %#x, want 0x00 0x01", nbnsQuery[4], nbnsQuery[5])
	}
	// Question type at offset 12 + 1 + 32 + 1 = 46: should be 0x00 0x21 (NBSTAT).
	if nbnsQuery[46] != 0x00 || nbnsQuery[47] != 0x21 {
		t.Errorf("QTYPE: got %#x %#x, want 0x00 0x21 (NBSTAT)", nbnsQuery[46], nbnsQuery[47])
	}
	// Question class at offset 48: should be 0x00 0x01 (IN).
	if nbnsQuery[48] != 0x00 || nbnsQuery[49] != 0x01 {
		t.Errorf("QCLASS: got %#x %#x, want 0x00 0x01 (IN)", nbnsQuery[48], nbnsQuery[49])
	}
}

func TestNBNSLocalhostSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	// Localhost rarely runs nmbd, so we typically expect "". If a developer's
	// box does run Samba, the response is non-empty. Either is fine — we
	// only verify the function doesn't panic or hang past the timeout.
	_ = NBNS(ctx, "127.0.0.1")
}
```

- [ ] **Step 3.2: Verify tests fail (TDD)**

```bash
go test ./internal/probe/ -v -run "ParseNBNS|NBNSQuery|NBNSLocalhost"
```

Expected: FAIL — `parseNBNSResponse`, `nbnsQuery`, and `NBNS` don't exist yet.

- [ ] **Step 3.3: Create `internal/probe/nbns.go`**

```go
package probe

import (
	"context"
	"net"
	"strings"
	"time"
)

// nbnsQuery is the 50-byte NBNS Node Status Request datagram.
//
// 12-byte DNS-style header:
//   - Transaction ID 0x1234
//   - Flags 0x0000 (standard query, no broadcast)
//   - QDCOUNT 1, ANCOUNT 0, NSCOUNT 0, ARCOUNT 0
//
// Encoded NetBIOS wildcard name: length 0x20, then "CK" (which is the
// nibble-encoding of '*' = 0x2A: 'A' + 0x2 = 'C', 'A' + 0xA = 'K') followed
// by 30 'A' characters (the encoding of 15 NUL bytes), terminated with NUL.
//
// Question type 0x0021 (NBSTAT), class 0x0001 (IN).
var nbnsQuery = []byte{
	// header
	0x12, 0x34, // transaction ID
	0x00, 0x00, // flags
	0x00, 0x01, // QDCOUNT
	0x00, 0x00, // ANCOUNT
	0x00, 0x00, // NSCOUNT
	0x00, 0x00, // ARCOUNT
	// encoded name: length + 2-char '*' + 30-char NULs + terminator
	0x20,
	'C', 'K',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	0x00,
	// QTYPE NBSTAT
	0x00, 0x21,
	// QCLASS IN
	0x00, 0x01,
}

// NBNS sends an NBNS Node Status Request to ip:137 and returns the device's
// Workstation/Redirector name. Returns "" on no response, timeout, or any
// parse error. Bounded by a 500 ms read deadline.
//
// Devices that don't speak NBNS (most Linux/macOS, IoT) simply ignore the
// query and we hit the read deadline. One stray UDP packet per scan cycle
// per host — negligible noise.
func NBNS(ctx context.Context, ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	addr := &net.UDPAddr{IP: parsed, Port: 137}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	deadline := time.Now().Add(500 * time.Millisecond)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return ""
	}

	if _, err := conn.Write(nbnsQuery); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return parseNBNSResponse(buf[:n])
}

// parseNBNSResponse extracts the first non-group Workstation name from an
// NBNS Node Status Response. Layout:
//
//   [0..12)   header
//   [12..50)  question section (echoes our 38-byte question)
//   [50..62)  answer section header (name ptr + type + class + TTL + RDLENGTH)
//   [62]      NUM_NAMES
//   [63..)    NAME_RECORDS, each 18 bytes:
//                15 bytes name (space-padded)
//                 1 byte suffix type (0x00 = Workstation/Redirector)
//                 2 bytes flags (top bit of first byte = group)
//
// A valid response is at least 12 + 38 + 12 + 1 + 18 = 81 bytes.
func parseNBNSResponse(buf []byte) string {
	const minLen = 81
	if len(buf) < minLen {
		return ""
	}
	numNames := int(buf[62])
	if numNames == 0 {
		return ""
	}
	const recBase = 63
	const recSize = 18
	for i := 0; i < numNames; i++ {
		off := recBase + i*recSize
		if off+recSize > len(buf) {
			break
		}
		nameBytes := buf[off : off+15]
		suffix := buf[off+15]
		flagsHigh := buf[off+16]
		// Suffix 0x00 is Workstation/Redirector — the actual machine name.
		if suffix != 0x00 {
			continue
		}
		// Top bit of the flags' first byte = Group flag. We want unique names.
		if flagsHigh&0x80 != 0 {
			continue
		}
		name := strings.TrimRight(string(nameBytes), " ")
		if name == "" {
			continue
		}
		return name
	}
	return ""
}
```

- [ ] **Step 3.4: Verify all tests pass**

```bash
go test ./internal/probe/ -v
go vet ./...
```

All 6 `parseNBNSResponse` cases plus `TestNBNSQueryFormat` and `TestNBNSLocalhostSmoke` must pass. Existing probe tests still pass.

- [ ] **Step 3.5: Commit**

```bash
git add internal/probe/nbns.go internal/probe/nbns_test.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "probe: NBNS Node Status Request for NetBIOS hostname lookup"
```

---

## Task 4: `ResolveHostname` chain

**Files:**
- Modify: `internal/probe/dns.go` (append `ResolveHostname`)
- Modify: `internal/probe/dns_test.go` (append chain test)

- [ ] **Step 4.1: Append `ResolveHostname` to `internal/probe/dns.go`**

Append at the end of `internal/probe/dns.go`:

```go
// ResolveHostname tries multiple lookup paths in priority order and returns
// the first non-empty answer. Each probe has its own bounded timeout so the
// chain is bounded by the sum of probe timeouts even on dead hosts.
//
// Order:
//   1. system rDNS
//   2. gateway-as-resolver (if gatewayIP is non-nil)
//   3. NBNS (UDP 137)
//   4. mDNS reverse (UDP 5353 unicast)
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

- [ ] **Step 4.2: Append chain-runtime test to `internal/probe/dns_test.go`**

Append at the end of `internal/probe/dns_test.go`:

```go
func TestResolveHostnameDeadIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	got := probe.ResolveHostname(ctx, "192.0.2.1", nil)
	elapsed := time.Since(start)

	if got != "" {
		t.Errorf("ResolveHostname on TEST-NET-1 should return empty, got %q", got)
	}
	// Chain bound: system rDNS may take a couple of seconds depending on the
	// system resolver, then NBNS (500 ms) and mDNS-reverse (500 ms). Allow
	// up to 4 s total before declaring the chain unbounded.
	if elapsed > 4*time.Second {
		t.Errorf("ResolveHostname took %v, expected under 4s", elapsed)
	}
}
```

- [ ] **Step 4.3: Verify tests pass**

```bash
go test ./internal/probe/ -v -run TestResolveHostnameDeadIP
go test ./internal/probe/ -v
go vet ./...
```

`TestResolveHostnameDeadIP` must pass; all probe tests must continue to pass.

- [ ] **Step 4.4: Commit**

```bash
git add internal/probe/dns.go internal/probe/dns_test.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "probe: ResolveHostname chain with bounded runtime"
```

---

## Task 5: Wire `ActiveWorker.Gateway` and switch to `ResolveHostname`

**Files:**
- Modify: `internal/scanner/active.go`
- Modify: `internal/scanner/scanner.go`

- [ ] **Step 5.1: Update `ActiveWorker` struct and `probeOne` in `internal/scanner/active.go`**

Find the `ActiveWorker` struct (lines 15–20) and replace with:

```go
// ActiveWorker periodically probes every host in Subnet plus any IP it has
// learned about, calling probe.Ping, probe.ScanPorts, and probe.ResolveHostname.
// One full sweep emits one Update per responding host.
type ActiveWorker struct {
	Subnet      *net.IPNet
	HostIPs     []net.IP // pre-enumerated subnet hosts
	Gateway     net.IP   // default-route gateway IP for the gateway-resolver hostname probe
	Interval    time.Duration
	WorkerCount int
}
```

Then find the `update.Hostname` line in `probeOne` (around line 92) and replace it with:

```go
		Hostname:  probe.ResolveHostname(ctx, ip.String(), w.Gateway),
```

The full `probeOne` function should now look like:

```go
func (w *ActiveWorker) probeOne(ctx context.Context, ip net.IP, out chan<- Update) {
	if ctx.Err() != nil {
		return
	}
	pingRes, err := probe.Ping(ctx, ip.String())
	if err != nil || !pingRes.Alive {
		return
	}
	update := Update{
		Source:    "active",
		Time:      time.Now(),
		IP:        ip,
		Alive:     true,
		RTT:       pingRes.RTT,
		OSGuess:   probe.OSGuess(pingRes.TTL),
		Hostname:  probe.ResolveHostname(ctx, ip.String(), w.Gateway),
		OpenPorts: probe.ScanPorts(ctx, ip.String(), probe.DefaultPorts(), 500*time.Millisecond),
	}
	select {
	case out <- update:
	case <-ctx.Done():
	}
}
```

- [ ] **Step 5.2: Plumb gateway in `internal/scanner/scanner.go`**

Find the `active := &ActiveWorker{...}` block in `Run` (around lines 59–63) and replace with:

```go
	active := &ActiveWorker{
		Subnet:      s.cfg.Iface.Subnet,
		HostIPs:     hosts,
		Gateway:     s.cfg.Iface.Gateway,
		WorkerCount: 32,
	}
```

- [ ] **Step 5.3: Verify build, tests, and race**

```bash
go build ./...
go test ./...
go test -race ./...
go vet ./...
```

All clean. Existing scanner tests must still pass — the merger tests don't depend on `Gateway`, and the data-flow tests construct `Update`s directly without going through `probeOne`.

- [ ] **Step 5.4: Commit**

```bash
git add internal/scanner/active.go internal/scanner/scanner.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "scanner: wire ActiveWorker.Gateway and call ResolveHostname"
```

---

## Task 6: Final lint and verify

**Files:** none modified.

- [ ] **Step 6.1: Run vet, staticcheck, full test suite, race**

```bash
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go test ./...
go test -race ./...
```

All clean.

- [ ] **Step 6.2: Smoke build and version check**

```bash
make build
./bin/lan-inventory --version
ls -la bin/lan-inventory
rm -rf bin/
```

Expected:
- `lan-inventory 0.1.0` printed.
- Binary size shouldn't change meaningfully (the new code is ~150 lines, no new dependencies).

- [ ] **Step 6.3: Commit any lint fixes (only if needed)**

If staticcheck or vet flagged anything in earlier tasks (unused returns from `conn.Close()`, etc.), fix inline:

```bash
git add -u
git diff --cached --quiet && echo "no changes" || git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "chore: address lint warnings after hostname enrichment"
```

---

## Done

After all 6 tasks complete:

- 5 commits on the `feat/hostname-enrichment` branch (gateway plumbing, dns variants, NBNS, ResolveHostname chain, scanner wiring), plus optional lint cleanup.
- `go test ./...` passes; race clean; vet clean; staticcheck clean.
- Hostname column on the live TUI now resolves for: devices behind dnsmasq-style routers (DHCP-lease names), Windows/Samba boxes (NBNS), and mDNS-only devices that didn't actively announce services (mDNS-reverse).
- Chain runtime is bounded — a fully dead host adds at most ~2 s to its probe cycle, easily absorbed by the 30 s active-scan interval.
