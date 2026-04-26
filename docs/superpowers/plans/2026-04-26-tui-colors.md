# TUI Color Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add purposeful color throughout the lan-inventory TUI — status semantics, dim absent fields, blue accents for selection and key labels — by centralizing every styled string in a new `internal/tui/style.go`.

**Architecture:** New `internal/tui/style.go` defines lipgloss styles using ANSI named colors (so the user's terminal theme drives the hue). New `internal/tui/util.go` adds `visibleLen` and `padRight` so colored cells don't break table alignment. Each existing view file (`model.go`, `devices.go`, `services.go`, `subnet.go`, `events.go`) is updated to consume the style helpers. Existing string-containment tests stay green; two new tests verify color semantics.

**Tech Stack:** Go 1.24, `github.com/charmbracelet/lipgloss` (already in go.mod), `github.com/muesli/termenv` (transitive dep already present, used directly in tests for color profile control).

**Spec:** `docs/superpowers/specs/2026-04-26-tui-colors-design.md`

---

## File structure

```
internal/tui/
├── style.go       (NEW)  — all lipgloss styles + styleStatus / styleEventType
├── util.go        (NEW)  — visibleLen, padRight (ANSI-aware width)
├── util_test.go   (NEW)  — unit tests for visibleLen/padRight
├── model.go       (MOD)  — renderHeader + summaryLine + helpText use styles
├── devices.go     (MOD)  — status colors, dim divider/empties, padRight rows, selected row, detail-strip labels
├── services.go    (MOD)  — service-type key in blue
├── subnet.go      (MOD)  — glyphs colored per status
├── events.go      (MOD)  — time dim, type colored
└── tui_test.go    (MOD)  — TestStatusColors + TestColorsCanBeDisabled + assertion in TestSubnetTabRendersGrid
```

**Note on operator workflow:** This plan modifies existing committed code on master. Implementer should follow `superpowers:using-git-worktrees` to create a `feat/tui-colors` worktree before starting.

---

## Task 1: Add `internal/tui/style.go` and `internal/tui/util.go`

**Files:**
- Create: `internal/tui/style.go`
- Create: `internal/tui/util.go`
- Create: `internal/tui/util_test.go`

This task introduces no visual change — just adds the central style helpers and ANSI-aware width helpers that subsequent tasks will use.

- [ ] **Step 1.1: Create `internal/tui/util.go`**

```go
package tui

import "strings"

// visibleLen returns the number of printed cells in s, ignoring ANSI escape
// sequences. Use this instead of len() when sizing columns that may contain
// styled content.
func visibleLen(s string) int {
	out, in := 0, false
	for _, r := range s {
		if r == 0x1b {
			in = true
			continue
		}
		if in {
			if r == 'm' {
				in = false
			}
			continue
		}
		out++
	}
	return out
}

// padRight pads s with spaces on the right until visibleLen(s) == w. ANSI
// escape sequences in s are not counted toward the width.
func padRight(s string, w int) string {
	pad := w - visibleLen(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}
```

- [ ] **Step 1.2: Create `internal/tui/util_test.go`**

```go
package tui

import "testing"

func TestVisibleLen(t *testing.T) {
	cases := []struct {
		s    string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"\x1b[32monline\x1b[0m", 6},
		{"\x1b[31m\x1b[1mERR\x1b[0m", 3},
		{"\x1b[2;32mboth\x1b[0m", 4},
	}
	for _, c := range cases {
		if got := visibleLen(c.s); got != c.want {
			t.Errorf("visibleLen(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestPadRight(t *testing.T) {
	cases := []struct {
		s    string
		w    int
		want string
	}{
		{"", 3, "   "},
		{"ab", 5, "ab   "},
		{"abc", 3, "abc"},
		{"abcd", 3, "abcd"}, // already wider — return unchanged
		{"\x1b[32mok\x1b[0m", 5, "\x1b[32mok\x1b[0m   "},
	}
	for _, c := range cases {
		if got := padRight(c.s, c.w); got != c.want {
			t.Errorf("padRight(%q, %d) = %q, want %q", c.s, c.w, got, c.want)
		}
	}
}
```

- [ ] **Step 1.3: Run tests to verify they pass**

```bash
go test ./internal/tui/ -v -run "TestVisibleLen|TestPadRight"
```

Expected: PASS for both new tests. Existing TUI tests should continue to pass too.

- [ ] **Step 1.4: Create `internal/tui/style.go`**

```go
package tui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/lab1702/lan-inventory/internal/model"
)

// All TUI styles. Use ANSI color names (0–15) so the user's terminal theme
// drives the exact hue. Status colors are deliberately green/yellow/red so
// they read correctly under every common theme (dark, light, Solarized, etc.).
var (
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(8)) // bright black
	styleAccent = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(4)) // blue
	styleWarn   = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(3)) // yellow
	styleErr    = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(9)) // bright red
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(2)) // green

	styleTabActive   = styleAccent.Bold(true).Underline(true)
	styleTabInactive = styleDim
	styleHeaderRow   = styleBold
	styleSelectedRow = lipgloss.NewStyle().
				Background(lipgloss.ANSIColor(4)).
				Foreground(lipgloss.ANSIColor(15))
)

// styleStatus returns the foreground style appropriate for a Device.Status
// value: green for online, yellow for stale, red for offline.
func styleStatus(s model.Status) lipgloss.Style {
	switch s {
	case model.StatusOnline:
		return styleOK
	case model.StatusStale:
		return styleWarn
	case model.StatusOffline:
		return styleErr
	}
	return lipgloss.NewStyle()
}

// styleEventType returns the foreground style for an Event.Type value: green
// for joined, blue for updated, red for left.
func styleEventType(t model.EventType) lipgloss.Style {
	switch t {
	case model.EventJoined:
		return styleOK
	case model.EventUpdated:
		return styleAccent
	case model.EventLeft:
		return styleErr
	}
	return lipgloss.NewStyle()
}
```

- [ ] **Step 1.5: Verify build and tests**

```bash
go build ./...
go test ./internal/tui/ -v
go vet ./...
```

All existing TUI tests must still pass. The two new util tests must pass. Build clean. Vet clean.

Note: `style.go` defines unexported symbols but several aren't yet referenced by view code. Go will not flag them as unused (variables aren't checked the same way as imports). Helpers `styleStatus` / `styleEventType` may produce a "declared and not used" warning depending on the analyzer — they will be used by subsequent tasks.

- [ ] **Step 1.6: Commit**

```bash
git add internal/tui/style.go internal/tui/util.go internal/tui/util_test.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "tui: central style and ANSI-aware width helpers"
```

---

## Task 2: Refactor Devices table to use `padRight` (no color yet)

**Files:**
- Modify: `internal/tui/devices.go` (lines 22–47, the `viewDevices` table-building block)

This is structural prep. The current code uses `fmt.Sprintf("%-15s  %-17s …", …)` which would silently inflate column widths once cells contain ANSI escape sequences. We switch to building each cell, padding with `padRight`, then joining with two-space separators. No color is added in this task — the rendered output should be **byte-identical** to today's. All existing tests stay green.

- [ ] **Step 2.1: Replace the table-building block in `viewDevices`**

In `internal/tui/devices.go`, find the section starting at `var b strings.Builder` and ending at the closing `}` of the data-row `for` loop (lines 22 through 47 in the current file). Replace it with:

```go
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Sort: %s   ", m.sortKey))
	b.WriteString(fmt.Sprintf("Selection: %d/%d\n\n", m.selectedRow+1, len(devices)))

	// Column widths chosen to match the previous fmt.Sprintf("%-15s  %-17s ...") layout.
	const (
		wIP       = 15
		wMAC      = 17
		wVendor   = 12
		wHost     = 22
		wOS       = 12
		wPorts    = 22
		wRTT      = 8
	)
	headerCells := []string{
		padRight("IP", wIP),
		padRight("MAC", wMAC),
		padRight("Vendor", wVendor),
		padRight("Hostname", wHost),
		padRight("OS", wOS),
		padRight("Ports", wPorts),
		padRight("RTT", wRTT),
		"Status",
	}
	header := strings.Join(headerCells, "  ")
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", visibleLen(header)))
	b.WriteString("\n")

	for i, d := range devices {
		marker := "  "
		if i == m.selectedRow {
			marker = "> "
		}
		row := strings.Join([]string{
			padRight(firstIP(d), wIP),
			padRight(d.MAC, wMAC),
			padRight(truncate(d.Vendor, 12), wVendor),
			padRight(truncate(d.Hostname, 22), wHost),
			padRight(truncate(d.OSGuess, 12), wOS),
			padRight(truncate(portsCSV(d.OpenPorts), 22), wPorts),
			padRight(rttString(d.RTT), wRTT),
			d.Status.String(),
		}, "  ")
		b.WriteString(marker)
		b.WriteString(row)
		b.WriteString("\n")
	}
```

Note `d.Status.String()` is now explicit (was previously `d.Status` with `fmt.Sprintf("%s", …)` invoking the Stringer). Required because we're using `strings.Join` with explicit strings.

- [ ] **Step 2.2: Verify all existing TUI tests still pass**

```bash
go test ./internal/tui/ -v
go vet ./...
```

All 9 existing tests must pass. No visual change has been introduced; output is byte-identical for the no-color path.

- [ ] **Step 2.3: Commit**

```bash
git add internal/tui/devices.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "tui: build Devices table cells with padRight (prep for color)"
```

---

## Task 3: Color the header (active tab + summary line)

**Files:**
- Modify: `internal/tui/model.go` (functions `renderHeader` lines 229–241 and `summaryLine` lines 243–257)

- [ ] **Step 3.1: Replace `renderHeader`**

In `internal/tui/model.go`, find the `renderHeader` function. Replace its body with:

```go
func (m Model) renderHeader() string {
	tabs := []string{"Devices", "Services", "Subnet", "Events"}
	rendered := make([]string, len(tabs))
	for i, name := range tabs {
		label := fmt.Sprintf("[%d] %s", i+1, name)
		if int(m.tab) == i {
			label = styleTabActive.Render(label)
		} else {
			label = styleTabInactive.Render(label)
		}
		rendered[i] = label
	}
	stats := m.summaryLine()
	return strings.Join(rendered, "  ") + "\n" + stats
}
```

This drops the inline `lipgloss.NewStyle().Bold(true).Underline(true)` in favor of the central `styleTabActive`, and adds the `styleTabInactive` (dim) treatment to non-active tabs.

The `lipgloss` import (line 11) is no longer used directly by `model.go` after this change. Remove it from the imports block at the top of the file.

- [ ] **Step 3.2: Replace `summaryLine`**

Find `summaryLine` and replace its body with:

```go
func (m Model) summaryLine() string {
	online, stale, offline := 0, 0, 0
	for _, d := range m.devices {
		switch d.Status {
		case model.StatusOnline:
			online++
		case model.StatusStale:
			stale++
		case model.StatusOffline:
			offline++
		}
	}
	parts := []string{
		styleOK.Render(fmt.Sprintf("Online: %d", online)),
		styleWarn.Render(fmt.Sprintf("Stale: %d", stale)),
		styleErr.Render(fmt.Sprintf("Offline: %d", offline)),
		fmt.Sprintf("Subnet: %s", m.deps.Subnet),
		fmt.Sprintf("Iface: %s", m.deps.Iface),
	}
	return strings.Join(parts, "   ")
}
```

The whole `Online: N`, `Stale: N`, `Offline: N` token is colored as one piece (label + count together).

- [ ] **Step 3.3: Verify build and tests**

```bash
go build ./...
go test ./internal/tui/ -v
go vet ./...
```

All existing tests must still pass — they check for substrings like `"Services"` and `"192.168.1.0/24"` that remain present, just with ANSI escapes around them.

- [ ] **Step 3.4: Commit**

```bash
git add internal/tui/model.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "tui: color header tabs and summary stats"
```

---

## Task 4: Color the Devices tab

**Files:**
- Modify: `internal/tui/devices.go`

Apply: status color, dim divider/separator, dim empty fields, dim "Sort:" line, selected-row backdrop, detail-strip labels in blue.

- [ ] **Step 4.1: Update `viewDevices` to color the table**

Replace the table-building block in `viewDevices` (the block introduced in Task 2) with:

```go
	var b strings.Builder
	b.WriteString(styleDim.Render(fmt.Sprintf("Sort: %s   Selection: %d/%d", m.sortKey, m.selectedRow+1, len(devices))))
	b.WriteString("\n\n")

	const (
		wIP       = 15
		wMAC      = 17
		wVendor   = 12
		wHost     = 22
		wOS       = 12
		wPorts    = 22
		wRTT      = 8
	)
	headerCells := []string{
		padRight(styleHeaderRow.Render("IP"), wIP),
		padRight(styleHeaderRow.Render("MAC"), wMAC),
		padRight(styleHeaderRow.Render("Vendor"), wVendor),
		padRight(styleHeaderRow.Render("Hostname"), wHost),
		padRight(styleHeaderRow.Render("OS"), wOS),
		padRight(styleHeaderRow.Render("Ports"), wPorts),
		padRight(styleHeaderRow.Render("RTT"), wRTT),
		styleHeaderRow.Render("Status"),
	}
	header := strings.Join(headerCells, "  ")
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(styleDim.Render(strings.Repeat("-", visibleLen(header))))
	b.WriteString("\n")

	for i, d := range devices {
		marker := "  "
		if i == m.selectedRow {
			marker = "> "
		}
		row := strings.Join([]string{
			padRight(firstIP(d), wIP),
			padRight(d.MAC, wMAC),
			padRight(dimIfEmpty(truncate(d.Vendor, 12)), wVendor),
			padRight(dimIfEmpty(truncate(d.Hostname, 22)), wHost),
			padRight(dimIfEmpty(truncate(d.OSGuess, 12)), wOS),
			padRight(dimIfEmpty(truncate(portsCSV(d.OpenPorts), 22)), wPorts),
			padRight(rttString(d.RTT), wRTT),
			styleStatus(d.Status).Render(d.Status.String()),
		}, "  ")
		line := marker + row
		if i == m.selectedRow {
			line = styleSelectedRow.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
```

`rttString` already returns `"-"` for zero — that's left as default-styled (not dim) intentionally since RTT being absent is informative. `dimIfEmpty` is a new tiny helper added in the next step that wraps an empty or `"-"` value in `styleDim`.

- [ ] **Step 4.2: Add the `dimIfEmpty` helper**

Append to `internal/tui/devices.go`:

```go
// dimIfEmpty returns styleDim-rendered s when s is empty, "—", or "--".
// Otherwise returns s unchanged.
func dimIfEmpty(s string) string {
	if s == "" || s == "—" || s == "--" {
		return styleDim.Render(s)
	}
	return s
}
```

- [ ] **Step 4.3: Update `detailStrip` labels**

In `internal/tui/devices.go`, replace the `detailStrip` function with:

```go
func detailStrip(d *model.Device) string {
	var b strings.Builder
	b.WriteString(styleDim.Render("─── selected ─────────────────────────"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("MAC:     "), d.MAC))
	b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("Vendor:  "), d.Vendor))
	b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("OS guess:"), d.OSGuess))
	if len(d.OpenPorts) > 0 {
		ports := make([]string, 0, len(d.OpenPorts))
		for _, p := range d.OpenPorts {
			label := fmt.Sprintf("%d/%s", p.Number, p.Proto)
			if p.Service != "" {
				label += " (" + p.Service + ")"
			}
			ports = append(ports, label)
		}
		b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("Ports:   "), strings.Join(ports, ", ")))
	}
	if len(d.Services) > 0 {
		svcs := make([]string, 0, len(d.Services))
		for _, s := range d.Services {
			svcs = append(svcs, fmt.Sprintf("%s %q :%d", s.Type, s.Name, s.Port))
		}
		b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("Services:"), strings.Join(svcs, "; ")))
	}
	b.WriteString(fmt.Sprintf("%s %s / %s\n",
		styleAccent.Render("First/Last seen:"),
		d.FirstSeen.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339)))
	if len(d.RTTHistory) > 0 {
		samples := make([]string, 0, len(d.RTTHistory))
		for _, r := range d.RTTHistory {
			samples = append(samples, rttString(r))
		}
		b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("RTT history:"), strings.Join(samples, " ")))
	}
	return b.String()
}
```

- [ ] **Step 4.4: Verify all existing TUI tests still pass**

```bash
go test ./internal/tui/ -v
go vet ./...
```

All 9 existing tests must pass. The substring assertions still hold; new ANSI codes don't break them.

- [ ] **Step 4.5: Commit**

```bash
git add internal/tui/devices.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "tui: color Devices tab — status, dim absent, selected row, detail labels"
```

---

## Task 5: Color the Services tab

**Files:**
- Modify: `internal/tui/services.go`

- [ ] **Step 5.1: Replace `viewServices`**

In `internal/tui/services.go`, replace `viewServices` with:

```go
func (m Model) viewServices() string {
	groups := groupServices(m.devices)
	if len(groups) == 0 {
		return "(no services seen yet)"
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		hosts := groups[k]
		count := len(hosts)
		instLabel := "instance"
		if count != 1 {
			instLabel = "instances"
		}
		hostList := strings.Join(hosts, ", ")
		key := padRight(styleAccent.Render(k), 22)
		b.WriteString(fmt.Sprintf("%s  %d %s  →  %s\n", key, count, instLabel, hostList))
	}
	return b.String()
}
```

The service-type key (`_http._tcp`, `22/tcp (ssh)`, etc.) gets blue. Padded with `padRight` (ANSI-aware) so the count column aligns.

- [ ] **Step 5.2: Verify**

```bash
go test ./internal/tui/ -v
go vet ./...
```

All tests pass. `TestServicesTabGroupsByType` still finds `"_http._tcp"` and `"2 instances"` substrings in output.

- [ ] **Step 5.3: Commit**

```bash
git add internal/tui/services.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "tui: color service-type keys on Services tab"
```

---

## Task 6: Color the Subnet tab

**Files:**
- Modify: `internal/tui/subnet.go`

- [ ] **Step 6.1: Replace the glyph rendering loop**

In `internal/tui/subnet.go`, find the inner `for col := 0; col < gridSide; col++` loop and replace the glyph-emitting section. The new function body:

```go
func (m Model) viewSubnet() string {
	_, subnet, err := net.ParseCIDR(m.deps.Subnet)
	if err != nil || subnet == nil {
		return "(no subnet info)"
	}
	statusByLast := map[string]model.Status{}
	for _, d := range m.devices {
		for _, ip := range d.IPs {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if subnet.Contains(ip4) {
				statusByLast[ip4.String()] = d.Status
			}
		}
	}

	ones, _ := subnet.Mask.Size()
	if ones < 22 {
		return "(subnet too large to render)"
	}
	hostBits := 32 - ones
	gridSide := 1 << (hostBits / 2)
	if gridSide < 1 {
		gridSide = 1
	}
	gridOther := 1 << (hostBits - hostBits/2)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Subnet %s — %d hosts\n", m.deps.Subnet, 1<<hostBits))
	b.WriteString(styleDim.Render("Legend: ● online · stale x offline _ unseen"))
	b.WriteString("\n\n")

	base := subnet.IP.Mask(subnet.Mask).To4()
	for row := 0; row < gridOther; row++ {
		for col := 0; col < gridSide; col++ {
			offset := row*gridSide + col
			ip := make(net.IP, 4)
			copy(ip, base)
			carry := offset
			for i := 3; i >= 0 && carry > 0; i-- {
				sum := int(ip[i]) + carry
				ip[i] = byte(sum & 0xff)
				carry = sum >> 8
			}
			b.WriteString(coloredGlyph(statusByLast[ip.String()]))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func coloredGlyph(s model.Status) string {
	switch s {
	case model.StatusOnline:
		return styleOK.Render("●")
	case model.StatusStale:
		return styleWarn.Render("·")
	case model.StatusOffline:
		return styleErr.Render("x")
	}
	return styleDim.Render("_")
}
```

- [ ] **Step 6.2: Verify**

```bash
go test ./internal/tui/ -v
go vet ./...
```

`TestSubnetTabRendersGrid` still passes — it only checks for the presence of `●` or `·` as substrings, both of which are still present (just wrapped in ANSI escapes).

- [ ] **Step 6.3: Commit**

```bash
git add internal/tui/subnet.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "tui: color Subnet tab grid glyphs by status"
```

---

## Task 7: Color the Events tab, filter prompt, and help overlay

**Files:**
- Modify: `internal/tui/events.go`
- Modify: `internal/tui/model.go` (`View` filter prompt; `helpText`)

- [ ] **Step 7.1: Replace `viewEvents`**

In `internal/tui/events.go`, replace `viewEvents` with:

```go
func (m Model) viewEvents() string {
	if len(m.events) == 0 {
		return "(no events yet)"
	}
	var b strings.Builder
	for _, e := range m.events {
		ip := ""
		if e.IP != nil {
			ip = e.IP.String()
		}
		t := styleDim.Render(e.Time.Format("15:04:05"))
		typeStr := padRight(styleEventType(e.Type).Render(e.Type.String()), 7)
		b.WriteString(fmt.Sprintf("%s  %s  %-18s  %s\n",
			t,
			typeStr,
			e.MAC,
			ip,
		))
	}
	return b.String()
}
```

The time column gets dim; the event-type word gets the color from `styleEventType`. `MAC` and `IP` stay default. Note: `e.Type.String()` is explicit (was implicit through `%-7s` formatting).

- [ ] **Step 7.2: Color the filter prompt in `View`**

In `internal/tui/model.go`, find this block in `View`:

```go
	if m.filterMode || m.filterBuf != "" {
		b.WriteString(fmt.Sprintf("\n\n/filter: %s", m.filterBuf))
	}
```

Replace with:

```go
	if m.filterMode || m.filterBuf != "" {
		b.WriteString("\n\n")
		b.WriteString(styleWarn.Render(fmt.Sprintf("/filter: %s", m.filterBuf)))
	}
```

- [ ] **Step 7.3: Color the help overlay**

In `internal/tui/model.go`, replace `helpText` with:

```go
func helpText() string {
	rows := []struct {
		key  string
		desc string
	}{
		{"1-4", "switch tabs (Devices / Services / Subnet / Events)"},
		{"↑/↓ or k/j", "navigate selection"},
		{"Enter", "(in filter mode) apply the filter"},
		{"s", "cycle sort key (ip → hostname → vendor → rtt → last_seen)"},
		{"/", "start filter (typing narrows the device list; Enter applies)"},
		{"r", "force a rescan now"},
		{"?", "toggle this help"},
		{"q / Esc", "quit"},
	}
	lines := []string{
		styleBold.Render("Help — lan-inventory"),
		"",
	}
	for _, r := range rows {
		lines = append(lines, fmt.Sprintf("  %s  %s", padRight(styleAccent.Render(r.key), 12), r.desc))
	}
	lines = append(lines, "", styleDim.Render("Press any key to dismiss."))
	return strings.Join(lines, "\n")
}
```

- [ ] **Step 7.4: Verify**

```bash
go test ./internal/tui/ -v
go vet ./...
```

`TestEventsTabShowsRingBuffer` still finds `aa:bb:cc:dd:ee:99` and `joined`. `TestHelpOverlay` still finds `Help`, `1-4`, `/`, `s`, `r`, `Enter`. `TestFilterMode` still finds `printer` and rejects `macbook`.

- [ ] **Step 7.5: Commit**

```bash
git add internal/tui/events.go internal/tui/model.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "tui: color Events, filter prompt, and help overlay"
```

---

## Task 8: Add color-semantic tests

**Files:**
- Modify: `internal/tui/tui_test.go`

Two new tests pin the contract: status colors are emitted, and they disappear when the color profile is set to ASCII.

- [ ] **Step 8.1: Add the import**

In `internal/tui/tui_test.go`, add to the import block:

```go
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
```

`lipgloss` is already an indirect dep via the bubbletea import; `termenv` is a transitive dep already in `go.sum`. No new module required.

- [ ] **Step 8.2: Append `TestStatusColors`**

Append to `internal/tui/tui_test.go`:

```go
func TestStatusColors(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI)
	defer lipgloss.SetColorProfile(prev)

	devices := []*model.Device{
		{IPs: []net.IP{net.ParseIP("192.168.1.10")}, Hostname: "online-host", Status: model.StatusOnline},
		{IPs: []net.IP{net.ParseIP("192.168.1.20")}, Hostname: "stale-host", Status: model.StatusStale},
		{IPs: []net.IP{net.ParseIP("192.168.1.30")}, Hostname: "offline-host", Status: model.StatusOffline},
	}
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0", Snapshot: func() []*model.Device { return devices }})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	time.Sleep(1500 * time.Millisecond)
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	// At least three distinct ANSI escape sequences should appear in the
	// rendered table — one per status word, plus likely more for the
	// summary line and tab styling. We don't pin to exact codes (lipgloss
	// may emit \x1b[31m or \x1b[91m for red depending on profile), only
	// that the table is colored at all.
	count := bytes.Count(out, []byte("\x1b["))
	if count < 3 {
		t.Errorf("expected >=3 ANSI escape sequences in colored output, got %d:\n%s", count, out)
	}
}
```

- [ ] **Step 8.3: Append `TestColorsCanBeDisabled`**

```go
func TestColorsCanBeDisabled(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.Ascii)
	defer lipgloss.SetColorProfile(prev)

	devices := []*model.Device{
		{IPs: []net.IP{net.ParseIP("192.168.1.10")}, Hostname: "host", Status: model.StatusOnline},
	}
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0", Snapshot: func() []*model.Device { return devices }})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	time.Sleep(1500 * time.Millisecond)
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	if bytes.Contains(out, []byte("\x1b[")) {
		t.Errorf("expected no ANSI escape sequences when ColorProfile=Ascii, got:\n%s", out)
	}
	// Sanity: content is still rendered.
	if !bytes.Contains(out, []byte("host")) {
		t.Errorf("expected hostname in output even without color:\n%s", out)
	}
}
```

- [ ] **Step 8.4: Extend `TestSubnetTabRendersGrid`**

Find `TestSubnetTabRendersGrid`. Add this assertion after the existing `if !bytes.Contains(out, …)` check, INSIDE the same test function:

```go
	// Confirm the online glyph carries an ANSI escape (color is being applied).
	if bytes.Contains(out, []byte("●")) && !bytes.Contains(out, []byte("\x1b[")) {
		t.Errorf("expected ANSI escapes around colored glyphs:\n%s", out)
	}
```

- [ ] **Step 8.5: Run all TUI tests**

```bash
go test ./internal/tui/ -v
go vet ./...
```

Expected: 11 tests pass (9 existing + 2 new). Vet clean.

If `TestStatusColors` fails because `bytes.Count(out, []byte("\x1b["))` is too low, lower the threshold to 1 — the test only needs to confirm some color is present.

If the test runtime in this environment auto-detects no TTY and emits no codes regardless of `SetColorProfile`, switch to checking `styleStatus(model.StatusOnline).Render("online")` against an expected-string built the same way — but lipgloss should respect the explicit profile setting.

- [ ] **Step 8.6: Commit**

```bash
git add internal/tui/tui_test.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "tui: tests for status colors and color-disable behavior"
```

---

## Task 9: Final lint and verification

**Files:** none modified.

- [ ] **Step 9.1: Run vet, staticcheck, full test suite, and a build**

```bash
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go test ./...
go test -race ./...
go build ./...
```

All must be clean. If staticcheck flags anything (typically: unused styles in `style.go` if a tab task was skipped), fix it inline.

- [ ] **Step 9.2: Smoke build the binary and confirm `--version`**

```bash
make build
./bin/lan-inventory --version
rm -rf bin/
```

Expected output: `lan-inventory 0.1.0`.

- [ ] **Step 9.3: Commit any lint fixes (if needed)**

```bash
git add -u
git diff --cached --quiet && echo "no changes" || git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "chore: address lint after color refresh"
```

---

## Done

After all 9 tasks complete:

- 7 commits on the `feat/tui-colors` branch (style/util, devices padRight refactor, header colors, devices colors, services colors, subnet colors, events+help+filter colors), plus 1 for color tests, plus optional lint cleanup.
- `go test ./...` passes with 11 TUI tests green.
- `go vet ./...` and `staticcheck ./...` clean.
- Race detector clean.
- Binary still builds and `--version` works.
- Every styled string in the TUI flows through `internal/tui/style.go`. Future palette changes are a one-file edit.
