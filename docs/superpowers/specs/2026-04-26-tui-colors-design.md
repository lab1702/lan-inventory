# TUI Color Refresh — Design

**Status:** Approved  •  **Date:** 2026-04-26

A focused refinement on top of v0.1.0. The TUI today renders entirely in
default text plus bold/underline on the active tab. This change introduces
purposeful color throughout the four tabs, the header, and the help/filter
overlays, plus a centralized style module so future palette work is a
one-file edit.

## Goals and non-goals

**Goals**

- Color carries information — status, freshness, severity — never decoration.
- Adapt to the user's terminal theme (light/dark, Solarized, Gruvbox, etc.) by using ANSI named colors rather than hex codes.
- Centralize every styled string in `internal/tui/style.go` so palette changes are one-file.
- Preserve all existing tests; add focused color-semantic tests.
- Graceful degradation when stdout is not a TTY (no ANSI escapes leak).

**Non-goals**

- Not introducing a custom theming system or user-configurable palettes.
- Not changing layout, key bindings, or any data flow.
- Not adding a golden-file regression suite for visual diffs.
- Not changing `internal/snapshot/snapshot.go` (`--once --table` keeps its own
  ANSI helper). Avoiding cross-package coupling for a mild DRY win.

## Color philosophy

Three rules govern every color decision:

1. **Color carries information.** If two cells differ only by color, the color must mean something the user can name (status, freshness, severity).
2. **Dim equals absent.** Empty fields, unseen cells, divider lines, and secondary metadata use ANSI bright-black (8) so the eye glides past them.
3. **At most three semantic colors per screen.** Green (good), yellow (warning), red (bad). Plus blue/cyan as neutral accents for headings and selection. No rainbow.

ANSI named-color choice (lipgloss `ANSIColor(n)`):

| Role        | ANSI | Notes                                |
|-------------|------|--------------------------------------|
| OK / good   | 2    | green                                |
| Warning     | 3    | yellow                               |
| Error / bad | 9    | bright red                           |
| Accent      | 4    | blue (selection bg, key labels)      |
| Info        | 6    | cyan (reserved for future use)       |
| Dim         | 8    | bright black (separators, absent)    |
| Highlight   | 15   | bright white (selection text only)   |

## What gets colored, per screen

**Header (all tabs).**
- Active tab number+label: blue + bold + underline.
- Inactive tabs: dim.
- Summary stats: count values colored to match — green "Online: 28", yellow "Stale: 2", red "Offline: 1". Subnet/Iface labels remain default text.

**Devices tab.**
- Status column: green (online) / yellow (stale) / red (offline).
- Selected row: blue background + bright-white text. Leading `>` marker retained for non-color terminals.
- Header row: bold (no foreground color).
- Divider line: dim.
- Empty fields (`--`, `—`): dim.
- "Sort: ip   Selection: 1/N" line: dim.
- Detail-strip labels (`MAC:`, `Vendor:`, `OS guess:`, etc.): blue.

**Services tab.**
- Service-type key (`_http._tcp`, `22/tcp (ssh)`): blue.
- Instance count and host list: default text. Dim a single-host entry to the count's right.

**Subnet tab.**
- Glyphs themselves take ANSI colors:
  - ● green (online)
  - · yellow (stale)
  - x red (offline)
  - `_` dim (unseen)
- Header line ("Subnet ... — N hosts"): default. Legend line: dim.
- This is the screen with the highest information density payoff for color.

**Events tab.**
- Time column: dim.
- Event type: green (joined), blue (updated), red (left).
- MAC and IP: default.

**Filter prompt (`/filter: foo`):** yellow, so it stands out against the table.

**Help overlay.**
- Title bold.
- Key bindings (the leftmost token on each row): blue.
- Descriptions: default.
- "Press any key to dismiss" line: dim.

## Code structure

### New file: `internal/tui/style.go`

Owns every styled string in the TUI. View files consume helpers from here; no
view file calls `lipgloss.NewStyle()` directly.

```go
package tui

import (
    "github.com/charmbracelet/lipgloss"
    "github.com/lab1702/lan-inventory/internal/model"
)

var (
    styleBold   = lipgloss.NewStyle().Bold(true)
    styleDim    = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(8))
    styleAccent = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(4))
    styleWarn   = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(3))
    styleErr    = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(9))
    styleOK     = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(2))

    styleTabActive   = styleAccent.Bold(true).Underline(true)
    styleTabInactive = styleDim
    styleHeaderRow   = styleBold
    styleSelectedRow = lipgloss.NewStyle().
        Background(lipgloss.ANSIColor(4)).
        Foreground(lipgloss.ANSIColor(15))
)

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

### Column-width handling

Lipgloss-rendered strings include ANSI escape sequences, so `len(s)` is wrong
for table padding. The TUI's existing `viewDevices` uses `fmt.Sprintf("%-15s",
…)` which silently inflates colored cells. Two helpers move into a new file
`internal/tui/util.go` (mirroring the ones already in `internal/snapshot`):

```go
package tui

import "strings"

func visibleLen(s string) int {
    out, in := 0, false
    for _, r := range s {
        if r == 0x1b { in = true; continue }
        if in {
            if r == 'm' { in = false }
            continue
        }
        out++
    }
    return out
}

func padRight(s string, w int) string {
    pad := w - visibleLen(s)
    if pad <= 0 { return s }
    return s + strings.Repeat(" ", pad)
}
```

`devices.go` switches from `fmt.Sprintf("%-15s  …", …)` to building rows with
`padRight(styled, width)` segments joined by two-space separators.

### View files touched

- `internal/tui/model.go` — `renderHeader` and `summaryLine` adopt styles.
- `internal/tui/devices.go` — table rows use `padRight`; status, header,
  divider, dim fields all use style helpers; selected row uses
  `styleSelectedRow.Render(rowText)`; detail-strip labels use `styleAccent`.
- `internal/tui/services.go` — service-type key uses `styleAccent`.
- `internal/tui/subnet.go` — each glyph is wrapped in the right style helper
  before being written to the builder.
- `internal/tui/events.go` — time dim, type colored by `styleEventType`.

### Out of scope

- `internal/snapshot/snapshot.go` already has its own `colorStatus` helper
  with hardcoded ANSI escape constants. It stays as-is. The TUI and the
  table renderer keep separate, parallel implementations. Cross-package
  coupling not warranted for one helper.

## Testing strategy

**Existing string-containment tests stay green.** ANSI escape sequences sit
between characters, not inside them, so `bytes.Contains(out, []byte("macbook.local"))`
still works after styling. No existing test needs modification.

**Two new tests in `internal/tui/tui_test.go`:**

1. `TestStatusColors` — render a Devices tab with one online + one stale + one
   offline device. Assert the rendered output contains the expected ANSI
   prefix near each status word:

   ```go
   for _, want := range [][]byte{
       []byte("\x1b[32m"), // green: online
       []byte("\x1b[33m"), // yellow: stale
   } {
       if !bytes.Contains(out, want) {
           t.Errorf("missing %q", want)
       }
   }
   // Red is ANSI 9 (bright red) which lipgloss emits as \x1b[91m
   if !bytes.Contains(out, []byte("\x1b[91m")) {
       t.Errorf("missing red")
   }
   ```

   Implementation may need to adjust the exact codes during impl based on
   what lipgloss actually emits for the chosen color profile. The test runs
   under lipgloss's default ANSI16 profile.

2. `TestColorsCanBeDisabled` — set `lipgloss.SetColorProfile(termenv.Ascii)`
   in test setup, render a device, assert the output contains no `\x1b[`
   escape sequences. Reset the profile in the test's defer.

**Existing `TestSubnetTabRendersGrid`:** add an assertion that the rendered ●
glyph for an Online device is preceded by a green ANSI prefix.

**TTY detection:** Bubble Tea + lipgloss + termenv handle this automatically.
When stdout is not a TTY (e.g., piped), termenv falls back to no color. We
rely on this default and don't add manual TTY checks in the TUI codepath.

## Implementation phases

1. Add `internal/tui/style.go` with all styles and helpers.
2. Add `internal/tui/util.go` with `visibleLen` and `padRight`.
3. Update `internal/tui/model.go` (header + summary).
4. Update `internal/tui/devices.go` (table + selection + detail strip).
5. Update `internal/tui/services.go`.
6. Update `internal/tui/subnet.go`.
7. Update `internal/tui/events.go`.
8. Add `TestStatusColors` and `TestColorsCanBeDisabled`; extend
   `TestSubnetTabRendersGrid` with green-glyph assertion.
9. Verify `go test -race ./...`, `go vet ./...`, `staticcheck ./...` all green.

Each phase is one commit on a feature branch.

## Risks and mitigations

- **lipgloss emits unexpected escape codes for ANSI 9.** Test 1 may need
  adjustment to expect `\x1b[91m` rather than `\x1b[31m`. Cheap to discover
  during implementation.
- **Existing string-containment tests rely on substring matches that span
  styled segments.** None of the current tests appear to do this, but if any
  do, they need to be split. Mitigation: grep the test file before starting.
- **Selected-row blue background may be unreadable on terminals where ANSI 4
  is dark blue and ANSI 15 is off-white.** User explicitly approved this; if
  it becomes an issue in practice, swap to `Reverse(true)` in a follow-up.
