# Full OUI Vendor Database — Design

**Status:** Approved  •  **Date:** 2026-04-26

A focused refinement on top of the v0.1.0 + color-refresh tree. The current
`internal/oui/manuf.txt` ships 10 seed entries that were never meant for real
use; consequently most devices on a real home LAN show an empty Vendor column.
This change replaces the seed with the full Wireshark manuf database (filtered
to entries our 24-bit-prefix lookup can match), adds a `manuf-refresh` Make
target so the data can be updated on demand, and ships the upstream license
alongside the data.

## Goals and non-goals

**Goals**

- Vendor column is populated for the vast majority of real-world devices on a typical home LAN (Apple, Samsung, Espressif, Raspberry Pi, etc. — all the major manufacturers covered).
- The refresh process is one Make command and produces a deterministic, committed file.
- License attribution shipped alongside the data.
- Embedded file size kept reasonable: ~2 MB after filtering (down from 3 MB raw).
- Defense-in-depth: parser tolerates a hand-edited or raw-upstream manuf without producing nonsense matches.

**Non-goals**

- Not auto-refreshing on a schedule. The refresh is manual and explicit.
- Not supporting 28-bit or 36-bit sub-OUI ranges. Our lookup matches on the first 24 bits (`mac[:8]`) only; finer-grained ranges are filtered out at refresh time.
- Not changing the lookup API. `oui.Lookup(mac string) string` keeps the same signature.
- Not switching to a binary embedded format. Plain text stays — easy to inspect, diff, and hand-edit if needed.
- Not vendoring an existing OUI library. The current 30-line parser is enough.

## Source data

Upstream: `https://www.wireshark.org/download/automated/data/manuf`

Format (one entry per line, tab-separated):

```
OO:UU:II<TAB>ShortName<TAB>Long Vendor Name
```

Plus comment lines (start with `#`) and blank lines. The full upstream file
(~3 MB) also contains 28-bit and 36-bit sub-OUI ranges for cases where a
24-bit OUI is split among smaller vendors:

```
00:1B:C5:00:0/28<TAB>ShortName<TAB>Long Name
00:55:DA:0E:0/36<TAB>ShortName<TAB>Long Name
```

These are 6,359 (/28) + 11,550 (/36) lines as of the snapshot. The lookup
keys on `mac[:8]` (first three octets) so finer-grained ranges can never
match — they would be dead data in the in-memory map. Filtered out at
refresh time.

## Files touched

| Path                       | Change | Purpose                                                          |
|----------------------------|--------|------------------------------------------------------------------|
| `Makefile`                 | Modify | Add `manuf-refresh` target.                                       |
| `internal/oui/oui.go`      | Modify | Skip lines whose prefix column contains `/` (defense-in-depth). |
| `internal/oui/manuf.txt`   | Replace | Seed 10 → ~38k 24-bit OUI lines.                                 |
| `internal/oui/MANUF-LICENSE` | Add  | Upstream Wireshark license (GPL-2) for the manuf data.           |
| `README.md`                | Modify | One-line note in Development section.                             |

No new dependencies. No new packages.

## `manuf-refresh` Make target

```make
manuf-refresh:
	@echo "Fetching Wireshark manuf database..."
	@curl -sSfL https://www.wireshark.org/download/automated/data/manuf -o /tmp/manuf.raw
	@echo "Filtering to 24-bit OUI entries..."
	@grep -v '^#' /tmp/manuf.raw | grep -v '^$$' | grep -v '/' > internal/oui/manuf.txt
	@rm -f /tmp/manuf.raw
	@wc -l internal/oui/manuf.txt
	@echo "Done. Review the diff and commit if it looks right."
```

Behavior:

- `curl -sSfL`: silent on success, errors loudly on HTTP failure (no silent corruption).
- Three `grep -v` filters: comments (`^#`), blank lines (`^$`), and any `/`-prefixed sub-OUI line.
- Final `wc -l` gives a quick sanity number for the diff review.
- Printed reminder tells the user to review and commit manually.
- Add to `.PHONY` declaration.

The refresh is not run automatically by any other target. `make build`,
`make test`, and CI all continue to use the committed `manuf.txt` as the
source of truth.

## Parser tweak

In `internal/oui/oui.go`'s `loadTable`, after splitting on tabs and reading
the prefix:

```go
prefix := strings.ToUpper(strings.TrimSpace(parts[0]))
if strings.Contains(prefix, "/") {
    continue
}
short := strings.TrimSpace(parts[1])
```

The existing `len(prefix) < 8` guard at the lookup site (`oui.Lookup`) would
already prevent these entries from matching — they would just sit in the map
unused. The new guard is purely defensive: keeps the map clean if a future
manual edit or upstream paste reintroduces /-prefixed lines.

## License attribution

`internal/oui/MANUF-LICENSE` ships the upstream Wireshark license verbatim. The file is sourced from `https://gitlab.com/wireshark/wireshark/-/raw/master/COPYING` (Wireshark is dual-licensed; GPL-2 covers the bundled manuf data). It is added once during initial implementation and only updated when Wireshark itself changes its top-level license — rare enough that it doesn't need automation.

The `oui.go` package doc comment gains one line:

```go
// Package oui resolves a MAC address to a vendor short-name using an
// embedded copy of Wireshark's manuf database (or a trimmed equivalent).
//
// The bundled manuf.txt and its license (MANUF-LICENSE) are fetched from
// https://www.wireshark.org/download/automated/data/manuf via `make manuf-refresh`.
package oui
```

## Testing strategy

**No new test code.** The parser tweak is a one-line `if` guard. The existing
`TestLookupKnown` and `TestLookupUnknown` cover the lookup behavior. After
swapping in the full manuf.txt:

- `TestLookupKnown` continues to pass (the seed-list MACs are still in the
  full database — Apple, Raspberry Pi, TP-Link, etc.).
- If the parser silently broke under the new file (e.g., dropping all
  ~38k entries), `TestLookupKnown` would fail spectacularly because
  `Lookup("00:1b:63:aa:bb:cc")` would return `""` instead of `"Apple"`.

Manual verification after refresh:

```bash
make manuf-refresh
go test ./internal/oui/ -v
```

Both must stay green. CI runs the same commands.

## Out of scope (non-goals reaffirmed)

- Auto-refresh / scheduled CI updates of manuf.txt.
- 28-bit and 36-bit OUI granularity.
- Switch to a binary embedded format for size reduction.
- Vendor library replacement.

## Risks and mitigations

- **Upstream URL changes.** If wireshark.org moves the file, `make manuf-refresh` fails loudly via `curl -f`. Mitigation: documented URL in the spec; recovery is updating the Make target and re-running.
- **License re-licensing upstream.** Wireshark's licensing is stable but if it changed, our shipped `MANUF-LICENSE` would drift from upstream. Mitigation: refresh process should update both the data and the license file together. The Make target can be extended later to also fetch the license.
- **Binary size growth.** `bin/lan-inventory` grows from ~10 MB to ~12 MB. Acceptable for v0.1.x.

## Implementation phases

1. Add `manuf-refresh` Make target and run it once to populate the new manuf.txt.
2. Add the parser guard in `oui.go`.
3. Add `MANUF-LICENSE` (curl from `https://gitlab.com/wireshark/wireshark/-/raw/master/COPYING`).
4. Update package doc comment.
5. Update README.
6. Verify all tests, vet, staticcheck, build.

Single feature branch, ~6 small commits.
