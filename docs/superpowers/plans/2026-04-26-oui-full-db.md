# Full OUI Vendor Database Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 10-entry seed `internal/oui/manuf.txt` with the full Wireshark manuf database (~38k 24-bit OUIs after filtering), add a `manuf-refresh` Make target so the data can be updated on demand, and ship the upstream license alongside the data.

**Architecture:** Pure data + tooling change. The lookup code (`internal/oui/oui.go`) stays the same except for one defensive guard line. The Make target downloads upstream, filters out comments, blank lines, and 28-bit/36-bit sub-OUI ranges (which our 24-bit-prefix lookup can never match), and writes the result to `internal/oui/manuf.txt` for `//go:embed` to pick up at next build.

**Tech Stack:** Go 1.24, `//go:embed`, `curl`, `grep`. No new code dependencies.

**Spec:** `docs/superpowers/specs/2026-04-26-oui-full-db-design.md`

---

## File structure

```
.
├── Makefile                       (MOD)  — add manuf-refresh target
├── README.md                      (MOD)  — note about the refresh target
└── internal/oui/
    ├── oui.go                     (MOD)  — parser guard + doc comment
    ├── manuf.txt                  (REPLACE) — 10 seed → ~38k full DB
    └── MANUF-LICENSE              (NEW)  — Wireshark COPYING (BSD/GPL)
```

**Note on operator workflow:** This plan modifies committed code on master. Implementer should follow `superpowers:using-git-worktrees` to create a `feat/oui-full-db` worktree before starting.

---

## Task 1: Parser guard for /-prefixed lines

**Files:**
- Modify: `internal/oui/oui.go` (one line added inside `loadTable`)

Defense-in-depth: skip any line whose prefix column contains `/` (the marker for 28-bit and 36-bit sub-OUI entries upstream uses). The existing `len(mac) < 8` guard at the lookup site would already prevent these from matching, but the new guard keeps them out of the in-memory map entirely.

- [ ] **Step 1.1: Add the guard inside `loadTable`**

In `internal/oui/oui.go`, find this block in `loadTable`:

```go
		prefix := strings.ToUpper(strings.TrimSpace(parts[0]))
		short := strings.TrimSpace(parts[1])
		if prefix == "" || short == "" {
			continue
		}
		table[prefix] = short
```

Replace with:

```go
		prefix := strings.ToUpper(strings.TrimSpace(parts[0]))
		if strings.Contains(prefix, "/") {
			continue
		}
		short := strings.TrimSpace(parts[1])
		if prefix == "" || short == "" {
			continue
		}
		table[prefix] = short
```

- [ ] **Step 1.2: Verify existing tests still pass**

```bash
go test ./internal/oui/ -v
go vet ./...
```

Both `TestLookupKnown` and `TestLookupUnknown` must pass. Vet clean. The seed manuf.txt has no /-prefixed lines, so this guard fires zero times against the current data — behavior is byte-identical.

- [ ] **Step 1.3: Commit**

```bash
git add internal/oui/oui.go
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "oui: skip /-prefixed sub-OUI lines in loadTable"
```

---

## Task 2: Add `manuf-refresh` Make target

**Files:**
- Modify: `Makefile`

- [ ] **Step 2.1: Update `.PHONY` and append the target**

Replace the entire contents of `Makefile` with:

```make
.PHONY: build test lint vet smoke clean manuf-refresh

build:
	go build -o bin/lan-inventory ./cmd/lan-inventory

test:
	go test ./...

vet:
	go vet ./...

lint:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

smoke: build
	sudo setcap cap_net_raw,cap_net_admin=eip ./bin/lan-inventory
	./bin/lan-inventory --once --table

clean:
	rm -rf bin/

manuf-refresh:
	@echo "Fetching Wireshark manuf database..."
	@curl -sSfL https://www.wireshark.org/download/automated/data/manuf -o /tmp/manuf.raw
	@echo "Filtering to 24-bit OUI entries..."
	@grep -v '^#' /tmp/manuf.raw | grep -v '^$$' | grep -v '/' > internal/oui/manuf.txt
	@rm -f /tmp/manuf.raw
	@wc -l internal/oui/manuf.txt
	@echo "Done. Review the diff and commit if it looks right."
```

NOTE: Makefile uses **TAB** indentation on recipe lines. Verify with `cat -A Makefile | head -20` after writing — recipe-line indentation should appear as `^I`.

- [ ] **Step 2.2: Verify the target syntax (no actual download yet)**

```bash
make -n manuf-refresh
```

Expected output (the `-n` dry-run prints commands without executing):

```
echo "Fetching Wireshark manuf database..."
curl -sSfL https://www.wireshark.org/download/automated/data/manuf -o /tmp/manuf.raw
echo "Filtering to 24-bit OUI entries..."
grep -v '^#' /tmp/manuf.raw | grep -v '^$' | grep -v '/' > internal/oui/manuf.txt
rm -f /tmp/manuf.raw
wc -l internal/oui/manuf.txt
echo "Done. Review the diff and commit if it looks right."
```

(The `@` prefix is for silencing actual execution — `-n` ignores it and prints all commands.)

- [ ] **Step 2.3: Commit**

```bash
git add Makefile
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "make: add manuf-refresh target for OUI database updates"
```

---

## Task 3: Add `MANUF-LICENSE`

**Files:**
- Create: `internal/oui/MANUF-LICENSE`

The bundled manuf data is sourced from Wireshark, which is GPL-2-licensed. Wireshark's top-level `COPYING` file is the upstream license that covers all bundled data including manuf.

- [ ] **Step 3.1: Download the upstream license**

```bash
curl -sSfL https://gitlab.com/wireshark/wireshark/-/raw/master/COPYING -o internal/oui/MANUF-LICENSE
```

- [ ] **Step 3.2: Verify the file is non-empty and looks like a license**

```bash
wc -l internal/oui/MANUF-LICENSE
head -5 internal/oui/MANUF-LICENSE
```

Expected: at least a few hundred lines; first line typically reads something like `Wireshark` or `This file is part of the Wireshark distribution`.

If the file is empty or very small (under 100 lines), the GitLab URL has changed — escalate as BLOCKED rather than committing a placeholder.

- [ ] **Step 3.3: Commit**

```bash
git add internal/oui/MANUF-LICENSE
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "oui: add upstream Wireshark license for bundled manuf data"
```

---

## Task 4: Run refresh and replace `manuf.txt`

**Files:**
- Replace: `internal/oui/manuf.txt`

Execute the new Make target. The output replaces the 10-entry seed with the full filtered database.

- [ ] **Step 4.1: Run the refresh**

```bash
make manuf-refresh
```

Expected output (line counts may drift slightly with upstream updates):

```
Fetching Wireshark manuf database...
Filtering to 24-bit OUI entries...
38000-40000 internal/oui/manuf.txt
Done. Review the diff and commit if it looks right.
```

If the count is dramatically off (e.g., zero lines, or millions), upstream has changed format — escalate as BLOCKED.

- [ ] **Step 4.2: Sanity-check the new file**

```bash
wc -l internal/oui/manuf.txt
head -3 internal/oui/manuf.txt
grep -c '/' internal/oui/manuf.txt
grep -c '^#' internal/oui/manuf.txt
```

Expected:
- ~38000–40000 lines
- First three lines look like `XX:XX:XX<TAB>ShortName<TAB>Long Vendor Name`
- `grep -c '/'` returns `0` (filter worked)
- `grep -c '^#'` returns `0` (comments stripped)

- [ ] **Step 4.3: Verify all OUI tests pass against the new data**

```bash
go test ./internal/oui/ -v
```

Expected:
- `TestLookupKnown` PASS — the seed-list MACs (Apple, RaspberryPi, TP-Link) are also in the full DB.
- `TestLookupUnknown` PASS — none of the unknown cases (`""`, `"not-a-mac"`, `"ff:ff:ff:ff:ff:ff"`, `"01:02:03:04:05:06"`) are present.

If `TestLookupKnown` fails, the parser silently broke under the new file — investigate before committing.

- [ ] **Step 4.4: Verify the binary builds and `--version` still works**

```bash
go build ./...
go test ./...
```

All packages green. The binary now embeds ~2 MB of vendor data; build size grows from ~10 MB to ~12 MB.

- [ ] **Step 4.5: Commit**

```bash
git add internal/oui/manuf.txt
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "oui: replace seed with full Wireshark manuf database (~38k entries)"
```

---

## Task 5: Update package doc comment and README

**Files:**
- Modify: `internal/oui/oui.go` (top-level package doc comment)
- Modify: `README.md` (Development section)

- [ ] **Step 5.1: Replace the package doc comment**

In `internal/oui/oui.go`, find the existing top comment:

```go
// Package oui resolves a MAC address to a vendor short-name using an
// embedded copy of Wireshark's manuf database (or a trimmed equivalent).
package oui
```

Replace with:

```go
// Package oui resolves a MAC address to a vendor short-name using an
// embedded copy of Wireshark's manuf database.
//
// The bundled manuf.txt and its license (MANUF-LICENSE) are fetched from
// https://www.wireshark.org/download/automated/data/manuf and
// https://gitlab.com/wireshark/wireshark/-/raw/master/COPYING respectively,
// via `make manuf-refresh`.
package oui
```

- [ ] **Step 5.2: Add a note in README.md's Development section**

Find the Development section in `README.md`:

```markdown
## Development

```bash
make test     # run all unit tests
make vet      # go vet
make lint     # staticcheck
make smoke    # build, setcap, and run --once --table on your live network
```
```

Replace with:

```markdown
## Development

```bash
make test            # run all unit tests
make vet             # go vet
make lint            # staticcheck
make smoke           # build, setcap, and run --once --table on your live network
make manuf-refresh   # refresh the OUI vendor database from Wireshark upstream
```

The OUI vendor database (`internal/oui/manuf.txt`) is sourced from Wireshark
and committed to the repo. Run `make manuf-refresh` to update it; it pulls
from `wireshark.org`, filters to 24-bit OUI entries, and rewrites the file.
Review the diff and commit if it looks right.
```

- [ ] **Step 5.3: Verify build and tests**

```bash
go build ./...
go test ./...
go vet ./...
```

All green.

- [ ] **Step 5.4: Commit**

```bash
git add internal/oui/oui.go README.md
git -c user.name='Claude' -c user.email='noreply@anthropic.com' commit -m "docs: note manuf-refresh target in package doc and README"
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
- Binary size reported by `ls -la`. Compare against your previous local build to confirm the ~2 MB growth from embedded data is in line with the spec.

- [ ] **Step 6.3: Spot-check vendor lookup for common prefixes**

Quickly verify the new manuf actually contains entries the seed didn't:

```bash
grep -c '^B8:27:EB' internal/oui/manuf.txt   # Raspberry Pi (was in seed)
grep -c '^00:0C:29' internal/oui/manuf.txt   # VMware (was NOT in seed)
grep -c '^F0:18:98' internal/oui/manuf.txt   # Apple (modern range, was NOT in seed)
```

Each should return `1`. If any return `0`, the data is incomplete — escalate.

- [ ] **Step 6.4: No commit needed (verification only)**

If Step 6.3 surfaced any unexpected zeros, escalate to the operator. Otherwise, the implementation is complete.

---

## Done

After all 6 tasks complete:

- 5 commits on the `feat/oui-full-db` branch (parser guard, Make target, license, manuf data, doc/README) plus optional fix commits.
- `go test ./...` passes; `go vet ./...` clean; `staticcheck ./...` clean.
- `make manuf-refresh` works on demand and produces a deterministic file.
- Binary embeds ~2 MB of vendor data; `lan-inventory --version` still works.
- Vendor column on the live TUI now shows real names for Apple, Samsung, Espressif, Raspberry Pi, etc. instead of mostly empty cells.
