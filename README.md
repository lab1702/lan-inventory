# lan-inventory

A zero-config home-LAN inventory tool. Run it, see your network.

A single Go binary that auto-discovers devices on your local /24, presents a
live TUI dashboard, and can also dump a one-shot JSON or text snapshot for
scripts and cron.

## What it shows

- IP, MAC, vendor (OUI lookup)
- Hostname (mDNS preferred, reverse DNS fallback)
- OS family guess (mDNS / vendor / NBNS / ports / TTL)
- Common open ports with service labels
- mDNS service announcements
- Last-seen timestamp and online/stale/offline status

## Install

```bash
go install github.com/lab1702/lan-inventory/cmd/lan-inventory@latest
sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)
```

Or build from source:

```bash
make build
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/lan-inventory
./bin/lan-inventory
```

The `setcap` step is needed once; `lan-inventory` requires raw-socket access
to sniff ARP packets and send ICMP ping. Without it the tool refuses to start.

## Usage

```bash
lan-inventory                 # interactive TUI dashboard
lan-inventory --once          # single scan, JSON to stdout, exit
lan-inventory --once --table  # single scan, human-readable table, exit
lan-inventory --version
```

### TUI keys

- `1`–`4` switch tabs (Devices / Services / Subnet / Events)
- `↑/↓` or `j/k` navigate
- `/` filter (Enter or Esc exits filter input; clear with Backspace)
- `r` force a rescan
- `q`, `Esc`, or `Ctrl+C` quit
- `?` help overlay

### Exit codes (non-interactive)

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Runtime error |
| 2    | Configuration error (no privilege, no default route, oversized subnet) |
| 3    | No devices discovered |

## Limitations

- IPv4 only.
- Targets /24 home networks; subnets larger than /22 are refused.
- No persistence: state is wiped on quit.
- Linux only. Default-route detection and the kernel-ARP-cache seed are
  Linux-specific; macOS and Windows builds will fail at startup until those
  are implemented.

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

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).

The bundled OUI vendor database is sourced from Wireshark, which is also
licensed under GPL-2.0-or-later; the upstream license text is preserved at
[internal/oui/MANUF-LICENSE](internal/oui/MANUF-LICENSE).
