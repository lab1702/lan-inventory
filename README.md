# lan-inventory

A zero-config home-LAN inventory tool. Run it, see your network.

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

## Usage

```bash
lan-inventory               # interactive TUI dashboard
lan-inventory --once        # one scan, print JSON, exit
lan-inventory --once --table # one scan, print table, exit
lan-inventory --version
lan-inventory --help
```

See `docs/superpowers/specs/` for the design.
