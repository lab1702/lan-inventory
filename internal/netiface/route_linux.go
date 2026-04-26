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
