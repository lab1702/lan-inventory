//go:build linux

package netiface

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// defaultRouteInterface reads /proc/net/route and returns the interface that
// owns the default route (destination 00000000 with the lowest metric).
func defaultRouteInterface() (*net.Interface, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/route: %w", err)
	}
	defer f.Close()

	type cand struct {
		iface  string
		metric int
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
			best = &cand{iface: fields[0], metric: metric}
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no default route — cannot determine which subnet to scan")
	}
	iface, err := net.InterfaceByName(best.iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", best.iface, err)
	}
	return iface, nil
}
