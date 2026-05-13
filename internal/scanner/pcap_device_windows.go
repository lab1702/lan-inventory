// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package scanner

import (
	"fmt"

	"github.com/google/gopacket/pcap"

	"github.com/lab1702/lan-inventory/internal/netiface"
)

// pcapDeviceName returns the Npcap device identifier (\Device\NPF_{GUID})
// for the interface that owns iface.HostIP. Windows pcap does not accept
// the friendly net.Interface name returned by the Go stdlib; it expects
// the GUID-tagged device path enumerated by pcap_findalldevs.
func pcapDeviceName(iface *netiface.Info) (string, error) {
	if iface == nil || iface.HostIP == nil {
		return "", fmt.Errorf("pcapDeviceName: iface or HostIP nil")
	}
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("pcap.FindAllDevs: %w", err)
	}
	for _, d := range devs {
		for _, a := range d.Addresses {
			if a.IP == nil {
				continue
			}
			if a.IP.Equal(iface.HostIP) {
				return d.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no pcap device matches interface %s (HostIP %s)", iface.Name, iface.HostIP)
}
