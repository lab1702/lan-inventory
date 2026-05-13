// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !windows

package scanner

import "github.com/lab1702/lan-inventory/internal/netiface"

// pcapDeviceName returns the libpcap device identifier for the given
// interface. On non-Windows platforms libpcap and the kernel agree on
// interface naming (eth0, enp195s0, en0, …), so we pass the friendly
// name through unchanged.
func pcapDeviceName(iface *netiface.Info) (string, error) {
	return iface.Name, nil
}
