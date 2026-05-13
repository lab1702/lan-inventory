// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"errors"
	"fmt"

	"github.com/google/gopacket/pcap"

	"github.com/lab1702/lan-inventory/internal/netiface"
)

// ErrNoRawSocket is returned by Precheck when raw-socket access is missing.
var ErrNoRawSocket = errors.New("raw socket access denied")

// Precheck verifies that the calling process can open libpcap on the
// chosen interface. It is a fast smoke test that pcap_open_live succeeds
// — exactly the same call ARPWorker will make. If it fails, the user has
// no raw socket privilege (Linux) or Npcap is missing / not in
// WinPcap-API-compatible mode (Windows), and the rest of the program
// will be useless.
func Precheck(iface *netiface.Info) error {
	dev, err := pcapDeviceName(iface)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoRawSocket, err)
	}
	handle, err := pcap.OpenLive(dev, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoRawSocket, err)
	}
	handle.Close()
	return nil
}