// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"errors"
	"fmt"

	"github.com/google/gopacket/pcap"
)

// ErrNoRawSocket is returned by Precheck when raw-socket access is missing.
var ErrNoRawSocket = errors.New("raw socket access denied")

// Precheck verifies that the calling process can open libpcap on the named
// interface. It is a fast smoke test that pcap_open_live succeeds — exactly
// the same call ARPWorker will make. If it fails, the user has no raw socket
// privilege, and the rest of the program will be useless.
func Precheck(ifaceName string) error {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoRawSocket, err)
	}
	handle.Close()
	return nil
}