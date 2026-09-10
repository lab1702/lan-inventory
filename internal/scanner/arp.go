// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/lab1702/lan-inventory/internal/netiface"
	"github.com/lab1702/lan-inventory/internal/oui"
)

// ARPWorker passively sniffs ARP packets on the given interface and emits an
// Update for every packet seen.
type ARPWorker struct {
	Iface *netiface.Info
}

// A positive timeout makes an idle capture return control to the cancellation
// check. BlockForever can also leave Close waiting for the packet reader.
const arpReadTimeout = 100 * time.Millisecond

type arpCapture interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
	SetBPFFilter(string) error
	Close()
}

func (w *ARPWorker) Run(ctx context.Context, out chan<- Update) error {
	return w.run(ctx, out, func(iface *netiface.Info, timeout time.Duration) (arpCapture, error) {
		dev, err := pcapDeviceName(iface)
		if err != nil {
			return nil, fmt.Errorf("resolve pcap device: %w", err)
		}
		handle, err := pcap.OpenLive(dev, 65536, true, timeout)
		if err != nil {
			return nil, fmt.Errorf("pcap open %s: %w (do you have CAP_NET_RAW or Npcap installed?)", dev, err)
		}
		return handle, nil
	})
}

func (w *ARPWorker) run(ctx context.Context, out chan<- Update, open func(*netiface.Info, time.Duration) (arpCapture, error)) error {
	if w.Iface == nil || w.Iface.Subnet == nil {
		return fmt.Errorf("ARP interface and subnet are required")
	}
	if ctx.Err() != nil {
		return nil
	}
	handle, err := open(w.Iface, arpReadTimeout)
	if err != nil {
		return err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return fmt.Errorf("set bpf filter: %w", err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	// NextPacket reads synchronously: no PacketSource goroutine can remain
	// blocked on a packet send after this worker stops consuming.
	for ctx.Err() == nil {
		pkt, err := src.NextPacket()
		if errors.Is(err, pcap.NextErrorTimeoutExpired) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read ARP packet: %w", err)
		}
		arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
		if !ok {
			continue
		}
		mac := net.HardwareAddr(arp.SourceHwAddress).String()
		ip := net.IP(arp.SourceProtAddress).To4()
		if mac == "" || ip == nil || ip.IsUnspecified() || !w.Iface.Subnet.Contains(ip) {
			continue
		}
		ip = append(net.IP(nil), ip...)
		update := Update{
			Source: "arp",
			Time:   time.Now(),
			MAC:    strings.ToLower(mac),
			IP:     ip,
			Vendor: oui.Lookup(mac),
		}
		select {
		case out <- update:
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}
