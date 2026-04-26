package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/lab1702/lan-inventory/internal/oui"
)

// ARPWorker passively sniffs ARP packets on the given interface and emits an
// Update for every packet seen.
type ARPWorker struct {
	IfaceName string
}

func (w *ARPWorker) Run(ctx context.Context, out chan<- Update) error {
	handle, err := pcap.OpenLive(w.IfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w (do you have CAP_NET_RAW?)", w.IfaceName, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return fmt.Errorf("set bpf filter: %w", err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-packets:
			if !ok {
				return nil
			}
			arpLayer := pkt.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp, ok := arpLayer.(*layers.ARP)
			if !ok {
				continue
			}
			mac := net.HardwareAddr(arp.SourceHwAddress).String()
			ip := append(net.IP{}, arp.SourceProtAddress...)
			if mac == "" || ip == nil || ip.IsUnspecified() {
				continue
			}
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
	}
}
