// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/lab1702/lan-inventory/internal/netiface"
)

func arpTestInfo() *netiface.Info {
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	return &netiface.Info{Name: "test0", Subnet: subnet}
}

type fakeARPCapture struct {
	read      func() ([]byte, gopacket.CaptureInfo, error)
	filterErr error
	filter    string
	closed    atomic.Bool
	reading   atomic.Bool
	closeBusy atomic.Bool
}

func (f *fakeARPCapture) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	f.reading.Store(true)
	defer f.reading.Store(false)
	return f.read()
}
func (f *fakeARPCapture) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (f *fakeARPCapture) SetBPFFilter(filter string) error {
	f.filter = filter
	return f.filterErr
}
func (f *fakeARPCapture) Close() {
	f.closeBusy.Store(f.reading.Load())
	f.closed.Store(true)
}

func TestARPCancellationOnQuietCapture(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	capture := &fakeARPCapture{}
	capture.read = func() ([]byte, gopacket.CaptureInfo, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		time.Sleep(10 * time.Millisecond)
		return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
	}
	worker := &ARPWorker{Iface: arpTestInfo()}
	result := make(chan error, 1)
	var timeout time.Duration
	go func() {
		result <- worker.run(ctx, make(chan Update), func(_ *netiface.Info, readTimeout time.Duration) (arpCapture, error) {
			timeout = readTimeout
			return capture, nil
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("capture did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle capture did not stop after cancellation")
	}
	if timeout <= 0 || timeout > time.Second {
		t.Errorf("read timeout %v must be positive and bounded", timeout)
	}
	if !capture.closed.Load() || capture.closeBusy.Load() {
		t.Error("capture must close after its reader stops")
	}
	if capture.filter != "arp" {
		t.Errorf("capture filter = %q", capture.filter)
	}
}

func TestARPErrorsReachCallerAndCloseCapture(t *testing.T) {
	failure := errors.New("capture unavailable")
	for _, stage := range []string{"open", "filter", "read"} {
		t.Run(stage, func(t *testing.T) {
			capture := &fakeARPCapture{read: func() ([]byte, gopacket.CaptureInfo, error) {
				return nil, gopacket.CaptureInfo{}, failure
			}}
			if stage == "filter" {
				capture.filterErr = failure
			}
			worker := &ARPWorker{Iface: arpTestInfo()}
			err := worker.run(context.Background(), make(chan Update), func(*netiface.Info, time.Duration) (arpCapture, error) {
				if stage == "open" {
					return nil, failure
				}
				return capture, nil
			})
			if !errors.Is(err, failure) {
				t.Fatalf("Run error = %v, want %v", err, failure)
			}
			if stage != "open" && !capture.closed.Load() {
				t.Error("capture not closed after error")
			}
		})
	}
}

func TestARPEmitsPacketAndCancelsBlockedOutput(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: mac, DstMAC: net.HardwareAddr{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, Operation: layers.ARPRequest,
			SourceHwAddress: mac, SourceProtAddress: []byte{192, 168, 1, 10},
			DstHwAddress: make([]byte, 6), DstProtAddress: []byte{192, 168, 1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	capture := &fakeARPCapture{read: func() ([]byte, gopacket.CaptureInfo, error) {
		return buffer.Bytes(), gopacket.CaptureInfo{}, nil
	}}
	worker := &ARPWorker{Iface: arpTestInfo()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan Update)
	result := make(chan error, 1)
	go func() {
		result <- worker.run(ctx, out, func(*netiface.Info, time.Duration) (arpCapture, error) { return capture, nil })
	}()
	select {
	case update := <-out:
		if update.Source != "arp" || update.MAC != mac.String() || !update.IP.Equal(net.IPv4(192, 168, 1, 10)) {
			t.Errorf("unexpected update: %+v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("no ARP update")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("capture did not stop with no output consumer")
	}
}

func TestARPIgnoresOtherSubnetsOnSameInterface(t *testing.T) {
	var packets [][]byte
	mac := net.HardwareAddr{0, 0x11, 0x22, 0x33, 0x44, 0x55}
	for _, ip := range []string{"192.168.2.10", "169.254.1.10", "192.168.1.10"} {
		buf := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
			&layers.Ethernet{SrcMAC: mac, DstMAC: net.HardwareAddr{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeARP},
			&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, Operation: layers.ARPRequest,
				SourceHwAddress: mac, SourceProtAddress: net.ParseIP(ip).To4(), DstHwAddress: make([]byte, 6), DstProtAddress: []byte{192, 168, 1, 1}})
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, buf.Bytes())
	}
	capture := &fakeARPCapture{read: func() ([]byte, gopacket.CaptureInfo, error) {
		if len(packets) == 0 {
			return nil, gopacket.CaptureInfo{}, io.EOF
		}
		packet := packets[0]
		packets = packets[1:]
		return packet, gopacket.CaptureInfo{}, nil
	}}
	out := make(chan Update, 3)
	err := (&ARPWorker{Iface: arpTestInfo()}).run(context.Background(), out, func(*netiface.Info, time.Duration) (arpCapture, error) { return capture, nil })
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected end of fake capture, got %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("published %d updates, want only the in-subnet host", len(out))
	}
	if got := (<-out).IP.String(); got != "192.168.1.10" {
		t.Fatalf("published out-of-subnet IP %s", got)
	}
}
