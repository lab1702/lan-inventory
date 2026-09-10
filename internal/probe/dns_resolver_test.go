// SPDX-License-Identifier: GPL-2.0-or-later

package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestReverseDNSResolverPlatform(t *testing.T) {
	r := reverseDNSResolver()
	if runtime.GOOS == "windows" {
		if !r.PreferGo || r.Dial == nil {
			t.Fatal("Windows PTR lookups require the cancellable Go DNS resolver")
		}
	} else if r != net.DefaultResolver {
		t.Fatal("non-Windows PTR lookups must preserve the system default resolver")
	}
}

func TestCancellableDNSResolverSilentServer(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		name := "deadline"
		if cancelEarly {
			name = "cancel_after_query"
		}
		t.Run(name, func(t *testing.T) {
			server, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			r := newCancellableDNSResolver(func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.LocalAddr().String())
			})
			timeout := 500 * time.Millisecond
			if cancelEarly {
				timeout = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			result := make(chan error, 1)
			done := make(chan struct{})
			start := time.Now()
			go func() {
				defer close(done)
				_, err := r.LookupAddr(ctx, "203.0.113.249")
				result <- err
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("DNS lookup did not stop after cancellation")
				}
			})
			// Receive a real PTR query, then intentionally never answer it.
			// Parsing the datagram also detects wrappers that accidentally hide
			// PacketConn and cause net.Resolver to use TCP length framing on UDP.
			buf := make([]byte, 1500)
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				t.Fatalf("waiting for DNS query: %v", err)
			}
			var message dnsmessage.Message
			if err := message.Unpack(buf[:n]); err != nil {
				t.Fatalf("invalid DNS datagram framing: %v", err)
			}
			if len(message.Questions) != 1 || message.Questions[0].Type != dnsmessage.TypePTR ||
				message.Questions[0].Name.String() != "249.113.0.203.in-addr.arpa." {
				t.Fatalf("unexpected DNS questions: %+v", message.Questions)
			}
			if cancelEarly {
				start = time.Now()
				cancel()
			}
			select {
			case err := <-result:
				if err == nil || ctx.Err() == nil {
					t.Fatalf("silent DNS lookup completed without context error: lookup=%v, context=%v", err, ctx.Err())
				}
				if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
					t.Fatalf("DNS lookup took %v after %s", elapsed, name)
				}
			case <-time.After(1500 * time.Millisecond):
				t.Fatalf("DNS lookup ignored %s while awaiting a response", name)
			}
		})
	}
}

func TestDNSConnectionCloseUnregistersCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newCancellableDNSResolver(func(context.Context, string, string) (net.Conn, error) {
		return client, nil
	})
	conn, err := r.Dial(ctx, "tcp", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if _, isPacket := conn.(net.PacketConn); isPacket {
		t.Fatal("stream connection was incorrectly exposed as a datagram connection")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.(*dnsContextConn).stop() {
		t.Fatal("normal Close left a context callback registered")
	}
}

func TestReverseDNSViaRetriesTruncatedUDPOverTCP(t *testing.T) {
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	deadline := time.Now().Add(2 * time.Second)
	if err := tcp.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := udp.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		serverResult <- serveTruncatedDNS(udp, tcp, deadline)
	}()
	t.Cleanup(func() {
		udp.Close()
		tcp.Close()
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
			t.Error("DNS test server did not stop")
		}
	})
	got := reverseDNSViaAddress(context.Background(), "203.0.113.249", tcp.Addr().String())
	if got != "gateway-host.lan" {
		t.Fatalf("PTR lookup after UDP truncation = %q, want gateway-host.lan", got)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func serveTruncatedDNS(udp net.PacketConn, tcp *net.TCPListener, deadline time.Time) error {
	buf := make([]byte, 1500)
	n, addr, err := udp.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("read UDP query: %w", err)
	}
	var query dnsmessage.Message
	if err := query.Unpack(buf[:n]); err != nil {
		return fmt.Errorf("decode UDP query: %w", err)
	}
	if len(query.Questions) != 1 || query.Questions[0].Type != dnsmessage.TypePTR ||
		query.Questions[0].Name.String() != "249.113.0.203.in-addr.arpa." {
		return fmt.Errorf("unexpected UDP questions: %+v", query.Questions)
	}
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: query.ID, Response: true, Truncated: true,
			RecursionDesired: query.RecursionDesired, RecursionAvailable: true,
		},
		Questions: query.Questions,
	}
	wire, err := response.Pack()
	if err != nil {
		return err
	}
	if _, err := udp.WriteTo(wire, addr); err != nil {
		return fmt.Errorf("write truncated UDP reply: %w", err)
	}
	conn, err := tcp.Accept()
	if err != nil {
		return fmt.Errorf("accept TCP fallback: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return fmt.Errorf("read TCP DNS length: %w", err)
	}
	wire = make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, wire); err != nil {
		return fmt.Errorf("read TCP DNS query: %w", err)
	}
	var retry dnsmessage.Message
	if err := retry.Unpack(wire); err != nil {
		return fmt.Errorf("decode TCP query: %w", err)
	}
	if len(retry.Questions) != 1 || retry.Questions[0] != query.Questions[0] {
		return fmt.Errorf("TCP retry changed the PTR question: %+v", retry.Questions)
	}
	response.ID = retry.ID
	response.Truncated = false
	response.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{
			Name: retry.Questions[0].Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 60,
		},
		Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("gateway-host.lan.")},
	}}
	wire, err = response.Pack()
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
	_, err = conn.Write(append(size[:], wire...))
	return err
}
