// SPDX-License-Identifier: GPL-2.0-or-later

package probe

import (
	"context"
	"net"
)

func newCancellableDNSResolver(dial func(context.Context, string, string) (net.Conn, error)) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			// Go sets socket deadlines for DNS, but cancellation after Dial
			// also needs to interrupt reads immediately. No lookup goroutine
			// is left waiting for an uncancellable native resolver call.
			wrapped := &dnsContextConn{Conn: conn}
			wrapped.stop = context.AfterFunc(ctx, func() { conn.Close() })
			if packet, ok := conn.(net.PacketConn); ok {
				// net.Resolver uses PacketConn to select UDP message framing.
				return &dnsContextPacketConn{dnsContextConn: wrapped, packet: packet}, nil
			}
			return wrapped, nil
		},
	}
}

type dnsContextConn struct {
	net.Conn
	stop func() bool
}

func (c *dnsContextConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

type dnsContextPacketConn struct {
	*dnsContextConn
	packet net.PacketConn
}

func (c *dnsContextPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.packet.ReadFrom(b)
}

func (c *dnsContextPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.packet.WriteTo(b, addr)
}
