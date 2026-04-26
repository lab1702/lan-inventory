package probe

import (
	"context"
	"net"
	"strings"
	"time"
)

// ReverseDNS does a PTR lookup for ip via the system default resolver and
// returns the first result, with the trailing dot trimmed. Returns "" on
// timeout, no result, or any error.
func ReverseDNS(ctx context.Context, ip string) string {
	resolver := net.DefaultResolver
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// ReverseDNSVia performs a PTR lookup using a custom resolver IP rather than
// the system default. Used to query the LAN gateway's local DNS, which often
// knows DHCP-lease names that upstream resolvers don't. Returns "" on any
// error or empty result. Bounded by a 500 ms timeout.
func ReverseDNSVia(ctx context.Context, ip string, resolverIP string) string {
	if resolverIP == "" {
		return ""
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 500 * time.Millisecond}
			return d.DialContext(ctx, "udp", net.JoinHostPort(resolverIP, "53"))
		},
	}
	cctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	names, err := r.LookupAddr(cctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// ReverseDNSMDNS sends a unicast PTR query to the device's UDP port 5353
// (mDNS protocol port). Some devices answer their own .local hostname here
// even when they don't actively announce services. Returns "" on any error
// or empty result. Bounded by a 500 ms timeout.
//
// The function name reflects the protocol (mDNS) but the transport is
// unicast — we send directly to the device's IP, not the multicast group.
func ReverseDNSMDNS(ctx context.Context, ip string) string {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 500 * time.Millisecond}
			return d.DialContext(ctx, "udp", net.JoinHostPort(ip, "5353"))
		},
	}
	cctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	names, err := r.LookupAddr(cctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
