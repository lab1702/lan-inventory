package probe

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

// tcpAliveProbePorts is the fixed shortlist of TCP ports we use to detect
// host liveness when ICMP doesn't answer. These cover the common defaults
// for Windows (135, 445), Unix-like (22), and routers/printers (80).
var tcpAliveProbePorts = []int{445, 135, 22, 80}

// TCPAlive returns true if a TCP connection attempt to any of the probe
// ports either succeeds or receives an explicit "connection refused"
// (RST). Both outcomes prove the host is up — only "no response within
// the per-port timeout" suggests the host is dead.
//
// Use this as an ICMP-ping fallback for hosts that block ICMP (Windows
// hosts ignore ICMP echo by default). The function tries ports
// sequentially with a short per-port timeout (200 ms) and returns at the
// first positive signal.
func TCPAlive(ctx context.Context, ip string) bool {
	for _, p := range tcpAliveProbePorts {
		if ctx.Err() != nil {
			return false
		}
		d := net.Dialer{Timeout: 200 * time.Millisecond}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
		if err == nil {
			conn.Close()
			return true
		}
		// "connection refused" means the host responded with RST — it's up.
		if strings.Contains(err.Error(), "connection refused") {
			return true
		}
	}
	return false
}
