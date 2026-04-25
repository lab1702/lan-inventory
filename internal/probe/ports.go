package probe

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

// DefaultPorts is the fixed shortlist scanned by the active prober.
func DefaultPorts() []int {
	return []int{22, 53, 80, 443, 445, 631, 1400, 5000, 5353, 8080, 9100}
}

// ScanPorts attempts a TCP connect to each port on host with the given
// per-port timeout, in parallel. Returns only the ports that accepted the
// connection. Respects ctx cancellation.
func ScanPorts(ctx context.Context, host string, ports []int, perPortTimeout time.Duration) []model.Port {
	if ctx.Err() != nil {
		return nil
	}
	var (
		mu     sync.Mutex
		out    []model.Port
		wg     sync.WaitGroup
		dialer = net.Dialer{Timeout: perPortTimeout}
	)
	for _, p := range ports {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			cctx, cancel := context.WithTimeout(ctx, perPortTimeout)
			defer cancel()
			conn, err := dialer.DialContext(cctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			out = append(out, model.Port{Number: p, Proto: "tcp", Service: ServiceLabel(p)})
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out
}

// ServiceLabel returns the conventional name for a well-known port, or "".
func ServiceLabel(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 53:
		return "dns"
	case 80, 8080:
		return "http"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 631:
		return "ipp"
	case 1400:
		return "sonos"
	case 5000:
		return "upnp"
	case 5353:
		return "mdns"
	case 9100:
		return "jetdirect"
	}
	return ""
}
