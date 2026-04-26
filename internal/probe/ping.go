package probe

import (
	"context"
	"fmt"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// PingResult is the outcome of a single ICMP ping attempt.
type PingResult struct {
	Alive bool
	RTT   time.Duration
	TTL   int
}

// Ping sends a single ICMP echo to the given IP and waits for a reply, with
// the timeout taken from ctx. Requires raw socket privilege; the caller is
// responsible for surfacing setup errors.
func Ping(ctx context.Context, ip string) (PingResult, error) {
	pinger, err := probing.NewPinger(ip)
	if err != nil {
		return PingResult{}, fmt.Errorf("new pinger: %w", err)
	}
	pinger.SetPrivileged(true)
	pinger.Count = 1
	pinger.Timeout = 1 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < pinger.Timeout {
			pinger.Timeout = rem
		}
	}

	var ttl int
	pinger.OnRecv = func(pkt *probing.Packet) { ttl = pkt.TTL }

	if err := pinger.RunWithContext(ctx); err != nil {
		return PingResult{}, fmt.Errorf("ping: %w", err)
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return PingResult{Alive: false}, nil
	}
	return PingResult{
		Alive: true,
		RTT:   stats.AvgRtt,
		TTL:   ttl,
	}, nil
}
