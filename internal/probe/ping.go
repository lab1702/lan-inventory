// SPDX-License-Identifier: GPL-2.0-or-later

package probe

import "time"

// PingResult is the outcome of a single ICMP ping attempt.
type PingResult struct {
	Alive bool
	RTT   time.Duration
	TTL   int
}
