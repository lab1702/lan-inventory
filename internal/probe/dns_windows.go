// SPDX-License-Identifier: GPL-2.0-or-later

package probe

import "net"

// Go reads Windows adapter DNS settings for this resolver, while its own
// DNS transport can enforce deadlines without waiting for native DnsQuery.
var windowsReverseDNSResolver = newCancellableDNSResolver((&net.Dialer{}).DialContext)

func reverseDNSResolver() *net.Resolver {
	return windowsReverseDNSResolver
}
