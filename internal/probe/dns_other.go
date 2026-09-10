// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !windows

package probe

import "net"

func reverseDNSResolver() *net.Resolver {
	return net.DefaultResolver
}
