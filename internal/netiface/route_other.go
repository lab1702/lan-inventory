// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package netiface

import (
	"fmt"
	"net"
)

func defaultRouteInterface() (*net.Interface, net.IP, error) {
	return nil, nil, fmt.Errorf("default route detection not implemented on this platform")
}