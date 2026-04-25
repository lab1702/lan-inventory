//go:build !linux

package netiface

import (
	"fmt"
	"net"
)

func defaultRouteInterface() (*net.Interface, error) {
	return nil, fmt.Errorf("default route detection not implemented on this platform")
}
