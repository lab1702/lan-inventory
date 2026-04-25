// Package netiface auto-detects the default network interface and its IPv4
// subnet, and provides helpers for iterating the subnet.
package netiface

import (
	"errors"
	"fmt"
	"net"
)

// Info describes the interface chosen for scanning.
type Info struct {
	Name   string
	Subnet *net.IPNet
	HostIP net.IP // our own IP on this interface
}

// MaxPrefixOnesAllowed is the maximum prefix length that's "small enough" — a
// /22 and below is permitted. Anything larger (e.g., /20, /16) is refused.
const MinPrefixOnesAllowed = 22 // ones >= 22 ⇒ subnet ≤ /22

// ErrSubnetTooLarge is returned by CheckSubnetSize when the subnet is bigger
// than the design ceiling.
var ErrSubnetTooLarge = errors.New("subnet too large")

// CheckSubnetSize validates that the subnet's size is within design limits.
// Returns nil for /22 and smaller (more host bits = smaller; ones >= 22).
func CheckSubnetSize(subnet *net.IPNet) error {
	ones, bits := subnet.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("not an IPv4 subnet: %s", subnet)
	}
	if ones < MinPrefixOnesAllowed {
		return fmt.Errorf("%w: subnet /%d too large — this tool targets home-LAN /24 deployments", ErrSubnetTooLarge, ones)
	}
	return nil
}

// SubnetIPs returns all usable host IPs in the subnet (excludes network and
// broadcast addresses for IPv4).
func SubnetIPs(subnet *net.IPNet) []net.IP {
	var out []net.IP
	ip := subnet.IP.Mask(subnet.Mask).To4()
	if ip == nil {
		return out
	}
	for cur := make(net.IP, 4); ; {
		copy(cur, ip)
		if !subnet.Contains(cur) {
			break
		}
		// skip network and broadcast
		ones, _ := subnet.Mask.Size()
		isNetwork := equalIP(cur, subnet.IP.Mask(subnet.Mask))
		isBroadcast := isBroadcastAddr(cur, subnet)
		if !isNetwork && !isBroadcast || ones == 32 || ones == 31 {
			out = append(out, append(net.IP{}, cur...))
		}
		// increment
		incIP(ip)
		if !subnet.Contains(ip) {
			break
		}
	}
	return out
}

func equalIP(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if a4[i] != b4[i] {
			return false
		}
	}
	return true
}

func isBroadcastAddr(ip net.IP, subnet *net.IPNet) bool {
	mask := subnet.Mask
	bcast := make(net.IP, 4)
	base := subnet.IP.To4()
	for i := 0; i < 4; i++ {
		bcast[i] = base[i] | ^mask[i]
	}
	return equalIP(ip, bcast)
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

// Detect picks the interface owning the default IPv4 route, validates the
// subnet size, and returns Info. This function reads OS state and is not
// unit-tested; covered by manual smoke testing.
func Detect() (*Info, error) {
	defaultIface, err := defaultRouteInterface()
	if err != nil {
		return nil, err
	}
	addrs, err := defaultIface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("read addrs for %s: %w", defaultIface.Name, err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		// Build subnet from mask
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			continue
		}
		subnet := &net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: net.CIDRMask(ones, 32)}
		if err := CheckSubnetSize(subnet); err != nil {
			return nil, err
		}
		return &Info{Name: defaultIface.Name, Subnet: subnet, HostIP: ip4}, nil
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", defaultIface.Name)
}
