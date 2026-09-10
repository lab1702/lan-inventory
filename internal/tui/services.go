// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/lab1702/lan-inventory/internal/model"
)

func (m Model) viewServices() string {
	groups := groupServices(m.devices)
	if len(groups) == 0 {
		return "(no services seen yet)"
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		hosts := groups[k]
		count := len(hosts)
		countLabel := "host"
		if count != 1 {
			countLabel = "hosts"
		}
		hostList := strings.Join(hosts, ", ")
		key := padRight(styleAccent.Render(k), 22)
		b.WriteString(fmt.Sprintf("%s  %d %s  →  %s\n", key, count, countLabel, hostList))
	}
	// Wrap before the viewport counts and slices physical lines. Otherwise
	// terminal-width clipping permanently hides later hosts in each group.
	return lipgloss.NewStyle().Width(max(1, m.width)).Render(strings.TrimSuffix(b.String(), "\n"))
}

// groupServices counts hosts, not advertised instances. Multiple entries for
// the same service on one device count once, using MAC (or IP) as identity.
func groupServices(devices []*model.Device) map[string][]string {
	groups := map[string]map[string]struct{}{}
	endpoints := map[string]*serviceEndpoint{}
	for i, d := range devices {
		ips := serviceIPs(d)
		mac := strings.ToLower(d.MAC)
		id := fmt.Sprintf("device %d", i+1)
		if mac != "" {
			id = "mac:" + mac
		} else if len(ips) > 0 {
			id = "ip:" + ips[0]
		}
		host := endpoints[id]
		if host == nil {
			host = &serviceEndpoint{mac: mac, ips: map[string]struct{}{}, fallback: id}
			endpoints[id] = host
		}
		// Duplicate records for one MAC can carry different addresses or
		// names. Merge addresses and choose a stable nonempty display name.
		if d.Hostname != "" && (host.name == "" || d.Hostname < host.name) {
			host.name = d.Hostname
		}
		for _, ip := range ips {
			host.ips[ip] = struct{}{}
		}
		for _, s := range d.Services {
			if _, ok := groups[s.Type]; !ok {
				groups[s.Type] = map[string]struct{}{}
			}
			groups[s.Type][id] = struct{}{}
		}
		for _, p := range d.OpenPorts {
			label := fmt.Sprintf("%d/%s", p.Number, p.Proto)
			if p.Service != "" {
				label = fmt.Sprintf("%d/%s (%s)", p.Number, p.Proto, p.Service)
			}
			if _, ok := groups[label]; !ok {
				groups[label] = map[string]struct{}{}
			}
			groups[label][id] = struct{}{}
		}
	}
	out := map[string][]string{}
	for k, set := range groups {
		names := map[string]int{}
		for id := range set {
			names[endpoints[id].label()]++
		}
		labels := map[string]string{}
		counts := map[string]int{}
		for id := range set {
			host := endpoints[id]
			label := host.label()
			if names[label] > 1 {
				label += " (" + host.address() + ")"
			}
			labels[id] = label
			counts[label]++
		}
		hosts := make([]string, 0, len(labels))
		for id, label := range labels {
			// Known hosts can briefly share an address. Keep their labels
			// distinct even after adding that shared address.
			if counts[label] > 1 {
				label += " [" + endpoints[id].owner() + "]"
			}
			hosts = append(hosts, label)
		}
		sort.Strings(hosts)
		out[k] = hosts
	}
	return out
}

type serviceEndpoint struct {
	name     string
	mac      string
	ips      map[string]struct{}
	fallback string
}

func serviceIPs(d *model.Device) []string {
	ips := make([]string, 0, len(d.IPs))
	for _, ip := range d.IPs {
		if ip != nil {
			ips = append(ips, ip.String())
		}
	}
	sort.Strings(ips)
	return ips
}

func (h *serviceEndpoint) label() string {
	if h.name != "" {
		return h.name
	}
	return h.address()
}

func (h *serviceEndpoint) address() string {
	if len(h.ips) > 0 {
		ips := make([]string, 0, len(h.ips))
		for ip := range h.ips {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		return strings.Join(ips, ", ")
	}
	return h.owner()
}

func (h *serviceEndpoint) owner() string {
	if h.mac != "" {
		return h.mac
	}
	return h.fallback
}
