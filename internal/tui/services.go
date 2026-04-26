package tui

import (
	"fmt"
	"sort"
	"strings"

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
		instLabel := "instance"
		if count != 1 {
			instLabel = "instances"
		}
		hostList := strings.Join(hosts, ", ")
		key := padRight(styleAccent.Render(k), 22)
		b.WriteString(fmt.Sprintf("%s  %d %s  →  %s\n", key, count, instLabel, hostList))
	}
	return b.String()
}

// groupServices builds map[serviceType] = []hostLabel from the devices.
// Service type can come from either mDNS Services or open-port labels.
func groupServices(devices []*model.Device) map[string][]string {
	groups := map[string]map[string]struct{}{}
	for _, d := range devices {
		host := d.Hostname
		if host == "" {
			host = firstIP(d)
		}
		for _, s := range d.Services {
			if _, ok := groups[s.Type]; !ok {
				groups[s.Type] = map[string]struct{}{}
			}
			groups[s.Type][host] = struct{}{}
		}
		for _, p := range d.OpenPorts {
			label := fmt.Sprintf("%d/%s", p.Number, p.Proto)
			if p.Service != "" {
				label = fmt.Sprintf("%d/%s (%s)", p.Number, p.Proto, p.Service)
			}
			if _, ok := groups[label]; !ok {
				groups[label] = map[string]struct{}{}
			}
			groups[label][host] = struct{}{}
		}
	}
	out := map[string][]string{}
	for k, set := range groups {
		hosts := make([]string, 0, len(set))
		for h := range set {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		out[k] = hosts
	}
	return out
}
