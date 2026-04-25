package scanner

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

// MergerOptions tunes the merger's timing behavior.
type MergerOptions struct {
	StaleAfter    time.Duration // Online → Stale after this idle period (default 60s)
	LeftAfter     time.Duration // Stale → Offline + emit Left after this idle period (default 5m)
	SweepInterval time.Duration // how often to scan for status transitions (default 30s)
}

func (o *MergerOptions) defaults() {
	if o.StaleAfter == 0 {
		o.StaleAfter = 60 * time.Second
	}
	if o.LeftAfter == 0 {
		o.LeftAfter = 5 * time.Minute
	}
	if o.SweepInterval == 0 {
		o.SweepInterval = 30 * time.Second
	}
}

// Merger owns the live device map and emits DeviceEvents.
type Merger struct {
	opts MergerOptions

	mu      sync.RWMutex
	byMAC   map[string]*model.Device
	byIP    map[string]*model.Device // for MAC-less entries
}

// NewMerger constructs an idle merger; call Run to start consuming updates.
func NewMerger(opts MergerOptions) *Merger {
	opts.defaults()
	return &Merger{
		opts:  opts,
		byMAC: make(map[string]*model.Device),
		byIP:  make(map[string]*model.Device),
	}
}

// Snapshot returns a copy of all devices in arbitrary order.
func (m *Merger) Snapshot() []*model.Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*model.Device, 0, len(m.byMAC)+len(m.byIP))
	for _, d := range m.byMAC {
		out = append(out, copyDevice(d))
	}
	for _, d := range m.byIP {
		out = append(out, copyDevice(d))
	}
	return out
}

// Run consumes updates from in and publishes events to out. Returns when ctx
// is cancelled.
func (m *Merger) Run(ctx context.Context, in <-chan Update, out chan<- model.DeviceEvent) {
	ticker := time.NewTicker(m.opts.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-in:
			if !ok {
				return
			}
			m.handleUpdate(u, out)
		case now := <-ticker.C:
			m.sweepStatus(now, out)
		}
	}
}

func (m *Merger) handleUpdate(u Update, out chan<- model.DeviceEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mac := strings.ToLower(u.MAC)
	ipKey := ""
	if u.IP != nil {
		ipKey = u.IP.String()
	}

	var dev *model.Device
	created := false

	switch {
	case mac != "":
		// MAC-keyed path. If we have a preceding IP-only entry for this IP, fold it in.
		if existing, ok := m.byMAC[mac]; ok {
			dev = existing
		} else {
			dev = &model.Device{MAC: mac, FirstSeen: u.Time, Status: model.StatusOnline}
			created = true
			m.byMAC[mac] = dev
		}
		// Migrate IP-only entry if present — the device was already known under
		// the IP key, so this is a refinement (Updated), not a new sighting (Joined).
		if ipKey != "" {
			if old, ok := m.byIP[ipKey]; ok && old != dev {
				mergeFromIPOnly(dev, old)
				delete(m.byIP, ipKey)
				created = false
			}
		}
	case ipKey != "":
		if existing, ok := m.byIP[ipKey]; ok {
			dev = existing
		} else {
			dev = &model.Device{FirstSeen: u.Time, Status: model.StatusOnline}
			created = true
			m.byIP[ipKey] = dev
		}
	default:
		return // can't key this update
	}

	mergeUpdate(dev, u)

	evt := model.DeviceEvent{Device: copyDevice(dev)}
	if created {
		evt.Type = model.EventJoined
	} else {
		evt.Type = model.EventUpdated
	}
	select {
	case out <- evt:
	default:
		// drop if consumer is slow; the live map is still authoritative
	}
}

// sweepStatus updates device statuses based on age (now - LastSeen):
//   - Online (≤ StaleAfter)
//   - Stale  (StaleAfter < age ≤ LeftAfter)
//   - Offline (age > LeftAfter) — emits EventLeft on the transition
func (m *Merger) sweepStatus(now time.Time, out chan<- model.DeviceEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	staleCut := now.Add(-m.opts.StaleAfter)
	leftCut := now.Add(-m.opts.LeftAfter)

	transition := func(d *model.Device) {
		switch {
		case d.LastSeen.Before(leftCut):
			if d.Status != model.StatusOffline {
				d.Status = model.StatusOffline
				select {
				case out <- model.DeviceEvent{Type: model.EventLeft, Device: copyDevice(d)}:
				default:
				}
			}
		case d.LastSeen.Before(staleCut):
			if d.Status == model.StatusOnline {
				d.Status = model.StatusStale
			}
		}
	}
	for _, d := range m.byMAC {
		transition(d)
	}
	for _, d := range m.byIP {
		transition(d)
	}
}

// mergeUpdate applies non-zero fields of u onto dev.
func mergeUpdate(dev *model.Device, u Update) {
	if u.IP != nil {
		if !containsIP(dev.IPs, u.IP) {
			dev.IPs = append(dev.IPs, u.IP)
		}
	}
	if u.MAC != "" && dev.MAC == "" {
		dev.MAC = strings.ToLower(u.MAC)
	}
	if u.Hostname != "" {
		dev.Hostname = u.Hostname
	}
	if u.Vendor != "" {
		dev.Vendor = u.Vendor
	}
	if u.OSGuess != "" {
		dev.OSGuess = u.OSGuess
	}
	if u.OpenPorts != nil {
		dev.OpenPorts = u.OpenPorts
	}
	for _, s := range u.Services {
		if !containsService(dev.Services, s) {
			dev.Services = append(dev.Services, s)
		}
	}
	if u.RTT > 0 {
		dev.RTT = u.RTT
		dev.RTTHistory = append(dev.RTTHistory, u.RTT)
		if len(dev.RTTHistory) > 10 {
			dev.RTTHistory = dev.RTTHistory[len(dev.RTTHistory)-10:]
		}
	}
	if u.Time.After(dev.LastSeen) {
		dev.LastSeen = u.Time
	}
	if dev.FirstSeen.IsZero() {
		dev.FirstSeen = u.Time
	}
	// Any received update means we just heard from the device — Online.
	// The sweep handles decay back to Stale/Offline based on age.
	dev.Status = model.StatusOnline
	sort.Slice(dev.OpenPorts, func(i, j int) bool { return dev.OpenPorts[i].Number < dev.OpenPorts[j].Number })
}

func mergeFromIPOnly(dst, src *model.Device) {
	for _, ip := range src.IPs {
		if !containsIP(dst.IPs, ip) {
			dst.IPs = append(dst.IPs, ip)
		}
	}
	if dst.Hostname == "" {
		dst.Hostname = src.Hostname
	}
	if dst.OSGuess == "" {
		dst.OSGuess = src.OSGuess
	}
	if len(dst.OpenPorts) == 0 {
		dst.OpenPorts = src.OpenPorts
	}
	for _, s := range src.Services {
		if !containsService(dst.Services, s) {
			dst.Services = append(dst.Services, s)
		}
	}
	if dst.RTT == 0 {
		dst.RTT = src.RTT
	}
	if len(dst.RTTHistory) == 0 {
		dst.RTTHistory = src.RTTHistory
	}
	if src.FirstSeen.Before(dst.FirstSeen) || dst.FirstSeen.IsZero() {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
}

func containsIP(list []net.IP, ip net.IP) bool {
	for _, x := range list {
		if x.Equal(ip) {
			return true
		}
	}
	return false
}

func containsService(list []model.ServiceInst, s model.ServiceInst) bool {
	for _, x := range list {
		if x.Type == s.Type && x.Name == s.Name && x.Port == s.Port {
			return true
		}
	}
	return false
}

func copyDevice(d *model.Device) *model.Device {
	cp := *d
	cp.IPs = append([]net.IP(nil), d.IPs...)
	cp.OpenPorts = append([]model.Port(nil), d.OpenPorts...)
	cp.Services = append([]model.ServiceInst(nil), d.Services...)
	cp.RTTHistory = append([]time.Duration(nil), d.RTTHistory...)
	return &cp
}
