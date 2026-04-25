package scanner

import (
	"context"
	"net"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

// Update is what a Worker emits to the merger. Every field except Source is
// optional; the merger merges non-zero fields into the Device.
type Update struct {
	Source     string             // "arp" | "mdns" | "active"
	Time       time.Time          // when the observation happened
	MAC        string             // lowercase, colon-separated; "" if unknown
	IP         net.IP             // required for nearly every update
	Hostname   string             // mDNS or rDNS
	Vendor     string             // OUI lookup may have already been applied
	OSGuess    string             // active prober only
	OpenPorts  []model.Port       // active prober only; empty replaces existing
	Services   []model.ServiceInst // mDNS only; appended/deduped
	RTT        time.Duration      // active prober only
	Alive      bool               // active prober: is the device responding?
}

// A Worker emits Updates on its output channel until the context is cancelled.
// Implementations: arpWorker, mdnsWorker, activeWorker.
type Worker interface {
	Run(ctx context.Context, out chan<- Update) error
}
