// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/netiface"
	"github.com/lab1702/lan-inventory/internal/scanner"
	"github.com/lab1702/lan-inventory/internal/snapshot"
	"github.com/lab1702/lan-inventory/internal/tui"
)

const version = "0.1.0"

const (
	exitOK        = 0
	exitRuntime   = 1
	exitConfig    = 2
	exitNoDevices = 3
)

func main() {
	once := flag.Bool("once", false, "run a single scan, print result, exit")
	table := flag.Bool("table", false, "with --once: print human-readable table instead of JSON")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("lan-inventory %s\n", version)
		os.Exit(exitOK)
	}

	iface, err := netiface.Detect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", err)
		os.Exit(exitConfig)
	}

	if err := scanner.Precheck(iface.Name); err != nil {
		fmt.Fprintln(os.Stderr, "lan-inventory: needs raw socket access to sniff ARP and send ICMP.")
		fmt.Fprintln(os.Stderr, "Either run with sudo, or grant capabilities once:")
		fmt.Fprintln(os.Stderr, "    sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)")
		os.Exit(exitConfig)
	}

	if *once {
		os.Exit(runOnce(iface, *table))
	}
	os.Exit(runTUI(iface))
}

func runOnce(iface *netiface.Info, asTable bool) int {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	scn := scanner.New(scanner.Config{Iface: iface})
	doneEvents := make(chan struct{})
	go func() {
		for range scn.Events() {
		}
		close(doneEvents)
	}()
	go scn.Run(ctx)

	// Spec: "starts ARP and mDNS listeners, waits 8 seconds for passive
	// signals, runs one full active sweep, snapshots, and exits." The
	// ActiveWorker kicks off its initial sweep on Run(); a full /24 sweep
	// with 32 workers and 1 s per-host ping timeout takes up to ~15 s for
	// fully dead subnets. We give the whole thing 20 s of wall time, which
	// covers passive warmup + active sweep on typical home LANs.
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	cancel()
	<-doneEvents

	devices := scn.Snapshot()
	if len(devices) == 0 {
		fmt.Fprintln(os.Stderr, "lan-inventory: no devices discovered")
		return exitNoDevices
	}

	header := snapshot.Header{
		ScannedAt: time.Now().UTC(),
		Subnet:    iface.Subnet.String(),
		Iface:     iface.Name,
	}
	if asTable {
		isTTY := isTerminal(os.Stdout)
		if err := snapshot.WriteTable(os.Stdout, devices, isTTY); err != nil {
			fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", err)
			return exitRuntime
		}
	} else {
		if err := snapshot.WriteJSON(os.Stdout, header, devices); err != nil {
			fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", err)
			return exitRuntime
		}
	}
	return exitOK
}

func runTUI(iface *netiface.Info) int {
	ctx, cancel := signalContext()
	defer cancel()

	scn := scanner.New(scanner.Config{Iface: iface})
	go scn.Run(ctx)

	deps := tui.Deps{
		Subnet:   iface.Subnet.String(),
		Iface:    iface.Name,
		Snapshot: scn.Snapshot,
		Events:   func() <-chan model.DeviceEvent { return scn.Events() },
		OnRescan: func() { go scn.TriggerSweep(ctx) },
	}
	prog := tea.NewProgram(tui.NewModel(deps), tea.WithAltScreen())
	if _, err := prog.Run(); err != nil {
		if errors.Is(err, context.Canceled) {
			return exitOK
		}
		fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", err)
		return exitRuntime
	}
	return exitOK
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}