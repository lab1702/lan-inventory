// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
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

	if err := scanner.Precheck(iface); err != nil {
		fmt.Fprintln(os.Stderr, "lan-inventory: needs packet-capture access on this interface.")
		switch runtime.GOOS {
		case "linux":
			fmt.Fprintln(os.Stderr, "Either run with sudo, or grant capabilities once:")
			fmt.Fprintln(os.Stderr, "    sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)")
		case "windows":
			fmt.Fprintln(os.Stderr, "Install Npcap from https://npcap.com/")
			fmt.Fprintln(os.Stderr, `(check "WinPcap API-compatible mode" during install).`)
			fmt.Fprintln(os.Stderr, "The driver grants user-level capture; no per-run Administrator needed.")
		case "darwin":
			fmt.Fprintln(os.Stderr, "Either install Wireshark's ChmodBPF helper")
			fmt.Fprintln(os.Stderr, "(brew install --cask wireshark), or run with sudo:")
			fmt.Fprintln(os.Stderr, "    sudo lan-inventory")
		default:
			fmt.Fprintln(os.Stderr, "This platform may need additional privileges to open packet capture.")
			fmt.Fprintln(os.Stderr, "Consult your OS docs for how to grant raw-socket / pcap access.")
		}
		os.Exit(exitConfig)
	}

	if *once {
		os.Exit(runOnce(iface, *table))
	}
	os.Exit(runTUI(iface))
}

func runOnce(iface *netiface.Info, asTable bool) int {
	ctx, cancel := signalContext()
	defer cancel()

	scn := scanner.New(scanner.Config{Iface: iface})
	doneEvents := make(chan struct{})
	go func() {
		for range scn.Events() {
		}
		close(doneEvents)
	}()
	err := scn.RunOnce(ctx)
	<-doneEvents
	if err != nil {
		fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", err)
		return exitRuntime
	}

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

	deps := tui.Deps{
		Subnet:   iface.Subnet.String(),
		Iface:    iface.Name,
		Snapshot: scn.Snapshot,
		Events:   func() <-chan model.DeviceEvent { return scn.Events() },
		OnRescan: func() { scn.TriggerSweep(ctx) },
	}
	prog := tea.NewProgram(tui.NewModel(deps), tea.WithAltScreen(), tea.WithContext(ctx))
	scanDone := make(chan error, 1)
	go func() {
		err := scn.Run(ctx)
		scanDone <- err
		if err != nil && !errors.Is(err, context.Canceled) {
			cancel()
		}
	}()
	_, uiErr := prog.Run()
	cancel()
	scanErr := <-scanDone
	if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
		fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", scanErr)
		return exitRuntime
	}
	if uiErr != nil && !errors.Is(uiErr, tea.ErrProgramKilled) && !errors.Is(uiErr, context.Canceled) {
		fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", uiErr)
		return exitRuntime
	}
	return exitOK
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
			// Caller cancelled (e.g. normal TUI quit) — unwind instead of
			// parking on <-ch forever.
		}
		signal.Stop(ch)
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
