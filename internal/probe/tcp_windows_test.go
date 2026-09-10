// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package probe

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsConnectionRefusedWindows(t *testing.T) {
	// Go wraps the Winsock error from ConnectEx in both error types.
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{
		Syscall: "connectex", Err: windows.WSAECONNREFUSED,
	}}
	if !isConnectionRefused(refused) {
		t.Fatal("wrapped Winsock connection refusal must count as alive")
	}
	for _, err := range []error{nil, windows.WSAETIMEDOUT, windows.WSAENETUNREACH,
		&net.OpError{Op: "dial", Net: "tcp", Err: windows.WSAEHOSTUNREACH}} {
		if isConnectionRefused(err) {
			t.Errorf("non-refusal error %v must not count as alive", err)
		}
	}
}
