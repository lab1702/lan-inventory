// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package probe

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isConnectionRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
