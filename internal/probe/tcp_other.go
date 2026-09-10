// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !windows

package probe

import (
	"errors"
	"syscall"
)

func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
