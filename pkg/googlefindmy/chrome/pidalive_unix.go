// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

//go:build unix

package chrome

import (
	"errors"
	"syscall"
)

// processAlive reports whether a local process with pid exists. Signal 0
// performs the permission and existence checks without delivering a signal;
// EPERM still proves the process exists.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
