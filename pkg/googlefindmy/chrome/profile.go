// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package chrome

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SingletonLockName is the lock Chrome keeps in a user-data-dir while an
// instance is using it.
const SingletonLockName = "SingletonLock"

// CheckProfileFree returns an error when another Chrome instance holds the
// profile in dir. Chrome allows a single instance per profile directory: a
// second launch is handed to the running instance, which the automation cannot
// control and which surfaces only as chromedp's "chrome failed to start:
// Opening in existing browser session".
//
// Stale locks are left to Chrome, which breaks them itself; a lock is reported
// only when it names a live process on this host.
func CheckProfileFree(dir string) error {
	if dir == "" {
		return nil
	}
	pid, ok := profileOwner(dir)
	if !ok {
		return nil
	}
	return fmt.Errorf("%w: chrome profile %s is used by another Chrome instance (pid %d); close that window and retry", ErrProfileInUse, dir, pid)
}

// profileOwner reads the profile's SingletonLock and returns the owning PID
// when it belongs to a live process on this host.
func profileOwner(dir string) (int, bool) {
	target, err := os.Readlink(filepath.Join(dir, SingletonLockName))
	if err != nil {
		return 0, false
	}
	host, pid, ok := parseSingletonLock(target)
	if !ok {
		return 0, false
	}
	if local, err := os.Hostname(); err != nil || host != local {
		// Lock owned by another machine (e.g. a network home); Chrome decides.
		return 0, false
	}
	if !processAlive(pid) {
		return 0, false
	}
	return pid, true
}

// parseSingletonLock splits a lock target of the form "<host>-<pid>".
// Hostnames may contain dashes, so the PID is the part after the last dash.
func parseSingletonLock(target string) (host string, pid int, ok bool) {
	i := strings.LastIndex(target, "-")
	if i <= 0 || i == len(target)-1 {
		return "", 0, false
	}
	pid, err := strconv.Atoi(target[i+1:])
	if err != nil || pid <= 0 {
		return "", 0, false
	}
	return target[:i], pid, true
}

// ErrProfileInUse is returned by CheckProfileFree when the profile is locked.
var ErrProfileInUse = errors.New("chrome profile in use")
