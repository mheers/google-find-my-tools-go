// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

//go:build !unix

package chrome

// processAlive cannot check other platforms reliably, so it reports false and
// lets Chrome resolve its own lock (a stale lock can never block a launch).
func processAlive(int) bool { return false }
