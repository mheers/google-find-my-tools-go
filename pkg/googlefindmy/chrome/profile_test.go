// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package chrome

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestParseSingletonLock(t *testing.T) {
	host, pid, ok := parseSingletonLock("marcel-framework-3736015")
	if !ok || host != "marcel-framework" || pid != 3736015 {
		t.Fatalf("parseSingletonLock = %q, %d, %v", host, pid, ok)
	}

	for _, invalid := range []string{"", "no-pid", "host-", "-123", "host-abc", "host-0"} {
		if _, _, ok := parseSingletonLock(invalid); ok {
			t.Errorf("parseSingletonLock(%q) should fail", invalid)
		}
	}
}

func TestCheckProfileFree(t *testing.T) {
	if err := CheckProfileFree(""); err != nil {
		t.Fatalf("empty profile dir should be free: %v", err)
	}

	dir := t.TempDir()
	if err := CheckProfileFree(dir); err != nil {
		t.Fatalf("dir without a lock should be free: %v", err)
	}

	host, err := os.Hostname()
	if err != nil {
		t.Skipf("hostname: %v", err)
	}
	lock := filepath.Join(dir, SingletonLockName)

	if err := os.Symlink(host+"-"+strconv.Itoa(os.Getpid()), lock); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	err = CheckProfileFree(dir)
	if err == nil {
		t.Fatal("live lock should be reported")
	}
	if !errors.Is(err, ErrProfileInUse) {
		t.Fatalf("error should wrap ErrProfileInUse: %v", err)
	}

	// A lock from another host (e.g. a network home) is left to Chrome.
	_ = os.Remove(lock)
	if err := os.Symlink("other-host-"+strconv.Itoa(os.Getpid()), lock); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if err := CheckProfileFree(dir); err != nil {
		t.Fatalf("lock from another host should be ignored: %v", err)
	}

	// A stale lock (dead PID) must not block a launch.
	_ = os.Remove(lock)
	if err := os.Symlink(host+"-999999999", lock); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if err := CheckProfileFree(dir); err != nil {
		t.Fatalf("stale lock should be ignored: %v", err)
	}
}
