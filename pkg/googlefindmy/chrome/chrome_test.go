// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package chrome

import "testing"

func TestNoSandboxOptIn(t *testing.T) {
	t.Setenv(NoSandboxEnv, "")

	if (Config{}).noSandbox() {
		t.Error("--no-sandbox must be off by default")
	}
	if !(Config{NoSandbox: true}).noSandbox() {
		t.Error("--no-sandbox must be enabled when requested")
	}

	t.Setenv(NoSandboxEnv, "1")
	if !(Config{}).noSandbox() {
		t.Error("--no-sandbox must be enabled by the environment variable")
	}
}

func TestAllocatorOptions(t *testing.T) {
	opts := Config{Headless: true, DisableGPU: true, WindowSize: "1280,720"}.AllocatorOptions()
	if len(opts) == 0 {
		t.Fatal("expected allocator options")
	}
}

func TestAllocatorFlags(t *testing.T) {
	flags := Config{UserDataDir: "/tmp/findhub-profile"}.initFlags()

	if got, ok := flags["enable-automation"]; !ok || got != false {
		t.Errorf("enable-automation = %v, want false", got)
	}
	if got := flags["disable-blink-features"]; got != "AutomationControlled" {
		t.Errorf("disable-blink-features = %v, want AutomationControlled", got)
	}
	if got := flags["user-data-dir"]; got != "/tmp/findhub-profile" {
		t.Errorf("user-data-dir = %v, want /tmp/findhub-profile", got)
	}
	for _, name := range []string{"password-store", "use-mock-keychain"} {
		if got, ok := flags[name]; !ok || got != false {
			t.Errorf("%s = %v, want false (keyring encryption must match the profile)", name, got)
		}
	}

	if _, ok := (Config{}).initFlags()["user-data-dir"]; ok {
		t.Error("user-data-dir must be omitted when UserDataDir is empty")
	}
}
