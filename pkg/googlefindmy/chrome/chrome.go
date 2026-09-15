// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

// Package chrome holds the shared Chrome/Chromium launch configuration used by
// the browser automation flows (OAuth, Maps and Saved Lists).
package chrome

import (
	"os"

	"github.com/chromedp/chromedp"
)

// NoSandboxEnv is the environment variable that forces --no-sandbox. It is
// intended for containers and CI where Chrome's sandbox cannot be used.
const NoSandboxEnv = "GOOGLEFINDMY_CHROME_NO_SANDBOX"

// Config describes how the automation Chrome instance is launched.
type Config struct {
	// Headless runs Chrome without a visible window. Interactive login flows
	// need a visible window.
	Headless bool
	// NoSandbox disables Chrome's sandbox. This removes the main security
	// boundary of the browser and should only be enabled in containers where
	// the sandbox is unavailable; on normal machines leave it false. It can
	// also be forced with GOOGLEFINDMY_CHROME_NO_SANDBOX=1.
	NoSandbox bool
	// DisableDevShmUsage avoids small /dev/shm mounts.
	DisableDevShmUsage bool
	// DisableGPU turns off GPU acceleration (useful for headless servers).
	DisableGPU bool
	// WindowSize sets the initial window size, e.g. "1280,720".
	WindowSize string
	// UserDataDir makes Chrome reuse a persistent profile instead of the
	// throwaway temporary directory chromedp creates for every run. The
	// interactive sign-in flows need it: against a fresh profile, every run
	// is a stranger to Google and the sign-in is refused with "This browser
	// or app may not be secure". Sign in to the directory once with a normal
	// Chrome (`google-chrome --user-data-dir=<dir>`), close it, and later
	// runs reuse the stored session. Empty keeps chromedp's temporary
	// profile.
	UserDataDir string
}

// initFlags returns the Chrome command-line flags for the config. It is a
// separate step from AllocatorOptions so the flags stay testable.
func (c Config) initFlags() map[string]any {
	flags := map[string]any{
		"headless": c.Headless,
		// chromedp's defaults mark the browser as automation-controlled
		// (--enable-automation). Google's sign-in pages reject such browsers,
		// so turn the flag off and hide the corresponding Blink feature.
		"enable-automation":      false,
		"disable-blink-features": "AutomationControlled",
		// chromedp forces --password-store=basic and --use-mock-keychain to
		// avoid keyring prompts. Those change how Chrome encrypts cookies, so
		// a profile signed in by a normal Chrome cannot be decrypted by the
		// automation and the account appears signed out (and the cookies are
		// dropped). Drop both flags so Chrome uses the system keyring, like
		// the launch that primed the profile.
		"password-store":    false,
		"use-mock-keychain": false,
	}
	if c.noSandbox() {
		flags["no-sandbox"] = true
	}
	if c.DisableDevShmUsage {
		flags["disable-dev-shm-usage"] = true
	}
	if c.DisableGPU {
		flags["disable-gpu"] = true
	}
	if c.WindowSize != "" {
		flags["window-size"] = c.WindowSize
	}
	if c.UserDataDir != "" {
		flags["user-data-dir"] = c.UserDataDir
	}
	return flags
}

// AllocatorOptions returns the chromedp exec-allocator options for the config.
func (c Config) AllocatorOptions() []chromedp.ExecAllocatorOption {
	opts := make([]chromedp.ExecAllocatorOption, 0, len(chromedp.DefaultExecAllocatorOptions)+8)
	opts = append(opts, chromedp.DefaultExecAllocatorOptions[:]...)
	for name, value := range c.initFlags() {
		opts = append(opts, chromedp.Flag(name, value))
	}
	return opts
}

func (c Config) noSandbox() bool {
	return c.NoSandbox || os.Getenv(NoSandboxEnv) == "1"
}
