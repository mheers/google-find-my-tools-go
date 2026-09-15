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
}

// AllocatorOptions returns the chromedp exec-allocator options for the config.
func (c Config) AllocatorOptions() []chromedp.ExecAllocatorOption {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", c.Headless),
	)
	if c.noSandbox() {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
	if c.DisableDevShmUsage {
		opts = append(opts, chromedp.Flag("disable-dev-shm-usage", true))
	}
	if c.DisableGPU {
		opts = append(opts, chromedp.Flag("disable-gpu", true))
	}
	if c.WindowSize != "" {
		opts = append(opts, chromedp.Flag("window-size", c.WindowSize))
	}
	return opts
}

func (c Config) noSandbox() bool {
	return c.NoSandbox || os.Getenv(NoSandboxEnv) == "1"
}
