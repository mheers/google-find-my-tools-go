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
