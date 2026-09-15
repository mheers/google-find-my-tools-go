package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewStoreCreatesPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "credentials")
	store, err := NewStore(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if store == nil {
		t.Fatal("NewStore returned nil store")
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat secrets dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("secrets dir permissions = %o, want 700", got)
	}
}

func TestNewStoreFailsWhenDirectoryCannotBeCreated(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := NewStore(filepath.Join(file, "secrets.json")); err == nil {
		t.Fatal("expected an error when the parent path is a regular file")
	}
}
