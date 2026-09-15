// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
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

func TestUpdateCreatesFile(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Update(func(s *Secrets) error {
		s.Username = "user@example.com"
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil || got.Username != "user@example.com" {
		t.Fatalf("secrets = %#v", got)
	}
}

// TestUpdateIsAtomic runs concurrent updates against distinct fields; without
// an atomic load-modify-save both fields would lose writes.
func TestUpdateIsAtomic(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const perField = 50
	var wg sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		field := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perField; i++ {
				err := store.Update(func(s *Secrets) error {
					if field == 0 {
						n, _ := strconv.Atoi(s.Username)
						s.Username = strconv.Itoa(n + 1)
					} else {
						n, _ := strconv.Atoi(s.OAuthToken)
						s.OAuthToken = strconv.Itoa(n + 1)
					}
					return nil
				})
				if err != nil {
					t.Errorf("Update: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("secrets missing after updates")
	}
	if got.Username != strconv.Itoa(perField) || got.OAuthToken != strconv.Itoa(perField) {
		t.Fatalf("lost updates: username=%q oauth_token=%q, want %d for both",
			got.Username, got.OAuthToken, perField)
	}
}

func TestUpdatePropagatesErrorWithoutWriting(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	sentinel := errors.New("stop")
	err = store.Update(func(s *Secrets) error {
		s.Username = "should-not-be-persisted"
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Update error = %v, want %v", err, sentinel)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Fatalf("secrets should not have been written: %#v", got)
	}
}

func TestClearIsIdempotent(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.Clear(); err != nil {
		t.Fatalf("Clear on a missing file: %v", err)
	}
	if err := store.Update(func(s *Secrets) error { s.Username = "u"; return nil }); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if err := store.Clear(); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
}

func TestExistsReflectsFileState(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if store.Exists() {
		t.Fatal("Exists = true for a missing file")
	}
	if err := store.Update(func(s *Secrets) error { s.Username = "u"; return nil }); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !store.Exists() {
		t.Fatal("Exists = false after writing secrets")
	}
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if store.Exists() {
		t.Fatal("Exists = true after Clear")
	}
}
