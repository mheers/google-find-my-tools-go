// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

// Package auth manages the secrets.json credential store for Google Find My API.
// Thread-safe, atomic writes. Replaces Python Auth/token_cache.py.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrSecretsNotFound indicates that the credential store is missing data
// required for the requested operation (e.g. the file does not exist yet or a
// required token was never stored). Use errors.Is to test for it.
var ErrSecretsNotFound = errors.New("auth: secrets not found")

// Secrets holds all tokens/credentials needed for the Find My API.
type Secrets struct {
	OAuthToken     string          `json:"oauth_token"`
	AASToken       string          `json:"aas_token"`
	Username       string          `json:"username"`
	SharedKey      string          `json:"shared_key,omitempty"` // hex-encoded
	OwnerKey       string          `json:"owner_key,omitempty"`  // hex-encoded
	FCMCredentials json.RawMessage `json:"fcm_credentials,omitempty"`
	MapsCookies    json.RawMessage `json:"maps_cookies,omitempty"`
}

// Store reads and writes secrets.json atomically.
type Store struct {
	path string
	mu   sync.RWMutex
}

// NewStore creates a Store for the given secrets.json path. The parent
// directory is created with 0700 permissions if needed; secrets files must
// not be readable by other users.
func NewStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create secrets dir: %w", err)
	}
	return &Store{path: path}, nil
}

// Load reads secrets.json. Returns nil, nil if file doesn't exist.
func (s *Store) Load() (*Secrets, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (*Secrets, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("load secrets: %w", err)
	}

	var secrets Secrets
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("parse secrets: %w", err)
	}
	return &secrets, nil
}

// Save writes secrets.json atomically (temp file + rename).
func (s *Store) Save(secrets *Secrets) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(secrets)
}

// Update atomically applies fn to the stored secrets and writes the result,
// creating an empty Secrets when the file does not exist yet. Callers must not
// call Store methods from fn (the lock is held for the duration).
func (s *Store) Update(fn func(*Secrets) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	secrets, err := s.loadLocked()
	if err != nil {
		return err
	}
	if secrets == nil {
		secrets = &Secrets{}
	}
	if err := fn(secrets); err != nil {
		return err
	}
	return s.saveLocked(secrets)
}

func (s *Store) saveLocked(secrets *Secrets) error {
	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	// fsync the directory so the rename survives a crash.
	if dir, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// Exists returns true if secrets.json exists.
func (s *Store) Exists() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := os.Stat(s.path)
	return err == nil
}

// Clear removes secrets.json. It is a no-op when the file does not exist.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
