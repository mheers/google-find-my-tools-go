// Package auth manages the secrets.json credential store for Google Find My API.
// Thread-safe, atomic writes. Replaces Python Auth/token_cache.py.
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

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

	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// Exists returns true if secrets.json exists.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Clear removes secrets.json.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.Remove(s.path)
}
