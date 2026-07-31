package savedplaces

import (
	"encoding/json"
	"fmt"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/auth"
)

// LoadMapsCookies extracts the Maps cookies from an auth store, supporting
// both raw JSON map and the legacy JSON-string-wrapped representation.
func LoadMapsCookies(store *auth.Store) (map[string]string, error) {
	secrets, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("load secrets: %w", err)
	}
	if secrets == nil || secrets.MapsCookies == nil {
		return nil, fmt.Errorf("maps cookies not found — run 'gmauthenticate' first")
	}
	var cookies map[string]string
	if err := json.Unmarshal(secrets.MapsCookies, &cookies); err != nil {
		var s string
		if err2 := json.Unmarshal(secrets.MapsCookies, &s); err2 != nil {
			return nil, fmt.Errorf("parse maps cookies: %w", err)
		}
		if err2 := json.Unmarshal([]byte(s), &cookies); err2 != nil {
			return nil, fmt.Errorf("parse maps cookies (legacy): %w", err2)
		}
	}
	return cookies, nil
}
