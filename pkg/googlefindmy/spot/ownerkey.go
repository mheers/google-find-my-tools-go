package spot

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/auth"
	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/crypto"
)

// GetOwnerKey fetches, decrypts, and caches the owner key. It first checks
// the auth store for a cached owner key. If missing, it calls the Spot API
// to get the encrypted owner key, decrypts it with the shared key, and
// caches the result.
//
// The spotClient must be configured with a token source that provides a
// Spot bearer token (scope "spot", playServices=true).
func GetOwnerKey(ctx context.Context, authStore *auth.Store) ([]byte, error) {
	secrets, err := authStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load secrets: %w", err)
	}
	if secrets == nil {
		return nil, fmt.Errorf("secrets not found; run 'gauthenticate' first")
	}

	// Check cache.
	if secrets.OwnerKey != "" {
		key, err := hex.DecodeString(secrets.OwnerKey)
		if err == nil && len(key) > 0 {
			return key, nil
		}
	}

	// Need shared key.
	if secrets.SharedKey == "" {
		return nil, fmt.Errorf("shared key not found; re-run 'gauthenticate'")
	}
	sharedKey, err := hex.DecodeString(secrets.SharedKey)
	if err != nil {
		return nil, fmt.Errorf("decode shared key: %w", err)
	}

	// Get spot bearer token from the master aas_token.
	spotToken, err := auth.RequestScopeToken(secrets.Username, secrets.AASToken, "0", "spot", true)
	if err != nil {
		return nil, fmt.Errorf("get spot token: %w", err)
	}

	// Create spot client and fetch encrypted owner key.
	spotClient := NewClient(func(ctx context.Context) (string, error) {
		return spotToken, nil
	})

	resp, err := spotClient.GetEidInfoForE2eeDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("get eid info: %w", err)
	}

	encryptedOwnerKey := resp.GetEncryptedOwnerKeyAndMetadata().GetEncryptedOwnerKey()
	if len(encryptedOwnerKey) == 0 {
		return nil, fmt.Errorf("empty encrypted owner key in response")
	}

	// Decrypt.
	ownerKey, err := crypto.DecryptOwnerKey(sharedKey, encryptedOwnerKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt owner key: %w", err)
	}

	// Cache.
	secrets.OwnerKey = hex.EncodeToString(ownerKey)
	if err := authStore.Save(secrets); err != nil {
		return nil, fmt.Errorf("cache owner key: %w", err)
	}

	return ownerKey, nil
}
