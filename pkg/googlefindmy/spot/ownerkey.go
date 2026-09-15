// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package spot

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/auth"
	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/crypto"
	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/fcm"
)

// androidIDFromSecrets extracts the decimal FCM android ID from the stored
// credentials. Google binds scope tokens to the android ID used during FCM
// registration, so the real value must be sent (not a placeholder).
func androidIDFromSecrets(secrets *auth.Secrets) (string, error) {
	if len(secrets.FCMCredentials) == 0 {
		return "", fmt.Errorf("%w: fcm credentials missing; register for FCM first", auth.ErrSecretsNotFound)
	}
	var creds fcm.FCMCredentials
	if err := json.Unmarshal(secrets.FCMCredentials, &creds); err != nil {
		return "", fmt.Errorf("parse fcm credentials: %w", err)
	}
	if creds.GCM == nil || creds.GCM.AndroidID == 0 {
		return "", fmt.Errorf("%w: fcm credentials do not contain an android id", auth.ErrSecretsNotFound)
	}
	return strconv.FormatUint(uint64(creds.GCM.AndroidID), 10), nil
}

// GetOwnerKey fetches, decrypts, and caches the owner key. It first checks
// the auth store for a cached owner key. If missing, it calls the Spot API
// to get the encrypted owner key, decrypts it with the shared key, and
// caches the result.
//
// The spot client uses a bearer token derived with the FCM android ID stored
// in the credentials (scope "spot", playServices=true).
func GetOwnerKey(ctx context.Context, authStore *auth.Store) ([]byte, error) {
	secrets, err := authStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load secrets: %w", err)
	}
	if secrets == nil {
		return nil, fmt.Errorf("%w: run the authentication flow first", auth.ErrSecretsNotFound)
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
		return nil, fmt.Errorf("%w: shared key missing; re-run the authentication flow", auth.ErrSecretsNotFound)
	}
	sharedKey, err := hex.DecodeString(secrets.SharedKey)
	if err != nil {
		return nil, fmt.Errorf("decode shared key: %w", err)
	}

	// Scope tokens are bound to the android ID used for FCM registration.
	androidID, err := androidIDFromSecrets(secrets)
	if err != nil {
		return nil, err
	}

	// Get spot bearer token from the master aas_token.
	spotToken, err := auth.RequestScopeToken(ctx, secrets.Username, secrets.AASToken, androidID, "spot", true)
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
	if err := authStore.Update(func(stored *auth.Secrets) error {
		stored.OwnerKey = hex.EncodeToString(ownerKey)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("cache owner key: %w", err)
	}

	return ownerKey, nil
}
