// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package spot

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/auth"
)

func TestAndroidIDFromSecrets(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"number form", `{"gcm":{"android_id":123456789,"security_token":7}}`, "123456789", false},
		{"python string form", `{"gcm":{"android_id":"987654321","security_token":"7"}}`, "987654321", false},
		{"no credentials", ``, "", true},
		{"invalid json", `not-json`, "", true},
		{"missing gcm", `{"keys":{"public":"x"}}`, "", true},
		{"zero android id", `{"gcm":{"android_id":0}}`, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secrets := &auth.Secrets{}
			if tc.raw != "" {
				secrets.FCMCredentials = json.RawMessage(tc.raw)
			}
			got, err := androidIDFromSecrets(secrets)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got android id %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("androidIDFromSecrets: %v", err)
			}
			if got != tc.want {
				t.Fatalf("android id = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGetOwnerKeyUsesCache(t *testing.T) {
	store, err := auth.NewStore(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if err := store.Save(&auth.Secrets{OwnerKey: "0102fe"}); err != nil {
		t.Fatalf("save secrets: %v", err)
	}

	key, err := GetOwnerKey(context.Background(), store)
	if err != nil {
		t.Fatalf("GetOwnerKey: %v", err)
	}
	if len(key) != 3 || key[0] != 0x01 || key[1] != 0x02 || key[2] != 0xfe {
		t.Fatalf("owner key = %x, want 0102fe", key)
	}
}

func TestGetOwnerKeyMissingSecretsIsSentinelError(t *testing.T) {
	store, err := auth.NewStore(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if _, err := GetOwnerKey(context.Background(), store); !errors.Is(err, auth.ErrSecretsNotFound) {
		t.Fatalf("error = %v, want auth.ErrSecretsNotFound", err)
	}
}

func TestGetOwnerKeyMissingSharedKeyIsSentinelError(t *testing.T) {
	store, err := auth.NewStore(filepath.Join(t.TempDir(), "secrets.json"))
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if err := store.Save(&auth.Secrets{Username: "u", AASToken: "t"}); err != nil {
		t.Fatalf("save secrets: %v", err)
	}
	if _, err := GetOwnerKey(context.Background(), store); !errors.Is(err, auth.ErrSecretsNotFound) {
		t.Fatalf("error = %v, want auth.ErrSecretsNotFound", err)
	}
}
