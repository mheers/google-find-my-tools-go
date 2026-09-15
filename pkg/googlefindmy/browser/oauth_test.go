// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package browser

import (
	"fmt"
	"strings"
	"testing"
)

func TestBuildOAuthURL(t *testing.T) {
	got := buildOAuthURL("user@example.com")
	for _, want := range []string{
		"client_id=848232127117.apps.googleusercontent.com",
		"response_type=token",
		"scope=https%3A%2F%2Fwww.google.com%2Faccounts%2FOAuthLogin",
		"Email=user%40example.com",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("buildOAuthURL missing %q in %q", want, got)
		}
	}

	if got := buildOAuthURL(""); strings.Contains(got, "Email=") {
		t.Errorf("buildOAuthURL without email should not set Email: %q", got)
	}
}

func validVaultKeysJSON() (string, [32]byte) {
	var key [32]byte
	var b strings.Builder
	b.WriteString(`{"finder_hw":[{"key":{`)
	for i := 0; i < 32; i++ {
		key[i] = byte((i * 7) % 256)
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"%d":%d`, i, key[i])
	}
	b.WriteString(`}}]}`)
	return b.String(), key
}

func TestExtractSharedKey(t *testing.T) {
	input, want := validVaultKeysJSON()
	got, err := extractSharedKey(input)
	if err != nil {
		t.Fatalf("extractSharedKey: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("key length = %d, want 32", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key byte %d = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestExtractSharedKeyRejectsMalformedInput(t *testing.T) {
	valid, _ := validVaultKeysJSON()

	tests := []struct {
		name  string
		input string
	}{
		{"invalid json", `not-json`},
		{"missing domain", `{"other":[]}`},
		{"empty entries", `{"finder_hw":[]}`},
		{"missing key object", `{"finder_hw":[{}]}`},
		{"missing byte", strings.Replace(valid, `,"31":217`, "", 1)},
		{"out of range", strings.Replace(valid, `"0":0`, `"0":300`, 1)},
		{"non integer", strings.Replace(valid, `"0":0`, `"0":1.5`, 1)},
		{"non numeric", strings.Replace(valid, `"0":0`, `"0":"ff"`, 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := extractSharedKey(tc.input); err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
		})
	}
}

func FuzzExtractSharedKey(f *testing.F) {
	input, _ := validVaultKeysJSON()
	f.Add(input)
	f.Add(`{"finder_hw":[{}]}`)
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = extractSharedKey(s)
	})
}
