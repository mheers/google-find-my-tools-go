// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// loadVectors reads the cross-implementation test vectors captured from the
// reference Python implementation (third_party/GoogleFindMyTools).
func loadVectors(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestTruncatedSHA256(t *testing.T) {
	v := loadVectors(t)
	tv := v["truncated_sha256"].(map[string]any)
	in := mustHex(tv["input"].(string))
	got := TruncatedSHA256(in, 0x01)
	if hex.EncodeToString(got) != tv["op_01"].(string) {
		t.Fatalf("truncated sha256 mismatch: got %x", got)
	}
}

func TestGenerateFMDNKeys(t *testing.T) {
	v := loadVectors(t)
	tv := v["key_derivation"].(map[string]any)
	ik := mustHex(tv["identity_key"].(string))
	keys := GenerateFMDNKeys(ik)
	if hex.EncodeToString(keys.RecoveryKey) != tv["recovery"].(string) {
		t.Fatalf("recovery key mismatch: got %x", keys.RecoveryKey)
	}
	if hex.EncodeToString(keys.RingingKey) != tv["ringing"].(string) {
		t.Fatalf("ringing key mismatch: got %x", keys.RingingKey)
	}
	if hex.EncodeToString(keys.TrackingKey) != tv["tracking"].(string) {
		t.Fatalf("tracking key mismatch: got %x", keys.TrackingKey)
	}
}

func TestGenerateEID(t *testing.T) {
	v := loadVectors(t)
	ik := mustHex(v["identity_key"].(string))
	for _, e := range v["eids"].([]any) {
		tc := e.(map[string]any)
		ts := int64(tc["timestamp"].(float64))
		want := tc["eid"].(string)
		got, err := GenerateEID(ik, ts)
		if err != nil {
			t.Fatalf("GenerateEID: %v", err)
		}
		if hex.EncodeToString(got) != want {
			t.Fatalf("EID mismatch for ts=%d: got %x want %s", ts, got, want)
		}
	}
}

func TestEAXKnownAnswer(t *testing.T) {
	v := loadVectors(t)
	e := v["eax"].(map[string]any)
	key := mustHex(e["key"].(string))
	nonce := mustHex(e["nonce"].(string))
	msg := mustHex(e["message"].(string))
	wantCt := e["ciphertext"].(string)
	wantTag := e["tag"].(string)

	ctTag, err := EncryptEAX(key, nonce, nil, msg)
	if err != nil {
		t.Fatalf("EncryptEAX: %v", err)
	}
	gotCt := hex.EncodeToString(ctTag[:len(ctTag)-16])
	gotTag := hex.EncodeToString(ctTag[len(ctTag)-16:])
	if gotCt != wantCt || gotTag != wantTag {
		t.Fatalf("EAX mismatch: ct got %s want %s; tag got %s want %s", gotCt, wantCt, gotTag, wantTag)
	}

	pt, err := DecryptEAX(key, nonce, nil, ctTag)
	if err != nil {
		t.Fatalf("DecryptEAX: %v", err)
	}
	if hex.EncodeToString(pt) != e["message"].(string) {
		t.Fatalf("EAX roundtrip mismatch")
	}
}

func TestForeignTrackerRoundTrip(t *testing.T) {
	v := loadVectors(t)
	ik := mustHex(v["identity_key"].(string))
	loc := mustHex(v["foreign_tracker"].([]any)[0].(map[string]any)["location"].(string))

	// Encrypt with a random 32-byte scalar, EID from the first vector.
	eid := mustHex(v["eids"].([]any)[0].(map[string]any)["eid"].(string))
	random := mustHex("1111111111111111111111111111111111111111111111111111111111111111")
	ctTag, sx, err := EncryptForeignTracker(loc, random, eid)
	if err != nil {
		t.Fatalf("EncryptForeignTracker: %v", err)
	}

	ts := int64(v["eids"].([]any)[0].(map[string]any)["timestamp"].(float64))
	pt, err := DecryptForeignTracker(ik, ctTag, sx, ts)
	if err != nil {
		t.Fatalf("DecryptForeignTracker: %v", err)
	}
	if hex.EncodeToString(pt) != hex.EncodeToString(loc) {
		t.Fatalf("foreign tracker roundtrip mismatch: got %x", pt)
	}
}

func TestForeignTrackerVector(t *testing.T) {
	v := loadVectors(t)
	ik := mustHex(v["identity_key"].(string))
	for _, e := range v["foreign_tracker"].([]any) {
		tc := e.(map[string]any)
		ctTag := mustHex(tc["encrypted_and_tag"].(string))
		sx := mustHex(tc["sx"].(string))
		ts := int64(tc["timestamp"].(float64))
		want := tc["location"].(string)

		pt, err := DecryptForeignTracker(ik, ctTag, sx, ts)
		if err != nil {
			t.Fatalf("DecryptForeignTracker ts=%d: %v", ts, err)
		}
		if hex.EncodeToString(pt) != want {
			t.Fatalf("foreign tracker mismatch ts=%d: got %x want %s", ts, pt, want)
		}
	}
}

func TestDecryptRejectsMalformedInput(t *testing.T) {
	key := make([]byte, 32)
	encrypted := append([]byte{0x02, 0x00}, make([]byte, 64)...)

	if _, err := DecryptSharedKey(key, encrypted); err == nil {
		t.Error("DecryptSharedKey: expected error for truncated input")
	}
	if _, err := DecryptApplicationKey(key, encrypted); err == nil {
		t.Error("DecryptApplicationKey: expected error for truncated input")
	}
	if _, err := DecryptSecurityDomainKey(key, []byte{0x02, 0x00}); err == nil {
		t.Error("DecryptSecurityDomainKey: expected error for truncated input")
	}
	if _, err := DecryptOwnerKey(key, nil); err == nil {
		t.Error("DecryptOwnerKey: expected error for empty input")
	}
}

func TestEIDRejectsInvalidIdentityKey(t *testing.T) {
	if _, err := GenerateEID([]byte("too-short"), 1_700_000_000); err == nil {
		t.Fatal("GenerateEID: expected error for a non-32-byte identity key")
	}
}

func TestEncryptForeignTrackerRejectsZeroScalar(t *testing.T) {
	eid := mustHex("9d8188455646a1b02ef769bf9845f095c1e79499")
	if _, _, err := EncryptForeignTracker([]byte("msg"), make([]byte, 32), eid); err == nil {
		t.Fatal("EncryptForeignTracker: expected error for an all-zero scalar")
	}
	if _, _, err := EncryptForeignTracker([]byte("msg"), nil, eid); err == nil {
		t.Fatal("EncryptForeignTracker: expected error for an empty scalar")
	}
}

func TestDecryptForeignTrackerRejectsMalformedInput(t *testing.T) {
	validKey := make([]byte, 32)
	shortCt := []byte{0x01, 0x02, 0x03}
	eid := mustHex("9d8188455646a1b02ef769bf9845f095c1e79499")

	if _, err := DecryptForeignTracker(validKey, shortCt, eid, 0); err == nil {
		t.Fatal("expected error for ciphertext shorter than the tag")
	}
	if _, err := DecryptForeignTracker([]byte("bad-key"), append(shortCt, make([]byte, 32)...), eid, 0); err == nil {
		t.Fatal("expected error for an invalid identity key")
	}
}

func FuzzDecryptSharedKey(f *testing.F) {
	f.Add(make([]byte, 32), append([]byte{0x02, 0x00}, make([]byte, 80)...))
	f.Fuzz(func(t *testing.T, key, encrypted []byte) {
		// Must never panic, regardless of input shape.
		_, _ = DecryptSharedKey(key, encrypted)
	})
}

func FuzzDecryptForeignTracker(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 48), make([]byte, 20), int64(0))
	f.Fuzz(func(t *testing.T, identityKey, encryptedAndTag, sx []byte, timestamp int64) {
		_, _ = DecryptForeignTracker(identityKey, encryptedAndTag, sx, timestamp)
	})
}
