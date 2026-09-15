// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// deriveKeyForTest mirrors the salt/info derivation used by decryptWithDerivedKey.
func deriveKeyForTest(input, info []byte) []byte {
	salt := append(append([]byte{}, securebox...), secureboxVersion...)
	return deriveKeyUsingHKDFSHA256(input, salt, info)
}

// sealGCMForTest returns iv||ciphertext||tag with a fixed IV.
func sealGCMForTest(t *testing.T, key, plaintext, aad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	iv := bytes.Repeat([]byte{0x42}, 12)
	return gcm.Seal(iv, iv, plaintext, aad)
}

// cbcEncryptForTest returns iv||ciphertext with AES-CBC and no padding.
func cbcEncryptForTest(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	if len(plaintext)%aes.BlockSize != 0 {
		t.Fatalf("plaintext length %d is not block aligned", len(plaintext))
	}
	iv := bytes.Repeat([]byte{0x24}, aes.BlockSize)
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return append(iv, out...)
}

func withVersion(data []byte) []byte {
	return append(append([]byte{}, secureboxVersion...), data...)
}

func TestDecryptKeyBackupChain(t *testing.T) {
	lskfHash := bytes.Repeat([]byte{0x11}, 32)

	recoveryPlain := bytes.Repeat([]byte{0xAA}, 32)
	encRecovery := withVersion(sealGCMForTest(t, deriveKeyForTest(lskfHash, sharedHKDFAESGCM), recoveryPlain, aadLocallyEncRecovery))
	recovery, err := DecryptRecoveryKey(lskfHash, encRecovery)
	if err != nil {
		t.Fatalf("DecryptRecoveryKey: %v", err)
	}
	if !bytes.Equal(recovery, recoveryPlain) {
		t.Fatalf("recovery key mismatch: %x", recovery)
	}

	applicationPlain := bytes.Repeat([]byte{0xBB}, 32)
	encApplication := withVersion(sealGCMForTest(t, deriveKeyForTest(recovery, sharedHKDFAESGCM), applicationPlain, aadEncryptedAppKey))
	application, err := DecryptApplicationKey(recovery, encApplication)
	if err != nil {
		t.Fatalf("DecryptApplicationKey: %v", err)
	}
	if !bytes.Equal(application, applicationPlain) {
		t.Fatalf("application key mismatch: %x", application)
	}

	securityDomainPlain := bytes.Repeat([]byte{0xCC}, 32)
	securityDomain, err := DecryptSecurityDomainKey(application, sealGCMForTest(t, application, securityDomainPlain, nil))
	if err != nil {
		t.Fatalf("DecryptSecurityDomainKey: %v", err)
	}
	if !bytes.Equal(securityDomain, securityDomainPlain) {
		t.Fatalf("security domain key mismatch: %x", securityDomain)
	}
}

func TestDecryptSharedAndOwnerKeys(t *testing.T) {
	securityDomainKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate security domain key: %v", err)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}
	ecdhShared, err := ephemeral.ECDH(securityDomainKey.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}

	sharedKeyPlain := bytes.Repeat([]byte{0x5A}, 32)
	sealedShared := sealGCMForTest(t, deriveKeyForTest(ecdhShared, p256HKDFAESGCM), sharedKeyPlain, aadSharedKey)
	encryptedShared := append(withVersion(ephemeral.PublicKey().Bytes()), sealedShared...)

	sharedKey, err := DecryptSharedKey(securityDomainKey.Bytes(), encryptedShared)
	if err != nil {
		t.Fatalf("DecryptSharedKey: %v", err)
	}
	if !bytes.Equal(sharedKey, sharedKeyPlain) {
		t.Fatalf("shared key mismatch: %x", sharedKey)
	}

	ownerKeyPlain := bytes.Repeat([]byte{0x77}, 32)
	ownerKey, err := DecryptOwnerKey(sharedKey, sealGCMForTest(t, sharedKey, ownerKeyPlain, nil))
	if err != nil {
		t.Fatalf("DecryptOwnerKey: %v", err)
	}
	if !bytes.Equal(ownerKey, ownerKeyPlain) {
		t.Fatalf("owner key mismatch: %x", ownerKey)
	}

	eikPlain := bytes.Repeat([]byte{0x33}, 32)
	eikCBC, err := DecryptEIK(ownerKey, cbcEncryptForTest(t, ownerKey, eikPlain))
	if err != nil {
		t.Fatalf("DecryptEIK (CBC): %v", err)
	}
	if !bytes.Equal(eikCBC, eikPlain) {
		t.Fatalf("EIK (CBC) mismatch: %x", eikCBC)
	}
	eikGCM, err := DecryptEIK(ownerKey, sealGCMForTest(t, ownerKey, eikPlain, nil))
	if err != nil {
		t.Fatalf("DecryptEIK (GCM): %v", err)
	}
	if !bytes.Equal(eikGCM, eikPlain) {
		t.Fatalf("EIK (GCM) mismatch: %x", eikGCM)
	}

	accountPlain := bytes.Repeat([]byte{0x44}, 16)
	accountCBC, err := DecryptAccountKey(ownerKey, cbcEncryptForTest(t, ownerKey, accountPlain))
	if err != nil {
		t.Fatalf("DecryptAccountKey (CBC): %v", err)
	}
	if !bytes.Equal(accountCBC, accountPlain) {
		t.Fatalf("account key (CBC) mismatch: %x", accountCBC)
	}
	accountGCM, err := DecryptAccountKey(ownerKey, sealGCMForTest(t, ownerKey, accountPlain, nil))
	if err != nil {
		t.Fatalf("DecryptAccountKey (GCM): %v", err)
	}
	if !bytes.Equal(accountGCM, accountPlain) {
		t.Fatalf("account key (GCM) mismatch: %x", accountGCM)
	}
}

func TestDecryptKeyBackupRejectsInvalidLengths(t *testing.T) {
	ownerKey := bytes.Repeat([]byte{0x01}, 32)
	if _, err := DecryptEIK(ownerKey, bytes.Repeat([]byte{0x02}, 47)); err == nil {
		t.Error("DecryptEIK: expected an error for an invalid length")
	}
	if _, err := DecryptAccountKey(ownerKey, bytes.Repeat([]byte{0x02}, 33)); err == nil {
		t.Error("DecryptAccountKey: expected an error for an invalid length")
	}
	if _, err := DecryptSharedKey(ownerKey, withVersion(bytes.Repeat([]byte{0x02}, 30))); err == nil {
		t.Error("DecryptSharedKey: expected an error for a truncated public key")
	}
}
