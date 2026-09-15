package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/hkdf"
)

// KeyBackup constants, copied verbatim from Python KeyBackup.cloud_key_decryptor.
var (
	secureboxVersion       = []byte{0x02, 0x00}
	securebox              = []byte("SECUREBOX")
	sharedHKDFAESGCM       = []byte("SHARED HKDF-SHA-256 AES-128-GCM")
	p256HKDFAESGCM         = []byte("P256 HKDF-SHA-256 AES-128-GCM")
	aadSharedKey           = []byte("V1 shared_key")
	aadEncryptedAppKey     = []byte("V1 encrypted_application_key")
	aadLocallyEncRecovery  = []byte("V1 locally_encrypted_recovery_key")
	secureboxVersionLength = len(secureboxVersion)
)

// deriveKeyUsingHKDFSHA256 derives a 16-byte AES-128 key using HKDF-SHA256,
// matching Python derive_key_using_hkdf_sha256.
func deriveKeyUsingHKDFSHA256(inputKey, salt, info []byte) []byte {
	r := hkdf.New(sha256.New, inputKey, salt, info)
	out := make([]byte, 16)
	if _, err := r.Read(out); err != nil {
		panic(err)
	}
	return out
}

// p256SharedSecret performs ECDH P-256. privateKeyJWT is the 32-byte raw
// private scalar (JWT format), publicKey is the 65-byte uncompressed point.
func p256SharedSecret(privateKeyJWT, publicKey []byte) ([]byte, error) {
	privBytes := privateKeyJWT
	if len(privBytes) > 32 {
		privBytes = privBytes[:32]
	}
	priv, err := ecdh.P256().NewPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.P256().NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// DecryptOwnerKey decrypts the owner key with the shared key. The owner key is
// valid for all trackers and is AES-GCM encrypted directly with the shared key.
func DecryptOwnerKey(sharedKey, encryptedOwnerKey []byte) ([]byte, error) {
	return gcmDecrypt(sharedKey, encryptedOwnerKey)
}

// DecryptEIK decrypts the Encrypted Identity Key (EIK) with the owner key.
// Two encodings exist: 48 bytes (AES-CBC, no padding) or 60 bytes (AES-GCM).
func DecryptEIK(ownerKey, encryptedEIK []byte) ([]byte, error) {
	switch len(encryptedEIK) {
	case 48:
		return aesCBCNoPaddingDecrypt(ownerKey, encryptedEIK)
	case 60:
		return gcmDecrypt(ownerKey, encryptedEIK)
	default:
		return nil, errors.New("crypto: invalid encrypted EIK length")
	}
}

// DecryptAccountKey decrypts the account key with the owner key (32 bytes CBC,
// 44 bytes GCM).
func DecryptAccountKey(ownerKey, encryptedAccountKey []byte) ([]byte, error) {
	switch len(encryptedAccountKey) {
	case 32:
		return aesCBCNoPaddingDecrypt(ownerKey, encryptedAccountKey)
	case 44:
		return gcmDecrypt(ownerKey, encryptedAccountKey)
	default:
		return nil, errors.New("crypto: invalid encrypted account key length")
	}
}

// DecryptSharedKey decrypts the shared key from the security domain key. This
// path uses ECDH P-256 with the embedded public key plus HKDF key derivation.
func DecryptSharedKey(securityDomainKey, encryptedSharedKey []byte) ([]byte, error) {
	return decryptWithDerivedKey(encryptedSharedKey, securityDomainKey, p256HKDFAESGCM, aadSharedKey, true)
}

// DecryptSecurityDomainKey decrypts the security domain key with the
// application key (direct AES-GCM, no derivation).
func DecryptSecurityDomainKey(applicationKey, encryptedSecurityDomainKey []byte) ([]byte, error) {
	return gcmDecrypt(applicationKey, encryptedSecurityDomainKey)
}

// DecryptApplicationKey decrypts the application key with the recovery key
// (HKDF-derived key, direct shared-key info).
func DecryptApplicationKey(recoveryKey, encryptedApplicationKey []byte) ([]byte, error) {
	return decryptWithDerivedKey(encryptedApplicationKey, recoveryKey, sharedHKDFAESGCM, aadEncryptedAppKey, false)
}

// DecryptRecoveryKey decrypts the recovery key with the LSKF hash.
func DecryptRecoveryKey(lskfHash, encryptedRecoveryKey []byte) ([]byte, error) {
	return decryptWithDerivedKey(encryptedRecoveryKey, lskfHash, sharedHKDFAESGCM, aadLocallyEncRecovery, false)
}

// decryptWithDerivedKey implements the common HKDF+AESGCM decryption path.
// deriveWithPublicKey toggles the ECDH branch used by the shared key.
func decryptWithDerivedKey(encryptedData, privateKey, info, aad []byte, deriveWithPublicKey bool) ([]byte, error) {
	if len(encryptedData) < secureboxVersionLength || string(encryptedData[:secureboxVersionLength]) != string(secureboxVersion) {
		return nil, errors.New("crypto: invalid version or data length")
	}

	ciphertextOffset := 0
	if deriveWithPublicKey {
		ciphertextOffset = 65
	}
	// Guard against truncated input before slicing: version + optional public
	// key + at least an AES-GCM IV.
	if len(encryptedData) < secureboxVersionLength+ciphertextOffset+12 {
		return nil, errors.New("crypto: encrypted data too short")
	}
	ciphertextAndIV := encryptedData[secureboxVersionLength+ciphertextOffset:]

	salt := append(append([]byte{}, securebox...), secureboxVersion...)
	derivedKey := deriveKeyUsingHKDFSHA256(privateKey, salt, info)

	if deriveWithPublicKey {
		sharedPublicKey := encryptedData[secureboxVersionLength : secureboxVersionLength+ciphertextOffset]
		ecdhShared, err := p256SharedSecret(privateKey, sharedPublicKey)
		if err != nil {
			return nil, err
		}
		derivedKey = deriveKeyUsingHKDFSHA256(ecdhShared, salt, info)
	}

	return gcmDecryptAD(derivedKey, ciphertextAndIV, aad)
}

// aesCBCNoPaddingDecrypt decrypts AES-CBC with no padding (IV prepended).
func aesCBCNoPaddingDecrypt(key, encryptedDataAndIV []byte) ([]byte, error) {
	const ivLen = 16
	if len(encryptedDataAndIV) < ivLen {
		return nil, errors.New("crypto: ciphertext too short for CBC")
	}
	iv := encryptedDataAndIV[:ivLen]
	ct := encryptedDataAndIV[ivLen:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ct))
	mode.CryptBlocks(plaintext, ct)
	return plaintext, nil
}
