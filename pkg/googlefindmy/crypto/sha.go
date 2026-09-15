package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// TruncatedSHA256 computes SHA256(identityKey || operation)[:8], matching the
// Python FMDNCrypto.sha.calculate_truncated_sha256 primitive.
func TruncatedSHA256(identityKey []byte, operation byte) []byte {
	h := sha256.New()
	h.Write(identityKey)
	h.Write([]byte{operation})
	return h.Sum(nil)[:8]
}

// HMACSHA256 returns the HMAC-SHA256 of message under key, matching the
// Python FMDNCrypto.sha.calculate_hmac_sha256 primitive.
func HMACSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}
