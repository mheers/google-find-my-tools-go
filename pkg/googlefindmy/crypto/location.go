// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package crypto

import "crypto/sha256"

// DecryptOwnReport decrypts an "own report" location: the encrypted location is
// AES-GCM encrypted directly with SHA256(identityKey) as the key. It returns the
// decrypted Location protobuf bytes for the caller to parse.
func DecryptOwnReport(identityKey, encryptedLocation []byte) ([]byte, error) {
	key := sha256.Sum256(identityKey)
	return gcmDecrypt(key[:], encryptedLocation)
}

// DecryptForeignReport decrypts a "foreign report" location using FMDN E2EE
// (SECP160r1 + AES-EAX). beaconTimeCounter is the timestamp on which the EID
// (and therefore the scalar r) is based — for MCU trackers this is 0.
func DecryptForeignReport(identityKey, encryptedLocation, publicKeyRandom []byte, beaconTimeCounter int64) ([]byte, error) {
	return DecryptForeignTracker(identityKey, encryptedLocation, publicKeyRandom, beaconTimeCounter)
}
