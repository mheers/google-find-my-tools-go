// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package crypto

// FMDNKeys holds the three derived sub-keys for a given identity (EIK).
type FMDNKeys struct {
	RecoveryKey []byte
	RingingKey  []byte
	TrackingKey []byte
}

// GenerateFMDNKeys derives the recovery, ringing and tracking keys from an
// identity key, matching Python FMDNCrypto.key_derivation.FMDNOwnerOperations.
func GenerateFMDNKeys(identityKey []byte) FMDNKeys {
	return FMDNKeys{
		RecoveryKey: TruncatedSHA256(identityKey, 0x01),
		RingingKey:  TruncatedSHA256(identityKey, 0x02),
		TrackingKey: TruncatedSHA256(identityKey, 0x03),
	}
}
