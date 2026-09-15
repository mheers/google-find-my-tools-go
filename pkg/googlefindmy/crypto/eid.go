// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package crypto

import (
	"errors"
	"fmt"
	"math/big"
)

// EID constants.
const (
	// EIDK is the number of least-significant bits masked off the timestamp.
	EIDK = 10
	// EIDRotationPeriod is 2^K seconds.
	EIDRotationPeriod = 1 << EIDK
)

// getMaskedTimestamp zeroes the K least-significant bits of the timestamp and
// returns it as a 4-byte big-endian value.
func getMaskedTimestamp(timestamp int64, k int) []byte {
	mask := ^((int64(1) << k) - 1)
	ts := timestamp & mask
	out := make([]byte, 4)
	for i := 0; i < 4; i++ {
		out[3-i] = byte(ts >> (8 * i))
	}
	return out
}

// calculateR derives the scalar r used in EID generation. It matches the
// Python FMDNCrypto.eid_generator.calculate_r implementation exactly.
// It returns an error when identityKey is not a 32-byte AES-256 key.
func calculateR(identityKey []byte, timestamp int64) (*big.Int, error) {
	if len(identityKey) != 32 {
		return nil, fmt.Errorf("crypto: identity key must be 32 bytes, got %d", len(identityKey))
	}

	tsBytes := getMaskedTimestamp(timestamp, EIDK)

	data := make([]byte, 32)
	for i := 0; i < 11; i++ {
		data[i] = 0xFF
	}
	data[11] = EIDK
	copy(data[12:16], tsBytes)
	// data[16:27] stays zero
	data[27] = EIDK
	copy(data[28:32], tsBytes)

	rDash, err := aesECBEncrypt(identityKey, data)
	if err != nil {
		return nil, fmt.Errorf("crypto: eid: %w", err)
	}
	rDashInt := new(big.Int).SetBytes(rDash)
	return new(big.Int).Mod(rDashInt, secp160r1Order), nil
}

// GenerateEID computes the Ephemeral Identifier for the given identity key and
// timestamp. It returns the x-coordinate of r*G as a 20-byte big-endian value.
// identityKey must be 32 bytes.
func GenerateEID(identityKey []byte, timestamp int64) ([]byte, error) {
	r, err := calculateR(identityKey, timestamp)
	if err != nil {
		return nil, err
	}
	if r.Sign() == 0 {
		return nil, errors.New("crypto: eid: derived scalar is zero")
	}
	x, _ := scalarBaseMult(r.Bytes())
	if x == nil {
		return nil, errors.New("crypto: eid: r*G is the point at infinity")
	}
	out := make([]byte, 20)
	x.FillBytes(out)
	return out, nil
}
