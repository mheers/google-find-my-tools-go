package crypto

import "math/big"

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
func calculateR(identityKey []byte, timestamp int64) *big.Int {
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
		// identityKey is always 32 bytes for AES-256; impossible to fail here.
		panic(err)
	}
	rDashInt := new(big.Int).SetBytes(rDash)
	return new(big.Int).Mod(rDashInt, secp160r1Order)
}

// GenerateEID computes the Ephemeral Identifier for the given identity key and
// timestamp. It returns the x-coordinate of r*G as a 20-byte big-endian value.
func GenerateEID(identityKey []byte, timestamp int64) ([]byte, error) {
	r := calculateR(identityKey, timestamp)
	x, _ := scalarBaseMult(r.Bytes())
	out := make([]byte, 20)
	if x != nil {
		x.FillBytes(out)
	}
	return out, nil
}
