package crypto

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

var (
	errInvalidEID      = errors.New("crypto: invalid EID / public key")
	errShortCiphertext = errors.New("crypto: ciphertext shorter than tag")
)

// hkdfSHA256 derives length bytes from secret using HKDF-SHA256 with a
// zero-filled salt (matching Python's HKDF(salt=None)) and the given info.
func hkdfSHA256(secret, info []byte, length int) []byte {
	salt := make([]byte, 32) // SHA-256 digest size, all zeros
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, length)
	if _, err := r.Read(out); err != nil {
		panic(err)
	}
	return out
}

// EncryptForeignTracker encrypts a location message for a foreign (non-owner)
// tracker, mirroring Python FMDNCrypto.foreign_tracker_cryptor.encrypt.
//
// random should be 32 bytes of CSPRNG output; eid is the 20-byte Ephemeral
// Identifier advertised by the tracker. It returns (ciphertext||tag, Sx) where
// Sx is the x-coordinate of the ephemeral public key (20 bytes).
func EncryptForeignTracker(message, random, eid []byte) ([]byte, []byte, error) {
	if len(random) == 0 {
		return nil, nil, errors.New("crypto: random scalar must not be empty")
	}
	s := new(big.Int).SetBytes(random)
	s.Mod(s, secp160r1Order)
	if s.Sign() == 0 {
		return nil, nil, errors.New("crypto: random scalar reduces to zero")
	}

	sx, _ := scalarBaseMult(s.Bytes())
	if sx == nil {
		return nil, nil, errors.New("crypto: ephemeral public key is the point at infinity")
	}

	rx := new(big.Int).SetBytes(eid)
	rX, rY := PointFromX(eid)
	if rX == nil {
		return nil, nil, errInvalidEID
	}

	// k = HKDF-SHA256( (s*R).x )
	sharedX, _ := pointMul(s, rX, rY)
	if sharedX == nil {
		return nil, nil, errors.New("crypto: shared point is the point at infinity")
	}
	sharedBytes := make([]byte, 20)
	sharedX.FillBytes(sharedBytes)
	k := hkdfSHA256(sharedBytes, nil, 32)

	// nonce = R.x[12:] || S.x[12:]
	lrX := make([]byte, 20)
	rx.FillBytes(lrX)
	lsX := make([]byte, 20)
	sx.FillBytes(lsX)
	nonce := append(lrX[12:], lsX[12:]...)

	ctTag, err := EncryptEAX(k, nonce, nil, message)
	if err != nil {
		return nil, nil, err
	}

	// Sx as a plain 20-byte big-endian x-coordinate (matching the Python
	// reference, which does not embed any y-parity bit).
	sxBytes := make([]byte, 20)
	sx.FillBytes(sxBytes)
	return ctTag, sxBytes, nil
}

// DecryptForeignTracker decrypts a location report produced by
// EncryptForeignTracker, mirroring Python ...foreign_tracker_cryptor.decrypt.
//
// encryptedAndTag is ciphertext||tag, Sx is the 20-byte ephemeral public key
// x-coordinate (with the high bit encoding y-parity), and beaconTimeCounter is
// the timestamp on which the EID (and thus r) is based.
func DecryptForeignTracker(identityKey, encryptedAndTag, sx []byte, beaconTimeCounter int64) ([]byte, error) {
	if len(encryptedAndTag) < 16 {
		return nil, errShortCiphertext
	}

	// Reconstruct r from the identity key and timestamp.
	r, err := calculateR(identityKey, beaconTimeCounter)
	if err != nil {
		return nil, err
	}
	if r.Sign() == 0 {
		return nil, errors.New("crypto: derived scalar is zero")
	}
	rx2, _ := pointMulScalarBase(r)
	if rx2 == nil {
		return nil, errors.New("crypto: r*G is the point at infinity")
	}

	// Reconstruct S from its x-coordinate (even-y convention, matching Python).
	sX, sY := PointFromX(sx)
	if sX == nil {
		return nil, errInvalidEID
	}

	// k = HKDF-SHA256( (r*S).x )
	sharedX, _ := pointMul(r, sX, sY)
	if sharedX == nil {
		return nil, errors.New("crypto: shared point is the point at infinity")
	}
	sharedBytes := make([]byte, 20)
	sharedX.FillBytes(sharedBytes)
	k := hkdfSHA256(sharedBytes, nil, 32)

	// nonce = R.x[12:] || S.x[12:]
	lrX := make([]byte, 20)
	rx2.FillBytes(lrX)
	lsX := make([]byte, 20)
	sX.FillBytes(lsX)
	nonce := append(lrX[12:], lsX[12:]...)

	return DecryptEAX(k, nonce, nil, encryptedAndTag)
}

// pointMulScalarBase returns k*G.
func pointMulScalarBase(k *big.Int) (x, y *big.Int) {
	return secp160r1.ScalarBaseMult(k.Bytes()) //nolint:staticcheck // secp160r1 has no crypto/ecdh equivalent; see the curve doc comment.
}

// pointMul returns k*(X,Y) using Go's generic scalar multiplication.
func pointMul(k *big.Int, x, y *big.Int) (xr, yr *big.Int) {
	px, py := secp160r1.ScalarMult(x, y, k.Bytes()) //nolint:staticcheck // secp160r1 has no crypto/ecdh equivalent; see the curve doc comment.
	return px, py
}
