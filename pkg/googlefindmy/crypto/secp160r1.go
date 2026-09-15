// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

// Package crypto implements the cryptographic primitives needed to talk to the
// Google Find My Device (FMDN) APIs in pure Go — replacing the Python
// GoogleFindMyTools dependency.
//
// It covers two subsystems:
//   - FMDNCrypto: E2EE for location reports (SECP160r1, AES-EAX-256, EID generation)
//   - KeyBackup:  cloud key decryption (AES-GCM-128, ECDH P-256, HKDF-SHA256)
//
// All test vectors were captured from the reference Python implementation
// (third_party/GoogleFindMyTools) and live in crypto/testdata/vectors.json.
package crypto

import (
	"crypto/elliptic"
	"math/big"
)

// secp160r1 is the NIST P-160 curve used by FMDN. It is not in Go's standard
// library, but because its "a" parameter equals -3 (like all NIST curves), we
// can reuse crypto/elliptic's generic short-Weierstrass implementation.
//
// SECURITY NOTE: crypto/elliptic's generic CurveParams implementation is not
// constant-time. Since secp160r1 is not available via crypto/ecdh, scalar
// multiplications with secret scalars (EID generation, foreign tracker
// decryption) are theoretically exposed to local timing side channels. The
// reference Python implementation has the same property; this is an accepted
// limitation of the port, not a regression.
var secp160r1 = &elliptic.CurveParams{
	Name:    "secp160r1",
	P:       bigFromHex("ffffffffffffffffffffffffffffffff7fffffff"),
	N:       bigFromHex("100000000000000000001f4c8f927aed3ca752257"),
	B:       bigFromHex("1c97befc54bd7a8b65acf89f81d4d4adc565fa45"),
	Gx:      bigFromHex("4a96b5688ef573284664698968c38bb913cbfc82"),
	Gy:      bigFromHex("23a628553168947d59dcc912042351377ac5fb32"),
	BitSize: 161,
}

// secp160r1Order is the curve order, kept as a *big.Int for convenience.
var secp160r1Order = secp160r1.N

// bigFromHex parses a hex string into a big.Int.
func bigFromHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("crypto: invalid hex in curve parameter")
	}
	return n
}

// ScalarBaseMult returns x, y = k*G on secp160r1.
func scalarBaseMult(k []byte) (x, y *big.Int) {
	return secp160r1.ScalarBaseMult(k) //nolint:staticcheck // secp160r1 has no crypto/ecdh equivalent; see the curve doc comment.
}

// PointFromX reconstructs the (x, y) point on secp160r1 from an x-coordinate,
// choosing the even-y solution. This mirrors the Python rx_to_ry helper: it
// solves y^2 = x^3 + ax + b (mod p) via a modular square root and forces y even.
func PointFromX(xBytes []byte) (x, y *big.Int) {
	xInt := new(big.Int).SetBytes(xBytes)
	if xInt.Cmp(secp160r1.P) >= 0 {
		return nil, nil
	}

	// y^2 = x^3 - 3x + b  (a == -3 for secp160r1)
	x3 := new(big.Int).Exp(xInt, big.NewInt(3), secp160r1.P)
	aX := new(big.Int).Mul(big.NewInt(-3), xInt)
	aX.Mod(aX, secp160r1.P)
	yy := new(big.Int).Add(x3, aX)
	yy.Add(yy, secp160r1.B)
	yy.Mod(yy, secp160r1.P)

	// Modular square root via p == 3 (mod 4): y = yy^((p+1)/4) mod p.
	exp := new(big.Int).Add(secp160r1.P, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	yInt := new(big.Int).Exp(yy, exp, secp160r1.P)

	// Verify the result.
	check := new(big.Int).Mul(yInt, yInt)
	check.Mod(check, secp160r1.P)
	if check.Cmp(yy) != 0 {
		return nil, nil
	}

	// Ensure y is even (FMDN convention).
	if yInt.Bit(0) == 1 {
		yInt.Sub(secp160r1.P, yInt)
	}
	return xInt, yInt
}
