// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// rb128 is the constant used for CMAC subkey generation with a 128-bit block.
// It is 0x87 in the least-significant byte (big-endian: trailing byte).
var rb128 = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87}

// cmac computes the CMAC (OMAC1) of data using AES with the given key.
func cmac(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	const bs = 16

	// L = E(0^bs)
	L := make([]byte, bs)
	block.Encrypt(L, L)

	// Generate subkeys K1, K2.
	K1 := make([]byte, bs)
	shiftLeft(K1, L)
	if L[0]&0x80 != 0 {
		xorBytes(K1, K1, rb128)
	}
	K2 := make([]byte, bs)
	shiftLeft(K2, K1)
	if K1[0]&0x80 != 0 {
		xorBytes(K2, K2, rb128)
	}

	x := make([]byte, bs)
	encrypt := func(block16 []byte) {
		xorBytes(x, x, block16)
		block.Encrypt(x, x)
	}

	// Number of full blocks and trailing remainder.
	n := len(data) / bs
	rem := len(data) % bs

	if len(data) == 0 {
		// Empty message: the last block is the pad byte with K2.
		last := make([]byte, bs)
		last[0] = 0x80
		xorBytes(last, last, K2)
		encrypt(last)
		return x, nil
	}

	// Process all full blocks except the final one (if the message is an
	// exact multiple of the block size, the final full block is special).
	lastIsFull := rem == 0
	numRegular := n
	if lastIsFull {
		numRegular = n - 1
	}
	for i := 0; i < numRegular; i++ {
		encrypt(data[i*bs : (i+1)*bs])
	}

	if lastIsFull {
		last := make([]byte, bs)
		copy(last, data[(n-1)*bs:n*bs])
		xorBytes(last, last, K1)
		encrypt(last)
	} else {
		pad := make([]byte, bs)
		copy(pad, data[n*bs:])
		pad[rem] = 0x80
		xorBytes(pad, pad, K2)
		encrypt(pad)
	}
	return x, nil
}

// shiftLeft shifts a block left by one bit (big-endian).
func shiftLeft(dst, src []byte) {
	var carry byte
	for i := len(src) - 1; i >= 0; i-- {
		n := src[i] << 1
		dst[i] = n | carry
		carry = src[i] >> 7
	}
}

func xorBytes(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

// eaxOMAC computes the EAX OMAC for the given flag (0=nonce, 1=header,
// 2=ciphertext). PyCryptodome's EAX seeds each CMAC with a 16-byte prefix block
// consisting of 15 zero bytes followed by the flag byte, then feeds in data.
func eaxOMAC(key []byte, flag byte, data []byte) ([]byte, error) {
	prefix := make([]byte, 16)
	prefix[15] = flag
	return cmac(key, append(prefix, data...))
}

// EncryptEAX encrypts plaintext with AES-EAX-256, returning ciphertext || tag.
// The tag length is 16 bytes (full block).
func EncryptEAX(key, nonce, header, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonceMac, err := eaxOMAC(key, 0x00, nonce)
	if err != nil {
		return nil, err
	}
	headerMac, err := eaxOMAC(key, 0x01, header)
	if err != nil {
		return nil, err
	}

	// CTR mode keyed by the nonce MAC as the initial counter.
	ctr := cipher.NewCTR(block, nonceMac)
	ciphertext := make([]byte, len(plaintext))
	ctr.XORKeyStream(ciphertext, plaintext)

	cipherMac, err := eaxOMAC(key, 0x02, ciphertext)
	if err != nil {
		return nil, err
	}

	tag := make([]byte, 16)
	for i := 0; i < 16; i++ {
		tag[i] = nonceMac[i] ^ headerMac[i] ^ cipherMac[i]
	}
	return append(ciphertext, tag...), nil
}

// DecryptEAX verifies and decrypts ciphertext||tag produced by EncryptEAX.
func DecryptEAX(key, nonce, header, ciphertextAndTag []byte) ([]byte, error) {
	if len(ciphertextAndTag) < 16 {
		return nil, errors.New("crypto: ciphertext shorter than tag")
	}
	ciphertext := ciphertextAndTag[:len(ciphertextAndTag)-16]
	tag := ciphertextAndTag[len(ciphertextAndTag)-16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonceMac, err := eaxOMAC(key, 0x00, nonce)
	if err != nil {
		return nil, err
	}
	headerMac, err := eaxOMAC(key, 0x01, header)
	if err != nil {
		return nil, err
	}

	ctr := cipher.NewCTR(block, nonceMac)
	plaintext := make([]byte, len(ciphertext))
	ctr.XORKeyStream(plaintext, ciphertext)

	cipherMac, err := eaxOMAC(key, 0x02, ciphertext)
	if err != nil {
		return nil, err
	}

	expected := make([]byte, 16)
	for i := 0; i < 16; i++ {
		expected[i] = nonceMac[i] ^ headerMac[i] ^ cipherMac[i]
	}
	if !equalBytes(expected, tag) {
		return nil, errors.New("crypto: EAX tag verification failed")
	}
	return plaintext, nil
}

func equalBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// aesECBEncrypt is a multi-block AES-ECB encryption (no padding). The input
// length must be a multiple of the block size (16 bytes). Used by EID
// generation which AES-ECB encrypts a 32-byte structure.
func aesECBEncrypt(key, data []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%16 != 0 {
		return nil, errors.New("crypto: ECB input must be block-aligned")
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		c.Encrypt(out[i:i+16], data[i:i+16])
	}
	return out, nil
}

// gcmDecrypt performs AES-GCM decryption (standard, no associated data). The
// 12-byte IV is prepended to the ciphertext.
func gcmDecrypt(key, ciphertextAndIV []byte) ([]byte, error) {
	if len(ciphertextAndIV) < 12 {
		return nil, errors.New("crypto: ciphertext too short for GCM")
	}
	iv := ciphertextAndIV[:12]
	ct := ciphertextAndIV[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ct, nil)
}

// gcmDecryptAD performs AES-GCM decryption with associated data.
func gcmDecryptAD(key, ciphertextAndIV, associatedData []byte) ([]byte, error) {
	if len(ciphertextAndIV) < 12 {
		return nil, errors.New("crypto: ciphertext too short for GCM")
	}
	iv := ciphertextAndIV[:12]
	ct := ciphertextAndIV[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ct, associatedData)
}
