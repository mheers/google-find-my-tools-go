// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

// Package grpc provides minimal gRPC message framing used by the Spot API.
//
// The Spot service is called over HTTP/2 with the application/grpc content
// type. Each message is prefixed by a single "compressed" flag byte (0 =
// uncompressed) followed by a big-endian uint32 length and the raw payload.
// This mirrors Python SpotApi/grpc_parser.py and avoids pulling in the full
// grpc-go stack for a handful of unary calls.
package grpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// Wrap prepends the gRPC framing header to payload.
func Wrap(payload []byte) []byte {
	if len(payload) > math.MaxUint32 {
		// Unreachable on 32-bit platforms and practically unreachable
		// elsewhere; guard so the length cast below cannot truncate.
		panic("grpc: payload exceeds the gRPC frame limit")
	}
	out := make([]byte, 5+len(payload))
	out[0] = 0 // not compressed
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// maxFrameSize bounds a single gRPC message so a malicious or buggy peer
// cannot force an unbounded allocation.
const maxFrameSize = 16 << 20 // 16 MiB

// Unwrap extracts the inner payload from a gRPC-framed message.
func Unwrap(framed []byte) ([]byte, error) {
	if len(framed) < 5 {
		return nil, fmt.Errorf("grpc: frame too short (%d bytes)", len(framed))
	}
	if framed[0] != 0 {
		return nil, errors.New("grpc: compressed frames are not supported")
	}
	length := binary.BigEndian.Uint32(framed[1:5])
	if length > maxFrameSize {
		return nil, fmt.Errorf("grpc: frame length %d exceeds limit %d", length, maxFrameSize)
	}
	if uint32(len(framed)-5) < length {
		return nil, fmt.Errorf("grpc: frame length %d exceeds available %d", length, len(framed)-5)
	}
	return framed[5 : 5+int(length)], nil
}

// ReadFrame reads a single gRPC-framed message from r.
func ReadFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("grpc: read header: %w", err)
	}
	if header[0] != 0 {
		return nil, errors.New("grpc: compressed frames are not supported")
	}
	length := binary.BigEndian.Uint32(header[1:5])
	if length > maxFrameSize {
		return nil, fmt.Errorf("grpc: frame length %d exceeds limit %d", length, maxFrameSize)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("grpc: read body: %w", err)
	}
	return body, nil
}
