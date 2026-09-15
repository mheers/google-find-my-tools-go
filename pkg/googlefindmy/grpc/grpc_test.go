package grpc

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWrapUnwrap(t *testing.T) {
	payload := []byte("hello grpc world")
	framed := Wrap(payload)
	if len(framed) != 5+len(payload) {
		t.Fatalf("framed len = %d, want %d", len(framed), 5+len(payload))
	}
	if framed[0] != 0 {
		t.Errorf("compressed flag = %d, want 0", framed[0])
	}
	got, err := Unwrap(framed)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("Unwrap = %q, want %q", got, payload)
	}
}

func TestWrapUnwrapLarge(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 70000) // > 16-bit length
	framed := Wrap(payload)
	got, err := Unwrap(framed)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("round-trip mismatch")
	}
}

func TestUnwrapTooShort(t *testing.T) {
	if _, err := Unwrap([]byte{0, 1, 2}); err == nil {
		t.Error("expected error for short frame")
	}
}

func TestUnwrapRejectsOversizedFrame(t *testing.T) {
	framed := make([]byte, 5)
	binary.BigEndian.PutUint32(framed[1:5], maxFrameSize+1)
	if _, err := Unwrap(framed); err == nil {
		t.Fatal("expected error for oversized frame")
	}
}

func TestReadFrameRejectsOversizedFrame(t *testing.T) {
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[1:5], maxFrameSize+1)
	if _, err := ReadFrame(bytes.NewReader(header)); err == nil {
		t.Fatal("expected error for oversized frame")
	}
}

func TestReadFrameTruncated(t *testing.T) {
	framed := Wrap([]byte("payload"))
	if _, err := ReadFrame(bytes.NewReader(framed[:7])); err == nil {
		t.Fatal("expected error for truncated frame body")
	}
}

func TestUnwrapRejectsCompressedFrame(t *testing.T) {
	framed := Wrap([]byte("payload"))
	framed[0] = 1 // gzip flag
	if _, err := Unwrap(framed); err == nil {
		t.Fatal("expected an error for a compressed frame")
	}
}

func TestReadFrameRejectsCompressedFrame(t *testing.T) {
	framed := Wrap([]byte("payload"))
	framed[0] = 1
	if _, err := ReadFrame(bytes.NewReader(framed)); err == nil {
		t.Fatal("expected an error for a compressed frame")
	}
}

func FuzzUnwrap(f *testing.F) {
	f.Add(Wrap([]byte("hello")))
	f.Add([]byte{0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, framed []byte) {
		payload, err := Unwrap(framed)
		if err == nil && uint32(len(payload)) > maxFrameSize {
			t.Fatalf("returned payload larger than the frame limit: %d", len(payload))
		}
	})
}
