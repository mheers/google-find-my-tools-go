package grpc

import (
	"bytes"
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
