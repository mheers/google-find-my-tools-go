package httpbody

import (
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	short := []byte("hello")
	if got := Truncate(short); got != "hello" {
		t.Fatalf("Truncate(short) = %q", got)
	}
	long := []byte(strings.Repeat("a", maxLen+50))
	got := Truncate(long)
	if len(got) != maxLen+len("…") {
		t.Fatalf("Truncate(long) length = %d, want %d", len(got), maxLen+3)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("Truncate(long) = %q, want ellipsis suffix", got)
	}
}

func TestRedact(t *testing.T) {
	in := "Error=BadAuthentication&Token=oauth2rt_secret&SID=abc123&Email=user@example.com&SSID=keepme?no"
	got := Redact(in)
	for _, leaked := range []string{"oauth2rt_secret", "abc123", "user@example.com", "keepme"} {
		if strings.Contains(got, leaked) {
			t.Errorf("Redact leaked %q: %q", leaked, got)
		}
	}
	if !strings.Contains(got, "Token=***") {
		t.Errorf("Redact = %q, want Token=***", got)
	}
	if !strings.Contains(got, "Error=BadAuthentication") {
		t.Errorf("Redact must keep non-sensitive values: %q", got)
	}
	if !strings.Contains(got, "SSID=***") {
		t.Errorf("Redact must match SSID at the field boundary, not redact via SID: %q", got)
	}
}

func TestSafe(t *testing.T) {
	got := Safe([]byte("Token=secret\nError=BadAuthentication"))
	if strings.Contains(got, "secret") {
		t.Fatalf("Safe leaked a token: %q", got)
	}
}
