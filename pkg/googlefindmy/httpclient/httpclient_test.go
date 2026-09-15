// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package httpclient

import (
	"net/http"
	"testing"
)

func TestDefaultAppliesTimeout(t *testing.T) {
	if got := Default().Timeout; got != DefaultTimeout {
		t.Fatalf("Default().Timeout = %s, want %s", got, DefaultTimeout)
	}
	if DefaultTimeout <= 0 {
		t.Fatal("DefaultTimeout must be positive")
	}
}

func TestOrDefault(t *testing.T) {
	custom := &http.Client{}
	if got := OrDefault(custom); got != custom {
		t.Fatal("OrDefault returned a different client for a non-nil input")
	}
	if got := OrDefault(nil); got.Timeout != DefaultTimeout {
		t.Fatalf("OrDefault(nil).Timeout = %s, want %s", got.Timeout, DefaultTimeout)
	}
}
