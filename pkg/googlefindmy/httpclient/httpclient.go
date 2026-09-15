// Package httpclient provides the default HTTP client configuration shared by
// the Find My API clients.
package httpclient

import (
	"net/http"
	"time"
)

// DefaultTimeout bounds a single HTTP request. Google's endpoints can stall;
// no API call should be able to hang forever.
const DefaultTimeout = 30 * time.Second

// Default returns a new client that applies DefaultTimeout.
func Default() *http.Client {
	return &http.Client{Timeout: DefaultTimeout}
}

// OrDefault returns hc when it is non-nil and Default otherwise, so callers
// can keep an optional *http.Client field without nil checks.
func OrDefault(hc *http.Client) *http.Client {
	if hc == nil {
		return Default()
	}
	return hc
}
