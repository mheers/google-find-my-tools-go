package fcm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	fcmpb "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/fcm"
)

type registerCapture struct {
	mu              sync.Mutex
	installHeaders  http.Header
	registerHeaders http.Header
	installBody     map[string]any
	registerBody    map[string]any
}

func (c *registerCapture) headers() (http.Header, http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.installHeaders, c.registerHeaders
}

func (c *registerCapture) bodies() (map[string]any, map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.installBody, c.registerBody
}

// newRegisterTestServer serves the check-in, GCM register, FIS install and FCM
// register endpoints used by register().
func newRegisterTestServer(t *testing.T, capture *registerCapture) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/checkin", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := &fcmpb.AndroidCheckinRequest{}
		if err := proto.Unmarshal(body, req); err != nil {
			t.Errorf("server cannot parse checkin request: %v", err)
		}
		resp := &fcmpb.AndroidCheckinResponse{
			StatsOk:       proto.Bool(true),
			AndroidId:     proto.Uint64(42),
			SecurityToken: proto.Uint64(7),
		}
		out, err := proto.Marshal(resp)
		if err != nil {
			t.Errorf("marshal checkin response: %v", err)
		}
		_, _ = w.Write(out)
	})
	mux.HandleFunc("/c2dm/register3", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "token=gcm-token\n")
	})
	mux.HandleFunc("/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/installations"):
			var parsed map[string]any
			_ = json.Unmarshal(body, &parsed)
			capture.mu.Lock()
			capture.installHeaders = r.Header.Clone()
			capture.installBody = parsed
			capture.mu.Unlock()
			_, _ = io.WriteString(w, `{"authToken":{"token":"fis-token","expiresIn":"3600s"},"refreshToken":"refresh-token","fid":"fid-1"}`)
		case strings.HasSuffix(r.URL.Path, "/registrations"):
			var parsed map[string]any
			_ = json.Unmarshal(body, &parsed)
			capture.mu.Lock()
			capture.registerHeaders = r.Header.Clone()
			capture.registerBody = parsed
			capture.mu.Unlock()
			_, _ = io.WriteString(w, `{"name":"projects/p/registrations/1","token":"fcm-reg-token"}`)
		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewServer(mux)
}

func testRegisterConfig(ts *httptest.Server) Config {
	cfg := DefaultConfig()
	cfg.CheckinURL = ts.URL + "/checkin"
	cfg.RegisterURL = ts.URL + "/c2dm/register3"
	cfg.InstallURL = ts.URL + "/v1/"
	cfg.FCMRegURL = ts.URL + "/v1/"
	return cfg
}

func TestRegister(t *testing.T) {
	capture := &registerCapture{}
	ts := newRegisterTestServer(t, capture)
	defer ts.Close()
	cfg := testRegisterConfig(ts)

	creds, err := register(context.Background(), ts.Client(), cfg)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if got := creds.RegistrationToken(); got != "fcm-reg-token" {
		t.Errorf("RegistrationToken = %q, want fcm-reg-token", got)
	}
	if creds.Keys == nil || creds.Keys.Private == "" || creds.Keys.Public == "" || creds.Keys.Secret == "" {
		t.Errorf("keys incomplete: %#v", creds.Keys)
	}
	if got := uint64(creds.GCM.AndroidID); got != 42 {
		t.Errorf("android id = %d, want 42", got)
	}
	if got := uint64(creds.GCM.SecurityToken); got != 7 {
		t.Errorf("security token = %d, want 7", got)
	}
	if creds.Config == nil || creds.Config.ProjectID != cfg.ProjectID {
		t.Errorf("config = %#v, want project id %q", creds.Config, cfg.ProjectID)
	}

	installHeaders, registerHeaders := capture.headers()
	for name, h := range map[string]http.Header{"install": installHeaders, "register": registerHeaders} {
		if got := h.Get("X-Android-Package"); got != cfg.BundleID {
			t.Errorf("%s X-Android-Package = %q, want %q", name, got, cfg.BundleID)
		}
		if got := h.Get("X-Android-Cert"); got != cfg.AndroidCertSHA1 {
			t.Errorf("%s X-Android-Cert = %q, want %q", name, got, cfg.AndroidCertSHA1)
		}
	}
	if got := installHeaders.Get("x-goog-api-key"); got != cfg.APIKey {
		t.Errorf("install x-goog-api-key = %q, want %q", got, cfg.APIKey)
	}
	if got := registerHeaders.Get("x-goog-firebase-installations-auth"); got != "fis-token" {
		t.Errorf("register installations auth = %q, want fis-token", got)
	}

	installBody, registerBody := capture.bodies()
	if got := installBody["appId"]; got != cfg.AppID {
		t.Errorf("install appId = %v, want %q", got, cfg.AppID)
	}

	web, ok := registerBody["web"].(map[string]any)
	if !ok {
		t.Fatalf("register body web = %#v", registerBody["web"])
	}
	if web["applicationPubKey"] != nil {
		t.Errorf("applicationPubKey = %v, want null for the default VAPID key", web["applicationPubKey"])
	}
	if got := web["endpoint"]; got != "https://fcm.googleapis.com/fcm/send/gcm-token" {
		t.Errorf("endpoint = %v", got)
	}
	if got := web["p256dh"]; got != creds.Keys.Public {
		t.Errorf("p256dh = %v, want %q", got, creds.Keys.Public)
	}
	if got := web["auth"]; got != creds.Keys.Secret {
		t.Errorf("auth = %v, want the generated secret", got)
	}

	// The stored credentials must use the Python-compatible nested shape.
	var shape struct {
		Registration struct {
			Token string `json:"token"`
		} `json:"registration"`
		Installation struct {
			Token     string `json:"token"`
			ExpiresIn int    `json:"expires_in"`
		} `json:"installation"`
	}
	if err := json.Unmarshal(creds.FCM, &shape); err != nil {
		t.Fatalf("credentials are not valid JSON: %v", err)
	}
	if shape.Registration.Token != "fcm-reg-token" {
		t.Errorf("stored registration token = %q", shape.Registration.Token)
	}
	if shape.Installation.Token != "fis-token" || shape.Installation.ExpiresIn != 3600 {
		t.Errorf("stored installation = %+v", shape.Installation)
	}
}

func TestRegisterUsesCustomVAPIDKey(t *testing.T) {
	capture := &registerCapture{}
	ts := newRegisterTestServer(t, capture)
	defer ts.Close()
	cfg := testRegisterConfig(ts)
	cfg.VAPIDKey = "custom-vapid-key"

	if _, err := register(context.Background(), ts.Client(), cfg); err != nil {
		t.Fatalf("register: %v", err)
	}

	_, registerBody := capture.bodies()
	web, ok := registerBody["web"].(map[string]any)
	if !ok {
		t.Fatalf("register body web = %#v", registerBody["web"])
	}
	if got := web["applicationPubKey"]; got != "custom-vapid-key" {
		t.Errorf("applicationPubKey = %v, want custom-vapid-key", got)
	}
}

func TestRegistrationTokenShapes(t *testing.T) {
	tests := []struct {
		name string
		fcm  string
		want string
	}{
		{"nested", `{"registration":{"token":"nested-token"},"installation":{"token":"x"}}`, "nested-token"},
		{"flat", `{"token":"flat-token"}`, "flat-token"},
		{"missing", `{"registration":{}}`, ""},
		{"invalid", `not-json`, ""},
		{"empty", ``, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			creds := &FCMCredentials{FCM: json.RawMessage(tc.fcm)}
			if got := creds.RegistrationToken(); got != tc.want {
				t.Fatalf("RegistrationToken = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeCertSHA1(t *testing.T) {
	got, err := normalizeCertSHA1("38:91:8A:45:3D:07:19:93:54:F8:B1:9A:F0:5E:C6:56:2C:ED:57:88")
	if err != nil {
		t.Fatalf("normalizeCertSHA1: %v", err)
	}
	if want := "38918a453d07199354f8b19af05ec6562ced5788"; got != want {
		t.Fatalf("normalized = %q, want %q", got, want)
	}
	for _, invalid := range []string{"", "abc", strings.Repeat("z", 40)} {
		if _, err := normalizeCertSHA1(invalid); err == nil {
			t.Errorf("normalizeCertSHA1(%q): expected an error", invalid)
		}
	}
}

func TestAddAndroidHeadersRequiresConfig(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := addAndroidHeaders(req, Config{}); err == nil {
		t.Fatal("expected an error when BundleID/AndroidCertSHA1 are missing")
	}
}

func TestGenerateKeysArePaddedBase64URL(t *testing.T) {
	keys, err := GenerateKeys()
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	for name, v := range map[string]string{"public": keys.Public, "private": keys.Private, "secret": keys.Secret} {
		if strings.ContainsAny(v, "+/") {
			t.Errorf("%s value %q is not URL-safe base64", name, v)
		}
		if _, err := decodeBase64URL(v); err != nil {
			t.Errorf("%s value %q does not decode: %v", name, v, err)
		}
	}
}

func TestRetryRetriesTransientErrors(t *testing.T) {
	attempts := 0
	err := retryWith(context.Background(), retryConfig{attempts: 5, baseDelay: time.Millisecond, maxDelay: 5 * time.Millisecond}, func() error {
		attempts++
		if attempts < 3 {
			return &httpStatusError{Op: "test", Status: http.StatusServiceUnavailable}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retryWith: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestRetryStopsOnPermanentError(t *testing.T) {
	attempts := 0
	err := retryWith(context.Background(), retryConfig{attempts: 5, baseDelay: time.Millisecond, maxDelay: 5 * time.Millisecond}, func() error {
		attempts++
		return &httpStatusError{Op: "test", Status: http.StatusBadRequest, Body: "blocked"}
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (permanent errors must not be retried)", attempts)
	}
}

func TestRetryHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := retryWith(ctx, retryConfig{attempts: 3, baseDelay: time.Millisecond, maxDelay: time.Millisecond}, func() error {
		t.Error("fn must not run with a cancelled context")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestIsTransient(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"429", &httpStatusError{Status: http.StatusTooManyRequests}, true},
		{"500", &httpStatusError{Status: http.StatusInternalServerError}, true},
		{"400", &httpStatusError{Status: http.StatusBadRequest}, false},
		{"wrapped 503", fmt.Errorf("wrap: %w", &httpStatusError{Status: http.StatusServiceUnavailable}), true},
		{"transient marker", transient(errors.New("PHONE_REGISTRATION_ERROR")), true},
		{"context deadline", context.DeadlineExceeded, false},
		{"network", &net.DNSError{IsTimeout: true}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransient(tc.err); got != tc.want {
				t.Fatalf("isTransient(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
