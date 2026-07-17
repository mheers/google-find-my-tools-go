package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExchangeOAuthToken(t *testing.T) {
	var got url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.Form
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("Token=oauth2rt_1%2Fabc123&Email=user%40example.com&SID=xyz"))
	}))
	defer ts.Close()

	orig := AuthURL
	AuthURL = ts.URL
	defer func() { AuthURL = orig }()

	aas, email, err := ExchangeOAuthToken("user@example.com", "oauthcookie", "1234567890abcdef")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aas != "oauth2rt_1/abc123" {
		t.Errorf("aas token = %q, want oauth2rt_1/abc123", aas)
	}
	if email != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", email)
	}

	if got.Get("Token") != "oauthcookie" {
		t.Errorf("posted Token = %q, want oauthcookie", got.Get("Token"))
	}
	if got.Get("androidId") != "1234567890abcdef" {
		t.Errorf("posted androidId = %q, want 1234567890abcdef", got.Get("androidId"))
	}
	if got.Get("service") != "ac2dm" {
		t.Errorf("posted service = %q, want ac2dm", got.Get("service"))
	}
	if got.Get("client_sig") != ClientSig {
		t.Errorf("posted client_sig = %q, want %q", got.Get("client_sig"), ClientSig)
	}
	if got.Get("droidguard_results") != "dummy123" {
		t.Errorf("posted droidguard_results = %q, want dummy123", got.Get("droidguard_results"))
	}
}

func TestExchangeOAuthTokenMissingToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Error=BadAuthentication"))
	}))
	defer ts.Close()

	orig := AuthURL
	AuthURL = ts.URL
	defer func() { AuthURL = orig }()

	if _, _, err := ExchangeOAuthToken("u", "tok", "aid"); err == nil {
		t.Fatal("expected error when Token missing from response")
	}
}

func TestRequestScopeToken(t *testing.T) {
	var got url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.Form
		_, _ = w.Write([]byte("Auth=serviceauth123&services=hist,mail"))
	}))
	defer ts.Close()

	orig := AuthURL
	AuthURL = ts.URL
	defer func() { AuthURL = orig }()

	tok, err := RequestScopeToken("user@example.com", "aastok", "aid", "android_device_manager", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "serviceauth123" {
		t.Errorf("token = %q, want serviceauth123", tok)
	}
	if got.Get("EncryptedPasswd") != "aastok" {
		t.Errorf("posted EncryptedPasswd = %q, want aastok", got.Get("EncryptedPasswd"))
	}
	if got.Get("service") != "oauth2:https://www.googleapis.com/auth/android_device_manager" {
		t.Errorf("posted service = %q", got.Get("service"))
	}
	if got.Get("app") != "com.google.android.apps.adm" {
		t.Errorf("posted app = %q, want com.google.android.apps.adm (playServices=false)", got.Get("app"))
	}

	// playServices=true uses the gms app
	_, _ = RequestScopeToken("u", "a", "aid", "spot", true)
	if got.Get("app") != "com.google.android.gms" {
		t.Errorf("posted app = %q, want com.google.android.gms (playServices=true)", got.Get("app"))
	}
}
