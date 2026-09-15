// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

// Package auth provides Google OAuth token exchange for Find My API.
// Replaces Python Auth/token_retrieval.py and the vendored gpsoauth library.
package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/httpclient"
	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/internal/httpbody"
)

// AuthURL is the Google OAuth token exchange endpoint. It is a package-level
// variable so tests can point it at an httptest server.
//
// Deprecated: callers should build clients against an explicit endpoint; the
// variable is kept for compatibility.
var AuthURL = "https://android.clients.google.com/auth"

// ClientSig is the Google Play Services signing certificate hash used when
// exchanging the oauth_token for an aas_token (mirrors gpsoauth's default).
const ClientSig = "38918a453d07199354f8b19af05ec6562ced5788"

// Client performs Google's OAuth token exchange against a single endpoint.
// The zero value uses AuthURL and a default HTTP client.
type Client struct {
	// Endpoint overrides the auth endpoint; empty means AuthURL.
	Endpoint string
	// HTTPClient overrides the HTTP client; nil means the shared default.
	HTTPClient *http.Client
}

// NewClient returns a Client using the package defaults.
func NewClient() *Client {
	return &Client{}
}

func (c *Client) endpoint() string {
	if c == nil || c.Endpoint == "" {
		return AuthURL
	}
	return c.Endpoint
}

func (c *Client) httpClient() *http.Client {
	if c == nil {
		return httpclient.Default()
	}
	return httpclient.OrDefault(c.HTTPClient)
}

// ExchangeOAuthToken exchanges an oauth_token (obtained from the Chrome OAuth
// flow) for an aas_token plus the account email. It mirrors
// gpsoauth.exchange_token(email, token, android_id, service="ac2dm").
//
// The email and androidID are required inputs: the email is normally retrieved
// earlier via the chrome username flow, and androidID comes from the FCM
// receiver (see FcmReceiver). The response re-confirms the email.
func (c *Client) ExchangeOAuthToken(ctx context.Context, email, oauthToken, androidID string) (aasToken, emailOut string, err error) {
	return exchangeOAuthToken(ctx, c.httpClient(), c.endpoint(), email, oauthToken, androidID)
}

func exchangeOAuthToken(ctx context.Context, client *http.Client, endpoint, email, oauthToken, androidID string) (aasToken, emailOut string, err error) {
	data := url.Values{}
	data.Set("accountType", "HOSTED_OR_GOOGLE")
	data.Set("Email", email)
	data.Set("has_permission", "1")
	data.Set("add_account", "1")
	data.Set("ACCESS_TOKEN", "1")
	data.Set("Token", oauthToken)
	data.Set("service", "ac2dm")
	data.Set("source", "android")
	data.Set("androidId", androidID)
	data.Set("device_country", "us")
	data.Set("operatorCountry", "us")
	data.Set("lang", "en")
	data.Set("sdk_version", strconv.Itoa(17))
	data.Set("google_play_services_version", "240913000")
	data.Set("client_sig", ClientSig)
	data.Set("callerSig", ClientSig)
	data.Set("droidguard_results", "dummy123")

	body, err := postAuthForm(ctx, client, endpoint, data)
	if err != nil {
		return "", "", err
	}

	// Google auth responses use \n as the separator, not &.
	vals, err := url.ParseQuery(strings.ReplaceAll(string(body), "\n", "&"))
	if err != nil {
		return "", "", fmt.Errorf("parse response: %w", err)
	}

	aasToken = vals.Get("Token")
	if aasToken == "" {
		return "", "", fmt.Errorf("aas_token (Token) not found in response: %s", httpbody.Safe(body))
	}
	emailOut = vals.Get("Email")
	return aasToken, emailOut, nil
}

// RequestScopeToken performs an OAuth request for a specific Google service
// using the master aas_token (mirrors gpsoauth.perform_oauth and the Python
// Auth.token_retrieval.request_token). It returns the service Auth token.
//
// scope is the bare service name, e.g. "android_device_manager" or "spot"; it
// is expanded to "oauth2:https://www.googleapis.com/auth/<scope>". When
// playServices is true the app is com.google.android.gms, otherwise
// com.google.android.apps.adm.
func (c *Client) RequestScopeToken(ctx context.Context, email, aasToken, androidID, scope string, playServices bool) (string, error) {
	return requestScopeToken(ctx, c.httpClient(), c.endpoint(), email, aasToken, androidID, scope, playServices)
}

// ExchangeOAuthToken is a convenience wrapper around
// Client.ExchangeOAuthToken using the package default endpoint.
func ExchangeOAuthToken(ctx context.Context, email, oauthToken, androidID string) (aasToken, emailOut string, err error) {
	return NewClient().ExchangeOAuthToken(ctx, email, oauthToken, androidID)
}

// RequestScopeToken is a convenience wrapper around
// Client.RequestScopeToken using the package default endpoint.
func RequestScopeToken(ctx context.Context, email, aasToken, androidID, scope string, playServices bool) (string, error) {
	return NewClient().RequestScopeToken(ctx, email, aasToken, androidID, scope, playServices)
}

func requestScopeToken(ctx context.Context, client *http.Client, endpoint, email, aasToken, androidID, scope string, playServices bool) (string, error) {
	app := "com.google.android.apps.adm"
	if playServices {
		app = "com.google.android.gms"
	}
	service := "oauth2:https://www.googleapis.com/auth/" + scope

	data := url.Values{}
	data.Set("accountType", "HOSTED_OR_GOOGLE")
	data.Set("Email", email)
	data.Set("has_permission", "1")
	data.Set("EncryptedPasswd", aasToken)
	data.Set("service", service)
	data.Set("source", "android")
	data.Set("androidId", androidID)
	data.Set("app", app)
	data.Set("client_sig", ClientSig)
	data.Set("device_country", "us")
	data.Set("operatorCountry", "us")
	data.Set("lang", "en")
	data.Set("sdk_version", strconv.Itoa(17))
	data.Set("google_play_services_version", "240913000")

	body, err := postAuthForm(ctx, client, endpoint, data)
	if err != nil {
		return "", err
	}

	// Google auth responses use \n as the separator, not &.
	vals, err := url.ParseQuery(strings.ReplaceAll(string(body), "\n", "&"))
	if err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	token := vals.Get("Auth")
	if token == "" {
		return "", fmt.Errorf("scope token (Auth) not found in response: %s", httpbody.Safe(body))
	}
	return token, nil
}

// postAuthForm posts url-encoded credentials and returns the response body.
// The context bounds the request; the caller's client supplies the timeout.
func postAuthForm(ctx context.Context, client *http.Client, endpoint string, data url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post auth: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth returned status %d: %s", resp.StatusCode, httpbody.Safe(body))
	}
	return body, nil
}
