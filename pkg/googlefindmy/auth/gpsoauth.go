// Package auth provides Google OAuth token exchange for Find My API.
// Replaces Python Auth/token_retrieval.py and the vendored gpsoauth library.
package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// AuthURL is the Google OAuth token exchange endpoint. It is a package-level
// variable so tests can point it at an httptest server.
var AuthURL = "https://android.clients.google.com/auth"

// ClientSig is the Google Play Services signing certificate hash used when
// exchanging the oauth_token for an aas_token (mirrors gpsoauth's default).
const ClientSig = "38918a453d07199354f8b19af05ec6562ced5788"

// ExchangeOAuthToken exchanges an oauth_token (obtained from the Chrome OAuth
// flow) for an aas_token plus the account email. It mirrors
// gpsoauth.exchange_token(email, token, android_id, service="ac2dm").
//
// The email and androidID are required inputs: the email is normally retrieved
// earlier via the chrome username flow, and androidID comes from the FCM
// receiver (see FcmReceiver). The response re-confirms the email.
func ExchangeOAuthToken(email, oauthToken, androidID string) (aasToken, emailOut string, err error) {
	return exchangeOAuthToken(http.DefaultClient, AuthURL, email, oauthToken, androidID)
}

func exchangeOAuthToken(client *http.Client, endpoint, email, oauthToken, androidID string) (aasToken, emailOut string, err error) {
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

	resp, err := client.PostForm(endpoint, data)
	if err != nil {
		return "", "", fmt.Errorf("post auth: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("auth returned status %d: %s", resp.StatusCode, string(body))
	}

	// Google auth responses use \n as the separator, not &.
	vals, err := url.ParseQuery(strings.ReplaceAll(string(body), "\n", "&"))
	if err != nil {
		return "", "", fmt.Errorf("parse response: %w", err)
	}

	aasToken = vals.Get("Token")
	if aasToken == "" {
		return "", "", fmt.Errorf("aas_token (Token) not found in response: %s", string(body))
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
func RequestScopeToken(email, aasToken, androidID, scope string, playServices bool) (string, error) {
	return requestScopeToken(http.DefaultClient, AuthURL, email, aasToken, androidID, scope, playServices)
}

func requestScopeToken(client *http.Client, endpoint, email, aasToken, androidID, scope string, playServices bool) (string, error) {
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

	resp, err := client.PostForm(endpoint, data)
	if err != nil {
		return "", fmt.Errorf("post auth: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth returned status %d: %s", resp.StatusCode, string(body))
	}

	// Google auth responses use \n as the separator, not &.
	vals, err := url.ParseQuery(strings.ReplaceAll(string(body), "\n", "&"))
	if err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	token := vals.Get("Auth")
	if token == "" {
		return "", fmt.Errorf("scope token (Auth) not found in response: %s", string(body))
	}
	return token, nil
}
