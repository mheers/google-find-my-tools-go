// Package browser handles Chrome-based OAuth flows for Google Find My API.
// Replaces Python Auth/auth_flow.py (Selenium-based).
package browser

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	findhub "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/findhub"
)

// OAuthResult holds the extracted oauth_token cookie.
type OAuthResult struct {
	OAuthToken string
}

// RunOAuthFlow opens Chrome, waits for the user to complete Google OAuth,
// then extracts the oauth_token cookie from the browser.
func RunOAuthFlow(ctx context.Context, email string) (*OAuthResult, error) {
	oauthURL := buildOAuthURL(email)

	// Create chrome context with options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.Flag("no-sandbox", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	chromeCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(slog.Debug))
	defer cancel()

	// Navigate to OAuth URL
	if err := chromedp.Run(chromeCtx, chromedp.Navigate(oauthURL)); err != nil {
		return nil, fmt.Errorf("navigate: %w", err)
	}

	slog.Info("waiting for user to complete OAuth in Chrome...")

	// Wait for oauth_token cookie to appear
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		var cookies []*network.Cookie
		if err := chromedp.Run(chromeCtx,
			chromedp.ActionFunc(func(ctx context.Context) error {
				resp, err := network.GetCookies().Do(ctx)
				if err != nil {
					return err
				}
				cookies = resp
				return nil
			}),
		); err != nil {
			return nil, fmt.Errorf("get cookies: %w", err)
		}

		for _, cookie := range cookies {
			if cookie.Name == "oauth_token" {
				slog.Info("found oauth_token cookie")
				return &OAuthResult{OAuthToken: cookie.Value}, nil
			}
		}

		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("timeout waiting for oauth_token cookie")
}

// buildOAuthURL constructs the Google OAuth URL.
func buildOAuthURL(email string) string {
	params := url.Values{}
	params.Set("client_id", "848232127117.apps.googleusercontent.com")
	params.Set("response_type", "token")
	params.Set("scope", "https://www.google.com/accounts/OAuthLogin")
	params.Set("redirect_uri", "https://accounts.google.com/o/oauth2/approved")
	if email != "" {
		params.Set("Email", email)
	}
	return "https://accounts.google.com/o/oauth2/auth?" + params.Encode()
}

// buildSecurityDomainURL constructs the security domain URL for shared key
// retrieval, mirroring Python shared_key_request.py:get_security_domain_request_url.
func buildSecurityDomainURL() (string, error) {
	req := &findhub.EncryptionUnlockRequestExtras{
		Operation: 1,
		SecurityDomain: &findhub.SecurityDomain{
			Name:    "finder_hw",
			Unknown: 0,
		},
		SessionId: uuid.NewString(),
	}
	b, err := proto.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal encryption unlock request: %w", err)
	}
	kdi := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
	return "https://accounts.google.com/encryption/unlock/android?kdi=" + kdi, nil
}

// RequestSharedKey opens Chrome, waits for the user to sign in, navigates to
// the security domain URL, and intercepts the window.mm.setVaultSharedKeys
// call to extract the E2EE shared key. Returns the hex-encoded shared key.
func RequestSharedKey(ctx context.Context) (string, error) {
	secURL, err := buildSecurityDomainURL()
	if err != nil {
		return "", fmt.Errorf("build security domain url: %w", err)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.Flag("no-sandbox", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	chromeCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Navigate to accounts.google.com first.
	slog.Info("navigating to accounts.google.com — please sign in...")
	if err := chromedp.Run(chromeCtx, chromedp.Navigate("https://accounts.google.com/")); err != nil {
		return "", fmt.Errorf("navigate to accounts: %w", err)
	}

	// Wait for the user to sign in (redirect to myaccount.google.com).
	slog.Info("waiting for sign-in (URL check, timeout 5min)...")
	deadline := time.Now().Add(5 * time.Minute)
	signedIn := false
	for time.Now().Before(deadline) {
		var currentURL string
		if err := chromedp.Run(chromeCtx,
			chromedp.Evaluate("window.location.href", &currentURL),
		); err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if strings.Contains(currentURL, "myaccount.google.com") {
			signedIn = true
			break
		}
		time.Sleep(1 * time.Second)
	}

	if !signedIn {
		return "", fmt.Errorf("sign-in timeout")
	}
	slog.Info("signed in, navigating to security domain URL...")

	// Navigate to the security domain unlock URL.
	if err := chromedp.Run(chromeCtx, chromedp.Navigate(secURL)); err != nil {
		return "", fmt.Errorf("navigate to security domain: %w", err)
	}

	// Inject JS that intercepts window.mm.setVaultSharedKeys and stores
	// the vault keys in a global variable we can poll.
	jsInject := `
		window.mm = {
			setVaultSharedKeys: function(str, vaultKeys) {
				window.__e2ee_vault_keys = vaultKeys;
			},
			closeView: function() {
				window.__e2ee_closed = true;
			}
		};
	`
	if err := chromedp.Run(chromeCtx, chromedp.Evaluate(jsInject, nil)); err != nil {
		return "", fmt.Errorf("inject js: %w", err)
	}

	// Wait for vault keys to be set (up to 30 seconds).
	slog.Info("waiting for E2EE vault keys...")
	waitDeadline := time.Now().Add(30 * time.Second)
	var vaultKeysStr string
	for time.Now().Before(waitDeadline) {
		var result interface{}
		if err := chromedp.Run(chromeCtx,
			chromedp.Evaluate("window.__e2ee_vault_keys || null", &result),
		); err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if result != nil {
			switch v := result.(type) {
			case string:
				vaultKeysStr = v
			default:
				b, _ := json.Marshal(result)
				vaultKeysStr = string(b)
			}
			if vaultKeysStr != "" {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	if vaultKeysStr == "" {
		return "", fmt.Errorf("timeout waiting for E2EE vault keys")
	}

	// Parse the vault keys JSON to extract the shared key.
	sharedKey, err := extractSharedKey(vaultKeysStr)
	if err != nil {
		return "", fmt.Errorf("extract shared key: %w", err)
	}

	slog.Info("shared key retrieved successfully")
	return hex.EncodeToString(sharedKey), nil
}

// extractSharedKey parses the vault keys JSON response and extracts the
// finder_hw shared key. Mirrors Python response_parser.py:get_fmdn_shared_key.
func extractSharedKey(vaultKeysStr string) ([]byte, error) {
	var vaultKeys map[string][]map[string]interface{}
	if err := json.Unmarshal([]byte(vaultKeysStr), &vaultKeys); err != nil {
		return nil, fmt.Errorf("parse vault keys: %w", err)
	}

	entries, ok := vaultKeys["finder_hw"]
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("no finder_hw key in vault keys")
	}

	keyMap, ok := entries[0]["key"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no key data in finder_hw entry")
	}

	// key is a JSON object with numeric string keys "0".."31" mapping to
	// byte values (e.g., {"0": 0x12, "1": 0x34, ...}).
	key := make([]byte, 0, 32)
	for i := 0; i < 32; i++ {
		s := fmt.Sprintf("%d", i)
		if v, ok := keyMap[s].(float64); ok {
			key = append(key, byte(int(v)))
		} else {
			return nil, fmt.Errorf("missing key byte %d", i)
		}
	}
	return key, nil
}
