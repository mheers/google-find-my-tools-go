// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

// Package browser handles Chrome-based OAuth flows for Google Find My API.
// Replaces Python Auth/auth_flow.py (Selenium-based).
package browser

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/chrome"
	findhub "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/findhub"
)

const (
	defaultLoginTimeout = 5 * time.Minute
	defaultKeysTimeout  = 30 * time.Second
	pollInterval        = 500 * time.Millisecond
	progressInterval    = 30 * time.Second
)

// ErrTimeout indicates that a flow waited for user interaction longer than
// its deadline. Use errors.Is to test for it.
var ErrTimeout = errors.New("browser: timeout")

// OAuthResult holds the extracted oauth_token cookie.
type OAuthResult struct {
	OAuthToken string
}

// deadlineFromContext returns the context deadline when set, otherwise now
// plus fallback.
func deadlineFromContext(ctx context.Context, fallback time.Duration) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(fallback)
}

// RunOAuthFlow opens Chrome, waits for the user to complete the Google
// embedded-setup sign-in, then extracts the oauth_token cookie from the
// browser. The wait honors the context deadline; the default is five minutes.
// cfg controls the Chrome launch; pass a persistent UserDataDir so later runs
// reuse an existing sign-in instead of signing in again.
func RunOAuthFlow(ctx context.Context, cfg chrome.Config, email string) (*OAuthResult, error) {
	if err := chrome.CheckProfileFree(cfg.UserDataDir); err != nil {
		return nil, err
	}
	oauthURL := buildOAuthURL(email)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, cfg.AllocatorOptions()...)
	defer cancel()

	chromeCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(slog.Debug))
	defer cancel()

	if err := chromedp.Run(chromeCtx, chromedp.Navigate(oauthURL)); err != nil {
		return nil, fmt.Errorf("navigate: %w", err)
	}

	slog.Info("waiting for user to complete OAuth in Chrome...")
	deadline := deadlineFromContext(ctx, defaultLoginTimeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	lastProgress := time.Now()

	for {
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

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w waiting for oauth_token cookie", ErrTimeout)
		}
		if time.Since(lastProgress) >= progressInterval {
			slog.Info("still waiting for OAuth login", "remaining", time.Until(deadline).Round(time.Second))
			lastProgress = time.Now()
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// buildOAuthURL returns the Google embedded-setup URL that drives the browser
// through the Android sign-in flow and sets the oauth_token cookie. It needs
// no OAuth client ID: the previous /o/oauth2/auth URL used a hardcoded
// third-party client that Google retired (HTTP 401 invalid_client). This
// mirrors the original Python flow (Auth/auth_flow.py).
func buildOAuthURL(email string) string {
	u := "https://accounts.google.com/EmbeddedSetup"
	if email != "" {
		params := url.Values{}
		params.Set("Email", email)
		u += "?" + params.Encode()
	}
	return u
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

// vaultKeysHookJS installs the capture hook before any page script runs. The
// Google page assigns window.mm; the property setter wraps that assignment so
// setVaultSharedKeys/closeView are observed without replacing the page's own
// object (the page's methods are still called).
const vaultKeysHookJS = `
(() => {
	const wrap = (v) => {
		if (!v || typeof v !== 'object') return v;
		const wrapFn = (name, marker, capture) => {
			if (typeof v[name] !== 'function' || v[marker]) return;
			const orig = v[name];
			v[name] = function () {
				try { capture.apply(null, arguments); } catch (e) {}
				return orig.apply(this, arguments);
			};
			v[marker] = true;
		};
		wrapFn('setVaultSharedKeys', '__fmd_keys_wrapped', function (str, keys) {
			window.__e2ee_vault_keys = keys;
		});
		wrapFn('closeView', '__fmd_close_wrapped', function () {
			window.__e2ee_closed = true;
		});
		return v;
	};
	let mm = {};
	Object.defineProperty(window, 'mm', {
		configurable: true,
		get: () => mm,
		set: (v) => { mm = wrap(v); },
	});
})();
`

// wrapVaultKeysJS wraps an already-assigned window.mm in place. It is a
// fallback for pages that mutate the object instead of assigning it.
const wrapVaultKeysJS = `
(() => {
	const v = window.mm;
	if (!v || typeof v !== 'object') return false;
	const wrapFn = (name, marker, capture) => {
		if (typeof v[name] !== 'function' || v[marker]) return;
		const orig = v[name];
		v[name] = function () {
			try { capture.apply(null, arguments); } catch (e) {}
			return orig.apply(this, arguments);
		};
		v[marker] = true;
	};
	wrapFn('setVaultSharedKeys', '__fmd_keys_wrapped', function (str, keys) {
		window.__e2ee_vault_keys = keys;
	});
	wrapFn('closeView', '__fmd_close_wrapped', function () {
		window.__e2ee_closed = true;
	});
	return true;
})();
`

// RequestSharedKey opens Chrome, waits for the user to sign in, navigates to
// the security domain URL, and intercepts the window.mm.setVaultSharedKeys
// call to extract the E2EE shared key. Returns the hex-encoded shared key.
// The sign-in wait honors the context deadline; the default is five minutes.
// cfg controls the Chrome launch; pass a persistent UserDataDir so later runs
// reuse an existing sign-in instead of signing in again.
func RequestSharedKey(ctx context.Context, cfg chrome.Config) (string, error) {
	if err := chrome.CheckProfileFree(cfg.UserDataDir); err != nil {
		return "", err
	}
	secURL, err := buildSecurityDomainURL()
	if err != nil {
		return "", fmt.Errorf("build security domain url: %w", err)
	}

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, cfg.AllocatorOptions()...)
	defer cancel()

	chromeCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Install the capture hook before any page script runs, so a page that
	// assigns window.mm cannot race the injection.
	if err := chromedp.Run(chromeCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(vaultKeysHookJS).Do(ctx)
		return err
	})); err != nil {
		return "", fmt.Errorf("install vault keys hook: %w", err)
	}

	slog.Info("navigating to accounts.google.com — please sign in...")
	if err := chromedp.Run(chromeCtx, chromedp.Navigate("https://accounts.google.com/")); err != nil {
		return "", fmt.Errorf("navigate to accounts: %w", err)
	}

	// Wait for the user to sign in (redirect to myaccount.google.com).
	slog.Info("waiting for sign-in (URL check)...")
	deadline := deadlineFromContext(ctx, defaultLoginTimeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	lastProgress := time.Now()

	for {
		var currentURL string
		if err := chromedp.Run(chromeCtx, chromedp.Location(&currentURL)); err != nil {
			slog.Debug("location check failed (retrying)", "err", err)
		} else if strings.Contains(currentURL, "myaccount.google.com") {
			break
		}

		if time.Now().After(deadline) {
			return "", fmt.Errorf("%w waiting for sign-in", ErrTimeout)
		}
		if time.Since(lastProgress) >= progressInterval {
			slog.Info("still waiting for sign-in", "remaining", time.Until(deadline).Round(time.Second))
			lastProgress = time.Now()
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
	slog.Info("signed in, navigating to security domain URL...")

	// Navigate to the security domain unlock URL.
	if err := chromedp.Run(chromeCtx, chromedp.Navigate(secURL)); err != nil {
		return "", fmt.Errorf("navigate to security domain: %w", err)
	}

	// Fallback for pages that mutated window.mm instead of assigning it.
	if err := chromedp.Run(chromeCtx, chromedp.Evaluate(wrapVaultKeysJS, nil)); err != nil {
		slog.Debug("post-load vault keys wrap failed", "err", err)
	}

	// Wait for vault keys to be set (up to 30 seconds by default).
	slog.Info("waiting for E2EE vault keys...")
	keysDeadline := deadlineFromContext(ctx, defaultKeysTimeout)
	var vaultKeysJSON string
	for {
		var closed bool
		if err := chromedp.Run(chromeCtx,
			chromedp.Evaluate(`window.__e2ee_closed === true`, &closed),
			chromedp.Evaluate(`JSON.stringify(window.__e2ee_vault_keys ?? null)`, &vaultKeysJSON),
		); err != nil {
			return "", fmt.Errorf("read vault keys: %w", err)
		}
		if closed {
			return "", errors.New("shared key page closed without providing the keys")
		}
		if vaultKeysJSON != "" && vaultKeysJSON != "null" {
			break
		}
		if time.Now().After(keysDeadline) {
			return "", fmt.Errorf("%w waiting for E2EE vault keys", ErrTimeout)
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}

	// Parse the vault keys JSON to extract the shared key.
	sharedKey, err := extractSharedKey(vaultKeysJSON)
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
		return nil, errors.New("no finder_hw key in vault keys")
	}

	keyMap, ok := entries[0]["key"].(map[string]interface{})
	if !ok {
		return nil, errors.New("no key data in finder_hw entry")
	}

	// key is a JSON object with numeric string keys "0".."31" mapping to
	// byte values (e.g., {"0": 0x12, "1": 0x34, ...}).
	var key [32]byte
	for i := 0; i < 32; i++ {
		raw, ok := keyMap[strconv.Itoa(i)]
		if !ok {
			return nil, fmt.Errorf("missing key byte %d", i)
		}
		f, ok := raw.(float64)
		if !ok || math.Trunc(f) != f || f < 0 || f > 255 {
			return nil, fmt.Errorf("invalid key byte %d: %v", i, raw)
		}
		key[i] = byte(f)
	}
	return key[:], nil
}
