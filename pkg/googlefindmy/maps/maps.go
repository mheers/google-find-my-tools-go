// Package maps implements the Google Maps Location Sharing API client.
// Replaces Python driver.py authenticate_maps, list_maps_contacts,
// fetch_maps_locations, and _call_maps_api.
package maps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/auth"
	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/chrome"
	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/httpclient"
)

// ErrCookiesExpired indicates that none of the stored Maps session cookies
// was accepted by the API. Re-run the Maps authentication flow to refresh
// them. Use errors.Is to test for it.
var ErrCookiesExpired = errors.New("maps: cookies expired or missing")

// Contact holds a parsed Maps Location Sharing contact or own-location entry.
type Contact struct {
	ID        string
	Name      string
	Type      string // "maps_shared" or "maps_self"
	Lat       float64
	Lon       float64
	Timestamp int64 // unix seconds
	Accuracy  float64
}

// AuthenticateMaps opens Chrome, navigates to Google Maps, waits for the user
// to log in, then extracts all google.com cookies and saves them to the store
// under "maps_cookies". Returns the number of cookies saved.
func AuthenticateMaps(ctx context.Context, store *auth.Store) (int, error) {
	slog.Info("starting Maps authentication — opening Chrome...")

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, chrome.Config{Headless: false}.AllocatorOptions()...)
	defer cancel()

	chromeCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	if err := chromedp.Run(chromeCtx, chromedp.Navigate("https://www.google.com/maps/")); err != nil {
		return 0, fmt.Errorf("navigate to maps: %w", err)
	}

	slog.Info("please log into Google Maps in the Chrome window...")
	slog.Info("waiting for login (polling cookies)...")

	var allCookies []*network.Cookie
	deadline := time.Now().Add(4 * time.Minute)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	lastProgress := time.Now()

	found := false
	for !found {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}

		if err := chromedp.Run(chromeCtx,
			chromedp.ActionFunc(func(ctx context.Context) error {
				resp, err := network.GetCookies().Do(ctx)
				if err != nil {
					return err
				}
				allCookies = resp
				return nil
			}),
		); err != nil {
			slog.Debug("get cookies error (retrying)", "err", err)
			continue
		}

		for _, c := range allCookies {
			if c.Name == "SID" {
				found = true
				break
			}
		}
		if !found && time.Now().After(deadline) {
			return 0, fmt.Errorf("login timeout — SID cookie not found after 4 minutes")
		}
		if !found && time.Since(lastProgress) >= 30*time.Second {
			slog.Info("still waiting for Maps login", "remaining", time.Until(deadline).Round(time.Second))
			lastProgress = time.Now()
		}
	}

	// Extra wait for all cookies to settle (bounded and cancellable).
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(3 * time.Second):
	}

	// Re-fetch cookies after the wait.
	if err := chromedp.Run(chromeCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			resp, err := network.GetCookies().Do(ctx)
			if err != nil {
				return err
			}
			allCookies = resp
			return nil
		}),
	); err != nil {
		return 0, fmt.Errorf("re-fetch cookies: %w", err)
	}

	mapsCookies := make(map[string]string)
	for _, c := range allCookies {
		if containsGoogleDomain(c.Domain) || isEssentialCookie(c.Name) {
			mapsCookies[c.Name] = c.Value
		}
	}

	if len(mapsCookies) == 0 {
		return 0, fmt.Errorf("no google.com cookies found after login")
	}

	raw, err := json.Marshal(mapsCookies)
	if err != nil {
		return 0, fmt.Errorf("marshal maps cookies: %w", err)
	}

	if err := store.Update(func(secrets *auth.Secrets) error {
		secrets.MapsCookies = raw
		return nil
	}); err != nil {
		return 0, fmt.Errorf("save maps cookies: %w", err)
	}

	slog.Info("maps authentication successful", "cookies", len(mapsCookies))
	return len(mapsCookies), nil
}

func containsGoogleDomain(domain string) bool {
	return len(domain) >= 11 && domain[len(domain)-11:] == ".google.com"
}

func isEssentialCookie(name string) bool {
	switch name {
	case "SID", "HSID", "SSID", "APISID", "SAPISID",
		"__Secure-3PAPISID", "__Secure-1PAPISID", "NID",
		"SIDCC", "__Secure-3PSIDCC", "__Secure-1PSIDCC",
		"CONSENT", "AEC", "OGPC", "SEARCH_SAMESITE":
		return true
	}
	return false
}

// ── Maps API Client ─────────────────────────────────────────────────────

// Client calls the Maps Location Sharing RPC endpoint.
type Client struct {
	cookies map[string]string
	hc      *http.Client
	apiURL  string

	mu                   sync.Mutex
	preferredAuthUser    int
	hasPreferredAuthUser bool
}

// NewClient creates a new Maps client with the given cookies.
func NewClient(cookies map[string]string) *Client {
	return &Client{cookies: cookies, hc: httpclient.Default(), apiURL: mapsAPIURL}
}

// WithHTTPClient sets a custom HTTP client (useful for testing).
func (c *Client) WithHTTPClient(hc *http.Client) *Client {
	c.hc = hc
	return c
}

// WithAPIURL sets a custom Maps RPC endpoint (useful for testing).
func (c *Client) WithAPIURL(u string) *Client {
	c.apiURL = u
	return c
}

const mapsAPIURL = "https://www.google.com/maps/rpc/locationsharing/read"

// pb is the static viewport descriptor (Google HQ). Irrelevant to the
// location-sharing data itself; a fixed value works for any account.
const pb = "!1m7!8m6!1m3!1i14!2i8413!3i5385!2i6!3x4095" +
	"!2m3!1e0!2sm!3i407105169!3m7!2sen!5e1105!12m4" +
	"!1e68!2m2!1sset!2sRoadmap!4e1!5m4!1e4!8m2!1e0!" +
	"1e1!6m9!1e12!2i2!26m1!4b1!30m1!" +
	"1f1.3953487873077393!39b1!44e1!50e0!23i4111425"

// GetState calls the MapsLocationSharingService GetState RPC and returns the
// parsed contacts (shared contacts + own location).
func (c *Client) GetState(ctx context.Context) ([]Contact, error) {
	data, err := c.callAPI(ctx)
	if err != nil {
		return nil, fmt.Errorf("get state: %w", err)
	}
	return parseContacts(data), nil
}

// callAPI tries each authuser index (0, 1, 2) against the Maps API,
// preferring the index that succeeded last. Returns the full parsed JSON
// array on first success.
func (c *Client) callAPI(ctx context.Context) ([]any, error) {
	for _, authuser := range c.authUserOrder() {
		result, err := c.tryAuthUser(ctx, authuser)
		if err != nil {
			slog.Debug("maps api authuser failed", "authuser", authuser, "err", err)
			continue
		}
		if result != nil {
			c.rememberAuthUser(authuser)
			return result, nil
		}
	}
	return nil, fmt.Errorf("%w: all authuser indices failed", ErrCookiesExpired)
}

// authUserOrder returns the account indices to try, starting with the one that
// worked previously.
func (c *Client) authUserOrder() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.hasPreferredAuthUser {
		return []int{0, 1, 2}
	}
	order := []int{c.preferredAuthUser}
	for _, authuser := range []int{0, 1, 2} {
		if authuser != c.preferredAuthUser {
			order = append(order, authuser)
		}
	}
	return order
}

func (c *Client) rememberAuthUser(authuser int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.preferredAuthUser = authuser
	c.hasPreferredAuthUser = true
}

func (c *Client) tryAuthUser(ctx context.Context, authuser int) ([]any, error) {
	u := fmt.Sprintf("%s?authuser=%d&hl=en&gl=us&pb=%s", c.apiURL, authuser, url.QueryEscape(pb))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	// Set cookies on the request
	for name, value := range c.cookies {
		req.AddCookie(&http.Cookie{
			Name:   name,
			Value:  value,
			Domain: ".google.com",
			Path:   "/",
		})
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Strip JSON hijacking prefix.
	data := body
	if len(data) > 4 && string(data[:4]) == ")]}'" {
		// Find the newline or just skip past the prefix
		for i := 4; i < len(data); i++ {
			if data[i] == '\n' || data[i] == '\'' || data[i] == '"' {
				data = data[i+1:]
				break
			}
		}
	}

	var parsed []any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	// Check the auth sentinel at index [6].
	if len(parsed) < 7 {
		slog.Debug("maps api: response too short", "len", len(parsed))
		return nil, nil
	}
	if sentinel, ok := parsed[6].(string); ok && sentinel == "GgA=" {
		slog.Debug("maps api: not authenticated (sentinel == GgA=)")
		return nil, nil
	}

	return parsed, nil
}

// parseContacts converts the raw Maps API response array into Contact structs.
func parseContacts(data []any) []Contact {
	var results []Contact

	// Shared contacts at index [0].
	if len(data) > 0 {
		if contactsRaw, ok := data[0].([]any); ok {
			for _, item := range contactsRaw {
				contactList, ok := item.([]any)
				if !ok || len(contactList) < 7 {
					continue
				}
				c := extractContact(contactList)
				if c.ID != "" {
					results = append(results, c)
				}
			}
		}
	}

	// Own location at index [9].
	if len(data) > 9 {
		if ownLoc, ok := data[9].([]any); ok && len(ownLoc) >= 2 {
			if locInfo, ok := ownLoc[1].([]any); ok && len(locInfo) >= 4 {
				if coords, ok := locInfo[1].([]any); ok && len(coords) >= 3 {
					lon, _ := toFloat(coords[1])
					lat, _ := toFloat(coords[2])
					tsMS, _ := toFloat(locInfo[2])
					acc, _ := toFloat(locInfo[3])
					ts := int64(tsMS)
					if tsMS > 100000000000 {
						ts /= 1000
					}

					ownID := "self"
					if len(data) > 7 {
						if id, ok := data[7].(string); ok && id != "" {
							ownID = id
						}
					}

					results = append(results, Contact{
						ID:        ownID,
						Name:      "You",
						Type:      "maps_self",
						Lat:       lat,
						Lon:       lon,
						Timestamp: ts,
						Accuracy:  acc,
					})
				}
			}
		}
	}

	return results
}

func extractContact(contact []any) Contact {
	c := Contact{Type: "maps_shared"}

	// basicInfo at [0]: [googleId, photoUrl, null, fullName, ...]
	if basicInfo, ok := contact[0].([]any); ok && len(basicInfo) >= 4 {
		if id, ok := basicInfo[0].(string); ok {
			c.ID = id
		}
		if name, ok := basicInfo[3].(string); ok {
			c.Name = name
		}
	}

	// shortProfile at [6] as fallback for ID/name
	if len(contact) > 6 {
		if sp, ok := contact[6].([]any); ok && len(sp) >= 4 {
			if c.ID == "" {
				if id, ok := sp[0].(string); ok {
					c.ID = id
				}
			}
			if c.Name == "" || c.Name == "Unknown" {
				if name, ok := sp[2].(string); ok {
					c.Name = name
				}
			}
		}
	}

	// locationInfo at [1]: [null, [null, lon, lat], timestampMs, accuracy, ...]
	if locInfo, ok := contact[1].([]any); ok && len(locInfo) >= 4 {
		if coords, ok := locInfo[1].([]any); ok && len(coords) >= 3 {
			c.Lon, _ = toFloat(coords[1])
			c.Lat, _ = toFloat(coords[2])
		}
		tsMS, _ := toFloat(locInfo[2])
		c.Timestamp = int64(tsMS)
		if tsMS > 100000000000 {
			c.Timestamp /= 1000
		}
		c.Accuracy, _ = toFloat(locInfo[3])
	}

	return c
}

func toFloat(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case string:
		var f float64
		if _, err := fmt.Sscanf(val, "%f", &f); err == nil {
			return f, true
		}
		return 0, false
	default:
		return 0, false
	}
}
