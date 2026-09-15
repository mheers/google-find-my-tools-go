// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

// Package savedplaces implements the Google Maps saved-places HTTP API client.
// Replaces the now-deleted findhub-tracker/internal/poi package.
package savedplaces

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/httpclient"
	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/internal/httpbody"
)

// Place is a saved place entry from a Google Maps list.
type Place struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Address   string     `json:"address"`
	Lat       float64    `json:"lat"`
	Lon       float64    `json:"lon"`
	Notes     string     `json:"notes,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// List is a Google Maps saved list containing places.
type List struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Places []Place `json:"places"`
}

// ListSpec identifies a saved list. Name is optional and is used only as a
// fallback when the API response does not include the list name.
type ListSpec struct {
	ID   string
	Name string
}

var (
	listPathPattern  = regexp.MustCompile(`/maps/placelists/list/([A-Za-z0-9_-]+)`)
	listDataPattern  = regexp.MustCompile(`!2s([A-Za-z0-9_-]+)!`)
	rawListIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// ParseListSpecs extracts saved-list IDs from copied Maps URLs or raw IDs.
// Each non-empty line may be a URL, a raw ID, or "Name<TAB>URL".
func ParseListSpecs(input string) ([]ListSpec, error) {
	seen := make(map[string]int)
	var specs []ListSpec
	for lineNumber, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name, value := parseListInputLine(line)
		id, err := extractListID(value)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		if index, ok := seen[id]; ok {
			if specs[index].Name == "" && name != "" {
				specs[index].Name = name
			}
			continue
		}
		seen[id] = len(specs)
		specs = append(specs, ListSpec{ID: id, Name: name})
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("no saved-list URLs or IDs found")
	}
	return specs, nil
}

func parseListInputLine(line string) (name, value string) {
	if fields := strings.SplitN(line, "\t", 2); len(fields) == 2 {
		return strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1])
	}
	return "", line
}

func extractListID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if match := listPathPattern.FindStringSubmatch(value); len(match) == 2 {
		return match[1], nil
	}
	if match := listDataPattern.FindStringSubmatch(value); len(match) == 2 {
		return match[1], nil
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Path != "" {
		if match := listPathPattern.FindStringSubmatch(parsed.Path); len(match) == 2 {
			return match[1], nil
		}
	}
	if rawListIDPattern.MatchString(value) {
		return value, nil
	}
	return "", fmt.Errorf("could not extract a saved-list ID from %q", value)
}

// Client calls the Google Maps saved-place entitylist API.
type Client struct {
	cookies  map[string]string
	hc       *http.Client
	apiURL   string
	authuser int
}

// NewClient creates a saved-places client with the given cookies.
func NewClient(cookies map[string]string) *Client {
	return &Client{
		cookies: cookies,
		hc:      httpclient.Default(),
		apiURL:  "https://www.google.com/maps/preview/entitylist",
	}
}

// WithAuthUser selects the Google account index sent to the entitylist API
// (default 0).
func (c *Client) WithAuthUser(authuser int) *Client {
	c.authuser = authuser
	return c
}

// WithHTTPClient sets a custom HTTP client (useful for testing).
func (c *Client) WithHTTPClient(hc *http.Client) *Client {
	c.hc = hc
	return c
}

// WithAPIURL sets a custom API base URL (useful for testing).
func (c *Client) WithAPIURL(u string) *Client {
	c.apiURL = u
	return c
}

// FetchList fetches a single saved list and returns its places. The list ID
// must be a raw "[A-Za-z0-9_-]+" token; URLs are accepted through
// ParseListSpecs, which normalizes them first.
func (c *Client) FetchList(ctx context.Context, spec ListSpec) (List, error) {
	if !rawListIDPattern.MatchString(spec.ID) {
		return List{}, fmt.Errorf("fetch list: invalid list id %q", spec.ID)
	}
	places, apiName, err := c.fetchListViaHTTP(ctx, spec.ID)
	if err != nil {
		return List{}, fmt.Errorf("fetch list %q: %w", spec.ID, err)
	}
	name := apiName
	if name == "" {
		name = spec.Name
	}
	return List{ID: spec.ID, Name: name, Places: places}, nil
}

// FetchLists fetches multiple saved lists. Lists that fail are skipped, and
// their errors are combined into the returned error so callers can tell "no
// lists" from "all lists failed".
func (c *Client) FetchLists(ctx context.Context, specs []ListSpec) ([]List, error) {
	var (
		lists []List
		errs  []error
	)
	for _, spec := range specs {
		list, err := c.FetchList(ctx, spec)
		if err != nil {
			slog.Warn("saved list fetch failed", "id", spec.ID, "err", err)
			errs = append(errs, fmt.Errorf("list %q: %w", spec.ID, err))
			continue
		}
		slog.Debug("saved list fetched", "name", list.Name, "places", len(list.Places))
		lists = append(lists, list)
	}
	return lists, errors.Join(errs...)
}

func (c *Client) fetchListViaHTTP(ctx context.Context, listID string) ([]Place, string, error) {
	queryURL := fmt.Sprintf(
		"%s/getlist?authuser=%d&hl=en&gl=us&pb=!1m6!1s%s!2e3!3m1!1e1!3m1!1e9!2e2!3e2!4i500",
		c.apiURL, c.authuser, listID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

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
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, "", fmt.Errorf("HTTP status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	text := string(body)
	if strings.HasPrefix(text, ")]}'") {
		if idx := strings.Index(text, "\n"); idx >= 0 {
			text = text[idx+1:]
		}
	}

	var data []any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		return nil, "", fmt.Errorf("parse JSON: %w (body: %s)", err, httpbody.Safe([]byte(text)))
	}

	places, listName := parseEntityList(data)
	return places, listName, nil
}

func parseEntityList(data []any) ([]Place, string) {
	if len(data) > 0 {
		if inner, ok := data[0].([]any); ok {
			data = inner
		}
	}

	var listName string
	if len(data) > 4 {
		if name, ok := data[4].(string); ok {
			listName = name
		}
	}

	slog.Debug("parsing entity list", "entries", len(data), "list_name", listName)

	var places []Place
	seen := map[string]bool{}

	// data[8] = array of place entries (one per place)
	if len(data) > 8 {
		if placeList, ok := data[8].([]any); ok {
			for _, item := range placeList {
				placeArr, _ := item.([]any)
				if len(placeArr) < 3 {
					continue
				}

				name, _ := placeArr[2].(string)
				if name == "" || strings.Count(name, ",") > 2 {
					continue
				}

				var address, note string
				var lat, lon float64
				var createdAt *time.Time
				hasCoords := false

				if meta, ok := placeArr[1].([]any); ok {
					if len(meta) >= 5 {
						if a, ok := meta[4].(string); ok {
							address = a
						}
					}
					if len(meta) >= 6 {
						if coords, ok := meta[5].([]any); ok && len(coords) >= 4 {
							lat, _ = coords[2].(float64)
							lon, _ = coords[3].(float64)
							hasCoords = true
						}
					}
				}
				if len(placeArr) > 3 {
					note, _ = placeArr[3].(string)
				}
				// Google stores place timestamps as [Unix seconds, nanoseconds].
				if len(placeArr) > 9 {
					createdAt = parseTimestamp(placeArr[9])
				}

				if !hasCoords {
					continue
				}

				key := fmt.Sprintf("%s_%.6f_%.6f", name, lat, lon)
				if seen[key] {
					continue
				}
				seen[key] = true

				places = append(places, Place{
					ID:        extractPlaceID(placeArr),
					Name:      name,
					Address:   address,
					Notes:     note,
					Lat:       lat,
					Lon:       lon,
					CreatedAt: createdAt,
				})
			}
		}
	}

	return places, listName
}

// extractPlaceID probes the entitylist payload for an opaque place ID. The
// exact position is undocumented and varies by response version, so this is
// best-effort and returns "" when no ID-shaped string is found.
func extractPlaceID(placeArr []any) string {
	if len(placeArr) <= 7 {
		return ""
	}
	raw, ok := placeArr[7].([]any)
	if !ok {
		return ""
	}
	return firstIDString(raw)
}

func firstIDString(values []any) string {
	for _, v := range values {
		switch val := v.(type) {
		case string:
			if looksLikePlaceID(val) {
				return val
			}
		case []any:
			if s := firstIDString(val); s != "" {
				return s
			}
		}
	}
	return ""
}

// looksLikePlaceID accepts the opaque alphanumeric IDs Google uses.
func looksLikePlaceID(s string) bool {
	if len(s) < 4 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9',
			r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r == '_', r == '-', r == ':':
		default:
			return false
		}
	}
	return true
}

func parseTimestamp(value any) *time.Time {
	parts, ok := value.([]any)
	if !ok || len(parts) < 2 {
		return nil
	}
	seconds, ok := parts[0].(float64)
	if !ok || seconds != float64(int64(seconds)) {
		return nil
	}
	nanos, ok := parts[1].(float64)
	if !ok || nanos != float64(int64(nanos)) || nanos < 0 || nanos >= 1e9 {
		return nil
	}
	createdAt := time.Unix(int64(seconds), int64(nanos)).UTC()
	return &createdAt
}
