// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package savedplaces

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/chrome"
)

// The Saved Lists UI is driven by Google Maps' markup; keep the selectors in
// one place and prefer the link-harvesting fallback when they stop matching.
const (
	savedNavSelector   = `[jsaction*="navigationrail.saved"]`
	yourPlacesSelector = `[aria-label="Your places"] .RcCsl .CsEnBe`
	listNameSelector   = `.Io6YTe`
	listDetailSelector = `.gSkmPd`
)

// listLink is a saved-list link harvested from the page.
type listLink struct {
	Href string `json:"href"`
	Name string `json:"name"`
}

// DiscoverListSpecs uses the authenticated Maps Saved Lists page to discover
// list IDs. It is separate from the HTTP exporter: discovery is occasional,
// while fetching list contents remains HTTP-only.
func DiscoverListSpecs(ctx context.Context, cookies map[string]string) ([]ListSpec, error) {
	opts := chrome.Config{
		Headless:           true,
		DisableDevShmUsage: true,
		DisableGPU:         true,
		WindowSize:         "1280,720",
	}.AllocatorOptions()
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	if err := setBrowserCookies(browserCtx, cookies); err != nil {
		return nil, fmt.Errorf("set Maps cookies: %w", err)
	}
	if err := openSavedLists(browserCtx); err != nil {
		return nil, withScreenshot(browserCtx, err)
	}
	names, err := discoverListNames(browserCtx)
	if err != nil {
		return nil, withScreenshot(browserCtx, err)
	}

	if len(names) == 0 {
		// Fallback: harvest saved-list links directly from the DOM. The URL
		// pattern is parsed by extractListID, so this keeps working when the
		// aria-label chain changes.
		links, err := discoverListLinks(browserCtx)
		if err != nil {
			return nil, withScreenshot(browserCtx, err)
		}
		specs := specsFromListLinks(links)
		if len(specs) == 0 {
			return nil, withScreenshot(browserCtx, errors.New("no saved lists found in Google Maps"))
		}
		return specs, nil
	}

	var specs []ListSpec
	seen := make(map[string]bool)
	for _, name := range names {
		if err := clickSavedList(browserCtx, name); err != nil {
			return nil, withScreenshot(browserCtx, fmt.Errorf("open saved list %q: %w", name, err))
		}
		var pageURL string
		if err := chromedp.Run(browserCtx, chromedp.Location(&pageURL)); err != nil {
			return nil, fmt.Errorf("read saved list URL: %w", err)
		}
		id, err := extractListID(pageURL)
		if err != nil {
			return nil, fmt.Errorf("extract ID for %q: %w", name, err)
		}
		if !seen[id] {
			seen[id] = true
			specs = append(specs, ListSpec{ID: id, Name: name})
		}
		if err := openSavedLists(browserCtx); err != nil {
			return nil, withScreenshot(browserCtx, err)
		}
	}
	return specs, nil
}

// specsFromListLinks extracts list specs from harvested links, skipping
// duplicates and unparseable URLs.
func specsFromListLinks(links []listLink) []ListSpec {
	var specs []ListSpec
	seen := make(map[string]bool)
	for _, link := range links {
		id, err := extractListID(link.Href)
		if err != nil {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		specs = append(specs, ListSpec{ID: id, Name: strings.TrimSpace(link.Name)})
	}
	return specs
}

// withScreenshot attaches the path of a failure screenshot to err when one
// could be captured.
func withScreenshot(ctx context.Context, err error) error {
	path := screenshotOnFailure(ctx, "saved-lists")
	if path == "" {
		return err
	}
	return fmt.Errorf("%w (screenshot: %s)", err, path)
}

func screenshotOnFailure(ctx context.Context, label string) string {
	var buf []byte
	if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&buf)); err != nil {
		return ""
	}
	path := filepath.Join(os.TempDir(), fmt.Sprintf("googlefindmy-%s-%d.png", label, time.Now().Unix()))
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return ""
	}
	return path
}

func setBrowserCookies(ctx context.Context, cookies map[string]string) error {
	actions := make([]chromedp.Action, 0, len(cookies)+1)
	for name, value := range cookies {
		name, value := name, value
		actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
			return network.SetCookie(name, value).WithDomain(".google.com").WithPath("/").WithSecure(true).Do(ctx)
		}))
	}
	actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
		return network.SetCookie("CONSENT", "YES+").WithDomain(".google.com").WithPath("/").WithSecure(true).Do(ctx)
	}))
	return chromedp.Run(ctx, actions...)
}

func openSavedLists(ctx context.Context) error {
	if err := chromedp.Run(ctx, chromedp.Navigate("https://www.google.com/maps/")); err != nil {
		return fmt.Errorf("open Google Maps: %w", err)
	}
	navJS := fmt.Sprintf(`() => !!document.querySelector(%q)`, savedNavSelector)
	if err := chromedp.Run(ctx, chromedp.PollFunction(navJS, nil, chromedp.WithPollingInterval(250*time.Millisecond), chromedp.WithPollingTimeout(30*time.Second))); err != nil {
		return fmt.Errorf("wait for Google Maps: %w", err)
	}
	clickJS := fmt.Sprintf(`(() => {
		const button = document.querySelector(%q);
		if (!button) return false;
		button.click();
		return true;
	})()`, savedNavSelector)
	var clicked bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(clickJS, &clicked)); err != nil {
		return fmt.Errorf("open Saved lists: %w", err)
	}
	if !clicked {
		return fmt.Errorf("open Saved lists: button not found")
	}
	placesJS := fmt.Sprintf(`() => !!document.querySelector(%q)`, yourPlacesSelector)
	if err := chromedp.Run(ctx, chromedp.PollFunction(placesJS, nil, chromedp.WithPollingInterval(250*time.Millisecond), chromedp.WithPollingTimeout(30*time.Second))); err != nil {
		return fmt.Errorf("wait for Saved lists: %w", err)
	}
	return nil
}

func discoverListNames(ctx context.Context) ([]string, error) {
	var names []string
	js := fmt.Sprintf(`(() => Array.from(document.querySelectorAll(%q))
		.map(button => {
			const name = button.querySelector(%q)?.textContent?.trim() || '';
			const detail = button.querySelector(%q)?.textContent || '';
			return {name, detail};
		})
		.filter(list => list.name && /places?/i.test(list.detail))
		.filter(list => !/0 places/i.test(list.detail))
		.map(list => list.name))()`, yourPlacesSelector, listNameSelector, listDetailSelector)
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &names)); err != nil {
		return nil, fmt.Errorf("read Saved lists: %w", err)
	}
	return names, nil
}

// discoverListLinks harvests saved-list links from the page. It is the
// fallback used when the aria-label based selectors no longer match.
func discoverListLinks(ctx context.Context) ([]listLink, error) {
	var raw []string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(() => Array.from(document.querySelectorAll('a[href*="/maps/placelists/list/"]'))
		.map(a => JSON.stringify({href: a.href, name: a.textContent || ''})))()`, &raw)); err != nil {
		return nil, fmt.Errorf("read saved list links: %w", err)
	}
	links := make([]listLink, 0, len(raw))
	for _, r := range raw {
		var link listLink
		if err := json.Unmarshal([]byte(r), &link); err != nil {
			continue
		}
		links = append(links, link)
	}
	return links, nil
}

func clickSavedList(ctx context.Context, name string) error {
	var clicked bool
	js := fmt.Sprintf(`((wanted) => {
		for (const button of document.querySelectorAll(%q)) {
			const label = button.querySelector(%q)?.textContent?.trim() || '';
			if (label === wanted) { button.click(); return true; }
		}
		return false;
	})(%q)`, yourPlacesSelector, listNameSelector, name)
	if err := chromedp.Run(ctx, chromedp.Evaluate(js, &clicked)); err != nil {
		return err
	}
	if !clicked {
		return fmt.Errorf("list button not found")
	}
	if err := chromedp.Run(ctx, chromedp.PollFunction(`() => /!2s[A-Za-z0-9_-]+!/.test(location.href) || /placelists\/list\//.test(location.href)`, nil, chromedp.WithPollingInterval(250*time.Millisecond), chromedp.WithPollingTimeout(15*time.Second))); err != nil {
		return fmt.Errorf("wait for list URL: %w", err)
	}
	return nil
}
