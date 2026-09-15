package savedplaces

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/chrome"
)

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
		return nil, err
	}
	names, err := discoverListNames(browserCtx)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no saved lists found in Google Maps")
	}

	var specs []ListSpec
	seen := make(map[string]bool)
	for _, name := range names {
		if err := clickSavedList(browserCtx, name); err != nil {
			return nil, fmt.Errorf("open saved list %q: %w", name, err)
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
			return nil, err
		}
	}
	return specs, nil
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
	if err := chromedp.Run(ctx, chromedp.PollFunction(`() => !!document.querySelector('[jsaction*="navigationrail.saved"]')`, nil, chromedp.WithPollingInterval(250*time.Millisecond), chromedp.WithPollingTimeout(30*time.Second))); err != nil {
		return fmt.Errorf("wait for Google Maps: %w", err)
	}
	var clicked bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(() => {
		const button = document.querySelector('[jsaction*="navigationrail.saved"]');
		if (!button) return false;
		button.click();
		return true;
	})()`, &clicked)); err != nil || !clicked {
		if err != nil {
			return fmt.Errorf("open Saved lists: %w", err)
		}
		return fmt.Errorf("open Saved lists: button not found")
	}
	if err := chromedp.Run(ctx, chromedp.PollFunction(`() => !!document.querySelector('[aria-label="Your places"] .CsEnBe')`, nil, chromedp.WithPollingInterval(250*time.Millisecond), chromedp.WithPollingTimeout(30*time.Second))); err != nil {
		return fmt.Errorf("wait for Saved lists: %w", err)
	}
	return nil
}

func discoverListNames(ctx context.Context) ([]string, error) {
	var names []string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(() => Array.from(document.querySelectorAll('[aria-label="Your places"] .RcCsl .CsEnBe'))
		.map(button => {
			const name = button.querySelector('.Io6YTe')?.textContent?.trim() || '';
			const detail = button.querySelector('.gSkmPd')?.textContent || '';
			return {name, detail};
		})
		.filter(list => list.name && /places?/i.test(list.detail))
		.filter(list => !/0 places/i.test(list.detail))
		.map(list => list.name))()`, &names)); err != nil {
		return nil, fmt.Errorf("read Saved lists: %w", err)
	}
	return names, nil
}

func clickSavedList(ctx context.Context, name string) error {
	var clicked bool
	js := fmt.Sprintf(`((wanted) => {
		for (const button of document.querySelectorAll('[aria-label="Your places"] .RcCsl .CsEnBe')) {
			const label = button.querySelector('.Io6YTe')?.textContent?.trim() || '';
			if (label === wanted) { button.click(); return true; }
		}
		return false;
	})(%q)`, name)
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
