// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package savedplaces

import "testing"

func TestSpecsFromListLinks(t *testing.T) {
	links := []listLink{
		{Href: "https://www.google.com/maps/placelists/list/abc123?hl=en", Name: "  Favorites "},
		{Href: "https://www.google.com/maps/placelists/list/abc123", Name: "duplicate"},
		{Href: "!2scustom_ID!", Name: "custom"},
		{Href: "https://example.com/not-a-list", Name: "nope"},
		{Href: "", Name: "empty"},
	}

	specs := specsFromListLinks(links)
	want := []ListSpec{
		{ID: "abc123", Name: "Favorites"},
		{ID: "custom_ID", Name: "custom"},
	}
	if len(specs) != len(want) {
		t.Fatalf("got %#v, want %#v", specs, want)
	}
	for i := range want {
		if specs[i] != want[i] {
			t.Errorf("spec %d = %#v, want %#v", i, specs[i], want[i])
		}
	}
}

func TestSpecsFromListLinksEmpty(t *testing.T) {
	if specs := specsFromListLinks(nil); len(specs) != 0 {
		t.Fatalf("got %#v, want no specs", specs)
	}
}
