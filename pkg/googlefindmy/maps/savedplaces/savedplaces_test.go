package savedplaces

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/auth"
)

func newTestStore(t *testing.T, path string) *auth.Store {
	t.Helper()
	store, err := auth.NewStore(path)
	if err != nil {
		t.Fatalf("auth.NewStore(%q): %v", path, err)
	}
	return store
}

func TestParseListSpecs(t *testing.T) {
	input := `Favorites	https://www.google.com/maps/placelists/list/favorite_ID?hl=en
https://www.google.com/maps/@0,0,5z/data=!4m2!10m1!1e1!11m2!2scustom_ID!3e2
favorite_ID
# ignored
`

	specs, err := ParseListSpecs(input)
	if err != nil {
		t.Fatalf("parse list specs: %v", err)
	}
	want := []ListSpec{{ID: "favorite_ID", Name: "Favorites"}, {ID: "custom_ID"}}
	if len(specs) != len(want) {
		t.Fatalf("got %#v, want %#v", specs, want)
	}
	for i := range want {
		if specs[i] != want[i] {
			t.Errorf("spec %d = %#v, want %#v", i, specs[i], want[i])
		}
	}
}

func TestParseListSpecsRejectsInvalidInput(t *testing.T) {
	if _, err := ParseListSpecs("not a saved list URL"); err == nil {
		t.Fatal("expected invalid input error")
	}
}

func TestParseListSpecsEmptyInput(t *testing.T) {
	_, err := ParseListSpecs("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if err.Error() != "no saved-list URLs or IDs found" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseListSpecsCommentsOnly(t *testing.T) {
	_, err := ParseListSpecs("# comment\n")
	if err == nil {
		t.Fatal("expected error for comments-only input")
	}
}

func TestParseListSpecsDuplicateBackfillsName(t *testing.T) {
	input := "favorite_ID\nFavorites\thttps://www.google.com/maps/placelists/list/favorite_ID?hl=en"
	specs, err := ParseListSpecs(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 {
		t.Fatalf("got %d specs, want 1", len(specs))
	}
	if specs[0].Name != "Favorites" {
		t.Fatalf("name = %q, want Favorites", specs[0].Name)
	}
}

func TestParseEntityList(t *testing.T) {
	data := []any{
		[]any{
			nil, nil, nil, nil, "Favorites", nil, nil, nil,
			[]any{
				[]any{nil, []any{nil, nil, "", nil, "123 Main St", []any{nil, nil, 52.5, 13.4}}, "Cafe", "Try the cake", nil, nil, nil, nil, []any{[]any{1}, []any{"id"}}, []any{1659706944.0, 322471000.0}, []any{1659706944.0, 322471000.0}},
			},
		},
	}

	places, name := parseEntityList(data)
	if name != "Favorites" {
		t.Fatalf("list name = %q, want Favorites", name)
	}
	if len(places) != 1 {
		t.Fatalf("got %d places, want 1", len(places))
	}
	place := places[0]
	if place.Name != "Cafe" || place.Address != "123 Main St" || place.Notes != "Try the cake" {
		t.Fatalf("unexpected place: %#v", place)
	}
	if place.Lat != 52.5 || place.Lon != 13.4 {
		t.Fatalf("unexpected coordinates: %v, %v", place.Lat, place.Lon)
	}
	wantCreatedAt := time.Unix(1659706944, 322471000).UTC()
	if place.CreatedAt == nil || !place.CreatedAt.Equal(wantCreatedAt) {
		t.Fatalf("created_at = %v, want %v", place.CreatedAt, wantCreatedAt)
	}
}

func TestParseTimestampRejectsMalformedValues(t *testing.T) {
	for _, value := range []any{
		[]any{float64(1)},
		[]any{"1", float64(0)},
		[]any{float64(1), float64(-1)},
		[]any{float64(1), float64(1e9)},
	} {
		if got := parseTimestamp(value); got != nil {
			t.Errorf("parseTimestamp(%#v) = %v, want nil", value, got)
		}
	}
}

func TestParseEntityListDeduplication(t *testing.T) {
	data := []any{
		[]any{
			nil, nil, nil, nil, "Test", nil, nil, nil,
			[]any{
				[]any{nil, []any{nil, nil, "", nil, "A", []any{nil, nil, 1.0, 2.0}}, "Dup", ""},
				[]any{nil, []any{nil, nil, "", nil, "A", []any{nil, nil, 1.0, 2.0}}, "Dup", ""},
			},
		},
	}

	places, _ := parseEntityList(data)
	if len(places) != 1 {
		t.Fatalf("got %d places after dedup, want 1", len(places))
	}
}

func TestParseEntityListSkipZeroCoordinates(t *testing.T) {
	data := []any{
		[]any{
			nil, nil, nil, nil, "Test", nil, nil, nil,
			[]any{
				[]any{nil, []any{nil, nil, "", nil, "Addr", []any{}}, "NoCoords", ""},
			},
		},
	}

	places, _ := parseEntityList(data)
	if len(places) != 0 {
		t.Fatalf("got %d places, want 0 (zero coords skipped)", len(places))
	}
}

func TestParseEntityListEmptyName(t *testing.T) {
	data := []any{
		[]any{
			nil, nil, nil, nil, "Test", nil, nil, nil,
			[]any{
				[]any{nil, []any{nil, nil, "", nil, "Addr", []any{nil, nil, 1.0, 2.0}}, "", ""},
			},
		},
	}

	places, _ := parseEntityList(data)
	if len(places) != 0 {
		t.Fatalf("got %d places, want 0 (empty name skipped)", len(places))
	}
}

func TestParseEntityListWithoutWrapper(t *testing.T) {
	data := []any{
		nil, nil, nil, nil, "Direct", nil, nil, nil,
		[]any{
			[]any{nil, []any{nil, nil, "", nil, "Addr", []any{nil, nil, 3.0, 4.0}}, "Place", "Note"},
		},
	}

	places, name := parseEntityList(data)
	if name != "Direct" {
		t.Fatalf("list name = %q, want Direct", name)
	}
	if len(places) != 1 || places[0].Name != "Place" {
		t.Fatalf("unexpected result: %#v", places)
	}
}

func TestParseEntityListCommaFilter(t *testing.T) {
	data := []any{
		[]any{
			nil, nil, nil, nil, "Test", nil, nil, nil,
			[]any{
				[]any{nil, []any{nil, nil, "", nil, "Addr", []any{nil, nil, 1.0, 2.0}}, "a, b, c, d", ""},
			},
		},
	}

	places, _ := parseEntityList(data)
	if len(places) != 0 {
		t.Fatalf("got %d places, want 0 (multi-comma name filtered)", len(places))
	}
}

func TestParseEntityListMalformedSkipped(t *testing.T) {
	data := []any{
		[]any{
			nil, nil, nil, nil, "Test", nil, nil, nil,
			[]any{
				"not an array",
				[]any{"short"},
			},
		},
	}

	places, _ := parseEntityList(data)
	if len(places) != 0 {
		t.Fatalf("got %d places from malformed data, want 0", len(places))
	}
}

func TestClientHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := NewClient(map[string]string{"test": "val"}).
		WithHTTPClient(srv.Client()).
		WithAPIURL(srv.URL)
	_, _, err := client.fetchListViaHTTP(context.Background(), "fake")
	if err == nil {
		t.Fatal("expected error for HTTP 401")
	}
	if !strings.Contains(err.Error(), "HTTP status 401") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewClient(map[string]string{"test": "val"}).
		WithHTTPClient(srv.Client()).
		WithAPIURL(srv.URL)
	_, _, err := client.fetchListViaHTTP(ctx, "fake")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestClientJSONHijackPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(")]}'\n[[]]"))
	}))
	defer srv.Close()

	client := NewClient(map[string]string{"test": "val"}).
		WithHTTPClient(srv.Client()).
		WithAPIURL(srv.URL)
	_, _, err := client.fetchListViaHTTP(context.Background(), "fake")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientFetchListSuccess(t *testing.T) {
	response := []any{
		[]any{
			nil, nil, nil, nil, "My List", nil, nil, nil,
			[]any{
				[]any{nil, []any{nil, nil, "", nil, "123 St", []any{nil, nil, 52.5, 13.4}}, "Cafe", "Note"},
			},
		},
	}
	body, _ := json.Marshal(response)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client := NewClient(map[string]string{"test": "val"}).
		WithHTTPClient(srv.Client()).
		WithAPIURL(srv.URL)

	list, err := client.FetchList(context.Background(), ListSpec{ID: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	if list.Name != "My List" {
		t.Fatalf("name = %q, want \"My List\"", list.Name)
	}
	if len(list.Places) != 1 || list.Places[0].Name != "Cafe" {
		t.Fatalf("unexpected places: %#v", list.Places)
	}
}

func TestClientFetchListNameFallback(t *testing.T) {
	response := []any{
		[]any{
			nil, nil, nil, nil, nil, nil, nil, nil,
			[]any{
				[]any{nil, []any{nil, nil, "", nil, "Addr", []any{nil, nil, 1.0, 2.0}}, "Place", ""},
			},
		},
	}
	body, _ := json.Marshal(response)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client := NewClient(map[string]string{"test": "val"}).
		WithHTTPClient(srv.Client()).
		WithAPIURL(srv.URL)

	list, err := client.FetchList(context.Background(), ListSpec{ID: "fake", Name: "Fallback"})
	if err != nil {
		t.Fatal(err)
	}
	if list.Name != "Fallback" {
		t.Fatalf("name = %q, want \"Fallback\" (fallback used)", list.Name)
	}
}

func TestLoadMapsCookiesRawJSON(t *testing.T) {
	secretsPath := t.TempDir() + "/secrets.json"
	store := newTestStore(t, secretsPath)

	cookies := map[string]string{"SID": "abc", "HSID": "def"}
	raw, _ := json.Marshal(cookies)
	if err := store.Save(&auth.Secrets{MapsCookies: raw}); err != nil {
		t.Fatalf("save secrets: %v", err)
	}

	got, err := LoadMapsCookies(store)
	if err != nil {
		t.Fatal(err)
	}
	if got["SID"] != "abc" || got["HSID"] != "def" {
		t.Fatalf("unexpected cookies: %#v", got)
	}
}

func TestLoadMapsCookiesLegacyFormat(t *testing.T) {
	secretsPath := t.TempDir() + "/secrets.json"
	store := newTestStore(t, secretsPath)

	cookies := map[string]string{"SID": "abc"}
	rawCookies, _ := json.Marshal(cookies)
	wrapped, _ := json.Marshal(string(rawCookies))
	if err := store.Save(&auth.Secrets{MapsCookies: wrapped}); err != nil {
		t.Fatalf("save secrets: %v", err)
	}

	got, err := LoadMapsCookies(store)
	if err != nil {
		t.Fatal(err)
	}
	if got["SID"] != "abc" {
		t.Fatalf("unexpected cookies: %#v", got)
	}
}

func TestLoadMapsCookiesMissing(t *testing.T) {
	store := newTestStore(t, t.TempDir()+"/nonexistent.json")
	_, err := LoadMapsCookies(store)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadMapsCookiesMissingField(t *testing.T) {
	secretsPath := t.TempDir() + "/secrets.json"
	store := newTestStore(t, secretsPath)
	if err := store.Save(&auth.Secrets{OAuthToken: "token"}); err != nil {
		t.Fatalf("save secrets: %v", err)
	}

	_, err := LoadMapsCookies(store)
	if err == nil {
		t.Fatal("expected error for missing maps_cookies field")
	}
	if !strings.Contains(err.Error(), "maps cookies not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadMapsCookiesMalformedJSON(t *testing.T) {
	secretsPath := t.TempDir() + "/secrets.json"
	if err := os.WriteFile(secretsPath, []byte(`{"maps_cookies": "not-json"}`), 0o600); err != nil {
		t.Fatalf("write secrets: %v", err)
	}
	store := newTestStore(t, secretsPath)

	_, err := LoadMapsCookies(store)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestExtractListIDFromPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/maps/placelists/list/abc123", "abc123"},
		{"https://www.google.com/maps/placelists/list/xyz-456?hl=en", "xyz-456"},
		{"!2scustom_ID!", "custom_ID"},
		{"raw_id_here", "raw_id_here"},
		{"https://www.google.com/maps/@0,0,5z/data=!4m2!10m1!1e1!11m2!2scustom_ID!3e2", "custom_ID"},
	}

	for _, tc := range tests {
		id, err := extractListID(tc.input)
		if err != nil {
			t.Errorf("extractListID(%q): %v", tc.input, err)
			continue
		}
		if id != tc.want {
			t.Errorf("extractListID(%q) = %q, want %q", tc.input, id, tc.want)
		}
	}
}

func TestExtractListIDInvalid(t *testing.T) {
	_, err := extractListID("https://example.com/not-a-list")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}
