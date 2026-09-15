package maps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseContacts_SharedOnly(t *testing.T) {
	data := []any{
		[]any{
			[]any{
				[]any{"user1", "http://photo", nil, "Alice"},
				[]any{nil, []any{nil, 13.4, 52.5}, float64(1719000000000), float64(10), "Berlin"},
				nil, nil, nil, nil,
				[]any{"user1", "http://photo", "Alice", "Ali"},
			},
			[]any{
				[]any{"user2", "http://photo", nil, "Bob"},
				nil, // no location
				nil, nil, nil, nil,
				[]any{"user2", "http://photo", "Bob", "B"},
			},
		},
	}

	contacts := parseContacts(data)
	assert.Len(t, contacts, 2)

	assert.Equal(t, "user1", contacts[0].ID)
	assert.Equal(t, "Alice", contacts[0].Name)
	assert.Equal(t, "maps_shared", contacts[0].Type)
	assert.InDelta(t, 52.5, contacts[0].Lat, 0.001)
	assert.InDelta(t, 13.4, contacts[0].Lon, 0.001)
	assert.Equal(t, int64(1719000000), contacts[0].Timestamp) // ms → s
	assert.InDelta(t, 10.0, contacts[0].Accuracy, 0.001)

	assert.Equal(t, "user2", contacts[1].ID)
	assert.Equal(t, "Bob", contacts[1].Name)
	assert.Equal(t, "maps_shared", contacts[1].Type)
	assert.InDelta(t, 0.0, contacts[1].Lat, 0.001) // no location
}

func TestParseContacts_WithOwnLocation(t *testing.T) {
	data := []any{
		[]any{},
		nil, nil, nil, nil, nil,
		"GgA=", // sentinel — should be ignored because auth user might return this
		"self_google_id",
		nil,
		[]any{
			nil,
			[]any{nil, []any{nil, -73.98, 40.76}, float64(1719100000000), float64(8), "NYC"},
			"token",
		},
		// index 9
	}

	// We need to modify the auth sentinel check: data[6] = "GgA=" means
	// unauthenticated for an actual API response — but for our parsing test,
	// we want to verify own-location extraction. The callAPI function checks
	// sentinel; parseContacts doesn't. So this test validates parseContacts
	// directly.
	contacts := parseContacts(data)
	assert.Len(t, contacts, 1)

	assert.Equal(t, "self_google_id", contacts[0].ID)
	assert.Equal(t, "You", contacts[0].Name)
	assert.Equal(t, "maps_self", contacts[0].Type)
	assert.InDelta(t, 40.76, contacts[0].Lat, 0.001)
	assert.InDelta(t, -73.98, contacts[0].Lon, 0.001)
	assert.Equal(t, int64(1719100000), contacts[0].Timestamp)
	assert.InDelta(t, 8.0, contacts[0].Accuracy, 0.001)
}

func TestParseContacts_BothSharedAndOwn(t *testing.T) {
	data := []any{
		[]any{
			[]any{
				[]any{"contact1", "http://photo", nil, "Charlie"},
				[]any{nil, []any{nil, 2.35, 48.86}, float64(1719200000000), float64(15), "Paris"},
				nil, nil, nil, nil,
				[]any{"contact1", "http://photo", "Charlie", "C"},
			},
		},
		nil, nil, nil, nil, nil,
		"some_value", // auth passes
		"my_google_id",
		nil,
		[]any{
			nil,
			[]any{nil, []any{nil, 13.41, 52.52}, float64(1719300000000), float64(5), "Berlin"},
			"token",
		},
	}

	contacts := parseContacts(data)
	assert.Len(t, contacts, 2)

	// First should be shared contact
	assert.Equal(t, "contact1", contacts[0].ID)
	assert.Equal(t, "maps_shared", contacts[0].Type)

	// Second should be own location
	assert.Equal(t, "my_google_id", contacts[1].ID)
	assert.Equal(t, "maps_self", contacts[1].Type)
	assert.Equal(t, "You", contacts[1].Name)
}

func TestParseContacts_EmptyResponse(t *testing.T) {
	contacts := parseContacts([]any{})
	assert.Len(t, contacts, 0)

	contacts = parseContacts([]any{nil, nil, nil, nil, nil, nil, nil, nil, nil, nil})
	assert.Len(t, contacts, 0)
}

func TestParseContacts_MissingFields(t *testing.T) {
	data := []any{
		[]any{
			// Contact with missing basicInfo fields
			[]any{
				[]any{}, // empty basic info
				[]any{nil, []any{nil, 1.0, 2.0}, float64(1000), float64(1)},
				nil, nil, nil, nil,
				nil, // no short profile
			},
		},
	}

	contacts := parseContacts(data)
	// Should produce a contact with empty ID (filtered out by extractContact)
	assert.Len(t, contacts, 0)
}

func TestParseContacts_UnixTimestamp(t *testing.T) {
	// Some responses return unix seconds directly (not ms)
	data := []any{
		[]any{
			[]any{
				[]any{"u1", "http://photo", nil, "Unix"},
				[]any{nil, []any{nil, 1.0, 2.0}, float64(1719000000), float64(1)},
				nil, nil, nil, nil,
				[]any{"u1", "http://photo", "Unix", "U"},
			},
		},
	}

	contacts := parseContacts(data)
	assert.Len(t, contacts, 1)
	// 1719000000 < 100000000000, so it should be kept as-is
	assert.Equal(t, int64(1719000000), contacts[0].Timestamp)
}

func sharedContactResponse() []any {
	contact := []any{
		[]any{"user1", "http://photo", nil, "Alice"},
		[]any{nil, []any{nil, 13.4, 52.5}, float64(1719000000000), float64(10), "Berlin"},
		nil, nil, nil, nil,
		[]any{"user1", "http://photo", "Alice", "Ali"},
	}
	return []any{
		[]any{contact},
		nil, nil, nil, nil, nil,
		"some_value", // auth sentinel, not "GgA="
		"self_id",
		nil,
	}
}

func TestGetStateSkipsUnauthenticatedAuthUser(t *testing.T) {
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authuser := r.URL.Query().Get("authuser")
		hits = append(hits, authuser)
		if authuser == "0" {
			_, _ = w.Write([]byte(")]}'\n[null,null,null,null,null,null,\"GgA=\"]"))
			return
		}
		body, _ := json.Marshal(sharedContactResponse())
		_, _ = w.Write(append([]byte(")]}'\n"), body...))
	}))
	defer srv.Close()

	client := NewClient(map[string]string{"SID": "x"}).
		WithHTTPClient(srv.Client()).
		WithAPIURL(srv.URL)

	contacts, err := client.GetState(context.Background())
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	assert.Len(t, contacts, 1)
	assert.Equal(t, "Alice", contacts[0].Name)
	assert.Equal(t, []string{"0", "1"}, hits)
}

func TestGetStateAllAuthUsersUnauthenticated(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(")]}'\n[null,null,null,null,null,null,\"GgA=\"]"))
	}))
	defer srv.Close()

	client := NewClient(map[string]string{"SID": "x"}).
		WithHTTPClient(srv.Client()).
		WithAPIURL(srv.URL)

	_, err := client.GetState(context.Background())
	if err == nil {
		t.Fatal("expected an error when every authuser index is unauthenticated")
	}
	if !strings.Contains(err.Error(), "cookies may be expired") {
		t.Fatalf("unexpected error: %v", err)
	}
	assert.Equal(t, 3, hits)
}

func FuzzParseContacts(f *testing.F) {
	f.Add([]byte(`[[["u","p",null,"Name"]]]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var parsed []any
		if err := json.Unmarshal(data, &parsed); err != nil {
			return
		}
		_ = parseContacts(parsed)
	})
}
