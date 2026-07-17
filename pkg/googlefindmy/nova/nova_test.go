package nova

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	findhub "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/findhub"
)

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, func()) {
	t.Helper()
	ts := httptest.NewServer(h)
	c := NewClient(func(ctx context.Context) (string, error) { return "adm-token", nil })
	c.BaseURL = ts.URL + "/nova/"
	return c, ts.Close
}

func TestListDevices(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nova/nbe_list_devices" {
			t.Errorf("path = %q, want /nova/nbe_list_devices", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer adm-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != userAgent {
			t.Errorf("User-Agent = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		req := &findhub.DevicesListRequest{}
		if err := proto.Unmarshal(body, req); err != nil {
			t.Fatalf("server cannot parse request: %v", err)
		}
		if req.GetDeviceListRequestPayload().GetType() != findhub.DeviceType_SPOT_DEVICE {
			t.Errorf("request type = %v, want SPOT_DEVICE", req.GetDeviceListRequestPayload().GetType())
		}
		if req.GetDeviceListRequestPayload().GetId() == "" {
			t.Error("request id (uuid) is empty")
		}

		// Build a canned response with two Spot devices.
		resp := &findhub.DevicesList{
			DeviceMetadata: []*findhub.DeviceMetadata{
				{
					UserDefinedDeviceName: "Keys",
					IdentifierInformation: &findhub.IdentitfierInformation{
						Type:       findhub.IdentifierInformationType_IDENTIFIER_SPOT,
						CanonicIds: &findhub.CanonicIds{CanonicId: []*findhub.CanonicId{{Id: "canonic-keys"}}},
					},
				},
			},
		}
		b, _ := proto.Marshal(resp)
		w.Write(b)
	})
	defer closeFn()

	list, err := c.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	ids := CanonicIDs(list)
	if len(ids) != 1 || ids[0].Name != "Keys" || ids[0].ID != "canonic-keys" {
		t.Fatalf("CanonicIDs = %+v, want [{Keys canonic-keys}]", ids)
	}
}

func TestLocate(t *testing.T) {
	c, closeFn := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nova/nbe_execute_action" {
			t.Errorf("path = %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		req := &findhub.ExecuteActionRequest{}
		if err := proto.Unmarshal(body, req); err != nil {
			t.Fatalf("server parse: %v", err)
		}
		if req.GetScope().GetDevice().GetCanonicId().GetId() != "canonic-keys" {
			t.Errorf("scope canonic id = %q", req.GetScope().GetDevice().GetCanonicId().GetId())
		}
		if req.GetRequestMetadata().GetRequestUuid() != "req-uuid" {
			t.Errorf("request uuid = %q", req.GetRequestMetadata().GetRequestUuid())
		}
		if req.GetRequestMetadata().GetGcmRegistrationId().GetId() != "gcm-token" {
			t.Errorf("gcm id = %q", req.GetRequestMetadata().GetGcmRegistrationId().GetId())
		}
		if req.GetAction().GetLocateTracker().GetContributorType() != findhub.SpotContributorType_FMDN_ALL_LOCATIONS {
			t.Errorf("contributor type = %v", req.GetAction().GetLocateTracker().GetContributorType())
		}
		w.Write([]byte{}) // actual location arrives via FCM
	})
	defer closeFn()

	_, err := c.Locate(context.Background(), "canonic-keys", "gcm-token", "req-uuid")
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
}
