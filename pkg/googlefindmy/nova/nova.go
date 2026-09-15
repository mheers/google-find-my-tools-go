// Package nova implements the Google Find My "Nova" HTTP API client.
// It replaces Python NovaApi/nova_request.py, ListDevices and
// ExecuteAction/LocateTracker. Requests are raw protobuf POSTs to
// https://android.googleapis.com/nova/<scope> authenticated with an ADM
// bearer token.
package nova

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/httpclient"
	findhub "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/findhub"
)

const (
	baseURL     = "https://android.googleapis.com/nova/"
	listScope   = "nbe_list_devices"
	actionScope = "nbe_execute_action"

	userAgent = "fmd/20006320; gzip"
)

// TokenSource returns a bearer token for the Nova API (the ADM oauth token).
type TokenSource func(ctx context.Context) (string, error)

// Client talks to the Nova API.
type Client struct {
	HTTPClient *http.Client
	Token      TokenSource

	// BaseURL overrides the default Nova endpoint (useful in tests).
	BaseURL string

	// fmdClientUUID is a session-fixed random UUID identifying this client,
	// sent on every action request.
	fmdClientUUID string
}

// NewClient creates a Nova client. token supplies the ADM bearer token.
func NewClient(token TokenSource) *Client {
	return &Client{
		HTTPClient:    httpclient.Default(),
		Token:         token,
		fmdClientUUID: uuid.NewString(),
	}
}

func (c *Client) request(ctx context.Context, scope string, payload []byte) ([]byte, error) {
	token, err := c.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("get nova token: %w", err)
	}

	u := c.BaseURL
	if u == "" {
		u = baseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u+scope, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("User-Agent", userAgent)

	hc := httpclient.OrDefault(c.HTTPClient)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nova request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nova %s: status %d: %s", scope, resp.StatusCode, string(body))
	}
	return body, nil
}

// ListDevices requests the list of Spot devices. It returns the decoded
// DevicesList protobuf.
func (c *Client) ListDevices(ctx context.Context) (*findhub.DevicesList, error) {
	req := &findhub.DevicesListRequest{
		DeviceListRequestPayload: &findhub.DevicesListRequestPayload{
			Type: findhub.DeviceType_SPOT_DEVICE,
			Id:   uuid.NewString(),
		},
	}
	b, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal device list request: %w", err)
	}

	resp, err := c.request(ctx, listScope, b)
	if err != nil {
		return nil, err
	}

	out := &findhub.DevicesList{}
	if err := proto.Unmarshal(resp, out); err != nil {
		return nil, fmt.Errorf("unmarshal device list: %w", err)
	}
	return out, nil
}

// Locate sends a "locate tracker" action for the given canonic device id. The
// gcmRegistrationID is the FCM token used to receive the location push, and
// requestUUID correlates the async push response. It returns the decoded
// DeviceUpdate protobuf (the actual location arrives via FCM, not in this
// response).
func (c *Client) Locate(ctx context.Context, canonicID, gcmRegistrationID, requestUUID string) (*findhub.DeviceUpdate, error) {
	req := &findhub.ExecuteActionRequest{
		Scope: &findhub.ExecuteActionScope{
			Type: findhub.DeviceType_SPOT_DEVICE,
			Device: &findhub.ExecuteActionDeviceIdentifier{
				CanonicId: &findhub.CanonicId{Id: canonicID},
			},
		},
		RequestMetadata: &findhub.ExecuteActionRequestMetadata{
			Type:              findhub.DeviceType_SPOT_DEVICE,
			RequestUuid:       requestUUID,
			FmdClientUuid:     c.fmdClientUUID,
			GcmRegistrationId: &findhub.GcmCloudMessagingIdProtobuf{Id: gcmRegistrationID},
			Unknown:           true,
		},
		Action: &findhub.ExecuteActionType{
			LocateTracker: &findhub.ExecuteActionLocateTrackerType{
				LastHighTrafficEnablingTime: &findhub.Time{Seconds: 1732120060},
				ContributorType:             findhub.SpotContributorType_FMDN_ALL_LOCATIONS,
			},
		},
	}
	b, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal locate request: %w", err)
	}

	resp, err := c.request(ctx, actionScope, b)
	if err != nil {
		return nil, err
	}

	out := &findhub.DeviceUpdate{}
	if err := proto.Unmarshal(resp, out); err != nil {
		return nil, fmt.Errorf("unmarshal device update: %w", err)
	}
	return out, nil
}

// CanonicID pairs a device's user-defined name with its canonic id.
type CanonicID struct {
	Name string
	ID   string
}

// CanonicIDs extracts all (name, canonic id) pairs from a device list,
// mirroring ProtoDecoders/decoder.py:get_canonic_ids.
func CanonicIDs(list *findhub.DevicesList) []CanonicID {
	var out []CanonicID
	for _, device := range list.GetDeviceMetadata() {
		var canonicIDs []*findhub.CanonicId
		switch device.GetIdentifierInformation().GetType() {
		case findhub.IdentifierInformationType_IDENTIFIER_ANDROID:
			canonicIDs = device.GetIdentifierInformation().GetPhoneInformation().GetCanonicIds().GetCanonicId()
		default:
			canonicIDs = device.GetIdentifierInformation().GetCanonicIds().GetCanonicId()
		}
		name := device.GetUserDefinedDeviceName()
		for _, cid := range canonicIDs {
			out = append(out, CanonicID{Name: name, ID: cid.GetId()})
		}
	}
	return out
}
