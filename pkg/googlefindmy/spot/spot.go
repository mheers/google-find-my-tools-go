// Package spot implements the Google Find My "Spot" gRPC-over-HTTP/2 API
// client. It replaces Python SpotApi/spot_request.py and the gRPC framing in
// SpotApi/grpc_parser.py. The endpoint is
// https://spot-pa.googleapis.com/google.internal.spot.v1.SpotService/<scope>,
// authenticated with a Spot bearer token.
package spot

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/grpc"
	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/httpclient"
	findhub "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/findhub"
)

const (
	baseURL              = "https://spot-pa.googleapis.com/google.internal.spot.v1.SpotService/"
	eidInfoScope         = "GetEidInfoForE2eeDevices"
	createBleDeviceScope = "CreateBleDevice"
	uploadKeysScope      = "UploadPrecomputedPublicKeyIds"

	userAgent = "com.google.android.gms/244433022 grpc-java-cronet/1.69.0-SNAPSHOT"
)

// TokenSource returns a bearer token for the Spot API (the Spot oauth token).
type TokenSource func(ctx context.Context) (string, error)

// Client talks to the Spot API.
type Client struct {
	HTTPClient *http.Client
	Token      TokenSource
	BaseURL    string
}

// NewClient creates a Spot client. token supplies the Spot bearer token.
func NewClient(token TokenSource) *Client {
	return &Client{HTTPClient: httpclient.Default(), Token: token}
}

// request marshals req, wraps it in gRPC framing, POSTs it, and returns the
// unwrapped response payload.
func (c *Client) request(ctx context.Context, scope string, req proto.Message) ([]byte, error) {
	token, err := c.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("get spot token: %w", err)
	}

	b, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	u := c.BaseURL
	if u == "" {
		u = baseURL
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u+scope, bytes.NewReader(grpc.Wrap(b)))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/grpc")
	httpReq.Header.Set("Te", "trailers")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Grpc-Accept-Encoding", "gzip")
	httpReq.Header.Set("User-Agent", userAgent)

	hc := httpclient.OrDefault(c.HTTPClient)
	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("spot request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	framed, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spot %s: status %d: %s", scope, resp.StatusCode, string(framed))
	}

	payload, err := grpc.Unwrap(framed)
	if err != nil {
		return nil, fmt.Errorf("unwrap spot response: %w", err)
	}
	return payload, nil
}

// GetEidInfoForE2eeDevices fetches the encrypted owner key metadata. The
// response contains the encrypted owner key (decryptable with the shared key)
// and its version.
func (c *Client) GetEidInfoForE2eeDevices(ctx context.Context) (*findhub.GetEidInfoForE2EeDevicesResponse, error) {
	req := &findhub.GetEidInfoForE2EeDevicesRequest{
		OwnerKeyVersion:    -1,
		HasOwnerKeyVersion: true,
	}
	raw, err := c.request(ctx, eidInfoScope, req)
	if err != nil {
		return nil, err
	}
	out := &findhub.GetEidInfoForE2EeDevicesResponse{}
	if err := proto.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("unmarshal eid info: %w", err)
	}
	return out, nil
}
