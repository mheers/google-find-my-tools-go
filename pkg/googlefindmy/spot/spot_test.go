// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 Marcel Heers <marcel@heers.it>

package spot

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/grpc"
	findhub "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/findhub"
)

func TestGetEidInfoForE2eeDevices(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/google.internal.spot.v1.SpotService/GetEidInfoForE2eeDevices" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer spot-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/grpc" {
			t.Errorf("Content-Type = %q", got)
		}

		body, _ := io.ReadAll(r.Body)
		req := &findhub.GetEidInfoForE2EeDevicesRequest{}
		payload, err := grpc.Unwrap(body)
		if err != nil {
			t.Fatalf("server unwrap: %v", err)
		}
		if err := proto.Unmarshal(payload, req); err != nil {
			t.Fatalf("server parse: %v", err)
		}
		if !req.GetHasOwnerKeyVersion() || req.GetOwnerKeyVersion() != -1 {
			t.Errorf("request = %+v, want ownerKeyVersion=-1 hasOwnerKeyVersion=true", req)
		}

		resp := &findhub.GetEidInfoForE2EeDevicesResponse{
			EncryptedOwnerKeyAndMetadata: &findhub.EncryptedOwnerKeyAndMetadata{
				EncryptedOwnerKey: []byte{0x01, 0x02, 0x03},
				OwnerKeyVersion:   1,
				SecurityDomain:    "test",
			},
		}
		b, _ := proto.Marshal(resp)
		w.Header().Set("Content-Type", "application/grpc")
		_, _ = w.Write(grpc.Wrap(b))
	}))
	defer ts.Close()

	c := NewClient(func(ctx context.Context) (string, error) { return "spot-token", nil })
	c.BaseURL = ts.URL + "/google.internal.spot.v1.SpotService/"

	out, err := c.GetEidInfoForE2eeDevices(context.Background())
	if err != nil {
		t.Fatalf("GetEidInfoForE2eeDevices: %v", err)
	}
	if out.GetEncryptedOwnerKeyAndMetadata().GetOwnerKeyVersion() != 1 {
		t.Errorf("owner key version = %d, want 1", out.GetEncryptedOwnerKeyAndMetadata().GetOwnerKeyVersion())
	}
}
