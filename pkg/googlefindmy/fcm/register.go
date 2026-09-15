// Package fcm manages Firebase Cloud Messaging registration and push (MCS)
// connections for receiving Find My device location pushes.
package fcm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	fcmpb "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/fcm"
)

// flexUint64 unmarshals from either a JSON number or a JSON string containing
// a decimal number. The Python FCM library serializes android_id and
// security_token as strings; the native Go code produces numbers.
type flexUint64 uint64

func (f *flexUint64) UnmarshalJSON(b []byte) error {
	// Try number first (Go native).
	if err := json.Unmarshal(b, (*uint64)(f)); err == nil {
		return nil
	}
	// Try string (Python legacy).
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	n := new(big.Int)
	n, ok := n.SetString(s, 10)
	if !ok {
		return fmt.Errorf("flexUint64: cannot parse %q", s)
	}
	*f = flexUint64(n.Uint64())
	return nil
}

// GCM check-in / register endpoints and Firebase project configuration.
const (
	checkinURL   = "https://android.clients.google.com/checkin"
	registerURL  = "https://android.clients.google.com/c2dm/register3"
	installURL   = "https://firebaseinstallations.googleapis.com/v1/"
	fcmRegURL    = "https://fcmregistrations.googleapis.com/v1/"
	authVersion  = "FIS_v2"
	sdkVersion   = "w:0.6.6"
	chromeVer    = "94.0.4606.51"
	bundleID     = "receiver.push.com"
	fcmProjectID = "625729076819"
	fcmAppID     = "1:625729076819:web:80c8c0c1e0c8c0c1"
	fcmAPIKey    = "AIzaSyBkZ6vQaab7vrmCqJZ4QvQaab7vrmCqJZ4Q"
	fcmSenderID  = "625729076819"

	// GCM_SERVER_KEY_B64 is the base64-encoded VAPID public key used to
	// subscribe to the "625729076819" sender (Google Find My).
	GCM_SERVER_KEY_B64 = "BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4"
)

// GCMCredentials holds the result of GCM check-in + register.
type GCMCredentials struct {
	Token         string     `json:"token"`
	AppID         string     `json:"app_id"`
	AndroidID     flexUint64 `json:"android_id"`
	SecurityToken flexUint64 `json:"security_token"`
}

// FCMCredentials holds the full set of credentials returned by Register.
type FCMCredentials struct {
	Keys   *KeysCredentials `json:"keys"`
	GCM    *GCMCredentials  `json:"gcm"`
	FCM    json.RawMessage  `json:"fcm"`
	Config *FCMConfig       `json:"config"`
}

// RegistrationToken returns the FCM registration token from the nested
// fcm.registration.token field. Returns empty string if not found.
func (c *FCMCredentials) RegistrationToken() string {
	if c.FCM == nil {
		return ""
	}
	var reg struct {
		Registration struct {
			Token string `json:"token"`
		} `json:"registration"`
	}
	if err := json.Unmarshal(c.FCM, &reg); err != nil {
		return ""
	}
	return reg.Registration.Token
}

// KeysCredentials holds the P-256 key pair for Web Push decryption.
type KeysCredentials struct {
	Public  string `json:"public"`
	Private string `json:"private"`
	Secret  string `json:"secret"`
}

// FCMConfig holds configuration data.
type FCMConfig struct {
	BundleID  string `json:"bundle_id"`
	ProjectID string `json:"project_id"`
	VapidKey  string `json:"vapid_key"`
}

// GenerateKeys creates a P-256 key pair and auth secret for Web Push ECE.
func GenerateKeys() (*KeysCredentials, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate p256 key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	// Raw 65-byte uncompressed point (discard SPKI header).
	rawPub := pubDER[26:]

	secret := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}

	return &KeysCredentials{
		Public:  base64.RawURLEncoding.EncodeToString(rawPub),
		Private: base64.RawURLEncoding.EncodeToString(privDER),
		Secret:  base64.RawURLEncoding.EncodeToString(secret),
	}, nil
}

// Register performs gcm check-in, gcm register, fcm install, and fcm
// registration, returning the full credentials object.
func Register(ctx context.Context, hc *http.Client) (*FCMCredentials, error) {
	androidID := uint64(0)
	securityToken := uint64(0)

	// 1. GCM check-in.
	checkinResp, err := gcmCheckin(ctx, hc, androidID, securityToken)
	if err != nil {
		return nil, fmt.Errorf("gcm checkin: %w", err)
	}
	androidID = checkinResp.GetAndroidId()
	securityToken = checkinResp.GetSecurityToken()

	// 2. GCM register (with retries for transient errors).
	gcmCreds, err := gcmRegisterWithRetry(ctx, hc, androidID, securityToken)
	if err != nil {
		return nil, fmt.Errorf("gcm register: %w", err)
	}

	// 3. Generate keys.
	keys, err := GenerateKeys()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}

	// 4. FCM installation.
	installData, err := fcmInstall(ctx, hc)
	if err != nil {
		return nil, fmt.Errorf("fcm install: %w", err)
	}

	// 5. FCM registration.
	fcmReg, err := fcmRegister(ctx, hc, gcmCreds, installData, keys)
	if err != nil {
		return nil, fmt.Errorf("fcm register: %w", err)
	}

	fcmBytes, _ := json.Marshal(fcmReg)
	creds := &FCMCredentials{
		Keys: keys,
		GCM:  gcmCreds,
		FCM:  fcmBytes,
		Config: &FCMConfig{
			BundleID:  bundleID,
			ProjectID: fcmProjectID,
			VapidKey:  GCM_SERVER_KEY_B64,
		},
	}
	return creds, nil
}

func gcmCheckin(ctx context.Context, hc *http.Client, androidID, securityToken uint64) (*fcmpb.AndroidCheckinResponse, error) {
	platform := fcmpb.ChromeBuildProto_PLATFORM_LINUX
	chromeVerStr := chromeVer
	channel := fcmpb.ChromeBuildProto_CHANNEL_STABLE
	deviceType := fcmpb.DeviceType_DEVICE_CHROME_BROWSER
	userSerial := int32(0)
	version := int32(3)

	chrome := &fcmpb.ChromeBuildProto{
		Platform:      &platform,
		ChromeVersion: &chromeVerStr,
		Channel:       &channel,
	}
	checkin := &fcmpb.AndroidCheckinProto{
		Type:        &deviceType,
		ChromeBuild: chrome,
	}
	req := &fcmpb.AndroidCheckinRequest{
		Checkin:          checkin,
		UserSerialNumber: &userSerial,
		Version:          &version,
	}
	if androidID != 0 && securityToken != 0 {
		id := int64(androidID)
		st := securityToken
		req.Id = &id
		req.SecurityToken = &st
	}

	body, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal checkin: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, checkinURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("checkin request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("checkin post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("checkin read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checkin status %d: %s", resp.StatusCode, string(respBody))
	}

	out := &fcmpb.AndroidCheckinResponse{}
	if err := proto.Unmarshal(respBody, out); err != nil {
		return nil, fmt.Errorf("checkin unmarshal: %w", err)
	}
	return out, nil
}

func gcmRegister(ctx context.Context, hc *http.Client, androidID, securityToken uint64) (*GCMCredentials, error) {
	gcmAppID := fmt.Sprintf("wp:%s#%x%x", bundleID, time.Now().UnixNano(), androidID)

	data := url.Values{}
	data.Set("app", "org.chromium.linux")
	data.Set("X-subtype", gcmAppID)
	data.Set("device", strconv.FormatUint(androidID, 10))
	data.Set("sender", GCM_SERVER_KEY_B64)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("gcm register request: %w", err)
	}
	httpReq.Header.Set("Authorization", fmt.Sprintf("AidLogin %d:%d", androidID, securityToken))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gcm register post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gcm register read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcm register status %d: %s", resp.StatusCode, string(body))
	}

	if bytes.Contains(body, []byte("Error")) {
		return nil, fmt.Errorf("gcm register error: %s", string(body))
	}
	parts := strings.SplitN(strings.TrimSpace(string(body)), "=", 2)
	if len(parts) != 2 || parts[0] != "token" {
		return nil, fmt.Errorf("gcm register unexpected response: %s", string(body))
	}
	token := parts[1]

	return &GCMCredentials{
		Token:         token,
		AppID:         gcmAppID,
		AndroidID:     flexUint64(androidID),
		SecurityToken: flexUint64(securityToken),
	}, nil
}

// gcmRegisterWithRetry wraps gcmRegister with retries (up to 30 attempts)
// to handle transient PHONE_REGISTRATION_ERROR responses from Google's servers.
func gcmRegisterWithRetry(ctx context.Context, hc *http.Client, androidID, securityToken uint64) (*GCMCredentials, error) {
	var lastErr error
	for i := 0; i < 30; i++ {
		creds, err := gcmRegister(ctx, hc, androidID, securityToken)
		if err == nil {
			return creds, nil
		}
		lastErr = err
		slog.Debug("gcm register attempt failed, retrying", "attempt", i+1, "err", err)
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("gcm register failed after 30 attempts: %w", lastErr)
}
func fcmInstall(ctx context.Context, hc *http.Client) (map[string]interface{}, error) {
	fid := make([]byte, 17)
	if _, err := io.ReadFull(rand.Reader, fid); err != nil {
		return nil, fmt.Errorf("generate fid: %w", err)
	}
	// FID header byte (top 4 bits = 0b0111).
	fid[0] = 0b01110000 | (fid[0] & 0b00001111)
	fid64 := base64.StdEncoding.EncodeToString(fid)

	hbData, _ := json.Marshal(map[string]interface{}{
		"heartbeats": []interface{}{},
		"version":    2,
	})
	hbHeader := base64.StdEncoding.EncodeToString(hbData)

	payload := map[string]interface{}{
		"appId":       fcmAppID,
		"authVersion": authVersion,
		"fid":         fid64,
		"sdkVersion":  sdkVersion,
	}
	payloadBytes, _ := json.Marshal(payload)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		installURL+"projects/"+fcmProjectID+"/installations",
		bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("fcm install request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-firebase-client", hbHeader)
	httpReq.Header.Set("x-goog-api-key", fcmAPIKey)

	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fcm install post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fcm install read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fcm install status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fcm install unmarshal: %w", err)
	}

	authToken, _ := result["authToken"].(map[string]interface{})
	return map[string]interface{}{
		"token":         authToken["token"],
		"expires_in":    authToken["expiresIn"],
		"refresh_token": result["refreshToken"],
		"fid":           result["fid"],
		"created_at":    time.Now().Unix(),
	}, nil
}

func fcmRegister(ctx context.Context, hc *http.Client, gcm *GCMCredentials, install map[string]interface{}, keys *KeysCredentials) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"web": map[string]interface{}{
			"applicationPubKey": GCM_SERVER_KEY_B64,
			"auth":              keys.Secret,
			"endpoint":          "https://fcm.googleapis.com/fcm/send/" + gcm.Token,
			"p256dh":            keys.Public,
		},
	}
	payloadBytes, _ := json.Marshal(payload)

	installToken, _ := install["token"].(string)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fcmRegURL+"projects/"+fcmProjectID+"/registrations",
		bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("fcm register request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-key", fcmAPIKey)
	httpReq.Header.Set("x-goog-firebase-installations-auth", installToken)

	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fcm register post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fcm register read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fcm register status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fcm register unmarshal: %w", err)
	}
	return result, nil
}

// Checkin performs GCM check-in only and returns the android ID.
// This is a lightweight alternative to full Register() when only the
// android ID is needed for OAuth token exchange.
func Checkin(ctx context.Context, hc *http.Client) (androidID, securityToken uint64, err error) {
	resp, err := gcmCheckin(ctx, hc, 0, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("gcm checkin: %w", err)
	}
	return resp.GetAndroidId(), resp.GetSecurityToken(), nil
}
