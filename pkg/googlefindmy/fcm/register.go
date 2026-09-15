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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/httpclient"
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

// Protocol constants. The Firebase project identifiers live in Config.
const (
	authVersion = "FIS_v2"
	sdkVersion  = "w:0.6.6"
	chromeVer   = "94.0.4606.51"

	// GCM_SERVER_KEY_B64 is the unpadded base64url VAPID public key used to
	// subscribe to the Google Find My FCM sender. It is a public client
	// identifier, not a secret.
	GCM_SERVER_KEY_B64 = "BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4"
)

// Config holds the Firebase/GCM client configuration used for registration.
// The defaults mirror the reference Python implementation and consist of
// public client identifiers, not user secrets. All fields are overridable so
// tests can point the endpoints at an httptest server.
type Config struct {
	ProjectID       string // FIS/FCM project, e.g. "google.com:api-project-289722593072"
	AppID           string // FCM app id, e.g. "1:289722593072:android:3cfcf5bc359f0308"
	APIKey          string // Firebase web API key
	SenderID        string // FCM sender id (informational)
	BundleID        string // Android package name, sent as X-Android-Package
	AndroidCertSHA1 string // APK signing cert SHA-1, sent as X-Android-Cert
	VAPIDKey        string // VAPID public key; the default is omitted on registration
	ChromeVersion   string // reported to GCM check-in

	CheckinURL  string
	RegisterURL string
	InstallURL  string
	FCMRegURL   string
}

// DefaultConfig returns the configuration used by Register, matching the
// values of the reference implementation.
func DefaultConfig() Config {
	return Config{
		ProjectID:       "google.com:api-project-289722593072",
		AppID:           "1:289722593072:android:3cfcf5bc359f0308",
		APIKey:          "AIzaSyD_gko3P392v6how2H7UpdeXQ0v2HLettc",
		SenderID:        "289722593072",
		BundleID:        "com.google.android.apps.adm",
		AndroidCertSHA1: "38918a453d07199354f8b19af05ec6562ced5788",
		VAPIDKey:        GCM_SERVER_KEY_B64,
		ChromeVersion:   chromeVer,

		CheckinURL:  "https://android.clients.google.com/checkin",
		RegisterURL: "https://android.clients.google.com/c2dm/register3",
		InstallURL:  "https://firebaseinstallations.googleapis.com/v1/",
		FCMRegURL:   "https://fcmregistrations.googleapis.com/v1/",
	}
}

// GCMCredentials holds the result of GCM check-in + register.
type GCMCredentials struct {
	Token         string     `json:"token"`
	AppID         string     `json:"app_id"`
	AndroidID     flexUint64 `json:"android_id"`
	SecurityToken flexUint64 `json:"security_token"`
}

// Installation holds the Firebase Installation Service result. The JSON keys
// are the ones the Python implementation stores in secrets.json.
type Installation struct {
	Token        string `json:"token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	FID          string `json:"fid"`
	CreatedAt    int64  `json:"created_at"`
}

// FCMCredentials holds the full set of credentials returned by Register.
// FCM keeps the Python-compatible shape
// {"registration": {...}, "installation": {...}} so secrets.json stays
// interchangeable with the reference tooling.
type FCMCredentials struct {
	Keys   *KeysCredentials `json:"keys"`
	GCM    *GCMCredentials  `json:"gcm"`
	FCM    json.RawMessage  `json:"fcm"`
	Config *FCMConfig       `json:"config"`
}

// RegistrationToken returns the FCM registration token. It accepts both the
// Python-compatible nested shape (fcm.registration.token) and the flat shape
// (fcm.token) written by earlier versions of this library. Returns an empty
// string if no token is present.
func (c *FCMCredentials) RegistrationToken() string {
	if len(c.FCM) == 0 {
		return ""
	}
	var nested struct {
		Registration struct {
			Token string `json:"token"`
		} `json:"registration"`
	}
	if err := json.Unmarshal(c.FCM, &nested); err == nil && nested.Registration.Token != "" {
		return nested.Registration.Token
	}
	var flat struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(c.FCM, &flat); err == nil {
		return flat.Token
	}
	return ""
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

// GenerateKeys creates a P-256 key pair and auth secret for Web Push ECE. The
// values are padded base64url, matching Python's urlsafe_b64encode output.
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
		Public:  base64.URLEncoding.EncodeToString(rawPub),
		Private: base64.URLEncoding.EncodeToString(privDER),
		Secret:  base64.URLEncoding.EncodeToString(secret),
	}, nil
}

// Register performs gcm check-in, gcm register, fcm install, and fcm
// registration with DefaultConfig, returning the full credentials object.
func Register(ctx context.Context, hc *http.Client) (*FCMCredentials, error) {
	return register(ctx, hc, DefaultConfig())
}

func register(ctx context.Context, hc *http.Client, cfg Config) (*FCMCredentials, error) {
	hc = httpclient.OrDefault(hc)

	// 1. GCM check-in.
	checkinResp, err := gcmCheckin(ctx, hc, cfg, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("gcm checkin: %w", err)
	}
	androidID := checkinResp.GetAndroidId()
	securityToken := checkinResp.GetSecurityToken()

	// 2. GCM register (with retries for transient errors).
	gcmCreds, err := gcmRegisterWithRetry(ctx, hc, cfg, androidID, securityToken)
	if err != nil {
		return nil, fmt.Errorf("gcm register: %w", err)
	}

	// 3. Generate keys.
	keys, err := GenerateKeys()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}

	// 4. FCM installation.
	install, err := fcmInstall(ctx, hc, cfg)
	if err != nil {
		return nil, fmt.Errorf("fcm install: %w", err)
	}

	// 5. FCM registration.
	registration, err := fcmRegister(ctx, hc, cfg, gcmCreds, install, keys)
	if err != nil {
		return nil, fmt.Errorf("fcm register: %w", err)
	}

	installRaw, err := json.Marshal(install)
	if err != nil {
		return nil, fmt.Errorf("marshal installation: %w", err)
	}
	fcmBytes, err := json.Marshal(struct {
		Registration json.RawMessage `json:"registration"`
		Installation json.RawMessage `json:"installation"`
	}{
		Registration: registration,
		Installation: installRaw,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal fcm credentials: %w", err)
	}

	creds := &FCMCredentials{
		Keys: keys,
		GCM:  gcmCreds,
		FCM:  fcmBytes,
		Config: &FCMConfig{
			BundleID:  cfg.BundleID,
			ProjectID: cfg.ProjectID,
			VapidKey:  cfg.VAPIDKey,
		},
	}
	return creds, nil
}

// addAndroidHeaders sets the Android app-restriction headers that Google
// requires for FIS/FCM requests. The certificate fingerprint is normalized to
// lowercase without separators.
func addAndroidHeaders(req *http.Request, cfg Config) error {
	if cfg.BundleID == "" || cfg.AndroidCertSHA1 == "" {
		return errors.New("fcm: BundleID and AndroidCertSHA1 are required for FIS/FCM requests")
	}
	cert, err := normalizeCertSHA1(cfg.AndroidCertSHA1)
	if err != nil {
		return err
	}
	req.Header.Set("X-Android-Package", cfg.BundleID)
	req.Header.Set("X-Android-Cert", cert)
	return nil
}

func normalizeCertSHA1(v string) (string, error) {
	h := strings.NewReplacer(":", "", " ", "").Replace(strings.ToLower(v))
	if len(h) != 40 {
		return "", fmt.Errorf("fcm: invalid Android cert SHA-1 %q", v)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fmt.Errorf("fcm: invalid Android cert SHA-1 %q: %w", v, err)
	}
	return h, nil
}

func parseExpiresIn(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSuffix(s, "s"))
	if err != nil {
		return 0, fmt.Errorf("fcm install: invalid expiresIn %q", s)
	}
	return n, nil
}

func gcmCheckin(ctx context.Context, hc *http.Client, cfg Config, androidID, securityToken uint64) (*fcmpb.AndroidCheckinResponse, error) {
	platform := fcmpb.ChromeBuildProto_PLATFORM_LINUX
	chromeVerStr := cfg.ChromeVersion
	if chromeVerStr == "" {
		chromeVerStr = chromeVer
	}
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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.CheckinURL, bytes.NewReader(body))
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

func gcmRegister(ctx context.Context, hc *http.Client, cfg Config, androidID, securityToken uint64) (*GCMCredentials, error) {
	gcmAppID := fmt.Sprintf("wp:%s#%x%x", cfg.BundleID, time.Now().UnixNano(), androidID)

	data := url.Values{}
	data.Set("app", "org.chromium.linux")
	data.Set("X-subtype", gcmAppID)
	data.Set("device", strconv.FormatUint(androidID, 10))
	data.Set("sender", GCM_SERVER_KEY_B64)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RegisterURL, strings.NewReader(data.Encode()))
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
func gcmRegisterWithRetry(ctx context.Context, hc *http.Client, cfg Config, androidID, securityToken uint64) (*GCMCredentials, error) {
	var lastErr error
	for i := 0; i < 30; i++ {
		creds, err := gcmRegister(ctx, hc, cfg, androidID, securityToken)
		if err == nil {
			return creds, nil
		}
		lastErr = err
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("gcm register failed after 30 attempts: %w", lastErr)
}

func fcmInstall(ctx context.Context, hc *http.Client, cfg Config) (*Installation, error) {
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
		"appId":       cfg.AppID,
		"authVersion": authVersion,
		"fid":         fid64,
		"sdkVersion":  sdkVersion,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal install payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.InstallURL+"projects/"+cfg.ProjectID+"/installations",
		bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("fcm install request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-firebase-client", hbHeader)
	httpReq.Header.Set("x-goog-api-key", cfg.APIKey)
	if err := addAndroidHeaders(httpReq, cfg); err != nil {
		return nil, err
	}

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

	var result struct {
		AuthToken struct {
			Token     string `json:"token"`
			ExpiresIn string `json:"expiresIn"`
		} `json:"authToken"`
		RefreshToken string `json:"refreshToken"`
		FID          string `json:"fid"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fcm install unmarshal: %w", err)
	}
	if result.AuthToken.Token == "" {
		return nil, fmt.Errorf("fcm install: response missing auth token")
	}
	expiresIn, err := parseExpiresIn(result.AuthToken.ExpiresIn)
	if err != nil {
		return nil, err
	}
	fidOut := result.FID
	if fidOut == "" {
		fidOut = fid64
	}
	return &Installation{
		Token:        result.AuthToken.Token,
		ExpiresIn:    expiresIn,
		RefreshToken: result.RefreshToken,
		FID:          fidOut,
		CreatedAt:    time.Now().Unix(),
	}, nil
}

// fcmRegister requests a registration token and returns the raw FIS/FCM
// response so it can be stored verbatim (the reference implementation keeps
// the response as registration.token).
func fcmRegister(ctx context.Context, hc *http.Client, cfg Config, gcm *GCMCredentials, install *Installation, keys *KeysCredentials) (json.RawMessage, error) {
	type webRegistration struct {
		// ApplicationPubKey is nil (JSON null) when the default VAPID key is
		// used; sending the default key back is rejected by FCM.
		ApplicationPubKey any    `json:"applicationPubKey"`
		Auth              string `json:"auth"`
		Endpoint          string `json:"endpoint"`
		P256dh            string `json:"p256dh"`
	}

	var pubKey any
	if cfg.VAPIDKey != "" && cfg.VAPIDKey != GCM_SERVER_KEY_B64 {
		pubKey = cfg.VAPIDKey
	}

	payload := map[string]interface{}{
		"web": webRegistration{
			ApplicationPubKey: pubKey,
			Auth:              keys.Secret,
			Endpoint:          "https://fcm.googleapis.com/fcm/send/" + gcm.Token,
			P256dh:            keys.Public,
		},
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal registration payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.FCMRegURL+"projects/"+cfg.ProjectID+"/registrations",
		bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("fcm register request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-key", cfg.APIKey)
	httpReq.Header.Set("x-goog-firebase-installations-auth", install.Token)
	if err := addAndroidHeaders(httpReq, cfg); err != nil {
		return nil, err
	}

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

	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("fcm register unmarshal: %w", err)
	}
	if result.Token == "" {
		return nil, fmt.Errorf("fcm register: response missing registration token")
	}
	return json.RawMessage(body), nil
}

// Checkin performs GCM check-in only with DefaultConfig and returns the
// android ID and security token. This is a lightweight alternative to full
// Register() when only the android ID is needed for OAuth token exchange.
func Checkin(ctx context.Context, hc *http.Client) (androidID, securityToken uint64, err error) {
	hc = httpclient.OrDefault(hc)
	resp, err := gcmCheckin(ctx, hc, DefaultConfig(), 0, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("gcm checkin: %w", err)
	}
	return resp.GetAndroidId(), resp.GetSecurityToken(), nil
}
