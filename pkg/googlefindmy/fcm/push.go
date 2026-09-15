package fcm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	fcmpb "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/fcm"
)

// MCS constants.
const (
	mcsHost           = "mtalk.google.com"
	mcsPort           = "5228"
	mcsVersion        = 41
	mcsSelectiveAckID = 12
)

// tags maps known FCM proto message types to their MCS wire tag value.
// Note: the keys use the actual package name "fcm" (not the import alias
// "fcmpb") because fmt.Sprintf("%T", msg) resolves to the package
// declaration name, not the import alias.
var tags = map[string]int{
	"*fcm.HeartbeatPing":     0,
	"*fcm.HeartbeatAck":      1,
	"*fcm.LoginRequest":      2,
	"*fcm.LoginResponse":     3,
	"*fcm.Close":             4,
	"*fcm.IqStanza":          7,
	"*fcm.DataMessageStanza": 8,
	"*fcm.StreamErrorStanza": 10,
}

var tagNames = map[int]func() proto.Message{
	0:  func() proto.Message { return &fcmpb.HeartbeatPing{} },
	1:  func() proto.Message { return &fcmpb.HeartbeatAck{} },
	2:  func() proto.Message { return &fcmpb.LoginRequest{} },
	3:  func() proto.Message { return &fcmpb.LoginResponse{} },
	4:  func() proto.Message { return &fcmpb.Close{} },
	7:  func() proto.Message { return &fcmpb.IqStanza{} },
	8:  func() proto.Message { return &fcmpb.DataMessageStanza{} },
	10: func() proto.Message { return &fcmpb.StreamErrorStanza{} },
}

// PushHandler receives decrypted data messages from the MCS connection.
// payload is the raw decrypted bytes — it may be JSON or protobuf depending
// on the message type. persistentID is used for selective ACK.
type PushHandler func(payload []byte, persistentID string)

// MCSClient manages a persistent MCS connection to receive FCM pushes.
type MCSClient struct {
	creds   *FCMCredentials
	handler PushHandler

	mu           sync.Mutex
	conn         net.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	firstMessage bool
}

// NewMCSClient creates a new MCS client.
func NewMCSClient(creds *FCMCredentials, handler PushHandler) *MCSClient {
	return &MCSClient{creds: creds, handler: handler}
}

// tlsConn returns a TLS connection wrapper.
func tlsConn(raw net.Conn) net.Conn {
	return tls.Client(raw, &tls.Config{InsecureSkipVerify: false, ServerName: "mtalk.google.com"})
}

// Connect dials mtalk.google.com:5228, performs TLS, logs in, and returns.
func (c *MCSClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.firstMessage = true
	c.mu.Unlock()

	d := net.Dialer{Timeout: 15 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(mcsHost, mcsPort))
	if err != nil {
		return fmt.Errorf("mcs dial: %w", err)
	}
	conn := tlsConn(rawConn)
	if err := conn.(*tls.Conn).HandshakeContext(ctx); err != nil {
		conn.Close()
		return fmt.Errorf("mcs tls: %w", err)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	// Set a read deadline so the login response doesn't hang forever.
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		conn.Close()
		return fmt.Errorf("mcs set read deadline: %w", err)
	}

	androidID := int64(uint64(c.creds.GCM.AndroidID))
	authService := fcmpb.LoginRequest_ANDROID_ID
	useRmq2 := true
	netType := int32(1)
	hbIntervalMs := int32(10_000)

	req := &fcmpb.LoginRequest{
		AdaptiveHeartbeat: proto.Bool(false),
		AuthService:       &authService,
		AuthToken:         proto.String(fmt.Sprintf("%d", uint64(c.creds.GCM.SecurityToken))),
		Id:                proto.String(chromeVer),
		Domain:            proto.String("mcs.android.com"),
		DeviceId:          proto.String(fmt.Sprintf("android-%x", uint64(androidID))),
		NetworkType:       &netType,
		Resource:          proto.String(fmt.Sprintf("%d", androidID)),
		User:              proto.String(fmt.Sprintf("%d", androidID)),
		UseRmq2:           &useRmq2,
		HeartbeatStat: &fcmpb.HeartbeatStat{
			Ip:         proto.String(""),
			Timeout:    proto.Bool(true),
			IntervalMs: &hbIntervalMs,
		},
	}

	if err := c.sendMsg(req); err != nil {
		c.conn.Close()
		return fmt.Errorf("mcs send login: %w", err)
	}

	resp, err := c.readMsg()
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("mcs read login response: %w", err)
	}
	loginResp, ok := resp.(*fcmpb.LoginResponse)
	if !ok {
		c.conn.Close()
		return fmt.Errorf("mcs: expected LoginResponse, got %T", resp)
	}
	log.Printf("[MCS] logged in (android-id=%x, server-timestamp=%d, stream-id=%d, settings=%d)",
		uint64(androidID), loginResp.GetServerTimestamp(),
		loginResp.GetStreamId(), len(loginResp.GetSetting()))
	return nil
}

// Listen runs the receive loop. Blocks until connection closes or error.
func (c *MCSClient) Listen() error {
	defer c.Close()

	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}

		if err := c.conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			return fmt.Errorf("mcs set deadline: %w", err)
		}
		msg, err := c.readMsg()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				c.sendMsg(&fcmpb.HeartbeatPing{})
				continue
			}
			return fmt.Errorf("mcs read: %w", err)
		}

		switch m := msg.(type) {
		case *fcmpb.HeartbeatPing:
			log.Printf("[MCS] heartbeat ping")
			c.sendMsg(&fcmpb.HeartbeatAck{})
		case *fcmpb.HeartbeatAck:
			log.Printf("[MCS] heartbeat ack")
		case *fcmpb.IqStanza:
			log.Printf("[MCS] iq stanza")
		case *fcmpb.DataMessageStanza:
			log.Printf("[MCS] data message stanza")
			handleDataMessage(c.creds, m, c.handler)
		case *fcmpb.Close:
			return fmt.Errorf("mcs closed by server")
		case *fcmpb.StreamErrorStanza:
			return fmt.Errorf("mcs stream error")
		default:
			log.Printf("[MCS] unhandled message type: %T", msg)
		}
	}
}

// Close closes the MCS connection.
func (c *MCSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// sendMsg marshals, frames, and writes a protobuf message to the MCS
// connection. The version byte is only included before the first receive.
func (c *MCSClient) sendMsg(msg proto.Message) error {
	tn := fmt.Sprintf("%T", msg)
	tag, ok := tags[tn]
	if !ok {
		return fmt.Errorf("mcs: unknown tag for %T", msg)
	}

	payload, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("mcs marshal %T: %w", msg, err)
	}

	c.mu.Lock()
	var frame []byte
	if c.firstMessage {
		frame = make([]byte, 0, 2+5+len(payload))
		frame = append(frame, byte(mcsVersion), byte(tag))
	} else {
		frame = make([]byte, 0, 1+5+len(payload))
		frame = append(frame, byte(tag))
	}
	frame = append(frame, encodeVarint32(uint32(len(payload)))...)
	frame = append(frame, payload...)
	_, err = c.conn.Write(frame)
	c.mu.Unlock()
	return err
}

// readMsg reads one MCS-framed message from the connection.
// The version byte is only present on the first message received.
func (c *MCSClient) readMsg() (proto.Message, error) {
	var tag int
	c.mu.Lock()
	isFirst := c.firstMessage
	if isFirst {
		c.firstMessage = false
	}
	c.mu.Unlock()

	if isFirst {
		var hdr [2]byte
		if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
			return nil, fmt.Errorf("mcs read header: %w", err)
		}
		tag = int(hdr[1])
	} else {
		var b [1]byte
		if _, err := io.ReadFull(c.conn, b[:]); err != nil {
			return nil, fmt.Errorf("mcs read tag: %w", err)
		}
		tag = int(b[0])
	}

	size, err := decodeVarint32(c.conn)
	if err != nil {
		return nil, fmt.Errorf("mcs read size: %w", err)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, fmt.Errorf("mcs read payload: %w", err)
	}

	newFn, ok := tagNames[tag]
	if !ok {
		return nil, fmt.Errorf("mcs: unknown tag %d", tag)
	}
	msg := newFn()
	if err := proto.Unmarshal(payload, msg); err != nil {
		return nil, fmt.Errorf("mcs unmarshal tag %d: %w", tag, err)
	}
	return msg, nil
}

// --- Selective ACK ---

func sendSelectiveAck(c *MCSClient) {
	extID := int32(mcsSelectiveAckID)
	iqType := fcmpb.IqStanza_SET
	msg := &fcmpb.IqStanza{
		Type: &iqType,
		Id:   proto.String(""),
		Extension: &fcmpb.Extension{
			Id: &extID,
		},
	}
	c.sendMsg(msg)
}

// --- Varint ---

func encodeVarint32(x uint32) []byte {
	var buf bytes.Buffer
	for x >= 0x80 {
		buf.WriteByte(byte(x) | 0x80)
		x >>= 7
	}
	buf.WriteByte(byte(x))
	return buf.Bytes()
}

func decodeVarint32(r io.Reader) (uint32, error) {
	var result uint32
	var shift uint
	b := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, err
		}
		result |= uint32(b[0]&0x7F) << shift
		if b[0]&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result, nil
}

// --- Web Push ECE Decryption (RFC 8291) ---

func handleDataMessage(creds *FCMCredentials, msg *fcmpb.DataMessageStanza, handler PushHandler) {
	log.Printf("[MCS] handleDataMessage: app_data=%d, raw_data_len=%d",
		len(msg.GetAppData()), len(msg.GetRawData()))

	decrypted, err := decryptWebPushECE(creds, msg)
	if err != nil {
		log.Printf("[MCS] decrypt: %v", err)
		return
	}

	log.Printf("[MCS] decrypted %d bytes", len(decrypted))
	persistentID := msg.GetPersistentId()
	if persistentID != "" && handler != nil {
		handler(decrypted, persistentID)
	}
}

// decryptWebPushECE decrypts an FCM Web Push (ECE, aesgcm) payload.
//
// SECURITY: key material derived here (shared secret, auth secret, HKDF
// intermediates, AES key/nonce) must never be logged. Log only lengths and
// error messages at most.
func decryptWebPushECE(creds *FCMCredentials, msg *fcmpb.DataMessageStanza) ([]byte, error) {
	var dhB64, saltB64, subtype string
	for _, a := range msg.GetAppData() {
		switch a.GetKey() {
		case "crypto-key":
			dhB64 = trimPrefix(a.GetValue(), "dh=")
		case "encryption":
			saltB64 = trimPrefix(a.GetValue(), "salt=")
		case "subtype":
			subtype = a.GetValue()
		}
	}
	if dhB64 == "" || saltB64 == "" {
		return nil, fmt.Errorf("missing crypto-key or encryption")
	}

	// The subtype matches the FCM sender's AppID. If it doesn't match exactly
	// (e.g. Python vs Go bundle IDs), we still attempt decryption — the
	// request UUID filter in the handler will reject unrelated messages.
	_ = subtype

	dhRaw, err := base64.URLEncoding.DecodeString(dhB64)
	if err != nil {
		return nil, fmt.Errorf("decode dh: %w", err)
	}
	salt, err := base64.URLEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}

	privDER, err := base64.URLEncoding.DecodeString(creds.Keys.Private)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	privKey, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	ecdsaPriv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key not ECDSA")
	}

	ecdhPriv, err := ecdsaPriv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("ecdh conversion: %w", err)
	}
	ecdhPub, err := ecdh.P256().NewPublicKey(dhRaw)
	if err != nil {
		return nil, fmt.Errorf("parse server public key: %w", err)
	}

	sharedSecret, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	authSecret, err := base64.URLEncoding.DecodeString(creds.Keys.Secret)
	if err != nil {
		return nil, fmt.Errorf("decode auth secret: %w", err)
	}

	// ECE key derivation using aesgcm (matching Python http_ece version="aesgcm").
	clientPub := ecdhPriv.PublicKey().Bytes()
	context := make([]byte, 0, len("P-256\x00")+2+len(clientPub)+2+len(dhRaw))
	context = append(context, []byte("P-256\x00")...)
	context = binary.BigEndian.AppendUint16(context, uint16(len(clientPub)))
	context = append(context, clientPub...)
	context = binary.BigEndian.AppendUint16(context, uint16(len(dhRaw)))
	context = append(context, dhRaw...)

	prk1 := hkdf.Extract(sha256.New, sharedSecret, authSecret)
	derived := make([]byte, 32)
	authInfo := []byte("Content-Encoding: auth\x00")
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk1, authInfo), derived); err != nil {
		return nil, fmt.Errorf("hkdf expand derived: %w", err)
	}

	prk2 := hkdf.Extract(sha256.New, derived, salt)
	keyInfo := append([]byte("Content-Encoding: aesgcm\x00"), context...)
	nonceInfo := append([]byte("Content-Encoding: nonce\x00"), context...)

	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk2, keyInfo), key); err != nil {
		return nil, fmt.Errorf("hkdf expand key: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk2, nonceInfo), nonce); err != nil {
		return nil, fmt.Errorf("hkdf expand nonce: %w", err)
	}

	rawData := msg.GetRawData()
	if len(rawData) == 0 {
		return nil, fmt.Errorf("no raw_data in message")
	}
	if len(rawData) < 16+2 {
		return nil, fmt.Errorf("raw_data too short: %d", len(rawData))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes gcm: %w", err)
	}

	// aesgcm: raw_data is AES-GCM(nonce, padding_header || plaintext) → tag appended.
	decrypted, err := gcm.Open(nil, nonce, rawData, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}

	// aesgcm padding: 2-byte big-endian padding length, then padding zeros.
	padLen := int(binary.BigEndian.Uint16(decrypted[:2]))
	if 2+padLen > len(decrypted) {
		return nil, fmt.Errorf("padding %d exceeds decrypted length %d", padLen, len(decrypted))
	}
	return decrypted[2+padLen:], nil
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

// Ensure rand is used (for the import — GoFetcher will use it later).
var _ = rand.Reader
