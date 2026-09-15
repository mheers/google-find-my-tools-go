package fcm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
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

	// mu guards conn, ctx/cancel, firstMessage and receivedPersistentIDs.
	mu           sync.Mutex
	conn         net.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	firstMessage bool

	// receivedPersistentIDs holds message IDs that were already delivered so
	// the server can be told about them on login and stop redelivering.
	receivedPersistentIDs []string
}

// NewMCSClient creates a new MCS client.
func NewMCSClient(creds *FCMCredentials, handler PushHandler) *MCSClient {
	return &MCSClient{creds: creds, handler: handler}
}

// currentConn returns the active connection or an error when the client is not
// connected.
func (c *MCSClient) currentConn() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil, errors.New("mcs: not connected")
	}
	return c.conn, nil
}

// currentCtx returns the client context or nil when not connected.
func (c *MCSClient) currentCtx() context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ctx
}

func (c *MCSClient) rememberPersistentID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.receivedPersistentIDs = append(c.receivedPersistentIDs, id)
}

func (c *MCSClient) persistentIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.receivedPersistentIDs...)
}

// tlsConn returns a TLS connection wrapper.
func tlsConn(raw net.Conn) net.Conn {
	return tls.Client(raw, &tls.Config{InsecureSkipVerify: false, ServerName: "mtalk.google.com"})
}

// Connect dials mtalk.google.com:5228, performs TLS, logs in, and returns.
func (c *MCSClient) Connect(ctx context.Context) error {
	if c.creds == nil || c.creds.GCM == nil {
		return errors.New("mcs: missing FCM GCM credentials")
	}

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
		_ = conn.Close()
		return fmt.Errorf("mcs tls: %w", err)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	// Set a read deadline so the login response doesn't hang forever.
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		_ = c.Close()
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
		// new_vc=1 matches the reference client and is required by newer
		// MCS servers.
		Setting: []*fcmpb.Setting{
			{Name: proto.String("new_vc"), Value: proto.String("1")},
		},
		ReceivedPersistentId: c.persistentIDs(),
		HeartbeatStat: &fcmpb.HeartbeatStat{
			Ip:         proto.String(""),
			Timeout:    proto.Bool(true),
			IntervalMs: &hbIntervalMs,
		},
	}

	if err := c.sendMsg(req); err != nil {
		_ = c.Close()
		return fmt.Errorf("mcs send login: %w", err)
	}

	resp, err := c.readMsg()
	if err != nil {
		_ = c.Close()
		return fmt.Errorf("mcs read login response: %w", err)
	}
	loginResp, ok := resp.(*fcmpb.LoginResponse)
	if !ok {
		_ = c.Close()
		return fmt.Errorf("mcs: expected LoginResponse, got %T", resp)
	}
	log.Printf("[MCS] logged in (android-id=%x, server-timestamp=%d, stream-id=%d, settings=%d)",
		uint64(androidID), loginResp.GetServerTimestamp(),
		loginResp.GetStreamId(), len(loginResp.GetSetting()))
	return nil
}

// Listen runs the receive loop. It blocks until the context is cancelled, the
// connection closes, or an error occurs. The client must be connected first.
func (c *MCSClient) Listen() error {
	defer func() { _ = c.Close() }()

	ctx := c.currentCtx()
	if ctx == nil {
		return errors.New("mcs: Listen called before Connect")
	}
	if _, err := c.currentConn(); err != nil {
		return err
	}

	// A blocking read cannot observe cancellation by itself, so close the
	// connection when the context is done to unblock it.
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-stopWatch:
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := c.currentConn()
		if err != nil {
			return err
		}
		if err := conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			return fmt.Errorf("mcs set deadline: %w", err)
		}
		msg, err := c.readMsg()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if err := c.sendMsg(&fcmpb.HeartbeatPing{}); err != nil {
					return fmt.Errorf("mcs send heartbeat: %w", err)
				}
				continue
			}
			return fmt.Errorf("mcs read: %w", err)
		}

		switch m := msg.(type) {
		case *fcmpb.HeartbeatPing:
			log.Printf("[MCS] heartbeat ping")
			if err := c.sendMsg(&fcmpb.HeartbeatAck{}); err != nil {
				return fmt.Errorf("mcs send heartbeat ack: %w", err)
			}
		case *fcmpb.HeartbeatAck:
			log.Printf("[MCS] heartbeat ack")
		case *fcmpb.IqStanza:
			log.Printf("[MCS] iq stanza")
		case *fcmpb.DataMessageStanza:
			log.Printf("[MCS] data message stanza")
			persistentID := handleDataMessage(c.creds, m, c.handler)
			if persistentID != "" {
				c.rememberPersistentID(persistentID)
				if err := sendSelectiveAck(c, persistentID); err != nil {
					return fmt.Errorf("mcs send selective ack: %w", err)
				}
			}
		case *fcmpb.Close:
			return errors.New("mcs closed by server")
		case *fcmpb.StreamErrorStanza:
			return errors.New("mcs stream error")
		default:
			log.Printf("[MCS] unhandled message type: %T", msg)
		}
	}
}

// Run connects and listens, reconnecting with exponential backoff (capped at
// 30s) until ctx is cancelled. Listen is the single-shot alternative.
func (c *MCSClient) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := c.Connect(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("[MCS] connect failed: %v", err)
		} else if err := c.Listen(); err != nil && ctx.Err() == nil {
			log.Printf("[MCS] connection lost: %v", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// Close closes the MCS connection. It is safe to call multiple times.
func (c *MCSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
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
	defer c.mu.Unlock()
	if c.conn == nil {
		return errors.New("mcs: not connected")
	}
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

	for len(frame) > 0 {
		n, err := c.conn.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		frame = frame[n:]
	}
	return nil
}

// readMsg reads one MCS-framed message from the connection.
// The version byte is only present on the first message received.
func (c *MCSClient) readMsg() (proto.Message, error) {
	conn, err := c.currentConn()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	isFirst := c.firstMessage
	if isFirst {
		c.firstMessage = false
	}
	c.mu.Unlock()

	var tag int
	if isFirst {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, fmt.Errorf("mcs read header: %w", err)
		}
		// The reference client accepts version >= MCS_VERSION (41) as well as
		// the legacy version 38.
		if version := int(hdr[0]); version < mcsVersion && version != 38 {
			return nil, fmt.Errorf("mcs: unsupported protocol version %d", version)
		}
		tag = int(hdr[1])
	} else {
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return nil, fmt.Errorf("mcs read tag: %w", err)
		}
		tag = int(b[0])
	}

	size, err := decodeVarint32(conn)
	if err != nil {
		return nil, fmt.Errorf("mcs read size: %w", err)
	}
	if size > maxMCSMessageSize {
		return nil, fmt.Errorf("mcs: message size %d exceeds limit %d", size, maxMCSMessageSize)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
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

// sendSelectiveAck tells the server that the message with persistentID was
// received so it can be dropped from the redelivery queue.
func sendSelectiveAck(c *MCSClient, persistentID string) error {
	extID := int32(mcsSelectiveAckID)
	iqType := fcmpb.IqStanza_SET
	ack := &fcmpb.SelectiveAck{Id: []string{persistentID}}
	data, err := proto.Marshal(ack)
	if err != nil {
		return fmt.Errorf("mcs marshal selective ack: %w", err)
	}
	msg := &fcmpb.IqStanza{
		Type: &iqType,
		Id:   proto.String(""),
		Extension: &fcmpb.Extension{
			Id:   &extID,
			Data: data,
		},
	}
	return c.sendMsg(msg)
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

// maxMCSMessageSize bounds the payload size accepted from the MCS stream to
// avoid unbounded allocations from a misbehaving or hostile server.
const maxMCSMessageSize = 16 << 20 // 16 MiB

func decodeVarint32(r io.Reader) (uint32, error) {
	var result uint32
	var shift uint
	b := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, err
		}
		if shift >= 32 {
			return 0, errors.New("mcs: varint32 overflow")
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

// handleDataMessage decrypts a data message and invokes the handler. It
// returns the message's persistent ID, which must be acknowledged even when
// decryption or handling fails.
func handleDataMessage(creds *FCMCredentials, msg *fcmpb.DataMessageStanza, handler PushHandler) string {
	log.Printf("[MCS] handleDataMessage: app_data=%d, raw_data_len=%d",
		len(msg.GetAppData()), len(msg.GetRawData()))

	persistentID := msg.GetPersistentId()
	decrypted, err := decryptWebPushECE(creds, msg)
	if err != nil {
		log.Printf("[MCS] decrypt: %v", err)
		return persistentID
	}

	log.Printf("[MCS] decrypted %d bytes", len(decrypted))
	if persistentID != "" && handler != nil {
		handler(decrypted, persistentID)
	}
	return persistentID
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

	// The subtype matches the FCM sender's AppID. Log a mismatch so misconfig
	// is visible, but still attempt decryption: the consumer filters messages
	// by request UUID.
	if subtype != "" && creds.GCM != nil && subtype != creds.GCM.AppID {
		log.Printf("[MCS] data message subtype %q does not match app id %q", subtype, creds.GCM.AppID)
	}

	dhRaw, err := decodeBase64URL(dhB64)
	if err != nil {
		return nil, fmt.Errorf("decode dh: %w", err)
	}
	salt, err := decodeBase64URL(saltB64)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}

	privDER, err := decodeBase64URL(creds.Keys.Private)
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

	authSecret, err := decodeBase64URL(creds.Keys.Secret)
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

// decodeBase64URL decodes padded and unpadded base64url values. FCM sends
// some fields unpadded while the Python reference emits padded values.
func decodeBase64URL(s string) ([]byte, error) {
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
