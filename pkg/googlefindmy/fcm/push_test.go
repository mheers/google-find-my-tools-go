package fcm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"

	fcmpb "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/proto/fcm"
)

// testPushCredentials generates a P-256 key pair and auth secret the same way
// GenerateKeys does, returning credentials plus the ECDH private key so tests
// can play the role of the FCM server.
func testPushCredentials(t testing.TB) (*FCMCredentials, *ecdh.PrivateKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	secret := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	ecdhPriv, err := priv.ECDH()
	if err != nil {
		t.Fatalf("ecdh conversion: %v", err)
	}

	creds := &FCMCredentials{
		Keys: &KeysCredentials{
			Public:  base64.URLEncoding.EncodeToString(pubDER[26:]),
			Private: base64.URLEncoding.EncodeToString(privDER),
			Secret:  base64.URLEncoding.EncodeToString(secret),
		},
		GCM: &GCMCredentials{
			Token:         "gcm-token",
			AppID:         "wp:test#1",
			AndroidID:     42,
			SecurityToken: 7,
		},
	}
	return creds, ecdhPriv
}

type testPush struct {
	msg *fcmpb.DataMessageStanza
	// secrets are all key material derived for this message; tests assert that
	// none of them show up in logs.
	secrets [][]byte
}

func expandHKDF(t testing.TB, prk, info []byte, length int) []byte {
	t.Helper()
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, info), out); err != nil {
		t.Fatalf("hkdf expand: %v", err)
	}
	return out
}

// encryptTestPush builds an FCM Web Push (ECE aesgcm) message the way the
// server would, mirroring encryptWebPushECE's derivation.
func encryptTestPush(t testing.TB, creds *FCMCredentials, clientPriv *ecdh.PrivateKey, plaintext []byte) testPush {
	t.Helper()

	serverPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	sharedSecret, err := serverPriv.ECDH(clientPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		t.Fatalf("salt: %v", err)
	}
	authSecret, err := base64.URLEncoding.DecodeString(creds.Keys.Secret)
	if err != nil {
		t.Fatalf("decode auth secret: %v", err)
	}

	prk1 := hkdf.Extract(sha256.New, sharedSecret, authSecret)
	derived := expandHKDF(t, prk1, []byte("Content-Encoding: auth\x00"), 32)
	prk2 := hkdf.Extract(sha256.New, derived, salt)

	clientPub := clientPriv.PublicKey().Bytes()
	serverPub := serverPriv.PublicKey().Bytes()
	context := make([]byte, 0, len("P-256\x00")+4+len(clientPub)+len(serverPub))
	context = append(context, []byte("P-256\x00")...)
	context = binary.BigEndian.AppendUint16(context, uint16(len(clientPub)))
	context = append(context, clientPub...)
	context = binary.BigEndian.AppendUint16(context, uint16(len(serverPub)))
	context = append(context, serverPub...)

	key := expandHKDF(t, prk2, append([]byte("Content-Encoding: aesgcm\x00"), context...), 16)
	nonce := expandHKDF(t, prk2, append([]byte("Content-Encoding: nonce\x00"), context...), 12)

	padded := make([]byte, 2, 2+len(plaintext))
	padded = append(padded, plaintext...)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	raw := gcm.Seal(nil, nonce, padded, nil)

	msg := &fcmpb.DataMessageStanza{
		From:         proto.String("test-sender"),
		Category:     proto.String("com.google.android.apps.adm"),
		PersistentId: proto.String("persistent-1"),
		AppData: []*fcmpb.AppData{
			{Key: proto.String("crypto-key"), Value: proto.String("dh=" + base64.URLEncoding.EncodeToString(serverPub))},
			{Key: proto.String("encryption"), Value: proto.String("salt=" + base64.URLEncoding.EncodeToString(salt))},
		},
		RawData: raw,
	}
	return testPush{
		msg:     msg,
		secrets: [][]byte{sharedSecret, authSecret, prk1, derived, prk2, key, nonce},
	}
}

// captureLogs redirects the standard logger into buf for the duration of a
// test and returns a restore function.
func captureLogs(buf *bytes.Buffer) func() {
	old := log.Writer()
	log.SetOutput(buf)
	return func() { log.SetOutput(old) }
}

func TestDecryptWebPushECE(t *testing.T) {
	creds, clientPriv := testPushCredentials(t)
	want := []byte(`{"location":"48.1,11.5"}`)
	push := encryptTestPush(t, creds, clientPriv, want)

	pc, err := newPushCrypto(creds)
	if err != nil {
		t.Fatalf("newPushCrypto: %v", err)
	}
	got, err := pc.decrypt(push.msg)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decrypted = %q, want %q", got, want)
	}
}

// TestDecryptWebPushECEAcceptsUnpaddedBase64 guards interoperability with FCM,
// which sends base64url values without padding while Python emits padding.
func TestDecryptWebPushECEAcceptsUnpaddedBase64(t *testing.T) {
	creds, clientPriv := testPushCredentials(t)
	want := []byte("unpadded-payload")
	push := encryptTestPush(t, creds, clientPriv, want)

	for _, a := range push.msg.GetAppData() {
		a.Value = proto.String(strings.TrimRight(a.GetValue(), "="))
	}
	creds.Keys.Private = strings.TrimRight(creds.Keys.Private, "=")
	creds.Keys.Secret = strings.TrimRight(creds.Keys.Secret, "=")

	pc, err := newPushCrypto(creds)
	if err != nil {
		t.Fatalf("newPushCrypto: %v", err)
	}
	got, err := pc.decrypt(push.msg)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decrypted = %q, want %q", got, want)
	}
}

func TestDecryptWebPushECEDoesNotLogSecrets(t *testing.T) {
	creds, clientPriv := testPushCredentials(t)
	payload := []byte(`{"location":"48.1,11.5"}`)
	push := encryptTestPush(t, creds, clientPriv, payload)

	var buf bytes.Buffer
	restore := captureLogs(&buf)
	defer restore()

	pc, err := newPushCrypto(creds)
	if err != nil {
		t.Fatalf("newPushCrypto: %v", err)
	}
	if _, err := pc.decrypt(push.msg); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	out := buf.String()
	for i, secret := range push.secrets {
		if len(secret) == 0 {
			continue
		}
		for _, encoded := range []string{
			hex.EncodeToString(secret),
			base64.StdEncoding.EncodeToString(secret),
			base64.RawStdEncoding.EncodeToString(secret),
		} {
			if strings.Contains(out, encoded) {
				t.Errorf("log output leaks secret #%d (encoded form found in %q)", i, out)
			}
		}
	}
	if strings.Contains(out, string(payload)) {
		t.Errorf("log output leaks the decrypted payload: %q", out)
	}
}

func TestHandleDataMessageDoesNotLogAppData(t *testing.T) {
	creds, clientPriv := testPushCredentials(t)
	want := []byte(`{"location":"48.1,11.5"}`)
	push := encryptTestPush(t, creds, clientPriv, want)

	var buf bytes.Buffer
	restore := captureLogs(&buf)
	defer restore()

	var got []byte
	client := NewMCSClient(creds, func(payload []byte, persistentID string) {
		got = payload
	})
	gotID := client.handleDataMessage(push.msg)

	if !bytes.Equal(got, want) {
		t.Fatalf("handler payload = %q, want %q", got, want)
	}
	if gotID != "persistent-1" {
		t.Fatalf("handler persistent id = %q, want persistent-1", gotID)
	}
	if strings.Contains(buf.String(), "dh=") {
		t.Errorf("log output contains app_data values: %q", buf.String())
	}
}

func TestDecodeVarint32RoundTrip(t *testing.T) {
	values := []uint32{0, 1, 127, 128, 16383, 16384, 1 << 21, ^uint32(0)}
	for _, want := range values {
		got, err := decodeVarint32(bytes.NewReader(encodeVarint32(want)))
		if err != nil {
			t.Fatalf("decodeVarint32(%d): %v", want, err)
		}
		if got != want {
			t.Fatalf("decodeVarint32 round trip = %d, want %d", got, want)
		}
	}
}

func TestDecodeVarint32RejectsOverflow(t *testing.T) {
	// Six continuation bytes; a uint32 varint never needs more than five.
	overflow := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	if _, err := decodeVarint32(bytes.NewReader(overflow)); err == nil {
		t.Fatal("expected an error for an overflowing varint")
	}
}

func TestReadMsgRejectsOversizedPayload(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := &MCSClient{conn: client, firstMessage: false}
	go func() {
		frame := append([]byte{8}, encodeVarint32(maxMCSMessageSize+1)...)
		_, _ = server.Write(frame)
	}()

	if _, err := c.readMsg(); err == nil {
		t.Fatal("expected an error for a payload larger than the limit")
	}
}

func TestReadMsgRejectsUnsupportedVersion(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := &MCSClient{conn: client, firstMessage: true}
	go func() {
		_, _ = server.Write([]byte{40, 0})
	}()

	if _, err := c.readMsg(); err == nil {
		t.Fatal("expected an error for an unsupported protocol version")
	}
}

func TestSendSelectiveAck(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := &MCSClient{conn: client, ctx: context.Background(), firstMessage: false}

	sendErr := make(chan error, 1)
	go func() { sendErr <- sendSelectiveAck(c, "persistent-1") }()

	var tag [1]byte
	if _, err := io.ReadFull(server, tag[:]); err != nil {
		t.Fatalf("read tag: %v", err)
	}
	if tag[0] != byte(tagByName["mcs_proto.IqStanza"]) {
		t.Fatalf("tag = %d, want %d", tag[0], tagByName["mcs_proto.IqStanza"])
	}
	size, err := decodeVarint32(server)
	if err != nil {
		t.Fatalf("read size: %v", err)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("sendSelectiveAck: %v", err)
	}

	iq := &fcmpb.IqStanza{}
	if err := proto.Unmarshal(payload, iq); err != nil {
		t.Fatalf("unmarshal iq: %v", err)
	}
	if iq.GetExtension().GetId() != int32(mcsSelectiveAckID) {
		t.Fatalf("extension id = %d, want %d", iq.GetExtension().GetId(), mcsSelectiveAckID)
	}
	ack := &fcmpb.SelectiveAck{}
	if err := proto.Unmarshal(iq.GetExtension().GetData(), ack); err != nil {
		t.Fatalf("unmarshal selective ack: %v", err)
	}
	if len(ack.GetId()) != 1 || ack.GetId()[0] != "persistent-1" {
		t.Fatalf("selective ack ids = %v, want [persistent-1]", ack.GetId())
	}
}

func TestListenWithoutConnect(t *testing.T) {
	c := NewMCSClient(&FCMCredentials{GCM: &GCMCredentials{}}, nil)
	if err := c.Listen(); err == nil {
		t.Fatal("expected an error when Listen is called before Connect")
	}
}

// TestListenAcksDataMessages feeds a real (encrypted) data message into the
// receive loop and asserts that a selective ACK for its persistent ID is sent
// back and the handler receives the plaintext.
func TestListenAcksDataMessages(t *testing.T) {
	creds, clientPriv := testPushCredentials(t)
	want := []byte(`{"location":"48.1,11.5"}`)
	push := encryptTestPush(t, creds, clientPriv, want)

	client, server := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() { _ = server.Close() }()

	c := NewMCSClient(creds, func(payload []byte, persistentID string) {
		if !bytes.Equal(payload, want) {
			t.Errorf("handler payload = %q, want %q", payload, want)
		}
		if persistentID != "persistent-1" {
			t.Errorf("handler persistent id = %q, want persistent-1", persistentID)
		}
	})
	c.mu.Lock()
	c.ctx = ctx
	c.conn = client
	c.firstMessage = false
	c.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- c.Listen() }()

	payload, err := proto.Marshal(push.msg)
	if err != nil {
		t.Fatalf("marshal data message: %v", err)
	}
	frame := append([]byte{byte(tagByName["mcs_proto.DataMessageStanza"])}, encodeVarint32(uint32(len(payload)))...)
	frame = append(frame, payload...)
	if _, err := server.Write(frame); err != nil {
		t.Fatalf("write data message: %v", err)
	}

	// The receive loop must answer with an IqStanza (tag 7) carrying a
	// selective ACK for persistent-1.
	var tag [1]byte
	if _, err := io.ReadFull(server, tag[:]); err != nil {
		t.Fatalf("read ack tag: %v", err)
	}
	if tag[0] != byte(tagByName["mcs_proto.IqStanza"]) {
		t.Fatalf("ack tag = %d, want %d", tag[0], tagByName["mcs_proto.IqStanza"])
	}
	size, err := decodeVarint32(server)
	if err != nil {
		t.Fatalf("read ack size: %v", err)
	}
	ackPayload := make([]byte, size)
	if _, err := io.ReadFull(server, ackPayload); err != nil {
		t.Fatalf("read ack payload: %v", err)
	}
	iq := &fcmpb.IqStanza{}
	if err := proto.Unmarshal(ackPayload, iq); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	ack := &fcmpb.SelectiveAck{}
	if err := proto.Unmarshal(iq.GetExtension().GetData(), ack); err != nil {
		t.Fatalf("unmarshal selective ack: %v", err)
	}
	if len(ack.GetId()) != 1 || ack.GetId()[0] != "persistent-1" {
		t.Fatalf("selective ack ids = %v, want [persistent-1]", ack.GetId())
	}
	if ids := c.persistentIDs(); len(ids) != 1 || ids[0] != "persistent-1" {
		t.Fatalf("tracked persistent ids = %v, want [persistent-1]", ids)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not return after cancellation")
	}
}

func TestListenCloseConcurrent(t *testing.T) {
	creds, _ := testPushCredentials(t)
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	c := NewMCSClient(creds, nil)
	c.mu.Lock()
	c.ctx = context.Background()
	c.conn = client
	c.firstMessage = false
	c.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- c.Listen() }()

	// Let Listen block on the first read, then close from this goroutine.
	time.Sleep(20 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not return after Close")
	}
}

func BenchmarkPushDecrypt(b *testing.B) {
	creds, clientPriv := testPushCredentials(b)
	push := encryptTestPush(b, creds, clientPriv, []byte(`{"location":"48.1,11.5"}`))
	pc, err := newPushCrypto(creds)
	if err != nil {
		b.Fatalf("newPushCrypto: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pc.decrypt(push.msg); err != nil {
			b.Fatalf("decrypt: %v", err)
		}
	}
}
