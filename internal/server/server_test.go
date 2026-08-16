package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/colefailla/clipd/internal/clipboard"
	"github.com/colefailla/clipd/internal/protocol"
	"github.com/colefailla/clipd/internal/transport"
)

const testToken = "test-token-of-sufficient-length"

// harness is a server listening on a loopback port, exercised over real TLS
// on real TCP so the tests cover the handshake, framing, deadlines and
// connection handling the daemon actually uses in production.
type harness struct {
	t    *testing.T
	addr string
	clip *clipboard.Fake
	pin  []byte
}

type harnessOption func(*Options)

func withMaxPayload(n int64) harnessOption { return func(o *Options) { o.MaxPayload = n } }
func withTimeout(d time.Duration) harnessOption {
	return func(o *Options) { o.Timeout = d }
}
func withClipboardError(err error) harnessOption {
	return func(o *Options) { o.Clipboard.(*clipboard.Fake).Err = err }
}
func withMaxConcurrent(n int) harnessOption { return func(o *Options) { o.MaxConcurrent = n } }

func newHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()

	tlsConfig, pin, err := transport.Ephemeral()
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}

	clip := &clipboard.Fake{}
	options := Options{
		Token:      testToken,
		TLS:        tlsConfig,
		Clipboard:  clip,
		MaxPayload: 1 << 20,
		Timeout:    2 * time.Second,
	}
	for _, opt := range opts {
		opt(&options)
	}

	srv, err := New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Port 0 lets the kernel pick, so tests never collide on a fixed port.
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v, want nil on shutdown", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return after cancellation")
		}
	})

	return &harness{t: t, addr: ln.Addr().String(), clip: clip, pin: pin}
}

// send performs a full client exchange and returns the server's response.
func (h *harness) send(token string, payload []byte) (protocol.Status, string) {
	h.t.Helper()

	conn := h.dial()
	defer conn.Close()

	if err := protocol.WriteRequest(conn, token, payload); err != nil {
		h.t.Fatalf("WriteRequest: %v", err)
	}
	status, message, err := protocol.ReadResponse(conn)
	if err != nil {
		h.t.Fatalf("ReadResponse: %v", err)
	}
	return status, message
}

// sendRaw writes arbitrary bytes and reads whatever comes back.
func (h *harness) sendRaw(frame []byte) (protocol.Status, string, error) {
	h.t.Helper()

	conn := h.dial()
	defer conn.Close()

	if _, err := conn.Write(frame); err != nil {
		h.t.Fatalf("write: %v", err)
	}
	return readResponse(conn)
}

// dial opens a connection and completes the TLS handshake, so tests operate
// on the same encrypted stream a real client uses.
func (h *harness) dial() net.Conn {
	h.t.Helper()
	return dialTLS(h.t, h.addr, h.pin, 10*time.Second)
}

// dialPlaintext connects without TLS, for testing what a v1 client sees.
func (h *harness) dialPlaintext() net.Conn {
	h.t.Helper()
	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		h.t.Fatalf("set deadline: %v", err)
	}
	return conn
}

func dialTLS(t *testing.T, addr string, pin []byte, deadline time.Duration) net.Conn {
	t.Helper()

	rawConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := rawConn.SetDeadline(time.Now().Add(deadline)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	clientConfig, err := transport.ClientConfig(pin)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	conn := tls.Client(rawConn, clientConfig)
	if err := conn.HandshakeContext(context.Background()); err != nil {
		rawConn.Close()
		t.Fatalf("TLS handshake: %v", err)
	}
	return conn
}

func readResponse(conn net.Conn) (protocol.Status, string, error) {
	status, message, err := protocol.ReadResponse(conn)
	return status, message, err
}

func TestCopySucceeds(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	payload := []byte("total 8\n-rw-r--r--  1 user  staff  0 Jan  1 00:00 file\n")

	status, message := h.send(testToken, payload)
	if !status.OK() {
		t.Fatalf("status = %v (%s), want ok", status, message)
	}
	if got := h.clip.Data(); !bytes.Equal(got, payload) {
		t.Errorf("clipboard = %q, want %q", got, payload)
	}
	if !strings.Contains(message, "copied") {
		t.Errorf("message = %q, want an acknowledgement mentioning the byte count", message)
	}
}

// TestPayloadIsPreservedVerbatim is the promise the README makes: whatever
// bytes go in come out, with no trimming, re-encoding or newline fixups.
func TestPayloadIsPreservedVerbatim(t *testing.T) {
	t.Parallel()

	payloads := map[string][]byte{
		"trailing newline":    []byte("docker ps output\n"),
		"no trailing newline": []byte("no newline here"),
		"multiple newlines":   []byte("a\n\n\nb\n"),
		"leading whitespace":  []byte("   indented\n\tby a tab\n"),
		"crlf":                []byte("windows\r\nline\r\nendings\r\n"),
		"nul bytes":           {'a', 0x00, 'b', 0x00},
		"invalid utf-8":       {0xff, 0xfe, 0x80},
		"ansi escapes":        []byte("\x1b[31mred\x1b[0m\n"),
		"empty":               {},
	}

	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			status, message := h.send(testToken, payload)
			if !status.OK() {
				t.Fatalf("status = %v (%s)", status, message)
			}
			if got := h.clip.Data(); !bytes.Equal(got, payload) {
				t.Errorf("clipboard = %q, want %q", got, payload)
			}
		})
	}
}

func TestBadTokenIsRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
	}{
		{"wrong token", "not-the-right-token-at-all"},
		{"prefix of the real token", testToken[:10]},
		{"real token with a suffix", testToken + "x"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			status, _ := h.send(tc.token, []byte("secret data"))
			if status != protocol.StatusAuthFailed {
				t.Errorf("status = %v, want auth failed", status)
			}
			if h.clip.Writes != 0 {
				t.Error("an unauthenticated request reached the clipboard")
			}
		})
	}
}

func TestPayloadAtLimitIsAccepted(t *testing.T) {
	t.Parallel()

	const limit = 4096
	h := newHarness(t, withMaxPayload(limit))

	payload := bytes.Repeat([]byte("x"), limit)
	status, message := h.send(testToken, payload)
	if !status.OK() {
		t.Fatalf("status = %v (%s), want a payload of exactly the limit to be accepted", status, message)
	}
	if len(h.clip.Data()) != limit {
		t.Errorf("clipboard holds %d bytes, want %d", len(h.clip.Data()), limit)
	}
}

func TestOversizedPayloadIsRejected(t *testing.T) {
	t.Parallel()

	const limit = 4096
	h := newHarness(t, withMaxPayload(limit))

	status, message := h.send(testToken, bytes.Repeat([]byte("x"), limit+1))
	if status != protocol.StatusPayloadTooLarge {
		t.Fatalf("status = %v (%s), want payload too large", status, message)
	}
	if h.clip.Writes != 0 {
		t.Error("an oversized payload reached the clipboard")
	}
	if !strings.Contains(message, "4096") {
		t.Errorf("message = %q, want it to state the limit", message)
	}
}

// TestOversizedPayloadIsRejectedBeforeTheBody is the memory-safety case: the
// declared length is attacker-controlled, so the server must refuse on the
// header alone rather than allocating for a body it will discard. The client
// here declares a terabyte and sends nothing.
func TestOversizedPayloadIsRejectedBeforeTheBody(t *testing.T) {
	t.Parallel()

	h := newHarness(t, withMaxPayload(1024))

	frame := append([]byte{}, protocol.Magic[:]...)
	frame = append(frame, protocol.CurrentVersion, byte(len(testToken)))
	frame = append(frame, testToken...)
	frame = binary.BigEndian.AppendUint64(frame, 1<<40)

	start := time.Now()
	status, _, err := h.sendRaw(frame)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if status != protocol.StatusPayloadTooLarge {
		t.Errorf("status = %v, want payload too large", status)
	}
	// The server answered without waiting for a body that was never coming.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("server took %s to reject; it appears to have waited for the body", elapsed)
	}
	if h.clip.Writes != 0 {
		t.Error("the clipboard was touched")
	}
}

func TestMalformedRequests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		frame []byte
	}{
		{
			name:  "not clipd at all",
			frame: []byte("GET / HTTP/1.1\r\nHost: mac\r\n\r\n"),
		},
		{
			name: "unsupported version",
			frame: func() []byte {
				f := append([]byte{}, protocol.Magic[:]...)
				return append(f, 0x99, 0x04, 't', 'o', 'k', 'n')
			}(),
		},
		{
			name: "zero-length token",
			frame: func() []byte {
				f := append([]byte{}, protocol.Magic[:]...)
				return append(f, protocol.CurrentVersion, 0x00)
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			status, _, err := h.sendRaw(tc.frame)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if status != protocol.StatusMalformed {
				t.Errorf("status = %v, want malformed", status)
			}
			if h.clip.Writes != 0 {
				t.Error("a malformed request reached the clipboard")
			}
		})
	}
}

// TestTruncatedPayloadIsRejected covers a client that declares more than it
// sends and then hangs up.
func TestTruncatedPayloadIsRejected(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	frame := append([]byte{}, protocol.Magic[:]...)
	frame = append(frame, protocol.CurrentVersion, byte(len(testToken)))
	frame = append(frame, testToken...)
	frame = binary.BigEndian.AppendUint64(frame, 100)
	frame = append(frame, []byte("only twelve!")...)

	conn := h.dial()
	defer conn.Close()
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Half-close so the server sees EOF rather than waiting out its deadline.
	// Both *net.TCPConn and *tls.Conn provide this; the interface avoids
	// caring which one the harness handed back.
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	} else {
		t.Fatal("connection does not support a half close")
	}

	status, _, err := readResponse(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if status != protocol.StatusMalformed {
		t.Errorf("status = %v, want malformed", status)
	}
	if h.clip.Writes != 0 {
		t.Error("a truncated payload reached the clipboard")
	}
}

// TestSlowClientIsServed proves the reads are assembled correctly when the
// frame arrives in many small pieces rather than one packet.
func TestSlowClientIsServed(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	payload := []byte("dribbled out one byte at a time\n")

	var frame bytes.Buffer
	if err := protocol.WriteRequest(&frame, testToken, payload); err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}

	conn := h.dial()
	defer conn.Close()

	for _, b := range frame.Bytes() {
		if _, err := conn.Write([]byte{b}); err != nil {
			t.Fatalf("write: %v", err)
		}
		time.Sleep(time.Millisecond)
	}

	status, message, err := readResponse(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !status.OK() {
		t.Fatalf("status = %v (%s)", status, message)
	}
	if got := h.clip.Data(); !bytes.Equal(got, payload) {
		t.Errorf("clipboard = %q, want %q", got, payload)
	}
}

// TestIdleConnectionIsClosed covers the resource-exhaustion case: a client
// that connects and then says nothing must not hold a handler forever.
func TestIdleConnectionIsClosed(t *testing.T) {
	t.Parallel()

	h := newHarness(t, withTimeout(300*time.Millisecond))

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	// Read until the server gives up on us. Without a deadline on the server
	// side this blocks until the test times out.
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Error("the server responded to a client that sent nothing")
	}
}

// TestBareConnectIsHarmless covers what `clipd status` does when probing
// reachability: connect, then hang up without sending anything.
func TestBareConnectIsHarmless(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The daemon must still be serving afterwards.
	status, message := h.send(testToken, []byte("still alive\n"))
	if !status.OK() {
		t.Fatalf("status = %v (%s) after a bare connect", status, message)
	}
}

// TestPlaintextClientGetsAnExplanation covers the most likely upgrade
// failure: a v1 client, which speaks the frame protocol directly, connecting
// to a v2 daemon. Without the magic sniff this is a bare connection close and
// an unexplained hang.
func TestPlaintextClientGetsAnExplanation(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	conn := h.dialPlaintext()
	defer conn.Close()

	// Exactly what clipd v1 puts on the wire.
	if err := protocol.WriteRequest(conn, testToken, []byte("v1 payload")); err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}

	status, message, err := protocol.ReadResponse(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if status != protocol.StatusMalformed {
		t.Errorf("status = %v, want malformed", status)
	}
	if !strings.Contains(strings.ToLower(message), "tls") {
		t.Errorf("message = %q, want it to explain that TLS is required", message)
	}
	if h.clip.Writes != 0 {
		t.Error("an unencrypted request reached the clipboard")
	}
}

// TestWrongPinIsRejected proves the client verifies the server's identity: a
// pin for a different key must abort before any secret is sent.
func TestWrongPinIsRejected(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	// A pin belonging to some other server entirely.
	_, otherPin, err := transport.Ephemeral()
	if err != nil {
		t.Fatalf("generate second certificate: %v", err)
	}

	rawConn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))

	clientConfig, err := transport.ClientConfig(otherPin)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	conn := tls.Client(rawConn, clientConfig)
	err = conn.HandshakeContext(context.Background())
	if err == nil {
		t.Fatal("handshake succeeded against a server with a different key")
	}

	var mismatch *transport.PinMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("error = %v (%T), want a PinMismatchError", err, err)
	}
	if h.clip.Writes != 0 {
		t.Error("the clipboard was touched despite a failed handshake")
	}
}

func TestClipboardFailureIsReported(t *testing.T) {
	t.Parallel()

	h := newHarness(t, withClipboardError(errors.New("pasteboard unavailable")))

	status, message := h.send(testToken, []byte("data"))
	if status != protocol.StatusInternalError {
		t.Errorf("status = %v, want internal error", status)
	}
	// The client is told the operation failed, not the internals of why.
	if strings.Contains(message, "pasteboard unavailable") {
		t.Errorf("message leaked backend detail: %q", message)
	}
}

func TestConcurrentCopies(t *testing.T) {
	t.Parallel()

	h := newHarness(t, withMaxConcurrent(4))

	const clients = 24
	var wg sync.WaitGroup
	errs := make(chan error, clients)

	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn := dialTLS(t, h.addr, h.pin, 20*time.Second)
			defer conn.Close()
			if err := protocol.WriteRequest(conn, testToken, []byte{byte(i)}); err != nil {
				errs <- err
				return
			}
			status, message, err := protocol.ReadResponse(conn)
			if err != nil {
				errs <- err
				return
			}
			if !status.OK() {
				errs <- errors.New(message)
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent copy failed: %v", err)
	}

	if h.clip.Writes != clients {
		t.Errorf("clipboard writes = %d, want %d", h.clip.Writes, clients)
	}
}

func TestShutdownStopsAccepting(t *testing.T) {
	t.Parallel()

	tlsConfig, _, err := transport.Ephemeral()
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}
	srv, err := New(Options{
		Token:      testToken,
		TLS:        tlsConfig,
		Clipboard:  &clipboard.Fake{},
		MaxPayload: 1 << 20,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	// Confirm it is up before shutting it down.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial before shutdown: %v", err)
	}
	conn.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve after cancellation = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}

	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("the listener still accepts connections after shutdown")
	}
}

func TestShutdownMethodIsIdempotent(t *testing.T) {
	t.Parallel()

	tlsConfig, _, err := transport.Ephemeral()
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}
	srv, err := New(Options{
		Token:      testToken,
		TLS:        tlsConfig,
		Clipboard:  &clipboard.Fake{},
		MaxPayload: 1 << 20,
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = srv.Serve(context.Background(), ln) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("first Shutdown: %v", err)
	}
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()

	valid := func() Options {
		return Options{
			Token:      testToken,
			Clipboard:  &clipboard.Fake{},
			MaxPayload: 1 << 20,
			Timeout:    time.Second,
		}
	}

	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"no token", func(o *Options) { o.Token = "" }},
		{"short token", func(o *Options) { o.Token = "short" }},
		{"no clipboard", func(o *Options) { o.Clipboard = nil }},
		{"zero payload limit", func(o *Options) { o.MaxPayload = 0 }},
		{"negative payload limit", func(o *Options) { o.MaxPayload = -1 }},
		{"zero timeout", func(o *Options) { o.Timeout = 0 }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := valid()
			tc.mutate(&opts)
			if _, err := New(opts); err == nil {
				t.Error("New accepted invalid options")
			}
		})
	}
}

// TestPayloadTimeoutScalesWithSize checks the deadline policy directly: a
// large payload on a slow link must not be cut off at the handshake timeout.
func TestPayloadTimeoutScalesWithSize(t *testing.T) {
	t.Parallel()

	tlsConfig, _, err := transport.Ephemeral()
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}
	srv, err := New(Options{
		Token:      testToken,
		TLS:        tlsConfig,
		Clipboard:  &clipboard.Fake{},
		MaxPayload: 100 << 20,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	small := srv.payloadTimeout(1024)
	if small != 5*time.Second {
		t.Errorf("timeout for a small payload = %s, want the base 5s", small)
	}
	large := srv.payloadTimeout(10 << 20)
	if large <= small {
		t.Errorf("timeout for 10 MiB (%s) is not greater than for 1 KiB (%s)", large, small)
	}
}
