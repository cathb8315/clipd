package client_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/colefailla/clipd/internal/client"
	"github.com/colefailla/clipd/internal/clipboard"
	"github.com/colefailla/clipd/internal/server"
	"github.com/colefailla/clipd/internal/transport"
)

// TestNothingReadableCrossesTheWire is the test this whole version exists for.
//
// In v1 a packet capture showed the token and the clipboard contents in plain
// ASCII, one after the other. This asserts that neither appears anywhere in
// the bytes the client actually transmits. If someone ever reintroduces a
// plaintext path — a fallback flag, a "just for debugging" branch — this fails
// rather than quietly undoing the point of the exercise.
func TestNothingReadableCrossesTheWire(t *testing.T) {
	t.Parallel()

	const (
		secretToken = "SUPER-SECRET-TOKEN-DO-NOT-LEAK-abcdefgh"
		secretData  = "CONFIDENTIAL-CLIPBOARD-CONTENTS-xyzzy"
	)

	tlsConfig, pin, err := transport.Ephemeral()
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	clip := &clipboard.Fake{}
	srv, err := server.New(server.Options{
		Token:      secretToken,
		TLS:        tlsConfig,
		Clipboard:  clip,
		MaxPayload: 1 << 20,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	backend, err := server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ctx, backend)
	}()

	// A tap sitting between client and daemon, recording everything the
	// client sends — the position an attacker on the LAN occupies.
	tap := newTap(t, backend.Addr().String())

	res, err := client.Copy(context.Background(), client.Options{
		Address: tap.addr,
		Token:   secretToken,
		TLS:     clientTLS(t, pin),
		Timeout: 10 * time.Second,
	}, []byte(secretData))
	if err != nil {
		t.Fatalf("Copy through the tap: %v", err)
	}
	if res.Bytes != len(secretData) {
		t.Errorf("Bytes = %d, want %d", res.Bytes, len(secretData))
	}
	// The copy really did work end to end; this is not a test that passes
	// because nothing happened.
	if got := string(clip.Data()); got != secretData {
		t.Fatalf("clipboard = %q, want %q", got, secretData)
	}

	captured := tap.captured()
	if len(captured) == 0 {
		t.Fatal("the tap recorded nothing; it is not observing the connection")
	}

	if bytes.Contains(captured, []byte(secretToken)) {
		t.Error("the authentication token appears in cleartext on the wire")
	}
	if bytes.Contains(captured, []byte(secretData)) {
		t.Error("the clipboard contents appear in cleartext on the wire")
	}
	// The v1 frame header would be the first four bytes of the stream.
	if bytes.HasPrefix(captured, []byte("CLPD")) {
		t.Error("the connection opens with an unencrypted clipd frame")
	}
	// A TLS record layer starts with a handshake record: 0x16, then the
	// legacy version 0x03 0x01.
	if len(captured) < 3 || captured[0] != 0x16 || captured[1] != 0x03 {
		t.Errorf("stream does not begin with a TLS handshake record: % x", captured[:min(8, len(captured))])
	}

	cancel()
	<-served
}

// tap proxies TCP to a backend while recording the client-to-server direction.
type tap struct {
	addr string

	mu   sync.Mutex
	seen bytes.Buffer
}

func newTap(t *testing.T, backend string) *tap {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tap listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	tp := &tap{addr: ln.Addr().String()}

	go func() {
		for {
			downstream, err := ln.Accept()
			if err != nil {
				return
			}
			upstream, err := net.DialTimeout("tcp", backend, 5*time.Second)
			if err != nil {
				downstream.Close()
				return
			}
			// Client to server, through the recorder.
			go func() {
				defer upstream.Close()
				_, _ = io.Copy(io.MultiWriter(upstream, tp), downstream)
			}()
			// Server back to client, unrecorded: the assertions are about
			// what leaves this machine.
			go func() {
				defer downstream.Close()
				_, _ = io.Copy(downstream, upstream)
			}()
		}
	}()
	return tp
}

func (tp *tap) Write(p []byte) (int, error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.seen.Write(p)
}

func (tp *tap) captured() []byte {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return append([]byte(nil), tp.seen.Bytes()...)
}
