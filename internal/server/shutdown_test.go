package server

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/colefailla/clipd/internal/clipboard"
	"github.com/colefailla/clipd/internal/protocol"
	"github.com/colefailla/clipd/internal/transport"
)

// TestShutdownWaitsForInFlightCopies is the property that matters when
// launchd stops the daemon: a copy already being handled must reach the
// clipboard rather than being dropped halfway.
func TestShutdownWaitsForInFlightCopies(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	clip := newBlockingClipboard(release)

	tlsConfig, pin, err := transport.Ephemeral()
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}
	srv, err := New(Options{
		Token:      testToken,
		TLS:        tlsConfig,
		Clipboard:  clip,
		MaxPayload: 1 << 20,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()

	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(context.Background(), ln)
	}()

	conn := dialTLS(t, addr, pin, 20*time.Second)
	defer conn.Close()
	if err := protocol.WriteRequest(conn, testToken, []byte("in flight")); err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}

	// Wait until the handler is parked inside the clipboard write.
	select {
	case <-clip.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler never reached the clipboard")
	}

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- srv.Shutdown(ctx)
	}()

	// Shutdown must still be waiting while the copy is unfinished.
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned (%v) while a copy was still in flight", err)
	case <-time.After(250 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not return after the copy completed")
	}

	status, _, err := protocol.ReadResponse(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !status.OK() {
		t.Errorf("status = %v, want the in-flight copy to have succeeded", status)
	}

	<-served
}

// TestShutdownRaceWithAccept hammers the window between a connection being
// accepted and the listener closing, which is where a handler could register
// itself after the wait had already begun.
func TestShutdownRaceWithAccept(t *testing.T) {
	t.Parallel()

	for range 10 {
		tlsConfig, pin, err := transport.Ephemeral()
		if err != nil {
			t.Fatalf("generate test certificate: %v", err)
		}
		srv, err := New(Options{
			Token:      testToken,
			TLS:        tlsConfig,
			Clipboard:  &clipboard.Fake{},
			MaxPayload: 1 << 20,
			Timeout:    2 * time.Second,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ln, err := Listen("127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		addr := ln.Addr().String()

		served := make(chan struct{})
		go func() {
			defer close(served)
			_ = srv.Serve(context.Background(), ln)
		}()

		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rawConn, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					return // refused once the listener is gone: expected
				}
				defer rawConn.Close()
				// A short deadline: on loopback a served exchange completes in
				// microseconds, and a connection left in the accept backlog
				// when the listener closed will never be answered at all.
				// Either outcome is acceptable here — the assertion under test
				// is that Shutdown itself returns cleanly, so every error on
				// this side is deliberately ignored.
				_ = rawConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
				clientConfig, err := transport.ClientConfig(pin)
				if err != nil {
					return
				}
				conn := tls.Client(rawConn, clientConfig)
				if err := conn.HandshakeContext(context.Background()); err != nil {
					return
				}
				_ = protocol.WriteRequest(conn, testToken, []byte("x"))
				_, _, _ = protocol.ReadResponse(conn)
			}()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		cancel()
		wg.Wait()
		<-served
	}
}

// blockingClipboard parks in Write until it is released, so a test can hold a
// handler open on demand.
type blockingClipboard struct {
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func newBlockingClipboard(release chan struct{}) *blockingClipboard {
	return &blockingClipboard{release: release, entered: make(chan struct{})}
}

func (b *blockingClipboard) Name() string { return "blocking" }

func (b *blockingClipboard) Write(ctx context.Context, _ []byte) error {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
