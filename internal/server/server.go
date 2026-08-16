// Package server implements the clipd daemon: accept a connection,
// authenticate it, read a clipboard payload, hand it to the host clipboard.
//
// The daemon runs in the foreground and never self-daemonizes. On macOS,
// launchd owns backgrounding, log redirection and restart-on-crash, so
// duplicating any of that here would only add ways to disagree with launchd.
package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/colefailla/clipd/internal/auth"
	"github.com/colefailla/clipd/internal/clipboard"
	"github.com/colefailla/clipd/internal/protocol"
)

const (
	// minThroughput is the slowest transfer rate the payload deadline
	// assumes. The handshake gets a flat timeout, but the body cannot: a
	// legitimate 10 MiB paste over a congested link must not be killed at the
	// same deadline that a 40-byte one gets. 256 KiB/s is far below any real
	// LAN and still bounds a byte-trickling client.
	minThroughput = 256 << 10

	// defaultMaxConcurrent bounds in-flight connections. A personal clipboard
	// never needs more, and the cap means an attacker cannot spawn unbounded
	// goroutines by opening sockets.
	defaultMaxConcurrent = 16

	// shutdownGrace is how long Shutdown waits for in-flight copies before
	// giving up on them.
	shutdownGrace = 5 * time.Second
)

// Options configures a Server.
type Options struct {
	// Token is the expected shared secret. Required.
	Token string

	// TLS is the server's TLS configuration. Required: there is no plaintext
	// mode. A flag to disable encryption would be set once during some late
	// night of debugging and never unset, and supporting both would double
	// the connection-handling paths for a two-machine tool.
	TLS *tls.Config

	// Clipboard receives accepted payloads. Required.
	Clipboard clipboard.Clipboard

	// MaxPayload is the largest accepted payload in bytes.
	MaxPayload int64

	// Timeout bounds the handshake and the acknowledgement write.
	Timeout time.Duration

	// MaxConcurrent bounds simultaneously handled connections.
	MaxConcurrent int

	// Logger receives operational logs. Clipboard contents are never logged.
	Logger *slog.Logger
}

// Server accepts clipd connections. The zero value is not usable; use New.
type Server struct {
	token      string
	tlsConfig  *tls.Config
	clip       clipboard.Clipboard
	maxPayload int64
	timeout    time.Duration
	log        *slog.Logger

	// sem bounds concurrent connection handlers.
	sem chan struct{}

	wg sync.WaitGroup

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

// New validates options and constructs a Server.
func New(opts Options) (*Server, error) {
	if err := auth.Validate(opts.Token); err != nil {
		return nil, err
	}
	if opts.TLS == nil {
		return nil, errors.New("server: no TLS configuration")
	}
	if opts.Clipboard == nil {
		return nil, errors.New("server: no clipboard backend")
	}
	if opts.MaxPayload < 1 {
		return nil, fmt.Errorf("server: max payload %d must be positive", opts.MaxPayload)
	}
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("server: timeout %s must be positive", opts.Timeout)
	}
	maxConcurrent := opts.MaxConcurrent
	if maxConcurrent < 1 {
		maxConcurrent = defaultMaxConcurrent
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	return &Server{
		token:      opts.Token,
		tlsConfig:  opts.TLS,
		clip:       opts.Clipboard,
		maxPayload: opts.MaxPayload,
		timeout:    opts.Timeout,
		log:        logger,
		sem:        make(chan struct{}, maxConcurrent),
	}, nil
}

// Listen opens a listener on addr. It is separate from Serve so callers can
// report the resolved address (which matters when the port is 0) and so tests
// can supply their own listener.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	return ln, nil
}

// Serve accepts connections until ctx is cancelled or the listener fails.
//
// It closes ln before returning. A cancelled context is a clean shutdown and
// yields a nil error.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("server: already shut down")
	}
	s.listener = ln
	s.mu.Unlock()

	// Cancellation reaches a blocked Accept only by closing the listener.
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.closeListener()
		case <-stopped:
		}
	}()
	defer close(stopped)

	s.log.Info("clipd daemon ready",
		"address", ln.Addr().String(),
		"clipboard", s.clip.Name(),
		"max_payload_bytes", s.maxPayload)

	for {
		// Acquire capacity before accepting. Blocking here applies back
		// pressure through the kernel's accept queue instead of piling up
		// goroutines for connections we are not ready to service.
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return s.drain(ctx)
		}

		conn, err := ln.Accept()
		if err != nil {
			<-s.sem
			if ctx.Err() != nil || s.isClosed() {
				return s.drain(ctx)
			}
			// A transient accept error (EMFILE, ECONNABORTED) should not kill
			// a daemon the user expects to stay up until launchd stops it.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}

		// A connection accepted in the instant before the listener closed
		// would otherwise register itself after Shutdown began waiting, which
		// is both a WaitGroup misuse and a copy that could be cut off
		// mid-write. Registering under the same lock that sets the closed
		// flag makes the two mutually exclusive.
		if !s.track() {
			conn.Close()
			<-s.sem
			return s.drain(ctx)
		}
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			s.handle(ctx, conn)
		}()
	}
}

// track registers an in-flight handler, or reports false if the server has
// already begun shutting down.
func (s *Server) track() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Add(1)
	return true
}

// Shutdown stops accepting and waits for in-flight connections.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeListener()
	return s.waitForHandlers(ctx)
}

func (s *Server) drain(ctx context.Context) error {
	s.closeListener()
	// ctx is already cancelled at this point, so give handlers their own
	// bounded window to finish the copy they are in the middle of.
	drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	if err := s.waitForHandlers(drainCtx); err != nil {
		s.log.Warn("shutdown timed out with connections still open")
	}
	s.log.Info("clipd daemon stopped")
	return nil
}

// waitForHandlers blocks until every registered handler is done.
//
// Callers must have closed the listener first: that is what stops track from
// admitting new handlers, and so what makes the wait conclusive.
func (s *Server) waitForHandlers(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) closeListener() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// handle services one connection. Every failure path closes the connection;
// none of them panic, and none of them log payload contents.
func (s *Server) handle(ctx context.Context, rawConn net.Conn) {
	defer rawConn.Close()
	remote := rawConn.RemoteAddr().String()

	// The deadline is set before the first read so a client that connects and
	// says nothing cannot hold the slot open indefinitely. It covers the TLS
	// handshake as well, since tls.Conn delegates deadlines downward.
	if err := rawConn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		s.log.Warn("set deadline failed", "remote", remote, "error", err)
		return
	}

	conn, reader, ok := s.startTLS(ctx, rawConn, remote)
	if !ok {
		return
	}

	req, err := protocol.ReadPrologue(reader)
	if err != nil {
		// A bare TCP connect that closes without sending anything is how
		// `clipd status` probes reachability, and how most port scanners
		// behave. It is not worth a warning.
		if errors.Is(err, io.EOF) {
			s.log.Debug("connection closed before request", "remote", remote)
			return
		}
		// A peer that has already blown its deadline gets nothing: writing a
		// response would reset the deadline and hand it another window, which
		// is exactly the hold-a-slot-open behaviour the deadline exists to
		// prevent.
		if isTimeout(err) {
			s.log.Warn("connection timed out before a request arrived", "remote", remote)
			return
		}
		s.log.Warn("malformed request", "remote", remote, "error", err)
		s.respond(conn, protocol.StatusMalformed, err.Error())
		return
	}

	if !auth.Compare(s.token, req.Token) {
		// Deliberately vague to the client, specific in the local log. There
		// is no rate limiting: a 256-bit token makes online guessing
		// pointless, and a lockout would just be a denial-of-service lever.
		s.log.Warn("authentication failed", "remote", remote)
		s.respond(conn, protocol.StatusAuthFailed, "authentication failed")
		return
	}

	payloadLen, err := protocol.ReadPayloadLen(reader)
	if err != nil {
		s.log.Warn("malformed request", "remote", remote, "error", err)
		s.respond(conn, protocol.StatusMalformed, err.Error())
		return
	}

	// The length is client-supplied, so it is checked before a single byte of
	// the body is read or a buffer sized for it — otherwise the limit would
	// be a suggestion rather than a memory bound.
	if payloadLen > uint64(s.maxPayload) {
		s.log.Warn("payload rejected", "remote", remote,
			"declared_bytes", payloadLen, "limit_bytes", s.maxPayload)
		s.respond(conn, protocol.StatusPayloadTooLarge,
			fmt.Sprintf("payload of %d bytes exceeds the server limit of %d bytes", payloadLen, s.maxPayload))
		return
	}

	if err := conn.SetReadDeadline(time.Now().Add(s.payloadTimeout(payloadLen))); err != nil {
		s.log.Warn("set read deadline failed", "remote", remote, "error", err)
		return
	}

	payload, err := protocol.ReadPayload(reader, payloadLen)
	if err != nil {
		s.log.Warn("payload read failed", "remote", remote, "error", err)
		if isTimeout(err) {
			return
		}
		s.respond(conn, protocol.StatusMalformed, err.Error())
		return
	}

	// Bound the clipboard write so a wedged helper cannot pin this handler.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
	defer cancel()
	if err := s.clip.Write(writeCtx, payload); err != nil {
		s.log.Error("clipboard write failed", "remote", remote, "error", err)
		s.respond(conn, protocol.StatusInternalError, "clipboard write failed")
		return
	}

	// Debug, not Info. launchd appends this file forever with no rotation, so
	// a line per copy is unbounded growth that buries the rare failure in
	// routine success. The client already reports a successful copy at the
	// point of use with -v, which is where the answer is actually wanted;
	// `clipd serve -v` turns these back on when diagnosing the daemon.
	s.log.Debug("clipboard updated", "remote", remote, "bytes", len(payload))
	s.respond(conn, protocol.StatusOK, fmt.Sprintf("copied %d bytes", len(payload)))
}

// startTLS completes the handshake, returning the encrypted connection and a
// reader over it. It reports false when the connection has been dealt with and
// the caller should stop.
//
// Before handing anything to crypto/tls it sniffs the first four bytes. A v1
// client speaks the frame protocol directly, and letting that hit the TLS
// handshake produces "first record does not look like a TLS handshake" on this
// side and a bare connection close on the other — leaving the user to guess.
// Recognising the magic costs one Peek and turns the most likely upgrade
// failure into a sentence that says what to do.
func (s *Server) startTLS(ctx context.Context, rawConn net.Conn, remote string) (net.Conn, *bufio.Reader, bool) {
	sniff := bufio.NewReader(rawConn)

	head, err := sniff.Peek(len(protocol.Magic))
	if err != nil {
		switch {
		case errors.Is(err, io.EOF):
			// A bare connect that closes without sending: port scanners, and
			// anything probing whether the port is open.
			s.log.Debug("connection closed before handshake", "remote", remote)
		case isTimeout(err):
			s.log.Warn("connection timed out before the handshake", "remote", remote)
		default:
			s.log.Warn("read failed before handshake", "remote", remote, "error", err)
		}
		return nil, nil, false
	}

	if [4]byte(head) == protocol.Magic {
		s.log.Warn("rejected an unencrypted request", "remote", remote)
		// Answered in the clear, because that is the only language this peer
		// speaks. It carries no secret — just an instruction.
		if err := rawConn.SetWriteDeadline(time.Now().Add(s.timeout)); err == nil {
			_ = protocol.WriteResponse(rawConn, protocol.StatusMalformed,
				"this daemon requires TLS; upgrade clipd on the client machine (see clipd version)")
		}
		return nil, nil, false
	}

	// The peeked bytes have been consumed from rawConn, so the handshake gets
	// a wrapper that replays them before continuing.
	conn := tls.Server(&peekedConn{Conn: rawConn, r: sniff}, s.tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		s.log.Warn("TLS handshake failed", "remote", remote, "error", err)
		return nil, nil, false
	}
	return conn, bufio.NewReader(conn), true
}

// peekedConn is a net.Conn whose reads come from a reader that has already
// buffered some of the stream.
type peekedConn struct {
	net.Conn
	r io.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// respond writes a status frame, refreshing the deadline first so a slow
// reader on the client side cannot make the acknowledgement hang.
func (s *Server) respond(conn net.Conn, status protocol.Status, message string) {
	if err := conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return
	}
	if err := protocol.WriteResponse(conn, status, message); err != nil {
		s.log.Debug("response write failed", "remote", conn.RemoteAddr().String(), "error", err)
	}
}

// payloadTimeout scales the read deadline with the declared payload size.
func (s *Server) payloadTimeout(n uint64) time.Duration {
	return s.timeout + time.Duration(n/minThroughput)*time.Second
}

// isTimeout reports whether an error came from an expired deadline.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
