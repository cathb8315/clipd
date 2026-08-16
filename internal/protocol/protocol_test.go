package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		token   string
		payload []byte
	}{
		{"typical", "s3cret-token-value", []byte("total 8\ndrwxr-xr-x  3 user  staff\n")},
		{"empty payload", "s3cret-token-value", []byte{}},
		{"trailing newline preserved", "tok", []byte("line\n")},
		{"no trailing newline", "tok", []byte("line")},
		{"tabs and control bytes", "tok", []byte("a\tb\r\n\x1b[31mred\x00\x7f")},
		// Not valid UTF-8. The transport must not care: it moves bytes.
		{"invalid utf-8", "tok", []byte{0xff, 0xfe, 0x80, 0x00, 0x41}},
		{"maximum length token", strings.Repeat("t", MaxTokenLen), []byte("x")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			if err := WriteRequest(&buf, tc.token, tc.payload); err != nil {
				t.Fatalf("WriteRequest: %v", err)
			}

			r := bytes.NewReader(buf.Bytes())
			req, err := ReadPrologue(r)
			if err != nil {
				t.Fatalf("ReadPrologue: %v", err)
			}
			if req.Version != CurrentVersion {
				t.Errorf("version = 0x%02x, want 0x%02x", req.Version, CurrentVersion)
			}
			if string(req.Token) != tc.token {
				t.Errorf("token = %q, want %q", req.Token, tc.token)
			}

			n, err := ReadPayloadLen(r)
			if err != nil {
				t.Fatalf("ReadPayloadLen: %v", err)
			}
			if n != uint64(len(tc.payload)) {
				t.Fatalf("payload length = %d, want %d", n, len(tc.payload))
			}

			got, err := ReadPayload(r, n)
			if err != nil {
				t.Fatalf("ReadPayload: %v", err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Errorf("payload = %q, want %q", got, tc.payload)
			}
			if r.Len() != 0 {
				t.Errorf("%d unread bytes remain after the frame", r.Len())
			}
		})
	}
}

// TestFragmentedReads proves the reader tolerates a stream delivered one byte
// at a time, which is the partial-read case a single conn.Read would botch.
func TestFragmentedReads(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("clipboard payload "), 64)
	var buf bytes.Buffer
	if err := WriteRequest(&buf, "token-value-here", payload); err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}

	r := iotest.OneByteReader(bytes.NewReader(buf.Bytes()))

	req, err := ReadPrologue(r)
	if err != nil {
		t.Fatalf("ReadPrologue: %v", err)
	}
	if string(req.Token) != "token-value-here" {
		t.Errorf("token = %q", req.Token)
	}
	n, err := ReadPayloadLen(r)
	if err != nil {
		t.Fatalf("ReadPayloadLen: %v", err)
	}
	got, err := ReadPayload(r, n)
	if err != nil {
		t.Fatalf("ReadPayload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("payload corrupted across fragmented reads")
	}
}

func TestWriteRequestRejectsBadTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrEmptyToken},
		{"too long", strings.Repeat("t", MaxTokenLen+1), ErrTokenTooLong},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := WriteRequest(io.Discard, tc.token, []byte("x"))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReadPrologueRejectsGarbage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
		want  error
	}{
		{
			name:  "wrong magic",
			input: []byte("GET / HTTP/1.1\r\n"),
			want:  ErrBadMagic,
		},
		{
			name:  "unsupported version",
			input: append(append([]byte{}, Magic[:]...), 0x99, 0x04, 't', 'o', 'k', 'n'),
			want:  ErrUnsupportedVersion,
		},
		{
			name:  "zero-length token",
			input: append(append([]byte{}, Magic[:]...), CurrentVersion, 0x00),
			want:  ErrEmptyToken,
		},
		{
			name:  "truncated before token",
			input: append(append([]byte{}, Magic[:]...), CurrentVersion, 0x08, 't'),
			want:  io.ErrUnexpectedEOF,
		},
		{
			name:  "empty stream",
			input: nil,
			want:  io.EOF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ReadPrologue(bytes.NewReader(tc.input))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestReadPayloadLenIsUntrusted documents that the decoder reports whatever
// length the peer declared. Enforcing a limit is the server's job, and it has
// to happen before ReadPayload is ever called.
func TestReadPayloadLenIsUntrusted(t *testing.T) {
	t.Parallel()

	declared := uint64(1) << 40
	buf := binary.BigEndian.AppendUint64(nil, declared)

	got, err := ReadPayloadLen(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadPayloadLen: %v", err)
	}
	if got != declared {
		t.Errorf("length = %d, want %d", got, declared)
	}
}

func TestReadPayloadTruncated(t *testing.T) {
	t.Parallel()

	_, err := ReadPayload(bytes.NewReader([]byte("only four")), 100)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  Status
		message string
	}{
		{"ok with message", StatusOK, "copied 42 bytes"},
		{"ok without message", StatusOK, ""},
		{"auth failed", StatusAuthFailed, "authentication failed"},
		{"too large", StatusPayloadTooLarge, "payload of 99 bytes exceeds the server limit of 10 bytes"},
		{"malformed", StatusMalformed, "protocol: not a clipd request"},
		{"internal", StatusInternalError, "clipboard write failed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			if err := WriteResponse(&buf, tc.status, tc.message); err != nil {
				t.Fatalf("WriteResponse: %v", err)
			}
			status, message, err := ReadResponse(iotest.OneByteReader(&buf))
			if err != nil {
				t.Fatalf("ReadResponse: %v", err)
			}
			if status != tc.status {
				t.Errorf("status = %v, want %v", status, tc.status)
			}
			if message != tc.message {
				t.Errorf("message = %q, want %q", message, tc.message)
			}
		})
	}
}

// TestWriteResponseTruncatesLongMessage checks that a diagnostic string too
// large for the uint16 length field is clipped rather than failing a copy
// that already succeeded.
func TestWriteResponseTruncatesLongMessage(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("m", MaxMessageLen+500)
	var buf bytes.Buffer
	if err := WriteResponse(&buf, StatusOK, long); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	_, message, err := ReadResponse(&buf)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if len(message) != MaxMessageLen {
		t.Errorf("message length = %d, want %d", len(message), MaxMessageLen)
	}
}

func TestStatusString(t *testing.T) {
	t.Parallel()

	if !StatusOK.OK() {
		t.Error("StatusOK.OK() = false")
	}
	if StatusAuthFailed.OK() {
		t.Error("StatusAuthFailed.OK() = true")
	}
	if got := Status(0x42).String(); !strings.Contains(got, "0x42") {
		t.Errorf("unknown status string = %q, want it to mention the code", got)
	}
}
