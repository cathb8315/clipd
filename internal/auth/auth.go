// Package auth handles clipd's shared-token authentication.
//
// The scheme is deliberately minimal: a single cryptographically random
// token, generated on the Mac and copied once to the client. The token
// authorises a client; it does not provide confidentiality. See the README
// security section.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// TokenBytes is the amount of entropy in a generated token. 256 bits makes
// online guessing hopeless, which is what lets the server skip rate limiting
// and lockouts entirely.
const TokenBytes = 32

// MinTokenLen guards against a user hand-editing the config file down to
// something guessable.
const MinTokenLen = 16

// MaxTokenLen matches the protocol's single-byte length field.
const MaxTokenLen = 255

var (
	// ErrNoToken means no token is configured. It is a distinct error because
	// a server with an empty token must refuse to start rather than accept
	// every client that presents an empty token.
	ErrNoToken = errors.New("auth: no token configured")

	// ErrTokenTooShort means a configured token has too little entropy.
	ErrTokenTooShort = errors.New("auth: token too short")

	// ErrTokenTooLong means a configured token cannot be represented on the wire.
	ErrTokenTooLong = errors.New("auth: token too long")
)

// GenerateToken returns a new URL-safe base64 token carrying TokenBytes of
// entropy. Base64url avoids characters that need quoting when the token is
// pasted into a shell command or a config file.
func GenerateToken() (string, error) {
	buf := make([]byte, TokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Validate reports whether a token is usable.
func Validate(token string) error {
	switch {
	case token == "":
		return ErrNoToken
	case len(token) < MinTokenLen:
		return fmt.Errorf("%w: %d characters (minimum %d)", ErrTokenTooShort, len(token), MinTokenLen)
	case len(token) > MaxTokenLen:
		return fmt.Errorf("%w: %d characters (maximum %d)", ErrTokenTooLong, len(token), MaxTokenLen)
	}
	return nil
}

// Compare reports whether a presented token matches the expected one.
//
// Both sides are hashed before comparison. subtle.ConstantTimeCompare
// short-circuits on a length mismatch, which would leak the expected token's
// length through timing; hashing first makes both inputs a fixed 32 bytes so
// the comparison is uniform regardless of what the client sent.
//
// An empty expected token never matches: a misconfigured server must reject
// everything rather than accept everything.
func Compare(expected string, presented []byte) bool {
	if expected == "" {
		return false
	}
	expectedSum := sha256.Sum256([]byte(expected))
	presentedSum := sha256.Sum256(presented)
	return subtle.ConstantTimeCompare(expectedSum[:], presentedSum[:]) == 1
}

// Redact renders a token safely for display: enough to tell two tokens apart
// when troubleshooting, not enough to use one.
func Redact(token string) string {
	if token == "" {
		return "(not set)"
	}
	const shown = 4
	if len(token) <= shown {
		return "(set)"
	}
	return fmt.Sprintf("%s… (%d characters)", token[:shown], len(token))
}
