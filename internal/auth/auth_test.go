package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 64)
	for range 64 {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if seen[token] {
			t.Fatalf("GenerateToken returned a duplicate: %q", token)
		}
		seen[token] = true

		if err := Validate(token); err != nil {
			t.Errorf("generated token failed validation: %v", err)
		}
		// Base64url output must survive being pasted into a shell command or
		// a JSON config without quoting.
		if strings.ContainsAny(token, "+/=\"'\\ \n\t") {
			t.Errorf("token contains characters that need quoting: %q", token)
		}
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrNoToken},
		{"too short", strings.Repeat("a", MinTokenLen-1), ErrTokenTooShort},
		{"minimum length", strings.Repeat("a", MinTokenLen), nil},
		{"maximum length", strings.Repeat("a", MaxTokenLen), nil},
		{"too long", strings.Repeat("a", MaxTokenLen+1), ErrTokenTooLong},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tc.token)
			if tc.want == nil {
				if err != nil {
					t.Errorf("Validate(%d chars) = %v, want nil", len(tc.token), err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()

	const expected = "correct-horse-battery-staple"

	tests := []struct {
		name      string
		expected  string
		presented string
		want      bool
	}{
		{"match", expected, expected, true},
		{"mismatch", expected, "wrong-token-entirely-here", false},
		{"prefix only", expected, "correct-horse", false},
		{"expected is a prefix of presented", expected, expected + "x", false},
		{"case differs", expected, "CORRECT-HORSE-BATTERY-STAPLE", false},
		{"empty presented", expected, "", false},
		// A server with no configured token must reject everything, most
		// importantly a client that also presents nothing.
		{"empty expected rejects empty", "", "", false},
		{"empty expected rejects anything", "", "guess", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Compare(tc.expected, []byte(tc.presented)); got != tc.want {
				t.Errorf("Compare(%q, %q) = %v, want %v", tc.expected, tc.presented, got, tc.want)
			}
		})
	}
}

// TestCompareHandlesArbitraryBytes checks that a token arriving off the wire
// can be any byte sequence without upsetting the comparison.
func TestCompareHandlesArbitraryBytes(t *testing.T) {
	t.Parallel()

	if Compare("token", []byte{0xff, 0x00, 0xfe}) {
		t.Error("Compare accepted arbitrary bytes")
	}
	if !Compare("\x00\xff", []byte{0x00, 0xff}) {
		t.Error("Compare rejected an exact byte match")
	}
}

func TestRedact(t *testing.T) {
	t.Parallel()

	const token = "abcdefghijklmnopqrstuvwxyz"
	got := Redact(token)
	if strings.Contains(got, token) {
		t.Errorf("Redact leaked the token: %q", got)
	}
	if !strings.HasPrefix(got, "abcd") {
		t.Errorf("Redact = %q, want it to start with the first four characters", got)
	}
	if Redact("") != "(not set)" {
		t.Errorf("Redact(\"\") = %q", Redact(""))
	}
	if Redact("ab") != "(set)" {
		t.Errorf("Redact of a short token leaked it: %q", Redact("ab"))
	}
}
