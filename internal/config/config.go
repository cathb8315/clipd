// Package config loads, validates and persists clipd's per-user settings.
//
// The format is JSON via encoding/json — no third-party config library, since
// the entire schema is six fields. Precedence is: defaults, then the config
// file, then environment variables, then command-line flags. Environment
// overrides exist so a script can run a one-off copy against a different Mac
// without rewriting the user's config file.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Defaults.
const (
	// DefaultPort sits outside the crowded 8000/8080/8443 range where local
	// development servers collide. IANA has it registered to Veritas Volume
	// Replicator, which is not something that shares a machine with this.
	DefaultPort = 8199

	// DefaultBindAddress listens on every interface.
	//
	// Loopback would be a safer-looking default and a useless one: the entire
	// point is that a Linux box across the LAN can reach this daemon. The
	// service is authenticated, so the exposure is a token check rather than
	// an open clipboard.
	DefaultBindAddress = "0.0.0.0"

	// DefaultMaxPayloadBytes is 10 MiB: comfortably more than any terminal
	// output a human pipes by hand, small enough that a stray `cat` of a
	// video file fails fast instead of filling memory.
	DefaultMaxPayloadBytes int64 = 10 << 20

	// DefaultTimeout bounds connect, handshake and acknowledgement. The
	// payload transfer gets additional time proportional to its size.
	DefaultTimeout = 5 * time.Second

	// MaxAllowedPayloadBytes caps what the config file may ask for, so a
	// typo cannot turn the daemon into an out-of-memory button.
	MaxAllowedPayloadBytes int64 = 1 << 30
)

// File layout.
const (
	// AppName is the config subdirectory name under the user's config dir.
	AppName = "clipd"

	// FileName is the config file within that directory.
	FileName = "config.json"

	// DirPerm and FilePerm are applied explicitly with Chmod after creation:
	// the mode passed to MkdirAll/OpenFile is masked by umask, and the token
	// must not be readable by other users on a shared machine.
	DirPerm  fs.FileMode = 0o700
	FilePerm fs.FileMode = 0o600
)

// Environment variable names.
const (
	EnvConfig      = "CLIPD_CONFIG"
	EnvServer      = "CLIPD_SERVER"
	EnvPort        = "CLIPD_PORT"
	EnvBind        = "CLIPD_BIND"
	EnvToken       = "CLIPD_TOKEN"
	EnvFingerprint = "CLIPD_FINGERPRINT"
	EnvTLSCert     = "CLIPD_TLS_CERT"
	EnvTLSKey      = "CLIPD_TLS_KEY"
	EnvMaxPayload  = "CLIPD_MAX_PAYLOAD"
	EnvTimeout     = "CLIPD_TIMEOUT"
)

// TLS material lives beside the config file.
const (
	TLSDirName   = "tls"
	CertFileName = "cert.pem"
	KeyFileName  = "key.pem"
)

// Config is the on-disk configuration.
//
// One struct serves both roles. A Mac uses BindAddress, Port, Token and
// MaxPayloadBytes; a Linux client uses ServerAddress, Port, Token and
// Timeout. Splitting them would mean two files and two code paths for a
// utility whose whole configuration fits on a screen.
type Config struct {
	// ServerAddress is the Mac's hostname or IP as seen from the client.
	// clipd never interprets it beyond passing it to the dialer, so a LAN
	// address, a .local hostname or a VPN name all work identically.
	ServerAddress string `json:"server_address"`

	// Port is used by both roles: the client dials it, the server binds it.
	Port int `json:"port"`

	// BindAddress is the server's listen address.
	BindAddress string `json:"bind_address"`

	// Token is the shared secret. Stored in plaintext, which is why the file
	// is 0600 inside a 0700 directory.
	Token string `json:"token"`

	// ServerFingerprint pins the daemon's public key. Not a secret — it is
	// the server's identity, not a credential — but a client without it
	// cannot verify what it is talking to, so it is required.
	ServerFingerprint string `json:"server_fingerprint"`

	// TLSCertPath and TLSKeyPath override where the daemon keeps its
	// keypair. Empty means the default location beside the config file,
	// resolved by CertPath and KeyPath.
	TLSCertPath string `json:"tls_cert_path"`
	TLSKeyPath  string `json:"tls_key_path"`

	// MaxPayloadBytes is enforced by the client before sending and by the
	// server before allocating.
	MaxPayloadBytes int64 `json:"max_payload_bytes"`

	// TimeoutMS is stored as milliseconds because JSON has no duration type
	// and a bare number is less error-prone than a string to hand-edit.
	TimeoutMS int64 `json:"timeout_ms"`
}

// Default returns the built-in configuration, with no token and no server
// address: both are established during setup.
func Default() Config {
	return Config{
		Port:            DefaultPort,
		BindAddress:     DefaultBindAddress,
		MaxPayloadBytes: DefaultMaxPayloadBytes,
		TimeoutMS:       DefaultTimeout.Milliseconds(),
	}
}

// DefaultPath returns the config file path for the current user.
//
// os.UserConfigDir already encodes the per-OS convention: Application Support
// on macOS, XDG_CONFIG_HOME (or ~/.config) on Linux.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user config directory: %w", err)
	}
	return filepath.Join(dir, AppName, FileName), nil
}

// ResolvePath picks the config path from, in order: an explicit flag value,
// CLIPD_CONFIG, then the platform default.
func ResolvePath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := os.Getenv(EnvConfig); env != "" {
		return env, nil
	}
	return DefaultPath()
}

// Exists reports whether a config file is present.
func Exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// Load reads the config file, filling unset fields from the defaults.
//
// A missing file is not an error: it yields defaults, so `clipd setup` and
// the environment-only workflow both work on a fresh machine. Callers decide
// whether the resulting config is usable by calling ValidateClient or
// ValidateServer.
func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}

	// Unknown fields are rejected rather than ignored: a typo like
	// "server_adress" would otherwise leave the user staring at a config that
	// looks correct while clipd silently uses the default.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var file Config
	if err := dec.Decode(&file); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Merge: an omitted or zero field keeps its default rather than becoming
	// zero, so a hand-written config need only set what it cares about.
	if file.ServerAddress != "" {
		cfg.ServerAddress = file.ServerAddress
	}
	if file.Port != 0 {
		cfg.Port = file.Port
	}
	if file.BindAddress != "" {
		cfg.BindAddress = file.BindAddress
	}
	if file.Token != "" {
		cfg.Token = file.Token
	}
	if file.ServerFingerprint != "" {
		cfg.ServerFingerprint = file.ServerFingerprint
	}
	if file.TLSCertPath != "" {
		cfg.TLSCertPath = file.TLSCertPath
	}
	if file.TLSKeyPath != "" {
		cfg.TLSKeyPath = file.TLSKeyPath
	}
	if file.MaxPayloadBytes != 0 {
		cfg.MaxPayloadBytes = file.MaxPayloadBytes
	}
	if file.TimeoutMS != 0 {
		cfg.TimeoutMS = file.TimeoutMS
	}
	return cfg, nil
}

// ApplyEnv overlays environment-variable overrides.
//
// getenv is injected so tests need not mutate the process environment; pass
// os.Getenv in production. A malformed value is an error rather than a
// silent fallback: a typo in CLIPD_PORT should be loud.
func (c *Config) ApplyEnv(getenv func(string) string) error {
	if v := getenv(EnvServer); v != "" {
		c.ServerAddress = v
	}
	if v := getenv(EnvPort); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("%s: %q is not a number", EnvPort, v)
		}
		c.Port = port
	}
	if v := getenv(EnvBind); v != "" {
		c.BindAddress = v
	}
	if v := getenv(EnvToken); v != "" {
		c.Token = v
	}
	if v := getenv(EnvFingerprint); v != "" {
		c.ServerFingerprint = v
	}
	if v := getenv(EnvTLSCert); v != "" {
		c.TLSCertPath = v
	}
	if v := getenv(EnvTLSKey); v != "" {
		c.TLSKeyPath = v
	}
	if v := getenv(EnvMaxPayload); v != "" {
		size, err := ParseSize(v)
		if err != nil {
			return fmt.Errorf("%s: %w", EnvMaxPayload, err)
		}
		c.MaxPayloadBytes = size
	}
	if v := getenv(EnvTimeout); v != "" {
		d, err := ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%s: %w", EnvTimeout, err)
		}
		c.TimeoutMS = d.Milliseconds()
	}
	return nil
}

// Save writes the config atomically with restrictive permissions.
//
// The write goes to a temporary file in the same directory and is then
// renamed, so an interrupted save cannot leave a truncated config — or worse,
// a config with a half-written token — in place.
func (c Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, DirPerm); err != nil {
		return fmt.Errorf("create config directory %s: %w", dir, err)
	}
	// MkdirAll's mode is subject to umask, and it does nothing at all if the
	// directory already existed with looser permissions.
	if err := os.Chmod(dir, DirPerm); err != nil {
		return fmt.Errorf("secure config directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, FileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if err := tmp.Chmod(FilePerm); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temporary config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install config %s: %w", path, err)
	}
	return nil
}

// Timeout returns TimeoutMS as a duration, falling back to the default if the
// stored value is not positive.
func (c Config) Timeout() time.Duration {
	if c.TimeoutMS <= 0 {
		return DefaultTimeout
	}
	return time.Duration(c.TimeoutMS) * time.Millisecond
}

// DialAddress is the host:port a client connects to. JoinHostPort is used
// rather than string concatenation so IPv6 literals are bracketed correctly.
func (c Config) DialAddress() string {
	return net.JoinHostPort(c.ServerAddress, strconv.Itoa(c.Port))
}

// ListenAddress is the host:port the daemon binds.
func (c Config) ListenAddress() string {
	return net.JoinHostPort(c.BindAddress, strconv.Itoa(c.Port))
}

// CertPath is where the daemon's certificate lives: the configured override,
// or a tls/ directory beside the config file.
//
// It is derived from the config path rather than stored, so moving the config
// with -config moves the whole set together.
func (c Config) CertPath(configPath string) string {
	if c.TLSCertPath != "" {
		return c.TLSCertPath
	}
	return filepath.Join(filepath.Dir(configPath), TLSDirName, CertFileName)
}

// KeyPath is the private-key counterpart to CertPath.
func (c Config) KeyPath(configPath string) string {
	if c.TLSKeyPath != "" {
		return c.TLSKeyPath
	}
	return filepath.Join(filepath.Dir(configPath), TLSDirName, KeyFileName)
}

// ValidateClient checks the fields a copy operation needs.
func (c Config) ValidateClient() error {
	if c.ServerAddress == "" {
		return errors.New("no server address configured: run `clipd configure` or set CLIPD_SERVER")
	}
	if c.Token == "" {
		return errors.New("no token configured: run `clipd configure` or set CLIPD_TOKEN")
	}
	// Without a pin there is nothing to verify the server against, so a copy
	// would be encrypted to whoever answered. That is not better than
	// plaintext, so it is refused rather than warned about.
	if c.ServerFingerprint == "" {
		return errors.New("no server fingerprint configured: run `clipd setup` on the Mac to display it, then `clipd configure -fingerprint`")
	}
	return c.validateCommon()
}

// ValidateServer checks the fields the daemon needs.
func (c Config) ValidateServer() error {
	if c.Token == "" {
		return errors.New("no token configured: run `clipd setup` on this Mac first")
	}
	if c.BindAddress == "" {
		return errors.New("no bind address configured")
	}
	return c.validateCommon()
}

func (c Config) validateCommon() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port %d is out of range (1-65535)", c.Port)
	}
	if c.MaxPayloadBytes < 1 {
		return fmt.Errorf("max payload %d must be positive", c.MaxPayloadBytes)
	}
	if c.MaxPayloadBytes > MaxAllowedPayloadBytes {
		return fmt.Errorf("max payload %s exceeds the %s ceiling",
			FormatSize(c.MaxPayloadBytes), FormatSize(MaxAllowedPayloadBytes))
	}
	if c.TimeoutMS < 1 {
		return fmt.Errorf("timeout %dms must be positive", c.TimeoutMS)
	}
	return nil
}

// ParseDuration parses a Go duration string such as "5s" or "500ms".
//
// A bare number is rejected with a hint rather than guessed at, because
// guessing wrong turns a 30-second timeout into 30 nanoseconds.
func ParseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: use a unit suffix, e.g. 5s or 500ms", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid duration %q: must be positive", s)
	}
	return d, nil
}

// ParseSize parses a byte count with an optional unit suffix: 1048576, 1MB,
// 512KiB. Decimal and binary suffixes are both accepted and both treated as
// binary multiples, since the distinction is noise at this scale.
func ParseSize(s string) (int64, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, errors.New("empty size")
	}

	upper := strings.ToUpper(trimmed)
	multiplier := int64(1)
	for _, unit := range []struct {
		suffix string
		mult   int64
	}{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
		{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30},
		{"B", 1},
	} {
		if strings.HasSuffix(upper, unit.suffix) {
			multiplier = unit.mult
			upper = strings.TrimSpace(strings.TrimSuffix(upper, unit.suffix))
			break
		}
	}

	value, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: use bytes or a suffix, e.g. 10MB", s)
	}
	if value <= 0 {
		return 0, fmt.Errorf("invalid size %q: must be positive", s)
	}
	if value > MaxAllowedPayloadBytes/multiplier {
		return 0, fmt.Errorf("size %q exceeds the %s ceiling", s, FormatSize(MaxAllowedPayloadBytes))
	}
	return value * multiplier, nil
}

// FormatSize renders a byte count for human consumption.
func FormatSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.3g GiB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.3g MiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.3g KiB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
