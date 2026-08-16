// Command clipd is a terminal-independent remote clipboard.
//
// One binary plays both roles. On macOS `clipd serve` runs a small daemon
// that writes what it receives to the system clipboard; on any machine that
// can reach it, `something | clipd` sends stdin there and exits. Nothing is
// asked of the terminal emulator, so the workflow behaves identically in
// Terminal.app, iTerm2, Ghostty, tmux or a VS Code panel.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/colefailla/clipd/internal/client"
	"github.com/colefailla/clipd/internal/config"
	"github.com/colefailla/clipd/internal/transport"
)

// Build information, injected with -ldflags. See the Makefile.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Exit codes. Distinct codes let a script branch on $? instead of parsing
// stderr. 64 is sysexits.h's EX_USAGE, kept apart from the operational codes
// so "I typed it wrong" never looks like "authentication failed".
const (
	exitOK       = 0
	exitFailure  = 1
	exitAuth     = 2
	exitTooLarge = 3
	exitConfig   = 4
	exitTLS      = 5
	exitUsage    = 64
)

// env is the process environment the commands run against, injected so the
// dispatcher and commands are testable without touching the real one.
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	// stdinIsPipe is true when stdin is a pipe or a file rather than a
	// terminal. It is what makes `ls | clipd` work without a subcommand.
	stdinIsPipe bool

	getenv func(string) string
}

// globalOptions are accepted before or after the subcommand.
type globalOptions struct {
	configPath string
	verbose    bool
	timeout    string
}

// commandFunc is the signature every subcommand implements.
type commandFunc func(ctx context.Context, e *env, g *globalOptions, args []string) int

// commands is the authoritative list of subcommand names.
//
// It is consulted before argument parsing decides anything else, because
// `clipd serve` and `clipd notes.txt` occupy the same argv slot: a name in
// this table is a command, and anything else is a filename.
var commands = map[string]commandFunc{
	"copy":      cmdCopy,
	"serve":     cmdServe,
	"setup":     cmdSetup,
	"configure": cmdConfigure,
	"status":    cmdStatus,
	"install":   cmdInstall,
	"uninstall": cmdUninstall,
	"version":   cmdVersion,
	"help":      cmdHelp,
}

func main() {
	e := &env{
		stdin:       os.Stdin,
		stdout:      os.Stdout,
		stderr:      os.Stderr,
		stdinIsPipe: stdinIsPipe(os.Stdin),
		getenv:      os.Getenv,
	}
	os.Exit(run(context.Background(), os.Args[1:], e))
}

// run dispatches a command line and returns a process exit code.
func run(ctx context.Context, args []string, e *env) int {
	var g globalOptions

	fs := flag.NewFlagSet("clipd", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	fs.Usage = func() { printUsage(e.stderr) }
	registerGlobalFlags(fs, &g)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(e.stdout)
			return exitOK
		}
		return exitUsage
	}

	rest := fs.Args()
	if len(rest) == 0 {
		// No subcommand. Piped stdin means the user wants a copy; a terminal
		// means they typed `clipd` to see what it does.
		if e.stdinIsPipe {
			return cmdCopy(ctx, e, &g, nil)
		}
		printUsage(e.stderr)
		return exitUsage
	}

	if isCommand(rest[0]) {
		return commands[rest[0]](ctx, e, &g, rest[1:])
	}

	// Not a command, so it is a file to copy.
	return cmdCopy(ctx, e, &g, rest)
}

// isCommand reports whether an argument names a subcommand.
//
// The match is exact: "serve" is a command, "serve.txt" and "./serve" are
// files. A file whose name collides with a command is reachable through the
// explicit form, `clipd copy serve`.
func isCommand(arg string) bool {
	_, ok := commands[arg]
	return ok
}

// registerGlobalFlags attaches the global flags to fs.
//
// Each flag's default is g's current value, so registering the same flags on
// a subcommand's flag set preserves anything already parsed from before the
// subcommand. That is what makes `clipd --verbose copy` and
// `clipd copy --verbose` equivalent.
func registerGlobalFlags(fs *flag.FlagSet, g *globalOptions) {
	fs.StringVar(&g.configPath, "config", g.configPath, "path to the clipd config file")
	fs.BoolVar(&g.verbose, "verbose", g.verbose, "report progress on stderr")
	fs.BoolVar(&g.verbose, "v", g.verbose, "shorthand for -verbose")
	fs.StringVar(&g.timeout, "timeout", g.timeout, "network timeout, e.g. 5s")
}

// newFlagSet builds a subcommand flag set that also accepts the global flags.
func newFlagSet(e *env, g *globalOptions, name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet("clipd "+name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	registerGlobalFlags(fs, g)
	fs.Usage = func() {
		fmt.Fprintf(e.stderr, "%s\n\nOptions:\n", usage)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags parses a subcommand's arguments, translating flag package
// outcomes into exit codes. ok is false when the caller should return code.
func parseFlags(fs *flag.FlagSet, e *env, args []string) (code int, ok bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, false
		}
		return exitUsage, false
	}
	return exitOK, true
}

// loadConfig resolves and loads configuration for a command, applying
// environment overrides and the global --timeout flag.
func loadConfig(e *env, g *globalOptions) (config.Config, string, error) {
	path, err := config.ResolvePath(g.configPath)
	if err != nil {
		return config.Config{}, "", err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return cfg, path, err
	}
	if err := cfg.ApplyEnv(e.getenv); err != nil {
		return cfg, path, err
	}
	if g.timeout != "" {
		d, err := config.ParseDuration(g.timeout)
		if err != nil {
			return cfg, path, fmt.Errorf("-timeout: %w", err)
		}
		cfg.TimeoutMS = d.Milliseconds()
	}
	return cfg, path, nil
}

// fail prints an error to stderr in the conventional `clipd: message` form
// and returns the exit code.
func fail(e *env, code int, err error) int {
	fmt.Fprintf(e.stderr, "clipd: %v\n", err)
	return code
}

// failf is fail for messages built on the spot.
func failf(e *env, code int, format string, args ...any) int {
	return fail(e, code, fmt.Errorf(format, args...))
}

// exitCodeFor maps a copy failure onto its exit code.
func exitCodeFor(err error) int {
	var cerr *client.Error
	if errors.As(err, &cerr) {
		switch cerr.Kind {
		case client.KindAuth:
			return exitAuth
		case client.KindTooLarge:
			return exitTooLarge
		case client.KindTLS:
			return exitTLS
		}
	}
	return exitFailure
}

// clientTLS builds the pinned TLS configuration from the configured
// fingerprint.
func clientTLS(cfg config.Config) (*tls.Config, error) {
	pin, err := transport.ParseFingerprint(cfg.ServerFingerprint)
	if err != nil {
		return nil, fmt.Errorf("server_fingerprint: %w", err)
	}
	return transport.ClientConfig(pin)
}

// stdinIsPipe reports whether stdin is connected to a pipe or a file rather
// than a terminal.
func stdinIsPipe(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		// If the mode cannot be determined, assume a terminal: printing usage
		// is a harmless mistake, silently blocking on a read is not.
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `clipd — send stdin to a remote Mac's clipboard

Usage:
  <command> | clipd              copy piped input to the configured Mac
  clipd <file>                   copy a file's contents
  clipd <command> [options]

Commands:
  copy        copy stdin or a file to the remote clipboard (the default)
  serve       run the clipboard daemon in the foreground (macOS)
  setup       macOS: create the config, generate the token and TLS keypair
  configure   client: set the server address, port, token and fingerprint
  status      show configuration, daemon state, reachability and pin check
  install     macOS: install and start the LaunchAgent
  uninstall   macOS: stop and remove the LaunchAgent
  version     print build information
  help        show help for a command

Global options:
  -config <path>     use an alternate config file
  -timeout <dur>     network timeout, e.g. 5s
  -verbose, -v       report progress on stderr

Environment:
  CLIPD_CONFIG, CLIPD_SERVER, CLIPD_PORT, CLIPD_BIND, CLIPD_TOKEN,
  CLIPD_FINGERPRINT, CLIPD_TLS_CERT, CLIPD_TLS_KEY, CLIPD_MAX_PAYLOAD,
  CLIPD_TIMEOUT

Run 'clipd help config' for the config file format.

Examples:
  docker ps | clipd
  clipd compose.yaml
  clipd -v status

Run 'clipd help <command>' for details.
`)
}

// cmdHelp prints general or per-command help.
func cmdHelp(_ context.Context, e *env, _ *globalOptions, args []string) int {
	if len(args) == 0 {
		printUsage(e.stdout)
		return exitOK
	}
	topic := args[0]
	text, ok := helpTopics[topic]
	if !ok {
		fmt.Fprintf(e.stderr, "clipd: no help for %q\n", topic)
		return exitUsage
	}
	fmt.Fprintln(e.stdout, text)
	return exitOK
}

var helpTopics = map[string]string{
	"copy": `clipd copy [file]

Reads stdin, or the named file, and copies it to the configured Mac's
clipboard. A file named "-" means stdin. This is what runs when no
subcommand is given and stdin is piped, so these are equivalent:

  echo hello | clipd
  echo hello | clipd copy

Content is sent byte for byte: newlines, tabs and the trailing newline are
preserved exactly as supplied. Input larger than the configured maximum is
rejected rather than truncated.

Options:
  -max-payload <size>   override the limit for this copy, e.g. 20MB

Exit codes: 0 success, 1 connection or server failure, 2 authentication
failure, 3 payload too large, 4 configuration error, 5 TLS handshake or
fingerprint mismatch, 64 usage error.`,

	"serve": `clipd serve

Runs the clipboard daemon in the foreground until SIGINT or SIGTERM. macOS
only, since writing the clipboard is what the daemon does.

It does not detach: under the LaunchAgent, launchd owns backgrounding,
restarts and log files.

Options:
  -bind <address>   listen address (default from config, 0.0.0.0)
  -port <port>      listen port (default from config, 8199)`,

	"setup": `clipd setup

Creates the config file on the Mac, generating a random authentication token
and a TLS keypair if they do not exist, then prints the exact command to run
on the client machine. Running it again prints the existing token and
fingerprint rather than replacing them.

The token is a secret. The fingerprint is not: it is the server's identity,
and clients use it to verify they are talking to this Mac.

Options:
  -bind <address>       listen address to store (default 0.0.0.0)
  -port <port>          listen port to store
  -max-payload <size>   maximum accepted payload, e.g. 10MB
  -rotate               generate a new token, invalidating the old one
  -rotate-cert          generate a new TLS keypair; every client must then be
                        reconfigured with the new fingerprint`,

	"configure": `clipd configure

Stores the Mac's address, port, token and server fingerprint on the client
machine. With no flags on a terminal it prompts for each value; in a script,
pass flags. Both the token and the fingerprint come from 'clipd setup' on
the Mac.

Options:
  -server <host>        Mac hostname or IP address
  -port <port>          port the daemon listens on
  -token <token>        authentication token, or "-" to read it from stdin
  -fingerprint <fp>     server key fingerprint; accepts the sha256: prefix or
                        not, colons or not, any case
  -max-payload <size>   maximum payload to send, e.g. 10MB
  -timeout <duration>   network timeout to store, e.g. 5s

The config file is written with 0600 permissions inside a 0700 directory,
because it contains the token in plaintext.`,

	"status": `clipd status

Shows the resolved configuration, the local daemon's state on macOS, and
whether the configured server is reachable. The token is never printed in
full.

On a client it also completes a TLS handshake with the daemon and reports
whether the server's key matches the pinned fingerprint, without sending the
token or any payload. A mismatch prints both fingerprints.`,

	"config": `clipd config file

Location:

  macOS   ~/Library/Application Support/clipd/config.json
  Linux   $XDG_CONFIG_HOME/clipd/config.json, or ~/.config/clipd/config.json

Override with -config <path> or CLIPD_CONFIG. The directory is created 0700
and the file 0600, because the token is stored in plaintext. The daemon's TLS
keypair lives in a tls/ directory beside the config file.

Keys, all optional except where noted:

  server_address      client: Mac hostname or IP. Required to copy.
  port                both:   port the daemon listens on (default 8199)
  bind_address        daemon: listen address (default 0.0.0.0)
  token               both:   shared authentication token. Required.
  server_fingerprint  client: pinned server public key. Required to copy.
  tls_cert_path       daemon: certificate path; empty means beside the config
  tls_key_path        daemon: private key path; empty means beside the config
  max_payload_bytes   both:   largest accepted payload (default 10485760)
  timeout_ms          both:   connect and handshake timeout (default 5000)

Keys belonging to the other role stay empty: a Mac has no server_address, a
client has no keypair. Unknown keys are rejected rather than ignored, so a
typo fails loudly instead of silently leaving a default in place.

Environment variables override the file:

  CLIPD_CONFIG CLIPD_SERVER CLIPD_PORT CLIPD_BIND CLIPD_TOKEN
  CLIPD_FINGERPRINT CLIPD_TLS_CERT CLIPD_TLS_KEY CLIPD_MAX_PAYLOAD
  CLIPD_TIMEOUT

CLIPD_MAX_PAYLOAD accepts a suffix (10MB, 512KiB); CLIPD_TIMEOUT takes a
duration (5s, 500ms).`,

	"install": `clipd install

macOS only. Generates the config and token if needed, writes
~/Library/LaunchAgents/com.clipd.agent.plist, and loads it into the user's
GUI session so the daemon starts at login and restarts if it crashes. No
root privileges are required.

Options:
  -exec <path>   binary path to record in the plist (default: this binary)`,

	"uninstall": `clipd uninstall

macOS only. Unloads the LaunchAgent and removes its plist. The config file
is left in place; delete it by hand to remove the stored token.`,

	"version": `clipd version

Prints the version, commit and build date recorded at build time, plus the
Go toolchain and target platform.`,

	"help": `clipd help [topic]

With no topic, prints the command list. With a topic, prints detail for that
command. 'clipd help config' documents the config file format.`,
}
