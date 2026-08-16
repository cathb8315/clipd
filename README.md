# clipd

[![CI](https://github.com/colefailla/clipd/actions/workflows/ci.yml/badge.svg)](https://github.com/colefailla/clipd/actions/workflows/ci.yml)

Send command output from a remote machine to your Mac's clipboard.

```bash
ssh debian
docker ps | clipd
```

The output is now in the Mac's clipboard.

clipd is useful when working over SSH from terminals that don't support
OSC 52, or in environments where OSC 52 doesn't reliably reach the local
terminal.

## How it works

clipd uses the same binary on both machines:

- On macOS, `clipd` runs as a LaunchAgent and writes received data to the
  system clipboard.
- On the remote machine, `clipd` reads stdin or a file and sends it to the Mac.

Connections use TLS 1.3, a pinned server key, and a shared authentication
token.

## Install

### macOS

Apple Silicon:

```bash
curl -fsSL https://github.com/colefailla/clipd/releases/latest/download/clipd_darwin_arm64 -o clipd
sudo install -m 0755 clipd /usr/local/bin/clipd
rm clipd
```

For Intel Macs, use `clipd_darwin_amd64`.

### Linux

x86-64:

```bash
curl -fsSL https://github.com/colefailla/clipd/releases/latest/download/clipd_linux_amd64 -o clipd
sudo install -m 0755 clipd /usr/local/bin/clipd
rm clipd
```

For ARM64, use `clipd_linux_arm64`.

With Go installed, either platform can also use:

```bash
go install github.com/colefailla/clipd/cmd/clipd@latest
```

Release downloads include `SHA256SUMS`.

## Setup

On the Mac:

```bash
clipd install
```

This creates the configuration and TLS keypair, installs the LaunchAgent, and
prints the token and server fingerprint needed by clients.

On the remote machine:

```bash
clipd configure \
  -server <mac-address> \
  -token '<token>' \
  -fingerprint '<fingerprint>'
```

Then test it:

```bash
echo hello | clipd
```

Run `clipd status` to check the configuration and connection.

## Usage

Copy command output:

```bash
ls -la | clipd
docker ps | clipd
git diff | clipd
```

Copy a file:

```bash
clipd notes.txt
```

Explicitly use the `copy` command:

```bash
clipd copy notes.txt
echo hello | clipd copy
```

Show the number of bytes copied:

```bash
docker ps | clipd -v
```

A successful copy produces no output unless `-v` is used. Errors are written
to stderr.

## Commands

```text
clipd                   Copy stdin
clipd copy [file]       Copy stdin or a file
clipd configure         Configure a client
clipd install           Install the macOS LaunchAgent
clipd uninstall         Remove the macOS LaunchAgent
clipd serve             Run the server in the foreground
clipd setup             Create or inspect server configuration
clipd status            Show configuration and connection status
clipd version           Show version information
clipd help [command]    Show help
```

## Configuration

Configuration is stored at:

```text
macOS:  ~/Library/Application Support/clipd/config.json
Linux:  ~/.config/clipd/config.json
```

`$XDG_CONFIG_HOME` is respected on Linux.

The default port is `8199`. The server listens on `0.0.0.0` by default so
remote machines can reach it.

A LAN IP, `.local` hostname, or Tailscale address can be used as the server
address.

Run:

```bash
clipd help config
clipd help <command>
```

for the config file format and per-command options.

## Security

clipd exposes a network service that can write to your Mac's clipboard. Only
run it on networks you trust or restrict access to it with your firewall.

Connections are encrypted with TLS 1.3. Clients authenticate using a randomly
generated token and verify the server using a pinned public-key fingerprint.

Anyone with the authentication token can write to your clipboard. Treat the
token as a secret.

The token is stored locally in the clipd configuration file, which is created
with user-only permissions. Clipboard contents and authentication tokens are
not logged.

If the server fingerprint changes unexpectedly, do not accept the new
fingerprint without determining why it changed.

## Troubleshooting

**The client hangs, then times out.** Usually the macOS firewall dropping the
connection. Allow incoming connections for clipd in System Settings → Network
→ Firewall → Options.

**`server key fingerprint ... does not match the pinned ...`** The daemon is
presenting a different key. If you rotated it with `clipd setup -rotate-cert`,
re-run `clipd configure -fingerprint`. If you didn't, investigate before
changing anything. `clipd status` shows both fingerprints.

**`this daemon requires TLS`, or `it may be running clipd v1`.** The two
machines are on different versions. Upgrade both.

## Building

Requires Go 1.24 or later.

```bash
make build
make check
make dist
```

clipd has no third-party Go dependencies.

## License

MIT. See [LICENSE](LICENSE).
