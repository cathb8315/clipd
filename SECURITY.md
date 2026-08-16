# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through GitHub's
[report a vulnerability](https://github.com/colefailla/clipd/security/advisories/new)
form, rather than opening a public issue.

Useful things to include: the clipd version (`clipd version`), both operating
systems involved, and the shortest sequence of steps that shows the problem.

This is a personal project maintained by one person, so there is no response
time commitment, and fixes go onto `main` and into the next tagged release
rather than being backported.

## Out of scope

Holding the authentication token is not an escalation. It is the intended
grant, and it authorises writing to the clipboard. The same goes for anyone
with the daemon's private key or a shell on either machine: those files are
protected by filesystem permissions and nothing more.

See the README's security section for what clipd does and does not defend
against.
