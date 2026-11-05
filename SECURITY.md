# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private reporting instead: open the **Security** tab of this repository and choose **Report a vulnerability**.

Include what you found, how to reproduce it, and which version you tested. Do not include real private keys or server addresses.

## Supported versions

Only the latest release gets fixes.

## What counts

Examples we want to hear about: traffic leaking outside the tunnel or kill switch, secrets stored unencrypted, the local SOCKS5 proxy reachable from other devices or apps, crashes triggered by a crafted config or QR code.

How the module routes traffic and stores keys is described in [docs/SECURITY.md](docs/SECURITY.md).
