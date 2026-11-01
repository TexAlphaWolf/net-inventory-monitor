# Security policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting: open
the **Security** tab of this repository and choose **Report a vulnerability**. Include what you
found, how to reproduce it and the version you tested. This is a personal project, so I answer on
a best-effort basis, usually within a week.

## What is in scope

netinv talks to devices on your network, and what they answer is not trustworthy. The most
interesting reports are about:

- **The network parsers** (DNS/mDNS, NetBIOS, SNMP, SSDP, nmap XML, `arp` output): input that
  crashes them, hangs them or makes them read out of bounds.
- **The dashboard and API**: cross-site scripting through a device name, injection,
  authentication bypass, request forgery, denial of service.
- **The export**: spreadsheet formula injection through device names.
- **The Docker setup**: ways to escape the container hardening or leak secrets.

## Design choices that matter

- **Only private ranges are scanned** (public ones need `NETINV_ALLOW_PUBLIC`), and the number of
  addresses is capped, so a typo cannot turn the tool into a scanner of other people's networks.
- **Device names are hostile.** The dashboard writes them with `textContent`, never as HTML (a
  test fails the build if forbidden DOM APIs appear), a strict Content-Security-Policy is sent,
  notification messages are plain text with control characters removed, and CSV cells that begin
  with `=`, `+`, `-` or `@` are prefixed so a spreadsheet does not run them.
- **Replies are checked.** UDP answers are accepted only from the address that was asked, with
  sizes and offsets validated.
- **Certificates are always verified**, including for `oui-update`.
- **Tokens** are compared in constant time. The dashboard keeps its token in `sessionStorage`.
  Without `NETINV_ADMIN_TOKEN` anyone who can reach the port can change the inventory, so the
  default bind address is `127.0.0.1`; put a reverse proxy with TLS in front before exposing it.
- **Notification errors** are logged without URLs or credentials, and webhooks do not follow
  redirects.
- **Secrets stay out of git**: `.env` and the database are ignored, and the real subnet lives only
  in your local `.env`.
- **Container**: non-root user, read-only filesystem, all capabilities dropped except `NET_RAW`
  for `ping`.
- CI runs CodeQL and `pip-audit`, and Dependabot proposes dependency updates.

## Known limitations (not vulnerabilities)

See "Known limitations" in [docs/architecture.md](docs/architecture.md): MAC addresses can be
forged, and the API has shared tokens rather than users.
