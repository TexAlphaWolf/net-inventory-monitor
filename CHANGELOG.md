# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] - 2026-11-01

### Added
- Scanner: ping sweep, ARP table (Windows, Linux) and reverse DNS, with no root and no extra tools
- SQLite inventory with change detection: new devices, devices offline or back, moved addresses,
  and a new device taking the address of a trusted one
- The first scan is a trusted baseline, so a fresh install does not report the whole network
- Vendor names from a bundled table or the IEEE registry (`netinv oui-update`)
- Command line: `scan`, `devices`, `events`, `trust`, `watch`, `label`, `forget`
- Safety checks: private ranges only, and a cap on the number of addresses
- A second, more patient ping for silent addresses (phones in power-save); this machine is listed
  with its own MAC address
- Dashboard (`netinv run`): devices, uptime, change history, trust / watch / rename / forget,
  "Scan now", CSV and JSON export
- Scans on a schedule, with a lock so two scans never overlap, and retention of old history
- Notifications to Telegram, a webhook and email, with severity filter and rate limit;
  `netinv notify-test`
- Optional read and admin tokens for the API
- Discovery of devices that ignore ping: SSDP announcements, and optional TCP probes
  (`NETINV_TCP_PORTS`)
- Names and descriptions asked from the device itself: mDNS, NetBIOS, SNMP v2c (opt-in)
- Optional nmap scanner (`NETINV_SCANNER=nmap`), including the vendor it reports
- `netinv` reads a `.env` file in the current folder, like Docker Compose does
- `NETINV_CA_BUNDLE` for `oui-update` behind an antivirus or proxy that re-signs HTTPS
- Animated demo and documentation: configuration, architecture, security policy
- Docker image and Compose file with host networking and a hardened container
