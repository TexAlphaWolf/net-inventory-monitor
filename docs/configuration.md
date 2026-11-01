# Configuration

Everything is configured with environment variables, all starting with `NETINV_`. `netinv` also
reads a `.env` file in the current folder (real environment variables win), and Docker Compose
reads the same file. Copy `.env.example` to `.env` to start; the real file is git-ignored.

## Scanning

| Variable | Default | Meaning |
|----------|---------|---------|
| `NETINV_SUBNETS` | *(required)* | Comma-separated IPv4 subnets, e.g. `192.168.1.0/24,10.0.20.0/24` |
| `NETINV_INTERVAL` | `300` | Seconds between scans in `netinv run` (minimum 10) |
| `NETINV_OFFLINE_AFTER` | `3` | Missed scans before a device is reported offline |
| `NETINV_PING_TIMEOUT_MS` | `800` | Wait for a ping reply |
| `NETINV_RETRY_TIMEOUT_MS` | `2500` | Second, more patient ping for silent addresses (`0` = off) |
| `NETINV_WORKERS` | `64` | Parallel pings |
| `NETINV_MAX_HOSTS` | `1024` | Refuse to scan more addresses than this |
| `NETINV_ALLOW_PUBLIC` | `false` | Allow public ranges. Only for networks you own |
| `NETINV_SCANNER` | `ping` | `ping` (system ping + ARP table) or `nmap` |
| `NETINV_RESOLVE_NAMES` | `true` | Reverse-DNS lookup of found devices |

## Discovery extras

| Variable | Default | Meaning |
|----------|---------|---------|
| `NETINV_DISCOVERY` | `true` | Ask devices for their name: SSDP, mDNS, NetBIOS |
| `NETINV_TCP_PORTS` | *(off)* | e.g. `22,80,443`: try these ports on addresses that ignore ping |
| `NETINV_SNMP_COMMUNITY` | *(off)* | Read-only SNMP v2c community, for switches and printers |
| `NETINV_OUI_FILE` | `oui.csv` next to the database | IEEE vendor list, see below |
| `NETINV_CA_BUNDLE` | *(system)* | Extra trusted CAs for `netinv oui-update` |

**Vendor names.** A small table of common vendors is built in. For the full IEEE list run
`netinv oui-update`; if an antivirus or proxy re-signs HTTPS and the download fails, save
<https://standards-oui.ieee.org/oui/oui.csv> from your browser as `data/oui.csv`, or point
`NETINV_CA_BUNDLE` at the extra certificate. Certificate checks are never switched off.

## Storage

| Variable | Default | Meaning |
|----------|---------|---------|
| `NETINV_DB` | `data/netinv.db` | SQLite file |
| `NETINV_RETENTION_DAYS` | `90` | Events and uptime history older than this are deleted (`0` = keep) |

## Web

| Variable | Default | Meaning |
|----------|---------|---------|
| `NETINV_READ_TOKEN` | *(off)* | If set, reading the API needs this bearer token |
| `NETINV_ADMIN_TOKEN` | *(off)* | If set, changes (trust, rename, forget, scan) need it. It also allows reading |
| `NETINV_BIND`, `NETINV_PORT` | `127.0.0.1`, `8090` | Docker only; for native use `netinv run --host --port` |

The dashboard asks for a token when needed and keeps it in `sessionStorage` (gone when the tab
closes).

## Notifications

All optional; with no channel configured nothing is sent. Check them with `netinv notify-test`.

| Variable | Default | Meaning |
|----------|---------|---------|
| `NETINV_NOTIFY_MIN_SEVERITY` | `medium` | `info`, `low`, `medium` or `high` |
| `NETINV_NOTIFY_MAX_PER_MINUTE` | `10` | More are collapsed into one summary message |
| `NETINV_TELEGRAM_TOKEN`, `NETINV_TELEGRAM_CHAT_ID` | | Telegram bot |
| `NETINV_WEBHOOK_URL`, `NETINV_WEBHOOK_TOKEN`, `NETINV_WEBHOOK_FORMAT` | `json` | `json` (Slack, Mattermost...) or `discord` |
| `NETINV_SMTP_HOST`, `_PORT`, `_SECURITY`, `_USER`, `_PASSWORD`, `_FROM`, `_TO` | `587`, `starttls` | Email; `_TO` is comma-separated |

Severity of each change: `ip_takeover` high, `new_device` medium, `ip_changed` and
`device_offline` low, `device_online` info. Offline and online messages are only sent for
devices you `watch`.
