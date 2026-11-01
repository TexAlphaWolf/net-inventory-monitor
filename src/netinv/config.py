"""Runtime configuration, read from environment variables (all prefixed with NETINV_)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from pathlib import Path

from .net import SubnetError, parse_subnets
from .probes import parse_ports


class ConfigError(ValueError):
    """A setting is missing or invalid."""


@dataclass(frozen=True)
class NotifySettings:
    """Where messages are sent. Every channel is optional; with none set, nothing is sent."""

    min_severity: str = "medium"
    max_per_minute: int = 10
    telegram_token: str | None = None
    telegram_chat_id: str | None = None
    webhook_url: str | None = None
    webhook_token: str | None = None
    webhook_format: str = "json"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_to: tuple[str, ...] = ()


@dataclass(frozen=True)
class Settings:
    subnets: list[IPv4Network]
    db_path: Path
    interval: int = 300
    offline_after: int = 3
    ping_timeout_ms: int = 800
    retry_timeout_ms: int = 2500
    workers: int = 64
    resolve_names: bool = True
    oui_file: Path | None = None
    notify: NotifySettings = field(default_factory=NotifySettings)
    retention_days: int = 90
    scanner: str = "ping"
    tcp_ports: tuple[int, ...] = ()
    discovery: bool = True
    snmp_community: str | None = None
    ca_bundle: Path | None = None
    read_token: str | None = None
    admin_token: str | None = None


def _whole_number(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip() or str(default)
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return value


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be true or false, got {raw!r}")


def _scanner_name() -> str:
    name = (os.environ.get("NETINV_SCANNER", "").strip() or "ping").lower()
    if name not in ("ping", "nmap"):
        raise ConfigError(f"NETINV_SCANNER must be ping or nmap, got {name!r}")
    return name


def _tcp_ports() -> tuple[int, ...]:
    try:
        return tuple(parse_ports(os.environ.get("NETINV_TCP_PORTS", "")))
    except ValueError as exc:
        raise ConfigError(f"NETINV_TCP_PORTS: {exc}") from None


def load_env_file(path: Path = Path(".env")) -> bool:
    """Read KEY=VALUE lines from `path` into the environment (real variables win).

    Docker Compose reads .env by itself; this lets `netinv` run natively with the same file.
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if value[:1] in ("'", '"') and (close := value.find(value[0], 1)) > 0:
            value = value[1:close]  # quoted: anything after the closing quote is a comment
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        os.environ.setdefault(key.strip(), value)
    return True


def _text(name: str) -> str | None:
    return os.environ.get(name, "").strip() or None


def _notify_settings() -> NotifySettings:
    recipients = tuple(
        item.strip() for item in os.environ.get("NETINV_SMTP_TO", "").split(",") if item.strip()
    )
    return NotifySettings(
        min_severity=(_text("NETINV_NOTIFY_MIN_SEVERITY") or "medium").lower(),
        max_per_minute=_whole_number("NETINV_NOTIFY_MAX_PER_MINUTE", 10, minimum=1),
        telegram_token=_text("NETINV_TELEGRAM_TOKEN"),
        telegram_chat_id=_text("NETINV_TELEGRAM_CHAT_ID"),
        webhook_url=_text("NETINV_WEBHOOK_URL"),
        webhook_token=_text("NETINV_WEBHOOK_TOKEN"),
        webhook_format=(_text("NETINV_WEBHOOK_FORMAT") or "json").lower(),
        smtp_host=_text("NETINV_SMTP_HOST"),
        smtp_port=_whole_number("NETINV_SMTP_PORT", 587, minimum=1),
        smtp_security=(_text("NETINV_SMTP_SECURITY") or "starttls").lower(),
        smtp_user=_text("NETINV_SMTP_USER"),
        smtp_password=_text("NETINV_SMTP_PASSWORD"),
        smtp_from=_text("NETINV_SMTP_FROM"),
        smtp_to=recipients,
    )


def load_db_path() -> Path:
    """The database path alone, for commands that do not scan and need no subnet."""
    return Path(os.environ.get("NETINV_DB", "").strip() or "data/netinv.db")


def load_settings() -> Settings:
    """Build settings from the environment.

    NETINV_SUBNETS          comma-separated IPv4 subnets to scan (required), e.g. 192.168.1.0/24
    NETINV_DB               SQLite file (default: data/netinv.db)
    NETINV_INTERVAL         seconds between scans in `netinv run` (default 300)
    NETINV_OFFLINE_AFTER    missed scans before a device is reported offline (default 3)
    NETINV_PING_TIMEOUT_MS  how long to wait for a ping reply (default 800)
    NETINV_RETRY_TIMEOUT_MS second, more patient ping for silent addresses (default 2500; 0 = off)
    NETINV_WORKERS          parallel pings (default 64)
    NETINV_MAX_HOSTS        refuse to scan more addresses than this (default 1024)
    NETINV_ALLOW_PUBLIC     allow public address ranges (default false; own networks only)
    NETINV_SCANNER          ping (default) or nmap (needs the nmap program)
    NETINV_DISCOVERY        also ask devices for their name: SSDP, mDNS, NetBIOS (default true)
    NETINV_TCP_PORTS        e.g. 22,80,443: try these ports on addresses that ignore ping (off)
    NETINV_SNMP_COMMUNITY   read-only SNMP v2c community to learn device names (off)
    NETINV_CA_BUNDLE        PEM file with extra trusted CAs for `oui-update`
    NETINV_RESOLVE_NAMES    reverse-DNS lookups for found devices (default true)
    NETINV_RETENTION_DAYS   delete events and uptime history older than this (default 90; 0 = keep)
    NETINV_READ_TOKEN       if set, reading the API needs this bearer token (or the admin token)
    NETINV_ADMIN_TOKEN      if set, changing anything (trust, rename, scan, forget) needs it
    NETINV_NOTIFY_*, NETINV_TELEGRAM_*, NETINV_WEBHOOK_*, NETINV_SMTP_*
                            notification channels: see docs/configuration.md
    NETINV_OUI_FILE         IEEE oui.csv for vendor names (default: oui.csv next to the database)
    """
    try:
        subnets = parse_subnets(
            os.environ.get("NETINV_SUBNETS", ""),
            max_hosts=_whole_number("NETINV_MAX_HOSTS", 1024, minimum=1),
            allow_public=_flag("NETINV_ALLOW_PUBLIC", False),
        )
    except SubnetError as exc:
        raise ConfigError(str(exc)) from None
    db_path = load_db_path()
    oui = os.environ.get("NETINV_OUI_FILE", "").strip()
    if not oui and (downloaded := db_path.parent / "oui.csv").exists():
        oui = str(downloaded)  # the file `netinv oui-update` saves next to the database
    return Settings(
        subnets=subnets,
        db_path=db_path,
        interval=_whole_number("NETINV_INTERVAL", 300, minimum=10),
        offline_after=_whole_number("NETINV_OFFLINE_AFTER", 3, minimum=1),
        ping_timeout_ms=_whole_number("NETINV_PING_TIMEOUT_MS", 800, minimum=100),
        retry_timeout_ms=_whole_number("NETINV_RETRY_TIMEOUT_MS", 2500),
        workers=_whole_number("NETINV_WORKERS", 64, minimum=1),
        resolve_names=_flag("NETINV_RESOLVE_NAMES", True),
        oui_file=Path(oui) if oui else None,
        notify=_notify_settings(),
        retention_days=_whole_number("NETINV_RETENTION_DAYS", 90),
        scanner=_scanner_name(),
        tcp_ports=_tcp_ports(),
        discovery=_flag("NETINV_DISCOVERY", True),
        snmp_community=_text("NETINV_SNMP_COMMUNITY"),
        ca_bundle=Path(ca) if (ca := _text("NETINV_CA_BUNDLE")) else None,
        read_token=_text("NETINV_READ_TOKEN"),
        admin_token=_text("NETINV_ADMIN_TOKEN"),
    )
