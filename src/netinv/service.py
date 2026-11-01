"""One scan cycle: scan, compare with the inventory, store, report."""

from __future__ import annotations

from datetime import UTC, datetime

from .config import Settings
from .engine import Change, apply_scan
from .nmap import NmapScanner
from .oui import VendorLookup
from .scanner import PingArpScanner, Scanner, make_enricher, make_ssdp
from .store import Store


def utcnow() -> datetime:
    """Naive UTC time without microseconds: the format used everywhere in the database."""
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def build_scanner(settings: Settings) -> Scanner:
    if settings.scanner == "nmap":
        return NmapScanner()
    return PingArpScanner(
        tcp_ports=list(settings.tcp_ports),
        ssdp=make_ssdp() if settings.discovery else None,
        enrich=make_enricher(settings.snmp_community) if settings.discovery else None,
        timeout_ms=settings.ping_timeout_ms,
        retry_timeout_ms=settings.retry_timeout_ms,
        workers=settings.workers,
        resolve_names=settings.resolve_names,
    )


def scan_once(
    settings: Settings,
    store: Store,
    scanner: Scanner | None = None,
    vendors: VendorLookup | None = None,
    now: datetime | None = None,
) -> list[Change]:
    scanner = scanner or build_scanner(settings)
    vendors = vendors or VendorLookup(settings.oui_file)
    hosts = scanner.scan(settings.subnets)
    return apply_scan(
        store,
        hosts,
        settings.subnets,
        now or utcnow(),
        vendors=vendors,
        offline_after=settings.offline_after,
    )
