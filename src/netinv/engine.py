"""Turning a scan into changes: new devices, devices going offline or online, moved addresses.

The first scan of an empty database is a *baseline*: everything found is trusted and nothing is
reported, otherwise a fresh install would announce your whole network as an intrusion.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Network

from .net import in_networks
from .oui import VendorLookup, is_randomized
from .scanner import Host
from .store import Device, Event, Store

# How serious each kind of change is, for notification filters and the dashboard.
SEVERITY = {
    "new_device": "medium",
    "ip_takeover": "high",
    "ip_changed": "low",
    "device_offline": "low",
    "device_online": "info",
    "baseline": "info",
}
KINDS = tuple(SEVERITY)


@dataclass
class Change:
    kind: str
    device: Device
    message: str
    ts: datetime

    @property
    def severity(self) -> str:
        return SEVERITY[self.kind]

    def as_event(self) -> Event:
        return Event(
            kind=self.kind,
            message=self.message,
            ts=self.ts,
            device_id=self.device.id,
            ip=self.device.ip,
        )


def _describe(device: Device) -> str:
    parts = [device.ip]
    if device.mac:
        parts.append(device.mac)
    if device.vendor:
        parts.append(device.vendor)
    elif device.randomized:
        parts.append("randomised MAC")
    return " / ".join(parts)


def apply_scan(
    store: Store,
    hosts: list[Host],
    networks: list[IPv4Network],
    now: datetime,
    *,
    vendors: VendorLookup | None = None,
    offline_after: int = 3,
) -> list[Change]:
    """Compare `hosts` with what is stored, save the result and return what changed."""
    vendors = vendors or VendorLookup()
    known = {d.id: d for d in store.devices()}
    baseline = not known
    changes: list[Change] = []
    seen: set[str] = set()
    probes: list[tuple[str, bool, float | None]] = []

    # One device may answer on several addresses (same MAC): keep the address we already know.
    by_id: dict[str, list[Host]] = {}
    for host in hosts:
        by_id.setdefault(host.device_id, []).append(host)

    for device_id, group in by_id.items():
        previous = known.get(device_id)
        host = _primary(group, previous.ip if previous else None)
        seen.add(device_id)
        extra_ips = sorted(h.ip for h in group if h is not host)
        if previous is None:
            device = _new_device(host, now, vendors, trusted=baseline)
            if extra_ips:
                device.details["other_ips"] = extra_ips
            if not baseline:
                changes.append(_new_device_change(device, known.values(), now))
        else:
            device = previous
            if device.ip != host.ip:
                changes.append(
                    Change(
                        "ip_changed",
                        device,
                        f"{device.name} moved from {device.ip} to {host.ip}",
                        now,
                    )
                )
                device.ip = host.ip
            if not device.online:
                changes.append(
                    Change(
                        "device_online", device, f"{device.name} ({device.ip}) is back online", now
                    )
                )
            device.online = True
            device.missed = 0
            device.hostname = host.hostname or device.hostname
            device.latency_ms = host.latency_ms
            device.last_seen = now
            if device.mac and not device.vendor:
                device.vendor = vendors.vendor(device.mac) or host.details.get("vendor_hint")
            device.details.update(
                {k: v for k, v in host.details.items() if k not in ("vendor_hint", "other_ips")}
            )
            if extra_ips:
                device.details["other_ips"] = extra_ips
            else:
                device.details.pop("other_ips", None)
        probes.append((device.id, True, host.latency_ms))
        store.save(device)

    # Devices of the scanned networks that did not show up this time.
    for device_id, device in known.items():
        if device_id in seen or not in_networks(device.ip, networks):
            continue
        device.missed += 1
        if device.online and device.missed >= offline_after:
            device.online = False
            changes.append(
                Change("device_offline", device, f"{device.name} ({device.ip}) went offline", now)
            )
        probes.append((device.id, False, None))
        store.save(device)

    if baseline and hosts:
        first = store.device(hosts[0].device_id)
        assert first is not None
        message = f"First scan: {len(by_id)} devices found and trusted as the baseline"
        changes.append(Change("baseline", first, message, now))
    store.add_probes(now, probes)
    store.add_events([c.as_event() for c in changes])
    return changes


def _primary(group: list[Host], known_ip: str | None) -> Host:
    for host in group:
        if host.ip == known_ip:
            return host
    return sorted(group, key=lambda h: (not h.responded, tuple(map(int, h.ip.split(".")))))[0]


def _new_device(host: Host, now: datetime, vendors: VendorLookup, *, trusted: bool) -> Device:
    return Device(
        id=host.device_id,
        ip=host.ip,
        mac=host.mac,
        hostname=host.hostname,
        vendor=(vendors.vendor(host.mac) if host.mac else None)
        or host.details.pop("vendor_hint", None),
        randomized=is_randomized(host.mac) if host.mac else False,
        trusted=trusted,
        first_seen=now,
        last_seen=now,
        latency_ms=host.latency_ms,
        details=dict(host.details),
    )


def _new_device_change(device: Device, known: Iterable[Device], now: datetime) -> Change:
    """A new device; worse if it just took the address of a trusted device that is still around."""
    for other in known:
        if other.ip == device.ip and other.trusted and other.id != device.id and other.online:
            return Change(
                "ip_takeover",
                device,
                f"New device {_describe(device)} answers on {device.ip}, the address of trusted "
                f"{other.name} (possible address conflict or spoofing)",
                now,
            )
    return Change("new_device", device, f"New device: {_describe(device)}", now)
