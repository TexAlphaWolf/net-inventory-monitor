from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import IPv4Network

import pytest

from netinv.scanner import Host
from netinv.store import Store

T0 = datetime(2026, 11, 1, 12, 0, 0)
NET = [IPv4Network("192.168.1.0/24")]


def at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


def host(ip: str, mac: str | None = None, **kwargs: object) -> Host:
    return Host(ip=ip, mac=mac, responded=True, **kwargs)  # type: ignore[arg-type]


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "test.db")


class FakeScanner:
    """Returns whatever hosts the test sets."""

    def __init__(self, hosts=None):
        self.hosts = hosts or []
        self.calls = 0

    def scan(self, networks):
        self.calls += 1
        return list(self.hosts)
