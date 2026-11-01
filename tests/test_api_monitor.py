from __future__ import annotations

import threading
from ipaddress import IPv4Network
from pathlib import Path

import pytest
from conftest import FakeScanner, host
from fastapi.testclient import TestClient

from netinv.api import STATIC, create_app
from netinv.config import NotifySettings, Settings
from netinv.monitor import Monitor
from netinv.notify import Notifier
from netinv.scanner import ScanError
from netinv.store import Store

ROUTER = "a4:2b:b0:11:22:33"
NEW = "00:11:22:33:44:55"


def settings(tmp_path: Path, **kwargs) -> Settings:
    return Settings(subnets=[IPv4Network("192.168.1.0/24")], db_path=tmp_path / "t.db", **kwargs)


class Channel:
    name = "fake"

    def __init__(self):
        self.sent = []

    def send(self, subject, body, alert):
        self.sent.append(subject)


@pytest.fixture
def parts(tmp_path):
    cfg = settings(tmp_path)
    store = Store(cfg.db_path)
    scanner = FakeScanner([host("192.168.1.1", ROUTER, hostname="router.lan")])
    channel = Channel()
    notifier = Notifier([channel], NotifySettings(min_severity="info"))
    monitor = Monitor(cfg, store, scanner, notifier)
    return cfg, store, scanner, monitor, channel, notifier


def client_for(parts, **kwargs):
    cfg, store, _, monitor, *_ = parts
    return TestClient(create_app(cfg, store, monitor, run_scheduler=False, **kwargs))


# ---------------------------------------------------------------------------------- monitor


def test_scan_now_updates_the_status(parts):
    cfg, store, scanner, monitor, channel, notifier = parts
    changes = monitor.scan_now()
    assert [c.kind for c in changes] == ["baseline"]
    assert monitor.status.scans == 1 and monitor.status.last_error is None
    assert monitor.status.last_changes == 1 and not monitor.status.running
    notifier.deliver(changes[0])  # baseline is filtered by submit, but delivery itself works
    assert store.device(ROUTER) is not None


def test_a_failing_scan_is_reported_not_raised(parts):
    monitor = parts[3]

    def boom(networks):
        raise ScanError("no ping")

    monitor.scanner.scan = boom
    assert monitor.scan_now() == []
    assert "no ping" in monitor.status.last_error
    assert monitor.status.scans == 1 and not monitor.status.running


def test_only_one_scan_at_a_time(parts):
    monitor = parts[3]
    inside, release = threading.Event(), threading.Event()
    original = monitor.scanner.scan

    def slow(networks):
        inside.set()
        release.wait(5)
        return original(networks)

    monitor.scanner.scan = slow
    worker = threading.Thread(target=monitor.scan_now)
    worker.start()
    assert inside.wait(5)
    assert monitor.scan_now() is None  # busy
    release.set()
    worker.join(5)
    assert monitor.status.scans == 1


def test_changes_are_sent_to_the_notifier(parts):
    cfg, store, scanner, monitor, channel, notifier = parts
    monitor.scan_now()
    scanner.hosts = [host("192.168.1.1", ROUTER), host("192.168.1.9", NEW)]
    monitor.scan_now()
    while not notifier._queue.empty():
        notifier.deliver(notifier._queue.get_nowait())
    assert any("New device" in s for s in channel.sent)


def test_retention_runs_after_a_scan(parts):
    cfg, store, scanner, monitor, *_ = parts
    from datetime import timedelta

    from netinv.service import utcnow
    from netinv.store import Event

    store.add_events([Event("new_device", "ancient", utcnow() - timedelta(days=400))])
    monitor.settings = Settings(subnets=cfg.subnets, db_path=cfg.db_path, retention_days=30)
    monitor.scan_now()
    assert "ancient" not in [e.message for e in store.events(limit=100)]


def test_scheduler_thread_scans_and_stops(parts):
    cfg, store, scanner, monitor, *_ = parts
    monitor.start()
    for _ in range(100):
        if monitor.status.scans:
            break
        threading.Event().wait(0.05)
    monitor.stop()
    assert monitor.status.scans >= 1
    Monitor(cfg, store, scanner).stop()  # never started


# --------------------------------------------------------------------------------- the API


def test_dashboard_and_headers(parts):
    client = client_for(parts)
    page = client.get("/")
    assert page.status_code == 200 and "netinv" in page.text
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-content-type-options"] == "nosniff"
    assert client.get("/dashboard.js").headers["content-type"].startswith("text/javascript")
    assert client.get("/dashboard.css").headers["content-type"].startswith("text/css")
    assert client.get("/health").json()["status"] == "ok"


def test_dashboard_never_renders_network_data_as_html():
    js = (STATIC / "dashboard.js").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert forbidden not in js


def test_hidden_attribute_is_not_overridden_by_css():
    css = (STATIC / "dashboard.css").read_text(encoding="utf-8")
    assert "[hidden] { display: none !important; }" in css


def test_devices_stats_events(parts):
    monitor = parts[3]
    monitor.scan_now()
    monitor.scanner.hosts = [host("192.168.1.1", ROUTER), host("192.168.1.9", NEW)]
    monitor.scan_now()
    client = client_for(parts)
    devices = client.get("/api/devices").json()
    assert [d["ip"] for d in devices] == ["192.168.1.1", "192.168.1.9"]
    assert devices[0]["uptime_24h"] == 100.0 and devices[0]["hostname"] == "router.lan"
    assert [d["ip"] for d in client.get("/api/devices?unknown=true").json()] == ["192.168.1.9"]
    stats = client.get("/api/stats").json()
    assert (stats["devices"], stats["online"], stats["unknown"]) == (2, 2, 1)
    assert stats["events_24h"] == 2 and stats["subnets"] == ["192.168.1.0/24"]
    events = client.get("/api/events?kind=new_device").json()
    assert len(events) == 1 and events[0]["kind"] == "new_device"
    assert client.get("/api/events?kind=bogus").status_code == 422
    history = client.get(f"/api/devices/{ROUTER}/history").json()
    assert len(history) == 2 and history[0]["up"] is True
    assert client.get("/api/devices/nope/history").status_code == 404


def test_change_a_device(parts):
    parts[3].scan_now()
    client = client_for(parts)
    url = f"/api/devices/{ROUTER}"
    result = client.patch(url, json={"trusted": False, "watched": True, "label": "  Router  "})
    assert result.status_code == 200
    body = result.json()
    assert body["label"] == "Router" and body["watched"] and not body["trusted"]
    assert client.patch(url, json={"label": ""}).json()["label"] is None
    assert client.patch(url, json={"label": "x" * 61}).status_code == 422
    assert client.patch("/api/devices/nope", json={"trusted": True}).status_code == 404
    assert client.delete(url).status_code == 204
    assert client.delete(url).status_code == 404


def test_scan_endpoint(parts):
    client = client_for(parts)
    result = client.post("/api/scan")
    assert result.status_code == 200 and result.json()["changes"][0]["kind"] == "baseline"
    parts[3]._lock.acquire()
    try:
        assert client.post("/api/scan").status_code == 409
    finally:
        parts[3]._lock.release()


def test_export_csv_and_json_are_safe(parts):
    monitor = parts[3]
    monitor.scanner.hosts = [host("192.168.1.5", NEW, hostname="=HYPERLINK(1)")]
    monitor.scan_now()
    client = client_for(parts)
    csv_text = client.get("/api/export").text
    assert csv_text.splitlines()[0].startswith("ip,mac,name")
    assert "'=HYPERLINK(1)" in csv_text  # a spreadsheet must not run it
    assert client.get("/api/export").headers["content-disposition"].startswith("attachment")
    assert client.get("/api/export?format=json").json()[0]["ip"] == "192.168.1.5"
    assert client.get("/api/export?format=xml").status_code == 422


def test_read_and_admin_tokens(parts):
    parts[3].scan_now()
    client = client_for(parts, read_token="reader", admin_token="boss")
    assert client.get("/api/devices").status_code == 401
    assert client.get("/api/devices", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/devices", headers={"Authorization": "Basic reader"}).status_code == 401
    reader = {"Authorization": "Bearer reader"}
    boss = {"Authorization": "Bearer boss"}
    assert client.get("/api/devices", headers=reader).status_code == 200
    assert client.get("/api/devices", headers=boss).status_code == 200
    url = f"/api/devices/{ROUTER}"
    assert client.patch(url, json={"trusted": True}, headers=reader).status_code == 401
    assert client.patch(url, json={"trusted": True}).status_code == 401
    assert client.patch(url, json={"trusted": True}, headers=boss).status_code == 200
    assert client.post("/api/scan", headers=reader).status_code == 401
    assert client.get("/health").status_code == 200  # liveness stays open
    assert client.get("/").status_code == 200  # the page asks for the token itself


def test_admin_only_protection_leaves_reading_open(parts):
    client = client_for(parts, admin_token="boss")
    assert client.get("/api/devices").status_code == 200
    assert client.post("/api/scan").status_code == 401


def test_app_lifespan_starts_and_stops_everything(parts):
    cfg, store, scanner, monitor, channel, notifier = parts
    app = create_app(cfg, store, monitor, run_scheduler=True)
    with TestClient(app) as client:
        for _ in range(100):
            if monitor.status.scans:
                break
            threading.Event().wait(0.05)
        assert client.get("/health").json()["scans"] >= 1
    assert notifier._thread is not None and not notifier._thread.is_alive()


def test_app_builds_its_own_monitor(tmp_path):
    cfg = settings(tmp_path, notify=NotifySettings(webhook_url="https://hooks.example/x"))
    app = create_app(cfg, Store(cfg.db_path), run_scheduler=False)
    with TestClient(app) as client:
        assert client.get("/api/stats").json()["notifications"] == ["webhook"]
