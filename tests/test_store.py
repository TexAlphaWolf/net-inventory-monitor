import sqlite3
from contextlib import closing
from datetime import timedelta

from conftest import T0, at

from netinv.store import MIGRATIONS, Device, Event, Store


def device(**kwargs):
    base = dict(
        id="aa:bb:cc:dd:ee:01",
        mac="aa:bb:cc:dd:ee:01",
        ip="192.168.1.5",
        first_seen=T0,
        last_seen=T0,
    )
    return Device(**{**base, **kwargs})


def test_new_database_is_migrated(store):
    assert store.schema_version() == len(MIGRATIONS)
    Store(store.path)  # opening again changes nothing
    assert store.schema_version() == len(MIGRATIONS)


def test_save_and_load_round_trip(store):
    store.save(
        device(
            hostname="pi",
            vendor="Raspberry",
            label="Pi",
            trusted=True,
            details={"ports": [22]},
            latency_ms=1.5,
        )
    )
    loaded = store.device("aa:bb:cc:dd:ee:01")
    assert loaded.hostname == "pi" and loaded.trusted and loaded.details == {"ports": [22]}
    assert loaded.as_dict()["first_seen"] == "2026-11-01T12:00:00Z"
    assert store.device("nope") is None


def test_devices_are_sorted_by_address_numerically(store):
    for n, ip in enumerate(["192.168.1.100", "192.168.1.9", "192.168.1.20"]):
        store.save(device(id=f"id{n}", mac=None, ip=ip))
    assert [d.ip for d in store.devices()] == ["192.168.1.9", "192.168.1.20", "192.168.1.100"]


def test_find_by_mac_ip_or_label(store):
    store.save(device(label="NAS"))
    for text in ("aa:bb:cc:dd:ee:01", "192.168.1.5", "nas", "  NAS "):
        assert store.find(text).id == "aa:bb:cc:dd:ee:01"
    assert store.find("missing") is None


def test_update_flags_and_forget(store):
    store.save(device())
    assert store.update_flags("aa:bb:cc:dd:ee:01", trusted=True, watched=True, label="Server")
    d = store.device("aa:bb:cc:dd:ee:01")
    assert d.trusted and d.watched and d.label == "Server" and d.name == "Server"
    assert store.update_flags(d.id, clear_label=True)
    assert store.device(d.id).label is None
    assert not store.update_flags("missing", trusted=True)
    store.add_probes(T0, [(d.id, True, 1.0)])
    assert store.forget(d.id) and not store.forget(d.id)
    assert store.history(d.id) == []


def test_name_falls_back(store):
    assert device(hostname="h").name == "h"
    assert device(vendor="V").name == "V"
    assert device().name == "aa:bb:cc:dd:ee:01"
    assert device(mac=None).name == "192.168.1.5"


def test_events_filter_and_limit(store):
    store.add_events([Event("new_device", f"m{i}", at(i), ip="192.168.1.5") for i in range(5)])
    store.add_events([Event("device_offline", "gone", at(9))])
    assert [e.message for e in store.events(limit=2)] == ["gone", "m4"]
    assert len(store.events(kind="new_device", limit=100)) == 5
    assert store.events(limit=0)[0].as_dict()["kind"] == "device_offline"


def test_uptime_window_and_history(store):
    store.add_probes(T0 - timedelta(hours=30), [("a", False, None)])
    store.add_probes(T0 - timedelta(hours=1), [("a", True, 2.0)])
    store.add_probes(T0, [("a", False, None)])
    assert store.uptime(T0, hours=24) == {"a": 50.0}
    assert store.uptime(T0, hours=48) == {"a": 33.3}
    assert store.history("a", limit=2) == [
        ("2026-11-01T11:00:00Z", True, 2.0),
        ("2026-11-01T12:00:00Z", False, None),
    ]


def test_purge(store):
    store.add_events([Event("x", "old", at(-60 * 48)), Event("x", "new", at(0))])
    store.add_probes(at(-60 * 48), [("a", True, 1.0)])
    store.add_probes(at(0), [("a", True, 1.0)])
    assert store.purge(at(-60 * 24)) == (1, 1)
    assert [e.message for e in store.events()] == ["new"]


def test_a_failed_write_is_rolled_back(store):
    try:
        with store._connect() as db:
            db.execute("INSERT INTO events (ts, kind, message) VALUES ('t', 'k', 'm')")
            raise RuntimeError
    except RuntimeError:
        pass
    assert store.events() == []


def test_wal_mode_and_file_created(tmp_path):
    target = tmp_path / "nested" / "dir" / "inv.db"
    Store(target)
    with closing(sqlite3.connect(target)) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
