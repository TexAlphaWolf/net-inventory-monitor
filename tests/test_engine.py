from ipaddress import IPv4Network

from conftest import NET, at, host

from netinv.engine import SEVERITY, apply_scan
from netinv.oui import VendorLookup

ROUTER = "a4:2b:b0:11:22:33"
PI = "b8:27:eb:00:00:01"
PHONE = "da:a1:19:00:00:01"
NEW = "00:11:22:33:44:55"


def scan(store, hosts, minute, **kwargs):
    return apply_scan(store, hosts, NET, at(minute), **kwargs)


def baseline(store):
    return scan(store, [host("192.168.1.1", ROUTER), host("192.168.1.10", PI)], 0)


def kinds(changes):
    return [c.kind for c in changes]


def test_first_scan_is_a_trusted_baseline(store):
    changes = baseline(store)
    assert kinds(changes) == ["baseline"]
    assert "2 devices" in changes[0].message
    assert all(d.trusted for d in store.devices())
    assert store.device(PI).vendor == "Raspberry Pi Trading"


def test_empty_first_scan_stays_silent(store):
    assert scan(store, [], 0) == []
    # ... and the next scan with devices is still the baseline.
    assert kinds(scan(store, [host("192.168.1.1", ROUTER)], 5)) == ["baseline"]


def test_new_device_is_untrusted_and_reported(store):
    baseline(store)
    changes = scan(
        store, [host("192.168.1.1", ROUTER), host("192.168.1.10", PI), host("192.168.1.99", NEW)], 5
    )
    assert kinds(changes) == ["new_device"]
    device = store.device(NEW)
    assert not device.trusted and device.first_seen == at(5)
    assert "192.168.1.99" in changes[0].message
    assert kinds(scan(store, [host("192.168.1.99", NEW)], 10)) == []  # reported only once


def test_randomised_mac_is_flagged(store):
    baseline(store)
    changes = scan(store, [host("192.168.1.30", PHONE)], 5)
    assert "randomised MAC" in changes[0].message
    assert store.device(PHONE).randomized


def test_offline_only_after_enough_missed_scans(store):
    baseline(store)
    only_router = [host("192.168.1.1", ROUTER)]
    assert scan(store, only_router, 5) == []
    assert scan(store, only_router, 10) == []
    changes = scan(store, only_router, 15)
    assert kinds(changes) == ["device_offline"]
    assert not store.device(PI).online
    assert scan(store, only_router, 20) == []  # already reported


def test_back_online_resets_the_counter(store):
    baseline(store)
    only_router = [host("192.168.1.1", ROUTER)]
    for minute in (5, 10, 15):
        scan(store, only_router, minute)
    changes = scan(store, [host("192.168.1.1", ROUTER), host("192.168.1.10", PI)], 20)
    assert kinds(changes) == ["device_online"]
    assert store.device(PI).online and store.device(PI).missed == 0


def test_a_short_blip_is_not_reported(store):
    baseline(store)
    scan(store, [host("192.168.1.1", ROUTER)], 5)
    assert scan(store, [host("192.168.1.1", ROUTER), host("192.168.1.10", PI)], 10) == []
    assert store.device(PI).missed == 0


def test_offline_after_can_be_one(store):
    baseline(store)
    assert kinds(scan(store, [host("192.168.1.1", ROUTER)], 5, offline_after=1)) == [
        "device_offline"
    ]


def test_address_change_is_reported(store):
    baseline(store)
    changes = scan(store, [host("192.168.1.1", ROUTER), host("192.168.1.77", PI)], 5)
    assert kinds(changes) == ["ip_changed"]
    assert "192.168.1.10 to 192.168.1.77" in changes[0].message
    assert store.device(PI).ip == "192.168.1.77"


def test_new_device_on_a_trusted_address_is_a_takeover(store):
    baseline(store)
    changes = scan(store, [host("192.168.1.1", ROUTER), host("192.168.1.10", NEW)], 5)
    assert kinds(changes) == ["ip_takeover"]
    assert changes[0].severity == "high"
    assert "address of trusted" in changes[0].message


def test_devices_outside_the_scanned_subnets_are_left_alone(store):
    baseline(store)
    other = [IPv4Network("10.0.20.0/24")]
    for minute in (5, 10, 15, 20):
        apply_scan(store, [], other, at(minute))
    assert store.device(PI).online and store.device(PI).missed == 0


def test_hosts_without_a_mac_are_tracked_by_address(store):
    scan(store, [host("192.168.1.5")], 0)
    assert store.device("ip:192.168.1.5") is not None
    changes = scan(store, [host("192.168.1.5"), host("192.168.1.6")], 5)
    assert kinds(changes) == ["new_device"]


def test_one_mac_on_two_addresses_keeps_the_known_one(store):
    baseline(store)
    both = [host("192.168.1.1", ROUTER), host("192.168.1.10", PI), host("192.168.1.11", PI)]
    assert scan(store, both, 5) == []
    device = store.device(PI)
    assert device.ip == "192.168.1.10" and device.details["other_ips"] == ["192.168.1.11"]
    scan(store, [host("192.168.1.10", PI)], 10)
    assert "other_ips" not in store.device(PI).details


def test_new_mac_with_two_addresses(store):
    baseline(store)
    scan(store, [host("192.168.1.50", NEW), host("192.168.1.51", NEW)], 5)
    assert store.device(NEW).details["other_ips"] == ["192.168.1.51"]


def test_hostname_and_vendor_are_filled_in_later(store):
    scan(store, [host("192.168.1.10", PI)], 0, vendors=VendorLookup())
    device = store.device(PI)
    device.vendor = None
    store.save(device)
    scan(store, [host("192.168.1.10", PI, hostname="pi.lan", latency_ms=2.5)], 5)
    device = store.device(PI)
    assert device.hostname == "pi.lan" and device.vendor == "Raspberry Pi Trading"
    assert device.latency_ms == 2.5 and device.name == "pi.lan"


def test_events_and_uptime_are_recorded(store):
    baseline(store)
    only_router = [host("192.168.1.1", ROUTER)]
    for minute in (5, 10, 15):
        scan(store, only_router, minute)
    assert [e.kind for e in store.events(limit=10)] == ["device_offline", "baseline"]
    uptime = store.uptime(at(20))
    assert uptime[ROUTER] == 100.0 and uptime[PI] == 25.0  # up in 1 of 4 scans


def test_every_kind_has_a_severity():
    assert set(SEVERITY.values()) <= {"info", "low", "medium", "high"}
