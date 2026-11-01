import subprocess
from ipaddress import IPv4Network

import pytest

from netinv import scanner
from netinv.scanner import (
    Host,
    PingArpScanner,
    ScanError,
    clean_name,
    local_addresses,
    merge_hosts,
    parse_ip_neigh,
    parse_local_addresses,
    parse_proc_arp,
    parse_windows_arp,
    ping_command,
    ping_once,
    read_arp_table,
)

# Italian Windows: the column titles and the "dinamico"/"statico" words differ, the layout does not.
WINDOWS_ARP = """
Interfaccia: 192.168.1.51 --- 0x10
  Indirizzo Internet    Indirizzo fisico      Tipo
  192.168.1.1           a4-2b-b0-11-22-33     dinamico
  192.168.1.20          da-a1-19-00-00-01     dinamico
  192.168.1.255         ff-ff-ff-ff-ff-ff     statico
  224.0.0.22            01-00-5e-00-00-16     statico

Interfaccia: 172.20.0.1 --- 0x1f
  Indirizzo Internet    Indirizzo fisico      Tipo
  172.20.0.5            00-15-5d-aa-bb-cc     dinamico
"""

IP_NEIGH = """\
192.168.1.1 dev eth0 lladdr a4:2b:b0:11:22:33 REACHABLE
192.168.1.20 dev eth0 lladdr da:a1:19:00:00:01 STALE
192.168.1.30 dev eth0  FAILED
192.168.1.31 dev eth0 lladdr 00:00:00:00:00:00 INCOMPLETE
fe80::1 dev eth0 lladdr a4:2b:b0:11:22:33 router STALE
"""

PROC_ARP = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a4:2b:b0:11:22:33     *        eth0
192.168.1.40     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.41     0x1         0x2         00:00:00:00:00:00     *        eth0
"""


def test_ping_command_per_system():
    assert ping_command("1.2.3.4", 800, "Windows") == ["ping", "-n", "1", "-w", "800", "1.2.3.4"]
    assert ping_command("1.2.3.4", 800, "Linux") == ["ping", "-c", "1", "-W", "1", "1.2.3.4"]
    assert ping_command("1.2.3.4", 2500, "Linux")[4] == "3"
    assert ping_command("1.2.3.4", 800, "Darwin")[4] == "800"


def test_parse_windows_arp_any_language():
    table = parse_windows_arp(WINDOWS_ARP)
    assert table["192.168.1.1"] == "a4:2b:b0:11:22:33"
    assert table["172.20.0.5"] == "00:15:5d:aa:bb:cc"
    assert len(table) == 5  # broadcast and multicast are filtered later, by the scanner


def test_parse_ip_neigh_drops_failed_and_ipv6():
    assert parse_ip_neigh(IP_NEIGH) == {
        "192.168.1.1": "a4:2b:b0:11:22:33",
        "192.168.1.20": "da:a1:19:00:00:01",
    }


def test_parse_proc_arp_drops_incomplete():
    assert parse_proc_arp(PROC_ARP) == {"192.168.1.1": "a4:2b:b0:11:22:33"}


def test_read_arp_table_windows_uses_arp(monkeypatch):
    monkeypatch.setattr(
        scanner, "_run", lambda command: WINDOWS_ARP if command == ["arp", "-a"] else ""
    )
    assert "192.168.1.1" in read_arp_table("Windows")


def test_read_arp_table_linux_prefers_proc(monkeypatch, tmp_path):
    fake = tmp_path / "arp"
    fake.write_text(PROC_ARP)
    real_path = scanner.Path

    monkeypatch.setattr(scanner, "Path", lambda p: fake if p == "/proc/net/arp" else real_path(p))
    assert read_arp_table("Linux") == {"192.168.1.1": "a4:2b:b0:11:22:33"}


def test_read_arp_table_falls_back_to_ip_neigh(monkeypatch, tmp_path):
    real_path = scanner.Path
    monkeypatch.setattr(
        scanner, "Path", lambda p: tmp_path / "missing" if p == "/proc/net/arp" else real_path(p)
    )
    monkeypatch.setattr(scanner, "_run", lambda command: IP_NEIGH)
    assert "192.168.1.20" in read_arp_table("Linux")
    assert read_arp_table("Darwin") == {}


def _completed(code=0, out="Reply from x: bytes=32 time=1ms TTL=64"):
    return subprocess.CompletedProcess([], code, stdout=out, stderr="")


def test_ping_once_success_and_failure(monkeypatch):
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: _completed())
    assert ping_once("192.168.1.1") is not None
    # Windows prints this and still exits 0 when a router says "host unreachable".
    unreachable = _completed(0, "Reply from 192.168.1.51: Destination host unreachable.")
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: unreachable)
    assert ping_once("192.168.1.9") is None
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: _completed(1, ""))
    assert ping_once("192.168.1.9") is None


def test_ping_once_timeout_and_missing_command(monkeypatch):
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("ping", 1)

    def missing(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(scanner.subprocess, "run", timeout)
    assert ping_once("192.168.1.9") is None
    monkeypatch.setattr(scanner.subprocess, "run", missing)
    with pytest.raises(ScanError, match="ping"):
        ping_once("192.168.1.9")


def test_run_reports_missing_commands(monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(scanner.subprocess, "run", missing)
    with pytest.raises(ScanError, match="arp"):
        scanner._run(["arp", "-a"])
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: _completed(0, "out"))
    assert scanner._run(["x"]) == "out"


def test_clean_name_strips_control_characters():
    assert clean_name("nas\x1b[31m.lan\n") == "nas[31m.lan"
    assert clean_name("\x00\x01") is None
    assert len(clean_name("a" * 500) or "") == 100


def test_reverse_dns_failure_is_none(monkeypatch):
    def fail(ip):
        raise OSError

    monkeypatch.setattr(scanner.socket, "gethostbyaddr", fail)
    assert scanner.reverse_dns("192.168.1.1") is None
    monkeypatch.setattr(scanner.socket, "gethostbyaddr", lambda ip: ("router.lan", [], [ip]))
    assert scanner.reverse_dns("192.168.1.1") == "router.lan"


def test_scanner_combines_ping_arp_and_names():
    alive = {"192.168.1.1": 1.5, "192.168.1.5": 3.0}
    arp = {
        "192.168.1.1": "a4:2b:b0:11:22:33",
        "192.168.1.20": "da:a1:19:00:00:01",  # ignores ping, but is in the ARP table
        "192.168.1.255": "ff:ff:ff:ff:ff:ff",  # broadcast
        "192.168.2.9": "00:11:22:33:44:55",  # another subnet
    }
    found = PingArpScanner(
        timeout_ms=100,
        workers=4,
        ping=lambda ip, timeout: alive.get(ip),
        arp=lambda: arp,
        resolver=lambda ip: f"host-{ip.rsplit('.', 1)[1]}",
        local=lambda: {},
    ).scan([IPv4Network("192.168.1.0/24")])
    assert [h.ip for h in found] == ["192.168.1.1", "192.168.1.5", "192.168.1.20"]
    router, no_mac, quiet = found
    assert router.mac == "a4:2b:b0:11:22:33" and router.responded and router.latency_ms == 1.5
    assert no_mac.mac is None and no_mac.device_id == "ip:192.168.1.5"
    assert quiet.mac == "da:a1:19:00:00:01" and not quiet.responded
    assert router.hostname == "host-1"


def test_scanner_can_skip_name_lookups():
    found = PingArpScanner(
        resolve_names=False,
        ping=lambda ip, t: 1.0 if ip.endswith(".7") else None,
        arp=lambda: {},
        resolver=lambda ip: pytest.fail("should not resolve"),
        local=lambda: {},
    ).scan([IPv4Network("192.168.1.0/24")])
    assert [h.ip for h in found] == ["192.168.1.7"]


def test_merge_hosts_fills_gaps():
    a = [Host(ip="192.168.1.2", mac=None, responded=False, details={"a": 1})]
    b = [
        Host(
            ip="192.168.1.2",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="x",
            latency_ms=2.0,
            responded=True,
            details={"a": 2, "b": 3},
        ),
        Host(ip="192.168.1.1"),
    ]
    merged = merge_hosts([a, b])
    assert [h.ip for h in merged] == ["192.168.1.1", "192.168.1.2"]
    second = merged[1]
    assert second.mac == "aa:bb:cc:dd:ee:ff" and second.hostname == "x" and second.responded
    assert second.latency_ms == 2.0 and second.details == {"a": 1, "b": 3}


def test_silent_addresses_get_a_second_more_patient_ping():
    calls: list[tuple[str, int]] = []

    def ping(ip, timeout):
        calls.append((ip, timeout))
        return 5.0 if (ip == "192.168.1.8" and timeout == 2500) else None

    found = PingArpScanner(
        timeout_ms=800,
        retry_timeout_ms=2500,
        ping=ping,
        arp=lambda: {"192.168.1.1": "a4:2b:b0:11:22:33"},
        resolve_names=False,
        local=lambda: {},
    ).scan([IPv4Network("192.168.1.0/29")])
    assert [h.ip for h in found] == ["192.168.1.1"]
    # .1 is in the ARP table so it is not asked again; the other silent addresses are
    retried = {ip for ip, timeout in calls if timeout == 2500}
    assert "192.168.1.1" not in retried and retried == {f"192.168.1.{n}" for n in range(2, 7)}


def test_retry_can_be_switched_off():
    calls = []
    PingArpScanner(
        retry_timeout_ms=0,
        ping=lambda ip, t: calls.append(t),
        arp=lambda: {},
        resolve_names=False,
        local=lambda: {},
    ).scan([IPv4Network("192.168.1.0/30")])
    assert set(calls) == {800}


def test_this_machine_is_added_with_its_mac():
    found = PingArpScanner(
        ping=lambda ip, t: 1.0 if ip == "192.168.1.51" else None,
        arp=lambda: {},
        resolve_names=False,
        retry_timeout_ms=0,
        local=lambda: {"192.168.1.51": "c4:03:a8:2a:35:14", "10.9.9.9": "00:11:22:33:44:55"},
    ).scan([IPv4Network("192.168.1.0/24")])
    assert [(h.ip, h.mac, h.details) for h in found] == [
        ("192.168.1.51", "c4:03:a8:2a:35:14", {"self": True})
    ]


def test_this_machine_is_added_even_if_ping_fails():
    found = PingArpScanner(
        ping=lambda ip, t: None,
        arp=lambda: {"192.168.1.60": "a4:2b:b0:11:22:33"},
        resolve_names=False,
        retry_timeout_ms=0,
        local=lambda: {"192.168.1.51": "c4:03:a8:2a:35:14"},
    ).scan([IPv4Network("192.168.1.0/24")])
    assert [h.ip for h in found] == ["192.168.1.51", "192.168.1.60"]


def test_parse_local_addresses_powershell_output():
    text = "192.168.1.51,C4-03-A8-2A-35-14\r\n172.20.0.1,00-15-5D-AA-BB-CC\nbad line\n"
    assert parse_local_addresses(text) == {
        "192.168.1.51": "c4:03:a8:2a:35:14",
        "172.20.0.1": "00:15:5d:aa:bb:cc",
    }


def test_local_addresses_windows_and_failures(monkeypatch):
    monkeypatch.setattr(scanner, "_run", lambda command: "192.168.1.51,C4-03-A8-2A-35-14\n")
    assert local_addresses("Windows") == {"192.168.1.51": "c4:03:a8:2a:35:14"}

    def broken(command):
        raise ScanError("no powershell")

    monkeypatch.setattr(scanner, "_run", broken)
    assert local_addresses("Windows") == {}


def test_local_addresses_linux_has_valid_macs():
    for ip, mac in local_addresses("Linux").items():
        assert ip.count(".") == 3 and len(mac) == 17
