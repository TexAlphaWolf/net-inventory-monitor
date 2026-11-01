from __future__ import annotations

import subprocess
from ipaddress import IPv4Network

import pytest
from conftest import NET, at, host

from netinv import nmap, service
from netinv.config import ConfigError, load_env_file, load_settings
from netinv.engine import apply_scan
from netinv.nmap import NmapScanner, parse_nmap_xml
from netinv.scanner import PingArpScanner, ScanError, make_enricher, make_ssdp

XML = """<?xml version="1.0"?>
<nmaprun>
 <host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/>
  <address addr="A4:2B:B0:11:22:33" addrtype="mac" vendor="Router Maker"/>
  <hostnames><hostname name="gateway.lan" type="PTR"/></hostnames><times srtt="1500"/></host>
 <host><status state="down"/><address addr="192.168.1.9" addrtype="ipv4"/></host>
 <host><status state="up"/><address addr="not-an-ip" addrtype="ipv4"/></host>
 <host><status state="up"/><address addr="192.168.1.20" addrtype="ipv4"/></host>
 <host><status state="up"/><address addr="AA:BB" addrtype="mac"/></host>
</nmaprun>"""


def test_parse_nmap_xml():
    hosts = parse_nmap_xml(XML)
    assert [h.ip for h in hosts] == ["192.168.1.1", "192.168.1.20"]
    router, plain = hosts
    assert router.mac == "a4:2b:b0:11:22:33" and router.hostname == "gateway.lan"
    assert router.latency_ms == 1.5 and router.details["vendor_hint"] == "Router Maker"
    assert plain.mac is None and plain.responded


def test_invalid_xml_is_an_error():
    with pytest.raises(ScanError, match="not valid XML"):
        parse_nmap_xml("<nmaprun><host>")


def completed(code=0, out=XML, err=""):
    return subprocess.CompletedProcess([], code, stdout=out, stderr=err)


def test_nmap_scanner_runs_the_binary(monkeypatch):
    seen = {}

    def run(command, **kwargs):
        seen["command"] = command
        return completed()

    monkeypatch.setattr(nmap.subprocess, "run", run)
    hosts = NmapScanner(binary="/usr/bin/nmap").scan([IPv4Network("192.168.1.0/24")])
    assert seen["command"][:4] == ["/usr/bin/nmap", "-sn", "-n", "-oX"]
    assert seen["command"][-1] == "192.168.1.0/24" and len(hosts) == 2


def test_nmap_scanner_only_returns_hosts_in_the_subnets(monkeypatch):
    monkeypatch.setattr(nmap.subprocess, "run", lambda *a, **k: completed())
    assert NmapScanner(binary="nmap").scan([IPv4Network("10.0.0.0/24")]) == []


def test_nmap_failures(monkeypatch):
    nets = [IPv4Network("192.168.1.0/24")]
    monkeypatch.setattr(nmap.shutil, "which", lambda name: None)
    with pytest.raises(ScanError, match="not found"):
        NmapScanner().scan(nets)
    monkeypatch.setattr(nmap.subprocess, "run", lambda *a, **k: completed(1, "", "need root\x1b"))
    with pytest.raises(ScanError, match="nmap failed: need root"):
        NmapScanner(binary="nmap").scan(nets)

    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("nmap", 1)

    monkeypatch.setattr(nmap.subprocess, "run", timeout)
    with pytest.raises(ScanError, match="too long"):
        NmapScanner(binary="nmap").scan(nets)


def test_vendor_hint_from_nmap_names_the_device(store):
    h = parse_nmap_xml(XML)[0]
    h.mac = "02:00:00:00:00:01"  # a prefix the bundled table does not know
    h.details["vendor_hint"] = "Hinted Inc"
    apply_scan(store, [h], NET, at(0))
    device = store.device("02:00:00:00:00:01")
    assert device.vendor == "Hinted Inc" and "vendor_hint" not in device.details


def test_details_from_probes_are_kept_up_to_date(store):
    apply_scan(store, [host("192.168.1.5", "b8:27:eb:00:00:01")], NET, at(0))
    h = host("192.168.1.5", "b8:27:eb:00:00:01")
    h.details["ssdp"] = "Linux UPnP"
    apply_scan(store, [h], NET, at(5))
    assert store.device("b8:27:eb:00:00:01").details["ssdp"] == "Linux UPnP"


# ------------------------------------------------------------------------ scanner extras


def test_tcp_ports_find_hosts_that_ignore_ping():
    tried = []

    def tcp(ip, ports):
        tried.append((ip, ports))
        return 22 if ip == "192.168.1.3" else None

    found = PingArpScanner(
        ping=lambda ip, t: None,
        arp=lambda: {},
        resolve_names=False,
        local=lambda: {},
        tcp_ports=[22, 80],
        tcp=tcp,
    ).scan([IPv4Network("192.168.1.0/29")])
    assert [h.ip for h in found] == ["192.168.1.3"]
    assert {ip for ip, _ in tried} == {f"192.168.1.{n}" for n in range(1, 7)}
    assert tried[0][1] == [22, 80]


def test_ssdp_announcements_add_hosts_and_details():
    found = PingArpScanner(
        ping=lambda ip, t: None,
        arp=lambda: {"192.168.1.40": "00:11:22:33:44:55"},
        resolve_names=False,
        local=lambda: {},
        retry_timeout_ms=0,
        ssdp=lambda nets: {"192.168.1.40": "Roku/9.4", "192.168.1.41": None, "10.0.0.1": "x"},
    ).scan([IPv4Network("192.168.1.0/24")])
    assert [(h.ip, h.mac, h.details) for h in found] == [
        ("192.168.1.40", "00:11:22:33:44:55", {"ssdp": "Roku/9.4"}),
        ("192.168.1.41", None, {}),
    ]


def test_announced_hosts_are_not_pinged_again():
    pinged = []
    PingArpScanner(
        ping=lambda ip, t: pinged.append((ip, t)),
        arp=lambda: {},
        resolve_names=False,
        local=lambda: {},
        ssdp=lambda nets: {"192.168.1.2": "x"},
    ).scan([IPv4Network("192.168.1.0/29")])
    assert ("192.168.1.2", 2500) not in pinged and ("192.168.1.3", 2500) in pinged


def test_enricher_runs_on_every_host():
    seen = []
    PingArpScanner(
        ping=lambda ip, t: 1.0 if ip == "192.168.1.1" else None,
        arp=lambda: {},
        resolve_names=False,
        local=lambda: {},
        retry_timeout_ms=0,
        enrich=seen.append,
    ).scan([IPv4Network("192.168.1.0/29")])
    assert [h.ip for h in seen] == ["192.168.1.1"]


def test_make_enricher_names_and_snmp(monkeypatch):
    from netinv import probes

    monkeypatch.setattr(probes, "mdns_name", lambda ip: None)
    monkeypatch.setattr(probes, "netbios_name", lambda ip: "WINBOX")
    monkeypatch.setattr(probes, "snmp_info", lambda ip, community: {"sysName": "sw1"})
    h = host("192.168.1.2")
    make_enricher("public")(h)
    assert h.hostname == "WINBOX" and h.details["snmp"] == {"sysName": "sw1"}
    h2 = host("192.168.1.3", hostname="known.lan")
    monkeypatch.setattr(probes, "netbios_name", lambda ip: pytest.fail("name already known"))
    make_enricher(None)(h2)
    assert h2.hostname == "known.lan" and "snmp" not in h2.details
    monkeypatch.setattr(probes, "mdns_name", lambda ip: None)
    monkeypatch.setattr(probes, "netbios_name", lambda ip: None)
    h3 = host("192.168.1.4")
    make_enricher("public")(h3)
    assert h3.hostname == "sw1"


def test_make_ssdp_uses_the_local_address_in_the_subnet(monkeypatch):
    from netinv import probes

    captured = {}
    monkeypatch.setattr(
        probes,
        "ssdp_discover",
        lambda interface, networks: captured.update(interface=interface) or {"192.168.1.9": "x"},
    )
    nets = [IPv4Network("192.168.1.0/24")]
    result = make_ssdp(lambda: {"172.20.0.1": "aa", "192.168.1.51": "bb"})(nets)
    assert captured["interface"] == "192.168.1.51" and result == {"192.168.1.9": "x"}
    make_ssdp(lambda: {})(nets)
    assert captured["interface"] is None


# ---------------------------------------------------------------------------- settings


@pytest.fixture
def env(monkeypatch, tmp_path):
    for name in (
        "NETINV_SCANNER",
        "NETINV_TCP_PORTS",
        "NETINV_DISCOVERY",
        "NETINV_SNMP_COMMUNITY",
        "NETINV_CA_BUNDLE",
        "NETINV_DB",
        "NETINV_OUI_FILE",
        "FOO",
        "BAR",
        "BAZ",
        "QUX",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NETINV_SUBNETS", "192.168.1.0/24")
    monkeypatch.setenv("NETINV_DB", str(tmp_path / "x.db"))
    return monkeypatch


def test_new_settings(env, tmp_path):
    s = load_settings()
    assert (s.scanner, s.tcp_ports, s.discovery, s.snmp_community) == ("ping", (), True, None)
    env.setenv("NETINV_SCANNER", "NMAP")
    env.setenv("NETINV_TCP_PORTS", "22,443")
    env.setenv("NETINV_DISCOVERY", "off")
    env.setenv("NETINV_SNMP_COMMUNITY", "public")
    env.setenv("NETINV_CA_BUNDLE", str(tmp_path / "ca.pem"))
    s = load_settings()
    assert (s.scanner, s.tcp_ports, s.discovery, s.snmp_community) == (
        "nmap",
        (22, 443),
        False,
        "public",
    )
    assert s.ca_bundle == tmp_path / "ca.pem"


@pytest.mark.parametrize("name, value", [("NETINV_SCANNER", "arp"), ("NETINV_TCP_PORTS", "ssh")])
def test_bad_new_settings(env, name, value):
    env.setenv(name, value)
    with pytest.raises(ConfigError, match=name):
        load_settings()


def test_build_scanner_choices(env):
    assert isinstance(service.build_scanner(load_settings()), PingArpScanner)
    env.setenv("NETINV_SCANNER", "nmap")
    assert isinstance(service.build_scanner(load_settings()), NmapScanner)
    env.setenv("NETINV_SCANNER", "ping")
    env.setenv("NETINV_DISCOVERY", "false")
    scanner = service.build_scanner(load_settings())
    assert scanner._ssdp is None and scanner._enrich is None


def test_env_file(env, tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        "﻿# comment\nFOO=one\nBAR = \"two words\"\nBAZ='3' # note\nQUX=4 # inline\n\nbroken line\n",
        encoding="utf-8",
    )
    env.setenv("QUX", "already")
    assert load_env_file(path) is True
    import os

    assert (os.environ["FOO"], os.environ["BAR"], os.environ["BAZ"]) == ("one", "two words", "3")
    assert os.environ["QUX"] == "already"  # a real variable wins
    assert load_env_file(tmp_path / "missing") is False
    for name in ("FOO", "BAR", "BAZ"):
        os.environ.pop(name, None)
