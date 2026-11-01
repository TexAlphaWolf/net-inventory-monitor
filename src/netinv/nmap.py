"""Optional scanner that uses nmap's host discovery (`nmap -sn`).

nmap sends ARP requests on the local network, which finds devices that ignore ping, and it
reports the vendor of each MAC address. It needs the `nmap` program (and, for ARP, the right to
send raw packets: root on Linux, Npcap on Windows). The default scanner needs none of that.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
from ipaddress import IPv4Network
from xml.etree import ElementTree

from .net import in_networks
from .oui import normalise_mac
from .probes import clean_text
from .scanner import Host, ScanError


def parse_nmap_xml(xml: str) -> list[Host]:
    """Hosts that nmap reports as "up" in its XML output."""
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        raise ScanError("nmap printed output that is not valid XML") from None
    hosts: list[Host] = []
    for node in root.iter("host"):
        status = node.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = None
        vendor = None
        for address in node.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip = address.get("addr")
            elif address.get("addrtype") == "mac":
                mac = normalise_mac(address.get("addr") or "")
                vendor = clean_text(address.get("vendor") or "")
        if not ip:
            continue
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        host = Host(ip=ip, mac=mac, responded=True)
        name = node.find("hostnames/hostname")
        if name is not None:
            host.hostname = clean_text(name.get("name") or "")
        if vendor:
            host.details["vendor_hint"] = vendor
        times = node.find("times")
        if times is not None and times.get("srtt", "").isdigit():
            host.latency_ms = round(int(times.get("srtt", "0")) / 1000, 1)
        hosts.append(host)
    return sorted(hosts, key=lambda h: ipaddress.ip_address(h.ip))


class NmapScanner:
    def __init__(self, *, timeout: int = 300, binary: str | None = None) -> None:
        self.timeout = timeout
        self.binary = binary or shutil.which("nmap")

    def scan(self, networks: list[IPv4Network]) -> list[Host]:
        if not self.binary:
            raise ScanError("nmap was not found: install it or use NETINV_SCANNER=ping")
        command = [self.binary, "-sn", "-n", "-oX", "-", *[str(n) for n in networks]]
        try:
            result = subprocess.run(  # noqa: S603 - fixed argv; networks are validated
                command, capture_output=True, text=True, timeout=self.timeout, check=False
            )
        except subprocess.TimeoutExpired:
            raise ScanError("nmap took too long") from None
        if result.returncode != 0:
            raise ScanError(f"nmap failed: {clean_text(result.stderr, 200) or result.returncode}")
        return [h for h in parse_nmap_xml(result.stdout) if in_networks(h.ip, networks)]
