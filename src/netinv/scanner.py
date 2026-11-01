"""Finding the devices that are on the network right now.

The default scanner needs no privileges and no extra software:

1. ping every address of the subnets (with the system `ping`, many at once);
2. read the system ARP table, which now knows the MAC address of every host that answered;
3. look up a name for each host (reverse DNS).

A host is reported when it answered a ping *or* has an ARP entry, so devices that ignore ping
(many phones) are still found. Everything that touches the system is injectable, so the parsing
and the logic are tested without a network.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import platform
import re
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from pathlib import Path
from typing import Any, Protocol

from . import probes as _probes
from .net import host_list, in_networks
from .oui import is_multicast_or_broadcast, normalise_mac

log = logging.getLogger("netinv.scanner")


@dataclass
class Host:
    """One device seen in a scan."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    latency_ms: float | None = None
    responded: bool = False  # answered a ping
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def device_id(self) -> str:
        """MAC address when we have one (stable), else the IP (hosts behind a router)."""
        return self.mac or f"ip:{self.ip}"


class Scanner(Protocol):
    def scan(self, networks: list[IPv4Network]) -> list[Host]: ...


# ------------------------------------------------------------------------------------- ping


def ping_command(ip: str, timeout_ms: int, system: str | None = None) -> list[str]:
    """The system ping command line for one echo request."""
    system = system or platform.system()
    if system == "Windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    if system == "Darwin":
        return ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    return ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout_ms / 1000))), ip]


def ping_once(ip: str, timeout_ms: int = 800) -> float | None:
    """Latency in milliseconds if `ip` answered, else None."""
    started = time.perf_counter()
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, `ip` was validated as an address
            ping_command(ip, timeout_ms),
            capture_output=True,
            text=True,
            timeout=timeout_ms / 1000 + 3,
            check=False,
        )
    except FileNotFoundError:
        raise ScanError("the `ping` command was not found; install it (iputils-ping)") from None
    except subprocess.TimeoutExpired:
        return None
    elapsed = (time.perf_counter() - started) * 1000
    # Windows exits 0 for "destination host unreachable" replies, so also require a TTL.
    if result.returncode == 0 and "ttl" in result.stdout.lower():
        return round(elapsed, 1)
    return None


class ScanError(RuntimeError):
    """The scan could not run."""


# ------------------------------------------------------------------------------- ARP table

_WIN_ARP = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})\s+\S+"
)
_IP_NEIGH = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*?lladdr\s+(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})"
    r"(?:\s+(?P<state>[A-Z]+))?"
)


def parse_windows_arp(text: str) -> dict[str, str]:
    """`arp -a` on Windows (any language) -> {ip: mac}."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        if m := _WIN_ARP.match(line):
            mac = normalise_mac(m["mac"])
            if mac:
                table[m["ip"]] = mac
    return table


def parse_ip_neigh(text: str) -> dict[str, str]:
    """`ip neigh` output -> {ip: mac}, without failed or incomplete entries."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        if (m := _IP_NEIGH.match(line.strip())) and m["state"] not in {"FAILED", "INCOMPLETE"}:
            mac = normalise_mac(m["mac"])
            if mac:
                table[m["ip"]] = mac
    return table


def parse_proc_arp(text: str) -> dict[str, str]:
    """/proc/net/arp -> {ip: mac}; flag 0x0 means the entry is incomplete."""
    table: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[2] != "0x0":
            mac = normalise_mac(parts[3])
            if mac and mac != "00:00:00:00:00:00":
                table[parts[0]] = mac
    return table


def read_arp_table(system: str | None = None) -> dict[str, str]:
    """The system ARP table as {ip: mac}."""
    system = system or platform.system()
    if system == "Windows":
        return parse_windows_arp(_run(["arp", "-a"]))
    proc = Path("/proc/net/arp")
    if proc.exists():
        return parse_proc_arp(proc.read_text(encoding="ascii", errors="replace"))
    if system == "Darwin":
        return {}  # `arp -an` on macOS prints (ip) at aa:b:c..., not supported yet
    return parse_ip_neigh(_run(["ip", "neigh"]))


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv
            command, capture_output=True, text=True, timeout=15, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ScanError(f"could not run `{command[0]}`: {type(exc).__name__}") from None
    return result.stdout


# ------------------------------------------------------------------- this machine's own addresses

_PS_LOCAL = (
    "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "
    "$a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; "
    "if ($a) { $_.IPAddress + ',' + $a.MacAddress } }"
)


def parse_local_addresses(text: str) -> dict[str, str]:
    """Lines of "ip,mac" (as printed by the PowerShell snippet above) -> {ip: mac}."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        ip, _, raw_mac = line.strip().partition(",")
        mac = normalise_mac(raw_mac)
        if mac and in_networks(ip, [IPv4Network("0.0.0.0/0")]):
            table[ip] = mac
    return table


def local_addresses(system: str | None = None) -> dict[str, str]:
    """{ip: mac} of this machine's own IPv4 interfaces (it is never in its own ARP table)."""
    system = system or platform.system()
    try:
        if system == "Windows":
            return parse_local_addresses(
                _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_LOCAL])
            )
        return _linux_local_addresses()
    except (ScanError, OSError):
        return {}


def _linux_local_addresses() -> dict[str, str]:
    if sys.platform == "win32":
        return {}
    import fcntl  # Unix only
    import struct

    table: dict[str, str] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for iface in Path("/sys/class/net").iterdir():
            try:
                mac = normalise_mac((iface / "address").read_text())
                packed = struct.pack("256s", iface.name.encode()[:15])
                ip = socket.inet_ntoa(
                    fcntl.ioctl(sock.fileno(), 0x8915, packed)[20:24]
                )  # SIOCGIFADDR
            except OSError:
                continue
            if mac and mac != "00:00:00:00:00:00":
                table[ip] = mac
    return table


# ----------------------------------------------------------------------------- name lookup


def reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    return clean_name(name)


def clean_name(name: str) -> str | None:
    """Host names come from the network, so keep printable characters only."""
    cleaned = "".join(ch for ch in name if ch.isprintable())[:100].strip()
    return cleaned or None


# ------------------------------------------------------------------------------- scanner


class PingArpScanner:
    """Ping sweep + ARP table + reverse DNS. No root, no extra tools."""

    def __init__(
        self,
        *,
        timeout_ms: int = 800,
        retry_timeout_ms: int = 2500,
        workers: int = 64,
        resolve_names: bool = True,
        ping: Callable[[str, int], float | None] = ping_once,
        arp: Callable[[], dict[str, str]] = read_arp_table,
        resolver: Callable[[str], str | None] = reverse_dns,
        local: Callable[[], dict[str, str]] = local_addresses,
        tcp_ports: list[int] | None = None,
        tcp: Callable[[str, list[int]], int | None] = _probes.tcp_open,
        ssdp: Callable[[list[IPv4Network]], dict[str, str | None]] | None = None,
        enrich: Callable[[Host], None] | None = None,
    ) -> None:
        self.tcp_ports = tcp_ports or []
        self._tcp = tcp
        self._ssdp = ssdp
        self._enrich = enrich
        self.timeout_ms = timeout_ms
        self.retry_timeout_ms = retry_timeout_ms
        self._local = local
        self.workers = workers
        self.resolve_names = resolve_names
        self._ping = ping
        self._arp = arp
        self._resolver = resolver

    def scan(self, networks: list[IPv4Network]) -> list[Host]:
        targets = [str(ip) for network in networks for ip in host_list(network)]
        target_set = set(targets)
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            latencies = self._sweep(pool, targets, self.timeout_ms)
            announced = self._ssdp(networks) if self._ssdp else {}
            arp = self._arp_in(networks)
            if self.retry_timeout_ms:
                # Phones in power-save sleep through a quick ping and ARP request: ask the
                # silent addresses again, more patiently (and, if asked, on a few TCP ports:
                # a host that blocks ping may still accept a connection).
                silent = [
                    ip
                    for ip in targets
                    if latencies[ip] is None and ip not in arp and ip not in announced
                ]
                latencies.update(self._sweep(pool, silent, self.retry_timeout_ms))
                if self.tcp_ports:
                    still = [ip for ip in silent if latencies[ip] is None]
                    answers = pool.map(lambda ip: self._tcp(ip, self.tcp_ports), still)
                    for ip, port in zip(still, answers, strict=True):
                        if port is not None:
                            latencies[ip] = 0.0
                arp = self._arp_in(networks)
            hosts = self._merge(latencies, arp, target_set)
            self._add_announced(hosts, announced, arp, target_set)
            self._add_this_machine(hosts, target_set)
            if self.resolve_names and hosts:
                names = pool.map(lambda h: self._resolver(h.ip), hosts)
                for host, name in zip(hosts, names, strict=True):
                    host.hostname = name
            if self._enrich and hosts:
                list(pool.map(self._enrich, hosts))
        return hosts

    @staticmethod
    def _add_announced(
        hosts: list[Host], announced: dict[str, str | None], arp: dict[str, str], targets: set[str]
    ) -> None:
        """Devices that answered an SSDP search are alive even if they ignore ping."""
        by_ip = {h.ip: h for h in hosts}
        for ip, server in announced.items():
            if ip not in targets:
                continue
            host = by_ip.get(ip)
            if host is None:
                host = Host(ip=ip, mac=arp.get(ip), responded=True)
                hosts.append(host)
            if server:
                host.details["ssdp"] = server
        hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))

    def _sweep(
        self, pool: ThreadPoolExecutor, ips: list[str], timeout_ms: int
    ) -> dict[str, float | None]:
        return dict(zip(ips, pool.map(lambda ip: self._ping(ip, timeout_ms), ips), strict=True))

    def _arp_in(self, networks: list[IPv4Network]) -> dict[str, str]:
        return {ip: mac for ip, mac in self._arp().items() if in_networks(ip, networks)}

    def _add_this_machine(self, hosts: list[Host], targets: set[str]) -> None:
        """This machine is not in its own ARP table: add its MAC from the interface list."""
        by_ip = {h.ip: h for h in hosts}
        for ip, mac in self._local().items():
            if ip not in targets:
                continue
            host = by_ip.get(ip)
            if host is None:
                host = Host(ip=ip, responded=True)
                hosts.append(host)
                hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))
            host.mac = mac
            host.details["self"] = True

    @staticmethod
    def _merge(
        latencies: dict[str, float | None], arp: dict[str, str], targets: set[str]
    ) -> list[Host]:
        hosts: dict[str, Host] = {}
        for ip, latency in latencies.items():
            if latency is not None:
                hosts[ip] = Host(ip=ip, latency_ms=latency, responded=True)
        for ip, mac in arp.items():
            if ip not in targets or is_multicast_or_broadcast(mac):
                continue
            hosts.setdefault(ip, Host(ip=ip)).mac = mac
        return sorted(hosts.values(), key=lambda h: ipaddress.ip_address(h.ip))


def make_enricher(snmp_community: str | None = None) -> Callable[[Host], None]:
    """Fill in the name and description of a host by asking the device (mDNS, NetBIOS, SNMP)."""

    def enrich(host: Host) -> None:
        if not host.hostname:
            host.hostname = _probes.mdns_name(host.ip) or _probes.netbios_name(host.ip)
        if snmp_community:
            info = _probes.snmp_info(host.ip, snmp_community)
            if info:
                host.details["snmp"] = info
                host.hostname = host.hostname or info.get("sysName")

    return enrich


def make_ssdp(
    local: Callable[[], dict[str, str]] = local_addresses,
) -> Callable[[list[IPv4Network]], dict[str, str | None]]:
    """An SSDP discovery function that sends from this machine's address in the subnet."""

    def discover(networks: list[IPv4Network]) -> dict[str, str | None]:
        interface = next((ip for ip in local() if in_networks(ip, networks)), None)
        return _probes.ssdp_discover(interface, networks)

    return discover


def merge_hosts(groups: Iterable[Iterable[Host]]) -> list[Host]:
    """Combine the results of several scanners; the first one to know a fact wins."""
    merged: dict[str, Host] = {}
    for group in groups:
        for host in group:
            current = merged.setdefault(host.ip, host)
            if current is host:
                continue
            current.mac = current.mac or host.mac
            current.hostname = current.hostname or host.hostname
            current.responded = current.responded or host.responded
            if current.latency_ms is None:
                current.latency_ms = host.latency_ms
            current.details.update(
                {k: v for k, v in host.details.items() if k not in current.details}
            )
    return sorted(merged.values(), key=lambda h: ipaddress.ip_address(h.ip))
