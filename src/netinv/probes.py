"""Extra ways to learn about a device: names and descriptions from the device itself.

Everything here talks UDP or TCP to one address, has a short timeout, and returns `None` when
the device does not answer. The answers come from the network, so they are hostile input:
parsers check every length and offset, cap what they keep, and never raise on garbage.

* mDNS reverse lookup (port 5353): phones, laptops, printers, Linux hosts say their ".local" name
* NetBIOS node status (port 137): Windows PCs, printers and NAS boxes say their name
* SNMP v2c GET (port 161): switches, routers, printers say name and description (opt-in)
* SSDP (port 1900, multicast): smart TVs, speakers, routers announce themselves
* TCP connect: a host that blocks ping but has an open port is still there
"""

from __future__ import annotations

import socket
import struct
import time
from ipaddress import IPv4Network

from .net import in_networks

MAX_TEXT = 100


def clean_text(raw: bytes | str, limit: int = MAX_TEXT) -> str | None:
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    cleaned = "".join(ch for ch in text if ch.isprintable()).strip()[:limit]
    return cleaned or None


def _udp_exchange(ip: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    """Send one datagram, return the first reply from that address (or None)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (ip, port))
            data, sender = sock.recvfrom(4096)
        except OSError:
            return None
    return data if sender[0] == ip else None


# ----------------------------------------------------------------------------------- DNS / mDNS


def _dns_name(data: bytes, offset: int) -> tuple[str, int] | None:
    """Read a (possibly compressed) DNS name. Returns (name, offset after it) or None."""
    labels: list[str] = []
    end: int | None = None
    jumps = 0
    while True:
        if offset >= len(data):
            return None
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # pointer
            if offset + 1 >= len(data):
                return None
            jumps += 1
            if jumps > 10:  # a loop, or a hostile packet
                return None
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length & 0xC0 or offset + 1 + length > len(data) or len(labels) > 30:
            return None
        labels.append(data[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), end if end is not None else offset


def build_ptr_query(name: str, txid: int = 0) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0, 1, 0, 0, 0)
    question = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return header + question + struct.pack(">HH", 12, 1)  # PTR, class IN


def parse_ptr_answers(data: bytes) -> list[str]:
    """The target names of every PTR record in a DNS response."""
    if len(data) < 12:
        return []
    _, flags, questions, answers, _, _ = struct.unpack(">HHHHHH", data[:12])
    if not flags & 0x8000:  # not a response
        return []
    offset = 12
    for _ in range(min(questions, 5)):
        parsed = _dns_name(data, offset)
        if parsed is None:
            return []
        offset = parsed[1] + 4
    names: list[str] = []
    for _ in range(min(answers, 20)):
        parsed = _dns_name(data, offset)
        if parsed is None or parsed[1] + 10 > len(data):
            break
        offset = parsed[1]
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        if rtype == 12 and (target := _dns_name(data, offset)):
            if text := clean_text(target[0]):
                names.append(text)
        offset += rdlength
    return names


def mdns_name(ip: str, timeout: float = 0.6, port: int = 5353) -> str | None:
    """Ask the device itself for its name: a reverse (PTR) query straight to its mDNS port."""
    reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    reply = _udp_exchange(ip, port, build_ptr_query(reverse), timeout)
    names = parse_ptr_answers(reply) if reply else []
    return names[0].removesuffix(".local") if names else None


# --------------------------------------------------------------------------------------- NetBIOS

_NBSTAT_QUERY = (
    b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
)


def parse_nbstat(data: bytes) -> str | None:
    """The workstation name from a NetBIOS node-status response."""
    if len(data) < 57 or data[2] & 0x80 == 0:
        return None
    count = data[56]
    offset = 57
    for _ in range(min(count, 20)):
        entry = data[offset : offset + 18]
        if len(entry) < 18:
            return None
        name, suffix, flags = entry[:15], entry[15], struct.unpack(">H", entry[16:18])[0]
        group = flags & 0x8000
        if suffix == 0x00 and not group:  # the computer name
            return clean_text(name.decode("ascii", "replace"))
        offset += 18
    return None


def netbios_name(ip: str, timeout: float = 0.6, port: int = 137) -> str | None:
    reply = _udp_exchange(ip, port, _NBSTAT_QUERY, timeout)
    return parse_nbstat(reply) if reply else None


# ------------------------------------------------------------------------------------------ SNMP

SNMP_OIDS = {
    "sysDescr": (1, 3, 6, 1, 2, 1, 1, 1, 0),
    "sysName": (1, 3, 6, 1, 2, 1, 1, 5, 0),
}


def _ber(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _oid(parts: tuple[int, ...]) -> bytes:
    body = bytes([parts[0] * 40 + parts[1]])
    for number in parts[2:]:
        chunk = [number & 0x7F]
        number >>= 7
        while number:
            chunk.append(0x80 | (number & 0x7F))
            number >>= 7
        body += bytes(reversed(chunk))
    return _ber(0x06, body)


def build_snmp_get(community: str, request_id: int = 1) -> bytes:
    """An SNMPv2c GET for sysDescr and sysName."""
    varbinds = b"".join(_ber(0x30, _oid(oid) + b"\x05\x00") for oid in SNMP_OIDS.values())
    pdu = _ber(
        0xA0,
        _ber(0x02, request_id.to_bytes(4, "big"))
        + _ber(0x02, b"\x00")
        + _ber(0x02, b"\x00")
        + _ber(0x30, varbinds),
    )
    return _ber(0x30, _ber(0x02, b"\x01") + _ber(0x04, community.encode()) + pdu)


def _tlv(data: bytes, offset: int) -> tuple[int, bytes, int] | None:
    """One BER element: (tag, content, offset after it), or None if it does not fit."""
    if offset + 2 > len(data):
        return None
    tag, first = data[offset], data[offset + 1]
    offset += 2
    if first & 0x80:
        size = first & 0x7F
        if size == 0 or size > 4 or offset + size > len(data):
            return None
        length = int.from_bytes(data[offset : offset + size], "big")
        offset += size
    else:
        length = first
    if offset + length > len(data):
        return None
    return tag, data[offset : offset + length], offset + length


def parse_snmp_response(data: bytes) -> dict[str, str]:
    """{"sysName": ..., "sysDescr": ...} from a GET response; empty for anything else."""
    names = {_oid(oid)[2:]: key for key, oid in SNMP_OIDS.items()}
    outer = _tlv(data, 0)
    if outer is None or outer[0] != 0x30:
        return {}
    version = _tlv(outer[1], 0)
    community = _tlv(outer[1], version[2]) if version else None
    pdu = _tlv(outer[1], community[2]) if community else None
    if pdu is None or pdu[0] != 0xA2:  # GetResponse
        return {}
    offset = 0
    for _ in range(3):  # request id, error status, error index
        field = _tlv(pdu[1], offset)
        if field is None:
            return {}
        offset = field[2]
    varbind_list = _tlv(pdu[1], offset)
    if varbind_list is None:
        return {}
    result: dict[str, str] = {}
    position = 0
    while position < len(varbind_list[1]):
        varbind = _tlv(varbind_list[1], position)
        if varbind is None:
            break
        position = varbind[2]
        oid = _tlv(varbind[1], 0)
        value = _tlv(varbind[1], oid[2]) if oid else None
        if oid and value and value[0] == 0x04 and oid[1] in names:
            if text := clean_text(value[1]):
                result[names[oid[1]]] = text
    return result


def snmp_info(ip: str, community: str, timeout: float = 0.8, port: int = 161) -> dict[str, str]:
    reply = _udp_exchange(ip, port, build_snmp_get(community), timeout)
    return parse_snmp_response(reply) if reply else {}


# ------------------------------------------------------------------------------------------ SSDP

SSDP_GROUP = ("239.255.255.250", 1900)
SSDP_REQUEST = (
    b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
    b"MX: 2\r\nST: ssdp:all\r\n\r\n"
)


def parse_ssdp(data: bytes) -> str | None:
    """The SERVER header (what the device says it is) from an SSDP response."""
    for line in data.split(b"\r\n")[1:40]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"server":
            return clean_text(value)
    return None


def ssdp_discover(
    interface_ip: str | None,
    networks: list[IPv4Network],
    wait: float = 2.5,
    group: tuple[str, int] = SSDP_GROUP,
) -> dict[str, str | None]:
    """Multicast an SSDP search and collect {ip: server header} of the devices that answer."""
    found: dict[str, str | None] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.settimeout(0.3)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            if interface_ip:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip)
                )
            sock.sendto(SSDP_REQUEST, group)
        except OSError:
            return found
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline and len(found) < 512:
            try:
                data, sender = sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if in_networks(sender[0], networks):
                found.setdefault(sender[0], parse_ssdp(data))
    return found


# -------------------------------------------------------------------------------------------- TCP


def tcp_open(ip: str, ports: list[int], timeout: float = 0.6) -> int | None:
    """The first of `ports` that accepts a connection, or None."""
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return port
        except OSError:
            continue
    return None


def parse_ports(text: str) -> list[int]:
    ports: list[int] = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        if not item.isdigit() or not 0 < int(item) < 65536:
            raise ValueError(f"{item!r} is not a TCP port")
        ports.append(int(item))
    return ports
