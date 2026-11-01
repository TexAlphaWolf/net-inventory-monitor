from __future__ import annotations

import socket
import struct
import threading
from ipaddress import IPv4Network

import pytest

from netinv import probes
from netinv.probes import (
    build_ptr_query,
    build_snmp_get,
    clean_text,
    mdns_name,
    netbios_name,
    parse_nbstat,
    parse_ports,
    parse_ptr_answers,
    parse_snmp_response,
    parse_ssdp,
    snmp_info,
    ssdp_discover,
    tcp_open,
)


class UdpServer:
    """A one-shot UDP server on loopback that answers with `reply(request)`."""

    def __init__(self, reply):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(3)
        self.port = self.sock.getsockname()[1]
        self.reply = reply
        self.requests: list[bytes] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            data, sender = self.sock.recvfrom(4096)
        except OSError:
            return
        self.requests.append(data)
        answer = self.reply(data)
        if answer is not None:
            self.sock.sendto(answer, sender)

    def close(self):
        self.thread.join(3)
        self.sock.close()


def serve(reply):
    server = UdpServer(reply)
    return server


def dns_ptr_response(name_labels: list[bytes], target: bytes = b"\x06laptop\x05local\x00") -> bytes:
    header = struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 0)
    question = b"\x01" + b"4" + b"\x07in-addr\x04arpa\x00" + struct.pack(">HH", 12, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(target)) + target
    return header + question + answer


# ----------------------------------------------------------------------------------- helpers


def test_clean_text():
    assert clean_text(b"nas\x00\x1b[0m\n") == "nas[0m"
    assert clean_text("   ") is None
    assert len(clean_text("x" * 500)) == 100


def test_parse_ports():
    assert parse_ports("22, 80,443,") == [22, 80, 443]
    assert parse_ports("") == []
    for bad in ("0", "70000", "ssh", "-1"):
        with pytest.raises(ValueError):
            parse_ports(bad)


# ------------------------------------------------------------------------------------- mDNS


def test_ptr_query_has_the_right_shape():
    query = build_ptr_query("4.3.2.1.in-addr.arpa")
    assert struct.unpack(">HHHHHH", query[:12]) == (0, 0, 1, 0, 0, 0)
    assert query.endswith(b"\x00\x00\x0c\x00\x01")


def test_parse_ptr_answers():
    assert parse_ptr_answers(dns_ptr_response([])) == ["laptop.local"]


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00" * 5,
        struct.pack(">HHHHHH", 0, 0x0000, 1, 1, 0, 0) + b"\x00",  # a query, not a response
        struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 0),  # claims records, has none
        struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c",  # pointer to itself
        struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\x3f" + b"a" * 5,  # label too long
        struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0",  # truncated pointer
    ],
)
def test_hostile_dns_packets_are_ignored(data):
    assert parse_ptr_answers(data) == []


def test_pointer_loop_does_not_hang():
    data = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c"
    assert probes._dns_name(data, 12) is None


def test_mdns_name_end_to_end():
    server = serve(lambda request: dns_ptr_response([]))
    try:
        assert mdns_name("127.0.0.1", timeout=2, port=server.port) == "laptop"
    finally:
        server.close()
    assert b"in-addr" in server.requests[0]


def test_mdns_name_no_answer():
    assert mdns_name("127.0.0.1", timeout=0.1, port=9) is None


def test_reply_from_somebody_else_is_ignored(monkeypatch):
    class Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def sendto(self, payload, address):
            pass

        def recvfrom(self, size):
            return b"spoofed", ("10.9.9.9", 5353)

    monkeypatch.setattr(probes.socket, "socket", lambda *a: Sock())
    assert probes._udp_exchange("192.168.1.5", 5353, b"x", 0.1) is None


# ---------------------------------------------------------------------------------- NetBIOS


def nbstat_response(names: list[tuple[bytes, int, int]]) -> bytes:
    body = b"".join(
        name.ljust(15) + bytes([suffix]) + struct.pack(">H", flags) for name, suffix, flags in names
    )
    return b"\x13\x37\x84\x00" + b"\x00" * 52 + bytes([len(names)]) + body


def test_parse_nbstat_picks_the_computer_name():
    data = nbstat_response(
        [(b"WORKGROUP", 0x00, 0x8400), (b"PRINTER01", 0x00, 0x0400), (b"PRINTER01", 0x20, 0x0400)]
    )
    assert parse_nbstat(data) == "PRINTER01"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00" * 60,
        nbstat_response([(b"WORKGROUP", 0x00, 0x8400)]),
        nbstat_response([(b"X", 0x20, 0x0400)])[:-5],
    ],
)
def test_parse_nbstat_rejects_garbage(data):
    assert parse_nbstat(data) is None


def test_netbios_name_end_to_end():
    server = serve(lambda request: nbstat_response([(b"DESKTOP-ABC", 0, 0x0400)]))
    try:
        assert netbios_name("127.0.0.1", timeout=2, port=server.port) == "DESKTOP-ABC"
    finally:
        server.close()
    assert netbios_name("127.0.0.1", timeout=0.1, port=9) is None


# ------------------------------------------------------------------------------------ SNMP


def snmp_response(sys_name: bytes | None, sys_descr: bytes | None) -> bytes:
    ber = probes._ber

    def varbind(oid, value):
        return ber(
            0x30, probes._oid(oid) + (ber(0x04, value) if value is not None else b"\x05\x00")
        )

    binds = varbind(probes.SNMP_OIDS["sysDescr"], sys_descr) + varbind(
        probes.SNMP_OIDS["sysName"], sys_name
    )
    pdu = ber(0xA2, ber(0x02, b"\x01") + ber(0x02, b"\x00") + ber(0x02, b"\x00") + ber(0x30, binds))
    return ber(0x30, ber(0x02, b"\x01") + ber(0x04, b"public") + pdu)


def test_snmp_request_is_well_formed():
    request = build_snmp_get("public", 7)
    assert request[0] == 0x30 and b"public" in request
    assert probes._oid((1, 3, 6, 1, 2, 1, 1, 5, 0)) in request


def test_oid_encoding_of_large_numbers():
    assert probes._oid((1, 3, 6, 1, 4, 1, 2636)) == bytes.fromhex("06072b0601040194" + "4c")


def test_long_ber_lengths():
    assert probes._ber(0x04, b"x" * 200)[:3] == bytes([0x04, 0x81, 200])


def test_parse_snmp_response():
    info = parse_snmp_response(snmp_response(b"sw-core", b"Managed switch\x1b[2J v1.2"))
    assert info == {"sysName": "sw-core", "sysDescr": "Managed switch[2J v1.2"}
    assert parse_snmp_response(snmp_response(None, b"only descr")) == {"sysDescr": "only descr"}


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x30",
        b"\x30\x84\xff\xff\xff\xff",
        b"\x04\x03abc",
        b"\x30\x03\x02\x01\x01",
        snmp_response(b"a", b"b")[:-7],
        b"\x30\x80" + b"\x00" * 6,
    ],
)
def test_hostile_snmp_packets_are_ignored(data):
    assert parse_snmp_response(data) == {}


def test_a_set_request_is_not_accepted_as_a_response():
    data = bytearray(snmp_response(b"a", b"b"))
    data[data.index(0xA2)] = 0xA0
    assert parse_snmp_response(bytes(data)) == {}


def test_snmp_info_end_to_end():
    server = serve(lambda request: snmp_response(b"router", b"Linux"))
    try:
        assert snmp_info("127.0.0.1", "public", timeout=2, port=server.port)["sysName"] == "router"
    finally:
        server.close()
    assert b"public" in server.requests[0]
    assert snmp_info("127.0.0.1", "public", timeout=0.1, port=9) == {}


# ------------------------------------------------------------------------------------ SSDP


def test_parse_ssdp():
    response = (
        b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Linux/5.4 UPnP/1.0 TV/1.0\r\n\r\n"
    )
    assert parse_ssdp(response) == "Linux/5.4 UPnP/1.0 TV/1.0"
    assert parse_ssdp(b"HTTP/1.1 200 OK\r\nST: x\r\n\r\n") is None
    assert parse_ssdp(b"") is None


def test_ssdp_discover_collects_answers_from_the_subnet(monkeypatch):
    server = serve(lambda request: b"HTTP/1.1 200 OK\r\nSERVER: Fake/1.0\r\n\r\n")
    try:
        found = ssdp_discover(
            None, [IPv4Network("127.0.0.0/8")], wait=1.0, group=("127.0.0.1", server.port)
        )
    finally:
        server.close()
    assert found == {"127.0.0.1": "Fake/1.0"}


def test_ssdp_ignores_answers_from_other_networks():
    server = serve(lambda request: b"HTTP/1.1 200 OK\r\n\r\n")
    try:
        found = ssdp_discover(
            None, [IPv4Network("192.168.1.0/24")], wait=0.6, group=("127.0.0.1", server.port)
        )
    finally:
        server.close()
    assert found == {}


# ------------------------------------------------------------------------------------- TCP


def test_tcp_open_finds_the_first_open_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        assert tcp_open("127.0.0.1", [9, port], timeout=1) == port
    assert tcp_open("127.0.0.1", [port], timeout=0.2) is None
