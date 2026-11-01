"""Subnet parsing and the safety checks around it."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network


class SubnetError(ValueError):
    """A subnet setting is invalid or not allowed."""


def parse_subnets(
    text: str | Iterable[str], *, max_hosts: int = 1024, allow_public: bool = False
) -> list[IPv4Network]:
    """Turn "192.168.1.0/24, 10.0.20.0/24" into networks, refusing risky input.

    * Only IPv4 is supported.
    * Public address ranges are refused unless `allow_public` is set: probing networks you do not
      own is not something a home inventory tool should do by accident.
    * The total number of addresses is capped, so a typo such as /8 cannot start a huge scan.
    """
    items = text.split(",") if isinstance(text, str) else list(text)
    networks: list[IPv4Network] = []
    for raw in items:
        item = raw.strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise SubnetError(f"{item!r} is not a valid subnet (example: 192.168.1.0/24)") from None
        if not isinstance(network, IPv4Network):
            raise SubnetError(f"{item!r}: only IPv4 subnets are supported")
        if not allow_public and not (network.is_private or network.is_link_local):
            raise SubnetError(
                f"{item!r} is not a private range; set NETINV_ALLOW_PUBLIC=true only for "
                "networks you own"
            )
        if network.prefixlen == 0:
            raise SubnetError("0.0.0.0/0 is not a subnet you want to scan")
        if network not in networks:
            networks.append(network)
    if not networks:
        raise SubnetError("no subnet configured: set NETINV_SUBNETS, for example 192.168.1.0/24")
    total = sum(host_count(n) for n in networks)
    if total > max_hosts:
        raise SubnetError(
            f"{total} addresses to scan is more than the limit of {max_hosts} "
            "(NETINV_MAX_HOSTS); use smaller subnets or raise the limit"
        )
    return networks


def host_count(network: IPv4Network) -> int:
    """How many addresses `host_list` would return, without building the list."""
    return network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses


def host_list(network: IPv4Network) -> list[IPv4Address]:
    """Usable host addresses (no network or broadcast address; /31 and /32 keep all)."""
    return list(network.hosts()) if network.prefixlen < 31 else list(network)


def in_networks(ip: str, networks: Iterable[IPv4Network]) -> bool:
    try:
        address = IPv4Address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)
