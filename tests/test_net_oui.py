import pytest

from netinv.net import SubnetError, host_list, in_networks, parse_subnets
from netinv.oui import (
    VendorLookup,
    is_multicast_or_broadcast,
    is_randomized,
    load_ieee_csv,
    normalise_mac,
)


def test_parse_subnets_accepts_private_ranges():
    nets = parse_subnets("192.168.1.0/24, 10.0.20.0/24 ,192.168.1.0/24")
    assert [str(n) for n in nets] == ["192.168.1.0/24", "10.0.20.0/24"]


def test_host_ignores_host_bits_and_blank_items():
    assert [str(n) for n in parse_subnets(["192.168.1.77/24", " "])] == ["192.168.1.0/24"]


@pytest.mark.parametrize(
    "text, message",
    [
        ("", "no subnet configured"),
        ("not-a-subnet", "not a valid subnet"),
        ("8.8.8.0/24", "not a private range"),
        ("fd00::/64", "only IPv4"),
        ("0.0.0.0/0", "not a private range"),
        ("10.0.0.0/8", "more than the limit"),
    ],
)
def test_parse_subnets_rejects_risky_input(text, message):
    with pytest.raises(SubnetError, match=message):
        parse_subnets(text)


def test_public_ranges_need_an_explicit_opt_in():
    assert parse_subnets("8.8.8.0/30", allow_public=True)
    with pytest.raises(SubnetError, match="0.0.0.0/0"):
        parse_subnets("0.0.0.0/0", allow_public=True, max_hosts=10**10)


def test_host_list_skips_network_and_broadcast():
    nets = parse_subnets("192.168.1.0/30")
    assert [str(h) for h in host_list(nets[0])] == ["192.168.1.1", "192.168.1.2"]
    assert len(host_list(parse_subnets("192.168.1.0/31")[0])) == 2
    assert len(host_list(parse_subnets("192.168.1.9/32")[0])) == 1


def test_in_networks():
    nets = parse_subnets("192.168.1.0/24")
    assert in_networks("192.168.1.5", nets)
    assert not in_networks("192.168.2.5", nets)
    assert not in_networks("garbage", nets)


def test_normalise_mac_variants():
    assert normalise_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalise_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert normalise_mac("aa:bb:cc") is None
    assert normalise_mac("zz:bb:cc:dd:ee:ff") is None


def test_randomised_and_multicast_bits():
    assert is_randomized("da:a1:19:00:00:01")
    assert not is_randomized("b8:27:eb:00:00:01")
    assert is_multicast_or_broadcast("ff:ff:ff:ff:ff:ff")
    assert is_multicast_or_broadcast("01:00:5e:00:00:fb")
    assert not is_multicast_or_broadcast("b8:27:eb:00:00:01")


def test_vendor_lookup_bundled():
    vendors = VendorLookup()
    assert vendors.vendor("b8:27:eb:12:34:56") == "Raspberry Pi Trading"
    assert vendors.vendor("c4:03:a8:2a:35:14") == "Intel"
    assert vendors.vendor("00:11:22:33:44:55") is None
    assert len(vendors) > 50


def test_vendor_of_a_randomised_address_is_unknown():
    # Locally administered bit set: the prefix is not an assigned vendor prefix.
    assert VendorLookup().vendor("52:54:00:12:34:56") is None


def test_ieee_csv_adds_vendors(tmp_path):
    csv_file = tmp_path / "oui.csv"
    csv_file.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,001122,"Example, Inc.",Somewhere\n'
        "MA-L,BADROW,Broken,x\n"
        "short\n",
        encoding="utf-8",
    )
    assert load_ieee_csv(csv_file) == {"001122": "Example, Inc."}
    assert VendorLookup(csv_file).vendor("00:11:22:aa:bb:cc") == "Example, Inc."
