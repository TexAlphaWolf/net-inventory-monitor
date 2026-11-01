"""MAC addresses: normalising, spotting randomised ones, and vendor lookup.

A small table of common vendors is built in so the tool works offline. For the full IEEE list run
`netinv oui-update` and point NETINV_OUI_FILE at the downloaded file.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

_MAC = re.compile(r"^[0-9a-f]{12}$")

# Prefix (first three bytes, upper case, no separators) -> vendor. A sample, not the whole registry.
BUNDLED: dict[str, str] = {
    **dict.fromkeys(
        ["B827EB", "DCA632", "E45F01", "D83ADD", "28CDC1", "2CCF67"], "Raspberry Pi Trading"
    ),
    **dict.fromkeys(["005056", "000C29", "000569"], "VMware"),
    "080027": "VirtualBox (PCS Systems)",
    "525400": "QEMU/KVM virtual NIC",
    "00155D": "Microsoft Hyper-V",
    **dict.fromkeys(
        [
            "240AC4",
            "30AEA4",
            "246F28",
            "A4CF12",
            "84CCA8",
            "7C9EBD",
            "5CCF7F",
            "600194",
            "18FE34",
            "2C3AE8",
            "68C63A",
            "ECFABC",
            "B4E62D",
            "DC4F22",
            "840D8E",
        ],
        "Espressif (ESP32/ESP8266)",
    ),
    "C403A8": "Intel",
    **dict.fromkeys(["44D9E7", "802AA8", "FCECDA", "788A20", "F09FC2", "245A4C"], "Ubiquiti"),
    **dict.fromkeys(["50C7BF", "98DAC4", "F4F26D", "14CC20", "A0F3C1", "EC086B"], "TP-Link"),
    **dict.fromkeys(["000393", "001CB3", "3C22FB", "F01898", "A483E7", "ACBC32"], "Apple"),
    **dict.fromkeys(["001247", "001632", "5C0A5B", "78BDBC"], "Samsung"),
    "001132": "Synology",
    **dict.fromkeys(["00089B", "245EBE"], "QNAP"),
    "00000C": "Cisco",
    **dict.fromkeys(["00095B", "00146C", "A00460"], "Netgear"),
    **dict.fromkeys(["3CA62F", "00040E", "246511"], "AVM (FRITZ!)"),
    **dict.fromkeys(["001788", "ECB5FA"], "Philips Hue"),
    **dict.fromkeys(["000E58", "5CAAFD", "949F3E"], "Sonos"),
    **dict.fromkeys(["001422", "F8BC12"], "Dell"),
}


def normalise_mac(value: str) -> str | None:
    """ "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff" and similar -> "aa:bb:cc:dd:ee:ff"; else None."""
    digits = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    if not _MAC.match(digits):
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def is_randomized(mac: str) -> bool:
    """True for locally administered addresses, which phones use to hide their identity."""
    return bool(int(mac[:2], 16) & 0x02)


def is_multicast_or_broadcast(mac: str) -> bool:
    return bool(int(mac[:2], 16) & 0x01)


class VendorLookup:
    """Vendor names by MAC prefix: the bundled sample plus an optional IEEE oui.csv."""

    def __init__(self, oui_file: Path | None = None) -> None:
        self._table = dict(BUNDLED)
        if oui_file is not None:
            self._table.update(load_ieee_csv(oui_file))

    def __len__(self) -> int:
        return len(self._table)

    def vendor(self, mac: str) -> str | None:
        prefix = mac.replace(":", "").upper()[:6]
        if is_randomized(mac):
            return None  # the prefix of a randomised address means nothing
        return self._table.get(prefix)


def load_ieee_csv(path: Path) -> dict[str, str]:
    """Read the IEEE MA-L registry (columns: Registry, Assignment, Organization Name, ...)."""
    table: dict[str, str] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[1]):
                table[row[1].upper()] = row[2].strip()[:80]
    return table
