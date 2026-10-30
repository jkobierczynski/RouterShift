# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Interface names: from each platform's spelling to the canonical one, and back through a port map."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .errors import RoutershiftError
from .model import Device, Interface, InterfaceKind

# Cisco-style prefixes, longest first so that "Te" does not swallow "TenGigabitEthernet". Value: kind, media.
_PREFIXES: List[Tuple[str, InterfaceKind, str]] = [
    ("HundredGigE", InterfaceKind.ETHERNET, "100g"),
    ("FortyGigabitEthernet", InterfaceKind.ETHERNET, "40g"),
    ("TwentyFiveGigE", InterfaceKind.ETHERNET, "25g"),
    ("TenGigabitEthernet", InterfaceKind.ETHERNET, "10g"),
    ("FiveGigabitEthernet", InterfaceKind.ETHERNET, "5g"),
    ("TwoGigabitEthernet", InterfaceKind.ETHERNET, "2.5g"),
    ("GigabitEthernet", InterfaceKind.ETHERNET, "1g"),
    ("FastEthernet", InterfaceKind.ETHERNET, "100m"),
    ("Ethernet", InterfaceKind.ETHERNET, ""),
    ("Port-channel", InterfaceKind.LAG, ""),
    ("Vlan", InterfaceKind.VLAN, ""),
    ("Loopback", InterfaceKind.LOOPBACK, ""),
    ("Management", InterfaceKind.MANAGEMENT, ""),
    ("Tunnel", InterfaceKind.TUNNEL, ""),
    ("Null", InterfaceKind.OTHER, ""),
]
_ABBREVIATIONS = {
    "hu": "HundredGigE", "fo": "FortyGigabitEthernet", "twe": "TwentyFiveGigE", "te": "TenGigabitEthernet",
    "fi": "FiveGigabitEthernet", "tw": "TwoGigabitEthernet", "gi": "GigabitEthernet", "fa": "FastEthernet",
    "et": "Ethernet", "eth": "Ethernet", "po": "Port-channel", "vl": "Vlan", "lo": "Loopback",
    "ma": "Management", "mgmt": "Management", "tu": "Tunnel",
}
_NAME = re.compile(r"^([A-Za-z-]+?)\s*(\d[\d/.:]*)$")

# How IOS names a port of each speed class.
_IOS_PREFIX = {"100g": "HundredGigE", "40g": "FortyGigabitEthernet", "25g": "TwentyFiveGigE",
               "10g": "TenGigabitEthernet", "5g": "FiveGigabitEthernet", "2.5g": "TwoGigabitEthernet",
               "1g": "GigabitEthernet", "100m": "FastEthernet"}


def canonical(name: str) -> Tuple[str, InterfaceKind, str]:
    """Canonical name, kind and media of an interface named the Cisco or Arista way (full or abbreviated)."""
    m = _NAME.match(name.strip())
    if not m:
        return name, InterfaceKind.OTHER, ""
    prefix, number = m.group(1), m.group(2)
    full = _ABBREVIATIONS.get(prefix.lower())
    if full is None:
        full = next((p for p, _, _ in _PREFIXES if p.lower() == prefix.lower()), "")
    for p, kind, media in _PREFIXES:
        if p == full:
            if kind == InterfaceKind.ETHERNET:
                if "." in number:
                    return f"Ethernet{number}", InterfaceKind.SUBINTERFACE, media
                return f"Ethernet{number}", kind, media
            if kind == InterfaceKind.LAG and "." in number:
                return f"Port-channel{number}", InterfaceKind.SUBINTERFACE, ""
            return f"{p}{number}", kind, media
    return name, InterfaceKind.OTHER, ""


def read_port_map(text: str) -> Dict[str, str]:
    """A port map file: one ``source = target`` per line, ``#`` starts a comment.

    The source side is the name in the source configuration or the canonical name.
    """
    result: Dict[str, str] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise RoutershiftError(f"port map line {n}: expected 'source = target'")
        left, right = (part.strip() for part in line.split("=", 1))
        result[left] = right
    return result


class PortMapper:
    """Names every interface of a device for the target platform."""

    def __init__(self, device: Device, target: str, overrides: Optional[Dict[str, str]] = None) -> None:
        self.device = device
        self.target = target
        self.overrides = overrides or {}
        self.renumbered: List[Tuple[str, str]] = []  # (source name, target name) chosen without the user
        self._names: Dict[str, str] = {}
        self._assign()

    def __call__(self, canonical_name: str) -> str:
        return self._names.get(canonical_name, canonical_name)

    def _override(self, iface: Interface) -> Optional[str]:
        for key in (iface.source_name, iface.name):
            if key and key in self.overrides:
                return self.overrides[key]
        return None

    def _assign(self) -> None:
        same = self.device.platform == self.target
        index = 0
        physical = [i for i in self.device.interfaces.values() if i.kind == InterfaceKind.ETHERNET]
        three_part = all(i.name.count("/") == 2 for i in physical)
        for iface in self.device.interfaces.values():
            if iface.kind != InterfaceKind.ETHERNET:
                continue
            index += 1
            chosen = self._override(iface)
            if chosen is None:
                if same and iface.source_name:
                    chosen = iface.source_name
                else:
                    chosen = self._default_physical(iface, index, three_part)
                    self.renumbered.append((iface.source_name or iface.name, chosen))
            self._names[iface.name] = chosen
        for iface in self.device.interfaces.values():
            if iface.kind == InterfaceKind.ETHERNET:
                continue
            chosen = self._override(iface)
            if chosen is None:
                chosen = self._default_logical(iface)
            self._names[iface.name] = chosen

    def _default_physical(self, iface: Interface, index: int, three_part: bool) -> str:
        number = iface.name[len("Ethernet"):]
        if self.target == "ios":
            prefix = _IOS_PREFIX.get(iface.media, "GigabitEthernet")
            return f"{prefix}{number}" if three_part else f"{prefix}1/0/{index}"
        # eos: front-panel ports are numbered 1..n
        return f"Ethernet{index}"

    def _default_logical(self, iface: Interface) -> str:
        name = iface.name
        if iface.kind == InterfaceKind.LAG:
            number = name[len("Port-channel"):]
            return f"Port-Channel{number}" if self.target == "eos" else f"Port-channel{number}"
        if iface.kind == InterfaceKind.MANAGEMENT:
            return "Management1" if self.target == "eos" else "GigabitEthernet0/0"
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.parent:
            tag = name.rsplit(".", 1)[1]
            return f"{self(iface.parent)}.{tag}"
        return name
