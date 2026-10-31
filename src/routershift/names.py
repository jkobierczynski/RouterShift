# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Interface names: from each platform's spelling to the canonical one, and back through a port map."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .errors import RoutershiftError
from .model import Device, Interface, InterfaceKind, SwitchportMode

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

_SLOT_BASE = {"aoscx": 1}

# How Comware names a port of each speed class.
_COMWARE_PREFIX = {"100g": "HundredGigE", "40g": "FortyGigE", "25g": "Twenty-FiveGigE", "10g": "Ten-GigabitEthernet",
                   "1g": "GigabitEthernet"}

# How Junos names a port of each speed class.
_JUNOS_PREFIX = {"100g": "et", "40g": "et", "25g": "et", "10g": "xe", "5g": "mge", "2.5g": "mge", "1g": "ge",
                 "100m": "ge"}

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
        physical = [i for i in self.device.interfaces.values() if i.kind == InterfaceKind.ETHERNET]
        # Keep the stack member and port numbers where both sides number ports member/slot/port, unless that makes
        # two ports one (a Catalyst's 1/0/x and its uplinks 1/1/x on AOS-CX); else number the ports in order.
        keep = [self._kept_number(i) for i in physical]
        if None in keep or len(set(keep)) != len(keep):
            keep = [None] * len(physical)
        for index, (iface, kept) in enumerate(zip(physical, keep), 1):
            chosen = self._override(iface)
            if chosen is None:
                if same and iface.source_name:
                    chosen = iface.source_name
                else:
                    chosen = self._default_physical(iface, index, kept)
                    self.renumbered.append((iface.source_name or iface.name, chosen))
            self._names[iface.name] = chosen
        for iface in self.device.interfaces.values():
            if iface.kind == InterfaceKind.ETHERNET:
                continue
            chosen = self._override(iface)
            if chosen is None:
                chosen = self._default_logical(iface)
            self._names[iface.name] = chosen

    def _kept_number(self, iface: Interface) -> Optional[str]:
        """member/slot/port of the port on the target, if it can keep its numbers."""
        parts = iface.name[len("Ethernet"):].split("/")
        if (len(parts) != 3 or not all(p.isdigit() for p in parts) or self.target == "eos"
                or {"junos", "nxos"} & {self.target, self.device.platform}):
            return None
        member, slot, port = (int(p) for p in parts)
        if self.target == "aoss":
            # stack members are member/port; a single switch numbers its ports 1..n
            members = {i.name[len("Ethernet"):].split("/")[0] for i in self.device.interfaces.values()
                       if i.kind == InterfaceKind.ETHERNET}
            return f"{member}/{port}" if len(members) > 1 else str(port)
        # IOS and Comware count the slot of the fixed ports from 0, AOS-CX from 1
        slot += _SLOT_BASE.get(self.target, 0) - _SLOT_BASE.get(self.device.platform, 0)
        return f"{member}/{slot}/{port}"

    def _default_physical(self, iface: Interface, index: int, kept: Optional[str]) -> str:
        if self.target == "ios":
            prefix = _IOS_PREFIX.get(iface.media, "GigabitEthernet")
            return f"{prefix}{kept or f'1/0/{index}'}"
        if self.target == "aoscx":
            return kept or f"1/1/{index}"
        if self.target == "aoss":
            return kept or str(index)
        if self.target == "comware":
            return f"{_COMWARE_PREFIX.get(iface.media, 'GigabitEthernet')}{kept or f'1/0/{index}'}"
        if self.target == "nxos":
            return f"Ethernet1/{index}"
        if self.target == "junos":
            return f"{_JUNOS_PREFIX.get(iface.media, 'ge')}-0/0/{index - 1}"
        # eos: front-panel ports are numbered 1..n
        return f"Ethernet{index}"

    def _default_logical(self, iface: Interface) -> str:
        name = iface.name
        if self.target == "aoscx":
            return self._aoscx_logical(iface)
        if self.target == "aoss":
            return self._aoss_logical(iface)
        if self.target == "comware":
            return self._comware_logical(iface)
        if self.target == "junos":
            return self._junos_logical(iface)
        if self.target == "nxos":
            return self._nxos_logical(iface)
        if iface.kind == InterfaceKind.LAG:
            number = name[len("Port-channel"):]
            return f"Port-Channel{number}" if self.target == "eos" else f"Port-channel{number}"
        if iface.kind == InterfaceKind.MANAGEMENT:
            return "Management1" if self.target == "eos" else "GigabitEthernet0/0"
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.parent:
            tag = name.rsplit(".", 1)[1]
            return f"{self(iface.parent)}.{tag}"
        return name

    def _comware_logical(self, iface: Interface) -> str:
        name = iface.name
        if iface.kind == InterfaceKind.LAG:
            word = "Route-Aggregation" if iface.mode == SwitchportMode.ROUTED else "Bridge-Aggregation"
            return f"{word}{name[len('Port-channel'):]}"
        if iface.kind == InterfaceKind.VLAN:
            return f"Vlan-interface{name[len('Vlan'):]}"
        if iface.kind == InterfaceKind.LOOPBACK:
            return f"LoopBack{name[len('Loopback'):]}"
        if iface.kind == InterfaceKind.MANAGEMENT:
            return "M-GigabitEthernet0/0/0"
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.parent:
            return f"{self(iface.parent)}.{name.rsplit('.', 1)[1]}"
        return name

    def _aoss_logical(self, iface: Interface) -> str:
        name = iface.name
        if iface.kind == InterfaceKind.LAG:
            return f"Trk{name[len('Port-channel'):]}"
        if iface.kind == InterfaceKind.VLAN:
            return f"vlan {name[len('Vlan'):]}"
        if iface.kind == InterfaceKind.LOOPBACK:
            return f"loopback {name[len('Loopback'):]}"
        if iface.kind == InterfaceKind.MANAGEMENT:
            return "oobm"
        return name

    def _aoscx_logical(self, iface: Interface) -> str:
        name = iface.name
        for prefix, word in (("Port-channel", "lag"), ("Vlan", "vlan"), ("Loopback", "loopback")):
            if name.startswith(prefix) and iface.kind != InterfaceKind.SUBINTERFACE:
                return f"{word} {name[len(prefix):]}"
        if iface.kind == InterfaceKind.MANAGEMENT:
            return "mgmt"
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.parent:
            return f"{self(iface.parent)}.{name.rsplit('.', 1)[1]}"
        return name

    def _junos_logical(self, iface: Interface) -> str:
        """Junos names: aeN (numbered from 0), irb.N, lo0.N, me0; a unit of its port for a subinterface."""
        name = iface.name
        if iface.kind == InterfaceKind.LAG:
            return f"ae{max(int(name[len('Port-channel'):]) - 1, 0)}"
        if iface.kind == InterfaceKind.VLAN:
            return f"irb.{name[len('Vlan'):]}"
        if iface.kind == InterfaceKind.LOOPBACK:
            return f"lo0.{name[len('Loopback'):]}"
        if iface.kind == InterfaceKind.MANAGEMENT:
            return "me0"
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.parent:
            return f"{self(iface.parent)}.{name.rsplit('.', 1)[1]}"
        return name

    def _nxos_logical(self, iface: Interface) -> str:
        """NX-OS names: port-channelN, VlanN, loopbackN, mgmt0."""
        name = iface.name
        if iface.kind == InterfaceKind.LAG:
            return f"port-channel{name[len('Port-channel'):]}"
        if iface.kind == InterfaceKind.LOOPBACK:
            return f"loopback{name[len('Loopback'):]}"
        if iface.kind == InterfaceKind.MANAGEMENT:
            return "mgmt0"
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.parent:
            return f"{self(iface.parent)}.{name.rsplit('.', 1)[1]}"
        return name
