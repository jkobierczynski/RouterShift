# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""First-hop redundancy (HSRP, VRRP, anycast gateways): what each target can hold, and the conversions between them
that every writer shares."""

from __future__ import annotations

import copy
import ipaddress
import re
from typing import Callable, Dict, List, Optional, Set

from .model import FhrpGroup, Interface
from .report import Report, Severity

SUPPORTED: Dict[str, Set[str]] = {
    "ios": {"hsrp", "vrrp"},
    "eos": {"vrrp", "anycast"},
    "aoscx": {"vrrp", "anycast"},
    "aoss": {"vrrp"},
    "comware": {"vrrp"},
    "nxos": {"hsrp", "vrrp"},
}

Add = Callable[[Severity, str, str], None]


def label(iface_name: str, group: FhrpGroup) -> str:
    if group.protocol == "anycast":
        return f"{iface_name} anycast {group.address}"
    return f"{iface_name} {group.protocol.upper()} {group.group}"


def mac(text: str) -> str:
    """A MAC address in any of the usual spellings as "xx:xx:xx:xx:xx:xx"."""
    digits = re.sub(r"[^0-9a-fA-F]", "", text).lower()
    if len(digits) != 12:
        raise ValueError(f"not a MAC address: {text}")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def owns(iface: Interface, group: FhrpGroup) -> bool:
    """The virtual address is the interface's own: the VRRP address owner."""
    return any(str(ipaddress.ip_interface(a).ip) == group.address for a in iface.ipv4)


def plan(iface: Interface, target: str, report: Report, name: str) -> List[FhrpGroup]:
    """The groups of an interface as the target can hold them: HSRP and anycast gateways become VRRP where the target
    lacks them, with group numbers and priorities in range. Each group is registered in the report."""
    out: List[FhrpGroup] = []
    taken = {g.group for g in iface.fhrp if g.protocol == "vrrp"}
    for source in iface.fhrp:
        group = copy.deepcopy(source)
        item = label(name, group)
        found = []

        def add(severity: Severity, code: str, message: str) -> None:
            found.append((severity, code, message))

        if group.protocol not in SUPPORTED[target]:
            group.protocol = "vrrp"
            group.preempt = source.preempts()
            group.version = None
            if not 1 <= group.group <= 255 or (source.protocol != "vrrp" and group.group in taken):
                group.group = min(set(range(1, 256)) - taken)
            taken.add(group.group)
            if source.protocol == "hsrp":
                add(Severity.APPROX, "fhrp-protocol",
                    f"HSRP group {source.group} becomes VRRP group {group.group}, as {target} has no HSRP; "
                    "move every router of the group at once")
                if source.hold_ms is not None:
                    add(Severity.APPROX, "fhrp-hold", "HSRP hold time dropped: VRRP derives it from the interval")
                    group.hold_ms = None
            else:
                add(Severity.REVIEW, "fhrp-anycast",
                    f"anycast gateway {source.address} becomes VRRP group {group.group}: one router forwards "
                    "instead of both; configure the peer the same way")
                group.mac = ""
        if group.protocol == "vrrp" and group.priority is not None and not 1 <= group.priority <= 254:
            group.priority = min(max(group.priority, 1), 254)
            add(Severity.APPROX, "fhrp-priority",
                f"priority {source.priority} out of the VRRP range, written as {group.priority}")
        item = label(name, group) if group.protocol != source.protocol else item
        report.item("fhrp", item)
        for severity, code, message in found:
            report.add("fhrp", item, severity, code, message)
        out.append(group)
    return out


def interval(ms: int, unit_ms: int, add: Add, low: int = 1, high: Optional[int] = None) -> int:
    """An interval in the target's unit (1000 for seconds, 10 for centiseconds), rounded and kept in range."""
    value = max(low, round(ms / unit_ms))
    if high is not None:
        value = min(value, high)
    if value * unit_ms != ms:
        add(Severity.APPROX, "fhrp-timer", f"interval {ms} ms written as {value * unit_ms} ms")
    return value


def adder(report: Report, name: str, group: FhrpGroup) -> Add:
    item = label(name, group)

    def add(severity: Severity, code: str, message: str) -> None:
        report.add("fhrp", item, severity, code, message)
    return add
