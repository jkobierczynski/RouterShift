# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""The DNS client beyond its servers (lookup switch, search list, source, static hosts) and PoE on the ports."""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple

from .model import Device, Interface
from .report import Report, Severity

DNS = "DNS client"
PRIORITIES = ("low", "medium", "high", "critical")

Add = Callable[[Severity, str, str], None]


def dns_stated(device: Device) -> bool:
    s = device.system
    return s.dns_lookup is not None or bool(s.dns_search or s.dns_source or s.dns_hosts)


def dns_unsupported(device: Device, report: Report, platform: str, lookup: bool = False, search: bool = False,
                    source: bool = False, hosts: bool = False) -> None:
    """Registers the DNS client item and reports the settings the target has no place for (the flags say which it
    has)."""
    s = device.system
    if not dns_stated(device):
        return
    report.item("system", DNS)
    missing: List[str] = []
    if s.dns_lookup is False and not lookup:
        missing.append("switching name lookup off")
    if s.dns_search and not search:
        missing.append(f"the search domains {', '.join(s.dns_search)}")
    if s.dns_source and not source:
        missing.append(f"the source interface {s.dns_source}")
    if s.dns_hosts and not hosts:
        missing.append(f"the static hosts {', '.join(s.dns_hosts)}")
    if missing:
        report.add("system", DNS, Severity.REVIEW, "dns-unsupported",
                   f"{platform} has no setting for {'; '.join(missing)}; left out")


def poe_stated(iface: Interface) -> bool:
    return iface.poe is not None or bool(iface.poe_priority) or iface.poe_max_mw is not None


def poe_priority(iface: Interface, allowed: Tuple[str, ...], add: Add, platform: str) -> str:
    """The port's PoE priority among the ones a target has: the nearest one, reported when it differs."""
    wanted = iface.poe_priority
    if not wanted or wanted in allowed:
        return wanted
    rank = PRIORITIES.index(wanted)
    nearest = min(allowed, key=lambda p: (abs(PRIORITIES.index(p) - rank), -PRIORITIES.index(p)))
    add(Severity.APPROX, "poe-priority", f"PoE priority {wanted} written as {nearest}, the nearest {platform} has")
    return nearest


def poe_limit(iface: Interface, add: Add, platform: str, supported: bool) -> Optional[int]:
    if iface.poe_max_mw is None or supported:
        return iface.poe_max_mw
    add(Severity.REVIEW, "poe-limit", f"{platform}: the PoE limit of {iface.poe_max_mw / 1000:g} W is not written; "
        "set it by hand")
    return None


def watts(mw: int) -> str:
    return f"{mw / 1000:g}"
