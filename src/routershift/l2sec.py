# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Layer 2 security helpers that every writer shares: DHCP snooping, ARP inspection, port security, storm control."""

from __future__ import annotations

from typing import Dict, List

from .model import Device, Interface
from .report import Report, Severity

VIOLATIONS = ("shutdown", "restrict", "protect")


def snooping_vlans(device: Device) -> List[int]:
    return sorted(v for v, vlan in device.vlans.items() if vlan.dhcp_snooping)


def snooping_vlans_written(device: Device, report: Report) -> List[int]:
    """The VLANs to snoop on a platform that lists them: those marked, or every VLAN where the source snoops all
    (Comware)."""
    marked = snooping_vlans(device)
    if marked or not device.dhcp_snooping:
        return marked
    if device.vlans:
        report.add("vlan", "DHCP snooping", Severity.APPROX, "dhcp-snooping",
                   "the source snoops every VLAN; the VLANs defined are listed")
    return sorted(device.vlans)


def inspection_vlans(device: Device) -> List[int]:
    return sorted(v for v, vlan in device.vlans.items() if vlan.arp_inspection)


def has_port_settings(iface: Interface) -> bool:
    return bool(iface.dhcp_trust or iface.arp_trust or iface.source_guard or iface.port_security
                or iface.storm_control)


def storm(iface: Interface, unicast: str, offered: List[str], report: Report, label: str,
          platform: str) -> Dict[str, float]:
    """The storm control levels to write, with the unicast kind the platform has ("unicast" on IOS, where it limits
    all unicast, or "unknown-unicast")."""
    result: Dict[str, float] = {}
    for kind, level in iface.storm_control.items():
        if kind in ("unicast", "unknown-unicast"):
            if kind != unicast:
                report.add("interface", label, Severity.APPROX, "storm-unicast",
                           f"storm control on {kind} is written as {unicast}")
            kind = unicast
        if kind in offered:
            result[kind] = level
        else:
            report.add("interface", label, Severity.REVIEW, "storm-control",
                       f"{platform} has no {kind} storm control here; left out")
    return result


def level_text(level: float) -> str:
    return str(int(level)) if level == int(level) else f"{level:g}"


def vlan_text(vlans: List[int], sep: str = ",") -> str:
    return sep.join(str(v) for v in vlans)
