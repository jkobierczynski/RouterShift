# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""MPLS helpers that every writer shares: the LDP router ID as an address or an interface."""

from __future__ import annotations

import ipaddress
from typing import List

from .model import Device, Interface
from .report import Report, Severity

SUPPORTED = ("ios", "eos", "comware")


def has_mpls(device: Device) -> bool:
    return device.mpls.ldp or bool(interfaces(device))


def interfaces(device: Device) -> List[Interface]:
    return [i for i in device.interfaces.values() if i.mpls]


def router_address(device: Device) -> str:
    """The router ID as an address: as given, or the first IPv4 address of the router ID interface."""
    m = device.mpls
    if m.router_id:
        return m.router_id
    iface = device.interfaces.get(m.router_id_interface)
    return iface.ipv4[0].split("/")[0] if iface is not None and iface.ipv4 else ""


def router_interface(device: Device) -> str:
    """The router ID as an interface: as given, or the interface that holds the router ID address."""
    m = device.mpls
    if m.router_id_interface or not m.router_id:
        return m.router_id_interface
    address = ipaddress.ip_address(m.router_id)
    return next((i.name for i in device.interfaces.values()
                 if any(ipaddress.ip_interface(a).ip == address for a in i.ipv4)), "")


def unsupported(device: Device, report: Report, platform: str) -> None:
    """Report MPLS on a target that has none."""
    if not has_mpls(device):
        return
    names = ", ".join(i.source_name or i.name for i in interfaces(device)) or "no interfaces"
    report.add("mpls", "MPLS and LDP", Severity.REVIEW, "mpls-unsupported",
               f"{platform} has no MPLS; LDP on {names} is left out")


def router_id_missing(device: Device, report: Report, wanted: str) -> None:
    m = device.mpls
    if m.router_id or m.router_id_interface:
        report.add("mpls", "LDP router ID", Severity.REVIEW, "mpls-router-id",
                   f"router ID {m.router_id or m.router_id_interface} has no matching {wanted}; set it by hand")
