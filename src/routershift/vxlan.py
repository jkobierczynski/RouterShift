# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""VXLAN and BGP EVPN: the helpers every reader and writer shares."""

from __future__ import annotations

import ipaddress
from typing import List

from .model import Device, Vxlan
from .report import Report, Severity

LABEL = "VXLAN"
PORT = 4789


def vtep(device: Device) -> Vxlan:
    if device.vxlan is None:
        device.vxlan = Vxlan()
    return device.vxlan


def source_address(device: Device) -> str:
    """The address of the source interface (AOS-CX takes an address)."""
    iface = device.interfaces.get(device.vxlan.source_interface) if device.vxlan else None
    return str(ipaddress.ip_interface(iface.ipv4[0]).ip) if iface is not None and iface.ipv4 else ""


def interface_of(device: Device, address: str) -> str:
    """The interface that holds an address (AOS-CX names the source by its address)."""
    ip = ipaddress.ip_address(address)
    return next((i.name for i in device.interfaces.values()
                 if any(ipaddress.ip_interface(a).ip == ip for a in i.ipv4)), "")


def evpn_neighbors(device: Device) -> List[str]:
    if device.bgp is None:
        return []
    return [n.address for n in list(device.bgp.peer_groups.values()) + device.bgp.neighbors if "evpn" in n.families]


def item(device: Device, report: Report) -> None:
    vx = device.vxlan
    if vx is None:
        return
    report.item("interface", LABEL)
    if vx.udp_port not in (None, PORT):
        report.add("interface", LABEL, Severity.REVIEW, "vxlan-port",
                   f"UDP port {vx.udp_port} is not written; the target uses {PORT}")


def unsupported(device: Device, report: Report, platform: str) -> None:
    """A target that writes no VXLAN; EVPN neighbors are reported with it."""
    if device.vxlan is not None:
        report.skip("interface", LABEL, "vxlan-unsupported",
                    f"{platform}: VXLAN (VNIs {', '.join(str(v) for v in vnis(device))}) is not written; configure it "
                    "by hand")
    if evpn_neighbors(device):
        report.add("bgp", f"bgp {device.bgp.local_as}" if device.bgp else "bgp", Severity.REVIEW, "evpn-unsupported",
                   f"{platform}: the EVPN address family of {', '.join(evpn_neighbors(device))} is not written")


def vnis(device: Device) -> List[int]:
    vx = device.vxlan
    return sorted(list(vx.vlan_vnis.values()) + list(vx.vrf_vnis.values())) if vx else []
