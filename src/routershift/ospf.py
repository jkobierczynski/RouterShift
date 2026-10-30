# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""OSPF helpers that every reader and writer shares: area numbers, and which interfaces a process runs on."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

from .model import Device, Interface, Ospf, OspfNetwork

REDISTRIBUTE = ("connected", "static", "bgp")


def area(text: str) -> str:
    """An area in dotted form: "0" and "0.0.0.0" are both "0.0.0.0"; AOS-S calls it "backbone"."""
    if text == "backbone":
        return "0.0.0.0"
    if text.isdigit():
        return str(ipaddress.IPv4Address(int(text)))
    return str(ipaddress.IPv4Address(text))


def area_number(dotted: str) -> str:
    """The decimal form IOS shows: "0.0.0.1" is "1"."""
    return str(int(ipaddress.IPv4Address(dotted)))


def process(device: Device, number: str = "", vrf: str = "") -> Ospf:
    """The process with this number, or else the one of this VRF; created when there is none."""
    for p in device.ospf:
        if number and p.process == number:
            return p
    if not number:
        for p in device.ospf:
            if p.vrf == vrf:
                return p
    p = Ospf(process=number or "1", vrf=vrf)
    device.ospf.append(p)
    return p


def interfaces(device: Device, p: Ospf) -> Dict[str, str]:
    """Every interface the process runs on, with its area: set on the interface, or matched by the most specific
    network statement that holds one of its addresses."""
    result: Dict[str, str] = {}
    for iface in device.interfaces.values():
        if iface.name in p.interface_areas:
            result[iface.name] = p.interface_areas[iface.name]
            continue
        if iface.vrf != p.vrf:
            continue
        match = _network(iface, p.networks)
        if match is not None:
            result[iface.name] = match.area
    return result


def _network(iface: Interface, networks: List[OspfNetwork]) -> Optional[OspfNetwork]:
    best: Optional[OspfNetwork] = None
    for cidr in iface.ipv4:
        ip = ipaddress.ip_interface(cidr).ip
        for network in networks:
            net = ipaddress.ip_network(network.prefix)
            if ip in net and (best is None or net.prefixlen > ipaddress.ip_network(best.prefix).prefixlen):
                best = network
    return best


def label(p: Ospf) -> str:
    return f"ospf {p.process}" + (f" vrf {p.vrf}" if p.vrf else "")


def rename(p: Ospf, mapping: Dict[str, str]) -> None:
    """Follow interfaces a reader renamed after reading the process."""
    p.interface_areas = {mapping.get(k, k): v for k, v in p.interface_areas.items()}
    p.passive_interfaces = [mapping.get(n, n) for n in p.passive_interfaces]
    p.active_interfaces = [mapping.get(n, n) for n in p.active_interfaces]


def attach(device: Device, areas: List[Tuple[str, str, str]], passive: Dict[str, bool]) -> None:
    """Settings read on interfaces, given to their process once every process is read: areas as (interface, process
    or "" for the interface's VRF, area), and passive (True) or active (False) interfaces."""
    for name, number, dotted in areas:
        vrf = device.interfaces[name].vrf if name in device.interfaces else ""
        process(device, number, vrf).interface_areas[name] = dotted
    for name, value in passive.items():
        vrf = device.interfaces[name].vrf if name in device.interfaces else ""
        p = next((p for p in device.ospf if name in p.interface_areas), None) or next(
            (p for p in device.ospf if p.vrf == vrf), None)
        if p is None:
            continue
        if value and not p.passive_default:
            p.passive_interfaces.append(name)
        elif not value and p.passive_default:
            p.active_interfaces.append(name)
