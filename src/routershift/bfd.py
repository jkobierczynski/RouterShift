# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""BFD and policy-based routing helpers that every reader and writer shares."""

from __future__ import annotations

import ipaddress
from typing import List, Tuple

from .model import Device, Interface, Ospf
from .report import Report, Severity

_SEPARATE = {"min-transmit-interval": "bfd_interval", "min-receive-interval": "bfd_min_rx",
             "detect-multiplier": "bfd_multiplier"}


def separate_line(iface: Interface, w: List[str]) -> bool:
    """bfd min-transmit-interval|min-receive-interval|detect-multiplier N (AOS-CX, Comware)."""
    if len(w) == 3 and w[0] == "bfd" and w[1] in _SEPARATE and w[2].isdigit():
        setattr(iface, _SEPARATE[w[1]], int(w[2]))
        return True
    return False


def separate_lines(iface: Interface) -> List[str]:
    return [f"bfd {word} {getattr(iface, attr)}" for word, attr in _SEPARATE.items()
            if getattr(iface, attr) is not None]


def has_timers(iface: Interface) -> bool:
    return any(v is not None for v in (iface.bfd_interval, iface.bfd_min_rx, iface.bfd_multiplier))


def joined_line(iface: Interface, platform: str, report: Report, label: str) -> List[str]:
    """IOS and EOS: bfd interval T min_rx|min-rx R multiplier M, all three or none (defaults filled in)."""
    if not has_timers(iface):
        return []
    values = [iface.bfd_interval, iface.bfd_min_rx, iface.bfd_multiplier]
    if None in values:
        report.add("interface", label, Severity.APPROX, "bfd-timers",
                   "BFD takes interval, receive interval and multiplier together; the missing ones are 50 ms and 3")
    t, r, m = (v if v is not None else d for v, d in zip(values, (50, 50, 3)))
    return [f"bfd interval {t} {'min_rx' if platform == 'ios' else 'min-rx'} {r} multiplier {m}"]


def ospf_interfaces(device: Device) -> List[str]:
    """Interfaces with BFD for OSPF, the 'all interfaces' setting spread over the OSPF interfaces."""
    def in_ospf(i: Interface, p: Ospf) -> bool:
        if i.name in p.interface_areas:
            return True
        addresses = [ipaddress.ip_interface(a).ip for a in i.ipv4]
        return any(a in ipaddress.ip_network(n.prefix) for n in p.networks for a in addresses)
    return [i.name for i in device.interfaces.values()
            if i.ospf_bfd or any(p.bfd_all and in_ospf(i, p) for p in device.ospf)]


def uses_bfd(device: Device) -> bool:
    bgp = device.bgp
    return any(has_timers(i) or i.ospf_bfd for i in device.interfaces.values()) or \
        any(p.bfd_all for p in device.ospf) or \
        bgp is not None and any(n.bfd for n in list(bgp.peer_groups.values()) + bgp.neighbors)


def unsupported(device: Device, report: Report, platform: str) -> None:
    """A target that writes no BFD and no policy-based routing."""
    if uses_bfd(device):
        report.add("system", "BFD", Severity.REVIEW, "bfd-unsupported",
                   f"{platform}: BFD is not written; routing protocols detect failures with their own timers")
    pbr_unsupported(device, report, platform)


def pbr_unsupported(device: Device, report: Report, platform: str) -> None:
    for iface in device.interfaces.values():
        if iface.pbr:
            report.add("interface", iface.name, Severity.REVIEW, "pbr-unsupported",
                       f"{platform}: policy-based routing with route map {iface.pbr} is not written; configure it by "
                       "hand")


def pbr_maps(device: Device) -> List[str]:
    """Route maps applied for policy-based routing, in interface order."""
    names: List[str] = []
    for iface in device.interfaces.values():
        if iface.pbr and iface.pbr not in names:
            names.append(iface.pbr)
    return names


def routing_maps(device: Device) -> List[str]:
    """Route maps that filter routes (BGP neighbors, redistribution)."""
    names = [m for p in device.ospf for m in p.redistribute_maps.values()]
    bgp = device.bgp
    if bgp is not None:
        names += list(bgp.redistribute_maps.values())
        for n in list(bgp.peer_groups.values()) + bgp.neighbors:
            names += [n.route_map_in, n.route_map_out]
    return [n for n in names if n]


def pbr_only(device: Device) -> List[str]:
    """Route maps used for policy-based routing and nothing else: written in the target's PBR form only."""
    routing = set(routing_maps(device))
    return [n for n in pbr_maps(device) if n not in routing]


def pbr_entries(device: Device, name: str, report: Report, platform: str) -> List[Tuple[int, List[str], str]]:
    """(sequence, ACLs, next hop) of each permit entry of a PBR route map; what a PBR policy cannot hold is
    reported."""
    rm = device.route_maps.get(name)
    label = f"route-map {name}"
    if rm is None:
        report.add("policy", label, Severity.REVIEW, "pbr-missing",
                   f"route map {name} is applied for policy-based routing but not defined; left out")
        return []
    result = []
    for e in rm.entries:
        other = [k for k in e.sets if k != "next-hop"]
        if e.action.value == "deny":
            report.add("policy", label, Severity.REVIEW, "pbr-entry",
                       f"entry {e.seq} denies (its packets are routed normally); left out of the {platform} policy")
            continue
        if e.match_prefix_lists or e.match_prefix_lists6 or e.match_tags or other:
            report.add("policy", label, Severity.REVIEW, "pbr-entry",
                       f"{platform} policy-based routing matches ACLs and sets a next hop; entry {e.seq} holds more "
                       "and is written with those only")
        result.append((e.seq, list(e.match_acls), e.sets.get("next-hop", "")))
    return result
