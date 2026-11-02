# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NX-OS multicast: IGMP snooping and its querier, PIM with its rendezvous points (also in VRFs), anycast RP, MSDP.

How the model maps to NX-OS:

* IGMP snooping is on by default; a VLAN that does not snoop says so under ``vlan configuration N``, where the
  querier is ``ip igmp snooping querier A`` (NX-OS needs the source address).
* Multicast routing is ``feature pim`` with ``ip pim sparse-mode`` on the interfaces; there is no global switch, and a
  VRF routes multicast where its interfaces run PIM. A rendezvous point is ``ip pim rp-address A [group-list G]``,
  globally or in the VRF's ``vrf context``.
* Anycast RP is native: ``ip pim anycast-rp A PEER`` for each RP that shares the address. MSDP is ``feature msdp``
  with ``ip msdp peer A connect-source I``.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Set

from . import multicast as multicast_text
from .model import Device, Interface
from .report import Report, Severity

LABEL = multicast_text.LABEL
Add = Callable[[Severity, str, str], None]
Name = Callable[[str], str]


def snooping_lines(device: Device, report: Report, ind: str) -> List[str]:
    d = device
    if not multicast_text.stated(d):
        return []
    report.item("vlan", LABEL)
    lines: List[str] = []
    if d.igmp_snooping is False:
        return ["no ip igmp snooping"]
    if d.igmp_snooping:
        lines.append("ip igmp snooping")
    on = multicast_text.snooped(d)
    queriers = multicast_text.queriers(d)
    for vid in sorted(d.vlans):
        body: List[str] = []
        if vid not in on:
            body.append("no ip igmp snooping")
        elif vid in queriers:
            vl = d.vlans[vid]
            address = vl.igmp_querier_address or d.igmp_querier_address or _svi_address(d, vid)
            if address:
                body.append(f"ip igmp snooping querier {address}")
                if not (vl.igmp_querier_address or d.igmp_querier_address):
                    report.add("vlan", LABEL, Severity.APPROX, "igmp-querier-address",
                               f"VLAN {vid}: NX-OS names the querier's source address; the SVI's {address} is written")
            else:
                report.add("vlan", LABEL, Severity.REVIEW, "igmp-querier-address",
                           f"VLAN {vid}: NX-OS needs a source address for the querier and the VLAN has no SVI address; "
                           "add 'ip igmp snooping querier A' by hand")
            if vl.igmp_querier_version or d.igmp_querier_version:
                report.add("vlan", LABEL, Severity.APPROX, "igmp-querier-version",
                           f"VLAN {vid}: the querier version ({vl.igmp_querier_version or d.igmp_querier_version}) is "
                           "left out; NX-OS queries with the version of the IGMP snooping it runs")
        if body:
            lines += [f"vlan configuration {vid}"] + [ind + b for b in body]
    return lines


def _svi_address(device: Device, vid: int) -> str:
    svi = device.interfaces.get(f"Vlan{vid}")
    addresses = (svi.ipv4 or svi.virtual_ipv4) if svi is not None else []
    return str(ipaddress.ip_interface(addresses[0]).ip) if addresses else ""


def rp_lines(rps: List[str], rp_groups: Dict[str, str], report: Report, ind: str = "") -> List[str]:
    lines: List[str] = []
    for rp in rps:
        groups = rp_groups.get(rp, "")
        if groups.startswith("acl "):
            lines.append(f"{ind}ip pim rp-address {rp}")
            report.add("system", "multicast routing", Severity.REVIEW, "pim-rp-acl",
                       f"rendezvous point {rp} serves the groups of ACL {groups[4:]}; NX-OS takes a group-list prefix "
                       "or a prefix list, so it is written for all groups: narrow it by hand")
        else:
            lines.append(f"{ind}ip pim rp-address {rp}" + (f" group-list {groups}" if groups else ""))
    return lines


def lines(device: Device, report: Report, port: Name, features: Set[str]) -> List[str]:
    """The global PIM, anycast RP and MSDP lines."""
    d = device
    out: List[str] = []
    vrf_routing = [name for name, m in d.multicast_vrfs.items() if m.routing or m.rps]
    pim_ports = any(i.pim for i in d.interfaces.values())
    if d.multicast_routing or vrf_routing or d.pim_rps or pim_ports:
        report.item("system", "multicast routing")
        features.add("pim")
    out += rp_lines(d.pim_rps, d.pim_rp_groups, report)
    out += [f"ip pim anycast-rp {a} {p}" for a, peers in d.pim_anycast.items() for p in peers]
    if d.msdp_peers:
        features.add("msdp")
    for peer, source in d.msdp_peers.items():
        if source:
            out.append(f"ip msdp peer {peer} connect-source {port(source)}")
        else:
            out.append(f"ip msdp peer {peer}")
            report.add("system", "multicast routing", Severity.REVIEW, "msdp-source",
                       f"MSDP peer {peer} has no connect-source in the source; NX-OS needs one: add it")
    for name, m in d.multicast_vrfs.items():
        if m.routing and not m.rps and not any(i.pim and i.vrf == name for i in d.interfaces.values()):
            report.add("system", "multicast routing", Severity.APPROX, "multicast-vrf",
                       f"NX-OS routes multicast in VRF {name} where its interfaces run PIM; none of them does in the "
                       "source, so nothing is written for it")
    return out


def vrf_lines(device: Device, name: str, report: Report, ind: str) -> List[str]:
    m = device.multicast_vrfs.get(name)
    if m is None:
        return []
    return rp_lines(m.rps, m.rp_groups, report, ind)


def interface_lines(iface: Interface, add: Add) -> List[str]:
    out: List[str] = []
    if iface.pim:
        out.append("ip pim sparse-mode")
        if iface.pim != "sparse":
            add(Severity.APPROX, "pim-mode", f"PIM {iface.pim} mode written as sparse mode, the one NX-OS runs")
    if iface.igmp_version is not None:
        out.append(f"ip igmp version {iface.igmp_version}")
    return out


# reading ------------------------------------------------------------------------------------------------------------

def read_pim(device: Device, vrf_name: str, w: List[str]) -> bool:
    """ip pim rp-address A [group-list G] | ip pim anycast-rp A P (w starts after 'ip pim')."""
    if w[0] == "rp-address" and len(w) in (2, 4) and (len(w) == 2 or w[2] == "group-list"):
        rp = str(ipaddress.IPv4Address(w[1]))
        groups = str(ipaddress.IPv4Network(w[3])) if len(w) == 4 else ""
        multicast_text.add_rp(device, vrf_name, rp, groups)
        if vrf_name:
            multicast_text.vrf(device, vrf_name).routing = True
        return True
    if w[0] == "anycast-rp" and len(w) == 3 and not vrf_name:
        device.pim_anycast.setdefault(str(ipaddress.IPv4Address(w[1])), []).append(str(ipaddress.IPv4Address(w[2])))
        return True
    return False


def read_vlan_configuration(device: Device, vid: int, w: List[str]) -> bool:
    vlan = device.vlans.get(vid)
    if vlan is None:
        return False
    if w == ["no", "ip", "igmp", "snooping"]:
        vlan.igmp_snooping = False
    elif w[:4] == ["ip", "igmp", "snooping", "querier"] and len(w) == 5:
        vlan.igmp_querier = True
        vlan.igmp_querier_address = str(ipaddress.IPv4Address(w[4]))
    else:
        return False
    return True
