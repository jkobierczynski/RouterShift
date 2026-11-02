# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AOS-CX data-centre fabric: EVPN instances, VSX and VSF options, VRF route targets and leaking, BGP options.

How the model maps to AOS-CX:

* An EVPN instance is a VLAN under ``evpn`` with its ``rd`` and ``route-target`` lines. AOS-CX has VLAN-based
  instances only: the VLANs of a VLAN-aware bundle are written each on their own, with the bundle's route targets.
* VXLAN floods to the other VTEPs by head-end replication; an underlay multicast group has no AOS-CX form.
* An MLAG pair is a VSX pair: the MLAG heartbeat (a second path, usually the management network) is the VSX keepalive,
  the reload delay of the MLAG ports ``linkup-delay-timer``. StackWise Virtual makes two switches one; AOS-CX does that
  with VSF (``vsf member``), whose links are the StackWise Virtual links.
* The route targets of a VRF that EVPN carries end in ``evpn``. Routes leaked from another VRF are imported with that
  VRF's export route targets, the nearest AOS-CX form.
* BGP timers, graceful restart, distances, the best-path options and aggregates keep their IOS-like spelling.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional

from . import vrfs as vrfs_text
from .model import Bgp, BgpAggregate, Device, EvpnInstance, Interface, Mlag, VrfInfo
from .report import Report, Severity

LINKUP_MAX = 600  # seconds, the most AOS-CX takes for linkup-delay-timer
GR_DEFAULT = 120


# writing ------------------------------------------------------------------------------------------------------------

def evpn_lines(device: Device, report: Report, ind: str, label: str) -> List[str]:
    """The evpn block: one VLAN-based instance per VLAN EVPN advertises."""
    vx = device.vxlan
    if vx is None or not vx.evpn_vlans:
        return []
    by_vlan: Dict[int, EvpnInstance] = {v: i for i in vx.evpn_instances.values() for v in i.vlans}
    lines = ["evpn"]
    for vid in vx.evpn_vlans:
        inst = by_vlan.get(vid)
        lines.append(f"{ind}vlan {vid}")
        lines.append(f"{ind * 2}rd {inst.rd if inst is not None and inst.rd and not inst.bundle else 'auto'}")
        imports = inst.rt_import if inst is not None else []
        exports = inst.rt_export if inst is not None else []
        lines += [f"{ind * 2}route-target {d} {v}"
                  for d, v in vrfs_text.targets(VrfInfo(rt_import=imports, rt_export=exports))]
        if not exports:
            lines.append(f"{ind * 2}route-target export auto")
        if not imports:
            lines.append(f"{ind * 2}route-target import auto")
    for inst in vx.evpn_instances.values():
        if inst.bundle:
            report.add("interface", label, Severity.APPROX, "evpn-bundle",
                       f"AOS-CX has VLAN-based EVPN instances only: the VLANs of bundle {inst.name} "
                       f"({', '.join(str(v) for v in inst.vlans)}) are written each with rd auto and the bundle's "
                       "route targets" + (f"; its route distinguisher {inst.rd} is left out" if inst.rd else ""))
        if inst.igmp:
            report.add("interface", label, Severity.REVIEW, "evpn-igmp",
                       f"instance {inst.name} advertises IGMP joins as EVPN routes; not written for AOS-CX, which "
                       "floods multicast to the VTEPs")
    if vx.mcast_groups:
        report.add("interface", label, Severity.APPROX, "vxlan-mcast",
                   "AOS-CX floods broadcast and unknown traffic to the other VTEPs by head-end replication: the "
                   "underlay multicast groups of VLANs " + ", ".join(f"{v} ({g})" for v, g in vx.mcast_groups.items())
                   + " are left out")
    return lines


def evpn_domain(device: Device, report: Report) -> None:
    bgp = device.bgp
    if bgp is None:
        return
    label = f"bgp {bgp.local_as}"
    if bgp.evpn_domain or bgp.evpn_remote_peers:
        report.add("bgp", label, Severity.REVIEW, "evpn-domain",
                   "AOS-CX has no EVPN domain gateway: the domain identifiers are left out and the neighbors of the "
                   "remote domain (" + ", ".join(bgp.evpn_remote_peers or ["none"]) + ") are ordinary EVPN neighbors")
    if bgp.evpn_host_flap:
        window, moves, expiry = bgp.evpn_host_flap
        report.add("bgp", label, Severity.APPROX, "evpn-host-flap",
                   f"MAC-move detection ({moves} moves in {window} seconds, {expiry} seconds) is left out: AOS-CX "
                   "uses its own MAC-move limits")


def vsx_options(device: Device, report: Report, label: str, vrf: Callable[[str], str]) -> List[str]:
    """The keepalive over the heartbeat path, and the link-up delay; what VSX has no setting for is reported."""
    m = device.mlag
    assert m is not None
    lines: List[str] = []
    if m.reload_delay is not None:
        delay = min(m.reload_delay, LINKUP_MAX)
        lines.append(f"linkup-delay-timer {delay}")
        if delay != m.reload_delay:
            report.add("interface", label, Severity.APPROX, "vsx-linkup",
                       f"the reload delay of {m.reload_delay} seconds is written as {LINKUP_MAX}, the AOS-CX limit")
    if m.reload_delay_non_mlag is not None:
        report.add("interface", label, Severity.APPROX, "vsx-linkup",
                   f"VSX delays the multi-chassis LAGs only: the reload delay of {m.reload_delay_non_mlag} seconds "
                   "for the other ports is left out")
    if m.dual_primary_delay is not None:
        report.add("interface", label, Severity.APPROX, "vsx-split",
                   "VSX detects a split through the keepalive and the secondary takes its multi-chassis LAGs down: "
                   f"the dual-primary detection delay ({m.dual_primary_delay} s"
                   + (f", {m.dual_primary_action}" if m.dual_primary_action else "") + ") is left out")
    return lines


def heartbeat_keepalive(device: Device, report: Report, label: str, vrf: Callable[[str], str]) -> Optional[str]:
    """keepalive peer HEARTBEAT source OWN vrf V, when the switch has an address in the heartbeat's VRF."""
    m = device.mlag
    if m is None or not m.heartbeat:
        return None
    own = [i for i in device.interfaces.values() if i.vrf == m.heartbeat_vrf and i.ipv4]
    if not own:
        report.add("interface", label, Severity.REVIEW, "mlag-heartbeat",
                   f"the heartbeat {m.heartbeat} has no source address in VRF {m.heartbeat_vrf or 'default'}; set the "
                   "VSX keepalive by hand")
        return None
    report.add("interface", label, Severity.APPROX, "mlag-heartbeat",
               f"the MLAG heartbeat {m.heartbeat} is written as the VSX keepalive (over {own[0].name}); the MLAG "
               "peer address on the peer link is left out, as VSX keeps its keepalive off the inter-switch link")
    where = f" vrf {vrf(m.heartbeat_vrf)}" if m.heartbeat_vrf else ""
    return f"keepalive peer {m.heartbeat} source {own[0].ipv4[0].split('/')[0]}{where}"


def vsf_lines(device: Device, report: Report, ind: str, port: Callable[[str], str]) -> List[str]:
    """StackWise Virtual as VSF: each member's links, and split detection over the management port."""
    m = device.mlag
    assert m is not None
    label = "multi-chassis LAG"
    report.item("interface", label)
    members: Dict[int, List[str]] = {}
    links: Dict[int, Dict[int, List[str]]] = {}
    for iface in device.interfaces.values():
        if iface.svl_link is None:
            continue
        name = port(iface.name)
        member = int(name.split("/")[0]) if re.match(r"\d+/\d+/\d+$", name) else 1
        links.setdefault(member, {}).setdefault(iface.svl_link, []).append(name)
        members.setdefault(member, [])
    lines: List[str] = []
    for member in sorted(links):
        lines.append(f"vsf member {member}")
        lines += [f"{ind}link {n} {','.join(names)}" for n, names in sorted(links[member].items())]
    if any(i.svl_dad for i in device.interfaces.values()):
        lines.append("vsf split-detect mgmt")
        report.add("interface", label, Severity.APPROX, "vsf-split",
                   "the dual-active detection ports are replaced by VSF split detection over the management port")
    report.add("interface", label, Severity.REVIEW, "vsf",
               "StackWise Virtual is written as VSF, the nearest AOS-CX feature (6200 and 6300 switches): check the "
               "member numbers and link ports" + (f"; the domain {m.domain} has no VSF form" if m.domain else ""))
    return lines


def trunk_groups(device: Device, report: Report, port: Callable[[str], str]) -> None:
    for vlan in device.vlans.values():
        if vlan.trunk_groups:
            report.add("vlan", str(vlan.vlan_id), Severity.APPROX, "trunk-group",
                       f"trunk group {', '.join(vlan.trunk_groups)} left out: AOS-CX has no trunk groups, the VLAN is "
                       "carried by every trunk that allows it")


def interface_notes(iface: Interface, add: Callable[[Severity, str, str], None]) -> None:
    if iface.trunk_groups:
        add(Severity.APPROX, "trunk-group",
            f"trunk groups {', '.join(iface.trunk_groups)} left out: the port carries the VLANs of its allowed list")
    if iface.evpn_esi or iface.lacp_system_id:
        what = ", ".join(x for x in (f"ethernet segment {iface.evpn_esi}" if iface.evpn_esi else "",
                                     f"LACP system ID {iface.lacp_system_id}" if iface.lacp_system_id else "") if x)
        add(Severity.REVIEW, "evpn-es",
            f"AOS-CX makes a LAG active on two switches with VSX (a multi-chassis LAG), not with an EVPN ethernet "
            f"segment: {what} left out")


def vrf_targets(device: Device, name: str, info: VrfInfo, report: Report) -> List[str]:
    """route-target lines of a VRF, with the export route targets of the VRFs it leaks routes from."""
    label = f"vrf {name}"
    pairs = [(d, v, info.rt_evpn) for d, v in vrfs_text.targets(info)]
    for source, rmap in info.leaks.items():
        src = device.vrf_info.get(source)
        if src is None or not src.rt_export:
            report.add("system", label, Severity.REVIEW, "vrf-leak",
                       f"the routes leaked from VRF {source}: that VRF exports no route targets to import; set the "
                       "leaking up by hand")
            continue
        for value in src.rt_export:
            if value not in info.rt_import:
                pairs.append(("import", value, src.rt_evpn))
        report.add("system", label, Severity.APPROX, "vrf-leak",
                   f"the routes leaked from VRF {source} are imported with its export route targets "
                   f"({', '.join(src.rt_export)}): only the routes it has in BGP are leaked"
                   + (f", and route map {rmap} is left out" if rmap else ""))
        if not info.rd:
            report.add("system", label, Severity.REVIEW, "vrf-leak",
                       "a VRF imports route targets only with a route distinguisher: add one")
    if info.export_map:
        report.add("system", label, Severity.REVIEW, "vrf-export-map",
                   f"the export route map {info.export_map} is left out: AOS-CX exports every route of the VRF with "
                   "its route targets; filter on the BGP neighbors instead")
    return [f"route-target {d} {v}" + (" evpn" if evpn else "") for d, v, evpn in pairs]


def bgp_globals(device: Device, bgp: Bgp, report: Report) -> List[str]:
    """Process-wide options, after bgp router-id."""
    label = f"bgp {bgp.local_as}"
    lines: List[str] = []
    if not bgp.router_id and device.system.router_id:
        lines.append(f"bgp router-id {device.system.router_id}")
        report.add("bgp", label, Severity.APPROX, "router-id",
                   f"AOS-CX has no global router ID: {device.system.router_id} is written as the BGP router ID")
    if bgp.keepalive is not None or bgp.hold is not None:
        lines.append(f"timers bgp {bgp.keepalive if bgp.keepalive is not None else 60} "
                     f"{bgp.hold if bgp.hold is not None else 180}")
    if bgp.graceful_restart:
        lines.append(f"graceful-restart restart-time {bgp.graceful_restart_time or GR_DEFAULT}")
    if bgp.distance:
        lines.append("distance bgp " + " ".join(str(x) for x in bgp.distance))
    if bgp.multipath_relax:
        lines.append("bgp bestpath as-path multipath-relax")
    if bgp.med_missing_as_worst or any(v.med_missing_as_worst for v in bgp.vrfs.values()):
        lines.append("bgp bestpath med missing-as-worst")
        if not bgp.med_missing_as_worst:
            report.add("bgp", label, Severity.APPROX, "bgp-med",
                       "missing-as-worst MED is set in some VRFs; AOS-CX sets it for the process, so it is written "
                       "there and applies to every VRF")
    misc = [what for what, stated in (
        ("asdot notation (AOS-CX shows AS numbers as plain numbers)", bgp.asdot),
        ("the choice of OSPF route types redistributed (all OSPF routes are)",
         bgp.ospf_match or any(v.ospf_match for v in bgp.vrfs.values()))) if stated]
    if misc:
        report.add("bgp", label, Severity.APPROX, "bgp-misc", "; ".join(misc) + ": left out")
    return lines


def aggregate_lines(aggregates: List[BgpAggregate], family: str) -> List[str]:
    return ["aggregate-address " + a.prefix + (" as-set" if a.as_set else "") + (" summary-only" if a.summary_only
                                                                                else "")
            for a in aggregates if (":" in a.prefix) == (family == "ipv6")]


# reading ------------------------------------------------------------------------------------------------------------

def read_evpn_line(device: Device, vid: int, w: List[str]) -> bool:
    """rd X and route-target import|export|both X under an evpn VLAN; auto is the default."""
    vx = device.vxlan
    assert vx is not None
    if w in (["rd", "auto"], ["route-target", "export", "auto"], ["route-target", "import", "auto"],
             ["route-target", "both", "auto"], ["redistribute", "host-route"]):
        return True
    inst = vx.evpn_instances.get(str(vid))
    if inst is None:
        inst = vx.evpn_instances[str(vid)] = EvpnInstance(str(vid), vlans=[vid])
    if w[0] == "rd" and len(w) == 2:
        inst.rd = w[1]
        return True
    if w[0] == "route-target" and len(w) == 3 and w[1] in ("import", "export", "both"):
        info = VrfInfo(rt_import=inst.rt_import, rt_export=inst.rt_export)
        return vrfs_text.route_target(info, w[1], w[2])
    return False


def read_vsx_line(m: Mlag, w: List[str]) -> bool:
    if w[0] == "linkup-delay-timer" and len(w) == 2 and w[1].isdigit():
        m.reload_delay = int(w[1])
        return True
    return False


def read_bgp_global(bgp: Bgp, w: List[str]) -> bool:
    n = len(w)
    if w[:2] == ["timers", "bgp"] and n == 4:
        bgp.keepalive, bgp.hold = int(w[2]), int(w[3])
    elif w[:2] == ["graceful-restart", "restart-time"] and n == 3:
        bgp.graceful_restart = True
        bgp.graceful_restart_time = None if int(w[2]) == GR_DEFAULT else int(w[2])
    elif w == ["graceful-restart"]:
        bgp.graceful_restart = True
    elif w[:2] == ["distance", "bgp"] and n == 5:
        bgp.distance = (int(w[2]), int(w[3]), int(w[4]))
    elif w == ["bgp", "bestpath", "as-path", "multipath-relax"]:
        bgp.multipath_relax = True
    elif w == ["bgp", "bestpath", "med", "missing-as-worst"]:
        bgp.med_missing_as_worst = True
    else:
        return False
    return True
