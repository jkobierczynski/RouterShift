# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NX-OS data-centre fabric: VXLAN and EVPN, the anycast gateway, vPC, VRF route targets and leaking, BGP options.

How the model maps to NX-OS:

* A VLAN carried in VXLAN has ``vn-segment N``; interface ``nve1`` lists the VNIs (``member vni N``) and how each
  floods: by BGP EVPN (``ingress-replication protocol bgp``), to an underlay multicast group (``mcast-group``) or to
  static peers (``ingress-replication protocol static`` / ``peer-ip``). A VRF's layer 3 VNI is ``vni N`` in its
  ``vrf context``, ``member vni N associate-vrf`` on nve1, and a VLAN with ``vn-segment N`` and an SVI in the VRF with
  ``ip forward``.
* An EVPN instance is ``evpn`` / ``vni N l2`` with ``rd`` and ``route-target`` lines. NX-OS has VLAN-based instances
  only: the VLANs of a VLAN-aware bundle are written each on their own, with the bundle's route targets.
* The anycast gateway is ``fabric forwarding anycast-gateway-mac M`` and, on each SVI, the gateway address with
  ``fabric forwarding mode anycast-gateway``.
* An MLAG pair is a vPC pair: ``vpc domain N`` with the heartbeat as ``peer-keepalive``, the reload delays as ``delay
  restore``; the peer link is ``vpc peer-link`` and an MLAG port-channel ``vpc N``. An EVPN ethernet segment is an
  ``ethernet-segment N`` with a ``system-mac`` (NX-OS derives a type 3 identifier from the two).
* The route targets of a VRF that EVPN carries end in ``evpn``; routes leaked from another VRF are imported with that
  VRF's export route targets, and the export route map is ``export map``.
* BGP timers, graceful restart, the best-path options, distances and aggregates keep their NX-OS spelling (``distance``
  and ``aggregate-address`` in the address family).
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import evpn as evpn_text
from . import vrfs as vrfs_text
from . import vxlan as vxlan_text
from .model import Bgp, BgpAggregate, Device, EvpnInstance, Interface, InterfaceKind, Mlag, VrfInfo
from .report import Report, Severity

LABEL = vxlan_text.LABEL
MLAG = "multi-chassis LAG"
Add = Callable[[Severity, str, str], None]
Name = Callable[[str], str]
ROLES = {"primary": 1, "secondary": 2}


def _dotted(mac: str) -> str:
    digits = mac.replace(":", "").replace(".", "").lower()
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def _colons(mac: str) -> str:
    digits = mac.replace(":", "").replace(".", "").lower()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


# VXLAN and EVPN -----------------------------------------------------------------------------------------------------

def l3vni_vlans(device: Device, report: Report) -> Dict[str, int]:
    """The VLAN that carries each layer 3 VNI: the one the source used, or a free one."""
    vx = device.vxlan
    if vx is None:
        return {}
    result = {vrf: vid for vrf, vid in vx.vrf_vlans.items() if vrf in vx.vrf_vnis}
    missing = [vrf for vrf in vx.vrf_vnis if vrf not in result]
    for vrf, vid in zip(missing, evpn_text.free_vlans(device, len(missing))):
        result[vrf] = vid
    if missing:
        report.add("interface", LABEL, Severity.APPROX, "evpn-l3vni-vlan",
                   "NX-OS carries a layer 3 VNI in a VLAN with an SVI in the VRF: "
                   + ", ".join(f"VNI {vx.vrf_vnis[v]} ({v}) in VLAN {result[v]}" for v in missing if v in result)
                   + "; these VLANs are picked by RouterShift among those the source does not use")
    return result


def vlan_vni(device: Device, vid: int) -> Optional[int]:
    vx = device.vxlan
    return vx.vlan_vnis.get(vid) if vx is not None else None


def l3vni_vlan_lines(device: Device, l3: Dict[str, int], ind: str) -> List[str]:
    vx = device.vxlan
    if vx is None:
        return []
    lines: List[str] = []
    for vrf, vid in l3.items():
        lines += [f"vlan {vid}", f"{ind}name L3VNI-{vrf}"[:40], f"{ind}vn-segment {vx.vrf_vnis[vrf]}"]
    return lines


def l3vni_interfaces(device: Device, l3: Dict[str, int], ind: str, vrf: Name) -> List[str]:
    lines: List[str] = []
    for name, vid in l3.items():
        if f"Vlan{vid}" in device.interfaces:
            continue
        lines += [f"interface Vlan{vid}", f"{ind}vrf member {vrf(name)}", f"{ind}ip forward"]
        if any(i.vrf == name and (i.ipv6 or i.virtual_ipv6) for i in device.interfaces.values()):
            lines.append(f"{ind}ipv6 address use-link-local-only")
        lines += [f"{ind}no shutdown", "!"]
    return lines


def nve_lines(device: Device, report: Report, ind: str, port: Name, vrf: Name) -> List[str]:
    vx = device.vxlan
    if vx is None:
        return []
    vxlan_text.item(device, report)
    lines = ["interface nve1", f"{ind}no shutdown"]
    if vx.evpn_vlans:
        lines.append(f"{ind}host-reachability protocol bgp")
    if vx.source_interface:
        lines.append(f"{ind}source-interface {port(vx.source_interface)}")
    for vid, vni in vx.vlan_vnis.items():
        lines.append(f"{ind}member vni {vni}")
        if vid in vx.mcast_groups:
            lines.append(f"{ind * 2}mcast-group {vx.mcast_groups[vid]}")
        elif vid in vx.evpn_vlans:
            lines.append(f"{ind * 2}ingress-replication protocol bgp")
        else:
            lines.append(f"{ind * 2}ingress-replication protocol static")
            lines += [f"{ind * 3}peer-ip {a}" for a in vx.flood_vteps]
    for name, vni in vx.vrf_vnis.items():
        lines.append(f"{ind}member vni {vni} associate-vrf")
    if vx.mlag_shared_mac:
        report.add("interface", LABEL, Severity.APPROX, "vxlan-mlag-mac",
                   "a vPC pair shares its VTEP address: give nve1's source loopback a secondary address common to "
                   "both switches (the EOS mlag-system-id MAC has no NX-OS setting)")
    if vx.qos_propagation:
        report.add("interface", LABEL, Severity.APPROX, "vxlan-qos",
                   "copying " + " and ".join(q.upper() for q in vx.qos_propagation) + " between the inner and outer "
                   "header is left out: NX-OS copies the DSCP to the outer header by default")
    return lines + ["!"]


def evpn_lines(device: Device, report: Report, ind: str) -> List[str]:
    """The evpn block: one VLAN-based instance per VLAN EVPN advertises."""
    vx = device.vxlan
    if vx is None or not vx.evpn_vlans:
        return []
    by_vlan: Dict[int, EvpnInstance] = {v: i for i in vx.evpn_instances.values() for v in i.vlans}
    lines = ["evpn"]
    for vid in vx.evpn_vlans:
        vni = vx.vlan_vnis.get(vid)
        if vni is None:
            report.add("interface", LABEL, Severity.REVIEW, "evpn-vni",
                       f"EVPN VLAN {vid} has no VNI; its instance is left out")
            continue
        inst = by_vlan.get(vid)
        lines.append(f"{ind}vni {vni} l2")
        lines.append(f"{ind * 2}rd {inst.rd if inst is not None and inst.rd and not inst.bundle else 'auto'}")
        imports = inst.rt_import if inst is not None else []
        exports = inst.rt_export if inst is not None else []
        lines += [f"{ind * 2}route-target import {rt}" for rt in imports] or [f"{ind * 2}route-target import auto"]
        lines += [f"{ind * 2}route-target export {rt}" for rt in exports] or [f"{ind * 2}route-target export auto"]
    for inst in vx.evpn_instances.values():
        if inst.bundle:
            report.add("interface", LABEL, Severity.APPROX, "evpn-bundle",
                       f"NX-OS has VLAN-based EVPN instances only: the VLANs of bundle {inst.name} "
                       f"({evpn_text.vlan_text(inst.vlans)}) are written each with rd auto and the bundle's route "
                       "targets" + (f"; its route distinguisher {inst.rd} is left out" if inst.rd else ""))
        if inst.igmp:
            report.add("interface", LABEL, Severity.REVIEW, "evpn-igmp",
                       f"instance {inst.name} advertises IGMP joins as EVPN routes; NX-OS does that with tenant "
                       "routed multicast (TRM), which is not written")
    return lines + ["!"]


def bgp_evpn(device: Device, bgp: Bgp, report: Report) -> List[str]:
    """Process-wide EVPN settings: the domain gateway is reported, MAC-move detection written."""
    lines: List[str] = []
    label = f"bgp {bgp.local_as}"
    if bgp.evpn_domain or bgp.evpn_remote_domain or bgp.evpn_remote_peers:
        report.add("bgp", label, Severity.REVIEW, "evpn-domains",
                   "NX-OS joins two EVPN domains with a Multi-Site border gateway (evpn multisite border-gateway), "
                   f"which is not written: the domains ({bgp.evpn_domain or '-'}, remote "
                   f"{bgp.evpn_remote_domain or '-'}) are left out and the remote-domain neighbors "
                   f"({', '.join(bgp.evpn_remote_peers) or '-'}) are ordinary EVPN neighbors")
    if bgp.evpn_inter_domain_nhs:
        report.add("bgp", label, Severity.REVIEW, "evpn-inter-domain",
                   "next-hop-self on IP-prefix routes passed between the EVPN domains is not written")
    if bgp.evpn_import_discard:
        report.add("bgp", label, Severity.APPROX, "evpn-import-discard",
                   "'route import match-failure action discard' is left out: NX-OS keeps only routes some VRF imports")
    if bgp.evpn_host_flap:
        window, moves, expiry = bgp.evpn_host_flap
        lines.append(f"l2rib dup-host-mac-detection {moves} {window}")
        if expiry:
            report.add("bgp", label, Severity.APPROX, "evpn-host-flap",
                       f"MAC-move detection is written as 'l2rib dup-host-mac-detection {moves} {window}'; the expiry "
                       f"timeout ({expiry} s) has no NX-OS setting")
    return lines


# the anycast gateway -------------------------------------------------------------------------------------------------

def anycast_mac_lines(device: Device) -> List[str]:
    if not device.anycast_mac or not any(i.virtual_ipv4 or i.virtual_ipv6 for i in device.interfaces.values()):
        return []
    return [f"fabric forwarding anycast-gateway-mac {_dotted(device.anycast_mac)}"]


def anycast_lines(device: Device, iface: Interface, add: Add) -> Tuple[List[str], List[str]]:
    """(the gateway addresses, the mode line) of an SVI with an anycast gateway."""
    if not (iface.virtual_ipv4 or iface.virtual_ipv6):
        return [], []
    addresses = [f"ip address {a}" + (" secondary" if n else "") for n, a in enumerate(iface.virtual_ipv4)]
    addresses += [f"ipv6 address {a}" for a in iface.virtual_ipv6]
    if iface.ipv4 or iface.ipv6:
        add(Severity.APPROX, "anycast-own-address",
            "an NX-OS anycast gateway SVI holds the gateway address only: the switch's own address "
            + ", ".join(iface.ipv4 + iface.ipv6) + " is left out")
    if not device.anycast_mac:
        add(Severity.REVIEW, "anycast-mac",
            "the source names no shared MAC; add 'fabric forwarding anycast-gateway-mac' with the fabric's MAC")
    return addresses, ["fabric forwarding mode anycast-gateway"]


# vPC ----------------------------------------------------------------------------------------------------------------

def vpc_lines(device: Device, report: Report, ind: str, vrf: Name) -> List[str]:
    m = device.mlag
    if m is None:
        return []
    report.item("interface", MLAG)
    if m.stack:
        links = [i.name for i in device.interfaces.values() if i.svl_link is not None]
        report.skip("interface", MLAG, "mlag-from-svl",
                    "StackWise Virtual makes one switch of two; NX-OS has no stacking. Pair the switches with vPC "
                    f"instead: a peer link of the StackWise Virtual links ({', '.join(links) or 'none'}), a "
                    "peer-keepalive and a vpc domain")
        return []
    domain = m.domain if m.domain.isdigit() and 1 <= int(m.domain) <= 1000 else "1"
    if domain != m.domain:
        report.add("interface", MLAG, Severity.APPROX, "vpc-domain",
                   f"a vPC domain is a number from 1 to 1000: domain {m.domain or '(none)'} is written as {domain}; "
                   "use the same on the peer")
    lines = [f"vpc domain {domain}"]
    if m.role in ROLES:
        lines.append(f"{ind}role priority {ROLES[m.role]}")
    keepalive = _keepalive(device, report, vrf)
    if keepalive:
        lines.append(f"{ind}{keepalive}")
    if m.reload_delay is not None:
        lines.append(f"{ind}delay restore {m.reload_delay}")
    if m.reload_delay_non_mlag is not None:
        lines.append(f"{ind}delay restore orphan-port {m.reload_delay_non_mlag}")
    if m.dual_primary_delay is not None:
        report.add("interface", MLAG, Severity.APPROX, "vpc-dual-active",
                   "vPC detects a dual-active pair through the peer-keepalive, and the secondary suspends its vPCs: "
                   f"the dual-primary detection delay ({m.dual_primary_delay} s"
                   + (f", {m.dual_primary_action}" if m.dual_primary_action else "") + ") is left out")
    if m.peer_address and m.heartbeat:
        report.add("interface", MLAG, Severity.APPROX, "vpc-peer-address",
                   f"vPC needs no address on the peer link: the MLAG peer address {m.peer_address} and local "
                   f"interface {m.local_interface or '-'} are left out (the SVI itself is written as it is)")
    if not m.peer_link:
        report.add("interface", MLAG, Severity.REVIEW, "vpc-peer-link", "the source names no peer link; add one")
    return lines + ["!"]


def _keepalive(device: Device, report: Report, vrf: Name) -> str:
    m = device.mlag
    assert m is not None
    if m.heartbeat:
        destination, where = m.heartbeat, m.heartbeat_vrf
    elif m.peer_address:
        destination = m.peer_address
        local = device.interfaces.get(m.local_interface)
        where = local.vrf if local is not None else ""
        report.add("interface", MLAG, Severity.REVIEW, "vpc-keepalive",
                   f"the MLAG peer address {m.peer_address} is written as the vPC peer-keepalive: Cisco advises a "
                   "keepalive outside the peer link, such as the management network")
    else:
        report.add("interface", MLAG, Severity.REVIEW, "vpc-keepalive", "the source has no keepalive path; add one")
        return ""
    own = [i for i in device.interfaces.values() if (i.vrf or "") == (where or "") and i.ipv4
           and ipaddress.ip_address(destination) in ipaddress.ip_interface(i.ipv4[0]).network]
    own = own or [i for i in device.interfaces.values() if (i.vrf or "") == (where or "") and i.ipv4]
    if not own:
        report.add("interface", MLAG, Severity.REVIEW, "vpc-keepalive",
                   f"the keepalive to {destination} has no source address in VRF {where or 'default'}; add one")
        return ""
    source = own[0].ipv4[0].split("/")[0]
    return f"peer-keepalive destination {destination} source {source} vrf {vrf(where) if where else 'default'}"


def port_lines(device: Device, iface: Interface, add: Add, ind: str) -> List[str]:
    """vPC membership, the ethernet segment, and what NX-OS has no form for."""
    lines: List[str] = []
    m = device.mlag
    if m is not None and not m.stack and iface.name == m.peer_link:
        lines.append("vpc peer-link")
    elif iface.mlag_id is not None:
        lines.append(f"vpc {iface.mlag_id}")
    if iface.trunk_groups:
        add(Severity.APPROX, "trunk-group",
            f"trunk groups {', '.join(iface.trunk_groups)} left out: NX-OS has no trunk groups, the port carries the "
            "VLANs of its allowed list")
    if iface.evpn_esi:
        number, mac, exact = _segment(iface)
        lines += [f"ethernet-segment {number}", f"{ind}system-mac {mac}"]
        if not exact:
            add(Severity.REVIEW, "evpn-es",
                f"NX-OS derives a type 3 ethernet segment identifier from the system MAC and the segment number: "
                f"identifier {iface.evpn_esi} becomes segment {number} with system MAC {mac}; give the peer the same")
        if iface.evpn_single_active or iface.evpn_df_preference is not None or iface.evpn_es_rt:
            add(Severity.APPROX, "evpn-es",
                "the redundancy mode, designated-forwarder preference and ES-import route target are left out: NX-OS "
                "runs all-active segments and derives the rest")
    elif iface.lacp_system_id:
        add(Severity.REVIEW, "lacp-system-id",
            f"the LAG's LACP system ID {iface.lacp_system_id} has no NX-OS setting without an ethernet segment; left "
            "out")
    return lines


def _segment(iface: Interface) -> Tuple[int, str, bool]:
    """(segment number, system MAC, whether the identifier is kept): a type 3 identifier is (MAC, number)."""
    raw = iface.evpn_esi.replace(":", "")
    if raw[:2] == "03":
        return int(raw[14:20], 16), _dotted(raw[2:14]), True
    mac = _dotted(iface.lacp_system_id) if iface.lacp_system_id else _dotted(raw[-12:])
    return evpn_text.es_number(iface), mac, False


def trunk_groups(device: Device, report: Report) -> None:
    for vlan in device.vlans.values():
        if vlan.trunk_groups:
            report.add("vlan", str(vlan.vlan_id), Severity.APPROX, "trunk-group",
                       f"trunk group {', '.join(vlan.trunk_groups)} left out: NX-OS has no trunk groups, the VLAN is "
                       "carried by every trunk that allows it")


# VRFs ---------------------------------------------------------------------------------------------------------------

def vrf_lines(device: Device, name: str, info: Optional[VrfInfo], report: Report, ind: str, six: bool) -> List[str]:
    """The body of a vrf context: the layer 3 VNI, the route distinguisher and the route targets per family."""
    vx = device.vxlan
    lines: List[str] = []
    label = f"vrf {name}"
    if vx is not None and name in vx.vrf_vnis:
        lines.append(f"{ind}vni {vx.vrf_vnis[name]}")
    if info is None:
        return lines
    if info.rd:
        lines.append(f"{ind}rd {info.rd}")
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
    body = [f"route-target {d} {v}" + (" evpn" if evpn else "") for d, v, evpn in pairs]
    if info.export_map:
        body.append(f"export map {info.export_map}")
    if body:
        for family in (["ipv4", "ipv6"] if six else ["ipv4"]):
            lines.append(f"{ind}address-family {family} unicast")
            lines += [f"{ind * 2}{line}" for line in body]
    return lines


# BGP ----------------------------------------------------------------------------------------------------------------

def bgp_globals(device: Device, bgp: Bgp, report: Report) -> List[str]:
    """Process-wide options, after router-id."""
    label = f"bgp {bgp.local_as}"
    lines: List[str] = []
    if not bgp.router_id and device.system.router_id:
        lines.append(f"router-id {device.system.router_id}")
        report.add("bgp", label, Severity.APPROX, "router-id",
                   f"NX-OS has no global router ID: {device.system.router_id} is written as the BGP router ID")
    if bgp.keepalive is not None or bgp.hold is not None:
        lines.append(f"timers bgp {bgp.keepalive if bgp.keepalive is not None else 60} "
                     f"{bgp.hold if bgp.hold is not None else 180}")
    if bgp.graceful_restart:
        lines.append("graceful-restart")
    if bgp.graceful_restart_time:
        lines.append(f"graceful-restart restart-time {bgp.graceful_restart_time}")
    if bgp.multipath_relax:
        lines.append("bestpath as-path multipath-relax")
    if bgp.med_missing_as_worst or any(v.med_missing_as_worst for v in bgp.vrfs.values()):
        lines.append("bestpath med missing-as-worst")
        if not bgp.med_missing_as_worst:
            report.add("bgp", label, Severity.APPROX, "bgp-med",
                       "missing-as-worst MED is set in some VRFs; it is written for the process and so applies to "
                       "every VRF")
    misc = [what for what, stated in (
        ("asdot notation (NX-OS shows AS numbers as plain numbers)", bgp.asdot),
        ("the choice of OSPF route types redistributed (all OSPF routes are; match the route type in the route "
         "map)", bgp.ospf_match or any(v.ospf_match for v in bgp.vrfs.values()))) if stated]
    if misc:
        report.add("bgp", label, Severity.APPROX, "bgp-misc", "; ".join(misc) + ": left out")
    return lines


def aggregate_lines(aggregates: List[BgpAggregate], family: str) -> List[str]:
    return ["aggregate-address " + a.prefix + (" as-set" if a.as_set else "") + (" summary-only" if a.summary_only
                                                                                else "")
            for a in aggregates if (":" in a.prefix) == (family == "ipv6")]


def distance_line(bgp: Bgp) -> List[str]:
    return [f"distance {bgp.distance[0]} {bgp.distance[1]} {bgp.distance[2]}"] if bgp.distance else []


# reading ------------------------------------------------------------------------------------------------------------

class Reader:
    """The NX-OS fabric lines, gathered as the reader meets them and settled at the end."""

    def __init__(self, device: Device) -> None:
        self.device = device
        self.segments: Dict[int, int] = {}  # VLAN -> vn-segment
        self.vrf_vnis: Dict[int, str] = {}  # VNI -> VRF (vrf context / vni)
        self.evpn: Set[int] = set()  # VNIs flooded by BGP or listed under evpn
        self.groups: Dict[int, str] = {}  # VNI -> multicast group
        self.instances: Dict[int, EvpnInstance] = {}  # VNI -> its instance, when not all auto
        self.anycast: Set[str] = set()  # SVIs in anycast gateway mode
        self.forward: Set[str] = set()  # SVIs with ip forward (layer 3 VNI)
        self.mlag: Optional[Mlag] = None
        self.es_ports: Dict[str, Tuple[int, str]] = {}  # port-channel -> (segment, system MAC)

    def vlan_line(self, vid: int, w: List[str]) -> bool:
        if w[0] == "vn-segment" and len(w) == 2 and w[1].isdigit():
            self.segments[vid] = int(w[1])
            return True
        return False

    def vrf_line(self, name: str, w: List[str]) -> bool:
        if w[0] == "vni" and len(w) == 2 and w[1].isdigit():
            self.vrf_vnis[int(w[1])] = name
            return True
        return False

    def nve(self, node_children: List[Tuple[List[str], List[List[str]]]]) -> List[Tuple[int, int]]:
        """interface nve1: (child index, grandchild index or -1) of each line not understood."""
        vx = vxlan_text.vtep(self.device)
        bad: List[Tuple[int, int]] = []
        from . import names
        for n, (w, grand) in enumerate(node_children):
            if w[0] == "source-interface" and len(w) == 2:
                vx.source_interface = names.canonical(w[1])[0]
            elif w in (["host-reachability", "protocol", "bgp"], ["no", "shutdown"]) or w[0] == "description":
                pass
            elif w[:2] == ["member", "vni"] and len(w) in (3, 4) and w[2].isdigit():
                vni = int(w[2])
                if w[3:] == ["associate-vrf"]:
                    continue
                if len(w) == 4:
                    bad.append((n, -1))
                    continue
                for k, g in enumerate(grand):
                    if g == ["ingress-replication", "protocol", "bgp"]:
                        self.evpn.add(vni)
                    elif g == ["ingress-replication", "protocol", "static"]:
                        pass
                    elif g[0] == "peer-ip" and len(g) == 2:
                        address = str(ipaddress.ip_address(g[1]))
                        if address not in vx.flood_vteps:
                            vx.flood_vteps.append(address)
                    elif g[0] == "mcast-group" and len(g) == 2:
                        self.groups[vni] = str(ipaddress.IPv4Address(g[1]))
                    elif g == ["suppress-arp"]:
                        pass
                    else:
                        bad.append((n, k))
            else:
                bad.append((n, -1))
        return bad

    def evpn_block(self, children: List[Tuple[List[str], List[List[str]]]]) -> List[Tuple[int, int]]:
        bad: List[Tuple[int, int]] = []
        for n, (w, grand) in enumerate(children):
            if w[0] == "vni" and len(w) == 3 and w[1].isdigit() and w[2] == "l2":
                vni = int(w[1])
                self.evpn.add(vni)
                inst = EvpnInstance(str(vni))
                for k, g in enumerate(grand):
                    try:
                        ok = evpn_text.instance_line(inst, g)
                    except (ValueError, IndexError):
                        ok = False
                    if not ok:
                        bad.append((n, k))
                if inst.rd or inst.rt_import or inst.rt_export:
                    self.instances[vni] = inst
            else:
                bad.append((n, -1))
        return bad

    def vpc_domain(self, domain: str, children: List[List[str]]) -> List[int]:
        m = self.mlag = Mlag(domain=domain)
        bad = []
        for n, w in enumerate(children):
            if w[:2] == ["peer-keepalive", "destination"] and len(w) >= 3:
                m.heartbeat = str(ipaddress.ip_address(w[2]))
                rest = w[3:]
                m.heartbeat_vrf = "management"  # the NX-OS default
                if rest[:1] == ["source"] and len(rest) >= 2:
                    rest = rest[2:]
                if rest[:1] == ["vrf"] and len(rest) == 2:
                    m.heartbeat_vrf = "" if rest[1] == "default" else rest[1]
                    rest = []
                if rest:
                    bad.append(n)
            elif w[:2] == ["role", "priority"] and len(w) == 3 and w[2].isdigit():
                m.role = {1: "primary", 2: "secondary"}.get(int(w[2]), "")
            elif w[:2] == ["delay", "restore"] and len(w) == 3 and w[2].isdigit():
                m.reload_delay = int(w[2])
            elif w[:3] == ["delay", "restore", "orphan-port"] and len(w) == 4 and w[3].isdigit():
                m.reload_delay_non_mlag = int(w[3])
            elif w in (["peer-switch"], ["peer-gateway"], ["auto-recovery"], ["ip", "arp", "synchronize"],
                       ["ipv6", "nd", "synchronize"]):
                pass  # behaviour the other platforms have by default
            else:
                bad.append(n)
        return bad

    def interface_line(self, iface: Interface, w: List[str], children: List[List[str]]) -> Optional[bool]:
        if w == ["vpc", "peer-link"]:
            if self.mlag is None:
                self.mlag = Mlag()
            self.mlag.peer_link = iface.name
        elif w[0] == "vpc" and len(w) == 2 and w[1].isdigit():
            iface.mlag_id = int(w[1])
        elif w == ["fabric", "forwarding", "mode", "anycast-gateway"]:
            self.anycast.add(iface.name)
        elif w == ["ip", "forward"]:
            self.forward.add(iface.name)
        elif w == ["ipv6", "address", "use-link-local-only"] and iface.kind == InterfaceKind.VLAN:
            pass
        elif w[0] == "ethernet-segment" and len(w) == 2 and w[1].isdigit():
            macs = [c[1] for c in children if c[0] == "system-mac" and len(c) == 2]
            if len(macs) != 1 or len(children) != 1:
                return False
            self.es_ports[iface.name] = (int(w[1]), macs[0])
        else:
            return None
        return True

    def finish(self) -> None:
        d = self.device
        if self.mlag is not None:
            peer_link = self.mlag.peer_link
            if d.mlag is not None:
                self.mlag.peer_link = self.mlag.peer_link or d.mlag.peer_link
            d.mlag = self.mlag
            d.mlag.peer_link = d.mlag.peer_link or peer_link
        for name, (number, mac) in self.es_ports.items():
            iface = d.interfaces.get(name)
            if iface is not None:
                raw = "03" + mac.replace(".", "").lower() + f"{number:06x}"
                iface.evpn_esi = ":".join(raw[i:i + 4] for i in range(0, 20, 4))
                iface.lacp_system_id = _dotted(mac)
        for name in self.anycast:
            iface = d.interfaces.get(name)
            if iface is not None:
                iface.virtual_ipv4, iface.ipv4 = iface.ipv4, []
                iface.virtual_ipv6, iface.ipv6 = iface.ipv6, []
        if not (self.segments or self.vrf_vnis):
            return
        vx = vxlan_text.vtep(d)
        for vni, vrf in self.vrf_vnis.items():
            vx.vrf_vnis[vrf] = vni
        for vid, vni in self.segments.items():
            if vni in self.vrf_vnis:
                vx.vrf_vlans[self.vrf_vnis[vni]] = vid
                d.vlans.pop(vid, None)
                if f"Vlan{vid}" in self.forward:
                    d.interfaces.pop(f"Vlan{vid}", None)
                continue
            vx.vlan_vnis[vid] = vni
            if vni in self.evpn and vid not in vx.evpn_vlans:
                vx.evpn_vlans.append(vid)
            if vni in self.groups:
                vx.mcast_groups[vid] = self.groups[vni]
            inst = self.instances.get(vni)
            if inst is not None:
                inst.name, inst.vlans = str(vid), [vid]
                vx.evpn_instances[inst.name] = inst


def read_anycast_mac(device: Device, w: List[str]) -> bool:
    if w[:3] == ["fabric", "forwarding", "anycast-gateway-mac"] and len(w) == 4:
        device.anycast_mac = _colons(w[3])
        return True
    return False
