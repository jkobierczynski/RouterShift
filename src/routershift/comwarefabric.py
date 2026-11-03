# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Comware 7 data-centre features: VXLAN with BGP EVPN, the distributed (anycast) gateway, M-LAG, EVPN ethernet
segments, EVPN route targets of VPN instances and route leaking. Written and read.

Comware carries a VLAN in VXLAN through a VSI: ``vsi VLANn`` with ``vxlan VNI`` and ``evpn encapsulation vxlan``,
which each port that carries the VLAN joins with a ``service-instance`` (``encapsulation s-vid n``, or
``encapsulation untagged`` for its untagged VLAN) and ``xconnect vsi``. The routed interface of such a VLAN is a
``Vsi-interface`` (``gateway vsi-interface n``); an anycast gateway is that interface with ``distributed-gateway
local`` and the shared MAC. A VRF's layer 3 VNI is ``l3-vni`` on a Vsi-interface of its own. M-LAG pairs two switches
with ``m-lag keepalive``, ``port m-lag peer-link`` and ``port m-lag group``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from . import vrfs as vrfs_text
from . import vxlan as vxlan_text
from .model import Device, EvpnInstance, Interface, InterfaceKind, Mlag, SwitchportMode, VrfInfo
from .report import Report, Severity

IND = " "
VSI = "VLAN"  # vsi VLANn
Add = Callable[[Severity, str, str], None]
_VNI_BASE = 3900  # Vsi-interfaces of the layer 3 VNIs are numbered down from here, past the VLAN IDs


def vsi_name(vid: int) -> str:
    return f"{VSI}{vid}"


def l3_numbers(device: Device) -> Dict[str, int]:
    """The Vsi-interface number that carries each VRF's layer 3 VNI."""
    vx = device.vxlan
    if vx is None:
        return {}
    taken = set(device.vlans) | set(vx.vlan_vnis)
    free = (n for n in range(_VNI_BASE, 0, -1) if n not in taken)
    return {vrf: next(free) for vrf in vx.vrf_vnis}


def gateway_vlan(device: Device, iface: Interface) -> Optional[int]:
    """The VLAN of an SVI whose VLAN is carried in VXLAN: Comware routes it as a Vsi-interface."""
    vx = device.vxlan
    if vx is None or iface.kind != InterfaceKind.VLAN or not iface.name[4:].isdigit():
        return None
    vid = int(iface.name[4:])
    return vid if vid in vx.vlan_vnis else None


# global lines ------------------------------------------------------------------------------------------------------

def vxlan_lines(device: Device, report: Report, port: Callable[[str], str], tunnel_base: int) -> List[str]:
    """l2vpn enable, the VTEP source, the static flood tunnels and one VSI per VLAN carried in VXLAN."""
    vx = device.vxlan
    if vx is None:
        return []
    vxlan_text.item(device, report)
    label = vxlan_text.LABEL
    out = ["l2vpn enable", "#"]
    source = vxlan_text.source_address(device)
    if source:
        out += [f"tunnel global source-address {source}", "#"]
    elif vx.source_interface:
        report.add("interface", label, Severity.REVIEW, "vxlan-source",
                   f"the source interface {vx.source_interface} has no IPv4 address; set 'tunnel global "
                   "source-address' by hand")
    tunnels = {peer: tunnel_base + n for n, peer in enumerate(vx.flood_vteps)}
    for peer, number in tunnels.items():
        out += [f"interface Tunnel{number} mode vxlan"] + ([f"{IND}source {source}"] if source else []) + \
            [f"{IND}destination {peer}", "#"]
    if vx.mlag_shared_mac:
        report.add("interface", label, Severity.APPROX, "vxlan-mlag-mac",
                   "the routed VXLAN traffic of an M-LAG pair uses the pair's system MAC on Comware; the EOS "
                   "'virtual-router encapsulation mac-address mlag-system-id' is left out")
    if vx.mcast_groups:
        report.add("interface", label, Severity.REVIEW, "vxlan-mcast",
                   "Comware floods VXLAN by head-end replication here: the multicast groups of VLANs "
                   + ", ".join(str(v) for v in sorted(vx.mcast_groups)) + " are left out")
    if vx.qos_propagation:
        report.add("interface", label, Severity.APPROX, "vxlan-qos",
                   "Comware copies the DSCP to the outer header by default; the ECN and DSCP propagation settings "
                   "are not written")
    instances: Dict[int, EvpnInstance] = {vid: inst for inst in vx.evpn_instances.values() for vid in inst.vlans}
    for inst in vx.evpn_instances.values():
        if inst.bundle:
            report.add("interface", label, Severity.APPROX, "evpn-bundle",
                       f"the VLAN-aware bundle {inst.name} becomes one EVPN instance per VLAN (each VSI), with the "
                       "bundle's route distinguisher and route targets")
        if inst.igmp:
            report.add("interface", label, Severity.APPROX, "evpn-igmp",
                       f"the IGMP routes of EVPN instance {inst.name} are not written")
    for vid, vni in sorted(vx.vlan_vnis.items()):
        body = []
        if any(i.kind == InterfaceKind.VLAN and i.name == f"Vlan{vid}" for i in device.interfaces.values()):
            body.append(f"gateway vsi-interface {vid}")
        body.append(f"vxlan {vni}")
        body += [f"{IND}tunnel {number}" for number in tunnels.values()]
        if vid in vx.evpn_vlans:
            found = instances.get(vid)
            body.append("evpn encapsulation vxlan")
            evpn = [f"route-distinguisher {found.rd if found is not None and found.rd else 'auto'}"]
            if found is not None and (found.rt_import or found.rt_export):
                pairs = vrfs_text.targets(VrfInfo(rt_import=found.rt_import, rt_export=found.rt_export))
                kinds = {"import": "import-extcommunity", "export": "export-extcommunity", "both": "both"}
                evpn += [f"vpn-target {v} {kinds[d]}" for d, v in pairs]
            else:
                evpn.append("vpn-target auto")
            body += [IND + line for line in evpn]
        out += [f"vsi {vsi_name(vid)}"] + [IND + b for b in body] + ["#"]
    for vrf, number in l3_numbers(device).items():
        out += [f"interface Vsi-interface{number}", f"{IND}ip binding vpn-instance {vrf}",
                f"{IND}l3-vni {vx.vrf_vnis[vrf]}", "#"]
    if vx.vrf_vlans:
        report.add("interface", label, Severity.APPROX, "l3vni-vlan",
                   "the VLANs that carried the layer 3 VNIs are not needed on Comware: each VRF's VNI is on a "
                   "Vsi-interface of its own")
    return out


def tunnel_base(device: Device) -> int:
    numbers = [int(i.name[6:]) for i in device.interfaces.values()
               if i.kind == InterfaceKind.TUNNEL and i.name[6:].isdigit()]
    return max(numbers, default=0) + 1


def service_instances(device: Device, iface: Interface) -> List[str]:
    """The service instances by which a layer 2 port carries its VXLAN VLANs."""
    vx = device.vxlan
    if vx is None or not vx.vlan_vnis or iface.mode == SwitchportMode.ROUTED or iface.lag or \
            iface.kind not in (InterfaceKind.ETHERNET, InterfaceKind.LAG):
        return []
    if iface.mode == SwitchportMode.ACCESS:
        vid = iface.access_vlan or 1
        return _instance(vid, "untagged") if vid in vx.vlan_vnis else []
    allowed = set(_vlan_ids(iface.allowed_vlans)) if iface.allowed_vlans else set(vx.vlan_vnis)
    native = iface.native_vlan or 1
    lines: List[str] = []
    for vid in sorted(v for v in vx.vlan_vnis if v in allowed):
        lines += _instance(vid, "untagged" if vid == native else f"s-vid {vid}")
    return lines


def _vlan_ids(text: str) -> List[int]:
    from .parsers.ioslike import _vlan_ids as ids  # the parsers import this module
    return ids(text)


def _instance(vid: int, encapsulation: str) -> List[str]:
    return [f"service-instance {vid}", f"{IND}encapsulation {encapsulation}", f"{IND}xconnect vsi {vsi_name(vid)}"]


def gateway_lines(device: Device, iface: Interface, add: Add) -> List[str]:
    """The anycast gateway of a Vsi-interface: the shared addresses, MAC and distributed-gateway local."""
    if not (iface.virtual_ipv4 or iface.virtual_ipv6):
        return []
    lines = []
    for n, cidr in enumerate(iface.virtual_ipv4):
        net = ipaddress.ip_interface(cidr)
        lines.append(f"ip address {net.ip} {net.netmask}" + (" sub" if n or iface.ipv4 else ""))
    lines += [f"ipv6 address {cidr}" for cidr in iface.virtual_ipv6]
    if device.anycast_mac:
        digits = device.anycast_mac.replace(":", "").replace(".", "").lower()
        lines.append(f"mac-address {digits[0:4]}-{digits[4:8]}-{digits[8:12]}")
    else:
        add(Severity.REVIEW, "anycast-mac", "the source names no shared MAC: set 'mac-address' to the same value on "
                                           "every leaf")
    lines.append("distributed-gateway local")
    if iface.ipv4:
        add(Severity.APPROX, "anycast-gateway", "Comware's distributed gateway has the same addresses on every leaf; "
                                                "the switch's own address is written as well, first")
    return lines


def anycast_without_vxlan(iface: Interface, add: Add) -> None:
    if iface.virtual_ipv4 or iface.virtual_ipv6:
        add(Severity.REVIEW, "anycast-gateway",
            "Comware runs an anycast (distributed) gateway only on a VLAN carried in VXLAN; the shared addresses "
            + ", ".join(iface.virtual_ipv4 + iface.virtual_ipv6) + " are left out: use VRRP instead")


# M-LAG and ethernet segments ---------------------------------------------------------------------------------------

def mlag_lines(device: Device, report: Report, port: Callable[[str], str], vrf_of: Callable[[str], str]) -> List[str]:
    m = device.mlag
    members = [i for i in device.interfaces.values() if i.mlag_id is not None]
    if m is None and not members:
        return []
    label = "multi-chassis LAG"
    report.item("interface", label)
    out: List[str] = []
    if m is None:
        report.add("interface", label, Severity.REVIEW, "mlag-peer",
                   "the source has multi-chassis LAGs but no peer settings; add 'm-lag keepalive' and the peer link")
        return out
    if m.stack:
        report.add("interface", label, Severity.REVIEW, "stackwise",
                   "StackWise Virtual becomes IRF on Comware, which is set up on each member before it joins; "
                   "configure it by hand")
        return out
    out.append("m-lag system-number " + ("2" if m.role == "secondary" else "1"))
    report.add("interface", label, Severity.REVIEW, "mlag-system",
               "set 'm-lag system-mac' to the same MAC on both switches, and 'm-lag system-number 2' on the peer"
               + (f"; the domain name {m.domain} has no Comware form" if m.domain else ""))
    keepalive = m.heartbeat or m.peer_address
    if keepalive:
        vrf = m.heartbeat_vrf if m.heartbeat else ""
        out.append(f"m-lag keepalive ip destination {keepalive}" + (f" vpn-instance {vrf}" if vrf else ""))
        if m.heartbeat and m.peer_address:
            report.add("interface", label, Severity.APPROX, "mlag-peer-address",
                       f"Comware keeps the pair alive over one path: the heartbeat {m.heartbeat} is written as the "
                       f"keepalive; the peer-link address {m.peer_address} and {m.local_interface or 'its SVI'} are "
                       "not needed")
    if m.reload_delay is not None:
        out.append(f"m-lag restore-delay {m.reload_delay}")
    if m.reload_delay_non_mlag is not None:
        report.add("interface", label, Severity.APPROX, "mlag-reload",
                   f"Comware delays only the M-LAG ports after a reload; the delay of the other ports "
                   f"({m.reload_delay_non_mlag} s) is left out")
    if m.dual_primary_delay is not None or m.dual_primary_action:
        out.append("m-lag mad default-action down" if m.dual_primary_action else "m-lag mad default-action none")
        if m.dual_primary_delay is not None:
            report.add("interface", label, Severity.APPROX, "mlag-mad",
                       f"Comware's M-LAG MAD acts at once; the detection delay of {m.dual_primary_delay} s is left out")
    return out + ["#"]


def lag_lines(device: Device, iface: Interface, add: Add) -> List[str]:
    lines = []
    m = device.mlag
    if m is not None and iface.name == m.peer_link:
        lines.append("port m-lag peer-link 1")
    if iface.mlag_id is not None:
        lines.append(f"port m-lag group {iface.mlag_id}")
    if iface.evpn_esi:
        groups = [g for g in iface.evpn_esi.replace(".", ":").split(":") if g]
        digits = "".join(groups).lower()
        if len(digits) == 20:
            lines.append("esi " + ".".join(digits[i:i + 4] for i in range(0, 20, 4)))
        else:
            add(Severity.REVIEW, "esi", f"the ethernet segment {iface.evpn_esi} is not 10 bytes; set 'esi' by hand")
    if iface.evpn_es_rt or iface.evpn_df_preference is not None or iface.evpn_single_active:
        add(Severity.APPROX, "evpn-es", "Comware derives the ES-import route target from the ESI and elects the "
                                        "designated forwarder itself; the route target, the DF preference and "
                                        "single-active redundancy are left out")
    if iface.lacp_system_id:
        add(Severity.APPROX, "lacp-system-id",
            f"the LACP system ID {iface.lacp_system_id} is left out: Comware's M-LAG takes its system MAC")
    return lines


def trunk_groups(device: Device, report: Report) -> None:
    for vlan in device.vlans.values():
        if vlan.trunk_groups:
            report.add("vlan", str(vlan.vlan_id), Severity.APPROX, "trunk-groups",
                       f"trunk group {', '.join(vlan.trunk_groups)} has no Comware form: the trunks permit the VLAN by "
                       "their own VLAN lists")
    for iface in device.interfaces.values():
        if iface.trunk_groups:
            report.add("interface", iface.source_name or iface.name, Severity.APPROX, "trunk-groups",
                       f"the trunk groups {', '.join(iface.trunk_groups)} have no Comware form; the port permits its "
                       "VLANs by its own list")


def evpn_domain(device: Device, report: Report) -> None:
    bgp = device.bgp
    if bgp is not None and (bgp.evpn_domain or bgp.evpn_remote_peers or bgp.evpn_host_flap):
        report.add("bgp", f"bgp {bgp.local_as}", Severity.REVIEW, "evpn-domain",
                   "the EVPN domain gateway (DCI) and host-flap settings have no direct Comware form; set up the "
                   "re-origination of the routes towards the other domain by hand")


# VPN instances -----------------------------------------------------------------------------------------------------

def vrf_lines(device: Device, name: str, info: VrfInfo, report: Report) -> List[str]:
    """The route targets of a VPN instance (under address-family evpn when they are EVPN's), with the export route
    targets of the VRFs it leaks routes from, and its export policy."""
    label = f"vrf {name}"
    pairs = vrfs_text.targets(info)
    extra: List[str] = []
    for source, rmap in info.leaks.items():
        src = device.vrf_info.get(source)
        if src is None or not src.rt_export:
            report.add("system", label, Severity.REVIEW, "vrf-leak",
                       f"the routes leaked from VRF {source}: that VRF exports no route targets to import; set the "
                       "leaking up by hand")
            continue
        extra += [v for v in src.rt_export if v not in info.rt_import and v not in extra]
        report.add("system", label, Severity.APPROX, "vrf-leak",
                   f"the routes leaked from VRF {source} are imported with its export route targets "
                   f"({', '.join(src.rt_export)}): only the routes it has in BGP are leaked"
                   + (f", and route map {rmap} is left out" if rmap else ""))
    pairs += [("import", v) for v in extra]
    kinds = {"import": "import-extcommunity", "export": "export-extcommunity", "both": "both"}
    targets = [f"vpn-target {v} {kinds[d]}" for d, v in pairs]
    lines = []
    if info.rt_evpn and targets:
        lines += ["address-family evpn"] + [IND + t for t in targets]
    else:
        lines += targets
    if info.export_map:
        lines.append(f"export route-policy {info.export_map}")
    return lines


# reading -----------------------------------------------------------------------------------------------------------

@dataclass
class FabricReader:
    device: Device
    gateways: Dict[int, int] = field(default_factory=dict)  # Vsi-interface number -> VLAN
    l3: Set[str] = field(default_factory=set)  # canonical names of the Vsi-interfaces that carry a layer 3 VNI
    tunnels: Dict[str, str] = field(default_factory=dict)  # VXLAN tunnel -> destination
    source: str = ""

    def vsi(self, node_words: List[str], children: List[List[str]], unparsed: Callable[[int], None]) -> bool:
        """vsi NAME with gateway, vxlan and evpn lines; children are (words) of every line below, depth-first."""
        if len(node_words) != 2:
            return False
        name = node_words[1]
        if not (name.startswith(VSI) and name[len(VSI):].isdigit()):
            return False
        vid = int(name[len(VSI):])
        vx = vxlan_text.vtep(self.device)
        inst = EvpnInstance(str(vid), [vid])
        evpn = False
        for n, w in enumerate(children):
            if w[:2] == ["gateway", "vsi-interface"] and len(w) == 3:
                self.gateways[int(w[2])] = vid
            elif w[0] == "vxlan" and len(w) == 2:
                vx.vlan_vnis[vid] = int(w[1])
            elif w[0] == "tunnel" and len(w) == 2:
                pass  # the static flood list is read from the tunnels
            elif w == ["evpn", "encapsulation", "vxlan"]:
                evpn = True
            elif w[0] == "route-distinguisher" and len(w) == 2:
                inst.rd = "" if w[1] == "auto" else w[1]
            elif w == ["vpn-target", "auto"]:
                pass
            elif w[0] == "vpn-target" and len(w) == 3:
                if w[2] in ("import-extcommunity", "both"):
                    inst.rt_import.append(w[1])
                if w[2] in ("export-extcommunity", "both"):
                    inst.rt_export.append(w[1])
            else:
                unparsed(n)
        if evpn:
            vx.evpn_vlans.append(vid)
            if inst.rd or inst.rt_import or inst.rt_export:
                vx.evpn_instances[inst.name] = inst
        return True

    def global_line(self, w: List[str]) -> bool:
        if w[:3] == ["tunnel", "global", "source-address"] and len(w) == 4:
            self.source = w[3]
            vxlan_text.vtep(self.device)
            return True
        if w == ["l2vpn", "enable"]:
            return True
        return False

    def mlag(self, w: List[str]) -> bool:
        m = self.device.mlag
        if m is None:
            m = self.device.mlag = Mlag()
        if w[:2] == ["m-lag", "system-number"] and len(w) == 3:
            m.role = "secondary" if w[2] == "2" else ""
        elif w[:2] == ["m-lag", "system-mac"] and len(w) == 3:
            pass
        elif w[:4] == ["m-lag", "keepalive", "ip", "destination"] and len(w) in (5, 7):
            m.heartbeat = w[4]
            if len(w) == 7:
                if w[5] != "vpn-instance":
                    return False
                m.heartbeat_vrf = w[6]
        elif w[:2] == ["m-lag", "restore-delay"] and len(w) == 3:
            m.reload_delay = int(w[2])
        elif w[:3] == ["m-lag", "mad", "default-action"] and len(w) == 4 and w[3] in ("down", "none"):
            m.dual_primary_action = "errdisable all-interfaces" if w[3] == "down" else ""
        else:
            return False
        return True

    def interface_line(self, iface: Interface, w: List[str]) -> bool:
        if w == ["distributed-gateway", "local"]:
            iface.virtual_ipv4, iface.ipv4 = iface.ipv4, []
            iface.virtual_ipv6, iface.ipv6 = iface.ipv6, []
            return True
        if w[0] == "l3-vni" and len(w) == 2:
            self.l3.add(iface.name)
            vxlan_text.vtep(self.device).vrf_vnis[iface.vrf or "default"] = int(w[1])
            return True
        if w[:3] == ["port", "m-lag", "peer-link"] and len(w) == 4:
            m = self.device.mlag or Mlag()
            self.device.mlag = m
            m.peer_link = iface.name
            return True
        if w[:3] == ["port", "m-lag", "group"] and len(w) == 4:
            iface.mlag_id = int(w[3])
            return True
        if w[0] == "esi" and len(w) == 2:
            digits = w[1].replace(".", "")
            iface.evpn_esi = ":".join(digits[i:i + 4] for i in range(0, len(digits), 4))
            return True
        return False

    def finish(self) -> None:
        d = self.device
        vx = d.vxlan
        if vx is None:
            return
        if self.source:
            vx.source_interface = vxlan_text.interface_of(d, self.source)
        vx.flood_vteps = list(self.tunnels.values())
        for name in self.l3:
            d.interfaces.pop(name, None)
        for iface in d.interfaces.values():  # the anycast MAC lives on the Vsi-interfaces
            if iface.virtual_ipv4 and iface.mac_address:
                d.anycast_mac = d.anycast_mac or iface.mac_address
                iface.mac_address = ""
