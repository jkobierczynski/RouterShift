# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""BGP EVPN beyond the VNIs: EVPN instances with their route distinguishers and route targets, multihoming (ethernet
segments), the gateway between two EVPN domains, and the IOS VLANs that carry layer 3 VNIs. Readers and the IOS and
EOS writer share these helpers."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .model import Bgp, Device, EvpnInstance, Interface, Vxlan
from .report import Report, Severity
from . import vxlan as vxlan_text

LABEL = vxlan_text.LABEL
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def instance(vx: Vxlan, name: str, vlans: List[int], bundle: bool = False) -> EvpnInstance:
    inst = vx.evpn_instances.get(name)
    if inst is None:
        inst = vx.evpn_instances[name] = EvpnInstance(name, list(vlans), bundle)
    for vid in vlans:
        if vid not in vx.evpn_vlans:
            vx.evpn_vlans.append(vid)
    return inst


def instance_line(inst: EvpnInstance, w: List[str]) -> bool:
    """rd X | rd auto | route-target import|export|both X|auto | redistribute learned|igmp (EOS and IOS)."""
    n = len(w)
    if w[0] == "rd" and n == 2:
        inst.rd = "" if w[1] == "auto" else w[1]
        return True
    if w[0] == "route-target" and n == 3 and w[1] in ("import", "export", "both"):
        if w[2] == "auto":
            return True
        for direction in (["import", "export"] if w[1] == "both" else [w[1]]):
            targets = inst.rt_import if direction == "import" else inst.rt_export
            if w[2] not in targets:
                targets.append(w[2])
        return True
    if w == ["redistribute", "learned"]:
        return True
    if w == ["redistribute", "igmp"]:
        inst.igmp = True
        return True
    return False


def vlan_list(text: str) -> List[int]:
    result: List[int] = []
    for part in text.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            result += list(range(int(lo), int(hi) + 1))
        elif part:
            result.append(int(part))
    return result


def vlan_text(vlans: List[int]) -> str:
    parts: List[str] = []
    ordered = sorted(set(vlans))
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        parts.append(str(ordered[i]) if i == j else f"{ordered[i]}-{ordered[j]}")
        i = j + 1
    return ",".join(parts)


def af_line(bgp_peers: Dict[str, List[str]], bgp: Bgp, w: List[str]) -> bool:
    """EOS address-family evpn options: domains, the remote-domain neighbors, inter-domain next-hop-self, route import
    discard and host-flap detection. bgp_peers collects the remote-domain neighbors."""
    n = len(w)
    if w[:2] == ["domain", "identifier"] and n in (3, 4):
        if n == 4 and w[3] == "remote":
            bgp.evpn_remote_domain = w[2]
        elif n == 3:
            bgp.evpn_domain = w[2]
        else:
            return False
        return True
    if w[0] == "neighbor" and n == 4 and w[2:] == ["domain", "remote"]:
        bgp_peers.setdefault("remote", []).append(w[1])
        return True
    if w == ["neighbor", "default", "next-hop-self", "received-evpn-routes", "route-type", "ip-prefix",
             "inter-domain"]:
        bgp.evpn_inter_domain_nhs = True
        return True
    if w == ["route", "import", "match-failure", "action", "discard"]:
        bgp.evpn_import_discard = True
        return True
    if w[:3] == ["host-flap", "detection", "window"] and n in (6, 9) and w[4] == "threshold" and \
            (n == 6 or w[6:8] == ["expiry", "timeout"]):
        bgp.evpn_host_flap = (int(w[3]), int(w[5]), int(w[8]) if n == 9 else 0)
        return True
    return False


# ethernet segments ---------------------------------------------------------------------------------------------------

def esi_from_eos(text: str) -> str:
    """EOS identifier 0000:0000:0021:0022:0020 (10 bytes, the type first), checked and lower-cased."""
    groups = text.split(":")
    if len(groups) != 5 or not all(len(g) == 4 and _HEX.match(g) for g in groups):
        raise ValueError(text)
    return text.lower()


def esi_from_ios(kind: str, value: str) -> str:
    """IOS identifier type 0 00.00.00.00.21.00.22.00.20 (the 9 bytes after the type)."""
    octets = value.split(".")
    if len(octets) != 9 or not all(len(o) == 2 and _HEX.match(o) for o in octets) or not kind.isdigit():
        raise ValueError(value)
    raw = f"{int(kind):02x}" + "".join(octets)
    return ":".join(raw[i:i + 4] for i in range(0, 20, 4)).lower()


def esi_to_ios(esi: str) -> Tuple[int, str]:
    raw = esi.replace(":", "")
    return int(raw[:2], 16), ".".join(raw[i:i + 2] for i in range(2, 20, 2))


def es_number(iface: Interface) -> int:
    """IOS numbers its ethernet segments; RouterShift takes the port-channel's number."""
    digits = re.findall(r"\d+", iface.name)
    return int(digits[-1]) if digits else 1


def segments(device: Device) -> List[Interface]:
    return [i for i in device.interfaces.values() if i.evpn_esi]


def es_line(iface: Interface, w: List[str]) -> bool:
    """EOS evpn ethernet-segment block lines."""
    n = len(w)
    if w[0] == "identifier" and n == 2:
        iface.evpn_esi = esi_from_eos(w[1])
    elif w[:2] == ["route-target", "import"] and n == 3:
        iface.evpn_es_rt = w[2].lower()
    elif w[:5] == ["designated-forwarder", "election", "algorithm", "preference", "value"] and n == 6:
        iface.evpn_df_preference = int(w[5])
    elif w == ["redundancy", "single-active"]:
        iface.evpn_single_active = True
    elif w == ["redundancy", "all-active"]:
        iface.evpn_single_active = False
    else:
        return False
    return True


def ios_es_line(iface: Interface, w: List[str]) -> bool:
    """IOS l2vpn evpn ethernet-segment N block lines."""
    n = len(w)
    if w[:2] == ["identifier", "type"] and n == 4:
        iface.evpn_esi = esi_from_ios(w[2], w[3])
    elif w[0] == "redundancy" and n == 2 and w[1] in ("all-active", "single-active"):
        iface.evpn_single_active = w[1] == "single-active"
    elif w[:2] == ["df-election", "preference"] and n == 3:
        iface.evpn_df_preference = int(w[2])
    else:
        return False
    return True


# writers -------------------------------------------------------------------------------------------------------------

def targets_lines(inst: EvpnInstance, ind: str) -> List[str]:
    if inst.rt_import and inst.rt_import == inst.rt_export:
        return [f"{ind}route-target both {rt}" for rt in inst.rt_import]
    return [f"{ind}route-target import {rt}" for rt in inst.rt_import] + \
        [f"{ind}route-target export {rt}" for rt in inst.rt_export]


def eos_instances(vx: Vxlan, ind: str) -> List[str]:
    """EOS router bgp: vlan N and vlan-aware-bundle NAME blocks."""
    lines: List[str] = []
    covered = set()
    for inst in vx.evpn_instances.values():
        covered |= set(inst.vlans)
        if inst.bundle:
            lines.append(f"vlan-aware-bundle {inst.name}")
        elif len(inst.vlans) == 1:
            lines.append(f"vlan {inst.vlans[0]}")
        else:
            continue
        lines.append(f"{ind}rd {inst.rd or 'auto'}")
        lines += targets_lines(inst, ind) or [f"{ind}route-target both auto"]
        lines.append(f"{ind}redistribute learned")
        if inst.igmp:
            lines.append(f"{ind}redistribute igmp")
        if inst.bundle:
            lines.append(f"{ind}vlan {vlan_text(inst.vlans)}")
    for vid in vx.evpn_vlans:
        if vid not in covered:
            lines += [f"vlan {vid}", f"{ind}rd auto", f"{ind}route-target both auto", f"{ind}redistribute learned"]
    return lines


def ios_instance_of(vx: Vxlan, vid: int) -> Optional[EvpnInstance]:
    return next((i for i in vx.evpn_instances.values() if vid in i.vlans), None)


def ios_instances(vx: Vxlan, report: Report, ind: str) -> List[str]:
    """IOS: one l2vpn evpn instance per VLAN (vlan-based), with the route distinguisher and route targets."""
    lines: List[str] = []
    for vid in vx.evpn_vlans:
        inst = ios_instance_of(vx, vid)
        lines += [f"l2vpn evpn instance {vid} vlan-based", f"{ind}encapsulation vxlan"]
        if vid in vx.mcast_groups:
            lines.append(f"{ind}replication-type static")
        if inst is not None:
            if inst.rd and not inst.bundle:
                lines.append(f"{ind}rd {inst.rd}")
            lines += [f"{ind}route-target import {rt}" for rt in inst.rt_import]
            lines += [f"{ind}route-target export {rt}" for rt in inst.rt_export]
        lines.append("!")
    for inst in vx.evpn_instances.values():
        if inst.bundle:
            report.add("interface", LABEL, Severity.APPROX, "evpn-bundle",
                       f"VLAN-aware bundle {inst.name} becomes one VLAN-based EVPN instance per VLAN "
                       f"({vlan_text(inst.vlans)}) with the bundle's route targets"
                       + (f"; each takes its own automatic route distinguisher instead of {inst.rd}" if inst.rd
                          else ""))
        if inst.igmp:
            report.add("interface", LABEL, Severity.REVIEW, "evpn-igmp",
                       f"EVPN instance {inst.name} advertises IGMP joins (redistribute igmp); IOS XE does that with "
                       "tenant routed multicast, which is not written")
    return lines


def free_vlans(device: Device, count: int) -> List[int]:
    """VLANs the source does not use, for the layer 3 VNIs on IOS (from 3900 down)."""
    used = set(device.vlans) | {int(n[4:]) for n in device.interfaces if n.startswith("Vlan") and n[4:].isdigit()}
    result: List[int] = []
    vid = 3900
    while len(result) < count and vid > 1:
        if vid not in used:
            result.append(vid)
        vid -= 1
    return result


def ios_l3vni_vlans(device: Device, report: Report) -> Dict[str, int]:
    """The VLAN that carries each layer 3 VNI on IOS: the one the source used, or a free one."""
    vx = device.vxlan
    if vx is None:
        return {}
    result = {vrf: vid for vrf, vid in vx.vrf_vlans.items() if vrf in vx.vrf_vnis}
    missing = [vrf for vrf in vx.vrf_vnis if vrf not in result]
    for vrf, vid in zip(missing, free_vlans(device, len(missing))):
        result[vrf] = vid
    if missing:
        report.add("interface", LABEL, Severity.APPROX, "evpn-l3vni-vlan",
                   "IOS carries a layer 3 VNI in a VLAN with an SVI in the VRF: "
                   + ", ".join(f"VNI {vx.vrf_vnis[v]} ({v}) in VLAN {result[v]}" for v in missing if v in result)
                   + "; these VLANs are picked by RouterShift among those the source does not use")
    return result


def domains_report(bgp: Bgp, report: Report, ios: bool) -> None:
    label = f"bgp {bgp.local_as}"
    if ios and (bgp.evpn_domain or bgp.evpn_remote_domain or bgp.evpn_remote_peers):
        report.add("bgp", label, Severity.REVIEW, "evpn-domains",
                   "IOS XE has no EVPN domain gateway (EOS domain identifier "
                   f"{bgp.evpn_domain or '-'}, remote {bgp.evpn_remote_domain or '-'}, remote-domain neighbors "
                   f"{', '.join(bgp.evpn_remote_peers) or '-'}); the nearest is a Multi-Site border gateway "
                   "(l2vpn evpn multisite border-gateway), which is not written. The neighbors are activated for "
                   "EVPN as ordinary peers")
    if ios and bgp.evpn_inter_domain_nhs:
        report.add("bgp", label, Severity.REVIEW, "evpn-inter-domain",
                   "next-hop-self on IP-prefix routes passed between the EVPN domains is not written")
    if ios and bgp.evpn_import_discard:
        report.add("bgp", label, Severity.APPROX, "evpn-import-discard",
                   "'route import match-failure action discard' is left out: IOS XE keeps only routes some VRF "
                   "imports anyway")
    if ios and bgp.evpn_host_flap and bgp.evpn_host_flap[2]:
        window, moves, expiry = bgp.evpn_host_flap
        report.add("bgp", label, Severity.APPROX, "evpn-host-flap",
                   f"host-flap detection written as 'mac duplication limit {moves} time {window}' under l2vpn evpn; "
                   f"the expiry timeout ({expiry} s) has no equivalent")


def eos_af_lines(bgp: Bgp) -> List[str]:
    lines: List[str] = []
    lines += [f"neighbor {p} domain remote" for p in bgp.evpn_remote_peers]
    if bgp.evpn_inter_domain_nhs:
        lines.append("neighbor default next-hop-self received-evpn-routes route-type ip-prefix inter-domain")
    if bgp.evpn_domain:
        lines.append(f"domain identifier {bgp.evpn_domain}")
    if bgp.evpn_remote_domain:
        lines.append(f"domain identifier {bgp.evpn_remote_domain} remote")
    if bgp.evpn_import_discard:
        lines.append("route import match-failure action discard")
    if bgp.evpn_host_flap:
        window, moves, expiry = bgp.evpn_host_flap
        lines.append(f"host-flap detection window {window} threshold {moves}" +
                     (f" expiry timeout {expiry}" if expiry else ""))
    return lines


def ios_segments(device: Device, ind: str) -> List[str]:
    """IOS: l2vpn evpn ethernet-segment N for each LAG with an identifier (the LAG names its segment)."""
    lines: List[str] = []
    for iface in segments(device):
        kind, value = esi_to_ios(iface.evpn_esi)
        lines += [f"l2vpn evpn ethernet-segment {es_number(iface)}", f"{ind}identifier type {kind} {value}",
                  f"{ind}redundancy {'single-active' if iface.evpn_single_active else 'all-active'}"]
        if iface.evpn_df_preference is not None:
            lines.append(f"{ind}df-election preference {iface.evpn_df_preference}")
        lines.append("!")
    return lines
