# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""IGMP snooping and PIM helpers that every reader and writer shares."""

from __future__ import annotations

import ipaddress
from typing import Dict, List

from . import names
from .model import Device, VrfMulticast
from .report import Report, Severity

SNOOPS_BY_DEFAULT = ("ios", "eos")  # the others snoop only the VLANs they are told to
PIM_MODES = ("sparse", "dense", "sparse-dense")
LABEL = "IGMP snooping"


def stated(device: Device) -> bool:
    """Whether the source says anything about IGMP snooping."""
    return device.igmp_snooping is not None or device.igmp_querier or \
        any(v.igmp_snooping is not None or v.igmp_querier for v in device.vlans.values())


def finish(device: Device) -> None:
    """A reader's last step: on a platform that snoops by default, a VLAN statement means snooping is on; the group
    ACLs RouterShift wrote for rendezvous points on IOS become group prefixes again."""
    for rp_groups in [device.pim_rp_groups] + [m.rp_groups for m in device.multicast_vrfs.values()]:
        for rp, groups in rp_groups.items():
            acl = device.acls.get(groups[4:]) if groups.startswith("acl RS-PIM-RP-") else None
            if acl is not None and len(acl.entries) == 1 and acl.entries[0].action.value == "permit" and \
                    acl.entries[0].source != "any":
                rp_groups[rp] = acl.entries[0].source
                del device.acls[acl.name]
    if device.platform in SNOOPS_BY_DEFAULT and stated(device) and device.igmp_snooping is None:
        device.igmp_snooping = True


def snooped(device: Device) -> List[int]:
    """The VLANs that snoop IGMP."""
    if device.igmp_snooping is False:
        return []
    return sorted(v.vlan_id for v in device.vlans.values()
                  if v.igmp_snooping or v.igmp_snooping is None and device.igmp_snooping)


def queriers(device: Device) -> List[int]:
    on = snooped(device)
    return [vid for vid in on if device.igmp_querier or device.vlans[vid].igmp_querier]


def uses_pim(device: Device) -> bool:
    return device.multicast_routing or bool(device.pim_rps) or \
        any(i.pim or i.igmp_version is not None for i in device.interfaces.values())


def pim_unsupported(device: Device, report: Report, platform: str) -> None:
    if uses_pim(device):
        report.add("system", "multicast routing", Severity.REVIEW, "pim-unsupported",
                   f"{platform}: multicast routing (PIM, IGMP on routed interfaces) is not written; configure it by "
                   "hand")


def querier_unsupported(device: Device, report: Report, platform: str) -> None:
    if queriers(device):
        report.add("vlan", LABEL, Severity.REVIEW, "igmp-querier",
                   f"{platform}: the IGMP querier is set on the VLAN interface; not written")


# rendezvous points, anycast RP and MSDP ------------------------------------------------------------------------------

def vrf(device: Device, name: str) -> VrfMulticast:
    if name not in device.multicast_vrfs:
        device.multicast_vrfs[name] = VrfMulticast()
    return device.multicast_vrfs[name]


def _add_rp(device: Device, vrf_name: str, rp: str, groups: str) -> None:
    rps, rp_groups = (device.pim_rps, device.pim_rp_groups) if not vrf_name else \
        (vrf(device, vrf_name).rps, vrf(device, vrf_name).rp_groups)
    if rp not in rps:
        rps.append(rp)
    if groups:
        rp_groups[rp] = groups


def eos_pim_line(device: Device, vrf_name: str, w: List[str]) -> bool:
    """EOS router pim sparse-mode / [vrf V /] ipv4: rp address A [G/len | access-list ACL], anycast-rp A PEER."""
    n = len(w)
    if w[:2] == ["rp", "address"] and n in (3, 4, 5):
        rp = str(ipaddress.IPv4Address(w[2]))
        if n == 3:
            groups = ""
        elif n == 4:
            groups = str(ipaddress.IPv4Network(w[3]))
        elif w[3] == "access-list":
            groups = f"acl {w[4]}"
        else:
            return False
        _add_rp(device, vrf_name, rp, groups)
        return True
    if w[0] == "anycast-rp" and n == 3 and not vrf_name:
        device.pim_anycast.setdefault(str(ipaddress.IPv4Address(w[1])), []).append(
            str(ipaddress.IPv4Address(w[2])))
        return True
    return False


def ios_rp(device: Device, w: List[str]) -> bool:
    """IOS: ip pim [vrf V] rp-address A [ACL] [override] (w starts after 'ip pim')."""
    vrf_name = ""
    if w[:1] == ["vrf"] and len(w) >= 2:
        vrf_name, w = w[1], w[2:]
    if w[:1] != ["rp-address"] or len(w) < 2:
        return False
    rest = [x for x in w[2:] if x != "override"]
    if len(rest) > 1:
        return False
    _add_rp(device, vrf_name, str(ipaddress.IPv4Address(w[1])), f"acl {rest[0]}" if rest else "")
    return True


def ios_msdp(device: Device, w: List[str]) -> bool:
    """IOS: ip msdp peer A [connect-source I] [remote-as N] (w starts after 'peer')."""
    peer = str(ipaddress.IPv4Address(w[0]))
    source = ""
    rest = w[1:]
    while rest:
        if rest[0] == "connect-source" and len(rest) >= 2:
            source, rest = names.canonical(rest[1])[0], rest[2:]
        elif rest[0] == "remote-as" and len(rest) >= 2:
            rest = rest[2:]
        else:
            return False
    device.msdp_peers[peer] = source
    return True


def rp_acl_name(rp: str, vrf_name: str = "") -> str:
    return "RS-PIM-RP-" + rp.replace(".", "-") + (f"-{vrf_name}" if vrf_name else "")


def ios_rp_lines(rps: List[str], rp_groups: Dict[str, str], vrf_name: str, vrf_target: str) -> List[str]:
    """IOS: ip pim [vrf V] rp-address A [ACL], with a standard ACL for a group prefix."""
    lines: List[str] = []
    where = f"vrf {vrf_target} " if vrf_name else ""
    for rp in rps:
        groups = rp_groups.get(rp, "")
        if groups.startswith("acl "):
            lines.append(f"ip pim {where}rp-address {rp} {groups[4:]}")
        elif groups:
            net = ipaddress.IPv4Network(groups)
            name = rp_acl_name(rp, vrf_name)
            lines += [f"ip access-list standard {name}", f" permit {net.network_address} {net.hostmask}",
                      f"ip pim {where}rp-address {rp} {name}"]
        else:
            lines.append(f"ip pim {where}rp-address {rp}")
    return lines


def eos_rp_lines(rps: List[str], rp_groups: Dict[str, str], ind: str) -> List[str]:
    lines: List[str] = []
    for rp in rps:
        groups = rp_groups.get(rp, "")
        if groups.startswith("acl "):
            lines.append(f"{ind}rp address {rp} access-list {groups[4:]}")
        else:
            lines.append(f"{ind}rp address {rp}" + (f" {groups}" if groups else ""))
    return lines
