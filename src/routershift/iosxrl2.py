# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""IOS-XR settings of a bridge domain and its ports: storm control, IGMP snooping and MST, written and read.

IOS-XR limits storms per port of a bridge domain (``storm-control broadcast kbps N`` under the ``interface`` of the
bridge domain), as a rate rather than a share of the port speed. A level in percent is written as that share of the
port's speed: the speed the port is set to, else the one its name tells (a bundle: the sum of its members).
``unicast`` becomes ``unknown-unicast``, the only unicast IOS-XR limits. The reader turns a rate back into a share of
the port speed.

IGMP snooping is switched on per bridge domain with an ``igmp snooping profile``: RouterShift writes the empty
profile RS-IGMP-SNOOPING, and RS-IGMP-QUERIER with ``internal-querier`` for a VLAN that also sends the queries.

Spanning tree runs on the ports listed under ``spanning-tree mst NAME`` (RouterShift writes RS-MST), which also holds
the region name, revision and instances. Every layer 2 port is listed, with its edge (``portfast``), BPDU guard, root
guard, cost and priority. A per-VLAN mode is written as MST, every VLAN in instance 0.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from . import l2sec as l2sec_text
from . import multicast as multicast_text
from . import stp as stp_text
from .confparse import Node
from .model import Device, Interface, InterfaceKind, StpMode
from .report import Report, Severity

KINDS = ["broadcast", "multicast", "unknown-unicast"]
MIN_KBPS, MAX_KBPS = 64, 1280000
SNOOPING = "RS-IGMP-SNOOPING"
QUERIER = "RS-IGMP-QUERIER"
_MEDIA_MBPS = {"400g": 400000, "100g": 100000, "50g": 50000, "40g": 40000, "25g": 25000, "10g": 10000,
               "5g": 5000, "2.5g": 2500, "1g": 1000, "100m": 100}


def mbps(device: Device, iface: Interface) -> Optional[int]:
    """The speed of a port in Mbit/s, as it is set or as its name tells; a bundle adds up its members."""
    if iface.kind == InterfaceKind.LAG:
        members = [mbps(device, m) for m in device.interfaces.values() if m.lag == iface.name]
        return sum(m for m in members if m) if members and all(members) else None
    if iface.speed:
        return iface.speed
    return _MEDIA_MBPS.get(iface.media)


# Writing -------------------------------------------------------------------------------------------------------------

def storm_lines(device: Device, iface: Interface, report: Report, label: str) -> List[str]:
    """The storm-control lines of a port in a bridge domain."""
    if not iface.storm_control:
        return []
    speed = mbps(device, iface)
    levels = l2sec_text.storm(iface, "unknown-unicast", KINDS, report, label, "IOS-XR")
    if speed is None:
        report.add("interface", label, Severity.REVIEW, "storm-control",
                   "the storm control is not written: IOS-XR limits storms in kbps or pps, and the speed of the port "
                   "is not known to turn the percentages into a rate; set it by hand")
        return []
    lines = []
    for kind, level in levels.items():
        kbps = round(speed * 1000 * level / 100)
        kept = min(max(kbps, MIN_KBPS), MAX_KBPS)
        lines.append(f"storm-control {kind} kbps {kept}")
        note = f"{kind} {l2sec_text.level_text(level)}% of {speed} Mbit/s is written as {kept} kbps"
        if kept != kbps:
            note += f" (IOS-XR takes {MIN_KBPS} to {MAX_KBPS} kbps)"
        report.add("interface", label, Severity.APPROX, "storm-rate", note)
    return lines


def snooping_plan(device: Device, vids: List[int], report: Report) -> Tuple[List[str], Dict[int, str]]:
    """The IGMP snooping profiles and the one each bridge domain (by VLAN) takes."""
    d = device
    if not multicast_text.stated(d):
        return [], {}
    report.item("vlan", multicast_text.LABEL)
    snooped = set(multicast_text.snooped(d))
    plan: Dict[int, str] = {}
    for vid in vids:
        vlan = d.vlans.get(vid)
        if vid in snooped or vlan is None and d.igmp_snooping:  # a VLAN only a port names snoops as all others
            plan[vid] = QUERIER if d.igmp_querier or vlan is not None and vlan.igmp_querier else SNOOPING
    out: List[str] = []
    if SNOOPING in plan.values():
        out += [f"igmp snooping profile {SNOOPING}", "!"]
    if QUERIER in plan.values():
        out += [f"igmp snooping profile {QUERIER}", " internal-querier", "!"]
        if d.igmp_querier_address or d.igmp_querier_version or any(
                v.igmp_querier_address or v.igmp_querier_version for v in d.vlans.values()):
            report.add("vlan", multicast_text.LABEL, Severity.APPROX, "igmp-querier",
                       "the querier's source address and version are not written: the IOS-XR internal querier "
                       "takes its address from 'system-ip-address' in the profile; set it by hand")
    return out, plan


# Reading -------------------------------------------------------------------------------------------------------------

class Reader:
    """Storm control rates and IGMP snooping profiles of bridge domains back into the model."""

    def __init__(self, device: Device) -> None:
        self.device = device
        self.rates: Dict[str, Dict[str, Tuple[int, Node]]] = {}  # canonical port -> kind -> kbps and its line
        self.queriers: List[str] = []  # profiles with internal-querier
        self.vlan_profiles: Dict[int, str] = {}  # VLAN -> the IGMP snooping profile of its bridge domain
        self.domains: List[int] = []  # the VLAN of every bridge domain

    def storm(self, port: str, node: Node) -> bool:
        """storm-control broadcast|multicast|unknown-unicast kbps N"""
        words = node.words
        if len(words) != 4 or words[0] != "storm-control" or words[1] not in KINDS or words[2] != "kbps" or \
                not words[3].isdigit():
            return False
        self.rates.setdefault(port, {})[words[1]] = (int(words[3]), node)
        return True

    def profile(self, name: str, children: List[List[str]]) -> bool:
        """igmp snooping profile NAME, empty or with internal-querier"""
        for c in children:
            if c != ["internal-querier"]:
                return False
        if children:
            self.queriers.append(name)
        return True

    def finish(self) -> List[Node]:
        """Rates become percentages of the port speed; returns the lines of ports whose speed is not known."""
        d = self.device
        unread: List[Node] = []
        for name, rates in self.rates.items():
            iface = d.interfaces.get(name)
            speed = mbps(d, iface) if iface is not None else None
            for kind, (kbps, node) in rates.items():
                if iface is None or speed is None:
                    unread.append(node)
                else:
                    iface.storm_control[kind] = round(kbps * 100 / (speed * 1000), 2)
        profiles = self.vlan_profiles
        if profiles and set(profiles) == set(self.domains):  # every bridge domain snoops
            d.igmp_snooping = True
            d.igmp_querier = all(p in self.queriers for p in profiles.values())
        for vid, profile in profiles.items():
            vlan = d.vlans.get(vid)
            if vlan is not None and not d.igmp_snooping:
                vlan.igmp_snooping = True
            if vlan is not None and not d.igmp_querier:
                vlan.igmp_querier = profile in self.queriers
        return unread


# Spanning tree -------------------------------------------------------------------------------------------------------

MST_NAME = "RS-MST"


def runs_mst(device: Device) -> bool:
    """Whether the bridge domains get MST: the source runs a spanning tree it states."""
    s = device.stp
    return device.stp_mode not in (None, StpMode.NONE) or device.stp_mode is None and bool(
        s.priority or s.vlan_priority or s.region or s.instances)


def mst_lines(device: Device, ports: List[Tuple[str, Interface]], report: Report) -> List[str]:
    """MST for the bridge domains: the region, the instance priorities and VLANs, and the ports (IOS-XR name, port)
    with their edge, BPDU guard, root guard, cost and priority settings."""
    d = device
    s = d.stp
    if not runs_mst(d):
        return []
    report.item("system", "spanning-tree mode")
    if d.stp_mode not in (None, StpMode.MSTP):
        report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                   f"IOS-XR bridge domains run MST (or PVRST on some platforms); {d.stp_mode.value} is written as MST "
                   "with every VLAN in instance 0")
    report.add("system", "spanning-tree mode", Severity.INFO, "stp-ports",
               "IOS-XR runs spanning tree only on the ports listed under 'spanning-tree mst'; every port of a bridge "
               "domain is listed")
    priority, _ = stp_text.priorities(d, StpMode.MSTP, report)
    lines = [f"spanning-tree mst {MST_NAME}"]
    if stp_text.region(d, StpMode.MSTP, report):
        if s.region:
            lines.append(f" name {s.region}")
        if s.revision is not None:
            lines.append(f" revision {s.revision}")
    for instance in sorted(set(priority) | set(s.instances)):
        lines.append(f" instance {instance}")
        if instance in s.instances and instance:
            lines.append(f"  vlan-ids {stp_text.vlan_text(s.instances[instance])}")
        if instance in priority:
            lines.append(f"  priority {priority[instance]}")
        lines.append(" !")
    for name, iface in ports:
        lines.append(f" interface {name}")
        if iface.stp_portfast:
            lines.append("  portfast")
        if iface.stp_bpduguard:
            lines.append("  portfast bpduguard")
        if iface.stp_guard == "root":
            lines.append("  guard root")
        if iface.stp_cost is not None:
            lines.append(f"  instance 0 cost {iface.stp_cost}")
        if iface.stp_port_priority is not None:
            lines.append(f"  instance 0 port-priority {iface.stp_port_priority}")
        lines.append(" !")
    return lines + ["!"]


def read_mst(device: Device, node: Node, port: Callable[[str], Interface],
             unparsed: Callable[[Node, str], None]) -> bool:
    """spanning-tree mst NAME / name, revision, instance N (vlan-ids, priority), interface X (portfast, ...)"""
    if node.words[:2] != ["spanning-tree", "mst"] or len(node.words) != 3:
        return False
    d = device
    s = d.stp
    d.stp_mode = StpMode.MSTP
    for child in node.children:
        c = child.words
        if c[0] == "name" and len(c) == 2:
            s.region = c[1]
        elif c[0] == "revision" and len(c) == 2 and c[1].isdigit():
            s.revision = int(c[1])
        elif c[0] == "instance" and len(c) == 2 and c[1].isdigit():
            n = int(c[1])
            for sub in child.children:
                w = sub.words
                if w[0] == "vlan-ids" and len(w) == 2:
                    s.instances[n] = _vlan_ids(w[1])
                elif w[0] == "priority" and len(w) == 2 and w[1].isdigit():
                    s.priority[n] = int(w[1])
                else:
                    unparsed(sub, node.text)
        elif c[0] == "interface" and len(c) == 2:
            iface = port(c[1])
            for sub in child.children:
                w = sub.words
                if w == ["portfast"]:
                    iface.stp_portfast = True
                elif w == ["portfast", "bpduguard"]:
                    iface.stp_bpduguard = True
                elif w == ["guard", "root"]:
                    iface.stp_guard = "root"
                elif w[:2] == ["instance", "0"] and len(w) == 4 and w[2] == "cost" and w[3].isdigit():
                    iface.stp_cost = int(w[3])
                elif w[:2] == ["instance", "0"] and len(w) == 4 and w[2] == "port-priority" and w[3].isdigit():
                    iface.stp_port_priority = int(w[3])
                else:
                    unparsed(sub, node.text)
        else:
            unparsed(child, node.text)
    return True


def _vlan_ids(text: str) -> List[int]:
    result: List[int] = []
    for part in text.split(","):
        low, _, high = part.partition("-")
        result += list(range(int(low), int(high or low) + 1))
    return result
