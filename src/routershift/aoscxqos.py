# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AOS-CX egress queuing: the DSCP map and schedule profiles.

How the model maps to AOS-CX:

* Traffic class N is local priority N, which the default queue profile puts in queue N: the DSCP to traffic-class
  map is ``qos dscp-map D local-priority N``.
* A queuing profile is a schedule profile of its own name: a strict-priority queue is ``strict queue N``, a share of
  the port ``dwrr queue N weight P`` (the weights of the queues are their shares). A port takes the profile with
  ``apply qos schedule-profile NAME`` and its trust with ``qos trust``. A port with queue settings of its own on top
  of its profile gets the schedule profile ``<profile>-P<n>``.
* Queue shaping, WRED and ECN have no place in an AOS-CX schedule profile and are reported.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Tuple

from . import queuing as queuing_text
from .junosqos import merged
from .model import Device, Interface, InterfaceKind, QosProfile, QosQueue
from .report import Report, Severity

KIND = "qos"
QUEUES = 8

Add = Callable[[Severity, str, str], None]


def _queue_lines(q: QosQueue, report: Report, label: str) -> List[str]:
    tag = f"queue {q.traffic_class}" + (f" (class {q.source_class})" if q.source_class else "")
    left: List[str] = []
    if q.priority or q.priority_level is not None:
        line = f"strict queue {q.traffic_class}"
        if q.priority_percent is not None:
            left.append(f"its priority share of {q.priority_percent} percent")
    elif q.bandwidth_percent is not None:
        line = f"dwrr queue {q.traffic_class} weight {q.bandwidth_percent}"
    elif q.bandwidth_remaining is not None:
        line = f"dwrr queue {q.traffic_class} weight {q.bandwidth_remaining}"
        report.add(KIND, label, Severity.APPROX, "qos-bandwidth-remaining",
                   f"{tag}: 'bandwidth remaining percent {q.bandwidth_remaining}' is written as a weight among the "
                   "queues that are not strict, which is what it is on AOS-CX")
    else:
        line = f"dwrr queue {q.traffic_class} weight 1"
        report.add(KIND, label, Severity.APPROX, "qos-weight",
                   f"{tag} has no share of its own: written with weight 1")
    if q.shape_percent is not None and q.shape_percent != q.priority_percent:
        left.append(f"shaping to {q.shape_percent} percent")
    elif q.shape_kbps is not None:
        left.append(f"shaping to {q.shape_kbps} kbps")
    if q.wred or q.ecn:
        left.append("ECN marking" if q.ecn else "WRED")
    if q.queue_limit is not None:
        left.append("the queue limit")
    if q.fair_queue:
        left.append("fair queuing")
    if left:
        report.add(KIND, label, Severity.APPROX, "qos-queue-options",
                   f"{tag}: {', '.join(left)} left out; AOS-CX schedule profiles take strict and DWRR queues only")
    return [line]


def schedule_profile(name: str, queues: Dict[int, QosQueue], report: Report, label: str, ind: str) -> List[str]:
    lines = [f"qos schedule-profile {name}"]
    for tc in sorted(queues, reverse=True):
        lines += [ind + line for line in _queue_lines(queues[tc], report, label)]
    missing = [str(tc) for tc in range(QUEUES) if tc not in queues]
    if missing:
        report.add(KIND, label, Severity.REVIEW, "qos-queues",
                   f"an AOS-CX schedule profile names every queue of the queue profile: add queues "
                   f"{', '.join(missing)} (dwrr with a weight) or use a queue profile with fewer queues")
    return lines


def _written(queues: Dict[int, QosQueue]) -> List[Tuple[int, bool, object]]:
    """What a schedule profile holds of the queues."""
    return [(tc, bool(q.priority or q.priority_level is not None),
             q.bandwidth_percent if q.bandwidth_percent is not None else q.bandwidth_remaining)
            for tc, q in sorted(queues.items())]


class Writer:
    def __init__(self, device: Device, report: Report, ind: str) -> None:
        self.device, self.report, self.ind = device, report, ind
        self.port_profiles: Dict[Tuple[str, str], str] = {}  # (profile, queues key) -> schedule profile

    def lines(self) -> List[str]:
        d = self.device
        out: List[str] = []
        if d.qos_dscp_tc or d.qos_tc_dscp:
            self.report.item(KIND, queuing_text.MAP_LABEL)
        out += [f"qos dscp-map {dscp} local-priority {tc}" for dscp, tc in sorted(d.qos_dscp_tc.items())]
        if d.qos_tc_dscp:
            self.report.add(KIND, queuing_text.MAP_LABEL, Severity.APPROX, "qos-rewrite",
                            "the traffic-class to DSCP map (" + ", ".join(f"{tc} -> {v}" for tc, v in
                                                                         sorted(d.qos_tc_dscp.items()))
                            + ") is left out: AOS-CX rewrites DSCP with a QoS policy (action dscp)")
        for p in d.qos_profiles.values():
            label = queuing_text.profile_label(p.name)
            self.report.item(KIND, label)
            out += schedule_profile(p.name, p.queues, self.report, label, self.ind)
            if p.shape_kbps:
                self.report.add(KIND, label, Severity.REVIEW, "qos-shape",
                                f"the port shaping to {p.shape_kbps} kbps is left out; set it on the ports by hand")
        for iface in d.interfaces.values():
            profile = d.qos_profiles.get(iface.qos_profile) if iface.qos_profile else None
            if profile is None or not iface.queues or \
                    _written(merged(profile, iface.queues)) == _written(profile.queues):
                continue
            key = (profile.name, repr(sorted((tc, vars(q)) for tc, q in iface.queues.items())))
            if key not in self.port_profiles:
                name = f"{profile.name}-P{sum(1 for p, _ in self.port_profiles if p == profile.name) + 1}"
                self.port_profiles[key] = name
                out += schedule_profile(name, merged(profile, iface.queues), self.report,
                                        queuing_text.profile_label(profile.name), self.ind)
        return out

    def interface(self, iface: Interface, add: Add) -> List[str]:
        """apply qos schedule-profile and the profile's trust and input policy, on a port that takes a profile."""
        profile = self.device.qos_profiles.get(iface.qos_profile) if iface.qos_profile else None
        if profile is None:
            if iface.queues:
                add(Severity.REVIEW, "qos-port-queues",
                    "the port's own queue settings have no profile to sit on; not written")
            return []
        name = profile.name
        key = (profile.name, repr(sorted((tc, vars(q)) for tc, q in iface.queues.items())))
        if iface.queues and key not in self.port_profiles:
            add(Severity.APPROX, "qos-port-queues",
                "the port's own queue settings (" + ", ".join(
                    f"queue {tc}: " + ", ".join(k.replace("_", " ") for k, v in vars(q).items()
                                                if k != "traffic_class" and v not in (None, False, ""))
                    for tc, q in sorted(iface.queues.items()))
                + f") have no place in an AOS-CX schedule profile; the port takes profile {profile.name}")
        elif iface.queues:
            name = self.port_profiles[key]
            add(Severity.APPROX, "qos-port-queues",
                f"the port's own queue settings are written as schedule profile {name}, profile {profile.name} with "
                "them on top")
        lines = [f"apply qos schedule-profile {name}"]
        if profile.trust and not iface.qos_trust:
            lines.append(f"qos trust {profile.trust}")
        if profile.input_policy and not iface.qos_policy_in:
            if profile.input_policy in self.device.qos_policies:
                lines.append(f"apply policy {profile.input_policy} "
                             f"{'routed-in' if iface.kind == InterfaceKind.VLAN else 'in'}")
                add(Severity.APPROX, "qos-input-policy",
                    f"the input policy {profile.input_policy} of profile {profile.name} is applied on the port")
        return lines


# reading ------------------------------------------------------------------------------------------------------------

def read_dscp_map(device: Device, w: List[str]) -> bool:
    """qos dscp-map D local-priority N [color C] [name X]."""
    if len(w) >= 5 and w[:2] == ["qos", "dscp-map"] and w[3] == "local-priority" and w[2].isdigit() and \
            w[4].isdigit() and (len(w) == 5 or w[5] in ("color", "name")):
        device.qos_dscp_tc[int(w[2])] = int(w[4])
        return True
    return False


def read_schedule_line(profile: QosProfile, w: List[str]) -> bool:
    if w[:2] == ["strict", "queue"] and len(w) == 3:
        profile.queues[int(w[2])] = QosQueue(int(w[2]), priority=True)
    elif w[:2] == ["dwrr", "queue"] and len(w) == 5 and w[3] == "weight":
        tc = int(w[2])
        profile.queues[tc] = QosQueue(tc, bandwidth_percent=None if w[4] == "1" else int(w[4]))
    else:
        return False
    return True


def finish(device: Device, applied: Dict[str, str]) -> None:
    """Profiles named <profile>-P<n> are the port settings of <profile>; queue order kept highest first."""
    for p in device.qos_profiles.values():
        p.queues = dict(sorted(p.queues.items(), reverse=True))
    port_profiles = {name: m.group(1) for name in device.qos_profiles
                     if (m := re.match(r"^(.+)-P\d+$", name)) and m.group(1) in device.qos_profiles}
    for port, name in applied.items():
        iface = device.interfaces.get(port)
        if iface is None:
            continue
        if name in port_profiles:
            base = device.qos_profiles[port_profiles[name]]
            iface.qos_profile = base.name
            iface.queues = _own(base.queues, device.qos_profiles[name].queues)
        else:
            iface.qos_profile = name
    for name in port_profiles:
        del device.qos_profiles[name]
    # a port's trust is its profile's when every port with the profile trusts the same
    by_profile: Dict[str, List[Interface]] = {}
    for iface in device.interfaces.values():
        if iface.qos_profile:
            by_profile.setdefault(iface.qos_profile, []).append(iface)
    for name, ports in by_profile.items():
        trusts = {i.qos_trust for i in ports}
        if len(trusts) == 1 and "" not in trusts:
            device.qos_profiles[name].trust = trusts.pop()
            for i in ports:
                i.qos_trust = ""


def _own(base: Dict[int, QosQueue], port: Dict[int, QosQueue]) -> Dict[int, QosQueue]:
    out: Dict[int, QosQueue] = {}
    for tc, q in port.items():
        b = base.get(tc, QosQueue(tc))
        diff = {k: v for k, v in vars(q).items() if v != getattr(b, k)}
        if diff:
            out[tc] = QosQueue(tc, **diff)
    return out
