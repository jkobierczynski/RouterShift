# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NX-OS QoS: classification and policing policies, the DSCP to traffic-class map, egress queuing, CoPP.

How the model maps to NX-OS (Nexus 9000, eight queues):

* A class is ``class-map type qos match-any NAME`` with ``match dscp`` and ``match access-group name``; a policy is
  ``policy-map type qos NAME`` with ``set dscp`` and ``police cir N kbps [bc N bytes] conform transmit violate drop``,
  applied inbound with ``service-policy type qos input``.
* Traffic class N is qos-group N, which the default queuing classes put in queue ``c-out-8q-qN``. NX-OS has no global
  DSCP map: RouterShift writes ``policy-map type qos RS-DSCP-MAP`` with a class ``RS-TC<n>`` per traffic class (the
  DSCP values of the map, ``set qos-group n``) and applies it inbound on the ports that queue by profile.
* A queuing profile is ``policy-map type queuing NAME``: a strict-priority queue is ``priority level 1``, a share
  ``bandwidth remaining percent N``, ECN marking ``random-detect ... ecn``, shaping ``shape min 0 kbps max N kbps``;
  a port takes it with ``service-policy type queuing output NAME``. A port with queue settings of its own on top of
  its profile gets the policy ``<profile>-P<n>``.
* CoPP is a profile (``copp profile strict``); the source's own classes and control-plane ACLs are reported, as they
  are set by copying the profile and editing it.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

from . import acl as acl_text
from . import qos as qos_text
from . import queuing as queuing_text
from .junosqos import merged
from .model import Device, Interface, QosAction, QosClass, QosPolicy, QosProfile, QosQueue
from .report import Report, Severity

KIND = "qos"
MAP_POLICY = "RS-DSCP-MAP"
TC_CLASS = "RS-TC"
DEFAULT_QUEUE = "c-out-8q-q-default"
Add = Callable[[Severity, str, str], None]


def _queue_class(tc: int) -> str:
    return DEFAULT_QUEUE if tc == 0 else f"c-out-8q-q{tc}"


# classification and policing ----------------------------------------------------------------------------------------

def class_lines(device: Device, report: Report, ind: str) -> List[str]:
    out: List[str] = []
    for c in device.qos_classes.values():
        label = f"class {c.name}"
        report.item(KIND, label)
        out.append(f"class-map type qos {'match-all' if c.match_all and c.dscp and c.acl else 'match-any'} {c.name}")
        if c.dscp:
            out.append(f"{ind}match dscp {','.join(str(d) for d in c.dscp)}")
        if c.acl and c.acl in device.acls:
            out.append(f"{ind}match access-group name {acl_text.safe_name(c.acl)}")
        elif c.acl:
            report.add(KIND, label, Severity.REVIEW, "acl-missing", f"ACL {c.acl} is not defined; left out")
    return out


def policy_lines(device: Device, report: Report, ind: str) -> List[str]:
    out: List[str] = []
    for p in device.qos_policies.values():
        report.item(KIND, f"policy {p.name}")
        out.append(f"policy-map type qos {p.name}")
        for a in p.actions:
            out.append(f"{ind}class {a.qos_class}")
            if a.set_dscp is not None:
                out.append(f"{ind * 2}set dscp {a.set_dscp}")
            if a.police_kbps is not None:
                burst = f" bc {a.burst_bytes} bytes" if a.burst_bytes else ""
                out.append(f"{ind * 2}police cir {a.police_kbps} kbps{burst} conform transmit violate drop")
    return out


def interface_policy_lines(device: Device, iface: Interface, add: Add) -> List[str]:
    out: List[str] = []
    for direction, name in (("input", iface.qos_policy_in), ("output", iface.qos_policy_out)):
        if not name:
            continue
        if name not in device.qos_policies:
            add(Severity.REVIEW, "qos-policy", f"policy {name} is applied but not defined; left out")
        elif direction == "output":
            add(Severity.REVIEW, "qos-output", f"a Nexus 9000 applies QoS policies inbound only; output policy {name} "
                                               "left out")
        else:
            out.append(f"service-policy type qos input {name}")
    if iface.qos_trust == "none":
        add(Severity.REVIEW, "qos-trust", "a Nexus 9000 classifies by DSCP on every port; 'no trust' is left out: "
                                          "remark with an input policy if the port must not be trusted")
    elif iface.qos_trust == "cos":
        add(Severity.APPROX, "qos-trust", "trust CoS left out: a Nexus 9000 classifies routed traffic by DSCP")
    return out


# queuing ------------------------------------------------------------------------------------------------------------

def _queue_lines(q: QosQueue, report: Report, label: str, ind: str) -> List[str]:
    tag = f"queue {q.traffic_class}" + (f" (class {q.source_class})" if q.source_class else "")
    lines: List[str] = []
    left: List[str] = []
    if q.priority or q.priority_level is not None:
        lines.append(f"priority level {q.priority_level or 1}")
        if q.priority_percent is not None:
            left.append(f"its priority share of {q.priority_percent} percent")
    elif q.bandwidth_remaining is not None:
        lines.append(f"bandwidth remaining percent {q.bandwidth_remaining}")
    elif q.bandwidth_percent is not None:
        lines.append(f"bandwidth remaining percent {q.bandwidth_percent}")
        report.add(KIND, label, Severity.APPROX, "qos-bandwidth",
                   f"{tag}: 'bandwidth percent {q.bandwidth_percent}' is written as a share of what the priority "
                   "queues leave, the form NX-OS takes")
    if q.shape_kbps is not None:
        lines.append(f"shape min 0 kbps max {q.shape_kbps} kbps")
    elif q.shape_percent is not None and q.shape_percent != q.priority_percent:
        left.append(f"shaping to {q.shape_percent} percent (NX-OS shapes to a rate)")
    if q.ecn:
        low, high, mark = q.ecn
        lines.append(f"random-detect minimum-threshold {low} kbytes maximum-threshold {high} kbytes drop-probability "
                     f"{mark} weight 0 ecn")
    elif q.wred:
        left.append("WRED without thresholds")
    if q.queue_limit is not None:
        left.append("the queue limit")
    if q.fair_queue:
        left.append("fair queuing")
    if left:
        report.add(KIND, label, Severity.APPROX, "qos-queue-options", f"{tag}: {', '.join(left)} left out")
    return [ind + line for line in lines]


def queuing_policy(name: str, queues: Dict[int, QosQueue], report: Report, label: str, ind: str) -> List[str]:
    out = [f"policy-map type queuing {name}"]
    for tc in sorted(queues, reverse=True):
        out.append(f"{ind}class type queuing {_queue_class(tc)}")
        out += _queue_lines(queues[tc], report, label, ind * 2)
    return out


def _signature(queues: Dict[int, QosQueue]) -> List[Tuple[int, object]]:
    return [(tc, (bool(q.priority or q.priority_level is not None), q.priority_level, q.bandwidth_remaining,
                  q.bandwidth_percent, q.shape_kbps, q.ecn)) for tc, q in sorted(queues.items())]


class Writer:
    def __init__(self, device: Device, report: Report, ind: str) -> None:
        self.device, self.report, self.ind = device, report, ind
        self.port_policies: Dict[Tuple[str, str], str] = {}  # (profile, queues key) -> queuing policy
        self.map_written = False

    def lines(self) -> List[str]:
        d = self.device
        out: List[str] = []
        if d.qos_dscp_tc or d.qos_tc_dscp:
            self.report.item(KIND, queuing_text.MAP_LABEL)
        by_tc: Dict[int, List[int]] = {}
        for dscp, tc in sorted(d.qos_dscp_tc.items()):
            by_tc.setdefault(tc, []).append(dscp)
        if by_tc:
            self.map_written = True
            for tc, values in sorted(by_tc.items(), reverse=True):
                out += [f"class-map type qos match-any {TC_CLASS}{tc}",
                        f"{self.ind}match dscp {','.join(str(v) for v in values)}"]
            out.append(f"policy-map type qos {MAP_POLICY}")
            for tc in sorted(by_tc, reverse=True):
                out += [f"{self.ind}class {TC_CLASS}{tc}", f"{self.ind * 2}set qos-group {tc}"]
            self.report.add(KIND, queuing_text.MAP_LABEL, Severity.APPROX, "qos-map",
                            f"NX-OS has no global DSCP map: it is written as policy {MAP_POLICY} (set qos-group per "
                            "traffic class), applied inbound on the ports that queue by profile")
        if d.qos_tc_dscp:
            self.report.add(KIND, queuing_text.MAP_LABEL, Severity.APPROX, "qos-rewrite",
                            "the traffic-class to DSCP map (" + ", ".join(f"{tc} -> {v}" for tc, v in
                                                                         sorted(d.qos_tc_dscp.items()))
                            + ") is left out: NX-OS rewrites DSCP with a QoS policy (set dscp)")
        for p in d.qos_profiles.values():
            label = queuing_text.profile_label(p.name)
            self.report.item(KIND, label)
            out += queuing_policy(p.name, p.queues, self.report, label, self.ind)
            if p.shape_kbps:
                self.report.add(KIND, label, Severity.REVIEW, "qos-shape",
                                f"the port shaping to {p.shape_kbps} kbps is left out; shape the queues instead")
        for iface in d.interfaces.values():
            profile = d.qos_profiles.get(iface.qos_profile) if iface.qos_profile else None
            if profile is None or not iface.queues or \
                    _signature(merged(profile, iface.queues)) == _signature(profile.queues):
                continue
            key = (profile.name, repr(sorted((tc, vars(q)) for tc, q in iface.queues.items())))
            if key not in self.port_policies:
                name = f"{profile.name}-P{sum(1 for p, _ in self.port_policies if p == profile.name) + 1}"
                self.port_policies[key] = name
                label = queuing_text.profile_label(name)
                self.report.item(KIND, label)
                out += queuing_policy(name, merged(profile, iface.queues), self.report, label, self.ind)
        return out

    def interface(self, iface: Interface, add: Add) -> List[str]:
        """The queuing policy, the DSCP map and the profile's input policy, on a port that takes a profile."""
        profile = self.device.qos_profiles.get(iface.qos_profile) if iface.qos_profile else None
        if profile is None:
            if iface.qos_profile:
                add(Severity.REVIEW, "qos-profile", f"profile {iface.qos_profile} is applied but not defined")
            elif iface.queues:
                add(Severity.REVIEW, "qos-port-queues", "the port's own queue settings have no profile; not written")
            return []
        name = profile.name
        key = (profile.name, repr(sorted((tc, vars(q)) for tc, q in iface.queues.items())))
        if iface.queues and key in self.port_policies:
            name = self.port_policies[key]
            add(Severity.APPROX, "qos-port-queues",
                f"the port's own queue settings are written as queuing policy {name}, profile {profile.name} with "
                "them on top")
        elif iface.queues:
            add(Severity.APPROX, "qos-port-queues",
                f"the port's own queue settings have no place in an NX-OS queuing policy; it takes {profile.name}")
        lines = [f"service-policy type queuing output {name}"]
        input_policy = iface.qos_policy_in or (profile.input_policy if profile.input_policy in
                                               self.device.qos_policies else "")
        if self.map_written and not input_policy:
            lines.append(f"service-policy type qos input {MAP_POLICY}")
        elif profile.input_policy and not iface.qos_policy_in and input_policy:
            lines.append(f"service-policy type qos input {input_policy}")
            add(Severity.APPROX, "qos-input-policy",
                f"the input policy {input_policy} of profile {profile.name} is applied on the port")
        if self.map_written and input_policy:
            add(Severity.REVIEW, "qos-map",
                f"the port has input policy {input_policy}, so the DSCP map ({MAP_POLICY}) is not applied: add "
                "'set qos-group' to its classes")
        if profile.trust == "none":
            add(Severity.REVIEW, "qos-trust", f"profile {profile.name} trusts nothing; a Nexus 9000 classifies by DSCP")
        return lines


def copp(device: Device, report: Report) -> List[str]:
    cp = device.control_plane
    if cp is None or not (cp.acls or cp.classes or cp.policy):
        return []
    report.item("system", "control plane")
    rates = ", ".join(f"{c.name} {c.pps} pps" if c.pps else f"{c.name} {c.kbps} kbps" if c.kbps else c.name
                      for c in cp.classes)
    acls = ", ".join(f"{a} ({v or 'default'})" for v, a in cp.acls.items())
    report.add("system", "control plane", Severity.REVIEW, "copp",
               "NX-OS protects its CPU with a CoPP profile: 'copp profile strict' is written. The source's own "
               + ", ".join(x for x in (f"classes ({rates})" if rates else "",
                                       f"control-plane ACLs {acls}" if acls else "") if x)
               + " are not written: copy the profile (copp copy profile strict prefix RS) and edit its classes")
    return ["copp profile strict"]


# reading ------------------------------------------------------------------------------------------------------------

def read_policy(device: Device, name: str, children: List[Tuple[List[str], List[List[str]]]]) -> List[Tuple[int, int]]:
    """policy-map type qos NAME: a policy, or the DSCP map RouterShift writes (set qos-group per class)."""
    bad: List[Tuple[int, int]] = []
    groups: Dict[str, int] = {}
    policy = QosPolicy(name)
    for n, (w, lines) in enumerate(children):
        if w[0] != "class" or len(w) != 2:
            bad.append((n, -1))
            continue
        action = QosAction(w[1])
        for k, line in enumerate(lines):
            if line[:2] == ["set", "qos-group"] and len(line) == 3 and line[2].isdigit():
                groups[w[1]] = int(line[2])
            else:
                try:
                    ok = action_line(action, line)
                except (ValueError, IndexError):
                    ok = False
                if not ok:
                    bad.append((n, k))
        policy.actions.append(action)
    if name == MAP_POLICY and groups:
        for cls, tc in groups.items():
            qos_class = device.qos_classes.pop(cls, None)
            for dscp in qos_class.dscp if qos_class is not None else []:
                device.qos_dscp_tc[dscp] = tc
        device.qos_dscp_tc = dict(sorted(device.qos_dscp_tc.items()))
        return bad
    device.qos_policies[name] = policy
    return bad


def read_queuing(device: Device, name: str, children: List[Tuple[List[str], List[List[str]]]]) -> List[Tuple[int, int]]:
    """policy-map type queuing NAME: a queuing profile, its classes the eight queues."""
    profile = QosProfile(name)
    bad: List[Tuple[int, int]] = []
    for n, (w, lines) in enumerate(children):
        m = re.match(r"^c-out-8q-q(\d|-default)$", w[3]) if w[:3] == ["class", "type", "queuing"] and len(w) == 4 \
            else None
        if m is None:
            bad.append((n, -1))
            continue
        tc = 0 if m.group(1) == "-default" else int(m.group(1))
        q = QosQueue(tc)
        for k, line in enumerate(lines):
            if not _queue_line(q, line):
                bad.append((n, k))
        profile.queues[tc] = q
    device.qos_profiles[name] = profile
    return bad


def _queue_line(q: QosQueue, w: List[str]) -> bool:
    n = len(w)
    if w[:2] == ["priority", "level"] and n == 3 and w[2].isdigit():
        q.priority = True
        q.priority_level = None if w[2] == "1" else int(w[2])
    elif w == ["priority"]:
        q.priority = True
    elif w[:3] == ["bandwidth", "remaining", "percent"] and n == 4:
        q.bandwidth_remaining = int(w[3])
    elif w[:2] == ["bandwidth", "percent"] and n == 3:
        q.bandwidth_percent = int(w[2])
    elif w[:2] == ["shape", "min"] and n == 7 and w[4] == "max" and w[3] == "kbps" and w[6] == "kbps":
        q.shape_kbps = int(w[5])
    elif w[0] == "random-detect" and n == 12 and w[1] == "minimum-threshold" and w[4] == "maximum-threshold" and \
            w[7] == "drop-probability" and w[3] == w[6] == "kbytes" and w[-1] == "ecn":
        q.ecn = (int(w[2]), int(w[5]), int(w[8]))
    else:
        return False
    return True


def finish(device: Device, applied: Dict[str, str]) -> None:
    """Policies named <profile>-P<n> are the port settings of <profile>; the DSCP map's input policy is dropped."""
    port_policies = {name: m.group(1) for name in device.qos_profiles
                     if (m := re.match(r"^(.+)-P\d+$", name)) and m.group(1) in device.qos_profiles}
    for port, name in applied.items():
        iface = device.interfaces.get(port)
        if iface is None:
            continue
        if name in port_policies:
            base = device.qos_profiles[port_policies[name]]
            iface.qos_profile = base.name
            iface.queues = _own(base.queues, device.qos_profiles[name].queues)
        else:
            iface.qos_profile = name
    for name in port_policies:
        del device.qos_profiles[name]
    for iface in device.interfaces.values():
        if iface.qos_policy_in == MAP_POLICY and device.qos_dscp_tc:
            iface.qos_policy_in = ""


def _own(base: Dict[int, QosQueue], port: Dict[int, QosQueue]) -> Dict[int, QosQueue]:
    out: Dict[int, QosQueue] = {}
    for tc, q in port.items():
        b = base.get(tc, QosQueue(tc))
        diff = {k: v for k, v in vars(q).items() if v != getattr(b, k)}
        if diff:
            out[tc] = QosQueue(tc, **diff)
    return out


def action_line(action: QosAction, w: List[str]) -> bool:
    """set dscp X | police cir ... (NX-OS)."""
    if w[:2] == ["set", "dscp"] and len(w) == 3:
        action.set_dscp = qos_text.dscp(w[2])
        return True
    return bool(police_line(action, w))


def police_line(action: QosAction, w: List[str]) -> Optional[bool]:
    """NX-OS: police cir N kbps|mbps [bc N bytes|kbytes] conform transmit violate drop."""
    if w[:2] != ["police", "cir"] or w[-4:] != ["conform", "transmit", "violate", "drop"]:
        return None
    args = w[2:-4]
    if len(args) not in (2, 5) or args[1] not in ("bps", "kbps", "mbps", "gbps"):
        return False
    rate = int(args[0]) * {"bps": 1, "kbps": 1000, "mbps": 1000000, "gbps": 1000000000}[args[1]]
    action.police_kbps = max(1, rate // 1000)
    if len(args) == 5:
        if args[2] != "bc" or args[4] not in ("bytes", "kbytes", "mbytes"):
            return False
        action.burst_bytes = int(args[3]) * {"bytes": 1, "kbytes": 1000, "mbytes": 1000000}[args[4]]
    return True
