# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""QoS queuing: the DSCP to traffic-class map, egress queue profiles (EOS qos profile with tx-queues, IOS output
policy-maps with priority, bandwidth, shaping and WRED), and the IOS and EOS forms of both.

EOS puts packets in a traffic class by their DSCP (qos map dscp X to traffic-class N) and schedules the queues of a
port by the profile applied to it. IOS classifies with class-maps in an output policy-map. RouterShift writes a
class-map RS-TC<n> for each traffic class on IOS, matching the DSCP values of the map, and reads an IOS queuing policy
back by giving its priority classes the highest traffic classes."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from . import qos as qos_text
from .model import Device, QosClass, QosProfile, QosQueue
from .report import Report, Severity

KIND = "qos"
MAP_LABEL = "DSCP to traffic-class map"
TC_CLASS = "RS-TC"
# IOS queuing actions: a policy-map with one of these in a class is an egress queuing policy
QUEUING_WORDS = ("priority", "bandwidth", "shape", "random-detect", "queue-limit", "fair-queue", "queue-buffers")


def profile_label(name: str) -> str:
    return f"profile {name}"


# EOS -----------------------------------------------------------------------------------------------------------------

def eos_map_line(device: Device, w: List[str]) -> bool:
    """qos map dscp D.. to traffic-class N; qos map traffic-class N to dscp D (w starts after 'qos map')."""
    if w[0] == "dscp" and len(w) >= 5 and w[-3:-1] == ["to", "traffic-class"]:
        tc = int(w[-1])
        for d in w[1:-3]:
            device.qos_dscp_tc[qos_text.dscp(d)] = tc
        return True
    if w[0] == "traffic-class" and len(w) == 5 and w[2:4] == ["to", "dscp"]:
        device.qos_tc_dscp[int(w[1])] = qos_text.dscp(w[4])
        return True
    return False


def eos_queue_line(queue: QosQueue, w: List[str]) -> bool:
    """A line of tx-queue N."""
    n = len(w)
    if w == ["priority", "strict"]:
        queue.priority = True
    elif w == ["no", "priority"]:
        queue.priority = False
    elif w[:2] == ["bandwidth", "percent"] and n == 3:
        queue.bandwidth_percent = int(w[2])
    elif w[:2] == ["shape", "rate"] and n == 4 and w[3] in ("percent", "kbps", "mbps"):
        if w[3] == "percent":
            queue.shape_percent = int(w[2])
        else:
            queue.shape_kbps = int(w[2]) * (1000 if w[3] == "mbps" else 1)
    elif w[:3] == ["random-detect", "ecn", "minimum-threshold"] and n == 10 and w[4] == "kbytes" and \
            w[5] == "maximum-threshold" and w[7] == "kbytes" and w[8] == "max-mark-probability":
        queue.ecn = (int(w[3]), int(w[6]), int(w[9]))
    else:
        return False
    return True


def eos_profile_line(profile: QosProfile, w: List[str]) -> bool:
    if w[:2] == ["qos", "trust"] and len(w) == 3 and w[2] in ("dscp", "cos", "disabled"):
        profile.trust = "none" if w[2] == "disabled" else w[2]
    elif w == ["no", "qos", "trust"]:
        profile.trust = "none"
    elif w[:4] == ["service-policy", "type", "qos", "input"] and len(w) == 5:
        profile.input_policy = w[4]
    elif w[:2] == ["shape", "rate"] and len(w) == 4 and w[3] in ("kbps", "mbps"):
        profile.shape_kbps = int(w[2]) * (1000 if w[3] == "mbps" else 1)
    else:
        return False
    return True


def queue(queues: Dict[int, QosQueue], tc: int) -> QosQueue:
    if not 0 <= tc <= 7:
        raise ValueError(tc)
    if tc not in queues:
        queues[tc] = QosQueue(tc)
    return queues[tc]


# IOS -----------------------------------------------------------------------------------------------------------------

def is_queuing(children_words: List[List[str]]) -> bool:
    return any(w and w[0] in QUEUING_WORDS for w in children_words)


def ios_queue_line(q: QosQueue, w: List[str]) -> bool:
    """A line of a class in an IOS queuing policy."""
    n = len(w)
    if w[0] == "priority":
        q.priority = True
        rest = w[1:]
        if rest[:1] == ["level"] and len(rest) >= 2:
            q.priority_level, rest = int(rest[1]), rest[2:]
        if rest[:1] == ["percent"] and len(rest) == 2:
            q.priority_percent, rest = int(rest[1]), []
        return not rest
    if w[:3] == ["bandwidth", "remaining", "percent"] and n == 4:
        q.bandwidth_remaining = int(w[3])
    elif w[:2] == ["bandwidth", "percent"] and n == 3:
        q.bandwidth_percent = int(w[2])
    elif w[:3] == ["shape", "average", "percent"] and n == 4:
        q.shape_percent = int(w[3])
    elif w[:2] == ["shape", "average"] and n == 3 and w[2].isdigit():
        q.shape_kbps = max(1, int(w[2]) // 1000)
    elif w in (["random-detect"], ["random-detect", "dscp-based"]):
        q.wred = True
    elif w == ["random-detect", "ecn"]:
        q.ecn = q.ecn or (0, 0, 0)
    elif w[0] == "queue-limit" and n in (2, 3) and w[2:] in ([], ["packets"]):
        q.queue_limit = int(w[1])
    elif w == ["fair-queue"]:
        q.fair_queue = True
    elif w[:3] == ["police", "rate", "percent"] and n == 4 and q.priority:
        q.shape_percent = int(w[3])  # a policed priority queue (Catalyst 9000)
    elif w[:3] == ["police", "cir", "percent"] and n == 4 and q.priority:
        q.shape_percent = int(w[3])
    else:
        return False
    return True


def assign_classes(device: Device, profile: QosProfile, classes: List[Tuple[str, QosQueue]]) -> Dict[str, str]:
    """IOS: give each queuing class a traffic class: RS-TC<n> keeps n; priority classes take the highest (by
    level), the other classes the ones below, class-default 0. The DSCP values the classes match fill the map.
    Returns the classes that could not be carried over whole: class -> why."""
    notes: Dict[str, str] = {}
    taken = {int(name[len(TC_CLASS):]) for name, _ in classes
             if name.startswith(TC_CLASS) and name[len(TC_CLASS):].isdigit()}
    free = [tc for tc in range(7, 0, -1) if tc not in taken]
    ordered = sorted(classes, key=lambda c: (not c[1].priority, c[1].priority_level or 9))
    for name, q in ordered:
        if name.startswith(TC_CLASS) and name[len(TC_CLASS):].isdigit():
            tc = int(name[len(TC_CLASS):])
        elif name == qos_text.DEFAULT_CLASS:
            tc = 0
        elif free:
            tc = free.pop(0)
        else:
            notes[name] = "a port has eight queues; this class gets none, so its traffic shares class-default's"
            continue
        q.traffic_class, q.source_class = tc, name
        profile.queues[tc] = q
        qc: Optional[QosClass] = device.qos_classes.get(name)
        if qc is not None:
            for d in qc.dscp:
                device.qos_dscp_tc.setdefault(d, tc)
            if qc.acl:
                notes[name] = (f"its traffic is queued by DSCP alone (traffic class {tc}); what it matches by ACL "
                               f"{qc.acl} goes to the queue of its DSCP value")
    return notes


# writers -------------------------------------------------------------------------------------------------------------

def used_tcs(device: Device) -> List[int]:
    tcs = set(device.qos_dscp_tc.values())
    for p in device.qos_profiles.values():
        tcs |= set(p.queues)
    return sorted(tcs, reverse=True)


def eos_lines(device: Device, ind: str, report: Report) -> List[str]:
    """qos map lines and qos profile blocks."""
    lines: List[str] = []
    by_tc: Dict[int, List[int]] = {}
    for d, tc in sorted(device.qos_dscp_tc.items()):
        by_tc.setdefault(tc, []).append(d)
    for tc, values in sorted(by_tc.items(), reverse=True):
        lines.append(f"qos map dscp {' '.join(str(v) for v in values)} to traffic-class {tc}")
    lines += [f"qos map traffic-class {tc} to dscp {d}" for tc, d in sorted(device.qos_tc_dscp.items())]
    if device.qos_dscp_tc or device.qos_tc_dscp:
        report.item(KIND, MAP_LABEL)
        if lines:
            lines.append("!")
    for p in device.qos_profiles.values():
        label = profile_label(p.name)
        report.item(KIND, label)
        lines.append(f"qos profile {p.name}")
        if p.trust == "none":
            lines.append(f"{ind}no qos trust")
        elif p.trust:
            lines.append(f"{ind}qos trust {p.trust}")
        if p.input_policy:
            lines.append(f"{ind}service-policy type qos input {p.input_policy}")
        if p.shape_kbps:
            lines.append(f"{ind}shape rate {p.shape_kbps} kbps")
        for tc in sorted(p.queues, reverse=True):
            lines.append(f"{ind}tx-queue {tc}")
            lines += [ind * 2 + line for line in eos_queue_lines(p.queues[tc], report, label)]
        lines.append("!")
    return lines


def eos_queue_lines(q: QosQueue, report: Report, label: str) -> List[str]:
    lines: List[str] = []
    tag = f"traffic class {q.traffic_class}" + (f" (class {q.source_class})" if q.source_class else "")
    lines.append("priority strict" if q.priority else "no priority")
    if q.priority_percent is not None:
        lines.append(f"shape rate {q.priority_percent} percent")
        report.add(KIND, label, Severity.APPROX, "qos-priority-percent",
                   f"{tag}: priority with {q.priority_percent} percent is written as a strict-priority queue shaped "
                   "to that share")
    if q.bandwidth_percent is not None:
        lines.append(f"bandwidth percent {q.bandwidth_percent}")
    if q.bandwidth_remaining is not None:
        lines.append(f"bandwidth percent {q.bandwidth_remaining}")
        report.add(KIND, label, Severity.APPROX, "qos-bandwidth-remaining",
                   f"{tag}: 'bandwidth remaining percent {q.bandwidth_remaining}' (a share of what the priority "
                   "queues leave) is written as a share of the port")
    if q.shape_percent is not None and q.shape_percent != q.priority_percent:
        lines.append(f"shape rate {q.shape_percent} percent")
    elif q.shape_kbps is not None:
        lines.append(f"shape rate {q.shape_kbps} kbps")
    if q.ecn and q.ecn != (0, 0, 0):
        lo, hi, prob = q.ecn
        lines.append(f"random-detect ecn minimum-threshold {lo} kbytes maximum-threshold {hi} kbytes "
                     f"max-mark-probability {prob}")
    elif q.ecn or q.wred:
        report.add(KIND, label, Severity.REVIEW, "qos-wred",
                   f"{tag}: " + ("ECN marking" if q.ecn else "WRED") + " without thresholds is not written; EOS "
                   "needs them (random-detect ecn|drop minimum-threshold .. maximum-threshold ..)")
    if q.queue_limit is not None or q.fair_queue:
        report.add(KIND, label, Severity.APPROX, "qos-queue-options",
                   f"{tag}: " + ", ".join(w for w, v in (("queue-limit", q.queue_limit is not None),
                                                         ("fair-queue", q.fair_queue)) if v)
                   + " left out; EOS sizes and serves its queues itself")
    return lines


def default_dscp(device: Device, tc: int) -> List[int]:
    """The DSCP values the default map puts in a traffic class (DSCP / 8) that the source's map does not move."""
    return [d for d in range(tc * 8, tc * 8 + 8) if d not in device.qos_dscp_tc]


def written_tcs(device: Device) -> List[int]:
    return [tc for tc in range(1, 8) if any(t == tc for t in device.qos_dscp_tc.values()) or default_dscp(device, tc)]


def ios_policy_name(device: Device, profile: str) -> str:
    return profile if profile not in device.qos_policies else f"{profile}-QUEUING"


def ios_lines(device: Device, report: Report) -> List[str]:
    """class-map RS-TC<n> per traffic class and a queuing policy-map per profile."""
    lines: List[str] = []
    if not (device.qos_profiles or device.qos_dscp_tc or device.qos_tc_dscp):
        return lines
    by_tc: Dict[int, List[int]] = {}
    for d, tc in sorted(device.qos_dscp_tc.items()):
        by_tc.setdefault(tc, []).append(d)
    if device.qos_dscp_tc or device.qos_tc_dscp:
        report.item(KIND, MAP_LABEL)
    if device.qos_dscp_tc:
        report.add(KIND, MAP_LABEL, Severity.APPROX, "qos-map",
                   "IOS has no DSCP to traffic-class map: each traffic class becomes a class-map RS-TC<n> that matches "
                   "its DSCP values, used by the queuing policies")
    if device.qos_tc_dscp:
        report.add(KIND, MAP_LABEL, Severity.REVIEW, "qos-rewrite",
                   "the rewrite of traffic classes to DSCP (" + ", ".join(
                       f"{tc} -> {d}" for tc, d in device.qos_tc_dscp.items()) + ") has no IOS equivalent; mark with "
                   "set dscp in an input policy instead")
    tcs_in_profiles = {tc for p in device.qos_profiles.values() for tc in p.queues if tc}
    for tc in sorted(set(by_tc) | tcs_in_profiles, reverse=True):
        name = f"{TC_CLASS}{tc}"
        if tc == 0 or name in device.qos_classes:
            continue
        sources = [q.source_class for p in device.qos_profiles.values() for t, q in p.queues.items()
                   if t == tc and q.source_class]
        if sources and all(s in device.qos_classes for s in sources):
            continue  # an IOS source's own classes are written as they were
        values = by_tc.get(tc) or default_dscp(device, tc)
        if not values:
            continue
        if tc not in by_tc:
            report.add(KIND, MAP_LABEL, Severity.APPROX, "qos-tc-default",
                       f"the map puts no DSCP value in traffic class {tc}; class-map {name} matches the values the "
                       f"default map gives it ({', '.join(str(v) for v in values)})")
        lines += [f"class-map match-any {name}", " match dscp " + " ".join(qos_text.dscp_name(d) for d in values), "!"]
    for p in device.qos_profiles.values():
        label = profile_label(p.name)
        report.item(KIND, label)
        name = ios_policy_name(device, p.name)
        body: List[str] = []
        level = 0
        for tc in sorted(p.queues, reverse=True):
            q = p.queues[tc]
            if tc and not q.source_class and tc not in written_tcs(device):
                report.add(KIND, label, Severity.REVIEW, "qos-tc-empty",
                           f"traffic class {tc} receives no DSCP value; its queue is left out")
                continue
            cls = qos_text.DEFAULT_CLASS if tc == 0 else (
                q.source_class if q.source_class in device.qos_classes else f"{TC_CLASS}{tc}")
            tag = f"traffic class {tc}"
            body.append(f" class {cls}")
            if q.priority:
                level = q.priority_level or min(level + 1, 2)
                if not q.priority_level and level == 2 and sum(1 for x in p.queues.values() if x.priority) > 2:
                    report.add(KIND, label, Severity.REVIEW, "qos-priority-levels",
                               f"{tag}: a Catalyst 9000 has two priority levels; this strict-priority queue shares "
                               "level 2")
                body.append(f"  priority level {level}" + (f" percent {q.priority_percent}"
                                                           if q.priority_percent is not None else ""))
                if q.shape_percent is not None:
                    body.append(f"  police rate percent {q.shape_percent}")
                    report.add(KIND, label, Severity.APPROX, "qos-priority-shape",
                               f"{tag}: the shaper of a strict-priority queue is written as a policer, the way a "
                               "Catalyst 9000 limits priority queues")
            else:
                share = q.bandwidth_remaining if q.bandwidth_remaining is not None else q.bandwidth_percent
                if share is not None:
                    body.append(f"  bandwidth remaining percent {share}")
                    if q.bandwidth_remaining is None:
                        report.add(KIND, label, Severity.APPROX, "qos-bandwidth",
                                   f"{tag}: 'bandwidth percent {share}' (a share of the port) is written as "
                                   "'bandwidth remaining percent', a share of what the priority queues leave, as "
                                   "IOS takes it beside priority classes")
                if q.shape_percent is not None:
                    body.append(f"  shape average percent {q.shape_percent}")
            if q.shape_kbps is not None and not q.priority:
                body.append(f"  shape average {q.shape_kbps * 1000}")
            if q.queue_limit is not None:
                body.append(f"  queue-limit {q.queue_limit} packets")
            if q.fair_queue:
                body.append("  fair-queue")
            if q.wred or q.ecn:
                body.append("  random-detect dscp-based")
            if q.ecn:
                text = f"{q.ecn[0]}-{q.ecn[1]} kbytes, marking up to {q.ecn[2]} percent" if q.ecn != (0, 0, 0) else ""
                report.add(KIND, label, Severity.REVIEW, "qos-ecn",
                           f"{tag}: ECN marking{' (' + text + ')' if text else ''} is written as WRED "
                           "(random-detect dscp-based); set the thresholds and ECN on the target if it supports them")
        if p.shape_kbps:
            lines += [f"policy-map {name}-CHILD"] + body + ["!"]
            lines += [f"policy-map {name}", f" class {qos_text.DEFAULT_CLASS}",
                      f"  shape average {p.shape_kbps * 1000}", f"   service-policy {name}-CHILD", "!"]
        else:
            lines += [f"policy-map {name}"] + body + ["!"]
        if p.trust == "none":
            report.add(KIND, label, Severity.APPROX, "qos-trust",
                       "'no qos trust' left out: a Catalyst 9000 trusts DSCP on every port")
        elif p.trust == "cos":
            report.add(KIND, label, Severity.REVIEW, "qos-trust",
                       "trust cos left out: a Catalyst 9000 trusts DSCP on every port")
        if p.input_policy:
            report.add(KIND, label, Severity.INFO, "qos-input",
                       f"its input policy {p.input_policy} is applied on each port of the profile")
    return lines


def ios_interface_policy(device: Device, profile: str) -> str:
    """The output policy a port of this profile takes on IOS."""
    return ios_policy_name(device, profile)
