# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Junos class of service: the DSCP to traffic-class map, egress queuing profiles, port trust, and QoS policies.

How the model maps to Junos:

* Traffic class N is forwarding class ``TC<N>`` on queue N (``class-of-service forwarding-classes``).
* The DSCP to traffic-class map is the DSCP classifier ``RS-DSCP``; the traffic-class to DSCP map is the rewrite
  rule ``RS-DSCP-REWRITE``. Both go on the unit of each port that trusts DSCP. A port that trusts nothing gets a
  fixed forwarding class (``unit 0 forwarding-class TC0``).
* A queuing profile is a scheduler map of its own name with a scheduler ``<profile>-TC<N>`` per queue: strict
  priority is ``priority strict-high``, a bandwidth share ``transmit-rate percent``, shaping ``shaping-rate``. A port
  with queue settings of its own on top of its profile gets the map ``<profile>-P<n>``.
* A QoS policy (classification and marking) is a firewall filter of its own name: one term per class, or per entry
  of the class's ACL (``<class>-<n>``), with ``then policer``/``then dscp``. A policy on a switch port is written as
  an ``ethernet-switching`` filter, on a routed port as an ``inet`` one. A last term passes what no class matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import qos as qos_text
from . import queuing as queuing_text
from .junospolicy import Policy, Reader as PolicyReader, Term, from_words, to_inet, to_switching
from .model import Acl, AclAction, Device, Interface, QosAction, QosClass, QosPolicy, QosProfile, QosQueue
from .report import Report, Severity

KIND = "qos"
CLASSIFIER = "RS-DSCP"
REWRITE = "RS-DSCP-REWRITE"
DEFAULT_TERM = "class-default"
QOS_ACTIONS = ("policer", "dscp", "forwarding-class", "loss-priority")
DEFAULT_BURST = 15000  # bytes, written where the source leaves the burst to the platform

Add = Callable[..., None]


def fc(tc: int) -> str:
    return f"TC{tc}"


def bits(value: int) -> str:
    return format(value, "06b")


_JUNOS_ALIASES = {"be": 0, "nc1": 48, "nc2": 56}


def _dscp_word(value: int) -> str:
    """Junos' alias of a DSCP value (be, ef, af41, cs3) or its six bits."""
    if value == 0:
        return "be"
    name = qos_text.dscp_name(value)
    return name if name.startswith(("af", "cs", "ef")) else bits(value)


def _rate(kbps: int) -> str:
    return f"{kbps // 1000}m" if kbps % 1000 == 0 else f"{kbps}k"


def read_rate(word: str) -> Optional[int]:
    """A Junos rate (50m, 2500k, 1g, or bits per second) in kbps."""
    m = re.match(r"^(\d+)([kmg]?)$", word.lower())
    if not m:
        return None
    value = int(m.group(1))
    return {"": value // 1000, "k": value, "m": value * 1000, "g": value * 1000000}[m.group(2)]


def read_bytes(word: str) -> Optional[int]:
    m = re.match(r"^(\d+)([kmg]?)$", word.lower())
    if not m:
        return None
    return int(m.group(1)) * {"": 1, "k": 1000, "m": 1000000, "g": 1000000000}[m.group(2)]


def read_dscp(word: str) -> Optional[int]:
    if re.match(r"^[01]{6}$", word):
        return int(word, 2)
    if word in _JUNOS_ALIASES:
        return _JUNOS_ALIASES[word]
    try:
        return qos_text.dscp(word)
    except ValueError:
        return None


# writing ------------------------------------------------------------------------------------------------------------

def merged(profile: QosProfile, own: Dict[int, QosQueue]) -> Dict[int, QosQueue]:
    """A profile's queues with a port's own settings on top."""
    out = dict(profile.queues)
    for tc, q in own.items():
        base = out.get(tc, QosQueue(tc))
        values = {k: v for k, v in vars(q).items() if v not in (None, False, "") and k != "traffic_class"}
        out[tc] = QosQueue(**{**vars(base), **values})
    return out


class CosWriter:
    def __init__(self, device: Device, add: Add, report: Report, port: Callable[[str], str]) -> None:
        self.device, self.add, self.report, self.port = device, add, report, port
        self.port_maps: Dict[Tuple[str, str], str] = {}  # (profile, queues key) -> scheduler map of the ports

    def write(self) -> None:
        dev = self.device
        tcs = set(dev.qos_dscp_tc.values()) | set(dev.qos_tc_dscp)
        for p in dev.qos_profiles.values():
            tcs |= set(p.queues)
        for i in dev.interfaces.values():
            tcs |= set(i.queues)
        if any(i.qos_trust == "none" for i in dev.interfaces.values()):
            tcs.add(0)
        for tc in sorted(tcs):
            self.add("class-of-service", "forwarding-classes", f"class {fc(tc)}", f"queue-num {tc}")
        if dev.qos_dscp_tc or dev.qos_tc_dscp:
            label = queuing_text.MAP_LABEL
            self.report.item(KIND, label)
            for d, tc in sorted(dev.qos_dscp_tc.items()):
                self.add("class-of-service", "classifiers", f"dscp {CLASSIFIER}", f"forwarding-class {fc(tc)}",
                         "loss-priority low", f"code-points {bits(d)}")
            for tc, d in sorted(dev.qos_tc_dscp.items()):
                self.add("class-of-service", "rewrite-rules", f"dscp {REWRITE}", f"forwarding-class {fc(tc)}",
                         "loss-priority low", f"code-point {bits(d)}")
            if dev.qos_dscp_tc:
                self.report.add(KIND, label, Severity.APPROX, "qos-default-map",
                                "the DSCP values the map does not name follow Junos' default DSCP classifier, not "
                                f"the {dev.platform.upper()} default")
        for p in dev.qos_profiles.values():
            self.report.item(KIND, queuing_text.profile_label(p.name))
            self.scheduler_map(p.name, p.queues, queuing_text.profile_label(p.name))
            if p.input_policy:
                self.report.add(KIND, queuing_text.profile_label(p.name), Severity.APPROX, "qos-profile-policy",
                                f"the profile's input policy {p.input_policy} is written as the input filter of each "
                                "port of the profile")
        for iface in dev.interfaces.values():
            self.interface(iface)

    def scheduler_map(self, name: str, queues: Dict[int, QosQueue], label: str) -> None:
        for tc in sorted(queues, reverse=True):
            scheduler = f"{name}-{fc(tc)}"
            self.scheduler(scheduler, queues[tc], label)
            self.add("class-of-service", "scheduler-maps", name, f"forwarding-class {fc(tc)}", f"scheduler {scheduler}")

    def scheduler(self, name: str, q: QosQueue, label: str) -> None:
        path = ("class-of-service", "schedulers", name)
        tag = f"traffic class {q.traffic_class}" + (f" (class {q.source_class})" if q.source_class else "")
        if q.priority or q.priority_level is not None or q.priority_percent is not None:
            self.add(*path, "priority strict-high")
        if q.priority_level is not None and q.priority_level > 1:
            self.report.add(KIND, label, Severity.APPROX, "qos-priority-level",
                            f"{tag}: priority level {q.priority_level} is written as strict-high, as Junos has one "
                            "strict priority")
        if q.priority_percent is not None:
            self.add(*path, f"shaping-rate percent {q.priority_percent}")
            self.report.add(KIND, label, Severity.APPROX, "qos-priority-percent",
                            f"{tag}: priority with {q.priority_percent} percent is written as a strict-high queue shaped "
                            "to that share")
        if q.bandwidth_percent is not None:
            self.add(*path, f"transmit-rate percent {q.bandwidth_percent}")
        elif q.bandwidth_remaining is not None:
            self.add(*path, f"transmit-rate percent {q.bandwidth_remaining}")
            self.report.add(KIND, label, Severity.APPROX, "qos-bandwidth-remaining",
                            f"{tag}: 'bandwidth remaining percent {q.bandwidth_remaining}' (a share of what the "
                            "priority queues leave) is written as a share of the port")
        if q.shape_percent is not None and q.shape_percent != q.priority_percent:
            self.add(*path, f"shaping-rate percent {q.shape_percent}")
        elif q.shape_kbps is not None:
            self.add(*path, f"shaping-rate {_rate(q.shape_kbps)}")
        if q.ecn is not None:
            self.add(*path, "explicit-congestion-notification")
            if q.ecn != (0, 0, 0):
                lo, hi, prob = q.ecn
                self.report.add(KIND, label, Severity.APPROX, "qos-ecn",
                                f"{tag}: ECN marking is on; its thresholds ({lo}-{hi} kbytes, {prob}%) are left to "
                                "Junos' default drop profile, which sets them as a fill level of the buffer")
        elif q.wred:
            self.report.add(KIND, label, Severity.REVIEW, "qos-wred",
                            f"{tag}: WRED needs a Junos drop profile (drop-profile-map); not written")
        if q.queue_limit is not None or q.fair_queue:
            self.report.add(KIND, label, Severity.APPROX, "qos-queue-options",
                            f"{tag}: " + ", ".join(w for w, v in (("queue-limit", q.queue_limit is not None),
                                                                 ("fair-queue", q.fair_queue)) if v)
                            + " left out; Junos sizes and serves its queues itself")
        if not (q.priority or q.priority_level is not None or q.priority_percent is not None
                or q.bandwidth_percent is not None or q.bandwidth_remaining is not None):
            self.add(*path, "transmit-rate remainder")  # a queue with no share takes what the others leave

    def interface(self, iface: Interface) -> None:
        dev = self.device
        profile = dev.qos_profiles.get(iface.qos_profile) if iface.qos_profile else None
        trust = iface.qos_trust or (profile.trust if profile is not None else "")
        if profile is None and not trust and not iface.queues:
            return
        path = ("class-of-service", "interfaces", self.port(iface.name))
        label = f"{iface.source_name or iface.name} -> {self.port(iface.name)}"
        if profile is not None:
            name = profile.name
            if iface.queues:
                key = repr(sorted((tc, vars(q)) for tc, q in iface.queues.items()))
                if (profile.name, key) not in self.port_maps:
                    name = f"{profile.name}-P{sum(1 for p, _ in self.port_maps if p == profile.name) + 1}"
                    self.port_maps[(profile.name, key)] = name
                    self.scheduler_map(name, merged(profile, iface.queues), queuing_text.profile_label(profile.name))
                name = self.port_maps[(profile.name, key)]
            self.add(*path, f"scheduler-map {name}")
            if profile.shape_kbps:
                self.add(*path, f"shaping-rate {_rate(profile.shape_kbps)}")
        elif iface.queues:
            self.report.add("interface", label, Severity.REVIEW, "qos-port-queues",
                            "the port's own queue settings have no profile to sit on; not written")
        if trust == "dscp":
            if dev.qos_dscp_tc:
                self.add(*path, "unit 0", "classifiers", f"dscp {CLASSIFIER}")
            if dev.qos_tc_dscp:
                self.add(*path, "unit 0", "rewrite-rules", f"dscp {REWRITE}")
            if not dev.qos_dscp_tc:
                self.report.add("interface", label, Severity.APPROX, "qos-trust",
                                "trusts DSCP: Junos' default DSCP classifier does, with its own queue mapping")
        elif trust == "cos":
            self.report.add("interface", label, Severity.APPROX, "qos-trust",
                            "trusts CoS: Junos' default IEEE 802.1p classifier does on a switch port, with its own "
                            "queue mapping")
        elif trust == "none":
            self.add(*path, "unit 0", f"forwarding-class {fc(0)}")


def policy_filters(device: Device, add: Add, report: Report, families: Dict[str, Set[str]]) -> None:
    """Each QoS policy as a firewall filter in the families it is applied in (inet when unused)."""
    used = {a.qos_class for p in device.qos_policies.values() for a in p.actions}
    for name in device.qos_classes:
        if name not in used:
            report.add(KIND, f"class {name}", Severity.APPROX, "qos-unused-class",
                       "used by no QoS policy; a Junos class lives only as a term of a filter, so it is left out")
    for policy in device.qos_policies.values():
        label = f"policy {policy.name}"
        report.item(KIND, label)
        for family in sorted(families.get(policy.name) or {"inet"}):
            _policy_filter(device, policy, family, add, report, label)


def _policy_filter(device: Device, policy: QosPolicy, family: str, add: Add, report: Report, label: str) -> None:
    base = ("firewall", f"family {family}", f"filter {policy.name}")
    marked = False
    for action in policy.actions:
        name = action.qos_class
        terms: List[Tuple[str, List[str]]] = []
        if name == qos_text.DEFAULT_CLASS:
            terms.append((DEFAULT_TERM, []))
        else:
            qc = device.qos_classes.get(name)
            if qc is None:
                report.add(KIND, label, Severity.REVIEW, "qos-class", f"class {name} is not defined; not written")
                continue
            if qc.dscp:
                terms.append((name, [f"dscp {_dscp_word(d)}" for d in qc.dscp]))
            acl = device.acls.get(qc.acl) if qc.acl else None
            if qc.acl and acl is None:
                report.add(KIND, label, Severity.REVIEW, "qos-class", f"class {name}: ACL {qc.acl} is not defined")
            if acl is not None:
                if qc.dscp:
                    report.add(KIND, label, Severity.APPROX, "qos-class",
                               f"class {name} matches DSCP and an ACL; each is a term of its own, so either matches")
                if any(e.action == AclAction.DENY for e in acl.entries):
                    report.add(KIND, label, Severity.REVIEW, "qos-class",
                               f"class {name}: the deny entries of {acl.name} (traffic left out of the class) are not "
                               "written")
                permits = [e for e in acl.entries if e.action == AclAction.PERMIT and not e.unsupported]
                for n, entry in enumerate(permits, 1):
                    words = from_words(entry, acl.family, label, report)
                    terms.append((f"{name}-{n}", to_switching(words) if family == "ethernet-switching" else words))
        for term_name, froms in terms:
            path = base + (f"term {term_name}",)
            for word in froms:
                add(*path, "from", word)
            if action.police_kbps:
                policer = f"{policy.name}-{name}"
                add("firewall", "policer", policer, "if-exceeding", f"bandwidth-limit {_rate(action.police_kbps)}")
                add("firewall", "policer", policer, "if-exceeding",
                    f"burst-size-limit {action.burst_bytes or DEFAULT_BURST}")
                add("firewall", "policer", policer, "then discard")
                add(*path, "then", f"policer {policer}")
                if not action.burst_bytes:
                    report.add(KIND, label, Severity.APPROX, "qos-burst",
                               f"class {name}: Junos policers need a burst; {DEFAULT_BURST} bytes is written")
            if action.set_dscp is not None:
                add(*path, "then", f"dscp {_dscp_word(action.set_dscp)}")
                marked = True
            add(*path, "then", "accept")
    if not any(a.qos_class == qos_text.DEFAULT_CLASS for a in policy.actions):
        add(*base, f"term {DEFAULT_TERM}", "then", "accept")
    if marked:
        report.add(KIND, label, Severity.APPROX, "qos-mark",
                   "marking is the filter action 'dscp'; switches that cannot rewrite DSCP in a filter (QFX) mark "
                   "through a forwarding class and a DSCP rewrite rule instead")


# reading ------------------------------------------------------------------------------------------------------------

@dataclass
class CosReader:
    device: Device
    fc_queue: Dict[str, int] = field(default_factory=dict)
    classifiers: Dict[str, Dict[int, str]] = field(default_factory=dict)  # name -> DSCP -> forwarding class
    rewrites: Dict[str, Dict[str, int]] = field(default_factory=dict)  # name -> forwarding class -> DSCP
    schedulers: Dict[str, List[List[str]]] = field(default_factory=dict)
    maps: Dict[str, Dict[str, str]] = field(default_factory=dict)  # scheduler map -> forwarding class -> scheduler
    ports: Dict[str, Dict[str, str]] = field(default_factory=dict)  # port -> what -> value
    policers: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def statement(self, w: List[str]) -> bool:
        """A line under class-of-service (w starts after it)."""
        if w[:2] == ["forwarding-classes", "class"] and len(w) == 5 and w[3] == "queue-num" and w[4].isdigit():
            self.fc_queue[w[2]] = int(w[4])
            return True
        if w[:2] == ["classifiers", "dscp"] and len(w) >= 8 and w[3] == "forwarding-class" and \
                w[5] == "loss-priority" and w[7] == "code-points":
            for word in w[8:]:
                d = read_dscp(word)
                if d is None:
                    return False
                self.classifiers.setdefault(w[2], {})[d] = w[4]
            return len(w) > 8
        if w[:2] == ["rewrite-rules", "dscp"] and len(w) == 9 and w[3] == "forwarding-class" and \
                w[5] == "loss-priority" and w[7] == "code-point":
            d = read_dscp(w[8])
            if d is None:
                return False
            if w[6] == "low":
                self.rewrites.setdefault(w[2], {})[w[4]] = d
            return True
        if w[0] == "schedulers" and len(w) >= 3:
            self.schedulers.setdefault(w[1], []).append(w[2:])
            return True
        if w[0] == "scheduler-maps" and len(w) == 6 and w[2] == "forwarding-class" and w[4] == "scheduler":
            self.maps.setdefault(w[1], {})[w[3]] = w[5]
            return True
        if w[0] == "interfaces" and len(w) >= 4:
            settings = self.ports.setdefault(w[1], {})
            rest = w[2:]
            if rest[0] in ("scheduler-map", "shaping-rate") and len(rest) == 2:
                settings[rest[0]] = rest[1]
                return True
            if rest[:2] == ["unit", "0"] and len(rest) == 5 and rest[2] in ("classifiers", "rewrite-rules") and \
                    rest[3] == "dscp":
                settings[rest[2]] = rest[4]
                return True
            if rest[:3] == ["unit", "0", "forwarding-class"] and len(rest) == 4:
                settings["forwarding-class"] = rest[3]
                return True
        return False

    def policer(self, w: List[str]) -> bool:
        """firewall policer NAME ... (w starts after 'policer')."""
        if len(w) == 4 and w[1] == "if-exceeding" and w[2] in ("bandwidth-limit", "burst-size-limit"):
            self.policers.setdefault(w[0], {})[w[2]] = w[3]
            return True
        if w[1:] == ["then", "discard"]:
            self.policers.setdefault(w[0], {})
            return True
        return False

    def tc(self, name: str) -> Optional[int]:
        if name in self.fc_queue:
            return self.fc_queue[name]
        m = re.match(r"^TC(\d)$", name)
        return int(m.group(1)) if m else None

    def queue(self, tc: int, scheduler: str) -> Optional[QosQueue]:
        q = QosQueue(tc)
        for s in self.schedulers.get(scheduler, []):
            if s == ["priority", "strict-high"]:
                q.priority = True
            elif s[:2] == ["transmit-rate", "percent"] and len(s) == 3:
                q.bandwidth_percent = int(s[2])
            elif s == ["transmit-rate", "remainder"]:
                pass
            elif s[:2] == ["shaping-rate", "percent"] and len(s) == 3:
                q.shape_percent = int(s[2])
            elif s[0] == "shaping-rate" and len(s) == 2 and read_rate(s[1]) is not None:
                q.shape_kbps = read_rate(s[1])
            elif s == ["explicit-congestion-notification"]:
                q.ecn = (0, 0, 0)
            elif s[0] == "priority" and len(s) == 2:
                pass  # low and high are Junos' weighted queues
            else:
                return None
        return q

    def finish(self, unread: Callable[[int, str, str], None], port_of: Callable[[str], Optional[Interface]]) -> None:
        dev = self.device
        for name, entries in self.classifiers.items():
            for d, cls in entries.items():
                tc = self.tc(cls)
                if tc is None:
                    unread(0, f"set class-of-service classifiers dscp {name} forwarding-class {cls}",
                           "a forwarding class with no queue number")
                elif name == CLASSIFIER or len(self.classifiers) == 1:
                    dev.qos_dscp_tc[d] = tc
        for name, rules in self.rewrites.items():
            if name == REWRITE or len(self.rewrites) == 1:
                for rule_fc, value in rules.items():
                    rule_tc = self.tc(rule_fc)
                    if rule_tc is not None:
                        dev.qos_tc_dscp[rule_tc] = value
        queues: Dict[str, Dict[int, QosQueue]] = {}
        for name, assigned in self.maps.items():
            out: Dict[int, QosQueue] = {}
            for map_fc, scheduler in assigned.items():
                queue_tc = self.tc(map_fc)
                q = self.queue(queue_tc, scheduler) if queue_tc is not None else None
                if q is None or queue_tc is None:
                    unread(0, f"set class-of-service scheduler-maps {name} forwarding-class {map_fc} scheduler "
                           f"{scheduler}", "a scheduler RouterShift cannot read as a queue")
                    continue
                out[queue_tc] = q
            queues[name] = dict(sorted(out.items(), reverse=True))
        port_maps = {}
        for name in queues:
            m = re.match(r"^(.+)-P\d+$", name)
            if m and m.group(1) in queues:
                port_maps[name] = m.group(1)
        for name, qs in queues.items():
            if name not in port_maps:
                dev.qos_profiles[name] = QosProfile(name, queues=qs)
        trusted: Dict[str, List[bool]] = {}
        for port, settings in self.ports.items():
            iface = port_of(port)
            if iface is None:
                unread(0, f"set class-of-service interfaces {port}", "an interface RouterShift does not know")
                continue
            name = settings.get("scheduler-map", "")
            if name in port_maps:
                profile = port_maps[name]
                iface.qos_profile = profile
                iface.queues = _own(dev.qos_profiles[profile].queues, queues[name])
            elif name:
                iface.qos_profile = name
            if "shaping-rate" in settings and iface.qos_profile:
                dev.qos_profiles[iface.qos_profile].shape_kbps = read_rate(settings["shaping-rate"])
            dscp = "classifiers" in settings or "rewrite-rules" in settings
            if dscp:
                iface.qos_trust = "dscp"
            elif "forwarding-class" in settings:
                iface.qos_trust = "none"
            if iface.qos_profile:
                trusted.setdefault(iface.qos_profile, []).append(dscp)
        # a profile all of whose ports trust DSCP trusts DSCP itself
        for name, flags in trusted.items():
            if all(flags):
                dev.qos_profiles[name].trust = "dscp"
                for iface in dev.interfaces.values():
                    if iface.qos_profile == name:
                        iface.qos_trust = ""

    def policy(self, family: str, policy: Policy, unread: Callable[[int, str, str], None],
               pending: List[Tuple[QosClass, Acl]]) -> None:
        """A firewall filter with QoS actions as a QoS policy."""
        dev = self.device
        qp = dev.qos_policies.setdefault(policy.name, QosPolicy(policy.name))
        if qp.actions:
            return  # the same policy in another family
        qp.origin.line = policy.line
        groups: Dict[str, List[Term]] = {}
        for term in policy.terms.values():
            only_dscp = term.froms and all(f[0] == "dscp" for f in term.froms)
            name = term.name if only_dscp or term.name == DEFAULT_TERM else re.sub(r"-\d+$", "", term.name)
            groups.setdefault(name, []).append(term)
        for name, terms in groups.items():
            action = QosAction(qos_text.DEFAULT_CLASS if name == DEFAULT_TERM else name)
            ok = True
            for t in terms[0].thens:
                if t[0] == "policer" and len(t) == 2:
                    rates = self.policers.get(t[1], {})
                    action.police_kbps = read_rate(rates.get("bandwidth-limit", ""))
                    burst = read_bytes(rates.get("burst-size-limit", ""))
                    action.burst_bytes = burst if burst != DEFAULT_BURST else None
                elif t[0] == "dscp" and len(t) == 2 and read_dscp(t[1]) is not None:
                    action.set_dscp = read_dscp(t[1])
                elif t not in (["accept"],) and t[0] != "count":
                    ok = False
            if not ok:
                unread(terms[0].line, f"set firewall family {family} filter {policy.name} term {terms[0].name}",
                       "a QoS filter action RouterShift cannot hold")
                continue
            if name == DEFAULT_TERM:
                if action.set_dscp is not None or action.police_kbps:
                    qp.actions.append(action)
                continue
            qc = dev.qos_classes.setdefault(name, QosClass(name))
            entries = []
            for term in terms:
                froms = [to_inet(f) for f in term.froms]
                if froms and all(f[0] == "dscp" for f in froms):
                    for f in froms:
                        d = read_dscp(f[1]) if len(f) == 2 else None
                        if d is None:
                            ok = False
                        elif d not in qc.dscp:
                            qc.dscp.append(d)
                    continue
                found = PolicyReader._entries(Term(term.name, term.line, froms, []), "inet", AclAction.PERMIT,
                                              False, None)
                if found is None:
                    ok = False
                else:
                    entries += found
            if not ok:
                unread(terms[0].line, f"set firewall family {family} filter {policy.name} term {terms[0].name}",
                       "a QoS filter match RouterShift cannot hold")
            if entries:
                acl = Acl(name)
                for n, e in enumerate(entries, 1):
                    e.sequence = n * 10
                acl.entries = entries
                pending.append((qc, acl))
            qp.actions.append(action)


def _own(base: Dict[int, QosQueue], port: Dict[int, QosQueue]) -> Dict[int, QosQueue]:
    """The settings of a port's queues that differ from its profile's."""
    out: Dict[int, QosQueue] = {}
    for tc, q in port.items():
        b = base.get(tc, QosQueue(tc))
        diff = {k: v for k, v in vars(q).items() if v != getattr(b, k)}
        if diff:
            out[tc] = QosQueue(tc, **diff)
    return out


def is_qos(policy: Policy) -> bool:
    return any(t and t[0] in QOS_ACTIONS for term in policy.terms.values() for t in term.thens)
