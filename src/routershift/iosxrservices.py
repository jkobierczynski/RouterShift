# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""IOS-XR QoS (MQC class maps and policy maps), NetFlow (exporter, monitor and sampler maps), port mirroring
(monitor sessions), IP SLA probes and tracked objects: written and read.

IOS-XR writes the end of a class map and a policy map as ``end-class-map`` and ``end-policy-map``, a flow monitor as
a ``flow monitor-map`` that names a ``flow exporter-map`` per collector, and a probe as an ``ipsla operation`` with
its ``schedule``.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from . import acl as acl_text
from . import qos as qos_text
from . import tracking as tracking_text
from .confparse import Node
from .model import (Device, FlowCollector, Interface, IpSla, MirrorSession, Netflow, Origin, QosAction, QosClass,
                    QosPolicy, Track)
from .report import Report, Severity

IND = " "
PLATFORM = "IOS-XR"
MONITOR = "RS-MONITOR"
SAMPLER = "RS-SAMPLER"
EXPORTER = "RS-EXPORTER"
_DIRECTION = {"both": "", "rx": " direction rx-only", "tx": " direction tx-only"}
Add = Callable[[Severity, str, str], None]


# QoS -----------------------------------------------------------------------------------------------------------------

def qos_lines(device: Device, report: Report) -> List[str]:
    out: List[str] = []
    for c in device.qos_classes.values():
        report.item("qos", f"class {c.name}")
        body: List[str] = []
        if c.dscp:
            body.append("match dscp " + " ".join(qos_text.dscp_name(v) for v in c.dscp))
        if c.acl:
            acl = device.acls.get(c.acl)
            family = "ipv6" if acl is not None and acl.family == 6 else "ipv4"
            body.append(f"match access-group {family} {acl_text.safe_name(c.acl)}")
        out += [f"class-map {'match-all' if c.match_all else 'match-any'} {c.name}"] + \
            [IND + b for b in body] + [f"{IND}end-class-map", "!"]
    for p in device.qos_policies.values():
        label = f"policy {p.name}"
        report.item("qos", label)
        body = []
        for a in p.actions:
            lines = []
            if a.set_dscp is not None:
                lines.append(f"set dscp {qos_text.dscp_name(a.set_dscp)}")
            if a.police_kbps is not None:
                lines.append(f"police rate {a.police_kbps} kbps" +
                             (f" burst {a.burst_bytes} bytes" if a.burst_bytes else ""))
                lines += [f"{IND}exceed-action drop", "!"]
            body += [f"class {a.qos_class}"] + [IND + line for line in lines] + ["!"]
        if not any(a.qos_class == qos_text.DEFAULT_CLASS for a in p.actions):
            body += [f"class {qos_text.DEFAULT_CLASS}", "!"]
        out += [f"policy-map {p.name}"] + [IND + b for b in body] + [f"{IND}end-policy-map", "!"]
    return out


def read_class_map(device: Device, node: Node, unparsed: Callable[[Node, str], None]) -> bool:
    """class-map match-any|match-all NAME / match dscp ... | match access-group ipv4 ACL / end-class-map"""
    w = node.words
    if len(w) not in (2, 3) or (len(w) == 3 and w[1] not in ("match-any", "match-all")):
        return False
    c = QosClass(w[-1], match_all=len(w) == 3 and w[1] == "match-all", origin=Origin(node.line, node.text))
    for child in node.children:
        x = child.words
        try:
            if x == ["end-class-map"]:
                continue
            if x[:2] == ["match", "dscp"] and len(x) > 2:
                c.dscp += [qos_text.dscp(v) for v in x[2:] if v not in ("ipv4", "ipv6")]
                continue
            if x[:2] == ["match", "access-group"] and len(x) == 4 and x[2] in ("ipv4", "ipv6"):
                c.acl = x[3]
                continue
        except ValueError:
            pass
        unparsed(child, node.text)
    device.qos_classes[c.name] = c
    return True


def read_policy_map(device: Device, node: Node, unparsed: Callable[[Node, str], None]) -> bool:
    """policy-map NAME / class C / set dscp X | police rate N kbps [burst N bytes] / end-policy-map"""
    if len(node.words) != 2:
        return False
    p = QosPolicy(node.words[1], origin=Origin(node.line, node.text))
    for child in node.children:
        x = child.words
        if x == ["end-policy-map"]:
            continue
        if x[0] != "class" or len(x) != 2:
            unparsed(child, node.text)
            continue
        a = QosAction(x[1])
        for line in child.children:
            y = line.words
            try:
                if y[:2] == ["set", "dscp"] and len(y) == 3:
                    a.set_dscp = qos_text.dscp(y[2])
                    continue
                if y[:2] == ["police", "rate"] and len(y) >= 4 and y[3] == "kbps":
                    a.police_kbps = int(y[2])
                    if y[4:5] == ["burst"] and len(y) == 7 and y[6] == "bytes":
                        a.burst_bytes = int(y[5])
                    elif len(y) != 4:
                        unparsed(line, node.text)
                    for sub in line.children:
                        if sub.words != ["exceed-action", "drop"]:
                            unparsed(sub, node.text)
                    continue
            except ValueError:
                pass
            unparsed(line, node.text)
        if a.qos_class == qos_text.DEFAULT_CLASS and a.set_dscp is None and a.police_kbps is None:
            continue
        p.actions.append(a)
    device.qos_policies[p.name] = p
    return True


def interface_qos(device: Device, iface: Interface, add: Add) -> List[str]:
    lines = []
    for attr, word in (("qos_policy_in", "input"), ("qos_policy_out", "output")):
        name = getattr(iface, attr)
        if name and name in device.qos_policies:
            lines.append(f"service-policy {word} {name}")
        elif name:
            add(Severity.REVIEW, "qos-missing", f"policy {name} is applied but not defined; left out")
    if iface.qos_trust:
        add(Severity.APPROX, "qos-trust", f"IOS-XR has no port trust setting ({iface.qos_trust}); classify with a "
                                          "policy map instead")
    return lines


# NetFlow -------------------------------------------------------------------------------------------------------------

def netflow_lines(device: Device, report: Report, port: Callable[[str], str]) -> List[str]:
    nf = device.netflow
    if nf is None:
        return []
    report.item("monitor", "NetFlow")
    out: List[str] = []
    exporters: List[str] = []
    version = {9: "v9", 10: "ipfix"}.get(nf.version or 9)
    if version is None:
        version = "v9"
        report.add("monitor", "NetFlow", Severity.APPROX, "netflow-version",
                   f"IOS-XR exports version 9 or IPFIX; version {nf.version} is written as version 9")
    for n, c in enumerate(nf.collectors, 1):
        name = EXPORTER if len(nf.collectors) == 1 else f"{EXPORTER}-{n}"
        exporters.append(name)
        body = [f"version {version}", "!", f"transport udp {c.port or 2055}"]
        if nf.source_interface:
            body.append(f"source {port(nf.source_interface)}")
        body.append(f"destination {c.address}" + (f" vrf {c.vrf}" if c.vrf else ""))
        out += [f"flow exporter-map {name}"] + [IND + b for b in body] + ["!"]
    if nf.record and nf.record != "netflow ipv4 original-input":
        report.add("monitor", "NetFlow", Severity.APPROX, "netflow-record",
                   f"the flow record '{nf.record}' is written as IOS-XR's record ipv4")
    out += [f"flow monitor-map {MONITOR}", f"{IND}record ipv4"] + [f"{IND}exporter {e}" for e in exporters] + ["!"]
    if nf.sample_rate:
        out += [f"sampler-map {SAMPLER}", f"{IND}random 1 out-of {nf.sample_rate}", "!"]
    return out


def interface_flow(device: Device, iface: Interface) -> List[str]:
    if not iface.flow or device.netflow is None:
        return []
    sampler = f" sampler {SAMPLER}" if device.netflow.sample_rate else ""
    directions = {"input": ["ingress"], "output": ["egress"], "both": ["ingress", "egress"]}[iface.flow]
    return [f"flow ipv4 monitor {MONITOR}{sampler} {d}" for d in directions]


class FlowReader:
    """flow exporter-map, flow monitor-map and sampler-map blocks; the interfaces that use them."""

    def __init__(self, device: Device, canonical: Callable[[str], str], unparsed: Callable[[Node, str], None]) -> None:
        self.device = device
        self.canonical = canonical
        self.unparsed = unparsed
        self.exporters: Dict[str, Netflow] = {}
        self.monitors: Dict[str, List[str]] = {}
        self.samplers: Dict[str, int] = {}

    def node(self, node: Node) -> bool:
        w = node.words
        if w[:2] == ["flow", "exporter-map"] and len(w) == 3:
            nf = self.exporters.setdefault(w[2], Netflow(origin=Origin(node.line, node.text)))
            collector = FlowCollector("")
            for child in node.children:
                x = child.words
                if x[0] == "version" and len(x) == 2 and x[1] in ("v9", "ipfix"):
                    nf.version = 9 if x[1] == "v9" else 10
                    for sub in child.children:
                        self.unparsed(sub, node.text)
                elif x[:2] == ["transport", "udp"] and len(x) == 3:
                    collector.port = int(x[2])
                elif x[0] == "source" and len(x) == 2:
                    nf.source_interface = self.canonical(x[1])
                elif x[0] == "destination" and len(x) in (2, 4):
                    collector.address = x[1]
                    collector.vrf = x[3] if len(x) == 4 and x[2] == "vrf" and x[3] != "default" else ""
                else:
                    self.unparsed(child, node.text)
            if collector.address:
                if collector.port == 2055:
                    collector.port = None
                nf.collectors.append(collector)
            return True
        if w[:2] == ["flow", "monitor-map"] and len(w) == 3:
            exporters = self.monitors.setdefault(w[2], [])
            for child in node.children:
                x = child.words
                if x[0] == "exporter" and len(x) == 2:
                    exporters.append(x[1])
                elif x[0] == "record" and x[1:2] == ["ipv4"]:
                    continue
                elif x[0] == "cache":
                    continue
                else:
                    self.unparsed(child, node.text)
            return True
        if w[0] == "sampler-map" and len(w) == 2:
            for child in node.children:
                x = child.words
                if x[:3] == ["random", "1", "out-of"] and len(x) == 4:
                    self.samplers[w[1]] = int(x[3])
                else:
                    self.unparsed(child, node.text)
            return True
        return False

    def interface(self, iface: Interface, words: List[str]) -> bool:
        """flow ipv4 monitor M [sampler S] ingress|egress"""
        if words[:3] != ["flow", "ipv4", "monitor"] or len(words) not in (5, 7) or words[-1] not in ("ingress",
                                                                                                    "egress"):
            return False
        monitor = words[3]
        if len(words) == 7:
            if words[4] != "sampler":
                return False
            rate = self.samplers.get(words[5])
            if rate:
                self.monitor(monitor).sample_rate = rate
        self.monitor(monitor)
        word = "input" if words[-1] == "ingress" else "output"
        iface.flow = word if iface.flow in ("", word) else "both"
        return True

    def monitor(self, monitor: str) -> Netflow:
        d = self.device
        if d.netflow is None:
            d.netflow = Netflow()
            for name in self.monitors.get(monitor, []):
                exporter = self.exporters.get(name)
                if exporter is not None:
                    d.netflow.collectors += exporter.collectors
                    d.netflow.version = d.netflow.version or exporter.version
                    d.netflow.source_interface = d.netflow.source_interface or exporter.source_interface
                    d.netflow.origin = exporter.origin
        return d.netflow


# port mirroring ------------------------------------------------------------------------------------------------------

def mirror_lines(device: Device, report: Report, port: Callable[[str], str]) -> List[str]:
    out: List[str] = []
    for s in device.mirror_sessions:
        label = f"mirror session {s.name}"
        report.item("monitor", label)
        if not s.destination:
            report.skip("monitor", label, "mirror-destination", "the session has no destination port; left out")
            continue
        out += [f"monitor-session {_session(s)} ethernet", f"{IND}destination interface {port(s.destination)}", "!"]
        if s.acl:
            report.add("monitor", label, Severity.REVIEW, "mirror-acl",
                       f"the ACL filter {s.acl} is not written: IOS-XR filters a mirror with an ethernet-services or "
                       "ipv4 ACL marked 'capture' on the source port; set it by hand")
    return out


def _session(s: MirrorSession) -> str:
    return s.name if not s.name.isdigit() else f"SPAN{s.name}"


def interface_mirror(device: Device, iface: Interface) -> List[str]:
    lines = []
    for s in device.mirror_sessions:
        direction = s.sources.get(iface.name)
        if direction is not None and s.destination:
            lines.append(f"monitor-session {_session(s)} ethernet{_DIRECTION.get(direction, '')}")
    return lines


def read_monitor_session(device: Device, node: Node, canonical: Callable[[str], str],
                         unparsed: Callable[[Node, str], None]) -> bool:
    w = node.words
    if len(w) not in (2, 3) or (len(w) == 3 and w[2] != "ethernet"):
        return False
    name = w[1][4:] if w[1].startswith("SPAN") and w[1][4:].isdigit() else w[1]
    s = _find_session(device, name, Origin(node.line, node.text))
    for child in node.children:
        x = child.words
        if x[:2] == ["destination", "interface"] and len(x) == 3:
            s.destination = canonical(x[2])
        else:
            unparsed(child, node.text)
    return True


def _find_session(device: Device, name: str, origin: Optional[Origin] = None) -> MirrorSession:
    for s in device.mirror_sessions:
        if s.name == name:
            return s
    s = MirrorSession(name)
    if origin is not None:
        s.origin = origin
    device.mirror_sessions.append(s)
    return s


def read_interface_mirror(device: Device, iface: Interface, words: List[str]) -> bool:
    """monitor-session NAME ethernet [direction rx-only|tx-only]"""
    if words[0] != "monitor-session" or len(words) not in (3, 5) or words[2] != "ethernet":
        return False
    direction = "both"
    if len(words) == 5:
        if words[3] != "direction" or words[4] not in ("rx-only", "tx-only"):
            return False
        direction = words[4][:2]
    name = words[1][4:] if words[1].startswith("SPAN") and words[1][4:].isdigit() else words[1]
    _find_session(device, name).sources[iface.name] = direction
    return True


# IP SLA and tracking -------------------------------------------------------------------------------------------------

def tracking_lines(device: Device, plan: tracking_text.Plan, report: Report, port: Callable[[str], str]) -> List[str]:
    out: List[str] = []
    operations: List[str] = []
    schedules: List[str] = []
    for sla in device.ip_slas.values():
        number = plan.slas.get(sla.name)
        if number is None:
            continue
        body = [f"destination address {sla.target}"]
        source = sla.source_address
        if not source and sla.source_interface:
            iface = device.interfaces.get(sla.source_interface)
            if iface is not None and iface.ipv4:
                source = iface.ipv4[0].split("/")[0]
                report.add(tracking_text.KIND, tracking_text.sla_label(sla), Severity.APPROX, "sla-source",
                           f"IOS-XR probes from an address: {sla.source_interface}'s address {source} is written")
            else:
                report.add(tracking_text.KIND, tracking_text.sla_label(sla), Severity.REVIEW, "sla-source",
                           f"IOS-XR probes from an address; {sla.source_interface} has none, left out")
        if source:
            body.append(f"source address {source}")
        if sla.vrf:
            body.append(f"vrf {sla.vrf}")
        if sla.timeout_ms is not None:
            body.append(f"timeout {sla.timeout_ms}")
        if sla.frequency is not None:
            body.append(f"frequency {sla.frequency}")
        operations += [f"operation {number}", f"{IND}type icmp echo"] + [IND * 2 + b for b in body] + \
            [f"{IND}!", "!"]
        schedules += [f"schedule operation {number}", f"{IND}start-time now", f"{IND}life forever", "!"]
    if operations:
        out += ["ipsla"] + [IND + line for line in operations + schedules] + ["!"]
    for t in device.tracks.values():
        name = plan.tracks.get(t.name)
        if name is None:
            continue
        if t.sla:
            body = [f"type rtr {plan.slas[t.sla]} reachability"]
        else:
            body = ["type line-protocol state", f"{IND}interface {port(t.interface)}"]
        if t.delay_up is not None:
            body.append(f"delay up {t.delay_up}")
        if t.delay_down is not None:
            body.append(f"delay down {t.delay_down}")
        out += [f"track {name}"] + [IND + b for b in body] + ["!"]
    return out


def read_ipsla(device: Device, node: Node, unparsed: Callable[[Node, str], None]) -> bool:
    if node.words != ["ipsla"]:
        return False
    for child in node.children:
        x = child.words
        if x[0] == "operation" and len(x) == 2:
            sla = IpSla(x[1], origin=Origin(child.line, child.text))
            for kind in child.children:
                if kind.words != ["type", "icmp", "echo"]:
                    unparsed(kind, node.text)
                    continue
                for line in kind.children:
                    y = line.words
                    if y[:2] == ["destination", "address"] and len(y) == 3:
                        sla.target = y[2]
                    elif y[:2] == ["source", "address"] and len(y) == 3:
                        sla.source_address = y[2]
                    elif y[0] == "vrf" and len(y) == 2:
                        sla.vrf = y[1]
                    elif y[0] == "timeout" and len(y) == 2:
                        sla.timeout_ms = int(y[1])
                    elif y[0] == "frequency" and len(y) == 2:
                        sla.frequency = int(y[1])
                    else:
                        unparsed(line, node.text)
            device.ip_slas[sla.name] = sla
        elif x[:2] == ["schedule", "operation"] and len(x) == 3:
            for line in child.children:
                if line.words not in (["start-time", "now"], ["life", "forever"]):
                    unparsed(line, node.text)
        else:
            unparsed(child, node.text)
    return True


def read_track(device: Device, node: Node, canonical: Callable[[str], str],
               unparsed: Callable[[Node, str], None]) -> bool:
    if len(node.words) != 2:
        return False
    t = Track(node.words[1], origin=Origin(node.line, node.text))
    for child in node.children:
        x = child.words
        if x[:2] == ["type", "rtr"] and len(x) == 4 and x[3] == "reachability":
            t.sla = x[2]
        elif x == ["type", "line-protocol", "state"]:
            for line in child.children:
                if line.words[0] == "interface" and len(line.words) == 2:
                    t.interface = canonical(line.words[1])
                else:
                    unparsed(line, node.text)
        elif x[0] == "delay" and len(x) == 3 and x[1] in ("up", "down"):
            setattr(t, f"delay_{x[1]}", int(x[2]))
        else:
            unparsed(child, node.text)
    device.tracks[t.name] = t
    return True
