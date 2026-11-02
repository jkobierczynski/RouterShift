# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NX-OS monitoring: SPAN sessions, sFlow, NetFlow, IP SLA probes and tracked objects, LLDP timers.

How the model maps to NX-OS:

* A mirror is ``monitor session N`` with ``source interface P rx|tx|both``, ``destination interface P``, ``filter
  access-group ACL`` and ``no shut``; the destination port takes ``switchport monitor``.
* sFlow is ``feature sflow`` with ``sflow sampling-rate``, ``sflow counter-poll-interval``, ``sflow agent-ip`` and one
  collector (``sflow collector-ip A vrf V`` and ``sflow collector-port``); the sampled ports are ``sflow data-source
  interface P`` lines.
* NetFlow is ``feature netflow`` with ``flow exporter`` (``destination A use-vrf V``, ``transport udp``, ``source``,
  ``version 9``), ``flow monitor RS-MONITOR`` with the built-in ``record netflow ipv4 original-input``, an optional
  ``sampler RS-SAMPLER`` (``mode 1 out-of N``) and ``ip flow monitor RS-MONITOR input [sampler RS-SAMPLER]`` on the
  ports (a Nexus 9000 records ingress traffic only).
* Probes and tracked objects use the IOS forms (``feature sla sender``, ``ip sla N`` / ``icmp-echo``, ``track N ip
  sla M reachability``, ``track N interface P line-protocol``); a static route follows one with ``track N`` and an
  HSRP or VRRP group with ``track N decrement D``.
* LLDP sends every ``lldp timer`` seconds and neighbours keep it ``lldp holdtime`` seconds.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Optional, Set

from . import monitor as monitor_text
from . import names
from . import tracking as tracking_text
from .model import Device, Interface, InterfaceKind, Netflow, Sflow
from .report import Report, Severity

KIND = monitor_text.KIND
MONITOR = "RS-MONITOR"
SAMPLER = monitor_text.SAMPLER
RECORD = monitor_text.IOS_RECORD  # netflow ipv4 original-input, built into NX-OS as well
Add = Callable[[Severity, str, str], None]
Name = Callable[[str], str]


# writing ------------------------------------------------------------------------------------------------------------

def mirror_lines(device: Device, report: Report, port: Name, ind: str) -> List[str]:
    numbers = monitor_text.numbers(device, report, "NX-OS", 32)
    lines: List[str] = []
    for s in device.mirror_sessions:
        if s.name not in numbers:
            continue
        sources = monitor_text.sources(s, report, "NX-OS")
        if sources is None:
            continue
        lines.append(f"monitor session {numbers[s.name]}")
        lines += [f"{ind}source interface {port(p)} {way}" for p, way in sources.items()]
        lines.append(f"{ind}destination interface {port(s.destination)}")
        if s.acl:
            if s.acl in device.acls:
                lines.append(f"{ind}filter access-group {s.acl}")
            else:
                report.add(KIND, monitor_text.label(s), Severity.REVIEW, "mirror-acl",
                           f"ACL {s.acl} that filters the mirror is not defined; left out")
        lines.append(f"{ind}no shut")
    return lines


def destinations(device: Device) -> Set[str]:
    return {s.destination for s in device.mirror_sessions if s.destination and s.sources}


def sflow_lines(device: Device, report: Report, port: Name, vrf: Name, features: Set[str]) -> List[str]:
    sf = device.sflow
    if sf is None:
        return []
    features.add("sflow")
    report.item(KIND, monitor_text.SFLOW)
    lines: List[str] = []
    if sf.sample_rate is not None:
        lines.append(f"sflow sampling-rate {sf.sample_rate}")
    if sf.polling_interval is not None:
        lines.append(f"sflow counter-poll-interval {sf.polling_interval}")
    if sf.collectors:
        c = sf.collectors[0]
        lines.append(f"sflow collector-ip {c.address} vrf {vrf(c.vrf) if c.vrf else 'default'}")
        if c.port is not None:
            lines.append(f"sflow collector-port {c.port}")
        if len(sf.collectors) > 1:
            report.add(KIND, monitor_text.SFLOW, Severity.REVIEW, "sflow-collectors",
                       "NX-OS sends sFlow to one collector; " + ", ".join(x.address for x in sf.collectors[1:])
                       + " left out")
    else:
        report.add(KIND, monitor_text.SFLOW, Severity.REVIEW, "sflow-collector", "no collector to send to")
    agent = monitor_text.agent(device, sf, report, "NX-OS")
    if agent:
        lines.append(f"sflow agent-ip {agent}")
    left = []
    if sf.extensions:
        left.append("the extensions " + ", ".join(sf.extensions))
    if sf.source_vrf:
        left.append(f"the source interface's VRF {sf.source_vrf}")
    if left:
        report.add(KIND, monitor_text.SFLOW, Severity.APPROX, "sflow-options",
                   " and ".join(left) + " left out: NX-OS samples with its own fields and sends from the agent address")
    lines += [f"sflow data-source interface {port(i.name)}" for i in monitor_text.sflow_ports(device)
              if i.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG)]
    return lines


def netflow_lines(device: Device, report: Report, port: Name, vrf: Name, ind: str, features: Set[str]) -> List[str]:
    nf = device.netflow
    if nf is None:
        return []
    features.add("netflow")
    monitor_text.netflow_item(nf, report)
    lines: List[str] = []
    exporters = []
    for n, c in enumerate(nf.collectors, 1):
        name = f"RS-EXPORT-{n}"
        exporters.append(name)
        lines += [f"flow exporter {name}", f"{ind}destination {c.address}" + (f" use-vrf {vrf(c.vrf)}" if c.vrf else "")]
        if c.port is not None:
            lines.append(f"{ind}transport udp {c.port}")
        if nf.source_interface:
            lines.append(f"{ind}source {port(nf.source_interface)}")
        lines.append(f"{ind}version 9")
    if nf.version not in (None, 9):
        report.add(KIND, monitor_text.NETFLOW, Severity.APPROX, "netflow-version",
                   f"exported as NetFlow version 9 (was {'IPFIX' if nf.version == 10 else f'version {nf.version}'})")
    if nf.record and nf.record != RECORD:
        report.add(KIND, monitor_text.NETFLOW, Severity.APPROX, "netflow-record",
                   f"flow record {nf.record} written as the built-in {RECORD}")
    lines += [f"flow monitor {MONITOR}", f"{ind}record {RECORD}"] + [f"{ind}exporter {e}" for e in exporters]
    if nf.sample_rate:
        lines += [f"sampler {SAMPLER}", f"{ind}mode 1 out-of {nf.sample_rate}"]
    return lines


def interface_lines(device: Device, iface: Interface, add: Add, mirror_ports: Set[str]) -> List[str]:
    lines: List[str] = []
    nf = device.netflow
    if nf is not None and iface.flow:
        sampler = f" sampler {SAMPLER}" if nf.sample_rate else ""
        lines.append(f"ip flow monitor {MONITOR} input{sampler}")
        if iface.flow != "input":
            add(Severity.APPROX, "netflow-direction",
                f"a Nexus 9000 records ingress flows only; the {iface.flow} flows are recorded inbound")
    if iface.name in mirror_ports and iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG):
        lines.append("switchport monitor")
    return lines


def tracking_lines(device: Device, plan: tracking_text.Plan, port: Name, vrf: Name, ind: str,
                   features: Set[str]) -> List[str]:
    lines: List[str] = []
    for sla in device.ip_slas.values():
        if sla.name not in plan.slas:
            continue
        features.add("sla sender")
        number = plan.slas[sla.name]
        source = f" source-interface {port(sla.source_interface)}" if sla.source_interface else \
            f" source-ip {sla.source_address}" if sla.source_address else ""
        lines += [f"ip sla {number}", f"{ind}icmp-echo {sla.target}{source}"]
        if sla.vrf:
            lines.append(f"{ind * 2}vrf {vrf(sla.vrf)}")
        if sla.frequency is not None:
            lines.append(f"{ind * 2}frequency {sla.frequency}")
        if sla.timeout_ms is not None:
            lines.append(f"{ind * 2}timeout {sla.timeout_ms}")
        lines.append(f"ip sla schedule {number} life forever start-time now")
    for t in device.tracks.values():
        if t.name not in plan.tracks:
            continue
        name = plan.tracks[t.name]
        if t.sla:
            lines.append(f"track {name} ip sla {plan.slas[t.sla]} reachability")
        else:
            lines.append(f"track {name} interface {port(t.interface)} line-protocol")
        delays = [f"{way} {value}" for way, value in (("up", t.delay_up), ("down", t.delay_down)) if value is not None]
        if delays:
            lines.append(f"{ind}delay {' '.join(delays)}")
    return lines


def lldp_lines(device: Device, report: Report) -> List[str]:
    m = device.management
    lines: List[str] = []
    if m.lldp_timer is not None or m.lldp_holdtime is not None or m.lldp_mgmt_interface or m.lldp_mgmt_vrf:
        report.item("management", "LLDP")
    if m.lldp_timer is not None:
        lines.append(f"lldp timer {m.lldp_timer}")
    if m.lldp_holdtime is not None:
        lines.append(f"lldp holdtime {m.lldp_holdtime}")
    if m.lldp_mgmt_interface or m.lldp_mgmt_vrf:
        what = " and ".join(x for x in (f"the address of {m.lldp_mgmt_interface}" if m.lldp_mgmt_interface else "",
                                        f"VRF {m.lldp_mgmt_vrf}" if m.lldp_mgmt_vrf else "") if x)
        report.add("management", "LLDP", Severity.APPROX, "lldp-mgmt",
                   f"the management address ({what}) is left out: NX-OS advertises the address of mgmt0 itself")
    return lines


def unwritable(device: Device, report: Report) -> None:
    if device.twamp_port is not None:
        report.item(KIND, "TWAMP reflector")
        report.add(KIND, "TWAMP reflector", Severity.REVIEW, "twamp",
                   f"the TWAMP reflector (UDP {device.twamp_port}) is not written: RouterShift knows no NX-OS form for "
                   "it; check whether the release has a TWAMP responder and set it by hand")


# reading ------------------------------------------------------------------------------------------------------------

class Reader:
    def __init__(self, device: Device) -> None:
        self.device = device
        self.sflow_ports: List[str] = []
        self.exporters: Dict[str, Netflow] = {}
        self.monitors: Dict[str, List[str]] = {}
        self.records: Dict[str, str] = {}
        self.samplers: Dict[str, int] = {}
        self.port_samplers: List[str] = []
        self.pending_port: Optional[int] = None  # sflow collector-port before collector-ip

    def _sflow(self, line: int, text: str) -> Sflow:
        if self.device.sflow is None:
            self.device.sflow = Sflow()
            self.device.sflow.origin.line, self.device.sflow.origin.text = line, text
        return self.device.sflow

    def sflow(self, w: List[str], line: int, text: str) -> bool:
        """sflow sampling-rate N | counter-poll-interval N | collector-ip A vrf V | collector-port N | agent-ip A |
        data-source interface P (w starts after 'sflow')."""
        n = len(w)
        if w[0] == "data-source" and n >= 3 and w[1] == "interface":
            self._sflow(line, text)
            self.sflow_ports += monitor_text.ios_ports(w[2:])
            return True
        sf = self._sflow(line, text)
        if w[0] == "sampling-rate" and n == 2:
            sf.sample_rate = int(w[1])
        elif w[0] == "counter-poll-interval" and n == 2:
            sf.polling_interval = int(w[1])
        elif w[0] == "collector-ip" and n == 4 and w[2] == "vrf":
            vrf = "" if w[3] == "default" else w[3]
            port = sf.collectors[0].port if sf.collectors else self.pending_port
            sf.collectors = [monitor_text.collector(str(ipaddress.ip_address(w[1])), port, vrf)]
        elif w[0] == "collector-port" and n == 2:
            if sf.collectors:
                sf.collectors[0].port = int(w[1])
            else:
                self.pending_port = int(w[1])
        elif w[0] == "agent-ip" and n == 2:
            sf.agent = str(ipaddress.ip_address(w[1]))
        else:
            return False
        return True

    def flow(self, w: List[str], children: List[List[str]]) -> Optional[List[int]]:
        """flow exporter NAME | flow monitor NAME: the children it did not understand, or None if not one."""
        if len(w) != 3 or w[1] not in ("exporter", "monitor"):
            return None
        bad: List[int] = []
        if w[1] == "exporter":
            exp = self.exporters[w[2]] = Netflow()
            for k, c in enumerate(children):
                if c[0] == "destination" and len(c) in (2, 4) and c[2:3] in ([], ["use-vrf"]):
                    exp.collectors.append(monitor_text.collector(str(ipaddress.ip_address(c[1])), None,
                                                                 c[3] if len(c) == 4 else ""))
                elif c[:2] == ["transport", "udp"] and len(c) == 3 and exp.collectors:
                    exp.collectors[-1].port = int(c[2])
                elif c[0] == "source" and len(c) >= 2:
                    exp.source_interface = names.canonical(" ".join(c[1:]))[0]
                elif c[0] == "version" and len(c) == 2 and c[1] in ("5", "9"):
                    exp.version = int(c[1])
                elif c[0] != "description":
                    bad.append(k)
            return bad
        exporters = self.monitors[w[2]] = []
        for k, c in enumerate(children):
            if c[0] == "exporter" and len(c) == 2:
                exporters.append(c[1])
            elif c[0] == "record" and len(c) >= 2:
                self.records[w[2]] = " ".join(c[1:])
            elif c[0] != "description":
                bad.append(k)
        return bad

    def sampler(self, name: str, children: List[List[str]]) -> List[int]:
        bad = []
        for k, c in enumerate(children):
            if c[0] == "mode" and len(c) == 4 and c[2] == "out-of" and c[1].isdigit() and c[3].isdigit():
                self.samplers[name] = max(1, int(c[3]) // int(c[1]))
            elif c[0] != "description":
                bad.append(k)
        return bad

    def interface_line(self, iface: Interface, w: List[str]) -> bool:
        """ip flow monitor M input|output [sampler S]; switchport monitor."""
        if w[:3] == ["ip", "flow", "monitor"] and len(w) in (5, 7) and w[4] in ("input", "output") and \
                w[5:6] in ([], ["sampler"]):
            iface.flow = w[4] if iface.flow in ("", w[4]) else "both"
            if len(w) == 7:
                self.port_samplers.append(w[6])
            return True
        return w == ["switchport", "monitor"]

    def finish(self) -> None:
        d = self.device
        for name in self.sflow_ports:
            iface = d.interfaces.get(name)
            if iface is not None:
                iface.sflow = True
        if not self.monitors and not self.exporters:
            return
        nf = d.netflow = d.netflow or Netflow()
        used = [e for exps in self.monitors.values() for e in exps] or list(self.exporters)
        for name in dict.fromkeys(used):
            exp = self.exporters.get(name)
            if exp is None:
                continue
            nf.collectors += exp.collectors
            nf.version = nf.version or exp.version
            nf.source_interface = nf.source_interface or exp.source_interface
        records = [r for r in self.records.values() if r]
        nf.record = records[0] if records else ""
        rates = [self.samplers[s] for s in self.port_samplers if s in self.samplers]
        if rates:
            nf.sample_rate = rates[0]


def monitor_session(device: Device, name: str, children: List[List[str]], line: int, text: str) -> List[int]:
    """monitor session N / source interface P [rx|tx|both] / destination interface P / filter access-group ACL."""
    s = monitor_text.session(device, name, line, text)
    bad = []
    for k, c in enumerate(children):
        if c[:2] == ["source", "interface"] and len(c) >= 3:
            way = monitor_text.direction(c[-1]) if len(c) > 3 else None
            for p in monitor_text.ios_ports(c[2:-1] if way else c[2:]):
                s.sources[p] = way or "both"
        elif c[:2] == ["destination", "interface"] and len(c) >= 3:
            s.destination = names.canonical(" ".join(c[2:]))[0]
        elif c[:2] == ["filter", "access-group"] and len(c) == 3:
            s.acl = c[2]
        elif c in (["no", "shut"], ["shut"]) or c[0] == "description":
            pass
        else:
            bad.append(k)
    return bad
