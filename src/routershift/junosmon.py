# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Junos monitoring: sFlow, flow export (inline J-Flow), port mirroring (analyzers), LLDP timers, the TWAMP reflector,
and probes (RPM) with the objects that track them.

How the model maps to Junos:

* sFlow is ``protocols sflow`` with the sampled ports listed under it; the agent is ``agent-id`` and the source
  ``source-ip``.
* NetFlow is inline J-Flow: a sampling instance ``RS-SAMPLING`` exporting version 9 (or IPFIX) to the collectors, the
  ports sampling input (``family inet sampling input``), and the instance bound to FPC 0.
* A mirror session is an analyzer of its name (``forwarding-options analyzer``) with the source units as ingress or
  egress inputs.
* An IP SLA probe is an RPM test (``services rpm probe <name> test icmp``); a tracked interface lives on in the VRRP
  groups that track it (``track interface``), as Junos has no tracked objects of their own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import monitor as monitor_text
from . import tracking as tracking_text
from .model import Device, FlowCollector, Interface, IpSla, MirrorSession, Netflow, Sflow
from .report import Report, Severity

KIND = monitor_text.KIND
SAMPLING = "RS-SAMPLING"
TEMPLATE = "RS-TEMPLATE"
TWAMP_PORT = 862
TEST = "icmp"

Add = Callable[..., None]


def analyzer_name(session: str) -> str:
    return session if not session[:1].isdigit() else f"mirror-{session}"


def _address(device: Device, name: str) -> str:
    iface = device.interfaces.get(name)
    return iface.ipv4[0].split("/")[0] if iface is not None and iface.ipv4 else ""


# writing ------------------------------------------------------------------------------------------------------------

class MonitorWriter:
    def __init__(self, device: Device, add: Add, report: Report, port: Callable[[str], str],
                 unit: Callable[[str], str], instance: Callable[[str], str]) -> None:
        self.device, self.add, self.report, self.port, self.unit, self.instance = \
            device, add, report, port, unit, instance

    def write(self) -> None:
        self.sflow()
        self.netflow()
        self.mirrors()
        self.lldp()
        self.twamp()
        self.probes()

    def sflow(self) -> None:
        sf = self.device.sflow
        if sf is None:
            return
        label = monitor_text.SFLOW
        self.report.item(KIND, label)
        base = ("protocols", "sflow")
        if sf.sample_rate:
            self.add(*base, "sample-rate", f"ingress {sf.sample_rate}")
        if sf.polling_interval is not None:
            self.add(*base, f"polling-interval {sf.polling_interval}")
        source = _address(self.device, sf.source_interface) if sf.source_interface else ""
        if sf.agent:
            self.add(*base, f"agent-id {sf.agent}")
        if source:
            self.add(*base, f"source-ip {source}")
        elif sf.source_interface:
            self.report.add(KIND, label, Severity.REVIEW, "sflow-source",
                            f"Junos takes a source address; {sf.source_interface} has none, left out")
        for c in sf.collectors:
            path = base + (f"collector {c.address}",)
            self.add(*path)
            if c.port is not None and c.port != monitor_text.SFLOW_PORT:
                self.add(*path, f"udp-port {c.port}")
            if c.vrf:
                self.add(*path, f"routing-instance {self.instance(c.vrf)}")
        for iface in monitor_text.sflow_ports(self.device):
            self.add(*base, f"interfaces {self.port(iface.name)}")
        if sf.extensions:
            self.report.add(KIND, label, Severity.APPROX, "sflow-extension",
                            f"the sFlow extensions ({', '.join(sf.extensions)}) are left out: Junos adds the "
                            "gateway and router data it has by itself")
        if any(c.vrf for c in sf.collectors) or sf.source_vrf:
            self.report.add(KIND, label, Severity.APPROX, "sflow-vrf",
                            "the collectors are reached through their routing instance (collector ... "
                            "routing-instance); check the platform supports it")

    def netflow(self) -> None:
        nf = self.device.netflow
        if nf is None:
            return
        monitor_text.netflow_item(nf, self.report)
        label = monitor_text.NETFLOW
        version = "version-ipfix" if nf.version == 10 else "version9"
        base = ("forwarding-options", "sampling", f"instance {SAMPLING}")
        self.add(*base, "input", f"rate {nf.sample_rate or 1}")
        for c in nf.collectors:
            path = base + ("family inet", "output", f"flow-server {c.address}")
            if c.port is not None:
                self.add(*path, f"port {c.port}")
            self.add(*path, version, f"template {TEMPLATE}")
            if c.vrf:
                self.report.add(KIND, label, Severity.REVIEW, "flow-vrf",
                                f"collector {c.address} is reached through VRF {c.vrf}; J-Flow exports from the main "
                                "routing table, written without it")
        source = _address(self.device, nf.source_interface) if nf.source_interface else ""
        if source:
            self.add(*base, "family inet", "output", f"inline-jflow source-address {source}")
        self.add("services", "flow-monitoring", version, f"template {TEMPLATE}", "ipv4-template")
        self.add("chassis", "fpc 0", f"sampling-instance {SAMPLING}")
        for iface in monitor_text.flow_ports(self.device):
            for way in ("input", "output"):
                if iface.flow in (way, "both"):
                    self.add("interfaces", self.port(iface.name), "unit 0", "family inet", f"sampling {way}")
        self.report.add(KIND, label, Severity.APPROX, "jflow",
                        "written as inline J-Flow (MX, SRX and PTX); EX and QFX switches sample with sFlow instead"
                        + (f"; the flow record {nf.record} is J-Flow's own IPv4 template" if nf.record else ""))
        if nf.version == 5:
            self.report.add(KIND, label, Severity.APPROX, "jflow-version",
                            "inline J-Flow exports version 9 or IPFIX; version 5 is written as version 9")

    def mirrors(self) -> None:
        for s in self.device.mirror_sessions:
            label = monitor_text.label(s)
            self.report.item(KIND, label)
            sources = monitor_text.sources(s, self.report, "Junos")
            if sources is None:
                continue
            base = ("forwarding-options", "analyzer", analyzer_name(s.name))
            for port, way in sources.items():
                unit = self.unit(port)
                if way in ("both", "rx"):
                    self.add(*base, "input", "ingress", f"interface {unit}")
                if way in ("both", "tx"):
                    self.add(*base, "input", "egress", f"interface {unit}")
            self.add(*base, "output", f"interface {self.unit(s.destination)}")
            if s.acl:
                self.report.add(KIND, label, Severity.REVIEW, "mirror-acl",
                                f"Junos mirrors only what a filter picks with the filter action 'analyzer "
                                f"{analyzer_name(s.name)}' in the source port's input filter; the ACL {s.acl} is not "
                                "written that way, so the analyzer mirrors all the traffic")

    def lldp(self) -> None:
        m = self.device.management
        base = ("protocols", "lldp")
        if m.lldp_timer is not None:
            self.add(*base, f"advertisement-interval {m.lldp_timer}")
        if m.lldp_holdtime is not None:
            interval = m.lldp_timer or 30
            multiplier = max(2, round(m.lldp_holdtime / interval))
            self.add(*base, f"hold-multiplier {multiplier}")
            if multiplier * interval != m.lldp_holdtime:
                self.report.add("management", "LLDP", Severity.APPROX, "lldp-hold",
                                f"Junos sets the hold time as a multiple of the interval: {multiplier * interval} s "
                                f"for {m.lldp_holdtime} s")
        if m.lldp_mgmt_interface:
            address = _address(self.device, m.lldp_mgmt_interface)
            if address:
                self.add(*base, f"management-address {address}")
            else:
                self.report.add("management", "LLDP", Severity.REVIEW, "lldp-mgmt",
                                f"the management address comes from {m.lldp_mgmt_interface}, which has no address")
        if m.lldp_timer is not None or m.lldp_holdtime is not None or m.lldp_mgmt_interface:
            self.report.item("management", "LLDP")
            if m.lldp_mgmt_vrf:
                self.report.add("management", "LLDP", Severity.APPROX, "lldp-mgmt-vrf",
                                f"the management address's VRF ({m.lldp_mgmt_vrf}) has no setting on Junos; the "
                                "address is written as it is")

    def twamp(self) -> None:
        dev = self.device
        if dev.twamp_port is None:
            return
        label = "TWAMP reflector"
        self.report.item(KIND, label)
        base = ("services", "rpm", "twamp", "server")
        if dev.twamp_port != TWAMP_PORT:
            self.add(*base, f"port {dev.twamp_port}")
        if dev.twamp_mode == "light":
            self.add(*base, "light")
        else:
            self.add(*base, "authentication-mode none")
        self.report.add(KIND, label, Severity.APPROX, "twamp",
                        "written as the RPM TWAMP server" + (" in light mode" if dev.twamp_mode == "light" else "")
                        + "; check the platform's release supports it and add the clients it may answer "
                        "(client-list)")

    def probes(self) -> None:
        dev = self.device
        for sla in dev.ip_slas.values():
            label = tracking_text.sla_label(sla)
            self.report.item(tracking_text.KIND, label)
            path = ("services", "rpm", f"probe {sla.name}", f"test {TEST}")
            self.add(*path, "probe-type icmp-ping")
            if sla.target:
                self.add(*path, f"target address {sla.target}")
            if sla.frequency is not None:
                self.add(*path, f"test-interval {sla.frequency}")
            if sla.timeout_ms is not None:
                self.add(*path, f"probe-timeout {max(1, round(sla.timeout_ms / 1000))}")
                if sla.timeout_ms % 1000:
                    self.report.add(tracking_text.KIND, label, Severity.APPROX, "rpm-timeout",
                                    f"RPM times out in whole seconds; {sla.timeout_ms} ms is rounded")
            source = sla.source_address or (_address(dev, sla.source_interface) if sla.source_interface else "")
            if source:
                self.add(*path, f"source-address {source}")
            if sla.vrf:
                self.add(*path, f"routing-instance {self.instance(sla.vrf)}")
        for t in dev.tracks.values():
            label = tracking_text.track_label(t)
            self.report.item(tracking_text.KIND, label)
            users = [g for i in dev.interfaces.values() for g in i.fhrp if t.name in g.tracks]
            if t.interface:
                self.report.add(tracking_text.KIND, label, Severity.APPROX, "junos-track",
                                f"Junos has no tracked objects: the interface {t.interface} is tracked by each VRRP "
                                "group that follows it (track interface)" + ("" if users else
                                                                             ", and no group follows it"))
            elif t.sla:
                self.report.add(tracking_text.KIND, label, Severity.REVIEW, "junos-track",
                                f"Junos has no tracked objects: the result of probe {t.sla} reaches routes only "
                                "through IP monitoring (services ip-monitoring policy ... match rpm-probe), which is "
                                "not written")
            if t.delay_up is not None or t.delay_down is not None:
                self.report.add(tracking_text.KIND, label, Severity.APPROX, "track-delay",
                                "the delay is left out; VRRP's priority-hold-time comes closest")


# reading ------------------------------------------------------------------------------------------------------------

@dataclass
class MonitorReader:
    device: Device
    sflow_ports: List[str] = field(default_factory=list)
    sflow_source: str = ""
    flow_ports: List[str] = field(default_factory=list)
    jflow_source: str = ""
    analyzers: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)  # name -> ingress|egress|output -> units
    probes: Dict[str, IpSla] = field(default_factory=dict)
    sources: Dict[str, str] = field(default_factory=dict)  # probe -> source address

    def sflow(self, w: List[str]) -> bool:
        """protocols sflow ... (w starts after 'sflow')."""
        dev = self.device
        sf = dev.sflow = dev.sflow or Sflow()
        if w[:2] == ["sample-rate", "ingress"] and len(w) == 3:
            sf.sample_rate = int(w[2])
        elif w[:2] == ["sample-rate", "egress"] and len(w) == 3:
            sf.sample_rate = sf.sample_rate or int(w[2])
        elif w[0] == "polling-interval" and len(w) == 2:
            sf.polling_interval = int(w[1])
        elif w[0] == "agent-id" and len(w) == 2:
            sf.agent = w[1]
        elif w[0] == "source-ip" and len(w) == 2:
            self.sflow_source = w[1]
        elif w[0] == "collector" and len(w) >= 2:
            c = next((x for x in sf.collectors if x.address == w[1]), None)
            if c is None:
                c = FlowCollector(w[1], monitor_text.SFLOW_PORT)
                sf.collectors.append(c)
            if w[2:3] == ["udp-port"] and len(w) == 4:
                c.port = int(w[3])
            elif w[2:3] == ["routing-instance"] and len(w) == 4:
                c.vrf = w[3]
            elif len(w) != 2:
                return False
        elif w[0] == "interfaces" and len(w) == 2:
            self.sflow_ports.append(w[1])
        else:
            return False
        return True

    def sampling(self, w: List[str]) -> bool:
        """forwarding-options sampling instance NAME ... (w starts after the instance name)."""
        nf = self.device.netflow = self.device.netflow or Netflow()
        if w[:2] == ["input", "rate"] and len(w) == 3:
            nf.sample_rate = int(w[2]) if w[2] != "1" else None
            return True
        if w[:3] == ["family", "inet", "output"] and len(w) >= 5:
            rest = w[3:]
            if rest[0] == "flow-server" and len(rest) >= 3:
                c = next((x for x in nf.collectors if x.address == rest[1]), None)
                if c is None:
                    c = FlowCollector(rest[1])
                    nf.collectors.append(c)
                if rest[2] == "port" and len(rest) == 4:
                    c.port = int(rest[3])
                    return True
                if rest[2] in ("version9", "version-ipfix") and len(rest) == 5 and rest[3] == "template":
                    nf.version = 10 if rest[2] == "version-ipfix" else 9
                    return True
                return False
            if rest[:2] == ["inline-jflow", "source-address"] and len(rest) == 3:
                self.jflow_source = rest[2]
                return True
        return False

    def analyzer(self, w: List[str]) -> bool:
        """forwarding-options analyzer NAME ... (w starts after 'analyzer')."""
        a = self.analyzers.setdefault(w[0], {})
        if w[1:3] in (["input", "ingress"], ["input", "egress"]) and len(w) == 5 and w[3] == "interface":
            a.setdefault(w[2], []).append(w[4])
            return True
        if w[1:3] == ["output", "interface"] and len(w) == 4:
            a.setdefault("output", []).append(w[3])
            return True
        return False

    def rpm(self, w: List[str]) -> bool:
        """services rpm ... (w starts after 'rpm')."""
        dev = self.device
        if w[:3] == ["twamp", "server", "light"] and len(w) == 3:
            dev.twamp_mode = "light"
            dev.twamp_port = dev.twamp_port or TWAMP_PORT
            return True
        if w[:3] == ["twamp", "server", "port"] and len(w) == 4:
            dev.twamp_port = int(w[3])
            dev.twamp_mode = dev.twamp_mode or "full"
            return True
        if w[:3] == ["twamp", "server", "authentication-mode"] and len(w) == 4:
            dev.twamp_port = dev.twamp_port or TWAMP_PORT
            dev.twamp_mode = dev.twamp_mode or "full"
            return True
        if w[0] == "probe" and len(w) >= 5 and w[2] == "test":
            sla = self.probes.setdefault(w[1], IpSla(w[1]))
            rest = w[4:]
            if rest == ["probe-type", "icmp-ping"]:
                return True
            if rest[:2] == ["target", "address"] and len(rest) == 3:
                sla.target = rest[2]
            elif rest[0] == "test-interval" and len(rest) == 2:
                sla.frequency = int(rest[1])
            elif rest[0] == "probe-timeout" and len(rest) == 2:
                sla.timeout_ms = int(rest[1]) * 1000
            elif rest[0] == "source-address" and len(rest) == 2:
                self.sources[w[1]] = rest[1]
            elif rest[0] == "routing-instance" and len(rest) == 2:
                sla.vrf = rest[1]
            else:
                return False
            return True
        return False

    def finish(self, canonical: Callable[[str], Optional[Interface]], interface_of: Callable[[str], str],
               unread: Callable[[int, str, str], None]) -> None:
        dev = self.device
        if dev.sflow is not None:
            sf = dev.sflow
            if self.sflow_source:
                sf.source_interface = interface_of(self.sflow_source)
                if not sf.source_interface:
                    sf.agent = sf.agent or self.sflow_source
                elif sf.agent == self.sflow_source:
                    sf.agent = ""
                iface = dev.interfaces.get(sf.source_interface)
                if iface is not None and iface.vrf:
                    sf.source_vrf = iface.vrf
            for port in self.sflow_ports:
                iface = canonical(port)
                if iface is None:
                    unread(0, f"set protocols sflow interfaces {port}", "an interface RouterShift does not know")
                else:
                    iface.sflow = True
        if dev.netflow is not None and self.jflow_source:
            dev.netflow.source_interface = interface_of(self.jflow_source)
        for name, parts in self.analyzers.items():
            session = monitor_text.session(dev, re.sub(r"^mirror-(?=\d)", "", name))
            for way, key in (("rx", "ingress"), ("tx", "egress")):
                for unit in parts.get(key, []):
                    iface = canonical(unit)
                    if iface is None:
                        unread(0, f"set forwarding-options analyzer {name} input {key} interface {unit}",
                               "an interface RouterShift does not know")
                        continue
                    before = session.sources.get(iface.name)
                    session.sources[iface.name] = "both" if before and before != way else way
            outputs = [canonical(u) for u in parts.get("output", [])]
            if outputs and outputs[0] is not None:
                session.destination = outputs[0].name
        for name, sla in self.probes.items():
            if name in self.sources:
                sla.source_interface = interface_of(self.sources[name])
                if not sla.source_interface:
                    sla.source_address = self.sources[name]
            dev.ip_slas[name] = sla

    @staticmethod
    def flow_port(iface: Interface, way: str) -> None:
        iface.flow = way if iface.flow in ("", way) else "both"
