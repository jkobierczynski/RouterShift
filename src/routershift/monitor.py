# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Port mirroring (SPAN), sFlow and NetFlow: the helpers every reader and writer shares."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import names

from .model import Device, FlowCollector, Interface, InterfaceKind, MirrorSession, Netflow, Sflow
from .report import Report, Severity

KIND = "monitor"
SFLOW = "sflow"
NETFLOW = "netflow"
DIRECTIONS = ("both", "rx", "tx")
SFLOW_PORT = 6343
# predefined IOS flow records a monitor can name without defining them
IOS_RECORD = "netflow ipv4 original-input"


def label(session: MirrorSession) -> str:
    return f"mirror session {session.name}"


def direction(word: str) -> Optional[str]:
    """A direction word of any platform as the model's: both, rx or tx."""
    return {"both": "both", "rx": "rx", "tx": "tx", "in": "rx", "out": "tx", "inbound": "rx", "outbound": "tx",
            "ingress": "rx", "egress": "tx"}.get(word.lower())


def session(device: Device, name: str, line: int = 0, text: str = "") -> MirrorSession:
    """The mirror session of that name, made the first time it is named."""
    for s in device.mirror_sessions:
        if s.name == name:
            return s
    s = MirrorSession(name)
    s.origin.line, s.origin.text = line, text
    device.mirror_sessions.append(s)
    return s


def numbers(device: Device, report: Report, platform: str, limit: int) -> Dict[str, str]:
    """The session number each session takes on a target that numbers them 1..limit; a session past the limit is
    reported and left out (it is not in the map)."""
    out: Dict[str, str] = {}
    used = {s.name for s in device.mirror_sessions if s.name.isdigit() and 1 <= int(s.name) <= limit}
    free = (str(n) for n in range(1, limit + 1) if str(n) not in used)
    for s in device.mirror_sessions:
        report.item(KIND, label(s))
        if s.name in used:
            out[s.name] = s.name
            continue
        number = next(free, None)
        if number is None:
            report.skip(KIND, label(s), "mirror-limit", f"{platform} has {limit} mirror sessions; left out")
            continue
        out[s.name] = number
        report.add(KIND, label(s), Severity.APPROX, "mirror-number", f"written as session {number}")
    return out


def sources(s: MirrorSession, report: Report, platform: str) -> Optional[Dict[str, str]]:
    """The source ports of a session, or None when it cannot be written."""
    if not s.destination or not s.sources:
        report.skip(KIND, label(s), "mirror-incomplete", "no source or no destination port; left out")
        return None
    out: Dict[str, str] = {}
    for port, way in s.sources.items():
        out[port] = way if way in DIRECTIONS else "both"
        if way not in DIRECTIONS:
            report.add(KIND, label(s), Severity.APPROX, "mirror-direction",
                       f"{platform} mirrors {port} both ways, not only {way}")
    return out


def physical(device: Device) -> List[Interface]:
    """The ports sFlow can sample: Ethernet ports that are not subinterfaces."""
    return [i for i in device.interfaces.values() if i.kind == InterfaceKind.ETHERNET and not i.parent]


def sflow_ports(device: Device) -> List[Interface]:
    return [i for i in device.interfaces.values() if i.sflow]


def flow_ports(device: Device) -> List[Interface]:
    return [i for i in device.interfaces.values() if i.flow]


def all_ports(device: Device) -> bool:
    """Whether sFlow samples every port (EOS samples all of them once it runs)."""
    ports = physical(device)
    return bool(ports) and all(i.sflow for i in ports)


def agent(device: Device, sflow: Sflow, report: Report, platform: str) -> str:
    """The agent address: as stated, or the first address of the source interface."""
    if sflow.agent:
        return sflow.agent
    iface = device.interfaces.get(sflow.source_interface)
    if iface is not None and iface.ipv4:
        report.add(KIND, SFLOW, Severity.APPROX, "sflow-agent",
                   f"{platform} takes an agent address: {iface.name}'s address written")
        return iface.ipv4[0].split("/")[0]
    if sflow.source_interface:
        report.add(KIND, SFLOW, Severity.REVIEW, "sflow-agent",
                   f"{platform} takes an agent address; {sflow.source_interface} has none, left out")
    return ""


def collector(address: str, port: Optional[int] = None, vrf: str = "") -> FlowCollector:
    return FlowCollector(address, port, vrf)


def port_text(c: FlowCollector, default: int) -> int:
    return c.port if c.port is not None else default


def vrf_unsupported(collectors: List[FlowCollector], report: Report, name: str, platform: str) -> None:
    for c in collectors:
        if c.vrf:
            report.add(KIND, name, Severity.REVIEW, "flow-vrf",
                       f"{platform}: collector {c.address} is reached through VRF {c.vrf}; written without it")


def sflow_unsupported(device: Device, report: Report, platform: str) -> None:
    if device.sflow is not None:
        report.skip(KIND, SFLOW, "sflow-unsupported",
                    f"{platform} has no sFlow; left out (NetFlow is the nearest it has)")


def netflow_unsupported(device: Device, report: Report, platform: str) -> None:
    if device.netflow is not None:
        report.skip(KIND, NETFLOW, "netflow-unsupported", f"{platform}: NetFlow is not written; configure it by hand")


def netflow_item(netflow: Netflow, report: Report) -> None:
    report.item(KIND, NETFLOW)
    if not netflow.collectors:
        report.add(KIND, NETFLOW, Severity.REVIEW, "netflow-collector", "no collector to export to")


def ios_ports(words: List[str]) -> List[str]:
    """An IOS or EOS port list as canonical names: Gi1/0/1 - 3 , Gi1/0/5 or Ethernet1-3,Ethernet5."""
    out: List[str] = []
    for part in " ".join(words).split(","):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"^(.*?\d)\s*-\s*(\d+)$", part)
        first, last = (m.group(1), m.group(2)) if m else (part, "")
        name = names.canonical(first)[0]
        if not last:
            out.append(name)
            continue
        head, tail = re.match(r"^(.*?)(\d+)$", name).groups()  # type: ignore[union-attr]
        out += [f"{head}{n}" for n in range(int(tail), int(last) + 1)]
    return out


def finish(device: Device) -> None:
    """A reader's last step: ports that record flows mean NetFlow is configured, collectors or not."""
    if device.netflow is None and flow_ports(device):
        device.netflow = Netflow()
