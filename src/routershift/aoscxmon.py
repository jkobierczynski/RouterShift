# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AOS-CX monitoring beyond mirror sessions and sFlow: LLDP options, tracked objects, and what has no AOS-CX form.

How the model maps to AOS-CX:

* LLDP sends every ``lldp timer`` seconds; neighbours keep the information ``lldp holdtime-multiplier`` times as long.
  The management address advertised is ``lldp management-ipv4-address``.
* A tracked object follows a port's link: ``track N interface P``, and a VRRP group names it with ``track N``.
* The sFlow source VRF is the VRF of the collectors; the sFlow extensions, a mirror's ACL filter and a TWAMP
  reflector have no AOS-CX setting and are reported.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Optional

from . import monitor as monitor_text
from . import tracking as tracking_text
from .model import Device
from .report import Report, Severity

DEFAULT_TIMER = 30


def lldp_lines(device: Device, report: Report, port: Callable[[str], str]) -> List[str]:
    m = device.management
    lines: List[str] = []
    label = "LLDP"
    if m.lldp_timer is not None or m.lldp_holdtime is not None or m.lldp_mgmt_interface:
        report.item("management", label)
    timer = m.lldp_timer
    if timer is not None:
        lines.append(f"lldp timer {timer}")
    if m.lldp_holdtime is not None:
        base = timer or DEFAULT_TIMER
        multiplier = max(2, min(10, round(m.lldp_holdtime / base)))
        lines.append(f"lldp holdtime-multiplier {multiplier}")
        if multiplier * base != m.lldp_holdtime:
            report.add("management", label, Severity.APPROX, "lldp-holdtime",
                       f"AOS-CX holds LLDP information a multiple of the timer: {multiplier} x {base} s = "
                       f"{multiplier * base} s (was {m.lldp_holdtime} s)")
    if m.lldp_mgmt_interface:
        iface = device.interfaces.get(m.lldp_mgmt_interface)
        if iface is not None and iface.ipv4:
            lines.append(f"lldp management-ipv4-address {iface.ipv4[0].split('/')[0]}")
            report.add("management", label, Severity.APPROX, "lldp-mgmt",
                       f"the management address is the address of {m.lldp_mgmt_interface}, which AOS-CX names itself")
        else:
            report.add("management", label, Severity.REVIEW, "lldp-mgmt",
                       f"the management address interface {m.lldp_mgmt_interface} has no IPv4 address; left out")
    if m.lldp_mgmt_vrf:
        report.add("management", label, Severity.APPROX, "lldp-mgmt",
                   f"the VRF of the management address ({m.lldp_mgmt_vrf}) is left out; AOS-CX takes the address alone")
    return lines


def track_lines(device: Device, report: Report, plan: tracking_text.Plan, port: Callable[[str], str]) -> List[str]:
    lines: List[str] = []
    for t in device.tracks.values():
        if t.name not in plan.tracks or not t.interface:
            if t.name in plan.tracks:
                report.skip(tracking_text.KIND, tracking_text.track_label(t), "track-kind",
                            "AOS-CX tracks port links only; left out")
            continue
        lines.append(f"track {plan.tracks[t.name]} interface {port(t.interface)}")
        if t.delay_up is not None or t.delay_down is not None:
            report.add(tracking_text.KIND, tracking_text.track_label(t), Severity.APPROX, "track-delay",
                       "AOS-CX tracks without a delay; written without it")
    return lines


def sflow_vrf(device: Device, report: Report) -> str:
    """The VRF the collectors are reached in, when the source names one for the agent."""
    sf = device.sflow
    if sf is None:
        return ""
    if sf.extensions:
        report.add(monitor_text.KIND, monitor_text.SFLOW, Severity.APPROX, "sflow-extensions",
                   f"the sFlow extensions ({', '.join(sf.extensions)}) are left out: AOS-CX sends the samples without "
                   "routing and switching extensions")
    if sf.source_vrf and not any(c.vrf for c in sf.collectors):
        report.add(monitor_text.KIND, monitor_text.SFLOW, Severity.APPROX, "sflow-vrf",
                   f"the source interface's VRF {sf.source_vrf} is written as the VRF of the collectors")
        return sf.source_vrf
    return ""


def unwritable(device: Device, report: Report) -> None:
    for s in device.mirror_sessions:
        if s.acl:
            report.add(monitor_text.KIND, f"mirror session {s.name}", Severity.REVIEW, "mirror-acl",
                       f"the ACL filter {s.acl} is left out, so the session copies all traffic of its sources: on "
                       "AOS-CX, mirror selected traffic with a classifier policy whose entries have 'action mirror "
                       "N', applied on the source ports")
    if device.twamp_port is not None or device.twamp_mode:
        report.item(monitor_text.KIND, "TWAMP reflector")
        report.skip(monitor_text.KIND, "TWAMP reflector", "twamp",
                    "AOS-CX has no TWAMP reflector; measure with an IP SLA responder or on a router")


# reading ------------------------------------------------------------------------------------------------------------

def read_lldp(device: Device, w: List[str], holdtime: Dict[str, int]) -> bool:
    m = device.management
    if w[:2] == ["lldp", "timer"] and len(w) == 3:
        m.lldp_timer = int(w[2])
    elif w[:2] == ["lldp", "holdtime-multiplier"] and len(w) == 3:
        holdtime["multiplier"] = int(w[2])
    elif w[:2] == ["lldp", "management-ipv4-address"] and len(w) == 3:
        holdtime["address"] = int(ipaddress.IPv4Address(w[2]))
    else:
        return False
    return True


def finish_lldp(device: Device, holdtime: Dict[str, int]) -> None:
    m = device.management
    if "multiplier" in holdtime:
        m.lldp_holdtime = holdtime["multiplier"] * (m.lldp_timer or DEFAULT_TIMER)
    if "address" in holdtime:
        address = str(ipaddress.IPv4Address(holdtime["address"]))
        for iface in device.interfaces.values():
            if any(a.split("/")[0] == address for a in iface.ipv4):
                m.lldp_mgmt_interface = iface.name
                break


def read_track(device: Device, w: List[str], canonical: Callable[[str], str], line: int, text: str) -> bool:
    """track N interface P."""
    if len(w) >= 4 and w[2] == "interface" and w[1].isdigit():
        t = tracking_text.track(device, w[1], line, text)
        t.interface = canonical(" ".join(w[3:]))
        return True
    return False


def vrrp_track(tracks: Dict[str, int], w: List[str]) -> Optional[bool]:
    if w[0] == "track" and len(w) == 2 and w[1].isdigit():
        tracks[w[1]] = tracking_text.DEFAULT_DECREMENT
        return True
    return None
