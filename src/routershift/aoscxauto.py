# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AOS-CX PTP and event handlers.

How the model maps to AOS-CX:

* PTP is the IEEE 1588v2 profile (``ptp profile 1588v2``) with its clock mode, domain and priorities; a PTP port has
  ``ptp enable`` and its message intervals. PTP runs on some AOS-CX switches only, so the writer says so.
* AOS-CX has no CLI event handlers: it automates with NAE agents (Python scripts), so each handler is reported with
  what it does.
"""

from __future__ import annotations

from typing import List, Optional

from . import automation
from .model import Device, Interface
from .report import Report, Severity

KIND = automation.KIND
PTP = automation.PTP
PROFILE = "1588v2"
MODES = {"boundary": "boundary", "e2etransparent": "transparent-e2e", "p2ptransparent": "transparent-p2p"}
_FROM_MODE = {v: k for k, v in MODES.items()}
TRANSPORTS = {"ipv4": "ipv4", "ipv6": "ipv6", "layer2": "ethernet"}
_FROM_TRANSPORT = {v: k for k, v in TRANSPORTS.items()}


def ptp_lines(device: Device, report: Report, ind: str) -> List[str]:
    p = device.ptp
    if p is None:
        return []
    report.item(KIND, PTP)
    lines = [f"ptp profile {PROFILE}"]
    if p.mode in MODES:
        lines.append(f"{ind}mode {MODES[p.mode]}")
    elif p.mode and p.mode != "disabled":
        report.add(KIND, PTP, Severity.REVIEW, "ptp-mode",
                   f"PTP mode {p.mode} has no AOS-CX form written by RouterShift; left out")
    for word, value in (("clock-domain", p.domain), ("priority1", p.priority1), ("priority2", p.priority2)):
        if value is not None:
            lines.append(f"{ind}{word} {value}")
    transports = {i.ptp_transport for i in device.interfaces.values() if i.ptp and i.ptp_transport}
    if len(transports) == 1:
        lines.append(f"{ind}transport-protocol {TRANSPORTS[transports.pop()]}")
    elif transports:
        report.add(KIND, PTP, Severity.APPROX, "ptp-transport",
                   "AOS-CX sets one transport for the profile; the ports use " + ", ".join(sorted(transports))
                   + ": the default is written")
    if any(i.ptp_delay_mechanism == "p2p" for i in device.interfaces.values() if i.ptp):
        lines.append(f"{ind}delay-mechanism peer-to-peer")
    lines.append(f"{ind}{'disable' if p.mode == 'disabled' else 'enable'}")
    left = [w for w, v in (("the clock identity", p.clock_identity), ("the source address", p.source_ip),
                           ("the message DSCP values", p.dscp_general is not None or p.dscp_event is not None)) if v]
    if left:
        report.add(KIND, PTP, Severity.APPROX, "ptp-options",
                   f"{', '.join(left)}: AOS-CX takes these from the switch and the port; left out")
    report.add(KIND, PTP, Severity.REVIEW, "ptp-platform",
               "PTP runs on some AOS-CX switches and releases only; check the target supports it and these commands")
    return lines


def ptp_interface(iface: Interface) -> List[str]:
    if not iface.ptp:
        return []
    lines = ["ptp enable"]
    for word, value in (("announce-interval", iface.ptp_announce_interval),
                        ("sync-interval", iface.ptp_sync_interval),
                        ("delay-request-interval", iface.ptp_delay_req_interval)):
        if value is not None:
            lines.append(f"ptp {word} {value}")
    return lines


def events(device: Device, report: Report) -> None:
    for h in device.event_handlers.values():
        name = automation.label(h)
        report.item(KIND, name)
        actions = "; ".join(a.text for a in h.actions) or "nothing"
        report.skip(KIND, name, "event-handler",
                    f"AOS-CX has no CLI event handlers; it automates with NAE agents (Python scripts): write one that "
                    f"runs on the '{h.trigger}' trigger and does: {actions}")


# reading ------------------------------------------------------------------------------------------------------------

class PtpReader:
    def __init__(self, device: Device) -> None:
        self.device = device
        self.transport = ""
        self.p2p = False

    def profile(self, children: List[List[str]]) -> List[int]:
        p = automation.ptp(self.device)
        bad = []
        for n, w in enumerate(children):
            if w[0] == "mode" and len(w) == 2 and w[1] in _FROM_MODE:
                p.mode = _FROM_MODE[w[1]]
            elif w[0] in ("clock-domain", "priority1", "priority2") and len(w) == 2:
                setattr(p, "domain" if w[0] == "clock-domain" else w[0], int(w[1]))
            elif w[0] == "transport-protocol" and len(w) == 2 and w[1] in _FROM_TRANSPORT:
                self.transport = _FROM_TRANSPORT[w[1]]
            elif w == ["delay-mechanism", "peer-to-peer"]:
                self.p2p = True
            elif w == ["enable"]:
                pass
            elif w == ["disable"]:
                p.mode = "disabled"
            else:
                bad.append(n)
        return bad

    @staticmethod
    def interface_line(iface: Interface, w: List[str]) -> Optional[bool]:
        if w == ["ptp", "enable"]:
            iface.ptp = True
        elif w[0] == "ptp" and len(w) == 3 and w[1] in ("announce-interval", "sync-interval",
                                                         "delay-request-interval"):
            attr = {"announce-interval": "ptp_announce_interval", "sync-interval": "ptp_sync_interval",
                    "delay-request-interval": "ptp_delay_req_interval"}[w[1]]
            setattr(iface, attr, int(w[2]))
        else:
            return None
        return True

    def finish(self) -> None:
        for iface in self.device.interfaces.values():
            if iface.ptp:
                if self.transport:
                    iface.ptp_transport = self.transport
                if self.p2p:
                    iface.ptp_delay_mechanism = "p2p"
