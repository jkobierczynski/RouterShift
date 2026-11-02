# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NX-OS PTP and EEM applets.

How the model maps to NX-OS:

* PTP is ``feature ptp`` with ``ptp source A`` (NX-OS needs the source address), ``ptp domain``, ``ptp priority1`` and
  ``ptp priority2``. A Nexus 9000 is a boundary clock unless told otherwise; gPTP is ``ptp device-type
  generalized-ptp``. A PTP port has ``ptp`` with ``ptp announce interval``, ``ptp sync interval`` and ``ptp
  delay-request minimum interval``.
* An event handler is an EEM applet: ``event manager applet NAME`` with one ``event`` (``syslog pattern``, ``cli
  match``, ``track N state up|down``, ``snmp oid``, ``timer``, ``none``) and numbered actions (``action 1.0 syslog
  priority P msg "TEXT"``, ``action 2.0 cli COMMAND``).
"""

from __future__ import annotations

import re
from typing import Callable, List, Optional

from . import automation
from . import mgmt as mgmt_text
from .model import Device, EventAction, EventHandler, Interface
from .report import Report, Severity

KIND = automation.KIND
PTP = automation.PTP
Name = Callable[[str], str]
SAVE = "copy running-config startup-config"


# PTP ----------------------------------------------------------------------------------------------------------------

def ptp_lines(device: Device, report: Report, features: set) -> List[str]:  # type: ignore[type-arg]
    p = device.ptp
    if p is None:
        return []
    features.add("ptp")
    report.item(KIND, PTP)
    lines: List[str] = []
    if p.source_ip:
        lines.append(f"ptp source {p.source_ip}")
    else:
        report.add(KIND, PTP, Severity.REVIEW, "ptp-source",
                   "NX-OS sends PTP from the address 'ptp source A' names, which the source does not give; add it")
    if p.mode == "gptp":
        lines.append("ptp device-type generalized-ptp")
    elif p.mode in ("e2etransparent", "p2ptransparent"):
        report.add(KIND, PTP, Severity.REVIEW, "ptp-mode",
                   f"PTP mode {p.mode}: a Nexus 9000 is a boundary clock; check whether the model can be a transparent "
                   "clock and set it by hand")
    lines += [f"ptp {word} {value}" for word, value in
              (("domain", p.domain), ("priority1", p.priority1), ("priority2", p.priority2)) if value is not None]
    left = [w for w, v in (("the clock identity", p.clock_identity),
                           ("the message DSCP values", p.dscp_general is not None or p.dscp_event is not None)) if v]
    if left:
        report.add(KIND, PTP, Severity.APPROX, "ptp-options",
                   f"{', '.join(left)}: NX-OS takes these from the switch itself; left out")
    mechanisms = {i.ptp_delay_mechanism for i in device.interfaces.values() if i.ptp and i.ptp_delay_mechanism}
    if "p2p" in mechanisms and p.mode != "gptp":
        report.add(KIND, PTP, Severity.APPROX, "ptp-mechanism",
                   "a Nexus 9000 boundary clock measures delay end to end (delay request); the peer delay mechanism "
                   "of the source is left out")
    report.add(KIND, PTP, Severity.REVIEW, "ptp-platform",
               "PTP runs on some Nexus 9000 models and line cards only; check the target supports it")
    return lines + (["!"] if lines else [])


def ptp_interface(iface: Interface, add: Callable[[Severity, str, str], None]) -> List[str]:
    lines: List[str] = []
    if iface.ptp:
        lines.append("ptp")
    for word, value in (("announce interval", iface.ptp_announce_interval), ("sync interval", iface.ptp_sync_interval),
                        ("delay-request minimum interval", iface.ptp_delay_req_interval)):
        if value is not None and iface.ptp:
            lines.append(f"ptp {word} {value}")
    if iface.ptp and iface.ptp_transport and iface.ptp_transport != "ipv4":
        add(Severity.APPROX, "ptp-transport", f"PTP over {iface.ptp_transport} is written as PTP over IPv4, the "
                                              "Nexus 9000 default")
    return lines


def read_global(device: Device, w: List[str]) -> bool:
    """ptp source A [vrf V] | domain N | priority1 N | priority2 N | device-type generalized-ptp|boundary-clock."""
    p = automation.ptp(device)
    n = len(w)
    if w[1] == "source" and n in (3, 5) and w[3:4] in ([], ["vrf"]):
        p.source_ip = w[2]
    elif w[1] in ("domain", "priority1", "priority2") and n == 3 and w[2].isdigit():
        setattr(p, w[1], int(w[2]))
    elif w[1] == "device-type" and n == 3 and w[2] in ("generalized-ptp", "boundary-clock"):
        p.mode = "gptp" if w[2] == "generalized-ptp" else "boundary"
    else:
        return False
    if not p.mode:
        p.mode = "boundary"
    return True


def read_interface(iface: Interface, w: List[str]) -> bool:
    """ptp | ptp announce interval N | ptp sync interval N | ptp delay-request minimum interval N."""
    n = len(w)
    if w == ["ptp"]:
        iface.ptp = True
    elif w[1:3] == ["announce", "interval"] and n == 4:
        iface.ptp_announce_interval = int(w[3])
    elif w[1:3] == ["sync", "interval"] and n == 4:
        iface.ptp_sync_interval = int(w[3])
    elif w[1:4] == ["delay-request", "minimum", "interval"] and n == 5:
        iface.ptp_delay_req_interval = int(w[4])
    else:
        return False
    return True


# EEM ----------------------------------------------------------------------------------------------------------------

def eem_lines(device: Device, report: Report, port: Name, ind: str) -> List[str]:
    lines: List[str] = []
    for h in device.event_handlers.values():
        name = automation.label(h)
        report.item(KIND, name)
        event = _event(device, h, port, report, name)
        if not event:
            report.skip(KIND, name, "event-trigger",
                        f"NX-OS EEM has no form RouterShift writes for the '{h.trigger}' trigger"
                        + (f" ({h.pattern})" if h.pattern else "") + "; left out")
            continue
        actions: List[str] = []
        if h.delay:
            report.add(KIND, name, Severity.APPROX, "event-delay",
                       f"the delay of {h.delay} seconds before the actions is left out: NX-OS EEM runs them at once")
        for a in h.actions:
            if a.kind == "syslog":
                level = f"priority {mgmt_text.LEVELS[a.level]} " if a.level is not None else ""
                actions.append(f'syslog {level}msg "{a.text}"')
            elif a.kind == "cli":
                actions.append(f"cli {a.text}")
            else:
                report.add(KIND, name, Severity.REVIEW, "event-script",
                           f"the shell command '{a.text}' has no EEM action (run it from the bash shell or a Python "
                           "script by hand); left out")
        if not actions:
            report.skip(KIND, name, "event-actions", "no action NX-OS EEM can run; left out")
            continue
        if device.platform != "nxos":
            report.add(KIND, name, Severity.REVIEW, "event-handler",
                       "written as an EEM applet: logger calls become syslog actions, CLI calls cli actions; check the "
                       "event fires as meant")
        lines.append(f"event manager applet {h.name}")
        if h.description:
            lines.append(f'{ind}description "{h.description.strip(chr(34))}"')
        lines.append(f"{ind}{event}")
        lines += [f"{ind}action {n}.0 {a}" for n, a in enumerate(actions, 1)]
    return lines


def _event(device: Device, h: EventHandler, port: Name, report: Report, name: str) -> str:
    if h.trigger == "startup-config":
        return f'event cli match "{SAVE}"'
    if h.trigger == "interface":
        report.add(KIND, name, Severity.APPROX, "event-interface",
                   "the interface change is caught by the NX-OS syslog message for it")
        return f'event syslog pattern "Interface {port(h.interface)} is (up|down)"'
    if h.trigger == "logging":
        return f'event syslog pattern "{h.pattern}"'
    if h.trigger == "cpu":
        op, value = h.pattern.split()
        return (f"event snmp oid {automation.CPU_OID} get-type exact entry-op {'gt' if op == '>' else 'ge'} "
                f"entry-val {value} poll-interval {h.poll_interval or 60}")
    if h.trigger == "track":
        return f"event track {h.track} state {h.pattern}"
    if h.trigger == "none":
        return "event none"
    if h.trigger == "cli" and h.pattern:
        return f'event cli match "{h.pattern}"'
    if h.trigger == "snmp" and h.pattern:
        return f"event snmp oid {h.pattern}"
    if h.trigger == "timer" and h.pattern:
        if device.platform != "nxos":
            report.add(KIND, name, Severity.REVIEW, "event-timer",
                       "the timer is written as the source has it; NX-OS timers also take a name (event timer "
                       "watchdog time N name X): check it")
        return f"event timer {h.pattern}"
    return ""


def read_event(h: EventHandler, w: List[str], canonical: Name) -> bool:
    """The NX-OS forms the IOS reader does not take: event cli match P, the interface syslog pattern."""
    if w[1:3] == ["cli", "match"] and len(w) == 4:
        h.trigger, h.pattern = ("startup-config" if w[3] == SAVE else "cli"), ("" if w[3] == SAVE else w[3])
        return True
    if w[1:3] == ["syslog", "pattern"] and len(w) == 4:
        m = re.fullmatch(r"Interface (\S+) is \(up\|down\)", w[3])
        if m:
            h.trigger, h.interface = "interface", canonical(m.group(1))
            return True
    return False


def read_action(h: EventHandler, w: List[str]) -> Optional[bool]:
    """action L cli COMMAND... (NX-OS, without 'command'); None when it is not that form."""
    if len(w) >= 4 and w[2] == "cli" and w[3] != "command":
        h.actions.append(EventAction("cli", " ".join(w[3:])))
        return True
    return None
