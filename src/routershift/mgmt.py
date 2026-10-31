# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Management access helpers that every reader and writer shares: syslog severities and what a target reports."""

from __future__ import annotations

from typing import Optional

from .model import Device
from .report import Report, Severity

# Syslog severities by number, with the names each platform family uses
LEVELS = ["emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging"]
COMWARE = ["emergency", "alert", "critical", "error", "warning", "notification", "informational", "debugging"]
SHORT = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
# AOS-S has five severities; each number maps to the nearest one that sends at least as much
AOSS = {0: "major", 1: "major", 2: "major", 3: "error", 4: "warning", 5: "info", 6: "info", 7: "debug"}
_AOSS_READ = {"major": 2, "error": 3, "warning": 4, "info": 6, "debug": 7}


def level(word: str) -> Optional[int]:
    """A severity from its number, long name (informational) or short name (info); None when unknown."""
    word = word.lower()
    if word.isdigit() and int(word) <= 7:
        return int(word)
    for names in (LEVELS, SHORT, COMWARE):
        if word in names:
            return names.index(word)
    return _AOSS_READ.get(word)


def aoss_level(value: int, report: Report) -> str:
    name = AOSS[value]
    if level(name) != value:
        report.add("system", "syslog level", Severity.APPROX, "syslog-level",
                   f"AOS-S has no level {LEVELS[value]}; {name} is written")
    return name


def has_lines(device: Device) -> bool:
    m = device.management
    return m.ssh is not None or m.telnet is not None or bool(m.vty_acl) or m.exec_timeout is not None


def transport(device: Device) -> str:
    """The IOS 'transport input' value for what the source allows."""
    m = device.management
    allowed = [name for name, on in (("ssh", m.ssh), ("telnet", m.telnet)) if on]
    return " ".join(allowed) if allowed else "none"


def items(device: Device, report: Report) -> None:
    """The report entries every writer makes; findings are added by the writer."""
    m = device.management
    for name, value in (("ssh server", m.ssh), ("telnet server", m.telnet), ("http server", m.http),
                        ("https server", m.https), ("LLDP", m.lldp), ("CDP", m.cdp)):
        if value is not None:
            report.item("management", name)
    if m.vty_acl:
        report.item("management", "remote login ACL")
    if m.exec_timeout is not None:
        report.item("management", "session idle timeout")


def no_server(report: Report, name: str, platform: str, enabled: Optional[bool]) -> None:
    if enabled:
        report.add("management", name, Severity.REVIEW, "mgmt-unsupported", f"{platform} has no {name}; left out")


