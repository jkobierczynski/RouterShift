# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Junos PTP and event policies.

How the model maps to Junos:

* PTP is ``protocols ptp``: the boundary clock is ``clock-mode boundary``, an end-to-end transparent clock
  ``e2e-transparent``; the domain and priorities keep their names. Each PTP port is a ``master interface`` unit, as
  Junos names a port's role where EOS and IOS let the best master clock algorithm choose it.
* An event handler is an event policy (``event-options policy``): saving the configuration is a commit
  (``ui_commit_completed``), a port changing state the link-down trap of that port, a timer a generated event. Its
  actions are operational commands (``then execute-commands commands``); a shell command or syslog message runs
  through ``start shell sh command``.
"""

from __future__ import annotations

import re
import shlex
from typing import Callable, Dict, List, Optional, Tuple

from . import automation
from . import mgmt as mgmt_text
from .junostext import quote
from .model import Device, EventAction, EventHandler, Interface
from .report import Report, Severity

KIND = automation.KIND
PTP = automation.PTP
COMMIT = "ui_commit_completed"
LINK_DOWN = "snmp_trap_link_down"
SHELL = "start shell sh command "
MODES = {"boundary": ("clock-mode", "boundary"), "e2etransparent": ("e2e-transparent",)}
TRANSPORTS = {"ipv4": "ipv4", "ipv6": "ipv6", "layer2": "ieee-802.3"}
WATCHDOG = re.compile(r"watchdog time (\d+)")

Add = Callable[..., None]


# writing ------------------------------------------------------------------------------------------------------------

def write_ptp(device: Device, add: Add, report: Report, unit: Callable[[str], str]) -> None:
    p = device.ptp
    if p is None:
        return
    report.item(KIND, PTP)
    base = ("protocols", "ptp")
    if p.mode in MODES:
        add(*base, " ".join(MODES[p.mode]))
    elif p.mode and p.mode != "disabled":
        report.add(KIND, PTP, Severity.REVIEW, "ptp-mode",
                   f"PTP mode {p.mode} has no Junos form written by RouterShift; left out")
    for word, value in (("domain", p.domain), ("priority1", p.priority1), ("priority2", p.priority2)):
        if value is not None:
            add(*base, f"{word} {value}")
    not_written = [w for w, v in (("the clock identity", p.clock_identity), ("the source address", p.source_ip),
                                  ("the message DSCP values", p.dscp_general is not None
                                   or p.dscp_event is not None)) if v]
    if not_written:
        report.add(KIND, PTP, Severity.APPROX, "ptp-options",
                   f"{', '.join(not_written)}: Junos takes these from the switch and the port; left out")
    ports = [i for i in device.interfaces.values() if i.ptp]
    for iface in ports:
        path = base + ("master", f"interface {unit(iface.name)}")
        transport = TRANSPORTS.get(iface.ptp_transport or "ipv4", "ipv4")
        add(*path, "multicast-mode", f"transport {transport}")
        if iface.ptp_announce_interval is not None:
            add(*path, f"announce-interval {iface.ptp_announce_interval}")
        if iface.ptp_sync_interval is not None:
            add(*path, f"sync-interval {iface.ptp_sync_interval}")
        if iface.ptp_delay_req_interval is not None:
            report.add(KIND, PTP, Severity.APPROX, "ptp-delay-req",
                       f"{iface.name}: the delay request interval is set on the slave side in Junos; left out")
        if iface.ptp_delay_mechanism == "p2p":
            report.add(KIND, PTP, Severity.APPROX, "ptp-p2p",
                       f"{iface.name}: peer-to-peer delay is not written; Junos uses end-to-end delay here")
    if ports:
        report.add(KIND, PTP, Severity.APPROX, "ptp-roles",
                   "Junos names each port's role: the PTP ports are written as master interfaces; make the port "
                   "facing the grandmaster a slave interface (with its clock-source)")
    report.add(KIND, PTP, Severity.REVIEW, "ptp-platform",
               "written in the QFX syntax; PTP depends on the platform and licence, check the target supports it")


def _shell(command: str) -> str:
    return SHELL + quote(command)


def write_events(device: Device, add: Add, report: Report, port: Callable[[str], str]) -> None:
    for h in device.event_handlers.values():
        name = automation.label(h)
        report.item(KIND, name)
        path = ("event-options", f"policy {h.name}")
        trigger: List[Tuple[str, ...]] = []
        generated: Optional[int] = None
        interface = ""
        if h.trigger == "startup-config":
            trigger = [("events", COMMIT)]
            report.add(KIND, name, Severity.APPROX, "event-commit",
                       "Junos has no separate save: the policy runs after every commit")
        elif h.trigger == "interface":
            interface = h.interface
        elif h.trigger == "track":
            t = device.tracks.get(h.track)
            if t is not None and t.interface:
                interface = t.interface
                report.add(KIND, name, Severity.APPROX, "event-track",
                           f"track {h.track} follows {t.interface}: written as that port's link-down event")
        elif h.trigger == "timer" and WATCHDOG.fullmatch(h.pattern):
            generated = int(WATCHDOG.fullmatch(h.pattern).group(1))  # type: ignore[union-attr]
            trigger = [("events", h.name.lower())]
        if interface:
            physical = port(interface).split(".")[0]
            trigger = [("events", LINK_DOWN),
                       ("attributes-match", f"{LINK_DOWN}.interface-name matches {quote('^' + physical + '$')}")]
            if h.trigger == "interface":
                report.add(KIND, name, Severity.APPROX, "event-link",
                           "written for the link going down: EOS and IOS also run the actions when it comes up")
        if not trigger:
            hint = {"cpu": " (an RMON alarm on the CPU load is the nearest Junos form)",
                    "logging": " (Junos policies match event IDs, not message text)"}.get(h.trigger, "")
            report.skip(KIND, name, "event-trigger",
                        f"Junos event policies have no form of the '{h.trigger}' trigger{hint}; left out")
            continue
        commands: List[str] = []
        for a in h.actions:
            if a.kind == "syslog":
                level = mgmt_text.SHORT[a.level if a.level is not None else 5]
                commands.append(_shell(f"logger -p local0.{level} {shlex.quote(a.text)}"))
            elif a.kind == "script":
                commands.append(_shell(a.text))
            else:
                commands.append(a.text)
        if not commands:
            report.skip(KIND, name, "event-actions", "no action left to write; left out")
            continue
        if generated is not None:
            add("event-options", f"generate-event {h.name.lower()}", f"time-interval {max(generated, 60)}")
            report.add(KIND, name, Severity.APPROX, "event-timer",
                       f"the timer is a generated event every {max(generated, 60)} seconds (60 at least)")
        for words in trigger:
            add(*path, " ".join(words))
        for c in commands:
            add(*path, "then", "execute-commands", f"commands {quote(c)}")
        report.add(KIND, name, Severity.REVIEW, "event-handler",
                   "written as a Junos event policy: CLI commands run as operational commands, shell commands and "
                   "syslog messages through 'start shell sh command'; check each command on Junos")
        if h.delay:
            report.add(KIND, name, Severity.APPROX, "event-delay",
                       f"Junos event policies run at once: the {h.delay} second delay is left out")
        if h.description:
            report.add(KIND, name, Severity.APPROX, "event-description",
                       f"Junos event policies have no description ('{h.description}'); left out")


# reading ------------------------------------------------------------------------------------------------------------

class AutoReader:
    def __init__(self, device: Device) -> None:
        self.device = device
        self.ptp_ports: Dict[str, Dict[str, str]] = {}  # unit -> settings
        self.events: Dict[str, List[str]] = {}  # policy -> events
        self.matches: Dict[str, str] = {}  # policy -> the interface its attributes-match names
        self.commands: Dict[str, List[str]] = {}
        self.generated: Dict[str, int] = {}

    def ptp(self, w: List[str]) -> bool:
        p = automation.ptp(self.device)
        if w == ["clock-mode", "boundary"]:
            p.mode = "boundary"
        elif w == ["e2e-transparent"]:
            p.mode = "e2etransparent"
        elif w[0] in ("domain", "priority1", "priority2") and len(w) == 2:
            setattr(p, w[0], int(w[1]))
        elif w[:2] == ["master", "interface"] and len(w) >= 4:
            settings = self.ptp_ports.setdefault(w[2], {})
            rest = w[3:]
            if rest[:2] == ["multicast-mode", "transport"] and len(rest) == 3 and rest[2] in TRANSPORTS.values():
                settings["transport"] = rest[2]
            elif rest[0] in ("announce-interval", "sync-interval") and len(rest) == 2:
                settings[rest[0]] = str(int(rest[1]))
            else:
                return False
        else:
            return False
        return True

    def event_options(self, w: List[str]) -> bool:
        if w[0] == "generate-event" and len(w) == 4 and w[2] == "time-interval":
            self.generated[w[1]] = int(w[3])
            return True
        if w[0] != "policy" or len(w) < 4:
            return False
        name, rest = w[1], w[2:]
        if rest[0] == "events" and len(rest) == 2:
            self.events.setdefault(name, []).append(rest[1])
        elif rest[0] == "attributes-match" and len(rest) == 4 and rest[1] == f"{LINK_DOWN}.interface-name" and \
                rest[2] == "matches":
            self.matches[name] = rest[3].strip("^$")
        elif rest[:3] == ["then", "execute-commands", "commands"] and len(rest) == 4:
            self.commands.setdefault(name, []).append(rest[3])
        else:
            return False
        return True

    def finish(self, canonical: Callable[[str], Optional[Interface]],
               unread: Callable[[int, str, str], None]) -> None:
        dev = self.device
        for unit, settings in self.ptp_ports.items():
            iface = canonical(unit)
            if iface is None:
                unread(0, f"set protocols ptp master interface {unit}", "no such interface")
                continue
            iface.ptp = True
            if "transport" in settings:
                iface.ptp_transport = {v: k for k, v in TRANSPORTS.items()}[settings["transport"]]
            if "announce-interval" in settings:
                iface.ptp_announce_interval = int(settings["announce-interval"])
            if "sync-interval" in settings:
                iface.ptp_sync_interval = int(settings["sync-interval"])
        for name, events in self.events.items():
            h = automation.handler(dev, name)
            if events == [COMMIT]:
                h.trigger = "startup-config"
            elif events == [LINK_DOWN] and name in self.matches:
                iface = canonical(self.matches[name])
                if iface is None:
                    unread(0, f"set event-options policy {name} attributes-match {LINK_DOWN}.interface-name "
                           f"matches {self.matches[name]}", "no such interface")
                    del dev.event_handlers[name]
                    continue
                h.trigger, h.interface = "interface", iface.name
            elif len(events) == 1 and events[0] in self.generated:
                h.trigger, h.pattern = "timer", f"watchdog time {self.generated.pop(events[0])}"
            else:
                for e in events:
                    unread(0, f"set event-options policy {name} events {e}",
                           "an event RouterShift does not convert")
                del dev.event_handlers[name]
                continue
            for c in self.commands.get(name, []):
                if c.startswith(SHELL):
                    words = automation.split(c[len(SHELL):])
                    h.actions.append(automation.eos_action(words[0] if len(words) == 1 else c[len(SHELL):]))
                else:
                    h.actions.append(EventAction("cli", c))
        for event, interval in self.generated.items():
            unread(0, f"set event-options generate-event {event} time-interval {interval}",
                   "a generated event no policy uses")
