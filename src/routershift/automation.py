# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""PTP and event handlers (EOS event-handler, IOS EEM applets) for the IOS and EOS reader and writer."""

from __future__ import annotations

import re
import shlex
from typing import List, Optional

from . import mgmt as mgmt_text
from .model import Device, EventAction, EventHandler, Interface, Ptp
from .report import Report, Severity

KIND = "system"
PTP = "PTP"
CPU_OID = "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1"  # CISCO-PROCESS-MIB cpmCPUTotal5secRev of the first CPU
SAVE_PATTERN = "^(write( memory)?|copy running-config startup-config)"
IOS_MODES = {"boundary": "boundary", "e2etransparent": "e2etransparent", "p2ptransparent": "p2ptransparent"}


def label(h: EventHandler) -> str:
    return f"event handler {h.name}"


# PTP ------------------------------------------------------------------------------------------------------------------

def ptp(device: Device) -> Ptp:
    if device.ptp is None:
        device.ptp = Ptp()
    return device.ptp


def global_line(device: Device, w: List[str], eos: bool) -> Optional[str]:
    """ptp ... on either platform. Returns None when not understood, else the IOS delay mechanism it names ("" when
    none)."""
    p = ptp(device)
    n = len(w)
    if w[1] == "mode" and n >= 3:
        if w[2] == "boundary" and not eos and n == 4 and w[3] in ("delay-req", "pdelay-req"):
            p.mode = "boundary"
            return "e2e" if w[3] == "delay-req" else "p2p"
        if n == 3 and (w[2] in ("boundary", "e2etransparent", "p2ptransparent", "gptp", "disabled") if eos
                       else w[2] in ("e2etransparent", "p2ptransparent")):
            p.mode = w[2]
            return ""
        return None
    if w[1:] == ["profile", "dot1as"] and not eos:
        p.mode = "gptp"
        return ""
    if w[1] in ("domain", "priority1", "priority2") and n == 3 and w[2].isdigit():
        setattr(p, w[1], int(w[2]))
        return ""
    if eos and w[1] == "clock-identity" and n == 3:
        p.clock_identity = w[2]
        return ""
    if eos and w[1:3] == ["source", "ip"] and n == 4:
        p.source_ip = w[3]
        return ""
    if eos and w[1] == "message-type" and n in (5, 6) and w[2] in ("general", "event") and w[3] == "dscp" and \
            w[4].isdigit() and w[5:] in ([], ["default"]):
        setattr(p, f"dscp_{w[2]}", int(w[4]))
        return ""
    return None


def port_line(iface: Interface, w: List[str]) -> bool:
    """Interface ptp lines of both platforms (EOS sync-message, IOS sync)."""
    n = len(w)
    if w in (["ptp", "enable"], ["no", "ptp", "enable"]):
        iface.ptp = w[0] != "no"
    elif w[1:2] == ["announce"] and w[2:3] == ["interval"] and n == 4:
        iface.ptp_announce_interval = int(w[3])
    elif w[1:2] in (["sync-message"], ["sync"]) and w[2:3] == ["interval"] and n == 4:
        iface.ptp_sync_interval = int(w[3])
    elif w[1:2] == ["delay-req"] and w[2:3] == ["interval"] and n == 4:
        iface.ptp_delay_req_interval = int(w[3])
    elif w[1:2] == ["delay-mechanism"] and n == 3 and w[2] in ("e2e", "p2p"):
        iface.ptp_delay_mechanism = w[2]
    elif w[1:2] == ["transport"] and n == 3 and w[2] in ("ipv4", "ipv6", "layer2"):
        iface.ptp_transport = w[2]
    else:
        return False
    return True


def ptp_lines(device: Device, report: Report, ios: bool) -> List[str]:
    p = device.ptp
    if p is None:
        return []
    report.item(KIND, PTP)
    lines: List[str] = []
    if ios:
        mechanisms = {i.ptp_delay_mechanism for i in device.interfaces.values() if i.ptp and i.ptp_delay_mechanism}
        if p.mode == "boundary":
            lines.append(f"ptp mode boundary {'pdelay-req' if mechanisms == {'p2p'} else 'delay-req'}")
            if len(mechanisms) > 1:
                report.add(KIND, PTP, Severity.REVIEW, "ptp-mechanism",
                           "the ports mix delay mechanisms; IOS sets one for the switch: delay-req (e2e) written")
        elif p.mode in IOS_MODES:
            lines.append(f"ptp mode {IOS_MODES[p.mode]}")
        elif p.mode == "gptp":
            lines.append("ptp profile dot1as")
        elif p.mode and p.mode != "disabled":
            report.add(KIND, PTP, Severity.REVIEW, "ptp-mode", f"PTP mode {p.mode} has no IOS form; left out")
        report.add(KIND, PTP, Severity.REVIEW, "ptp-platform",
                   "written in the Catalyst 9000 syntax; PTP depends on the platform and licence, check the target "
                   "supports this mode")
        not_written = [w for w, v in (("the clock identity", p.clock_identity), ("the source address", p.source_ip),
                                      ("the message DSCP values", p.dscp_general is not None
                                       or p.dscp_event is not None)) if v]
        if not_written:
            report.add(KIND, PTP, Severity.APPROX, "ptp-options",
                       f"{', '.join(not_written)}: IOS takes these from the switch itself; left out")
    else:
        if p.mode:
            lines.append(f"ptp mode {p.mode}")
        if p.clock_identity:
            lines.append(f"ptp clock-identity {p.clock_identity}")
        if p.source_ip:
            lines.append(f"ptp source ip {p.source_ip}")
        lines += [f"ptp message-type {kind} dscp {value} default" for kind, value in
                  (("general", p.dscp_general), ("event", p.dscp_event)) if value is not None]
    lines += [f"ptp {word} {value}" for word, value in
              (("priority1", p.priority1), ("priority2", p.priority2), ("domain", p.domain)) if value is not None]
    return lines + (["!"] if lines else [])


def ptp_port_lines(iface: Interface, ios: bool) -> List[str]:
    lines: List[str] = []
    if iface.ptp is not None:
        lines.append("ptp enable" if iface.ptp else "no ptp enable")
    for word, value in (("announce interval", iface.ptp_announce_interval),
                        ("sync interval" if ios else "sync-message interval", iface.ptp_sync_interval),
                        ("delay-req interval", iface.ptp_delay_req_interval)):
        if value is not None:
            lines.append(f"ptp {word} {value}")
    if not ios:
        lines += [f"ptp delay-mechanism {iface.ptp_delay_mechanism}"] if iface.ptp_delay_mechanism else []
        lines += [f"ptp transport {iface.ptp_transport}"] if iface.ptp_transport else []
    return lines


# event handlers: EOS ----------------------------------------------------------------------------------------------

def split(text: str) -> List[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def eos_action(command: str) -> EventAction:
    """A bash command line as the action it stands for: logger is a syslog message, FastCli a CLI command."""
    w = split(command)
    if w[:2] == ["logger", "-p"] and len(w) == 4 and "." in w[2]:
        return EventAction("syslog", w[3], mgmt_text.level(w[2].split(".", 1)[1]))
    if w[:1] == ["FastCli"] and "-c" in w and w.index("-c") == len(w) - 2:
        return EventAction("cli", w[-1])
    return EventAction("script", command)


def eos_trigger(h: EventHandler, words: List[str], children: List[List[str]], canonical) -> bool:  # type: ignore[no-untyped-def]
    """trigger on-startup-config | on-boot | on-intf IF operstatus | on-logging / regex R | on-counters / poll
    interval N, condition cpu.utilization > N."""
    kind = words[1] if len(words) >= 2 else ""
    if kind == "on-startup-config" and len(words) == 2:
        h.trigger = "startup-config"
    elif kind == "on-boot" and len(words) == 2:
        h.trigger = "boot"
    elif kind == "on-intf" and len(words) == 4 and words[3] == "operstatus":
        h.trigger, h.interface = "interface", canonical(words[2])
    elif kind == "on-logging" and len(words) == 2 and len(children) == 1 and children[0][0] == "regex":
        h.trigger, h.pattern = "logging", " ".join(children[0][1:])
        return True
    elif kind == "on-counters" and len(words) == 2:
        h.trigger = "counters"
        for c in children:
            if c[:2] == ["poll", "interval"] and len(c) == 3 and c[2].isdigit():
                h.poll_interval = int(c[2])
            elif c[0] == "condition":
                h.pattern = " ".join(c[1:])
            else:
                return False
        m = re.fullmatch(r"cpu\.utilization\s*(>=|>)\s*(\d+)", h.pattern)
        if m:
            h.trigger, h.pattern = "cpu", f"{m.group(1)} {m.group(2)}"
        return True
    else:
        return False
    return not children


def eos_lines(device: Device, report: Report, ind: str, port) -> List[str]:  # type: ignore[no-untyped-def]
    lines: List[str] = []
    for h in device.event_handlers.values():
        name = label(h)
        report.item(KIND, name)
        trigger: List[str] = []
        if h.trigger == "startup-config":
            trigger = ["trigger on-startup-config"]
        elif h.trigger == "boot":
            trigger = ["trigger on-boot"]
        elif h.trigger == "interface":
            trigger = [f"trigger on-intf {port(h.interface)} operstatus"]
        elif h.trigger == "logging":
            trigger = ["trigger on-logging", f"{ind * 2}regex {h.pattern}"]
        elif h.trigger == "cpu":
            trigger = ["trigger on-counters"] + ([f"{ind * 2}poll interval {h.poll_interval}"] if h.poll_interval
                                                 else []) + [f"{ind * 2}condition cpu.utilization {h.pattern}"]
        elif h.trigger == "counters":
            trigger = ["trigger on-counters"] + ([f"{ind * 2}poll interval {h.poll_interval}"] if h.poll_interval
                                                 else []) + [f"{ind * 2}condition {h.pattern}"]
        elif h.trigger == "track":
            t = device.tracks.get(h.track)
            if t is not None and t.interface:
                trigger = [f"trigger on-intf {port(t.interface)} operstatus"]
                report.add(KIND, name, Severity.APPROX, "event-track",
                           f"track {h.track} follows {t.interface}: the handler runs when its state changes either "
                           f"way, not only when it goes {h.pattern}")
        if not trigger:
            report.skip(KIND, name, "event-trigger",
                        f"EOS event handlers have no '{h.trigger}' trigger"
                        + (" (a timer is the EOS 'schedule' command)" if h.trigger == "timer" else "")
                        + "; left out")
            continue
        commands: List[str] = []
        for a in h.actions:
            if a.kind == "syslog":
                level = mgmt_text.SHORT[a.level if a.level is not None else 5]
                commands.append(f"logger -p local0.{level} {shlex.quote(a.text)}")
            elif a.kind == "cli":
                commands.append(f"FastCli -p 15 -c {shlex.quote(a.text)}")
            else:
                commands.append(a.text)
        if not commands:
            report.skip(KIND, name, "event-actions", "no action left to write; left out")
            continue
        if device.platform != "eos":
            report.add(KIND, name, Severity.REVIEW, "event-handler",
                       "written as an EOS event handler: syslog messages become logger, CLI commands FastCli calls; "
                       "check each command on EOS")
            if h.description:
                report.add(KIND, name, Severity.APPROX, "event-description",
                           f"EOS event handlers have no description ('{h.description}'); left out")
        lines += [f"event-handler {h.name}", f"{ind}{trigger[0]}"] + trigger[1:]
        if len(commands) == 1:
            lines.append(f"{ind}action bash {commands[0]}")
        else:
            lines += [f"{ind}action bash"] + [f"{ind * 2}{c}" for c in commands] + [f"{ind * 2}EOF"]
        if h.delay is not None:
            lines.append(f"{ind}delay {h.delay}")
        lines.append("!")
    return lines


# event handlers: IOS EEM ------------------------------------------------------------------------------------------

def ios_event(h: EventHandler, words: List[str], canonical) -> bool:  # type: ignore[no-untyped-def]
    """event track N state up|down, event syslog pattern P, event cli pattern P sync no skip no, event snmp oid CPU
    get-type exact entry-op gt|ge entry-val N poll-interval N, event timer cron cron-entry C, event none."""
    w = words
    if w[1:2] == ["track"] and len(w) == 5 and w[3] == "state" and w[4] in ("up", "down"):
        h.trigger, h.track, h.pattern = "track", w[2], w[4]
    elif w[1:3] == ["syslog", "pattern"] and len(w) >= 4:
        pattern = w[3]
        m = re.search(r"Interface (\S+), changed state", pattern)
        if "SYS-5-RESTART" in pattern:
            h.trigger = "boot"
        elif m:
            h.trigger, h.interface = "interface", canonical(m.group(1))
        else:
            h.trigger, h.pattern = "logging", pattern
    elif w[1:3] == ["cli", "pattern"] and len(w) >= 4:
        h.trigger, h.pattern = ("startup-config" if "startup-config" in w[3] or "write" in w[3] else "cli"), w[3]
    elif w[1:3] == ["snmp", "oid"] and len(w) >= 4:
        args = dict(zip(w[4::2], w[5::2]))
        h.poll_interval = int(float(args["poll-interval"])) if "poll-interval" in args else None
        op = {"gt": ">", "ge": ">="}.get(args.get("entry-op", ""))
        if w[3] == CPU_OID and op and "entry-val" in args:
            h.trigger, h.pattern = "cpu", f"{op} {args['entry-val']}"
        else:
            h.trigger, h.pattern = "snmp", " ".join(w[3:])
    elif w[1:2] == ["timer"] and len(w) >= 3:
        h.trigger, h.pattern = "timer", " ".join(w[2:])
    elif w[1:] == ["none"]:
        h.trigger = "none"
    else:
        return False
    return True


def ios_action(h: EventHandler, words: List[str]) -> bool:
    """action L syslog [priority P] msg M | cli command C [pattern P] | wait N."""
    w = words[2:]
    if w[:1] == ["syslog"]:
        level: Optional[int] = None
        if w[1:2] == ["priority"] and len(w) >= 3:
            level, w = mgmt_text.level(w[2]), w[:1] + w[3:]
        if w[1:2] == ["msg"] and len(w) == 3:
            h.actions.append(EventAction("syslog", w[2], 5 if level is None else level))
            return True
        return False
    if w[:2] == ["cli", "command"] and len(w) in (3, 5) and w[3:4] in ([], ["pattern"]):
        if w[2] and w[2] != "enable":  # enable is implied on EOS; an empty command answers a prompt
            h.actions.append(EventAction("cli", w[2]))
        return True
    if w[:1] == ["wait"] and len(w) == 2 and w[1].isdigit() and not h.actions:
        h.delay = int(w[1])
        return True
    return False


def ios_lines(device: Device, report: Report, port) -> List[str]:  # type: ignore[no-untyped-def]
    lines: List[str] = []
    for h in device.event_handlers.values():
        name = label(h)
        report.item(KIND, name)
        event = ""
        if h.trigger == "startup-config":
            event = f'event cli pattern "{SAVE_PATTERN}" sync no skip no'
        elif h.trigger == "boot":
            event = 'event syslog pattern "%SYS-5-RESTART"'
        elif h.trigger == "interface":
            event = f'event syslog pattern "Interface {port(h.interface)}, changed state"'
        elif h.trigger == "logging":
            event = f'event syslog pattern "{h.pattern}"'
        elif h.trigger == "cpu":
            op, value = h.pattern.split()
            event = (f"event snmp oid {CPU_OID} get-type exact entry-op {'gt' if op == '>' else 'ge'} "
                     f"entry-val {value} poll-interval {h.poll_interval or 60}")
        elif h.trigger in ("track", "timer", "none", "cli", "snmp") and device.platform == "ios":
            event = {"track": f"event track {h.track} state {h.pattern}", "timer": f"event timer {h.pattern}",
                     "none": "event none", "cli": f'event cli pattern "{h.pattern}" sync no skip no',
                     "snmp": f"event snmp oid {h.pattern}"}[h.trigger]
        if not event:
            report.skip(KIND, name, "event-trigger", f"IOS EEM has no form of the '{h.trigger}' trigger "
                        f"({h.pattern}); left out")
            continue
        actions: List[str] = []
        if h.delay:
            actions.append(f"wait {h.delay}")
        cli = [a for a in h.actions if a.kind == "cli"]
        if cli:
            actions.append('cli command "enable"')
        for a in h.actions:
            if a.kind == "syslog":
                level = f"priority {mgmt_text.LEVELS[a.level]} " if a.level is not None else ""
                actions.append(f'syslog {level}msg "{a.text}"')
            elif a.kind == "cli":
                actions.append(f'cli command "{a.text}"')
            else:
                report.add(KIND, name, Severity.REVIEW, "event-script",
                           f"the shell command '{a.text}' has no IOS equivalent (Guest Shell, if the platform has "
                           "it); left out")
        if not [a for a in h.actions if a.kind != "script"]:
            report.skip(KIND, name, "event-actions", "no action IOS can run; left out")
            continue
        if device.platform != "ios":
            report.add(KIND, name, Severity.REVIEW, "event-handler",
                       "written as an EEM applet: logger calls become syslog actions, FastCli calls cli actions; "
                       "check the trigger fires as meant")
        lines.append(f"event manager applet {h.name}")
        if h.description:
            lines.append(f" description {h.description}")
        lines.append(f" {event}")
        lines += [f" action {n}.0 {a}" for n, a in enumerate(actions, 1)]
        lines.append("!")
    return lines


def handler(device: Device, name: str) -> EventHandler:
    h = device.event_handlers.get(name)
    if h is None:
        h = device.event_handlers[name] = EventHandler(name, "")
    return h
