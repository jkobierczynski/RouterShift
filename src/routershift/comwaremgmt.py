# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Comware 7 management settings beyond the basics: the login and shell banners, the log buffer and the console and
terminal logging, syslog ports, LLDP timers, password control, NETCONF, gRPC and RESTful, SNMP MIB views, the engine
ID and the notifications switched on. Written and read; what Comware has no form for is reported."""

from __future__ import annotations

from typing import Dict, List, Optional

from . import mgmt as mgmt_text
from .model import Device
from .report import Report, Severity

_LOG_BUFFER = 1024  # Comware counts the log buffer in messages, at most this many
# notifications the source names -> Comware's snmp-agent trap enable words
_TRAPS: Dict[str, str] = {"bgp": "bgp", "ospf": "ospf", "config": "configuration", "configuration": "configuration",
                          "snmp link-down": "standard linkdown", "snmp link-up": "standard linkup",
                          "snmp linkdown": "standard linkdown", "snmp linkup": "standard linkup",
                          "snmp linkdown linkup": "standard linkdown linkup", "linkdown": "standard linkdown",
                          "linkup": "standard linkup", "snmp authentication": "standard authentication",
                          "snmp coldstart": "standard coldstart", "vrrp": "vrrp", "lldp": "lldp", "arp": "arp"}
_APIS = {"netconf": "netconf ssh server enable", "gnmi": "grpc enable", "http": "restful https enable"}


def banner_lines(device: Device, report: Report) -> List[str]:
    s = device.system
    out: List[str] = []
    for kind, text, label in (("login", s.banner_login, "banner login"), ("shell", s.banner_exec, "banner exec")):
        if text:
            report.item("system", label)
            delim = "%" if "%" not in text else "^"
            out += [f"header {kind} {delim}", text, delim]
    return out


def logging_lines(device: Device, report: Report) -> List[str]:
    s = device.system
    out: List[str] = []
    label = "local logging"
    if s.logging_buffer is not None or s.logging_buffer_level is not None or s.logging_console_level is not None \
            or s.logging_monitor_level is not None or s.logging_timestamp or s.logging_hostname \
            or s.logging_facility_levels:
        report.item("system", label)
    if s.logging_buffer is not None:
        out.append(f"info-center logbuffer size {_LOG_BUFFER}")
        report.add("system", label, Severity.APPROX, "log-buffer",
                   f"Comware counts the log buffer in messages: {s.logging_buffer} bytes are written as the most it "
                   f"keeps, {_LOG_BUFFER} messages")
    if s.logging_buffer_level is not None:
        out.append(f"info-center source default logbuffer level {mgmt_text.COMWARE[s.logging_buffer_level]}")
    for word, level in (("console", s.logging_console_level), ("monitor", s.logging_monitor_level)):
        if level is None:
            continue
        out.append(f"info-center source default {word} deny" if level < 0 else
                   f"info-center source default {word} level {mgmt_text.COMWARE[level]}")
    if s.logging_timestamp or s.logging_hostname:
        report.add("system", label, Severity.APPROX, "log-format",
                   "Comware stamps and names its syslog messages its own way; the timestamp resolution and the "
                   "hostname format are left out")
    if s.logging_facility_levels:
        report.add("system", label, Severity.APPROX, "log-facility",
                   "the severities per facility (" + ", ".join(f"{f} {lv}" for f, lv in s.logging_facility_levels.items())
                   + ") are left out: Comware sets them per module with 'info-center source MODULE'")
    return out


def loghost_suffix(device: Device, host: str, report: Report) -> str:
    """The port of a syslog server; Comware sends syslog over UDP only."""
    transport = device.system.syslog_transport.get(host)
    if transport is None:
        return ""
    report.item("system", "syslog servers")
    protocol, port = transport
    if protocol != "udp":
        report.add("system", "syslog servers", Severity.REVIEW, "syslog-transport",
                   f"Comware sends syslog over UDP only: {host} ({protocol} {port}) is written as UDP port {port}")
    return f" port {port}" if port != 514 else ""


def lldp_lines(device: Device, report: Report) -> List[str]:
    m = device.management
    out: List[str] = []
    if m.lldp_timer is None and m.lldp_holdtime is None and not m.lldp_mgmt_interface:
        return out
    report.item("management", "LLDP")
    timer = m.lldp_timer
    if timer is not None:
        out.append(f"lldp timer tx-interval {timer}")
    if m.lldp_holdtime is not None:
        base = timer or 30
        multiplier = max(2, min(10, round(m.lldp_holdtime / base)))
        out.append(f"lldp hold-multiplier {multiplier}")
        if multiplier * base != m.lldp_holdtime:
            report.add("management", "LLDP", Severity.APPROX, "lldp-hold",
                       f"Comware sets the hold time as a multiple of the interval: {m.lldp_holdtime} s is written as "
                       f"{multiplier} x {base} s")
    if m.lldp_mgmt_interface:
        report.add("management", "LLDP", Severity.APPROX, "lldp-mgmt",
                   f"the management address of {m.lldp_mgmt_interface} is not written: Comware advertises a port's "
                   "own address unless 'lldp management-address-tlv ip' is set on it")
    return out


def access_lines(device: Device, report: Report) -> List[str]:
    """Password control and the programmatic interfaces."""
    m = device.management
    out: List[str] = []
    if m.password_min_length is not None:
        report.item("management", "password length")
        out += ["password-control enable", f"password-control length {m.password_min_length}"]
    for api, vrf in m.apis.items():
        label = "programmatic interfaces"
        report.item("management", label)
        line = _APIS.get(api)
        if line is None:
            report.add("management", label, Severity.REVIEW, "api", f"Comware has no {api} server; left out")
            continue
        out.append(line)
        if vrf:
            report.add("management", label, Severity.APPROX, "api-vrf",
                       f"{api} answers in every VPN instance on Comware (the source used VRF {vrf})")
        if api in m.api_acls:
            report.add("management", label, Severity.REVIEW, "api-acl",
                       f"the client ACL {m.api_acls[api]} of {api} is not written; limit it by hand")
    return out


def snmp_lines(device: Device, report: Report) -> List[str]:
    s = device.snmp
    out: List[str] = []
    for view, subtrees in s.views.items():
        report.item("management", f"SNMP view {view}")
        out += [f"snmp-agent mib-view {'included' if included else 'excluded'} {view} {oid}"
                for oid, included in subtrees]
    if s.engine_id:
        report.item("management", "SNMP engine ID")
        out.append(f"snmp-agent local-engineid {s.engine_id}")
    return out


def trap_lines(device: Device, report: Report) -> List[str]:
    s = device.snmp
    if not s.trap_types:
        return ["snmp-agent trap enable"]
    words: List[str] = []
    left = []
    for t in s.trap_types:
        word = _TRAPS.get(t.lower())
        if word is None:
            left.append(t)
        elif word not in words:
            words.append(word)
    if left:
        report.add("management", "snmp traps", Severity.APPROX, "trap-types",
                   "Comware has no switch for the notifications " + ", ".join(left) + "; left out")
    merged: List[str] = []
    standard: List[str] = []
    for w in words:
        if w.startswith("standard "):
            standard += [x for x in w.split()[1:] if x not in standard]
        else:
            merged.append(f"snmp-agent trap enable {w}")
    if standard:
        merged.append("snmp-agent trap enable standard " + " ".join(standard))
    return merged or ["snmp-agent trap enable"]


def unwritable(device: Device, report: Report) -> None:
    """What Comware has no direct form for, reported once each."""
    d = device
    if d.roles or any(u.role for u in d.users):
        for name in d.roles:
            report.add("management", f"role {name}", Severity.REVIEW, "roles",
                       "Comware roles permit features and commands with 'role name' and 'rule N permit command'; "
                       "the role is not translated, rebuild it by hand")
    if any(u.ssh_keys for u in d.users):
        report.add("management", "SSH keys", Severity.REVIEW, "ssh-keys",
                   "Comware takes a user's SSH key with 'public-key peer NAME import sshkey FILE' and 'ssh user NAME "
                   "assign publickey NAME'; copy the keys to the switch and import them by hand")
    if d.management.console_login:
        report.add("management", "console login", Severity.APPROX, "console-login",
                   f"the console logs in with 'authentication-mode scheme' and the default ISP domain; the login "
                   f"list {d.management.console_login} is not written")
    if d.ptp is not None or any(i.ptp is not None for i in d.interfaces.values()):
        report.add("system", "PTP", Severity.REVIEW, "ptp",
                   "PTP is not written for Comware: set 'ptp profile', 'ptp mode' and 'ptp enable' on the ports by "
                   "hand, as the switch model allows")
    for name in d.event_handlers:
        report.add("system", f"event handler {name}", Severity.REVIEW, "event-handlers",
                   "Comware runs EAA monitor policies ('rtm cli-policy'); rebuild the handler by hand")
    if d.twamp_port is not None:
        report.add("monitor", "TWAMP reflector", Severity.REVIEW, "twamp",
                   "the TWAMP reflector is not written; Comware answers TWAMP Light with 'nqa twamp-light responder' "
                   "on the switches that have it")
    for session in d.mirror_sessions:
        if session.acl:
            report.add("monitor", f"mirror session {session.name}", Severity.REVIEW, "mirror-acl",
                       f"the mirror's ACL filter {session.acl} is not written: Comware mirrors by ACL with a QoS "
                       "policy (traffic behavior 'mirror-to interface'); set it up by hand")
    sf = d.sflow
    if sf is not None and (sf.extensions or sf.source_vrf):
        report.add("monitor", "sflow", Severity.APPROX, "sflow-options",
                   "Comware has no sFlow extensions or source VRF setting; left out")
    nf = d.netflow
    if nf is not None and nf.sample_rate:
        report.add("monitor", "netflow", Severity.REVIEW, "netflow-sampling",
                   f"sampling 1 in {nf.sample_rate} is not written: set a 'sampler' and 'ip netstream inbound "
                   "sampler' by hand")


# reading -----------------------------------------------------------------------------------------------------------

def read_info_center(device: Device, w: List[str]) -> bool:
    s = device.system
    if w[1:3] == ["logbuffer", "size"] and len(w) == 4:
        s.logging_buffer = int(w[3])
        return True
    if w[1:3] == ["source", "default"] and len(w) in (5, 6):
        where = w[3]
        if where not in ("logbuffer", "console", "monitor"):
            return False
        level: Optional[int]
        if w[4:] == ["deny"] and where != "logbuffer":
            level = -1
        elif w[4] == "level" and len(w) == 6:
            level = mgmt_text.level(w[5])
            if level is None:
                return False
        else:
            return False
        setattr(s, {"logbuffer": "logging_buffer_level", "console": "logging_console_level",
                    "monitor": "logging_monitor_level"}[where], level)
        return True
    return False


def read_global(device: Device, w: List[str]) -> bool:
    m = device.management
    if w[:3] == ["lldp", "timer", "tx-interval"] and len(w) == 4:
        m.lldp_timer = int(w[3])
    elif w[:2] == ["lldp", "hold-multiplier"] and len(w) == 3:
        m.lldp_holdtime = int(w[2]) * (m.lldp_timer or 30)
    elif w == ["password-control", "enable"]:
        pass
    elif w[:2] == ["password-control", "length"] and len(w) == 3:
        m.password_min_length = int(w[2])
    elif w == ["netconf", "ssh", "server", "enable"]:
        m.apis["netconf"] = ""
    elif w == ["grpc", "enable"]:
        m.apis["gnmi"] = ""
    elif w == ["restful", "https", "enable"]:
        m.apis["http"] = ""
    else:
        return False
    return True


def read_snmp(device: Device, w: List[str]) -> bool:
    s = device.snmp
    if w[1] == "mib-view" and len(w) == 5 and w[2] in ("included", "excluded"):
        s.views.setdefault(w[3], []).append((w[4], w[2] == "included"))
        return True
    if w[1] == "local-engineid" and len(w) == 3:
        s.engine_id = w[2]
        return True
    if w[1:3] == ["trap", "enable"] and len(w) > 3:
        s.traps = True
        names = {v: k for k, v in _TRAPS.items() if not k.startswith("snmp ") or k in ("snmp link-down",
                                                                                       "snmp link-up")}
        if w[3] == "standard":
            for x in w[4:]:
                found = {"linkdown": "snmp link-down", "linkup": "snmp link-up"}.get(x, f"snmp {x}")
                if found not in s.trap_types:
                    s.trap_types.append(found)
            return True
        if len(w) == 4 and w[3] in names:
            s.trap_types.append(names[w[3]])
            return True
    return False

