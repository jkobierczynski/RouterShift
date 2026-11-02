# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Who may manage the device and how: CLI roles (EOS role, IOS parser view), users' SSH keys, the programmatic
interfaces (NETCONF, gNMI, eAPI / RESTCONF) and the local logging options, for the IOS and EOS reader and writer."""

from __future__ import annotations

import re
from typing import List, Optional

from .model import Device, Role, RoleRule
from .report import Report, Severity

KIND = "management"
API_LABELS = {"netconf": "NETCONF", "gnmi": "gNMI", "http": "eAPI / RESTCONF"}
EOS_APIS = {"netconf": "netconf", "gnmi": "gnmi", "http-commands": "http"}
BUILTIN_ROLES = ("network-admin", "network-operator")
PLACEHOLDER = "CHANGE-ME"


# roles ----------------------------------------------------------------------------------------------------------------

def eos_role_line(role: Role, w: List[str]) -> bool:
    """[SEQ] permit|deny [mode MODE] command REGEX"""
    seq: Optional[int] = None
    if w and w[0].isdigit():
        seq, w = int(w[0]), w[1:]
    if not w or w[0] not in ("permit", "deny"):
        return False
    action, w = w[0], w[1:]
    mode = "exec"
    if w[:1] == ["mode"] and len(w) >= 2:
        mode, w = w[1], w[2:]
    if w[:1] != ["command"] or len(w) < 2:
        return False
    role.rules.append(RoleRule(action, mode, " ".join(w[1:]), seq))
    return True


def ios_view_line(role: Role, w: List[str]) -> bool:
    """commands exec|configure include [all] CMD...; secret is not kept."""
    if w[0] == "secret":
        return True
    if w[0] != "commands" or len(w) < 4 or w[2] not in ("include", "include-exclusive", "exclude"):
        return False
    mode = "exec" if w[1] == "exec" else "config" if w[1] == "configure" else w[1]
    words = w[4:] if w[3] == "all" else w[3:]
    if not words:
        return False
    role.rules.append(RoleRule("deny" if w[2] == "exclude" else "permit", mode, " ".join(words)))
    return True


def _alternatives(command: str) -> Optional[List[str]]:
    """The commands an EOS regular expression names when it is plain words with | between them, else None."""
    if not re.fullmatch(r"[A-Za-z0-9 _|-]+", command):
        return None
    return [c.strip() for c in command.split("|") if c.strip()]


def eos_role_lines(role: Role, ind: str) -> List[str]:
    lines = [f"role {role.name}"]
    seq = 0
    for rule in role.rules:
        seq = rule.sequence if rule.sequence is not None else seq + 10
        mode = "config-all" if rule.mode == "config" else rule.mode
        lines.append(f"{ind}{seq} {rule.action} mode {mode} command {rule.command}")
    if role.origin.text.startswith("parser view"):  # a view allows nothing it does not name
        lines += [f"{ind}{seq + 10} deny mode exec command .*", f"{ind}{seq + 20} deny mode config-all command .*"]
    return lines + ["!"]


def ios_view_lines(role: Role, report: Report) -> List[str]:
    """A parser view with the commands the role permits; regular expressions and denials are reported."""
    label = f"role {role.name}"
    report.item(KIND, label)
    lines = [f"parser view {role.name}", f" secret 0 {PLACEHOLDER}"]
    report.add(KIND, label, Severity.REVIEW, "role-view",
               "written as an IOS parser view: it needs aaa new-model, and its users enter it with 'enable view'; "
               f"replace the view secret {PLACEHOLDER}")
    for rule in role.rules:
        words = _alternatives(rule.command) if rule.action == "permit" else None
        if rule.action == "deny" and rule.command in (".*", "^.*$"):
            continue  # a parser view denies what it does not include
        mode = {"exec": "exec", "config": "configure", "config-all": "configure"}.get(rule.mode)
        if words is None or mode is None:
            report.add(KIND, label, Severity.REVIEW, "role-rule",
                       f"'{rule.action} mode {rule.mode} command {rule.command}' has no parser view form; left out")
            continue
        lines += [f" commands {mode} include all {cmd}" for cmd in words]
    return lines + ["!"]


def eos_role_name(role: str) -> str:
    return role


# SSH keys -------------------------------------------------------------------------------------------------------------

def ios_pubkey_lines(device: Device, report: Report) -> List[str]:
    users = [u for u in device.users if u.ssh_keys]
    if not users:
        return []
    lines = ["ip ssh pubkey-chain"]
    for u in users:
        label = f"user {u.name} SSH keys"
        report.item(KIND, label)
        report.add(KIND, label, Severity.APPROX, "ssh-key",
                   "written as key-string under ip ssh pubkey-chain; IOS shows it as a key hash afterwards, and "
                   "older releases take RSA keys only")
        lines.append(f"  username {u.name}")
        for key in u.ssh_keys:
            lines += ["   key-string", f"    {key}", "    exit"]
    return lines + ["!"]


# programmatic interfaces ----------------------------------------------------------------------------------------------

def ios_api_lines(device: Device, report: Report, vrf_name) -> List[str]:  # type: ignore[no-untyped-def]
    m = device.management
    lines: List[str] = []
    for api, vrf in m.apis.items():
        label = API_LABELS.get(api, api)
        report.item(KIND, label)
        acl = m.api_acls.get(api, "")
        if api == "netconf":
            lines.append("netconf-yang")
            if acl:
                lines.append(f"netconf-yang ssh ipv4 access-list name {acl}")
        elif api == "http":
            lines += ["ip http secure-server", "restconf"]
            if acl:
                lines.append(f"restconf ipv4 access-list name {acl}")
            if device.platform != "ios":
                report.add(KIND, label, Severity.REVIEW, "api-restconf",
                           "the source runs the eAPI (JSON-RPC CLI commands); the nearest on IOS is RESTCONF (YANG "
                           "models), so the clients must change")
        elif api == "gnmi":
            lines += ["gnxi", "gnxi secure-server"]
            report.add(KIND, label, Severity.REVIEW, "api-gnmi",
                       "gNMI (gnxi) needs a TLS trustpoint on IOS: gnxi secure-trustpoint; set it up by hand")
            if acl:
                report.add(KIND, label, Severity.REVIEW, "api-acl", f"the client ACL {acl} is not written for gnxi")
        if vrf and device.platform != "ios":
            report.add(KIND, label, Severity.APPROX, "api-vrf",
                       f"the source serves it in VRF {vrf}; IOS serves it through the SSH and HTTPS servers, check "
                       "that they listen there")
    return lines + (["!"] if lines else [])


def eos_api_lines(device: Device, report: Report, ind: str, vrf_name) -> List[str]:  # type: ignore[no-untyped-def]
    m = device.management
    lines: List[str] = []
    for api, vrf in m.apis.items():
        label = API_LABELS.get(api, api)
        report.item(KIND, label)
        acl = m.api_acls.get(api, "")
        if api == "http":
            lines += ["management api http-commands", f"{ind}no shutdown"]
            if vrf or acl:
                lines += [f"{ind}vrf {vrf_name(vrf) if vrf else 'default'}", f"{ind * 2}no shutdown"]
            if acl:
                lines.append(f"{ind * 2}ip access-group {acl}")
            if device.platform != "eos":
                report.add(KIND, label, Severity.REVIEW, "api-eapi",
                           "the source runs RESTCONF; the nearest on EOS is the eAPI (JSON-RPC CLI commands), so "
                           "the clients must change")
        elif api in ("gnmi", "netconf"):
            transport = "grpc" if api == "gnmi" else "ssh"
            name = vrf_name(vrf) if vrf else "default"
            lines += [f"management api {api}", f"{ind}transport {transport} {name}"]
            if vrf:
                lines.append(f"{ind * 2}vrf {vrf_name(vrf)}")
            if acl:
                lines.append(f"{ind * 2}ip access-group {acl}")
            if api == "gnmi" and device.platform != "eos":
                report.add(KIND, label, Severity.APPROX, "api-gnmi", "gnxi on IOS becomes the EOS gNMI agent; the "
                           "OpenConfig paths are the same, the native ones are not")
        lines.append("!")
    return lines


def eos_api_block(device: Device, words: List[str], children, unparsed) -> bool:  # type: ignore[no-untyped-def]
    """EOS management api http-commands | gnmi | netconf with its transports and VRFs."""
    api = EOS_APIS.get(words[2]) if len(words) == 3 else None
    if api is None:
        return False
    m = device.management
    on = api != "http"
    vrf = ""
    for child in children:
        c = child.words
        if c in (["no", "shutdown"], ["shutdown"]):
            on = c[0] == "no"
        elif c[0] == "vrf" and len(c) == 2:
            vrf = "" if c[1] == "default" else c[1]
            for g in child.children:
                if g.words[:2] == ["ip", "access-group"] and len(g.words) == 3:
                    m.api_acls[api] = g.words[2]
                elif g.words not in (["no", "shutdown"],):
                    unparsed(g, f"{' '.join(words)} / {child.text}")
        elif c[0] == "transport" and len(c) == 3:
            for g in child.children:
                if g.words[0] == "vrf" and len(g.words) == 2:
                    vrf = g.words[1]
                elif g.words[:2] == ["ip", "access-group"] and len(g.words) == 3:
                    m.api_acls[api] = g.words[2]
                else:
                    unparsed(g, f"{' '.join(words)} / {child.text}")
        elif c == ["provider", "eos-native"]:
            pass  # EOS paths besides OpenConfig
        else:
            unparsed(child, " ".join(words))
    if on:
        m.apis[api] = vrf
    return True


# local logging --------------------------------------------------------------------------------------------------------

def logging_lines(device: Device, report: Report, ios: bool) -> List[str]:
    from . import mgmt as mgmt_text
    s = device.system
    lines: List[str] = []
    name = mgmt_text.LEVELS
    if s.logging_buffer is not None or s.logging_buffer_level is not None:
        words = ["logging buffered"]
        words += [str(s.logging_buffer)] if s.logging_buffer is not None else []
        words += [name[s.logging_buffer_level]] if s.logging_buffer_level is not None else []
        lines.append(" ".join(words))
    for what, value in (("console", s.logging_console_level), ("monitor", s.logging_monitor_level)):
        if value == -1:
            lines.append(f"no logging {what}")
        elif value is not None:
            lines.append(f"logging {what} {name[value]}")
    if s.logging_timestamp == "msec":
        lines.append("service timestamps log datetime msec localtime show-timezone" if ios
                     else "logging format timestamp high-resolution")
    if s.logging_hostname:
        if ios:
            lines.append(f"logging origin-id {'ip' if s.logging_hostname == 'ip' else 'hostname'}")
            if s.logging_hostname == "fqdn":
                report.item(KIND, "syslog format")
                report.add(KIND, "syslog format", Severity.APPROX, "syslog-fqdn",
                           "IOS names itself by host name in syslog messages, not by its FQDN")
        elif s.logging_hostname != "hostname":  # EOS names itself by host name unless told otherwise
            lines.append(f"logging format hostname {'ipv4' if s.logging_hostname == 'ip' else 'fqdn'}")
    if s.logging_facility_levels:
        if ios:
            report.item(KIND, "syslog levels")
            report.add(KIND, "syslog levels", Severity.REVIEW, "syslog-facility",
                       "per-facility severities (" + ", ".join(f"{f} {name[v]}" for f, v in
                                                            s.logging_facility_levels.items())
                       + ") have no IOS form; use a logging discriminator if it matters; left out")
        else:
            lines += [f"logging level {f} {name[v]}" for f, v in s.logging_facility_levels.items()]
    return lines
