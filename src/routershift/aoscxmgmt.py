# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AOS-CX management: banners, user groups, SSH keys, the REST API, password rules, syslog transport, and what has
no AOS-CX setting.

How the model maps to AOS-CX:

* AOS-CX shows ``banner motd`` before the login and ``banner exec`` after it: a login banner is the motd, and a motd
  shown after the login (EOS, with a login banner too) the exec banner.
* A role is a user group (``user-group NAME``) with ``SEQ permit|deny cli command "REGEX"`` rules; a user of the role
  is ``user NAME group ROLE``. A user's SSH public keys are ``user NAME authorized-key KEY``.
* The HTTP API (EOS eAPI, IOS RESTCONF) is the AOS-CX REST API: ``https-server rest access-mode read-write``.
* The minimum password length is ``password complexity`` / ``minimum-length``.
* A syslog server's transport goes after its address: ``logging A tls 6514``.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from .model import Device, LocalUser, Role, RoleRule
from .report import Report, Severity

PLATFORM = "AOS-CX"


def banner_lines(device: Device, report: Report) -> List[str]:
    sy = device.system
    before = sy.banner_motd or sy.banner_login
    after = sy.banner_exec or (sy.banner_motd if sy.banner_login else "")
    lines: List[str] = []
    for kind, text in (("motd", before), ("exec", after)):
        if text:
            delim = "^" if "^" not in text else "%"
            lines += [f"banner {kind} {delim}", text, delim]
            report.item("system", f"banner {kind}")
    if sy.banner_login and sy.banner_motd:
        report.add("system", "banner motd", Severity.APPROX, "banner-login",
                   "the login banner is the motd (shown before the login), the motd the exec banner (after it)")
    if sy.banner_login and sy.banner_motd and sy.banner_exec:
        report.add("system", "banner exec", Severity.APPROX, "banner-exec",
                   "AOS-CX has one banner before the login and one after it: the source's motd is left out")
    return lines


def _regex(rule: RoleRule) -> str:
    return rule.command if rule.command.startswith((".", "^")) or "*" in rule.command else \
        f"({rule.command}).*" if "|" in rule.command else f"{rule.command}.*"


def role_lines(device: Device, report: Report, ind: str) -> List[str]:
    lines: List[str] = []
    for role in device.roles.values():
        label = f"role {role.name}"
        report.item("management", label)
        lines.append(f"user-group {role.name}")
        for n, r in enumerate(role.rules, 1):
            lines.append(f'{ind}{r.sequence or n * 10} {r.action} cli command "{_regex(r)}"')
        notes = []
        if any(r.mode != "exec" for r in role.rules):
            notes.append("the rules of configuration modes apply to every command on AOS-CX, where a user group's "
                         "rules do not tell the modes apart")
        if any(r.command != _regex(r) for r in role.rules):
            notes.append("commands are written as regular expressions that match their start")
        if notes:
            report.add("management", label, Severity.APPROX, "role-group", "; ".join(notes))
    return lines


def user_group(device: Device, user: LocalUser) -> Optional[str]:
    return user.role if user.role and user.role in device.roles else None


def ssh_key_lines(user: LocalUser) -> List[str]:
    return [f"user {user.name} authorized-key {key}" for key in user.ssh_keys]


def api_lines(device: Device, report: Report, vrf: str) -> List[str]:
    m = device.management
    lines: List[str] = []
    for api, where in m.apis.items():
        label = f"API {api}"
        report.item("management", label)
        if api == "http":
            lines.append("https-server rest access-mode read-write")
            report.add("management", label, Severity.APPROX, "api-rest",
                       "the HTTP API is the AOS-CX REST API, with its own URLs and JSON model"
                       + (f"; it serves in the HTTPS server's VRF ({vrf}), not {where}" if where and vrf != where
                          else ""))
        else:
            report.add("management", label, Severity.REVIEW, "api",
                       f"{api} has no AOS-CX setting RouterShift writes; AOS-CX is managed through its REST API")
        if api in m.api_acls:
            report.add("management", label, Severity.REVIEW, "api-acl",
                       f"the ACL {m.api_acls[api]} on its clients is not written; add its port to a control-plane ACL")
    return lines


def password_lines(device: Device, report: Report, ind: str) -> List[str]:
    n = device.management.password_min_length
    if n is None:
        return []
    report.item("management", "password length")
    return ["password complexity", f"{ind}minimum-length {n}", f"{ind}enable"]


def unwritable(device: Device, report: Report) -> None:
    sy = device.system
    if sy.logging_buffer is not None or sy.logging_buffer_level is not None or sy.logging_console_level is not None \
            or sy.logging_monitor_level is not None or sy.logging_timestamp or sy.logging_hostname \
            or sy.logging_facility_levels:
        report.item("system", "local logging")
        report.add("system", "local logging", Severity.APPROX, "local-logging",
                   "AOS-CX keeps its event log itself: the log buffer, console and monitor levels, time stamps, host "
                   "name and facility levels of the source are left out")
    snmp = device.snmp
    if snmp.views or snmp.engine_id:
        report.item("management", "SNMP views")
        report.add("management", "SNMP views", Severity.APPROX, "snmp-views",
                   "AOS-CX has no SNMP views and makes its own engine ID: " + ", ".join(
                       x for x in (f"views {', '.join(snmp.views)}" if snmp.views else "",
                                   f"engine ID {snmp.engine_id}" if snmp.engine_id else "") if x) + " left out")
    if snmp.trap_types:
        report.item("management", "snmp traps")
        report.add("management", "snmp traps", Severity.APPROX, "trap-types",
                   "AOS-CX sends its own set of notifications to each trap receiver: the choice ("
                   + ", ".join(snmp.trap_types) + ") is left out")


def syslog_transport(device: Device, host: str) -> str:
    """The transport words after a syslog server's address: "" for UDP on its default port."""
    found = device.system.syslog_transport.get(host)
    if found is None:
        return ""
    protocol, port = found
    default = {"udp": 514, "tcp": 1470, "tls": 6514}.get(protocol)
    return f" {protocol}" + (f" {port}" if port != default else "")


# reading ------------------------------------------------------------------------------------------------------------

def read_user_group(device: Device, name: str, children: List[List[str]]) -> List[int]:
    role = device.roles.setdefault(name, Role(name))
    bad = []
    for n, w in enumerate(children):
        if len(w) >= 4 and w[0].isdigit() and w[1] in ("permit", "deny") and w[2:4] == ["cli", "command"]:
            regex = " ".join(w[4:]).strip('"')
            m = re.fullmatch(r"\((.*)\)\.\*|([^().*^|]+)\.\*", regex)
            command = (m.group(1) or m.group(2)) if m else regex
            role.rules.append(RoleRule(w[1], "exec", command, int(w[0])))
        else:
            bad.append(n)
    return bad


def read_user_line(device: Device, w: List[str], keys: Dict[str, List[str]]) -> bool:
    """user NAME authorized-key KEY..."""
    if len(w) >= 4 and w[2] == "authorized-key":
        keys.setdefault(w[1], []).append(" ".join(w[3:]))
        return True
    return False


def finish(device: Device, keys: Dict[str, List[str]], groups: Dict[str, str], rest_api: bool) -> None:
    for user in device.users:
        user.ssh_keys += keys.get(user.name, [])
        if groups.get(user.name) in device.roles:
            user.role = groups[user.name]
    if rest_api:
        m = device.management
        m.apis["http"] = m.vrf if m.https else ""
