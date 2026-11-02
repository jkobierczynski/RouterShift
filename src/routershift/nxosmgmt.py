# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NX-OS management: banners, local logging, syslog transport, roles, SSH keys, APIs, password length, time zones.

How the model maps to NX-OS:

* ``banner motd`` is shown before the login and ``banner exec`` after it: a login banner is the motd, and a motd shown
  after the login (EOS, with a login banner too) the exec banner.
* The log buffer is the log file: ``logging logfile messages LEVEL size N``; ``logging console`` / ``logging monitor``
  take a level, ``logging timestamp milliseconds`` the sub-second stamps, ``logging origin-id`` what names the device,
  ``logging level FACILITY LEVEL`` a facility's level.
* A syslog server's transport goes on its line: ``logging server A L port N [secure]`` (NX-OS sends over UDP or TLS).
* A role is ``role name R`` with ``rule N permit|deny command CMD`` (``*`` the wildcard); NX-OS checks the highest
  numbered rule first, so the first rule gets the highest number. A user takes it with ``username U role R``.
* A user's SSH public key is ``username U sshkey KEY`` (one key per user).
* The HTTP API is NX-API (``feature nxapi``, ``nxapi use-vrf V``); NETCONF is ``feature netconf``, gNMI ``feature
  grpc`` (``grpc use-vrf V``).
* The minimum password length is ``userpassphrase min-length N``.
* A zone of the tz database is written as its standard offset (``clock timezone ABBR H M``) and its summer-time rule
  (``clock summer-time ABBR W DAY MONTH HH:MM W DAY MONTH HH:MM MINUTES``) as the tz database has them this year; read
  back, they become a zone of the tz database with the same rules.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from . import timezones
from .model import Device, LocalUser, Role, RoleRule
from .report import Report, Severity

PLATFORM = "NX-OS"
_RULE_LIMIT = 256
_REGEX = re.compile(r"[\[\]()+?\\{}$^|]")


def banner_lines(device: Device, report: Report) -> List[str]:
    sy = device.system
    before = sy.banner_login or sy.banner_motd
    after = sy.banner_exec or (sy.banner_motd if sy.banner_login else "")
    lines: List[str] = []
    for kind, text in (("motd", before), ("exec", after)):
        if text:
            delim = "#" if "#" not in text else "%"
            lines += [f"banner {kind} {delim}", text, delim]
            report.item("system", f"banner {kind}")
    if sy.banner_login and sy.banner_motd:
        report.add("system", "banner motd", Severity.APPROX, "banner-login",
                   "the login banner is the motd (shown before the login), the motd the exec banner (after it)")
    if sy.banner_login and sy.banner_motd and sy.banner_exec:
        report.add("system", "banner exec", Severity.APPROX, "banner-exec",
                   "NX-OS has one banner before the login and one after it: the source's motd is left out")
    return lines


def logging_lines(device: Device, report: Report) -> List[str]:
    sy = device.system
    lines: List[str] = []
    label = "local logging"
    if sy.logging_buffer is not None or sy.logging_buffer_level is not None or sy.logging_console_level is not None \
            or sy.logging_monitor_level is not None or sy.logging_timestamp or sy.logging_hostname \
            or sy.logging_facility_levels:
        report.item("system", label)
    if sy.logging_buffer is not None or sy.logging_buffer_level is not None:
        level = sy.logging_buffer_level if sy.logging_buffer_level is not None else 5
        size = sy.logging_buffer
        if size is not None and not 4096 <= size <= 4194304:
            report.add("system", label, Severity.APPROX, "logging-size",
                       f"the log file size {size} is out of the NX-OS range (4096 to 4194304 bytes); clamped")
            size = max(4096, min(4194304, size))
        lines.append(f"logging logfile messages {level}" + (f" size {size}" if size is not None else ""))
    if sy.logging_console_level == -1:
        lines.append("no logging console")
    elif sy.logging_console_level is not None:
        lines.append(f"logging console {sy.logging_console_level}")
    if sy.logging_monitor_level is not None and sy.logging_monitor_level >= 0:
        lines.append(f"logging monitor {sy.logging_monitor_level}")
    if sy.logging_timestamp == "msec":
        lines.append("logging timestamp milliseconds")
    if sy.logging_hostname in ("hostname", "fqdn"):
        lines.append("logging origin-id hostname")
        if sy.logging_hostname == "fqdn":
            report.add("system", label, Severity.APPROX, "logging-origin",
                       "NX-OS names the device by its host name in syslog messages, not by its FQDN")
    elif sy.logging_hostname == "ip":
        report.add("system", label, Severity.REVIEW, "logging-origin",
                   "NX-OS names the device by an address it is given (logging origin-id ip A); add it by hand")
    for facility, level in sy.logging_facility_levels.items():
        lines.append(f"logging level {facility} {level}")
    if sy.logging_facility_levels and device.platform != "nxos":
        report.add("system", label, Severity.APPROX, "logging-facility",
                   "the facility levels are written with the source's facility names; NX-OS names its facilities "
                   "after its features: check them (" + ", ".join(sy.logging_facility_levels) + ")")
    return lines


def syslog_transport(device: Device, host: str, report: Report) -> str:
    """The words after a syslog server's address (and level) for its transport: '' for UDP on 514."""
    found = device.system.syslog_transport.get(host)
    if found is None:
        return ""
    protocol, port = found
    if protocol == "tcp":
        report.add("system", f"syslog {host}", Severity.APPROX, "syslog-transport",
                   f"NX-OS sends syslog over UDP or TLS; TCP port {port} is written as UDP on that port")
    words = f" port {port}" if port != 514 else ""
    return words + (" secure" if protocol == "tls" else "")


def _command(rule: RoleRule) -> Tuple[str, bool]:
    """A rule's command in the NX-OS form (* the wildcard), and whether it translated cleanly."""
    text = rule.command.strip()
    if text.startswith("^"):
        text = text[1:]
    if text.endswith("$"):
        text = text[:-1]
    text = text.replace(".*", "*")
    if not text.endswith("*"):
        text += " *"  # the command and everything after it, as the source's rule matches
    return text, not _REGEX.search(text)


def role_lines(device: Device, report: Report, ind: str) -> List[str]:
    lines: List[str] = []
    for role in device.roles.values():
        label = f"role {role.name}"
        report.item("management", label)
        lines.append(f"role name {role.name}")
        rules: List[Tuple[str, str]] = []
        unclear: List[str] = []
        for r in role.rules:
            for part in r.command.split("|") if "|" in r.command and not r.command.startswith("^") else [r.command]:
                text, clean = _command(RoleRule(r.action, r.mode, part.strip()))
                if (r.action, text) in rules:
                    continue
                rules.append((r.action, text))
                if not clean:
                    unclear.append(text)
        top = min(_RULE_LIMIT, len(rules))
        for n, (action, text) in enumerate(rules[:_RULE_LIMIT]):
            lines.append(f"{ind}rule {top - n} {action} command {text}")
        notes = []
        if device.platform != "nxos":
            notes.append("NX-OS checks the highest-numbered rule first, so the rules are numbered from the top down; "
                         "a command is written with * after it so that what follows it matches too")
        if any(r.mode != "exec" for r in role.rules):
            notes.append("NX-OS command rules do not tell the configuration modes apart")
        if notes:
            report.add("management", label, Severity.APPROX, "role-rules", "; ".join(notes))
        if unclear:
            report.add("management", label, Severity.REVIEW, "role-regex",
                       "NX-OS rules take * as the only wildcard; these came from regular expressions: "
                       + ", ".join(unclear))
        if len(rules) > _RULE_LIMIT:
            report.add("management", label, Severity.REVIEW, "role-rules",
                       f"NX-OS takes {_RULE_LIMIT} rules in a role; the rest are left out")
    return lines


def user_role(device: Device, user: LocalUser) -> Optional[str]:
    return user.role if user.role and user.role in device.roles else None


def ssh_key_lines(user: LocalUser, report: Report, label: str) -> List[str]:
    if len(user.ssh_keys) > 1:
        report.add("management", label, Severity.APPROX, "ssh-keys",
                   f"NX-OS takes one SSH key per user; the first is written, {len(user.ssh_keys) - 1} left out")
    return [f"username {user.name} sshkey {user.ssh_keys[0]}"] if user.ssh_keys else []


def api_lines(device: Device, report: Report, vrf_name, features: Set[str]) -> List[str]:  # type: ignore[no-untyped-def]
    m = device.management
    lines: List[str] = []
    for api, where in m.apis.items():
        label = f"API {api}"
        report.item("management", label)
        vrf = vrf_name(where) if where else ""
        if api == "http":
            features.add("nxapi")
            if vrf:
                lines.append(f"nxapi use-vrf {vrf}")
            if device.platform != "nxos":
                report.add("management", label, Severity.APPROX, "api-nxapi",
                           "the HTTP API is NX-API, with its own JSON-RPC and CLI-over-HTTP model")
        elif api == "netconf":
            features.add("netconf")
            if vrf:
                report.add("management", label, Severity.APPROX, "api-vrf",
                           f"NETCONF runs over SSH in every VRF; the VRF {where} is left out")
        elif api == "gnmi":
            features.add("grpc")
            if vrf:
                lines.append(f"grpc use-vrf {vrf}")
        else:
            report.add("management", label, Severity.REVIEW, "api",
                       f"{api} has no NX-OS setting RouterShift writes")
        if api in m.api_acls:
            report.add("management", label, Severity.REVIEW, "api-acl",
                       f"the ACL {m.api_acls[api]} on its clients is not written; NX-OS filters them with the "
                       "management ACL or CoPP")
    if (m.http or m.https) and "http" not in m.apis:
        report.item("management", "web server")
        report.add("management", "web server", Severity.REVIEW, "web-server",
                   "NX-OS has no web management server; NX-API (feature nxapi) is the nearest, and is not switched on")
    return lines


def password_lines(device: Device, report: Report) -> List[str]:
    n = device.management.password_min_length
    if n is None:
        return []
    report.item("management", "password length")
    return [f"userpassphrase min-length {n}"]


def timezone_lines(tz: str, report: Report) -> List[str]:
    """clock timezone (and clock summer-time) for a tz database zone; [] if it is not one."""
    found = timezones.standard_and_summer(tz) if "/" in tz or tz.upper() == "UTC" else None
    if found is None:
        return []
    name, minutes, summer = found
    sign = "-" if minutes < 0 else ""
    lines = [f"clock timezone {name} {sign}{abs(minutes) // 60} {abs(minutes) % 60}"]
    if summer is not None:
        abbr, start, end, extra = summer
        lines.append(f"clock summer-time {abbr} {start} {end} {extra}")
        report.add("system", "time zone", Severity.APPROX, "timezone",
                   f"NX-OS takes an offset and a summer-time rule: '{tz}' is written with the rule the tz database "
                   f"gives for {timezones.YEAR}; a later change of the rule is not followed")
    return lines


# reading ------------------------------------------------------------------------------------------------------------

def read_role(device: Device, name: str, children: List[List[str]]) -> List[int]:
    """role name R / rule N permit|deny command CMD (the highest number first); description."""
    role = device.roles[name] = Role(name)
    rules: List[Tuple[int, RoleRule]] = []
    bad = []
    for k, w in enumerate(children):
        if w[0] == "rule" and len(w) >= 5 and w[1].isdigit() and w[2] in ("permit", "deny") and w[3] == "command":
            rules.append((int(w[1]), RoleRule(w[2], "exec", " ".join(w[4:]))))
        elif w[0] != "description":
            bad.append(k)
    role.rules = [r for _, r in sorted(rules, key=lambda x: -x[0])]
    return bad


def read_logging(device: Device, w: List[str]) -> bool:
    """logging logfile messages L [size N] | console [L] | monitor L | timestamp milliseconds | origin-id hostname |
    level FACILITY L."""
    s = device.system
    n = len(w)
    if w[1:3] == ["logfile", "messages"] and n in (4, 6) and w[3].isdigit() and (n == 4 or w[4] == "size"):
        s.logging_buffer_level = int(w[3])
        if n == 6:
            s.logging_buffer = int(w[5])
        return True
    if w[1] in ("console", "monitor") and n in (2, 3) and (n == 2 or w[2].isdigit()):
        setattr(s, f"logging_{w[1]}_level", int(w[2]) if n == 3 else 2 if w[1] == "console" else 5)
        return True
    if w[1:] == ["timestamp", "milliseconds"]:
        s.logging_timestamp = "msec"
        return True
    if w[1:] == ["origin-id", "hostname"]:
        s.logging_hostname = "hostname"
        return True
    if w[1] == "level" and n == 4 and w[3].isdigit():
        s.logging_facility_levels[w[2]] = int(w[3])
        return True
    return False


def read_server_options(device: Device, address: str, args: List[str]) -> Optional[List[str]]:
    """The options of logging server A after the level: port N, secure; the words left, or None if malformed."""
    protocol, port = "udp", 514
    rest = list(args)
    while rest and rest[0] in ("port", "secure"):
        if rest[0] == "port" and len(rest) >= 2 and rest[1].isdigit():
            port, rest = int(rest[1]), rest[2:]
        elif rest[0] == "secure":
            protocol, rest = "tls", rest[1:]
        else:
            return None
    if (protocol, port) != ("udp", 514):
        device.system.syslog_transport[address] = (protocol, port)
    return rest


def read_feature(device: Device, word: str) -> bool:
    m = device.management
    api = {"nxapi": "http", "netconf": "netconf", "grpc": "gnmi"}.get(word)
    if api is None:
        return False
    m.apis.setdefault(api, "")
    return True


def read_api_vrf(device: Device, w: List[str]) -> bool:
    """nxapi use-vrf V | grpc use-vrf V."""
    if len(w) == 3 and w[1] == "use-vrf" and w[0] in ("nxapi", "grpc"):
        device.management.apis[{"nxapi": "http", "grpc": "gnmi"}[w[0]]] = w[2]
        return True
    return False


def read_summer_time(w: List[str], summer: Dict[str, object]) -> bool:
    """clock summer-time ABBR W DAY MONTH HH:MM W DAY MONTH HH:MM MINUTES (w starts after 'clock')."""
    if w[0] != "summer-time" or len(w) != 11 or not w[10].isdigit():
        return False
    summer["rule"] = (w[1], " ".join(w[2:6]), " ".join(w[6:10]), int(w[10]))
    return True


def finish_timezone(device: Device, summer: Dict[str, object]) -> None:
    """A fixed offset with a summer-time rule becomes the tz database zone with the same rules, where one is found."""
    rule = summer.get("rule")
    tz = device.system.timezone
    words = tz.split()
    minutes = timezones.offset_minutes(tz)
    if rule is None or minutes is None or not words:
        return
    zone = timezones.zone_for(words[0], minutes, rule)  # type: ignore[arg-type]
    if zone:
        device.system.timezone = zone
