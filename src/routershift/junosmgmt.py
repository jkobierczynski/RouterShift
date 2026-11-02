# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Junos management: users with their SSH keys and login classes (roles), the session timeout, the remote-login ACL,
banners, local logging, SNMPv3 (users, groups, views, notification targets), the programmatic interfaces and the
password policy.

How the model maps to Junos:

* A role is a login class of its name: its permitted exec commands become ``allow-commands``, its denied ones
  ``deny-commands``, and a role that may not configure gets ``permissions view``. The session timeout is the
  ``idle-timeout`` of the classes RouterShift writes; Junos' own classes (super-user ...) cannot take one.
* The remote-login ACL is a filter ``<ACL>-LOGIN`` on the loopback (or me0 in the management VRF): SSH and telnet from
  the ACL's sources pass, from anywhere else they are dropped, and all other traffic passes on.
* The login banner is ``system login message`` (shown before the login prompt), the MOTD ``system login
  announcement`` (shown after login).
* SNMPv3 users are USM users of the local engine; groups are VACM access entries; a notification host is a target
  address with target parameters, notified through ``notify RS-NOTIFY``. A v1/v2c host is a trap group named after its
  community.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import aaa as aaa_text
from . import snmp as snmp_text
from .junostext import quote
from .model import (Acl, AclAction, AclEntry, Device, LocalUser, Role, RoleRule, SnmpGroup, SnmpHost, SnmpUser)
from .report import Report, Severity

LEVELS = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "any"]
CLASSES = [(15, "super-user"), (5, "operator"), (0, "read-only")]
BUILTIN_CLASSES = {"super-user": 15, "operator": 5, "read-only": 1, "unauthorized": 0}
HASHES = ("md5-crypt", "sha256-crypt", "sha512-crypt", "junos")
LOGIN_SUFFIX = "-LOGIN"
LOGIN_PORTS = ("ssh", "telnet")
NOTIFY = "RS-NOTIFY"
SSH_KEY_TYPES = {"ssh-rsa": "ssh-rsa", "ssh-ed25519": "ssh-ed25519", "ecdsa-sha2-nistp256": "ssh-ecdsa",
                 "ecdsa-sha2-nistp384": "ssh-ecdsa", "ecdsa-sha2-nistp521": "ssh-ecdsa", "ssh-dss": "ssh-dsa"}
_AUTH = {"md5": "authentication-md5", "sha": "authentication-sha", "sha224": "authentication-sha224",
         "sha256": "authentication-sha256", "sha384": "authentication-sha384", "sha512": "authentication-sha512"}
_PRIV = {"des": "privacy-des", "3des": "privacy-3des", "aes128": "privacy-aes128"}
_LEVEL = {"noauth": "none", "auth": "authentication", "priv": "privacy"}
_FROM_LEVEL = {v: k for k, v in _LEVEL.items()}
API_KEYS = {"netconf": ("netconf", "ssh"), "http": ("rest", "https"),
            "gnmi": ("extension-service", "request-response", "grpc", "clear-text")}

Add = Callable[..., None]


def class_of(user: LocalUser, device: Device) -> str:
    if user.role and user.role in device.roles:
        return user.role
    return aaa_text.role(user.privilege, CLASSES)


# writing ------------------------------------------------------------------------------------------------------------

class MgmtWriter:
    def __init__(self, device: Device, add: Add, report: Report, address_of: Callable[[str], str],
                 instance: Callable[[str], str], mgmt_vrfs: List[str], filter_name: Callable[[str], str]) -> None:
        self.device, self.add, self.report = device, add, report
        self.address_of, self.instance, self.mgmt_vrfs, self.filter_name = address_of, instance, mgmt_vrfs, filter_name

    # users and classes

    def users(self) -> None:
        dev = self.device
        for user in dev.users:
            label = aaa_text.user_label(user)
            self.report.item("management", label)
            path = ("system", "login", f"user {quote(user.name)}")
            self.add(*path, f"class {class_of(user, dev)}")
            if user.role and user.role not in dev.roles:
                self.report.add("management", label, Severity.APPROX, "user-role",
                                f"the platform role {user.role} is written as the login class of its privilege level")
            if user.password:
                self.report.add("management", label, Severity.REVIEW, "plain-password",
                                "Junos takes no clear-text password in a configuration; set it with 'set system "
                                f"login user {user.name} authentication plain-text-password'")
            elif user.password_hash and user.hash_type in HASHES:
                self.add(*path, "authentication", f"encrypted-password {quote(user.password_hash)}")
            elif user.password_hash:
                self.report.add("management", label, Severity.REVIEW, "password-hash",
                                f"the password hash ({user.hash_type or 'platform specific'}) cannot be used on Junos; "
                                f"set the password with 'set system login user {user.name} authentication "
                                "plain-text-password'")
            for key in user.ssh_keys:
                kind = SSH_KEY_TYPES.get(key.split()[0])
                if kind is None:
                    self.report.add("management", label, Severity.REVIEW, "ssh-key",
                                    f"the SSH key type {key.split()[0]} has no Junos form; not written")
                    continue
                self.add(*path, "authentication", f"{kind} {quote(key)}")
        if dev.aaa.enable_secret is not None:
            self.report.skip("management", "enable secret", "enable", "Junos has no enable password; the login "
                             "class of each user sets what it may do")
        self.classes()

    def classes(self) -> None:
        dev = self.device
        m = dev.management
        for role in dev.roles.values():
            label = f"role {role.name}"
            self.report.item("management", label)
            path = ("system", "login", f"class {role.name}")
            allow = [r.command for r in role.rules if r.action == "permit" and r.mode == "exec"]
            deny = [r.command for r in role.rules if r.action == "deny" and r.mode == "exec"]
            config = [r for r in role.rules if r.mode != "exec"]
            may_configure = any(r.action == "permit" for r in config)
            self.add(*path, "permissions all" if may_configure else "permissions view")
            if allow:
                self.add(*path, f"allow-commands {quote(_regex(allow))}")
            if deny:
                self.add(*path, f"deny-commands {quote(_regex(deny))}")
            if m.exec_timeout:
                self.add(*path, f"idle-timeout {m.exec_timeout}")
            notes = ["EOS checks the rules in order and stops at the first match; Junos matches allow-commands and "
                     "deny-commands as two regular expressions, allow-commands first"]
            if may_configure and any(r.action == "deny" for r in config):
                notes.append("the configuration rules become 'permissions all'; limit them with deny-configuration")
            self.report.add("management", label, Severity.APPROX, "role-class", "; ".join(notes))
        if m.exec_timeout is not None:
            label = "session timeout"
            self.report.item("management", label)
            self.report.add("management", label, Severity.APPROX, "idle-timeout",
                            f"Junos sets the idle timeout ({m.exec_timeout} minutes) per login class; it is written "
                            "into the classes of the roles only, as Junos' own classes (super-user, operator, "
                            "read-only) cannot take one" if dev.roles else
                            f"Junos sets the idle timeout ({m.exec_timeout} minutes) per login class, and its own "
                            "classes (super-user, operator, read-only) cannot take one; not written")
        if m.password_min_length is not None:
            self.report.item("management", "password length")
            self.add("system", "login", "password", f"minimum-length {m.password_min_length}")

    # the remote-login ACL

    def login_filter(self) -> Optional[Tuple[str, str]]:
        """The filter that stands in for the remote-login ACL, and the unit it goes on (lo0.0 or me0.0)."""
        dev = self.device
        m = dev.management
        if not m.vty_acl:
            return None
        label = f"remote login ACL {m.vty_acl}"
        self.report.item("management", label)
        acl = dev.acls.get(m.vty_acl)
        if acl is None:
            self.report.add("management", label, Severity.REVIEW, "vty-acl", f"ACL {m.vty_acl} is not defined")
            return None
        sources = [e.source for e in acl.entries if e.action == AclAction.PERMIT]
        if any(e.action == AclAction.DENY and e.source != "any" for e in acl.entries) or not sources:
            self.report.add("management", label, Severity.REVIEW, "vty-acl",
                            f"ACL {m.vty_acl} is not a plain list of permitted sources; not written as a login filter")
            return None
        name = self.filter_name(m.vty_acl) + LOGIN_SUFFIX
        base = ("firewall", "family inet", f"filter {name}")
        for source in sources:
            if source == "any":
                continue
            self.add(*base, "term logins", "from", f"source-address {source}")
        if "any" in sources:
            self.add(*base, "term logins", "from", "source-address 0.0.0.0/0")
        for port in LOGIN_PORTS:
            self.add(*base, "term logins", "from", f"destination-port {port}")
        self.add(*base, "term logins", "from", "protocol tcp")
        self.add(*base, "term logins", "then", "accept")
        for port in LOGIN_PORTS:
            self.add(*base, "term other-logins", "from", f"destination-port {port}")
        self.add(*base, "term other-logins", "from", "protocol tcp")
        self.add(*base, "term other-logins", "then", "discard")
        self.add(*base, "term rest", "then", "accept")
        mgmt = bool(m.vrf and m.vrf in self.mgmt_vrfs)
        unit = "me0" if mgmt else "lo0"
        self.report.add("management", label, Severity.APPROX, "vty-acl",
                        f"written as the filter {name} on {unit}: SSH and telnet from the ACL's sources pass, from "
                        "anywhere else they are dropped, and the rest of the traffic to the switch passes on")
        return name, unit

    # banners and logging

    def banners(self) -> None:
        sy = self.device.system
        login = sy.banner_login or sy.banner_motd
        after = sy.banner_motd if sy.banner_login else ""
        after = after or sy.banner_exec
        if login:
            self.report.item("system", "banner")
            self.add("system", "login", f"message {_text(login)}")
        if after:
            self.report.item("system", "banner")
            self.add("system", "login", f"announcement {_text(after)}")
        if sy.banner_motd and sy.banner_login and sy.banner_exec:
            self.report.add("system", "banner", Severity.APPROX, "banner-exec",
                            "Junos has one banner before login and one after it; the exec banner is left out")

    def logging(self) -> None:
        sy = self.device.system
        label = "local logging"
        stated = sy.logging_buffer is not None or sy.logging_buffer_level is not None or \
            sy.logging_console_level is not None or sy.logging_timestamp or sy.logging_hostname or \
            sy.logging_facility_levels or sy.logging_monitor_level is not None
        if not stated:
            return
        self.report.item("system", label)
        if sy.logging_buffer_level is not None or sy.logging_buffer is not None:
            level = LEVELS[sy.logging_buffer_level] if sy.logging_buffer_level is not None else "info"
            self.add("system", "syslog", "file messages", f"any {level}")
            if sy.logging_buffer is not None:
                self.report.add("system", label, Severity.APPROX, "log-buffer",
                                f"the log buffer ({sy.logging_buffer} bytes) is the file 'messages' on Junos, which "
                                "rotates by its own size")
        if sy.logging_console_level is not None:
            if sy.logging_console_level >= 0:
                self.add("system", "syslog", "console", f"any {LEVELS[sy.logging_console_level]}")
        if sy.logging_monitor_level is not None and sy.logging_monitor_level >= 0:
            self.add("system", "syslog", "user *", f"any {LEVELS[sy.logging_monitor_level]}")
        if sy.logging_timestamp == "msec":
            self.add("system", "syslog", "time-format millisecond")
        if sy.logging_hostname and sy.logging_hostname != "hostname":
            self.report.add("system", label, Severity.APPROX, "log-hostname",
                            f"Junos names itself by its host name in syslog; '{sy.logging_hostname}' is left out")
        if sy.logging_facility_levels:
            self.report.add("system", label, Severity.APPROX, "log-facility",
                            "the levels of single facilities (" + ", ".join(sy.logging_facility_levels) + ") have "
                            "no Junos counterpart: Junos facilities are daemon, kernel, user ... not protocols")

    def syslog_transport(self) -> None:
        sy = self.device.system
        for server, (protocol, port) in sy.syslog_transport.items():
            path = ("system", "syslog", f"host {server}")
            self.add(*path, f"port {port}")
            if protocol != "udp":
                self.add(*path, f"transport {protocol}")
            if protocol == "tls":
                self.report.add("system", f"syslog {server}", Severity.APPROX, "syslog-tls",
                                "TLS to the server also needs the server's CA (security pki) and a matching "
                                "certificate; check the release supports transport tls")

    # SNMP

    def snmp(self) -> None:
        dev = self.device
        sn = dev.snmp
        for c in sn.communities:
            if c.acl:
                acl = dev.acls.get(c.acl)
                label = snmp_text.community_label(dev, c)
                sources = [e.source for e in acl.entries if e.action == AclAction.PERMIT] if acl else []
                if acl is None or not sources:
                    self.report.add("management", label, Severity.REVIEW, "snmp-clients",
                                    f"the manager list {c.acl} is not a list of permitted sources; not written")
                    continue
                for source in sources:
                    self.add("snmp", f"community {quote(c.name)}", "clients",
                             "0.0.0.0/0" if source == "any" else source)
        if sn.engine_id:
            self.add("snmp", "engine-id", f"local {sn.engine_id}")
        for name, entries in sn.views.items():
            self.report.item("management", f"SNMP view {name}")
            for oid, included in entries:
                self.add("snmp", f"view {name}", f"oid {oid}", "include" if included else "exclude")
        for u in sn.users:
            label = snmp_text.user_label(u)
            self.report.item("management", label)
            path = ("snmp", "v3", "usm", "local-engine", f"user {u.name}")
            keys = snmp_text.user_keys(u, self.report)
            if u.auth:
                auth = _AUTH.get(u.auth)
                if auth is None:
                    self.report.add("management", label, Severity.REVIEW, "snmp-algorithm",
                                    f"the authentication {u.auth} has no Junos form; not written")
                else:
                    self.add(*path, auth, f"authentication-password {quote(keys[0])}")
            if u.priv:
                priv = _PRIV.get(u.priv, "privacy-aes128")
                if u.priv not in _PRIV:
                    self.report.add("management", label, Severity.REVIEW, "snmp-algorithm",
                                    f"{u.priv} is not offered by every Junos release; privacy-aes128 is written, so the "
                                    "managers must change to it as well")
                self.add(*path, priv, f"privacy-password {quote(keys[-1])}")
            if u.group:
                self.add("snmp", "v3", "vacm", "security-to-group", "security-model usm",
                         f"security-name {u.name}", f"group {u.group}")
        for g in sn.groups.values():
            self.report.item("management", f"SNMP group {g.name}")
            access: Tuple[str, ...] = ("snmp", "v3", "vacm", "access", f"group {g.name}", "default-context-prefix",
                                       "security-model usm", f"security-level {_LEVEL.get(g.level, 'privacy')}")
            self.add(*access)
            if g.read_view:
                self.add(*access, f"read-view {g.read_view}")
            if g.write_view:
                self.add(*access, f"write-view {g.write_view}")
        self.hosts()
        if sn.source:
            address = self.address_of(sn.source)
            if address:
                self.add("snmp", "trap-options", f"source-address {address}")
        if sn.vrf and sn.vrf not in self.mgmt_vrfs:
            self.report.add("management", "SNMP", Severity.APPROX, "snmp-vrf",
                            f"the agent answers in the main instance; VRF {sn.vrf} needs routing-instance-access and "
                            "the instance on each community")

    def hosts(self) -> None:
        dev = self.device
        sn = dev.snmp
        v3 = [h for h in sn.hosts if h.version == "3"]
        for h in sn.hosts:
            label = snmp_text.host_label(h)
            self.report.item("management", label)
            if h.version == "3":
                params = f"RS-{h.secret}-{h.level or 'priv'}"
                path = ("snmp", "v3", "target-address", h.address)
                self.add(*path, f"address {h.address}")
                self.add(*path, f"tag-list {NOTIFY}")
                self.add(*path, f"target-parameters {params}")
                if h.vrf:
                    self.add(*path, f"routing-instance {self.instance(h.vrf)}")
                p = ("snmp", "v3", "target-parameters", params, "parameters")
                self.add(*p, "message-processing-model v3")
                self.add(*p, "security-model usm")
                self.add(*p, f"security-level {_LEVEL.get(h.level, 'privacy')}")
                self.add(*p, f"security-name {h.secret}")
            else:
                group = ("snmp", f"trap-group {quote(h.secret or 'public')}")
                self.add(*group, f"version {'v1' if h.version == '1' else 'v2'}")
                self.add(*group, f"targets {h.address}")
                if h.vrf:
                    self.add(*group, f"routing-instance {self.instance(h.vrf)}")
                for category in _categories(sn.trap_types):
                    self.add(*group, f"categories {category}")
            if h.informs:
                self.report.add("management", label, Severity.APPROX, "snmp-inform",
                                "written as traps" if h.version != "3" else "written as informs (notify type inform)")
        if v3:
            kind = "inform" if all(h.informs for h in v3) else "trap"
            self.add("snmp", "v3", f"notify {NOTIFY}", f"type {kind}")
            self.add("snmp", "v3", f"notify {NOTIFY}", f"tag {NOTIFY}")
        if sn.trap_types:
            self.report.item("management", "snmp traps")
            self.report.add("management", "snmp traps", Severity.APPROX, "trap-types",
                            "Junos groups notifications by category: " + ", ".join(sn.trap_types) + " become "
                            + (", ".join(_categories(sn.trap_types)) or "all categories")
                            + (" on the v1/v2c trap groups; the SNMPv3 targets get every notification" if v3 else ""))

    # programmatic interfaces

    def apis(self) -> None:
        m = self.device.management
        for api, vrf in m.apis.items():
            label = f"API {api}"
            self.report.item("management", label)
            words = API_KEYS.get(api)
            if words is None:
                self.report.add("management", label, Severity.REVIEW, "api", "no Junos counterpart; not written")
                continue
            self.add("system", "services", *words)
            if api == "gnmi":
                self.report.add("management", label, Severity.APPROX, "api-gnmi",
                                "gNMI is Junos' gRPC extension service, written in clear text (port 32767); use ssl "
                                "with a local certificate for production")
            if vrf and vrf not in self.mgmt_vrfs:
                self.report.add("management", label, Severity.APPROX, "api-vrf",
                                f"Junos serves its APIs in the main instance (or the management instance); VRF {vrf} "
                                "is left out")
            if api in m.api_acls:
                self.report.add("management", label, Severity.REVIEW, "api-acl",
                                f"the ACL {m.api_acls[api]} on its clients is not written; add its port to the "
                                "routing engine's loopback filter")
        if m.console_login:
            self.report.item("management", "console login")
            self.report.add("management", "console login", Severity.APPROX, "console-login",
                            f"the console uses the system authentication order on Junos; the list "
                            f"{m.console_login} of the source is left out")


def _text(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', "'").replace("\n", "\\n") + '"'


def _regex(commands: List[str]) -> str:
    return commands[0] if len(commands) == 1 else "(" + ")|(".join(commands) + ")"


_CATEGORY = {"bgp": "routing", "ospf": "routing", "snmp link-down": "link", "snmp link-up": "link", "snmp": "link",
             "snmp linkdown linkup": "link", "snmp linkdown": "link", "snmp linkup": "link",
             "entity": "chassis", "config": "configuration", "vrrp": "vrrp-events", "lldp": "chassis",
             "authentication": "authentication", "snmp authentication": "authentication"}


def _categories(types: List[str]) -> List[str]:
    return list(dict.fromkeys(_CATEGORY[t] for t in types if t in _CATEGORY))


# reading ------------------------------------------------------------------------------------------------------------

@dataclass
class MgmtReader:
    device: Device
    classes: Dict[str, Dict[str, str]] = field(default_factory=dict)
    user_classes: Dict[str, str] = field(default_factory=dict)
    usm: Dict[str, SnmpUser] = field(default_factory=dict)
    targets: Dict[str, Dict[str, str]] = field(default_factory=dict)
    params: Dict[str, Dict[str, str]] = field(default_factory=dict)
    notify: Dict[str, str] = field(default_factory=dict)
    trap_groups: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    clients: Dict[str, List[str]] = field(default_factory=dict)
    trap_source: str = ""

    def login(self, w: List[str]) -> Optional[bool]:
        """system login ... lines this reader handles (w starts after 'login'); None for the others."""
        dev = self.device
        if w[0] == "announcement" and len(w) == 2:
            dev.system.banner_motd = w[1].replace("\\n", "\n")
            return True
        if w[0] == "message" and len(w) == 2:
            dev.system.banner_login = w[1].replace("\\n", "\n")
            return True
        if w[:2] == ["password", "minimum-length"] and len(w) == 3:
            dev.management.password_min_length = int(w[2])
            return True
        if w[0] == "class" and len(w) >= 4:
            self.classes.setdefault(w[1], {})[w[2]] = " ".join(w[3:])
            return True
        if w[0] == "user" and len(w) == 4 and w[2] == "class":
            self._user(w[1])
            self.user_classes[w[1]] = w[3]
            return True
        if w[0] == "user" and len(w) == 5 and w[2] == "authentication" and w[3] in set(SSH_KEY_TYPES.values()):
            self._user(w[1]).ssh_keys.append(w[4])
            return True
        return None

    def _user(self, name: str) -> LocalUser:
        user = next((u for u in self.device.users if u.name == name), None)
        if user is None:
            user = LocalUser(name)
            self.device.users.append(user)
        return user

    def snmp(self, w: List[str]) -> bool:
        """snmp ... lines beyond location, contact and communities (w starts after 'snmp')."""
        sn = self.device.snmp
        if w[:2] == ["engine-id", "local"] and len(w) == 3:
            sn.engine_id = w[2]
            return True
        if w[0] == "view" and len(w) == 5 and w[2] == "oid" and w[4] in ("include", "exclude"):
            sn.views.setdefault(w[1], []).append((w[3], w[4] == "include"))
            return True
        if w[0] == "community" and len(w) == 4 and w[2] == "clients":
            self.clients.setdefault(w[1], []).append(w[3])
            return True
        if w[:2] == ["trap-options", "source-address"] and len(w) == 3:
            self.trap_source = w[2]
            return True
        if w[0] == "trap-group" and len(w) >= 4:
            self.trap_groups.setdefault(w[1], {}).setdefault(w[2], []).append(w[3])
            return True
        if w[0] != "v3" or len(w) < 3:
            return False
        v = w[1:]
        if v[:3] == ["usm", "local-engine", "user"] and len(v) >= 6:
            u = self.usm.setdefault(v[3], SnmpUser(v[3]))
            kind, rest = v[4], v[5:]
            auth = {a: k for k, a in _AUTH.items()}
            priv = {p: k for k, p in _PRIV.items()}
            if kind in auth and rest[:1] == ["authentication-password"] and len(rest) == 2:
                u.auth, u.auth_key = auth[kind], "" if rest[1] == snmp_text.PLACEHOLDER else rest[1]
                return True
            if kind in priv and rest[:1] == ["privacy-password"] and len(rest) == 2:
                u.priv, u.priv_key = priv[kind], "" if rest[1] == snmp_text.PLACEHOLDER else rest[1]
                return True
            return False
        if v[:4] == ["vacm", "security-to-group", "security-model", "usm"] and len(v) == 8 and \
                v[4] == "security-name" and v[6] == "group":
            self.usm.setdefault(v[5], SnmpUser(v[5])).group = v[7]
            return True
        if v[:3] == ["vacm", "access", "group"] and len(v) >= 8 and v[4] == "default-context-prefix" and \
                v[5:7] == ["security-model", "usm"] and v[7] == "security-level" and len(v) >= 9:
            g = sn.groups.setdefault(v[3], SnmpGroup(v[3]))
            g.level = _FROM_LEVEL.get(v[8], "priv")
            rest = v[9:]
            if not rest:
                return True
            if rest[0] in ("read-view", "write-view") and len(rest) == 2:
                setattr(g, rest[0].replace("-", "_"), rest[1])
                return True
            return rest[0] == "notify-view" and len(rest) == 2
        if v[0] == "target-address" and len(v) == 4:
            self.targets.setdefault(v[1], {})[v[2]] = v[3]
            return True
        if v[0] == "target-parameters" and len(v) == 5 and v[2] == "parameters":
            self.params.setdefault(v[1], {})[v[3]] = v[4]
            return True
        if v[0] == "notify" and len(v) == 4 and v[2] in ("type", "tag"):
            self.notify[v[2]] = v[3]
            return True
        return False

    def finish(self, interface_of: Callable[[str], str], unread: Callable[[int, str, str], None]) -> None:
        dev = self.device
        sn = dev.snmp
        sn.users += list(self.usm.values())
        for name, settings in self.targets.items():
            params = self.params.get(settings.get("target-parameters", ""), {})
            level = _FROM_LEVEL.get(params.get("security-level", ""), "priv")
            host = SnmpHost(settings.get("address", name), "3", params.get("security-name", ""), level,
                            informs=self.notify.get("type") == "inform", vrf=settings.get("routing-instance", ""))
            sn.hosts.append(host)
        for community, group in self.trap_groups.items():
            version = {"v1": "1", "v2": "2c"}.get(group.get("version", ["v2"])[0], "2c")
            for target in group.get("targets", []):
                sn.hosts.append(SnmpHost(target, version, community, vrf=group.get("routing-instance", [""])[0]))
        if sn.hosts:
            sn.traps = True
        if self.trap_source:
            sn.source = interface_of(self.trap_source)
        for c in sn.communities:
            sources = self.clients.get(c.name)
            if not sources:
                continue
            key = [s if s != "0.0.0.0/0" else "any" for s in sources]
            same = next((a.name for a in dev.acls.values()
                         if [e.source for e in a.entries if e.action == AclAction.PERMIT] == key), None)
            if same is None:
                same = f"SNMP-CLIENTS-{sn.communities.index(c) + 1}"
                dev.acls[same] = Acl(same, entries=[AclEntry(AclAction.PERMIT, source=s) for s in key])
            c.acl = same
        # roles: the login classes RouterShift does not know as Junos' own
        for name, cls in self.classes.items():
            role = Role(name)
            seq = 10
            for which, action in (("allow-commands", "permit"), ("deny-commands", "deny")):
                if which in cls:
                    for command in _split(cls[which].strip('"')):
                        role.rules.append(RoleRule(action, "exec", command, seq))
                        seq += 10
            if cls.get("permissions") in ("view", None):
                role.rules.append(RoleRule("deny", "config-all", ".*", seq))
            if "idle-timeout" in cls:
                dev.management.exec_timeout = int(cls["idle-timeout"])
            dev.roles[name] = role
        for user in dev.users:
            user_class = self.user_classes.get(user.name, "")
            if user_class in BUILTIN_CLASSES:
                user.privilege = BUILTIN_CLASSES[user_class]
            elif user_class:
                user.role = user_class
                user.privilege = 15 if self.classes.get(user_class, {}).get("permissions") == "all" else 1


def _split(regex: str) -> List[str]:
    m = re.match(r"^\((.*)\)$", regex)
    if m and ")|(" in regex:
        return m.group(1).split(")|(")
    return [regex]

