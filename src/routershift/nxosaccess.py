# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NX-OS access: RADIUS and TACACS+, method lists, 802.1X, DHCP snooping and port security, SNMP notifications and
SNMPv3, and the extra settings of routed ports and SVIs.

How the model maps to NX-OS:

* A server is ``radius-server host A key 0 K [auth-port N acct-port N] [timeout N]`` (``tacacs-server host`` with
  ``port``); a group lists its servers and holds the VRF and source interface (``use-vrf``, ``source-interface``).
  TACACS+ needs ``feature tacacs+``.
* Method lists are ``aaa authentication login default|console``, ``aaa authorization commands default`` (no privilege
  levels: the role of the user decides) and one ``aaa accounting default`` for every session.
* 802.1X is ``feature dot1x`` with ``dot1x pae authenticator`` and ``dot1x port-control auto`` on the port; MAC
  authentication is ``dot1x mac-auth-bypass``. Port security needs ``feature port-security``; DHCP snooping and ARP
  inspection need ``feature dhcp``; IP source guard is ``ip verify source dhcp-snooping-vlan``.
* An SNMPv3 user has a role, not a group: ``snmp-server user U ROLE auth sha K priv aes-128 K``; NX-OS has no
  SNMP views. A notification host is ``snmp-server host A traps|informs version V SECRET``, with its VRF on a line of
  its own (``snmp-server host A use-vrf V``).
* The DHCP relay names the server's VRF on the address (``ip dhcp relay address A use-vrf V``); an unnumbered port is
  a point-to-point port (``medium p2p``).
"""

from __future__ import annotations

from typing import Callable, Dict, List, Set

from . import aaa as aaa_text
from . import hosts as hosts_text
from . import acl as acl_text
from . import l2sec as l2sec_text
from . import snmp as snmp_text
from .model import Device, Interface, InterfaceKind
from .report import Report, Severity

PLATFORM = "NX-OS"
Add = Callable[[Severity, str, str], None]
Vrf = Callable[[str], str]
Port = Callable[[str], str]
AUTH = ["md5", "sha", "sha256", "sha384", "sha512"]
PRIV = ["des", "aes128"]
HOST_MODES = {"single-host": "single-host", "multi-host": "multi-host", "multi-auth": "multi-host",
              "multi-domain": "multi-host"}


def _group_vrf(device: Device, addresses: List[str], protocol: str) -> str:
    vrfs = {s.vrf for s in device.aaa.servers if s.address in addresses and s.protocol == protocol}
    return vrfs.pop() if len(vrfs) == 1 else ""


def aaa_lines(device: Device, report: Report, ind: str, vrf: Vrf, port: Port, features: Set[str]) -> List[str]:
    a = device.aaa
    if not aaa_text.has_aaa(device):
        return []
    lines: List[str] = []
    for s in a.servers:
        label = aaa_text.server_label(s)
        report.item("management", label)
        key = aaa_text.key(s, report)
        words = [f"{s.protocol}-server host {s.address} key 0 {key}"]
        if s.protocol == "radius":
            words += [f"auth-port {s.auth_port}"] if s.auth_port else []
            words += [f"acct-port {s.acct_port}"] if s.acct_port else []
        else:
            features.add("tacacs+")
            words += [f"port {s.auth_port}"] if s.auth_port else []
        words += [f"timeout {s.timeout}"] if s.timeout is not None else []
        lines.append(" ".join(words))
        if s.vrf and not any(s.address in g.servers and g.protocol == s.protocol for g in a.groups.values()):
            report.add("management", label, Severity.REVIEW, "aaa-vrf",
                       f"NX-OS sets the VRF on a server group (use-vrf); put the server in a group in VRF {s.vrf}")
    sourced = set()
    for g in a.groups.values():
        label = f"{g.protocol} group {g.name}"
        report.item("management", label)
        if g.protocol == "tacacs":
            features.add("tacacs+")
        lines.append(f"aaa group server {'radius' if g.protocol == 'radius' else 'tacacs+'} {g.name}")
        known = {s.address for s in a.servers if s.protocol == g.protocol}
        for address in g.servers:
            if address not in known:
                report.add("management", label, Severity.REVIEW, "aaa-server",
                           f"server {address} is not defined; it is listed, define it by hand")
            lines.append(f"{ind}server {address}")
        group_vrf = g.vrf or _group_vrf(device, g.servers, g.protocol)
        if group_vrf:
            lines.append(f"{ind}use-vrf {vrf(group_vrf)}")
        if g.protocol in a.source:
            lines.append(f"{ind}source-interface {port(a.source[g.protocol])}")
            sourced.add(g.protocol)
    for protocol, source in a.source.items():
        if protocol not in sourced:
            lines.append(f"ip {protocol} source-interface {port(source)}")
    accounting = False
    for m in a.methods:
        label = aaa_text.method_label(m)
        report.item("management", label)
        methods = []
        for method in m.methods:
            if method.startswith("group:"):
                group = method[len("group:"):]
                methods.append(f"group {'tacacs+' if group == 'tacacs' else group}")
            elif method in ("local", "none"):
                methods.append(method)
            else:
                report.add("management", label, Severity.APPROX, "aaa-method",
                           f"NX-OS has no '{method}' method; left out of the list")
        if not methods:
            report.add("management", label, Severity.REVIEW, "aaa-method", "no method NX-OS takes; left out")
            continue
        if m.service == "login" and (m.name in ("default", "console")
                                     or m.name == device.management.console_login):
            name = "console" if m.name == device.management.console_login else m.name
            if m.name not in ("default", "console"):
                report.add("management", label, Severity.APPROX, "aaa-list",
                           f"the console's list {m.name} is written as NX-OS's console list")
            lines.append(f"aaa authentication login {name} {' '.join(methods)}")
        elif m.service == "login":
            report.add("management", label, Severity.REVIEW, "aaa-list",
                       f"NX-OS has a default and a console login list only; named list {m.name} is left out")
        elif m.service == "dot1x":
            features.add("dot1x")
            lines.append(f"aaa authentication dot1x default {' '.join(methods)}")
        elif m.kind == "authorization" and m.service == "commands":
            if m.level is not None and m.level != 15:
                report.add("management", label, Severity.APPROX, "aaa-level",
                           f"NX-OS authorizes every command alike; the list for level {m.level} is written for all "
                           "commands")
            lines.append(f"aaa authorization commands default {' '.join(methods)}")
            lines.append(f"aaa authorization config-commands default {' '.join(methods)}")
        elif m.kind == "authorization":
            report.add("management", label, Severity.APPROX, "aaa-exec",
                       "NX-OS takes the user's role from the server at login; exec authorization has no NX-OS list")
        elif m.kind == "accounting":
            if accounting:
                report.add("management", label, Severity.APPROX, "aaa-accounting",
                           "NX-OS has one accounting list for sessions and commands; the first one is written")
                continue
            accounting = True
            if m.service != "exec" or m.record != "start-stop":
                report.add("management", label, Severity.APPROX, "aaa-accounting",
                           f"NX-OS accounts every session and command start-stop; the {m.service} {m.record} list is "
                           "written as that")
            lines.append(f"aaa accounting default {' '.join(methods)}")
        else:
            report.add("management", label, Severity.REVIEW, "aaa-list",
                       f"NX-OS has no {m.kind} {m.service} list; left out")
    if a.coa:
        report.item("system", "RADIUS CoA")
        report.add("system", "RADIUS CoA", Severity.REVIEW, "coa",
                   "NX-OS takes no RADIUS change of authorization; reauthenticate the ports another way")
    return lines


def snmp_lines(device: Device, report: Report, vrf: Vrf, port: Port) -> List[str]:
    s = device.snmp
    lines: List[str] = []
    if s.location:
        lines.append(f"snmp-server location {s.location}")
    if s.contact:
        lines.append(f"snmp-server contact {s.contact}")
    for c in s.communities:
        label = snmp_text.community_label(device, c)
        report.item("management", label)
        name = snmp_text.secret(c.name, report, "management", label, "community")
        group = "network-admin" if c.access == "rw" else "network-operator"
        lines.append(f"snmp-server community {name} group {group}")
        if c.acl and c.acl in device.acls:
            lines.append(f"snmp-server community {name} use-acl {acl_text.safe_name(c.acl)}")
        elif c.acl:
            report.add("management", label, Severity.REVIEW, "acl-missing", f"ACL {c.acl} is not defined; left out")
    if s.views or s.engine_id:
        report.item("management", "SNMP views")
        report.add("management", "SNMP views", Severity.APPROX, "snmp-views",
                   "NX-OS has no SNMP views and makes its own engine ID: " + ", ".join(
                       x for x in (f"views {', '.join(s.views)}" if s.views else "",
                                   f"engine ID {s.engine_id}" if s.engine_id else "") if x) + " left out")
    for u in s.users:
        label = snmp_text.user_label(u)
        report.item("management", label)
        keys = snmp_text.user_keys(u, report)
        v3group = s.groups.get(u.group)
        role = "network-admin" if v3group is not None and v3group.write_view else "network-operator"
        if u.group in ("network-admin", "network-operator"):
            role = u.group
        elif u.group:
            report.add("management", label, Severity.APPROX, "snmp-group",
                       f"NX-OS gives an SNMPv3 user a role, not a group: group {u.group} is written as role {role}")
        words = [f"snmp-server user {u.name} {role}"]
        if u.auth:
            auth = snmp_text.pick(u.auth, AUTH, report, label)
            words.append(f"auth {'sha-256' if auth == 'sha256' else 'sha-384' if auth == 'sha384' else 'sha-512' if auth == 'sha512' else auth} {keys[0]}")
        if u.priv:
            priv = snmp_text.pick(u.priv, PRIV, report, label)
            words.append(f"priv {'aes-128 ' if priv == 'aes128' else ''}{keys[1]}")
        lines.append(" ".join(words))
    for g in s.groups.values():
        if not any(u.group == g.name for u in s.users):
            report.item("management", f"SNMPv3 group {g.name}")
            report.add("management", f"SNMPv3 group {g.name}", Severity.APPROX, "snmp-group",
                       "NX-OS has no SNMP groups; its users take a role, so the group without users is left out")
    if s.traps:
        report.item("management", "snmp traps")
        if s.trap_types:
            lines += [f"snmp-server enable traps {t}" for t in s.trap_types]
            report.add("management", "snmp traps", Severity.APPROX, "trap-types",
                       "the notifications are written with the source's keywords; check that NX-OS takes each one")
        else:
            lines.append("snmp-server enable traps")
    for h in s.hosts:
        label = snmp_text.host_label(h)
        report.item("management", label)
        words = ["snmp-server host", h.address, "informs" if h.informs else "traps", "version", h.version]
        words += [h.level] if h.version == "3" and h.level else []
        words.append(h.secret if h.version == "3" else snmp_text.secret(h.secret, report, "management", label,
                                                                        "community"))
        lines.append(" ".join(words))
        host_vrf = h.vrf or s.vrf
        if host_vrf:
            lines.append(f"snmp-server host {h.address} use-vrf {vrf(host_vrf)}")
    if s.source:
        lines.append(f"snmp-server source-interface traps {port(s.source)}")
        lines.append(f"snmp-server source-interface informs {port(s.source)}")
    if s.vrf and not s.hosts:
        report.add("management", "snmp vrf", Severity.APPROX, "snmp-vrf",
                   f"NX-OS answers SNMP in every VRF; the agent VRF {s.vrf} is left out")
    return lines


def l2sec_lines(device: Device, report: Report, features: Set[str]) -> List[str]:
    d = device
    lines: List[str] = []
    vlans = l2sec_text.snooping_vlans_written(d, report)
    if d.dhcp_snooping or vlans:
        features.add("dhcp")
        report.item("vlan", "DHCP snooping")
        lines.append("ip dhcp snooping")
        if vlans:
            lines.append(f"ip dhcp snooping vlan {l2sec_text.vlan_text(vlans)}")
        if d.dhcp_option82:
            lines.append("ip dhcp snooping information option")
    elif d.dhcp_option82:
        report.item("system", "DHCP snooping")
        report.add("system", "DHCP snooping", Severity.APPROX, "option82",
                   "NX-OS inserts option 82 from DHCP snooping, which the source does not run; left out")
    vlans = l2sec_text.inspection_vlans(d)
    if vlans:
        features.add("dhcp")
        report.item("vlan", "ARP inspection")
        lines.append(f"ip arp inspection vlan {l2sec_text.vlan_text(vlans)}")
    return lines


def port_lines(device: Device, iface: Interface, add: Add, label: str, report: Report, features: Set[str]) -> List[str]:
    """802.1X, DHCP snooping trust, ARP inspection, source guard, port security."""
    lines: List[str] = []
    if iface.dhcp_trust:
        features.add("dhcp")
        lines.append("ip dhcp snooping trust")
    if iface.arp_trust:
        features.add("dhcp")
        lines.append("ip arp inspection trust")
    if iface.source_guard:
        features.add("dhcp")
        lines.append("ip verify source dhcp-snooping-vlan")
    if iface.port_security:
        features.add("port-security")
        lines.append("switchport port-security")
        if iface.port_security_max is not None:
            lines.append(f"switchport port-security maximum {iface.port_security_max}")
        if iface.port_security_violation and iface.port_security_violation != "shutdown":
            lines.append(f"switchport port-security violation {iface.port_security_violation}")
    if iface.dot1x or iface.mab:
        features.add("dot1x")
        mode = iface.dot1x_host_mode or "single-host"
        if HOST_MODES.get(mode, "multi-host") != mode:
            add(Severity.APPROX, "dot1x-host-mode",
                f"NX-OS has single-host and multi-host only: {mode} is written as multi-host, where the first "
                "host to log in opens the port for every host")
        if iface.dot1x:
            lines.append("dot1x pae authenticator")
        lines.append("dot1x port-control auto")
        lines.append(f"dot1x host-mode {HOST_MODES.get(mode, 'multi-host')}")
        if iface.mab:
            lines.append("dot1x mac-auth-bypass")
        if iface.dot1x_reauth:
            lines.append("dot1x re-authentication")
        if iface.dot1x_reauth_period:
            lines.append(f"dot1x timeout re-authperiod {iface.dot1x_reauth_period}")
    if iface.dot1x_fail_vlan is not None:
        add(Severity.REVIEW, "dot1x-fail-vlan",
            f"NX-OS has no 802.1X fail VLAN: a client that fails stays blocked rather than going to VLAN "
            f"{iface.dot1x_fail_vlan}")
    if hosts_text.poe_stated(iface):
        add(Severity.REVIEW, "poe", "NX-OS switches give no PoE; power the device another way")
    if iface.voice_vlan is not None:
        add(Severity.REVIEW, "voice-vlan",
            f"NX-OS data-centre switches have no voice VLAN; VLAN {iface.voice_vlan} for phones is left out: tag it "
            "on a trunk if the phones need it")
    return lines


def layer3_lines(iface: Interface, add: Add, port: Port) -> List[str]:
    """Unicast RPF, ICMP, proxy ARP, the SVI MAC, autostate and unnumbered."""
    lines: List[str] = []
    if iface.kind == InterfaceKind.VLAN and iface.autostate is False:
        lines.append("no autostate")
    if iface.mac_address:
        if iface.kind == InterfaceKind.VLAN:
            digits = iface.mac_address.replace(":", "")
            lines.append(f"mac-address {digits[0:4]}.{digits[4:8]}.{digits[8:12]}")
        else:
            add(Severity.REVIEW, "svi-mac", "NX-OS sets a routed MAC on SVIs here; left out")
    if iface.unnumbered:
        if iface.kind == InterfaceKind.ETHERNET:
            lines.append("medium p2p")
        lines.append(f"ip unnumbered {port(iface.unnumbered)}")
    if iface.urpf:
        lines.append("ip verify unicast source reachable-via " + ("rx" if iface.urpf == "strict" else "any"))
    for word, value in (("redirects", iface.ip_redirects), ("unreachables", iface.ip_unreachables),
                        ("proxy-arp", iface.proxy_arp)):
        if value is not None:
            lines.append(f"{'' if value else 'no '}ip {word}")
    return lines


def relay_lines(iface: Interface, vrf: Vrf, port: Port) -> List[str]:
    lines = [f"ip dhcp relay address {helper}" + (f" use-vrf {vrf(iface.helper_vrf)}"
                                                    if iface.helper_vrf and iface.helper_vrf != "global" else "")
             for helper in iface.helper_addresses]
    if iface.helper_addresses and iface.helper_source:
        lines.append(f"ip dhcp relay source-interface {port(iface.helper_source)}")
    return lines


def unwritable(device: Device, report: Report) -> None:
    from . import dhcp as dhcp_text
    for pool in device.dhcp_pools:
        label = dhcp_text.label(pool)
        report.item("dhcp", label)
        report.skip("dhcp", label, "dhcp-server",
                    "NX-OS has no DHCP server; serve the scope from a DHCP server and relay to it")


def transfer_lines(device: Device, port: Port) -> List[str]:
    return [f"ip {protocol} source-interface {port(source)}"
            for protocol, source in device.system.transfer_source.items() if protocol in ("tftp", "ftp")]


def finish_snmp(device: Device, host_vrfs: Dict[str, str]) -> None:
    """NX-OS reader: the VRF lines of the notification hosts."""
    for h in device.snmp.hosts:
        if h.address in host_vrfs:
            h.vrf = host_vrfs[h.address]
