# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for HPE Aruba AOS-S (ProCurve / ProVision, 16.x).

The model's ports carry their VLANs; AOS-S lists the ports in each VLAN, so the
writer gathers them per VLAN. What AOS-S cannot do is written the nearest way
and reported: a routed port becomes a port in a VLAN of its own with the address
on the VLAN, and VRFs other than the management one do not exist.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from .. import acl as acl_text
from .. import dhcp as dhcp_text
from .. import l2sec as l2sec_text
from .. import mgmt as mgmt_text
from .. import mpls as mpls_text
from .. import nat as nat_text
from .. import wlan as wlan_text
from .. import vpn as vpn_text
from .. import vrfs as vrfs_text
from .. import multicast as multicast_text
from .. import bfd as bfd_text
from .. import igp as igp_text
from .. import routemap as routemap_text
from .. import fhrp
from .. import ospf as ospf_text
from .. import stp as stp_text
from .. import qos as qos_text
from .. import snmp as snmp_text
from .. import aaa as aaa_text
from ..model import Device, FhrpGroup, Interface, InterfaceKind, LacpMode, StaticRoute, StpMode, SwitchportMode, Vlan
from ..names import PortMapper
from ..parsers.ioslike import _vlan_ids
from ..report import Report, Severity
from ..timezones import offset_minutes

_IND = "   "
_PORT = re.compile(r"^(.*?)(\d+)$")
_TRANSIT_VLANS = range(3999, 3000, -1)  # where a routed port's VLAN is taken from


_AOSS_ACTIONS = {"send-disable": "shutdown", "send-alarm": "restrict", "none": "protect"}


def port_list(names: List[str]) -> str:
    """``1,2,3,5,Trk1`` as ``1-3,5,Trk1``."""
    parsed: List[Tuple[str, int, str]] = []
    for name in names:
        m = _PORT.match(name)
        parsed.append((m.group(1), int(m.group(2)), name) if m else (name, -1, name))
    parsed.sort(key=lambda p: (p[0].lower().startswith("trk"), p[0], p[1]))
    parts: List[str] = []
    i = 0
    while i < len(parsed):
        prefix, number, name = parsed[i]
        j = i
        while (number >= 0 and j + 1 < len(parsed) and parsed[j + 1][0] == prefix
               and parsed[j + 1][1] == parsed[j][1] + 1):
            j += 1
        parts.append(name if j == i else f"{name}-{parsed[j][2]}")
        i = j + 1
    return ",".join(parts)


def _quote(text: str) -> str:
    return '"' + text.replace('"', "'") + '"'


_SNMP_LEVEL_GROUP = {"priv": "managerpriv", "auth": "managerauth", "noauth": "operatornoauth"}


class Writer:
    def __init__(self, device: Device, ports: PortMapper, report: Report) -> None:
        self.device = device
        self.port = ports
        self.report = report
        self.out: List[str] = []
        self.mgmt_vrfs = {i.vrf for i in device.interfaces.values() if i.kind == InterfaceKind.MANAGEMENT and i.vrf}
        self.vlans: Dict[int, Vlan] = dict(device.vlans)
        self.untagged: Dict[int, List[str]] = {}
        self.tagged: Dict[int, List[str]] = {}
        self.no_untagged: List[str] = []
        self.svis: Dict[int, Interface] = {}
        self.svi_source: Dict[int, str] = {}  # VLAN of a routed port -> the port
        self.ospf_areas: Dict[str, str] = {}  # interface -> area, of the one process AOS-S runs
        self.voice: Set[int] = set()
        self.gateway_only: Optional[StaticRoute] = None  # the one default route, written as ip default-gateway

    def label(self, iface: Interface) -> str:
        return f"{iface.source_name or iface.name} -> {self.port(iface.name)}"

    def add(self, iface: Interface, severity: Severity, code: str, message: str) -> None:
        self.report.add("interface", self.label(iface), severity, code, message)

    def emit(self) -> str:
        self.gather()
        self.system()
        self.routing_mode()
        self.trunks()
        self.oobm()
        self.acls()
        self.qos()
        self.interfaces()
        self.l2sec()
        self.routes()
        self.vlan_blocks()
        self.spanning_tree()
        self.dhcp()
        nat_text.skip_all(self.device, self.report, "AOS-S")
        mpls_text.unsupported(self.device, self.report, "AOS-S")
        wlan_text.unsupported(self.device, self.report, "AOS-S")
        vpn_text.skip_all(self.device, self.report, "AOS-S")
        vrfs_text.no_vrfs(self.device, self.report, "AOS-S")
        routemap_text.unsupported(self.device, self.report, "AOS-S")
        bfd_text.unsupported(self.device, self.report, "AOS-S")
        igp_text.unsupported(self.device, self.report, "AOS-S")
        multicast_text.pim_unsupported(self.device, self.report, "AOS-S")
        if multicast_text.stated(self.device):
            self.report.item("vlan", multicast_text.LABEL)
        routemap_text.ospf_maps_unsupported(self.device, self.report, "AOS-S")
        vrfs_text.mlag_unsupported(self.device, self.report, "AOS-S",
                                   "AOS-S pairs switches with distributed trunking; configure it by hand")
        if self.device.bgp is not None:
            self.report.skip("bgp", f"bgp {self.device.bgp.local_as}", "bgp",
                             "not written: BGP on AOS-S depends on the model and release; configure it by hand")
        self.report.unparsed(self.device.unparsed)
        return "\n".join(self.out) + "\n"

    # VLAN membership -------------------------------------------------------------------------------------------------

    def gather(self) -> None:
        used = set(self.vlans) | {i.access_vlan for i in self.device.interfaces.values() if i.access_vlan}
        transit = (v for v in _TRANSIT_VLANS if v not in used)
        for iface in self.device.interfaces.values():
            if iface.kind == InterfaceKind.VLAN:
                self.svis[int(iface.name[len("Vlan"):])] = iface
        for iface in self.device.interfaces.values():
            name = self.port(iface.name)
            if iface.kind == InterfaceKind.SUBINTERFACE:
                self.report.skip("interface", self.label(iface), "subinterface",
                                 "AOS-S has no subinterfaces; carry the VLAN on a tagged port and put the address on "
                                 "the VLAN")
                continue
            if iface.kind == InterfaceKind.TUNNEL:
                self.report.skip("interface", self.label(iface), "tunnel",
                                 "tunnel interfaces are not converted for AOS-S; configure it by hand")
                continue
            if iface.kind not in (InterfaceKind.ETHERNET, InterfaceKind.LAG) or iface.lag:
                continue
            if iface.kind == InterfaceKind.LAG:
                self.report.item("interface", self.label(iface))
            if iface.mode == SwitchportMode.ROUTED:
                vid = next(transit)
                self.vlans[vid] = Vlan(vid, name=f"routed {name}")
                svi = Interface(f"Vlan{vid}", InterfaceKind.VLAN, ipv4=list(iface.ipv4), ipv6=list(iface.ipv6),
                                dhcp_client=iface.dhcp_client, helper_addresses=list(iface.helper_addresses),
                                vrf=iface.vrf, acl_in=iface.acl_in, acl_out=iface.acl_out,
                                acl6_in=iface.acl6_in, acl6_out=iface.acl6_out, fhrp=list(iface.fhrp),
                                ospf_cost=iface.ospf_cost, ospf_network=iface.ospf_network)
                self.svis[vid] = svi
                self.svi_source[vid] = iface.name
                self.untagged.setdefault(vid, []).append(name)
                self.add(iface, Severity.APPROX, "routed-port",
                         f"AOS-S has no routed ports: the port is untagged in VLAN {vid} of its own, which carries "
                         "the address")
            elif iface.mode == SwitchportMode.ACCESS:
                self.untagged.setdefault(iface.access_vlan or 1, []).append(name)
                if iface.voice_vlan is not None:
                    self.tagged.setdefault(iface.voice_vlan, []).append(name)
                    self.voice.add(iface.voice_vlan)
            else:
                native = iface.native_vlan or 1
                allowed = _vlan_ids(iface.allowed_vlans) if iface.allowed_vlans else sorted(self.vlans)
                if not iface.allowed_vlans:
                    self.add(iface, Severity.APPROX, "trunk-all",
                             "the trunk allows all VLANs; AOS-S tags a port per VLAN, so it is tagged in every VLAN "
                             "of the configuration")
                if native in allowed or not iface.allowed_vlans:
                    self.untagged.setdefault(native, []).append(name)
                else:
                    self.no_untagged.append(name)  # untagged frames are dropped, as on the source
                for vid in allowed:
                    if vid != native:
                        self.tagged.setdefault(vid, []).append(name)
        if self.no_untagged:
            self.vlans.setdefault(1, Vlan(1, name="DEFAULT_VLAN"))  # ports start untagged in it
        for vid in set(self.untagged) | set(self.tagged):
            self.vlans.setdefault(vid, Vlan(vid))
        self.groups = {vid: fhrp.plan(svi, "aoss", self.report, f"vlan {vid}")
                       for vid, svi in self.svis.items() if svi.fhrp}

    # system ----------------------------------------------------------------------------------------------------------

    def system(self) -> None:
        s = self.device.system
        rep = self.report
        if s.hostname:
            self.out.append(f"hostname {_quote(s.hostname)}")
            rep.item("system", "hostname")
        if s.timezone:
            minutes = offset_minutes(s.timezone)
            if minutes is None:
                rep.add("system", "time zone", Severity.REVIEW, "timezone",
                        f"time zone '{s.timezone}' has no fixed offset; AOS-S takes 'time timezone <minutes>' and "
                        "'time daylight-time-rule'; set it by hand")
            else:
                self.out.append(f"time timezone {minutes}")
                rep.add("system", "time zone", Severity.APPROX, "timezone",
                        "written as a fixed offset; add 'time daylight-time-rule' if the zone has summer time")
        servers = sorted(s.ntp_servers, key=lambda server: server != s.ntp_prefer)  # the preferred one first
        if s.ntp_servers and (s.ntp_keys or s.ntp_authenticate):
            self.out += ["timesync ntp", "ntp unicast"]
            for key in s.ntp_keys.values():
                rep.item("system", f"ntp key {key.number}")
                algorithm = key.algorithm
                if algorithm not in ("md5", "sha1"):
                    algorithm = "sha1"
                    rep.add("system", f"ntp key {key.number}", Severity.REVIEW, "ntp-algorithm",
                            f"{key.algorithm} is not offered; sha1 is written, so the servers must use it too")
                self.out.append(f"ntp authentication key-id {key.number} authentication-mode {algorithm} key-value "
                                f"{_quote(snmp_text.ntp_key(key, rep))}" + (" trusted" if key.trusted else ""))
            for server in servers:
                keyed = f" key {s.ntp_server_keys[server]}" if server in s.ntp_server_keys else ""
                self.out.append(f"ntp server {server}{keyed} iburst")
            self.out.append("ntp enable")
            rep.item("system", "ntp servers")
        elif s.ntp_servers:
            self.out += ["timesync sntp", "sntp unicast"]
            self.out += [f"sntp server priority {n} {server}" for n, server in enumerate(servers, 1)]
            rep.item("system", "ntp servers")
        if s.ntp_prefer and s.ntp_servers:
            rep.add("system", "ntp servers", Severity.APPROX, "ntp-prefer",
                    f"AOS-S has no preferred NTP server; {s.ntp_prefer} is listed first")
        if s.ntp_source and s.ntp_servers:
            rep.add("system", "ntp servers", Severity.REVIEW, "ntp-source",
                    f"NTP source interface {s.ntp_source} is not written; set 'ip source-interface' by hand")
        if s.domain_name:
            self.out.append(f"ip dns domain-name {_quote(s.domain_name)}")
            rep.item("system", "domain name")
        for n, server in enumerate(s.dns_servers, 1):
            self.out.append(f"ip dns server-address priority {n} {server}")
        if s.dns_servers:
            rep.item("system", "name servers")
        for host in s.syslog_servers:
            self.out.append(f"logging {host}")
        if s.syslog_servers:
            rep.item("system", "syslog servers")
        if s.logging_level is not None:
            rep.item("system", "syslog level")
            self.out.append(f"logging severity {mgmt_text.aoss_level(s.logging_level, rep)}")
        if s.logging_source.startswith(("Vlan", "Loopback")):
            kind = "vlan" if s.logging_source.startswith("Vlan") else "loopback"
            self.out.append(f"ip source-interface syslog {kind} {s.logging_source.lstrip('VlanLoopback')}")
            rep.item("system", "syslog source")
        elif s.logging_source:
            rep.add("system", "syslog source", Severity.REVIEW, "syslog-source",
                    f"source {s.logging_source} is not a VLAN or loopback; set 'ip source-interface syslog' by hand")
        self.management()
        self.snmp()
        self.users()
        self.aaa()
        if s.service_vrf and s.service_vrf in self.mgmt_vrfs:
            rep.add("system", "service vrf", Severity.APPROX, "oobm",
                    "the source reaches its servers through the management VRF; AOS-S picks the out-of-band port "
                    "by route, so check that the servers are reachable from oobm")
        if s.banner_motd:
            self.out.append(f"banner motd {_quote(s.banner_motd)}")
            rep.item("system", "banner motd")
        for vrf in self.device.vrfs:
            if vrf not in self.mgmt_vrfs:
                rep.add("system", f"vrf {vrf}", Severity.REVIEW, "vrf",
                        "AOS-S has no VRFs: its interfaces and routes are written in the one routing table")

    def users(self) -> None:
        if self.device.aaa.enable_secret is not None:
            self.report.skip("management", "enable secret", "enable-secret",
                             "AOS-S has no enable secret: the manager password gives full rights")
        taken = set()
        for u in self.device.users:
            label = aaa_text.user_label(u)
            level = "manager" if (u.privilege or 1) >= 15 else "operator"
            if level in taken:
                self.report.skip("management", label, "aoss-users",
                                 f"AOS-S has one {level} user; create the others with local-user accounts by hand")
                continue
            found = aaa_text.password(u, ("aoss-sha1",), self.report)
            if found is None:
                continue
            form, value = found
            if form == "none":
                self.report.skip("management", label, "no-password", "the user has no password in the source")
                continue
            taken.add(level)
            self.report.item("management", label)
            if u.privilege not in (None, 1, 15):
                self.report.add("management", label, Severity.APPROX, "privilege",
                                f"privilege {u.privilege} becomes the {level} user; AOS-S has no levels in between")
            self.out.append(f"password {level} user-name {_quote(u.name)} "
                            f"{'plaintext' if form == 'plain' else 'sha1'} {_quote(value)}")

    def _aaa_methods(self, methods: List[str], label: str) -> str:
        """'tacacs [server-group G] local' for at most two methods."""
        words = []
        kept = [m for m in methods if m.startswith("group:") or m in ("local", "none")]
        if len(kept) != len(methods) or len(kept) > 2:
            self.report.add("management", label, Severity.APPROX, "aaa-method",
                            "AOS-S takes a primary and a secondary method of radius, tacacs, local or none; "
                            f"written as {', '.join(kept[:2]) or 'local'}")
        for m in kept[:2] or ["local"]:
            if m.startswith("group:"):
                protocol = aaa_text.protocol_of(self.device, m) or "tacacs"
                name = m[len("group:"):]
                words.append(protocol if name == protocol else f"{protocol} server-group {_quote(name)}")
            else:
                words.append(m)
        return " ".join(words)

    def aaa(self) -> None:
        a = self.device.aaa
        rep = self.report
        for s in a.servers:
            label = aaa_text.server_label(s)
            rep.item("management", label)
            words = [f"{s.protocol}-server host {s.address}"]
            if s.protocol == "radius":
                words += [f"auth-port {s.auth_port}"] if s.auth_port else []
                words += [f"acct-port {s.acct_port}"] if s.acct_port else []
            elif s.auth_port and s.auth_port != 49:
                rep.add("management", label, Severity.REVIEW, "aaa-port", f"port {s.auth_port} left out: AOS-S uses 49")
            if s.vrf:
                rep.add("management", label, Severity.APPROX, "aaa-vrf", f"VRF {s.vrf} left out: AOS-S has no VRFs")
            self.out.append(" ".join(words + [f"key {_quote(aaa_text.key(s, rep))}"]))
        for g in a.groups.values():
            rep.item("management", f"{g.protocol} group {g.name}")
            self.out += [f"aaa server-group {g.protocol} {_quote(g.name)} host {address}" for address in g.servers]
        for protocol, source in a.source.items():
            if source.startswith(("Vlan", "Loopback")):
                kind = "vlan" if source.startswith("Vlan") else "loopback"
                self.out.append(f"ip source-interface {protocol} {kind} {source.lstrip('VlanLoopback')}")
            else:
                rep.add("management", f"{protocol} source", Severity.REVIEW, "aaa-source",
                        f"source {source} is not a VLAN or loopback; set 'ip source-interface' by hand")
        self._port_access()
        for m in a.methods:
            if m.service == "dot1x":
                continue  # written with the port access settings
            label = aaa_text.method_label(m)
            access = "ssh" if m.name == "default" else m.name
            if m.kind == "authentication" and access in ("ssh", "telnet", "console", "web"):
                rep.item("management", label)
                self.out.append(f"aaa authentication {access} {m.service} {self._aaa_methods(m.methods, label)}")
            elif m.kind == "authorization" and m.service == "commands" and m.name == "default":
                rep.item("management", label)
                self.out.append(f"aaa authorization commands {self._aaa_methods(m.methods, label)}")
            elif m.kind == "accounting" and m.name == "default":
                rep.item("management", label)
                record = m.record or "start-stop"
                if m.service == "commands" and record == "start-stop":
                    record = "stop-only"
                    rep.add("management", label, Severity.APPROX, "aaa-record",
                            "AOS-S accounts commands as stop-only")
                self.out.append(f"aaa accounting {m.service} {record} {self._aaa_methods(m.methods, label)}")
            else:
                rep.skip("management", label, "aaa-list",
                         "AOS-S has no such list (only per-access authentication, command authorization and "
                         "default accounting); configure it by hand")

    def management(self) -> None:
        """SSH, Telnet and web servers, the session timeout, LLDP (with per-port admin status) and CDP."""
        d = self.device
        m = d.management
        rep = self.report
        mgmt_text.items(d, rep)
        if m.ssh is not None:
            self.out.append("ip ssh" if m.ssh else "no ip ssh")
        if m.telnet is not None:
            self.out.append("telnet-server" if m.telnet else "no telnet-server")
        for name, value in (("plaintext", m.http), ("ssl", m.https)):
            if value is not None:
                self.out.append(f"{'' if value else 'no '}web-management {name}")
        if m.vty_acl:
            rep.add("management", "remote login ACL", Severity.REVIEW, "mgmt-acl",
                    f"AOS-S limits management access with 'ip authorized-managers'; write ACL {m.vty_acl} as such by "
                    "hand")
        if m.exec_timeout is not None:
            self.out.append(f"console idle-timeout {m.exec_timeout * 60}")
        if m.vrf:
            rep.add("management", "ssh server", Severity.APPROX, "mgmt-vrf",
                    f"AOS-S has no VRFs; the servers listen on every interface (the source used VRF {m.vrf})")
        if m.lldp is not None:
            self.out.append("lldp run" if m.lldp else "no lldp run")
        if m.cdp is not None:
            self.out.append("cdp run" if m.cdp else "no cdp run")
        for status, tx, rx in (("txonly", True, False), ("rxonly", False, True), ("disable", False, False)):
            names = [self.port(i.name) for i in d.interfaces.values() if (i.lldp_tx, i.lldp_rx) == (tx, rx)]
            if names:
                self.out.append(f"lldp admin-status {port_list(names)} {status}")

    def _port_access(self) -> None:
        """802.1X (authenticator) and MAC authentication (mac-based) on the ports, and the servers they use."""
        a = self.device.aaa
        rep = self.report
        for protocol, source in self.device.system.transfer_source.items():
            if protocol == "tftp" and source.startswith(("Vlan", "Loopback")):
                kind = "vlan" if source.startswith("Vlan") else "loopback"
                self.out.append(f"ip source-interface tftp {kind} {source.lstrip('VlanLoopback')}")
                rep.item("system", "tftp source")
            elif protocol == "tftp":
                rep.add("system", "tftp source", Severity.REVIEW, "transfer-source",
                        f"source {source} is not a VLAN or loopback; set 'ip source-interface tftp' by hand")
            else:
                rep.skip("system", f"{protocol} source", "transfer-source",
                         "AOS-S has no FTP client source setting; it copies files with TFTP, SFTP or SCP")
        method = next((m for m in a.methods if m.service == "dot1x"), None)
        ports = [i for i in self.device.interfaces.values() if (i.dot1x or i.mab) and not i.lag]
        if method is not None and (ports or a.dot1x):
            label = aaa_text.method_label(method)
            rep.item("management", label)
            group = next((x[len("group:"):] for x in method.methods if x.startswith("group:")), "radius")
            if len(method.methods) != 1:
                rep.add("management", label, Severity.APPROX, "aaa-method",
                        f"AOS-S authenticates ports against one RADIUS group; written as {group}")
            server_group = "" if group == "radius" else f" server-group {_quote(group)}"
            self.out.append(f"aaa authentication port-access eap-radius{server_group}")
            if any(i.mab for i in ports):
                self.out.append(f"aaa authentication mac-based chap-radius{server_group}")
        dot1x = [i for i in ports if i.dot1x]
        mab = [i for i in ports if i.mab]
        if dot1x:
            self.out.append(f"aaa port-access authenticator {port_list([self.port(i.name) for i in dot1x])}")
        for i in dot1x:
            name = self.port(i.name)
            limit = self._client_limit(i)
            if limit:
                self.out.append(f"aaa port-access authenticator {name} client-limit {limit}")
            if i.dot1x_reauth:
                self.out.append(f"aaa port-access authenticator {name} reauth-period {i.dot1x_reauth_period or 3600}")
        if a.dot1x:
            self.out.append("aaa port-access authenticator active")
            rep.item("management", "802.1X")
        if mab:
            self.out.append(f"aaa port-access mac-based {port_list([self.port(i.name) for i in mab])}")
        for i in mab:
            limit = self._client_limit(i)
            if limit and limit != 1:
                self.out.append(f"aaa port-access mac-based {self.port(i.name)} addr-limit {limit}")

    def _client_limit(self, i: Interface) -> int:
        """The client limit for a port's host mode; 0 = none (the port opens for all once one client logs in)."""
        mode = i.dot1x_host_mode or "single-host"
        if mode == "multi-domain":
            self.report.add("interface", f"{i.source_name or i.name} -> {self.port(i.name)}", Severity.APPROX,
                            "dot1x-host-mode", "multi-domain written as up to 32 clients: AOS-S has no separate voice "
                            "domain")
        return {"single-host": 1, "multi-host": 0}.get(mode, 32)

    def snmp(self) -> None:
        s = self.device.snmp
        rep = self.report
        for c in s.communities:
            label = snmp_text.community_label(self.device, c)
            rep.item("management", label)
            name = snmp_text.secret(c.name, rep, "management", label, "community")
            self.out.append(f"snmp-server community {_quote(name)} " +
                            ("operator restricted" if c.access == "ro" else "manager unrestricted"))
            if c.acl:
                rep.add("management", label, Severity.REVIEW, "snmp-acl",
                        f"ACL {c.acl} is not written for the community; use 'ip authorized-managers' by hand")
        if s.location:
            self.out.append(f"snmp-server location {_quote(s.location)}")
            rep.item("management", "snmp location")
        if s.contact:
            self.out.append(f"snmp-server contact {_quote(s.contact)}")
            rep.item("management", "snmp contact")
        for h in s.hosts:
            label = snmp_text.host_label(h)
            if h.version == "3":
                rep.skip("management", label, "snmp-v3-host",
                         "SNMPv3 notification targets are not written for AOS-S; add 'snmpv3 targetaddress' by hand")
                continue
            rep.item("management", label)
            secret = snmp_text.secret(h.secret, rep, "management", label, "community")
            self.out.append(f"snmp-server host {h.address} community {_quote(secret)}" + (" inform" if h.informs else ""))
            if h.vrf:
                rep.add("management", label, Severity.APPROX, "snmp-vrf", f"VRF {h.vrf} left out: AOS-S has no VRFs")
        if s.users:
            self.out.append("snmpv3 enable")
        for u in s.users:
            label = snmp_text.user_label(u)
            rep.item("management", label)
            keys = snmp_text.user_keys(u, rep)
            words = [f"snmpv3 user {_quote(u.name)}"]
            if u.auth:
                words.append(f"auth {snmp_text.pick(u.auth, ['md5', 'sha'], rep, label)} {_quote(keys[0])}")
            if u.priv:
                priv = snmp_text.pick(u.priv, ["des", "aes128"], rep, label)
                words.append(f"priv {'aes' if priv == 'aes128' else priv} {_quote(keys[1])}")
            self.out.append(" ".join(words))
            group = u.group if u.group.startswith(("manager", "operator")) else _SNMP_LEVEL_GROUP[snmp_text.level(u)]
            if group != u.group:
                rep.add("management", label, Severity.APPROX, "snmp-group",
                        f"in AOS-S group {group}, as AOS-S has fixed groups" + (f" (was {u.group})" if u.group else ""))
            self.out.append(f"snmpv3 group {group} user {_quote(u.name)} sec-model ver3")
        if s.source:
            rep.add("management", "snmp source", Severity.REVIEW, "snmp-source",
                    f"SNMP source interface {s.source} is not written; set 'ip source-interface' by hand")

    def routing_mode(self) -> None:
        routes = [r for r in self.device.static_routes if r.vrf not in self.mgmt_vrfs]
        l3_vlans = [v for v in self.svis.values() if v.ipv4 or v.dhcp_client]
        default = [r for r in routes if r.prefix == "0.0.0.0/0" and r.next_hop]
        vrrp = any(self.groups.values()) or bool(self.device.ospf)
        if len(routes) == 1 and default and len(l3_vlans) <= 1 and not vrrp:
            self.out.append(f"ip default-gateway {default[0].next_hop}")  # a layer 2 switch
            self.report.item("route", "0.0.0.0/0")
            self.gateway_only = default[0]
            return
        if routes or len(l3_vlans) > 1 or vrrp:
            self.out.append("ip routing")
        if any(self.groups.values()):
            self.out += ["router vrrp", f"{_IND}ipv4 enable", f"{_IND}exit"]
        self.ospf()

    def trunks(self) -> None:
        lags: Dict[str, List[Interface]] = {}
        for iface in self.device.interfaces.values():
            if iface.lag:
                lags.setdefault(iface.lag, []).append(iface)
        for lag, members in lags.items():
            modes = {m.lacp_mode for m in members}
            word = "trunk" if modes <= {LacpMode.STATIC, None} else "lacp"
            names = [self.port(m.name) for m in members]
            self.out.append(f"trunk {port_list(names)} {self.port(lag).lower()} {word}")
            if LacpMode.PASSIVE in modes:
                self.report.add("interface", f"{lag} -> {self.port(lag)}", Severity.APPROX, "lacp-passive",
                                "AOS-S trunks are LACP active; the source was passive")

    def oobm(self) -> None:
        for iface in self.device.interfaces.values():
            if iface.kind != InterfaceKind.MANAGEMENT:
                continue
            self.report.item("interface", self.label(iface))
            lines: List[str] = []
            if iface.dhcp_client:
                lines.append("ip address dhcp-bootp")
            for n, cidr in enumerate(iface.ipv4):
                if n:
                    self.add(iface, Severity.REVIEW, "mgmt-secondary", f"oobm takes one address; {cidr} left out")
                    continue
                net = ipaddress.ip_interface(cidr)
                lines.append(f"ip address {net.ip} {net.netmask}")
            for route in self.device.static_routes:
                if route.vrf and route.vrf == iface.vrf and route.prefix == "0.0.0.0/0" and route.next_hop:
                    lines.append(f"ip default-gateway {route.next_hop}")
            lines.append("disable" if iface.shutdown else "enable")
            self.out.append("oobm")
            self.out += [_IND + line for line in lines]
            self.out.append(_IND + "exit")

    def interfaces(self) -> None:
        for iface in self.device.interfaces.values():
            if iface.kind == InterfaceKind.LOOPBACK:
                self.out.append(f"interface loopback {iface.name[len('Loopback'):]}")
                for cidr in iface.ipv4:
                    net = ipaddress.ip_interface(cidr)
                    self.out.append(f"{_IND}ip address {net.ip} {net.netmask}")
                self.out.append(_IND + "exit")
                self.report.item("interface", self.label(iface))
                continue
            if iface.kind not in (InterfaceKind.ETHERNET,):
                continue
            label = self.label(iface)
            self.report.item("interface", label)
            if (iface.source_name or iface.name, self.port(iface.name)) in self.port.renumbered:
                self.add(iface, Severity.APPROX, "port-renamed",
                         f"named {self.port(iface.name)} without a port map; check it against the cabling of the "
                         "new device")
            lines: List[str] = []
            if iface.description:
                lines.append(f"name {_quote(iface.description)}")
            if iface.mode != SwitchportMode.ROUTED:  # a routed port's lists go to its VLAN
                lines += self._acl_bindings(iface)
                lines += self._qos_bindings(iface)
                levels = l2sec_text.storm(iface, "unknown-unicast", ["broadcast"], self.report, label, "AOS-S")
                for level in levels.values():
                    if level != int(level):
                        self.add(iface, Severity.APPROX, "storm-control",
                                 f"AOS-S takes whole percents: broadcast limit {level:g}% written as {round(level)}%")
                    lines.append(f"broadcast-limit {round(level)}")
            if iface.shutdown:
                lines.append("disable")
            if iface.speed is not None:
                lines.append(f"speed-duplex {iface.speed}-{iface.duplex or 'full'}")
                self.add(iface, Severity.APPROX, "speed", "forced speed: check that the port takes it")
            if iface.mtu is not None and iface.mtu > 1522:
                self.add(iface, Severity.APPROX, "mtu",
                         f"MTU {iface.mtu}: AOS-S sets jumbo frames per VLAN ('jumbo' in the VLAN), not per port")
            if lines:
                self.out.append(f"interface {self.port(iface.name)}")
                self.out += [_IND + line for line in lines]
                self.out.append(_IND + "exit")

    def routes(self) -> None:
        for route in self.device.static_routes:
            label = f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}"
            if route.vrf in self.mgmt_vrfs:
                self.report.item("route", label)
                if route.prefix != "0.0.0.0/0":
                    self.report.add("route", label, Severity.REVIEW, "oobm-route",
                                    "oobm takes only a default gateway; this route is left out")
                continue
            if self.gateway_only is route:
                continue
            self.report.item("route", label)
            if route.vrf:
                self.report.add("route", label, Severity.APPROX, "vrf",
                                f"VRF {route.vrf} does not exist on AOS-S; written in the one routing table")
            net = ipaddress.ip_network(route.prefix)
            if net.version == 4:
                words = ["ip", "route", str(net.network_address), str(net.netmask)]
            else:
                words = ["ipv6", "route", str(net)]
            if route.discard:
                words.append("blackhole")
            elif route.next_hop:
                words.append(route.next_hop)
            elif route.interface.startswith("Vlan"):
                words += ["vlan", route.interface[len("Vlan"):]]
            else:
                self.report.add("route", label, Severity.REVIEW, "route-interface",
                                f"AOS-S routes to a next hop or a VLAN, not to port {route.interface}; left out")
                continue
            if route.distance is not None:
                words += ["distance", str(route.distance)]
            if route.name:
                words += ["name", _quote(route.name)]
            self.out.append(" ".join(words))

    def vlan_blocks(self) -> None:
        all_ports = {p for members in self.untagged.values() for p in members}
        for vid in sorted(self.vlans):
            vlan = self.vlans[vid]
            self.out.append(f"vlan {vid}")
            if vlan.name:
                self.out.append(f"{_IND}name {_quote(vlan.name)}")
            if self.untagged.get(vid):
                self.out.append(f"{_IND}untagged {port_list(self.untagged[vid])}")
            if vid == 1:
                elsewhere = sorted((all_ports | set(self.no_untagged)) - set(self.untagged.get(1, [])))
                if elsewhere:
                    self.out.append(f"{_IND}no untagged {port_list(elsewhere)}")
            if self.tagged.get(vid):
                self.out.append(f"{_IND}tagged {port_list(self.tagged[vid])}")
            if vid in self.voice:
                self.out.append(f"{_IND}voice")
            svi = self.svis.get(vid)
            if svi is not None:
                self.out += [_IND + line for line in self._svi(svi)]
            elif vid != 1 or self.untagged.get(1) or self.tagged.get(1):
                self.out.append(f"{_IND}no ip address")
            if vid in multicast_text.snooped(self.device):
                self.out.append(f"{_IND}ip igmp")  # snooping, with the querier on
                if vid not in multicast_text.queriers(self.device):
                    self.out.append(f"{_IND}no ip igmp querier")
            self.out.append(_IND + "exit")
            if vid in self.device.vlans:
                self.report.item("vlan", str(vid))
        for vid, svi in self.svis.items():
            if vid not in self.vlans:
                self.report.skip("interface", self.label(svi), "svi-without-vlan",
                                 f"VLAN {vid} is not defined, so its interface has nowhere to go")

    def _svi(self, svi: Interface) -> List[str]:
        if svi.name in self.device.interfaces:
            self.report.item("interface", self.label(svi))
        if svi.vrf and svi.vrf not in self.mgmt_vrfs and svi.name in self.device.interfaces:
            self.add(svi, Severity.APPROX, "vrf", f"VRF {svi.vrf} does not exist on AOS-S; the address is in the "
                     "one routing table")
        lines: List[str] = []
        if svi.dhcp_client:
            lines.append("ip address dhcp-bootp")
        for cidr in svi.ipv4:
            net = ipaddress.ip_interface(cidr)
            lines.append(f"ip address {net.ip} {net.netmask}")
        if not lines:
            lines.append("no ip address")
        for cidr in svi.ipv6:
            lines.append(f"ipv6 address {cidr}")
        for helper in svi.helper_addresses:
            lines.append(f"ip helper-address {helper}")
        lines += self._acl_bindings(svi)
        lines += self._qos_bindings(svi)
        vid = int(svi.name[len("Vlan"):])
        lines += self._svi_ospf(vid, svi)
        for g in self.groups.get(vid, []):
            lines += self._vrrp(svi, g, fhrp.adder(self.report, f"vlan {vid}", g))
        return lines

    def ospf(self) -> None:
        if not self.device.ospf:
            return
        p, *others = self.device.ospf
        label = ospf_text.label(p)
        rep = self.report
        rep.item("ospf", label)

        def add(severity: Severity, code: str, message: str) -> None:
            rep.add("ospf", label, severity, code, message)

        for other in others:
            rep.skip("ospf", ospf_text.label(other), "ospf-process", "AOS-S runs one OSPF process; add it by hand")
        if p.vrf and p.vrf not in self.mgmt_vrfs:
            add(Severity.APPROX, "vrf", f"VRF {p.vrf} does not exist on AOS-S; OSPF runs in the one routing table")
        self.ospf_areas = ospf_text.interfaces(self.device, p)
        if p.networks:
            add(Severity.APPROX, "ospf-network", "network statements written as areas on the VLANs they match; a VLAN "
                "added later needs its own 'ip ospf area'")
        for name, dotted in self.ospf_areas.items():
            iface = self.device.interfaces.get(name)
            if iface is not None and iface.kind == InterfaceKind.LOOPBACK:
                add(Severity.REVIEW, "ospf-loopback",
                    f"{name} is in area {dotted} on the source; check that AOS-S advertises the loopback address")
        if p.router_id:
            self.out.append(f"ip router-id {p.router_id}")
        lines: List[str] = []
        for dotted in sorted(set(self.ospf_areas.values()) | set(p.area_types), key=ospf_text.area_number):
            kind = p.area_types.get(dotted, "")
            word = "backbone" if dotted == "0.0.0.0" else dotted
            if kind.startswith("stub"):
                lines.append(f"area {word} stub 1" + (" no-summary" if kind.endswith("no-summary") else ""))
            else:
                lines.append(f"area {word}")
                if kind:
                    add(Severity.REVIEW, "ospf-area", f"area {dotted} is {kind} on the source; set its type by hand")
        for source in p.redistribute:
            if source in ("connected", "static"):
                lines.append(f"redistribute {source}")
            else:
                add(Severity.REVIEW, "ospf-redistribute", f"redistribution of {source} left out")
        if p.default_originate:
            add(Severity.REVIEW, "ospf-default", "the default route the source originates is left out; add it by hand")
        if p.reference_bandwidth is not None:
            add(Severity.APPROX, "ospf-bandwidth",
                f"reference bandwidth {p.reference_bandwidth} Mbit/s left out; set costs on the VLANs if they matter")
        lines += ["enable", "exit"]
        self.out.append("router ospf")
        self.out += [_IND + line for line in lines]

    def dhcp(self) -> None:
        if not self.device.dhcp_pools:
            return
        for pool in self.device.dhcp_pools:
            label = dhcp_text.label(pool)
            if not pool.network:
                self.report.skip("dhcp", label, "dhcp-network", "a pool without a network (a host binding) is not written")
                continue
            self.report.item("dhcp", label)
            if pool.vrf and pool.vrf not in self.mgmt_vrfs:
                self.report.add("dhcp", label, Severity.APPROX, "vrf", f"VRF {pool.vrf} does not exist on AOS-S")
            net = ipaddress.ip_network(pool.network)
            lines = [f"network {net.network_address} {net.netmask}"]
            lines += [f"range {first} {last}" for first, last in pool.ranges]
            if pool.default_routers:
                lines.append("default-router " + " ".join(pool.default_routers))
            if pool.dns_servers:
                lines.append("dns-server " + " ".join(pool.dns_servers))
            if pool.domain_name:
                lines.append(f"domain-name {_quote(pool.domain_name)}")
            if pool.lease_seconds == 0:
                lines.append("lease infinite")
            elif pool.lease_seconds is not None:
                days, hours, minutes = dhcp_text.lease_parts(pool.lease_seconds)
                lines.append(f"lease {days:02d}:{hours:02d}:{minutes:02d}")
            self.out.append(f"dhcp-server pool {_quote(pool.name)}")
            self.out += [_IND + line for line in lines] + [_IND + "exit"]
        self.out.append("dhcp-server enable")

    def _svi_ospf(self, vid: int, svi: Interface) -> List[str]:
        name = self.svi_source.get(vid, svi.name)
        lines = []
        if name in self.ospf_areas:
            dotted = self.ospf_areas[name]
            lines.append(f"ip ospf area {'backbone' if dotted == '0.0.0.0' else dotted}")
            if self.device.ospf[0].passive(name):
                lines.append("ip ospf passive")
        if svi.ospf_cost is not None:
            lines.append(f"ip ospf cost {svi.ospf_cost}")
        if svi.ospf_network:
            self.report.add("ospf", ospf_text.label(self.device.ospf[0]) if self.device.ospf else "ospf",
                            Severity.REVIEW, "ospf-network-type",
                            f"network type {svi.ospf_network} of VLAN {vid} left out")
        return lines

    def _vrrp(self, svi: Interface, g: FhrpGroup, add: fhrp.Add) -> List[str]:
        owner = fhrp.owns(svi, g)
        body = ["owner" if owner else "backup"]
        for address in [g.address] + g.secondary:
            nets = [ipaddress.ip_interface(a).network for a in svi.ipv4]
            net = next((n for n in nets if ipaddress.ip_address(address) in n), None)
            body.append(f"virtual-ip-address {address}" + (f" {net.netmask}" if net else ""))
        if g.priority is not None and not owner:
            body.append(f"priority {g.priority}")
        if not g.preempts():
            body.append("no preempt-mode")
        if g.hello_ms is not None:
            body.append(f"advertise-interval {fhrp.interval(g.hello_ms, 1000, add, 1, 255)}")
        if g.version == 3:
            add(Severity.APPROX, "fhrp-version", "VRRPv3 written as VRRPv2, the version AOS-S runs for IPv4")
        if g.name:
            add(Severity.APPROX, "fhrp-name", f"description '{g.name}' left out: AOS-S has none for a group")
        if not g.shutdown:
            body.append("enable")
        body.append("exit")
        return [f"vrrp vrid {g.group}"] + [_IND + line for line in body]

    def qos(self) -> None:
        """Classes hold their own entries (match/ignore): DSCP values, and the entries of the ACL a class used."""
        rep = self.report
        for c in self.device.qos_classes.values():
            label = f"class {c.name}"
            rep.item("qos", label)
            lines: List[str] = []
            acl = self.device.acls.get(c.acl) if c.acl else None
            if acl is not None:
                lines = qos_text.class_lines(acl, rep, label, style="wildcard", any_protocol="ip", icmp6="icmp",
                                             icmp_names=False, quote_remark=True)
            elif c.acl:
                rep.add("qos", label, Severity.REVIEW, "acl-missing", f"ACL {c.acl} is not defined; left out")
            last = max([int(line.split()[0]) for line in lines], default=0)
            lines += [f"{last + 10 * (n + 1)} match ip any any ip-dscp {d}" for n, d in enumerate(c.dscp)]
            if c.match_all and c.dscp and acl is not None:
                rep.add("qos", label, Severity.APPROX, "qos-match",
                        "AOS-S class entries are alternatives: DSCP and ACL now match either, not both")
            self.out.append(f"class ipv4 {_quote(c.name)}")
            self.out += [_IND + line for line in lines] + [_IND + "exit"]
        for p in self.device.qos_policies.values():
            rep.item("qos", f"policy {p.name}")
            self.out.append(f"policy qos {_quote(p.name)}")
            seq = 10
            for a in p.actions:
                label = qos_text.action_label(p, a)
                if a.qos_class != qos_text.DEFAULT_CLASS and a.qos_class not in self.device.qos_classes:
                    rep.skip("qos", label, "qos-class", f"class {a.qos_class} is not defined; left out")
                    continue
                words = ["default-class"] if a.qos_class == qos_text.DEFAULT_CLASS else \
                    [f"{seq} class ipv4 {_quote(a.qos_class)}"]
                words += [f"action dscp {a.set_dscp}"] if a.set_dscp is not None else []
                words += [f"action rate-limit kbps {a.police_kbps}"] if a.police_kbps is not None else []
                self.out.append(_IND + " ".join(words))
                seq += 10
            self.out.append(_IND + "exit")

    def l2sec(self) -> None:
        """DHCP snooping and ARP protection with their VLANs and trusted ports, IP lockdown and port security."""
        d = self.device
        rep = self.report
        ifaces = list(d.interfaces.values())

        def names(test: Callable[[Interface], bool]) -> str:
            return port_list([self.port(i.name) for i in ifaces if test(i)])

        vlans = l2sec_text.snooping_vlans_written(d, rep)
        if d.dhcp_snooping or vlans:
            rep.item("vlan", "DHCP snooping")
            self.out.append("dhcp-snooping")
            if vlans:
                self.out.append(f"dhcp-snooping vlan {l2sec_text.vlan_text(vlans, ' ')}")
        vlans = l2sec_text.inspection_vlans(d)
        if vlans:
            rep.item("vlan", "ARP inspection")
            self.out += ["arp-protect", f"arp-protect vlan {l2sec_text.vlan_text(vlans, ' ')}"]
        for word, test in (("dhcp-snooping trust", lambda i: i.dhcp_trust), ("arp-protect trust", lambda i: i.arp_trust),
                           ("ip source-lockdown", lambda i: i.source_guard)):
            text = names(test)
            if text:
                self.out.append(f"{word} {text}")
        for i in ifaces:
            if not i.port_security:
                continue
            words = [f"port-security {self.port(i.name)} learn-mode static"]
            if i.port_security_max is not None:
                words.append(f"address-limit {i.port_security_max}")
            if i.port_security_violation not in ("", "protect"):
                action = {v: k for k, v in _AOSS_ACTIONS.items()}[i.port_security_violation]
                words.append(f"action {action}")
            self.out.append(" ".join(words))

    def _qos_bindings(self, iface: Interface) -> List[str]:
        lines = []
        for direction, name in (("in", iface.qos_policy_in), ("out", iface.qos_policy_out)):
            if name and name in self.device.qos_policies:
                lines.append(f"service-policy {_quote(name)} {direction}")
            elif name:
                self.report.add("interface", self.label(iface), Severity.REVIEW, "qos-policy",
                                f"policy {name} is applied but not defined; left out")
        if iface.qos_trust:
            lines.append(f"qos trust {'dot1p' if iface.qos_trust == 'cos' else iface.qos_trust}")
        return lines

    def _acl_bindings(self, iface: Interface) -> List[str]:
        lines = []
        for attr, family, direction in (("acl_in", "ip", "in"), ("acl_out", "ip", "out"), ("acl6_in", "ipv6", "in"),
                                        ("acl6_out", "ipv6", "out")):
            name = getattr(iface, attr)
            if name and name in self.device.acls:
                lines.append(f"{family} access-group {_quote(acl_text.safe_name(name))} {direction}")
            elif name:
                self.report.add("interface", self.label(iface), Severity.REVIEW, "acl-missing",
                                f"ACL {name} is applied but not defined; left out")
        return lines

    def acls(self) -> None:
        for acl in self.device.acls.values():
            name = acl_text.safe_name(acl.name)
            label = acl.name if name == acl.name else f"{acl.name} -> {name}"
            self.report.item("acl", label)
            header = f"ipv6 access-list {_quote(name)}" if acl.family == 6 else f"ip access-list extended {_quote(name)}"
            self.out.append(header)
            lines = acl_text.cisco_lines(acl, self.report, label, "wildcard", any_protocol="ipv6" if acl.family == 6
                                         else "ip", icmp6="icmp", icmp_names=False, quote_remark=True)
            self.out += [_IND + line for line in lines]
            self.out.append(_IND + "exit")

    def spanning_tree(self) -> None:
        mode = self.device.stp_mode
        is_switch = bool(self.untagged) or bool(self.tagged)
        if mode == StpMode.NONE or (mode is None and not is_switch):
            return
        self.out.append("spanning-tree")
        written = StpMode.MSTP
        if mode is None:
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-default",
                            "the source runs spanning tree in its default mode; AOS-S has it off until enabled, so "
                            "MSTP is switched on")
        elif mode == StpMode.RSTP:
            written = StpMode.RSTP
            self.out.append("spanning-tree force-version rstp-operation")
            self.report.item("system", "spanning-tree mode")
        elif mode == StpMode.RAPID_PVST:
            written = StpMode.RAPID_PVST
            self.out.append("spanning-tree mode rapid-pvst")
            self.report.item("system", "spanning-tree mode")
        elif mode == StpMode.MSTP:
            self.report.item("system", "spanning-tree mode")
        else:
            written = StpMode.RAPID_PVST
            self.out.append("spanning-tree mode rapid-pvst")
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                            f"{mode.value} is not available on AOS-S, written as rapid-pvst")
        s = self.device.stp
        if stp_text.region(self.device, written, self.report):
            self.out += [f"spanning-tree config-name {_quote(s.region)}"] if s.region else []
            self.out += [f"spanning-tree config-revision {s.revision}"] if s.revision is not None else []
            self.out += [f"spanning-tree instance {n} vlan {stp_text.vlan_text(v).replace(',', ' ')}"
                         for n, v in sorted(s.instances.items())]
        instances, vlans = stp_text.priorities(self.device, written, self.report)
        for instance, priority in sorted(instances.items()):  # AOS-S counts priorities in steps of 4096
            self.out.append(f"spanning-tree priority {priority // 4096}" if instance == 0 else
                            f"spanning-tree instance {instance} priority {priority // 4096}")
        for priority in sorted(set(vlans.values())):
            members = stp_text.vlan_text([v for v, p in vlans.items() if p == priority])
            self.out.append(f"spanning-tree vlan {members} priority {priority // 4096}")
        if instances or vlans:
            self.report.item("system", "bridge priority")
        ifaces = [i for i in self.device.interfaces.values() if not i.lag and i.kind != InterfaceKind.VLAN]

        def ports_with(test: Callable[[Interface], bool]) -> str:
            return port_list([self.port(i.name) for i in ifaces if test(i)])

        for word, test in (("admin-edge-port", lambda i: bool(i.stp_portfast)),
                           ("bpdu-protection", lambda i: bool(i.stp_bpduguard)),
                           ("root-guard", lambda i: i.stp_guard == "root"),
                           ("bpdu-filter", lambda i: i.stp_bpdufilter)):
            if ports_with(test):
                self.out.append(f"spanning-tree {ports_with(test)} {word}")
        for i in ifaces:
            if i.stp_cost is not None:
                self.out.append(f"spanning-tree {self.port(i.name)} path-cost {i.stp_cost}")
            if i.stp_port_priority is not None:
                self.out.append(f"spanning-tree {self.port(i.name)} priority {i.stp_port_priority // 16}")
            if i.stp_guard == "loop":
                self.report.add("interface", f"{i.source_name or i.name} -> {self.port(i.name)}", Severity.REVIEW,
                                "stp-loop-guard", "AOS-S has no spanning tree loop guard; consider 'loop-protect'")


def emit(device: Device, ports: PortMapper, report: Report) -> str:
    return Writer(device, ports, report).emit()
