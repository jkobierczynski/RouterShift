# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for HPE Aruba AOS-CX (10.x)."""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Tuple

from .. import acl as acl_text
from .. import multicast as multicast_text
from .. import monitor as monitor_text
from .. import vxlan as vxlan_text
from .. import tracking as tracking_text
from .. import hosts as hosts_text
from .. import bfd as bfd_text
from .. import igp as igp_text
from .. import routemap as routemap_text
from .. import bgp as bgp_text
from .. import dhcp as dhcp_text
from .. import l2sec as l2sec_text
from .. import mgmt as mgmt_text
from .. import vrfs as vrfs_text
from .. import mpls as mpls_text
from .. import nat as nat_text
from .. import wlan as wlan_text
from .. import vpn as vpn_text
from .. import fhrp
from .. import ospf as ospf_text
from .. import snmp as snmp_text
from .. import stp as stp_text
from .. import qos as qos_text
from .. import aaa as aaa_text
from ..parsers.aoscx import AOSCX_ROLES
from ..model import Device, Interface, Ospf, InterfaceKind, LacpMode, StaticRoute, StpMode, SwitchportMode
from ..names import PortMapper
from ..report import Report, Severity

MGMT_VRF = "mgmt"
_MAX_MTU = 9198
_IND = "    "

_Add = Callable[[Severity, str, str], None]


class Writer:
    def __init__(self, device: Device, ports: PortMapper, report: Report) -> None:
        self.device = device
        self.port = ports
        self.report = report
        self.out: List[str] = []
        self.vrf_names: Dict[str, str] = {}
        self.is_switch = bool(device.vlans) or any(
            i.mode != SwitchportMode.ROUTED for i in device.interfaces.values())
        self.mgmt_gateways: List[StaticRoute] = []

    def vrf(self, name: str) -> str:
        return self.vrf_names.get(name, name)

    def emit(self) -> str:
        self._plan_vrfs()
        self.system()
        self.vrfs()
        self.spanning_tree()
        self.acls()
        self.policies()
        if bfd_text.uses_bfd(self.device):
            self.out.append("bfd")
        bfd_text.pbr_unsupported(self.device, self.report, "AOS-CX")
        igp_text.unsupported(self.device, self.report, "AOS-CX")
        self.qos()
        self.vlans()
        self.groups = {i.name: fhrp.plan(i, "aoscx", self.report, self.port(i.name))
                       for i in self.device.interfaces.values() if i.fhrp}
        if any(g.protocol == "vrrp" for gs in self.groups.values() for g in gs):
            self.out.append("router vrrp enable")
        self.ospf_areas: Dict[str, List[Tuple[str, str]]] = {}  # interface -> [(process, area)]
        for p in self.device.ospf:
            self.ospf(p)
        # a LAG exists before the ports that join it
        order = {InterfaceKind.MANAGEMENT: 0, InterfaceKind.LAG: 1}
        for iface in sorted(self.device.interfaces.values(), key=lambda i: order.get(i.kind, 2)):
            self.interface(iface)
        self.vsx()
        self.vxlan()
        self.monitor()
        tracking_text.plan(self.device, self.report, "aoscx", "AOS-CX")
        self.routes()
        self.dhcp()
        nat_text.skip_all(self.device, self.report, "AOS-CX")
        mpls_text.unsupported(self.device, self.report, "AOS-CX")
        wlan_text.unsupported(self.device, self.report, "AOS-CX")
        vpn_text.skip_all(self.device, self.report, "AOS-CX")
        if self.device.bgp is not None:
            self.bgp()
        self.report.unparsed(self.device.unparsed)
        return "\n".join(self.out) + "\n"

    def _plan_vrfs(self) -> None:
        for iface in self.device.interfaces.values():
            if iface.kind == InterfaceKind.MANAGEMENT and iface.vrf and iface.vrf != MGMT_VRF:
                self.vrf_names[iface.vrf] = MGMT_VRF
                self.report.add("system", f"vrf {iface.vrf}", Severity.APPROX, "mgmt-vrf",
                                f"management VRF {iface.vrf} becomes {MGMT_VRF}, the VRF of the AOS-CX management port")
        for route in self.device.static_routes:
            if self.vrf(route.vrf) == MGMT_VRF and route.prefix in ("0.0.0.0/0", "::/0") and route.next_hop:
                self.mgmt_gateways.append(route)

    # system ----------------------------------------------------------------------------------------------------------

    def system(self) -> None:
        s = self.device.system
        rep = self.report
        if s.hostname:
            self.out.append(f"hostname {s.hostname}")
            rep.item("system", "hostname")
        if s.timezone:
            if "/" in s.timezone or s.timezone.upper() == "UTC":
                self.out.append(f"clock timezone {s.timezone.lower()}")
                rep.item("system", "time zone")
            else:
                rep.add("system", "time zone", Severity.REVIEW, "timezone",
                        f"time zone '{s.timezone}' is a name with an offset; AOS-CX takes a zone of the tz database "
                        "(clock timezone europe/brussels); set it by hand")
        if s.banner_motd:
            delim = "^" if "^" not in s.banner_motd else "%"
            self.out += [f"banner motd {delim}", s.banner_motd, delim]
            rep.item("system", "banner motd")
        via = f" vrf {self.vrf(s.service_vrf)}" if s.service_vrf else ""
        for key in s.ntp_keys.values():
            rep.item("system", f"ntp key {key.number}")
            algorithm = key.algorithm
            if algorithm not in ("md5", "sha1"):
                algorithm = "sha1"
                rep.add("system", f"ntp key {key.number}", Severity.REVIEW, "ntp-algorithm",
                        f"{key.algorithm} is not offered; sha1 is written, so the servers must use it too")
            self.out.append(f"ntp authentication-key {key.number} {algorithm} plaintext "
                            f"{snmp_text.ntp_key(key, rep)}" + (" trusted" if key.trusted else ""))
        if s.ntp_authenticate:
            self.out.append("ntp authentication")
        if s.ntp_servers:
            for server in s.ntp_servers:
                keyed = f" key {s.ntp_server_keys[server]}" if server in s.ntp_server_keys else ""
                self.out.append(f"ntp server {server}{keyed} iburst" + (" prefer" if server == s.ntp_prefer else ""))
            self.out.append("ntp enable")
            if s.ntp_source:
                rep.add("system", "ntp servers", Severity.REVIEW, "ntp-source",
                        f"NTP source interface {s.ntp_source} is not written; AOS-CX picks the source by VRF")
            if s.service_vrf:
                self.out.append(f"ntp vrf {self.vrf(s.service_vrf)}")
            rep.item("system", "ntp servers")
        if s.domain_name:
            self.out.append(f"ip dns domain-name {s.domain_name}")
            rep.item("system", "domain name")
        if s.dns_servers:
            self.out.append(f"ip dns server-address {' '.join(s.dns_servers)}{via}")
            rep.item("system", "name servers")
        hosts_text.dns_unsupported(self.device, rep, "AOS-CX", search=True, hosts=True)
        self.out += [f"ip dns domain-list {d}" for d in s.dns_search]
        self.out += [f"ip dns host {name} {address}" for name, address in s.dns_hosts.items()]
        severity = f" severity {mgmt_text.SHORT[s.logging_level]}" if s.logging_level is not None else ""
        for host in s.syslog_servers:
            self.out.append(f"logging {host}{severity}{via}")
        if s.syslog_servers:
            rep.item("system", "syslog servers")
        if s.logging_level is not None:
            rep.item("system", "syslog level")
            if not s.syslog_servers:
                rep.add("system", "syslog level", Severity.REVIEW, "syslog-level",
                        "AOS-CX sets the level per syslog server and there is none; left out")
        if s.logging_source:
            self.out.append(f"ip source-interface syslog interface {self.port(s.logging_source).replace(' ', '')}")
            rep.item("system", "syslog source")
        self.management()
        self.snmp()
        self.users()
        self.aaa()
        self.out.append("!")

    def _l2sec_interface(self, iface: Interface, add: Callable[[Severity, str, str], None]) -> List[str]:
        lines = []
        if iface.dhcp_trust:
            lines.append("dhcpv4-snooping trust")
        if iface.arp_trust:
            lines.append("arp inspection trust")
        if iface.source_guard:
            lines.append("ipv4 source-lockdown")
        if iface.port_security:
            lines += ["port-access port-security", "    enable"]
            if iface.port_security_max is not None:
                lines.append(f"    client-limit {iface.port_security_max}")
            if iface.port_security_violation not in ("", "shutdown"):
                add(Severity.REVIEW, "port-security",
                    f"violation mode {iface.port_security_violation} is not written; set the AOS-CX port security "
                    "violation action by hand")
        if iface.storm_control:
            levels = ", ".join(f"{k} {l2sec_text.level_text(v)}%" for k, v in iface.storm_control.items())
            add(Severity.REVIEW, "storm-control",
                f"storm control ({levels}) is not written: AOS-CX rate-limits in kbps or pps; set 'rate-limit' by hand")
        return lines

    def management(self) -> None:
        """SSH and HTTPS servers in a VRF, the CLI session timeout and LLDP; AOS-CX has no Telnet or plain HTTP
        server, and no CDP."""
        d = self.device
        m = d.management
        rep = self.report
        mgmt_text.items(d, rep)
        mgmt = any(i.kind == InterfaceKind.MANAGEMENT for i in d.interfaces.values())
        vrf = self.vrf(m.vrf) if m.vrf else MGMT_VRF if mgmt else "default"
        if m.ssh:
            self.out.append(f"ssh server vrf {vrf}")
        if m.https:
            self.out.append(f"https-server vrf {vrf}")
        mgmt_text.no_server(rep, "telnet server", "AOS-CX", m.telnet)
        mgmt_text.no_server(rep, "http server", "AOS-CX", m.http)
        if m.vty_acl:
            rep.add("management", "remote login ACL", Severity.REVIEW, "mgmt-acl",
                    f"apply ACL {m.vty_acl} to the control plane by hand (apply access-list ip ... control-plane vrf "
                    f"{vrf})")
        if m.exec_timeout is not None:
            self.out += ["cli-session", f"    timeout {m.exec_timeout}"]
        if m.lldp is False:
            self.out.append("no lldp")
        if m.cdp:
            rep.add("management", "CDP", Severity.APPROX, "cdp-lldp", "AOS-CX has no CDP; LLDP announces the switch")

    def users(self) -> None:
        if self.device.aaa.enable_secret is not None:
            self.report.skip("management", "enable secret", "enable-secret",
                             "AOS-CX has no enable secret: a user's group gives its rights")
        for u in self.device.users:
            label = aaa_text.user_label(u)
            found = aaa_text.password(u, ("aoscx-ciphertext",), self.report)
            if found is None:
                continue
            form, value = found
            if form == "none":
                self.report.skip("management", label, "no-password",
                                 "the user has no password in the source; AOS-CX needs one, create it by hand")
                continue
            group = aaa_text.role(u.privilege, AOSCX_ROLES)
            self.report.item("management", label)
            if u.privilege not in (None, 1, 15):
                self.report.add("management", label, Severity.APPROX, "privilege",
                                f"privilege {u.privilege} becomes group {group}; AOS-CX has no levels in between")
            self.out.append(f"user {u.name} group {group} password "
                            f"{'plaintext' if form == 'plain' else 'ciphertext'} {value}")

    def aaa(self) -> None:
        a = self.device.aaa
        rep = self.report
        for s in a.servers:
            label = aaa_text.server_label(s)
            rep.item("management", label)
            words = [f"{s.protocol}-server host {s.address} key plaintext {aaa_text.key(s, rep)}"]
            if s.protocol == "radius":
                words += [f"auth-port {s.auth_port}"] if s.auth_port else []
                words += [f"acct-port {s.acct_port}"] if s.acct_port else []
            elif s.auth_port:
                words.append(f"port {s.auth_port}")
            words += [f"timeout {s.timeout}"] if s.timeout is not None else []
            words += [f"vrf {self.vrf(s.vrf)}"] if s.vrf else []
            self.out.append(" ".join(words))
        by_address = {(s.protocol, s.address): s for s in a.servers}
        for g in a.groups.values():
            rep.item("management", f"{g.protocol} group {g.name}")
            self.out.append(f"aaa group server {g.protocol} {g.name}")
            for address in g.servers:
                server = by_address.get((g.protocol, address))
                vrf = (server.vrf if server else "") or g.vrf
                self.out.append(f"    server {address}" + (f" vrf {self.vrf(vrf)}" if vrf else ""))
        for protocol, source in a.source.items():
            vrfs = {s.vrf for s in a.servers if s.protocol == protocol}
            vrf = f" vrf {self.vrf(vrfs.pop())}" if len(vrfs) == 1 and "" not in vrfs else ""
            self.out.append(f"ip source-interface {protocol} interface {self.port(source).replace(' ', '')}{vrf}")
        for protocol, source in self.device.system.transfer_source.items():
            if protocol == "tftp":
                rep.item("system", "tftp source")
                self.out.append(f"ip source-interface tftp interface {self.port(source).replace(' ', '')}")
            else:
                rep.skip("system", f"{protocol} source", "transfer-source",
                         "AOS-CX has no FTP client source setting; it copies files with SFTP, SCP, TFTP or HTTP")
        accounting_written = False
        self._port_access()
        for m in a.methods:
            if m.service == "dot1x":
                continue  # written with the port access settings
            label = aaa_text.method_label(m)
            groups = [x[len("group:"):] for x in m.methods if x.startswith("group:")]
            rest = [x for x in m.methods if x in ("local", "none")]
            dropped = [x for x in m.methods if not x.startswith("group:") and x not in ("local", "none")]
            if (m.kind, m.service) in (("authentication", "enable"), ("authorization", "exec")):
                rep.skip("management", label, "aaa-service",
                         f"AOS-CX has no {m.kind} for {m.service}; a user's group gives its rights")
                continue
            if m.kind == "accounting" and accounting_written:
                rep.add("management", label, Severity.APPROX, "aaa-accounting",
                        "AOS-CX accounts all management sessions and commands with one list, written once")
                continue
            rep.item("management", label)
            if dropped:
                rep.add("management", label, Severity.APPROX, "aaa-method",
                        f"method {', '.join(dropped)} left out: AOS-CX has none")
            if m.kind == "authorization" and m.level not in (None, 15):
                rep.add("management", label, Severity.APPROX, "aaa-level",
                        f"AOS-CX authorizes every command, not level {m.level} only")
            service = {"login": "login", "commands": "commands", "exec": "all-mgmt"}[m.service]
            if m.kind == "accounting":
                service, accounting_written = "all-mgmt", True
            words = [f"aaa {m.kind} {service} {m.name}"] + ([m.record] if m.record else [])
            if groups:
                words.append("group " + " ".join(groups + rest))
            else:
                words += rest
            self.out.append(" ".join(words))

    def _port_access(self) -> None:
        """802.1X and MAC authentication: switched on globally, with the RADIUS group they use."""
        a = self.device.aaa
        rep = self.report
        method = next((m for m in a.methods if m.service == "dot1x"), None)
        group_lines: List[str] = []
        if method is not None:
            label = aaa_text.method_label(method)
            groups = [x[len("group:"):] for x in method.methods if x.startswith("group:")]
            rep.item("management", label)
            if groups:
                group_lines = [f"{_IND}radius server-group {groups[0]}"]
            if len(groups) != 1 or len(method.methods) != 1:
                rep.add("management", label, Severity.APPROX, "aaa-method",
                        f"AOS-CX authenticates ports against one RADIUS group; written as "
                        f"{groups[0] if groups else 'the default group'}")
        if a.dot1x:
            rep.item("management", "802.1X")
            self.out += ["aaa authentication port-access dot1x authenticator"] + group_lines + [f"{_IND}enable"]
        if any(i.mab for i in self.device.interfaces.values()):
            self.out += ["aaa authentication port-access mac-auth"] + group_lines + [f"{_IND}enable"]

    def _port_access_interface(self, iface: Interface, add: Callable[[Severity, str, str], None]) -> List[str]:
        if not (iface.dot1x or iface.mab):
            return []
        mode = iface.dot1x_host_mode or "single-host"
        prefix = "aaa authentication port-access"
        lines = []
        if mode == "multi-auth":
            lines.append(f"{prefix} client-limit 32")
            add(Severity.APPROX, "dot1x-clients", "multi-auth written as client mode with up to 32 clients; "
                                                 "change the client limit if the port needs more")
        else:
            lines.append(f"{prefix} client-limit 1" if mode == "single-host" else f"{prefix} client-limit 32")
        if mode in ("multi-host", "multi-domain"):
            lines.append(f"{prefix} auth-mode {'device-mode' if mode == 'multi-host' else 'multi-domain'}")
        if iface.dot1x:
            lines.append(f"{prefix} dot1x authenticator")
            lines += [f"{_IND}reauth"] if iface.dot1x_reauth else []
            lines += [f"{_IND}reauth-period {iface.dot1x_reauth_period}"] if iface.dot1x_reauth_period else []
            lines.append(f"{_IND}enable")
        if iface.mab:
            lines += [f"{prefix} mac-auth", f"{_IND}enable"]
        return lines

    _SNMP_AUTH = ["md5", "sha"]
    _SNMP_PRIV = ["des", "aes128"]

    def snmp(self) -> None:
        s = self.device.snmp
        rep = self.report
        if snmp_text.has_snmp(self.device) and (s.vrf or self.device.system.service_vrf):
            self.out.append(f"snmp-server vrf {self.vrf(s.vrf or self.device.system.service_vrf)}")
        for c in s.communities:
            label = snmp_text.community_label(self.device, c)
            rep.item("management", label)
            self.out.append(f"snmp-server community {snmp_text.secret(c.name, rep, 'management', label, 'community')}")
            self.out.append(f"    access-level {c.access}")
            if c.acl:
                rep.add("management", label, Severity.REVIEW, "snmp-acl",
                        f"ACL {c.acl} is not written for the community; restrict the managers by hand")
        if s.location:
            self.out.append(f"snmp-server system-location {s.location}")
            rep.item("management", "snmp location")
        if s.contact:
            self.out.append(f"snmp-server system-contact {s.contact}")
            rep.item("management", "snmp contact")
        for g in s.groups.values():
            rep.add("management", f"SNMPv3 group {g.name}", Severity.APPROX, "snmp-group",
                    "AOS-CX has no SNMPv3 groups; its users get the access of an SNMPv3 user")
        for u in s.users:
            label = snmp_text.user_label(u)
            rep.item("management", label)
            keys = snmp_text.user_keys(u, rep)
            words = [f"snmpv3 user {u.name}"]
            if u.auth:
                words.append(f"auth {snmp_text.pick(u.auth, self._SNMP_AUTH, rep, label)} auth-pass plaintext {keys[0]}")
            if u.priv:
                priv = snmp_text.pick(u.priv, self._SNMP_PRIV, rep, label)
                words.append(f"priv {'aes' if priv == 'aes128' else priv} priv-pass plaintext {keys[1]}")
            self.out.append(" ".join(words))
        for h in s.hosts:
            label = snmp_text.host_label(h)
            rep.item("management", label)
            words = [f"snmp-server host {h.address} {'inform' if h.informs else 'trap'} version v{h.version}"]
            if h.version == "3":
                words.append(f"user {h.secret}")
            else:
                words.append(f"community {snmp_text.secret(h.secret, rep, 'management', label, 'community')}")
            if h.vrf:
                words.append(f"vrf {self.vrf(h.vrf)}")
            self.out.append(" ".join(words))
        if s.source:
            rep.add("management", "snmp source", Severity.REVIEW, "snmp-source",
                    f"SNMP source interface {s.source} is not written; AOS-CX picks the source by VRF")

    def vsx(self) -> None:
        """vsx: inter-switch link, role and keepalive (by address)."""
        d = self.device
        m = d.mlag
        if m is None:
            return
        rep = self.report
        label = "multi-chassis LAG"
        rep.item("interface", label)
        lines = []
        if m.peer_link.startswith("Port-channel"):
            lines.append(f"inter-switch-link {self.port(m.peer_link)}")
        elif m.peer_link:
            rep.add("interface", label, Severity.REVIEW, "mlag-peer-link",
                    f"peer link {m.peer_link} is not a LAG; set the VSX inter-switch link by hand")
        lines.append(f"role {m.role or 'primary'}")
        if not m.role:
            rep.add("interface", label, Severity.REVIEW, "mlag-role", "role primary is written; make the peer secondary")
        source = d.interfaces.get(m.local_interface)
        if m.peer_address and source is not None and source.ipv4:
            vrf = f" vrf {self.vrf(source.vrf)}" if source.vrf else ""
            lines.append(f"keepalive peer {m.peer_address} source {source.ipv4[0].split('/')[0]}{vrf}")
            if d.platform == "eos":
                rep.add("interface", label, Severity.REVIEW, "mlag-keepalive",
                        "the MLAG peer-address and local-interface are written as the VSX keepalive; VSX prefers a "
                        "keepalive outside the inter-switch link")
        elif m.peer_address:
            rep.add("interface", label, Severity.REVIEW, "mlag-keepalive",
                    f"keepalive source {m.local_interface or '?'} has no address; set the VSX keepalive by hand")
        if m.domain:
            rep.add("interface", label, Severity.APPROX, "mlag-domain", f"VSX has no domain name (was {m.domain})")
        self.out += ["vsx"] + [_IND + line for line in lines]

    def vrfs(self) -> None:
        for name in self.device.vrfs:
            info = self.device.vrf_info.get(name)
            if self.vrf(name) == MGMT_VRF:  # predefined
                if info and (info.rd or info.rt_import or info.rt_export):
                    self.report.add("system", f"vrf {name}", Severity.REVIEW, "vrf-leaking",
                                    f"VRF {name} becomes the AOS-CX management VRF, which takes no route "
                                    "distinguisher or route targets; left out")
                continue
            self.out.append(f"vrf {name}")
            if info and info.rd:
                self.out.append(f"{_IND}rd {info.rd}")
            if info and (info.rt_import or info.rt_export):
                self.out.append(f"{_IND}address-family ipv4 unicast")
                self.out += [f"{_IND * 2}route-target {d} {v}" for d, v in vrfs_text.targets(info)]
            self.report.item("system", f"vrf {name}")

    def spanning_tree(self) -> None:
        mode = self.device.stp_mode
        if mode == StpMode.NONE or (mode is None and not self.is_switch):
            return
        self.out.append("spanning-tree")
        written = StpMode.RAPID_PVST if mode in (StpMode.RAPID_PVST, StpMode.PVST) else StpMode.MSTP
        if written == StpMode.RAPID_PVST:
            self.out.append("spanning-tree mode rpvst")
        if mode is None:
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-default",
                            "the source runs spanning tree in its default mode; AOS-CX has it off until enabled, "
                            "so MSTP is switched on")
        elif mode in (StpMode.MSTP, StpMode.RAPID_PVST):
            self.report.item("system", "spanning-tree mode")
        else:
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                            f"{mode.value} is not available on AOS-CX, written as "
                            f"{'rpvst' if written == StpMode.RAPID_PVST else 'mstp'}")
        s = self.device.stp
        if stp_text.region(self.device, written, self.report):
            self.out += [f"spanning-tree config-name {s.region}"] if s.region else []
            self.out += [f"spanning-tree config-revision {s.revision}"] if s.revision is not None else []
            self.out += [f"spanning-tree instance {n} vlan {stp_text.vlan_text(v)}"
                         for n, v in sorted(s.instances.items())]
        instances, vlans = stp_text.priorities(self.device, written, self.report)
        for instance, priority in sorted(instances.items()):  # AOS-CX counts priorities in steps of 4096
            self.out.append(f"spanning-tree priority {priority // 4096}" if instance == 0 else
                            f"spanning-tree instance {instance} priority {priority // 4096}")
        for priority in sorted(set(vlans.values())):
            members = stp_text.vlan_text([v for v, p in vlans.items() if p == priority])
            self.out.append(f"spanning-tree vlan {members} priority {priority // 4096}")
        if instances or vlans:
            self.report.item("system", "bridge priority")

    def acls(self) -> None:
        for acl in self.device.acls.values():
            name = acl_text.safe_name(acl.name)
            label = acl.name if name == acl.name else f"{acl.name} -> {name}"
            self.report.item("acl", label)
            self.out.append(f"access-list {'ipv6' if acl.family == 6 else 'ip'} {name}")
            lines = acl_text.cisco_lines(acl, self.report, label, "mask", any_protocol="any", icmp6="icmpv6",
                                         icmp_names=True, icmp_keyword="icmp-type", remark="comment",
                                         established=False)
            self.out += [_IND + line for line in lines]

    def qos(self) -> None:
        """Classes hold their own entries (match/ignore): DSCP values, and the entries of the ACL a class used."""
        rep = self.report
        for c in self.device.qos_classes.values():
            label = f"class {c.name}"
            rep.item("qos", label)
            lines: List[str] = []
            acl = self.device.acls.get(c.acl) if c.acl else None
            if acl is not None:
                lines = qos_text.class_lines(acl, rep, label, style="mask", any_protocol="any", icmp6="icmpv6",
                                             icmp_names=True, icmp_keyword="icmp-type", remark="comment",
                                             established=False)
            elif c.acl:
                rep.add("qos", label, Severity.REVIEW, "acl-missing", f"ACL {c.acl} is not defined; left out")
            last = max([int(line.split()[0]) for line in lines], default=0)
            lines += [f"{last + 10 * (n + 1)} match any any any dscp {d}" for n, d in enumerate(c.dscp)]
            if c.match_all and c.dscp and acl is not None:
                rep.add("qos", label, Severity.APPROX, "qos-match",
                        "AOS-CX class entries are alternatives: DSCP and ACL now match either, not both")
            self.out.append(f"class ip {c.name}")
            self.out += [_IND + line for line in lines]
        for p in self.device.qos_policies.values():
            rep.item("qos", f"policy {p.name}")
            self.out.append(f"policy {p.name}")
            seq = 10
            for a in p.actions:
                label = qos_text.action_label(p, a)
                if a.qos_class == qos_text.DEFAULT_CLASS or a.qos_class not in self.device.qos_classes:
                    why = ("AOS-CX has no default class in a policy" if a.qos_class == qos_text.DEFAULT_CLASS
                           else f"class {a.qos_class} is not defined")
                    rep.skip("qos", label, "qos-class", f"{why}; left out")
                    continue
                words = [f"{seq} class ip {a.qos_class}"]
                words += [f"action dscp {a.set_dscp}"] if a.set_dscp is not None else []
                if a.police_kbps is not None:
                    words.append(f"action cir kbps {a.police_kbps} cbs {max(1500, a.police_kbps * 125 // 8)} "
                                 "exceed drop")
                    rep.add("qos", label, Severity.APPROX, "qos-burst",
                            "the burst is not converted: written as 1/8 s of the rate")
                self.out.append(_IND + " ".join(words))
                seq += 10

    def _qos_interface(self, iface: Interface, add: Callable[[Severity, str, str], None]) -> List[str]:
        lines = []
        for direction, name in (("in", iface.qos_policy_in), ("out", iface.qos_policy_out)):
            if name and name in self.device.qos_policies:
                routed = "routed-" if iface.kind == InterfaceKind.VLAN else ""
                lines.append(f"apply policy {name} {routed}{direction}")
            elif name:
                add(Severity.REVIEW, "qos-policy", f"policy {name} is applied but not defined; left out")
        if iface.qos_trust:
            lines.append(f"qos trust {iface.qos_trust}")
        return lines

    def vlans(self) -> None:
        voice = {i.voice_vlan for i in self.device.interfaces.values() if i.voice_vlan is not None}
        snooped = set(l2sec_text.snooping_vlans_written(self.device, self.report))
        igmp = multicast_text.snooped(self.device)
        if multicast_text.stated(self.device):
            self.report.item("vlan", multicast_text.LABEL)
            multicast_text.querier_unsupported(self.device, self.report, "AOS-CX")
        if self.device.dhcp_snooping or snooped:
            self.out.append("dhcpv4-snooping")
            self.report.item("vlan", "DHCP snooping")
        if l2sec_text.inspection_vlans(self.device):
            self.report.item("vlan", "ARP inspection")
        for vlan in sorted(self.device.vlans.values(), key=lambda v: v.vlan_id):
            self.out.append(f"vlan {vlan.vlan_id}")
            if vlan.name:
                self.out.append(f"{_IND}name {vlan.name}")
            if vlan.vlan_id in voice:
                self.out.append(f"{_IND}voice")
            if vlan.shutdown:
                self.out.append(f"{_IND}shutdown")
            if vlan.vlan_id in snooped:
                self.out.append(f"{_IND}dhcpv4-snooping")
            if vlan.arp_inspection:
                self.out.append(f"{_IND}arp inspection")
            if vlan.vlan_id in igmp:
                self.out.append(f"{_IND}ip igmp snooping enable")
            self.report.item("vlan", str(vlan.vlan_id))
        d = self.device
        if d.multicast_routing or d.pim_rps:
            self.report.item("system", "multicast routing")
            self.out += ["router pim", f"{_IND}enable"] + [f"{_IND}rp-address {rp}" for rp in d.pim_rps]

    def vxlan(self) -> None:
        """interface vxlan 1 with its VNIs, and the evpn block for the VLANs EVPN advertises."""
        d = self.device
        vx = d.vxlan
        if vx is None:
            return
        vxlan_text.item(d, self.report)
        self.out.append("interface vxlan 1")
        source = vxlan_text.source_address(d)
        if source:
            self.out.append(f"{_IND}source ip {source}")
        elif vx.source_interface:
            self.report.add("interface", vxlan_text.LABEL, Severity.REVIEW, "vxlan-source",
                            f"AOS-CX takes a source address; {vx.source_interface} has none, left out")
        self.out.append(f"{_IND}no shutdown")
        for vid, vni in vx.vlan_vnis.items():
            self.out += [f"{_IND}vni {vni}", f"{_IND * 2}vlan {vid}"]
            if vid not in vx.evpn_vlans:
                self.out += [f"{_IND * 2}vtep-peer {a}" for a in vx.flood_vteps]
        for vrf, vni in vx.vrf_vnis.items():
            self.out += [f"{_IND}vni {vni}", f"{_IND * 2}vrf {self.vrf(vrf)}"]
        if vx.evpn_vlans:
            self.out.append("evpn")
            for vid in vx.evpn_vlans:
                self.out += [f"{_IND}vlan {vid}", f"{_IND * 2}rd auto", f"{_IND * 2}route-target export auto",
                             f"{_IND * 2}route-target import auto"]

    def monitor(self) -> None:
        """Mirror sessions and sFlow; AOS-CX NetFlow (IPFIX) is not written."""
        d = self.device
        rep = self.report
        numbers = monitor_text.numbers(d, rep, "AOS-CX", 4)
        for s in d.mirror_sessions:
            sources = monitor_text.sources(s, rep, "AOS-CX") if s.name in numbers else None
            if sources is None:
                continue
            self.out.append(f"mirror session {numbers[s.name]}")
            self.out += [f"{_IND}source interface {self.port(p)} {way}" for p, way in sources.items()]
            self.out += [f"{_IND}destination interface {self.port(s.destination)}", f"{_IND}enable"]
        sf = d.sflow
        if sf is not None:
            rep.item(monitor_text.KIND, monitor_text.SFLOW)
            if monitor_text.sflow_ports(d):
                self.out.append("sflow")
            for c in sf.collectors:
                port = f" port {c.port}" if c.port is not None else ""
                vrf = f" vrf {self.vrf(c.vrf)}" if c.vrf else ""
                self.out.append(f"sflow collector {c.address}{port}{vrf}")
            agent = monitor_text.agent(d, sf, rep, "AOS-CX")
            if agent:
                self.out.append(f"sflow agent-ip {agent}")
            if sf.sample_rate is not None:
                self.out.append(f"sflow sampling {sf.sample_rate}")
            if sf.polling_interval is not None:
                self.out.append(f"sflow polling {sf.polling_interval}")
        monitor_text.netflow_unsupported(d, rep, "AOS-CX")

    # interfaces ------------------------------------------------------------------------------------------------------

    def interface(self, iface: Interface) -> None:
        name = self.port(iface.name)
        label = f"{iface.source_name or iface.name} -> {name}"
        self.report.item("interface", label)

        def add(severity: Severity, code: str, message: str) -> None:
            self.report.add("interface", label, severity, code, message)

        if iface.kind == InterfaceKind.TUNNEL:
            self.report.skip("interface", label, "tunnel",
                             "tunnel interfaces are not converted for AOS-CX yet; configure it by hand")
            return
        lines: List[str] = ["shutdown" if iface.shutdown else "no shutdown"]
        if iface.description:
            lines.append(f"description {iface.description}")
        if iface.mtu is not None:
            mtu = min(iface.mtu, _MAX_MTU)
            if mtu != iface.mtu:
                add(Severity.APPROX, "mtu", f"MTU {iface.mtu} lowered to {mtu}, the largest AOS-CX takes")
            lines.append(f"mtu {mtu}")
        if iface.speed is not None:
            lines.append(f"speed {iface.speed}-{iface.duplex or 'full'}")
            add(Severity.APPROX, "speed", "forced speed: check that the transceiver and AOS-CX release take it")
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.encapsulation_vlan is not None:
            lines.append(f"encapsulation dot1q {iface.encapsulation_vlan}")
        if iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG):
            lines += self._layer2(iface, add)
        if iface.kind == InterfaceKind.LAG:
            lacp = {m.lacp_mode for m in self.device.interfaces.values() if m.lag == iface.name}
            mode = LacpMode.ACTIVE if LacpMode.ACTIVE in lacp else LacpMode.PASSIVE if lacp == {LacpMode.PASSIVE} \
                else None
            if mode is not None:
                lines.append(f"lacp mode {mode.value}")
        if iface.vrf and iface.kind != InterfaceKind.MANAGEMENT:
            lines.append(f"vrf attach {self.vrf(iface.vrf)}")
        lines += self._addresses(iface, add)
        for attr, family, direction in (("acl_in", "ip", "in"), ("acl_out", "ip", "out"), ("acl6_in", "ipv6", "in"),
                                        ("acl6_out", "ipv6", "out")):
            acl_name = getattr(iface, attr)
            if acl_name and acl_name in self.device.acls:
                if iface.kind == InterfaceKind.VLAN:
                    direction = f"routed-{direction}"  # a router ACL; "in" on a VLAN would filter switched traffic
                lines.append(f"apply access-list {family} {acl_text.safe_name(acl_name)} {direction}")
            elif acl_name:
                add(Severity.REVIEW, "acl-missing", f"ACL {acl_name} is applied but not defined; left out")
        lines += self._fhrp(iface, name)
        lines += self._ospf_interface(iface)
        if iface.pim or iface.igmp_version is not None:
            lines.append("ip igmp enable")
        if iface.pim:
            lines.append(f"ip pim-{'dense' if iface.pim == 'dense' else 'sparse'} enable")
            if iface.pim == "sparse-dense":
                add(Severity.APPROX, "pim-mode", "PIM sparse-dense mode written as sparse mode")
        if iface.igmp_version is not None:
            lines.append(f"ip igmp version {iface.igmp_version}")
        if iface.sflow and self.device.sflow is not None and not monitor_text.all_ports(self.device):
            lines.append("sflow")
        if hosts_text.poe_stated(iface):
            if iface.poe is False:
                lines.append("no power-over-ethernet")
            else:
                priority = hosts_text.poe_priority(iface, ("low", "high", "critical"), add, "AOS-CX")
                if priority:
                    lines.append(f"power-over-ethernet priority {priority}")
                hosts_text.poe_limit(iface, add, "AOS-CX", False)
        lines += self._port_access_interface(iface, add)
        lines += self._qos_interface(iface, add)
        lines += [f"no lldp {name}" for name, on in (("transmit", iface.lldp_tx), ("receive", iface.lldp_rx)) if not on]
        lines += self._l2sec_interface(iface, add)
        if iface.stp_portfast:
            lines.append("spanning-tree port-type admin-edge")
        if iface.stp_bpduguard:
            lines.append("spanning-tree bpdu-guard")
        if iface.stp_guard:
            lines.append(f"spanning-tree {iface.stp_guard}-guard")
        if iface.stp_bpdufilter:
            lines.append("spanning-tree bpdu-filter")
        if iface.stp_cost is not None:
            lines.append(f"spanning-tree cost {iface.stp_cost}")
        if iface.stp_port_priority is not None:
            lines.append(f"spanning-tree port-priority {iface.stp_port_priority // 16}")
        self.out.append(f"interface {name}" + (" multi-chassis" if iface.mlag_id is not None
                                               and iface.kind == InterfaceKind.LAG else ""))
        self.out += [_IND + line for line in lines]
        if (iface.source_name or iface.name, name) in self.port.renumbered:
            add(Severity.APPROX, "port-renamed",
                f"named {name} without a port map; check it against the cabling of the new device")

    def _fhrp(self, iface: Interface, name: str) -> List[str]:
        lines: List[str] = []
        for g in self.groups.get(iface.name, []):
            add = fhrp.adder(self.report, name, g)
            if g.protocol == "anycast":
                if g.mac:
                    lines.append(f"active-gateway ip mac {g.mac}")
                else:
                    add(Severity.REVIEW, "fhrp-mac", "the source has no anycast MAC; add 'active-gateway ip mac'")
                lines += [f"active-gateway ip {a}" for a in [g.address] + g.secondary]
                continue
            lines.append(f"vrrp {g.group} address-family ipv4")
            body = [f"address {g.address} primary"] + [f"address {a} secondary" for a in g.secondary]
            if g.priority is not None:
                body.append(f"priority {g.priority}")
            if not g.preempts():
                body.append("no preempt")
            if g.version == 3:
                body.append("version 3")
            if g.hello_ms is not None:
                body.append(f"timers advertise {fhrp.interval(g.hello_ms, 1, add, 100, 40950)}")
            if g.name:
                add(Severity.APPROX, "fhrp-name", f"description '{g.name}' left out: AOS-CX has none for a group")
            body.append("shutdown" if g.shutdown else "no shutdown")
            lines += [_IND + line for line in body]
        return lines

    def ospf(self, p: Ospf) -> None:
        label = ospf_text.label(p)
        self.report.item("ospf", label)
        areas = ospf_text.interfaces(self.device, p)
        if p.networks:
            self.report.add("ospf", label, Severity.APPROX, "ospf-network",
                            "network statements written as areas on the interfaces they match; an interface added "
                            "later needs its own 'ip ospf area'")
        for name, dotted in areas.items():
            self.ospf_areas.setdefault(name, []).append((p.process, dotted))
        self.out.append(f"router ospf {p.process}" + (f" vrf {self.vrf(p.vrf)}" if p.vrf else ""))
        lines: List[str] = []
        if p.router_id:
            lines.append(f"router-id {p.router_id}")
        if p.reference_bandwidth is not None:
            lines.append(f"reference-bandwidth {p.reference_bandwidth}")
        if p.passive_default:
            lines.append("passive-interface default")
        for source in p.redistribute:
            rm = p.redistribute_maps.get(source)
            lines.append(f"redistribute {source}" + (f" route-map {rm}" if rm else ""))
        if p.bfd_all:
            lines.append("bfd all-interfaces")
        if p.default_originate:
            lines.append("default-information originate" + (" always" if p.default_originate == "always" else ""))
        for dotted in sorted(set(areas.values()) | set(p.area_types), key=ospf_text.area_number):
            kind = p.area_types.get(dotted)
            lines.append(f"area {dotted}" + (f" {kind}" if kind else ""))
        self.out += [_IND + line for line in lines]

    def dhcp(self) -> None:
        for vrf in sorted({p.vrf for p in self.device.dhcp_pools}):
            self.out.append(f"dhcp-server vrf {self.vrf(vrf) if vrf else 'default'}")
            for pool in (p for p in self.device.dhcp_pools if p.vrf == vrf):
                label = dhcp_text.label(pool)
                if not pool.network:
                    self.report.skip("dhcp", label, "dhcp-network",
                                     "a pool without a network (a host binding) is not written")
                    continue
                self.report.item("dhcp", label)
                lines = [f"range {first} {last} prefix-len {dhcp_text.prefix_len(pool)}" for first, last in pool.ranges]
                if pool.default_routers:
                    lines.append("default-router " + " ".join(pool.default_routers))
                if pool.dns_servers:
                    lines.append("dns-server " + " ".join(pool.dns_servers))
                if pool.domain_name:
                    lines.append(f"domain-name {pool.domain_name}")
                if pool.lease_seconds == 0:
                    lines.append("lease infinite")
                elif pool.lease_seconds is not None:
                    days, hours, minutes = dhcp_text.lease_parts(pool.lease_seconds)
                    lines.append(f"lease {days:02d}:{hours:02d}:{minutes:02d}")
                lines.append("exit")
                self.out.append(f"{_IND}pool {pool.name.replace(' ', '_')}")
                self.out += [_IND * 2 + line for line in lines]
            self.out.append(f"{_IND}enable")

    def policies(self) -> None:
        """Prefix lists, then the route maps that match them."""
        routemap_text.items(self.device, self.report)
        for pl in self.device.prefix_lists.values():
            self.out += routemap_text.ios_prefix_lines(pl, "aoscx")
        skip = bfd_text.pbr_only(self.device)  # reported with the interface
        for rm in self.device.route_maps.values():
            if rm.name not in skip:
                self.out += routemap_text.ios_route_map_lines(rm, "aoscx", self.report, _IND)

    def bgp(self) -> None:
        bgp = self.device.bgp
        assert bgp is not None
        label = f"bgp {bgp.local_as}"
        self.report.item("bgp", label)
        if bgp.peer_groups:
            self.report.add("bgp", label, Severity.APPROX, "bgp-peer-group",
                            f"peer groups {', '.join(bgp.peer_groups)} written out on each member")
        lines: List[str] = []
        if bgp.router_id:
            lines.append(f"bgp router-id {bgp.router_id}")
        neighbors = bgp_text.flat(bgp)
        for peer in neighbors:
            self.report.item("bgp", f"neighbor {peer.address}")
            pre = f"neighbor {peer.address}"
            if peer.remote_as:
                lines.append(f"{pre} remote-as {peer.remote_as}")
            if peer.description:
                lines.append(f"{pre} description {peer.description}")
            if peer.update_source:
                lines.append(f"{pre} update-source {self.port(peer.update_source)}")
            if peer.ebgp_multihop is not None:
                lines.append(f"{pre} ebgp-multihop {peer.ebgp_multihop}")
            if peer.shutdown:
                lines.append(f"{pre} shutdown")
            if peer.bfd:
                lines.append(f"{pre} fall-over bfd")
        for af in ("ipv4", "ipv6"):
            body: List[str] = []
            for peer in neighbors:
                if af in peer.families:
                    body.append(f"neighbor {peer.address} activate")
                    if peer.next_hop_self:
                        body.append(f"neighbor {peer.address} next-hop-self")
                    if peer.send_community:
                        body.append(f"neighbor {peer.address} send-community standard")
                    for kind in ("route-map", "prefix-list"):
                        for direction in ("in", "out"):
                            name = getattr(peer, f"{kind.replace('-', '_')}_{direction}")
                            if name:
                                body.append(f"neighbor {peer.address} {kind} {name} {direction}")
            body += [f"network {p}" for p in bgp.networks if (":" in p) == (af == "ipv6")]
            for r in bgp.redistribute6 if af == "ipv6" else bgp.redistribute:
                rm = bgp.redistribute_maps.get(r) if af == "ipv4" else None
                body.append(f"redistribute {r}" + (f" route-map {rm}" if rm else ""))
            if body:
                lines.append(f"address-family {af} unicast")
                lines += [_IND + line for line in body]
                lines.append("exit-address-family")
        evpn = [p for p in neighbors if "evpn" in p.families]
        if evpn:
            lines.append("address-family l2vpn evpn")
            for p in evpn:
                lines += [f"{_IND}neighbor {p.address} activate", f"{_IND}neighbor {p.address} send-community extended"]
            lines.append("exit-address-family")
        self.out.append(f"router bgp {bgp.local_as}")
        self.out += [_IND + line for line in lines]

    def _ospf_interface(self, iface: Interface) -> List[str]:
        lines = [f"ip ospf {number} area {dotted}" for number, dotted in self.ospf_areas.get(iface.name, [])]
        for p in self.device.ospf:
            if iface.name in p.passive_interfaces and not p.passive_default:
                lines.append("ip ospf passive")
            elif iface.name in p.active_interfaces and p.passive_default:
                lines.append("no ip ospf passive")
        if iface.ospf_cost is not None:
            lines.append(f"ip ospf cost {iface.ospf_cost}")
        if iface.ospf_network:
            lines.append(f"ip ospf network {iface.ospf_network}")
        if iface.ospf_bfd and not any(p.bfd_all for p in self.device.ospf):
            lines.append("ip ospf bfd")
        return lines + bfd_text.separate_lines(iface)

    def _layer2(self, iface: Interface, add: _Add) -> List[str]:
        if iface.lag:
            return [f"lag {iface.lag[len('Port-channel'):]}"]
        if iface.mode == SwitchportMode.ROUTED:
            return ["routing"]
        lines = ["no routing"]
        if iface.mode == SwitchportMode.ACCESS:
            if iface.voice_vlan is not None:
                data = iface.access_vlan or 1
                lines += [f"vlan trunk native {data}", f"vlan trunk allowed {data},{iface.voice_vlan}"]
                add(Severity.APPROX, "voice-vlan",
                    f"access VLAN {data} with voice VLAN {iface.voice_vlan} written as a trunk (native {data}, "
                    f"tagged {iface.voice_vlan}), the AOS-CX way; LLDP-MED or a device profile hands phones the VLAN")
            else:
                lines.append(f"vlan access {iface.access_vlan or 1}")
        else:
            if iface.native_vlan is not None:
                lines.append(f"vlan trunk native {iface.native_vlan}")
            lines.append(f"vlan trunk allowed {iface.allowed_vlans or 'all'}")
        return lines

    def _addresses(self, iface: Interface, add: _Add) -> List[str]:
        lines: List[str] = []
        mgmt = iface.kind == InterfaceKind.MANAGEMENT
        if iface.dhcp_client:
            lines.append("ip dhcp")
        for n, cidr in enumerate(iface.ipv4):
            if mgmt:
                if n == 0:
                    lines.append(f"ip static {cidr}")
                else:
                    add(Severity.REVIEW, "mgmt-secondary", f"the management port takes one address; {cidr} left out")
            else:
                lines.append(f"ip address {cidr}" + (" secondary" if n else ""))
        for cidr in iface.ipv6:
            lines.append(f"ipv6 address {cidr}")
        for helper in iface.helper_addresses:
            lines.append(f"ip helper-address {helper}")
        if mgmt:
            for route in self.mgmt_gateways:
                if (":" in route.prefix) == (":" in route.next_hop):
                    lines.append(f"default-gateway {route.next_hop}")
        return lines

    # routing ---------------------------------------------------------------------------------------------------------

    def routes(self) -> None:
        for route in self.device.static_routes:
            label = f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}"
            self.report.item("route", label)
            if any(route is gateway for gateway in self.mgmt_gateways):
                continue  # written as default-gateway of the management port
            net = ipaddress.ip_network(route.prefix)
            words = ["ip" if net.version == 4 else "ipv6", "route", str(net)]
            if route.discard:
                words.append("blackhole")
            else:
                if route.next_hop:
                    words.append(route.next_hop)
                if route.interface:
                    words.append(self.port(route.interface))
            if route.distance is not None:
                words += ["distance", str(route.distance)]
            if route.vrf:
                words += ["vrf", self.vrf(route.vrf)]
            if route.name:
                self.report.add("route", label, Severity.APPROX, "route-name",
                                f"the route's name '{route.name}' has no place on AOS-CX and is left out")
            self.out.append(" ".join(words))


def emit(device: Device, ports: PortMapper, report: Report) -> str:
    return Writer(device, ports, report).emit()
