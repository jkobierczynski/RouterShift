# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for Cisco IOS-XR (ASR 9000, NCS 5500/540, 8000; 7.x).

IOS-XR is a router operating system with a structured CLI. This writer covers the system settings (DNS, NTP with
keys, syslog with local logging, banners, time zone), users, AAA with TACACS+ and RADIUS, SNMP v2c and v3, ACLs,
prefix lists, community and AS-path lists and route maps (as RPL sets and route policies), ports, bundles,
subinterfaces, loopbacks, the management port, VRFs with route targets, static routes, OSPF, IS-IS, MPLS LDP, BGP
with neighbor groups and VRFs, HSRP and VRRP, DHCP relay, PIM and IGMP, LLDP/CDP and the SSH, telnet and NETCONF
servers.

IOS-XR has no VLANs or switchports. A VLAN is written as a bridge domain ``VLANn`` (``VLANn-NAME`` when it has a
name) in bridge group ``VLANS``, routed through ``BVIn`` when the VLAN has an SVI. An access port joins as a whole
``l2transport`` interface; a trunk gets one ``l2transport`` subinterface per VLAN with ``encapsulation dot1q n`` and
the tag popped, and its native VLAN one with ``encapsulation untagged``. Spanning tree, port security, 802.1X, PoE and
the other switch features have no IOS-XR form and are reported.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

from .. import aaa as aaa_text
from .. import acl as acl_text
from .. import bfd as bfd_text
from .. import bgp as bgp_text
from .. import fhrp
from .. import hosts as hosts_text
from .. import iosxrpolicy as policy
from .. import iosxrservices as services
from .. import mgmt as mgmt_text
from .. import mpls as mpls_text
from .. import multicast as multicast_text
from .. import ospf as ospf_text
from .. import partial
from .. import routemap as routemap_text
from .. import snmp as snmp_text
from .. import stp as stp_text
from .. import tracking as tracking_text
from ..model import (Bgp, BgpNeighbor, BgpVrf, Device, FhrpGroup, Interface, InterfaceKind, LacpMode, Ospf,
                     StaticRoute, SwitchportMode)
from ..names import PortMapper
from ..parsers.ioslike import _vlan_ids
from ..report import Report, Severity
from ..timezones import offset_minutes, standard_and_summer

PLATFORM = "IOS-XR"
IND = " "
ROLES = [(15, "root-lr"), (0, "operator")]
HASHES = ("md5-crypt", "sha512-crypt", "iosxr-sha256", "iosxr-scrypt")
_HASH_NUMBER = {"md5-crypt": "5", "iosxr-sha256": "8", "iosxr-scrypt": "9", "sha512-crypt": "10"}
BRIDGE_GROUP = "VLANS"
WRITTEN = {"acl", "policy", "dhcp-relay", "fhrp", "speed", "mpls", "isis", "bfd", "aaa", "multicast", "qos",
           "monitor", "track"}
_LEVEL_WORDS = mgmt_text.LEVELS
_MAX_TRUNK_VLANS = 512  # a trunk of "all VLANs" is written for the VLANs the device defines, and no more than this


class Writer:
    def __init__(self, device: Device, ports: PortMapper, report: Report) -> None:
        self.device = device
        self.port = ports
        self.report = report
        self.out: List[str] = []
        self.pass_all = False
        self.prefix_policies: Dict[str, List[str]] = {}  # policies written for prefix lists on BGP neighbors
        self.halves: Dict[str, bool] = {}
        self.domains: Dict[int, List[str]] = {}  # VLAN -> the l2transport interfaces in its bridge domain
        self.track_plan = tracking_text.Plan()

    def label(self, iface: Interface) -> str:
        return f"{iface.source_name or iface.name} -> {self.port(iface.name)}"

    def adder(self, label: str) -> fhrp.Add:
        def add(severity: Severity, code: str, message: str) -> None:
            self.report.add("interface", label, severity, code, message)
        return add

    def emit(self) -> str:
        self.system()
        self.users()
        self.aaa()
        self.vrfs()
        self.snmp()
        self.acls()
        policies_at = len(self.out)
        self.track_plan = tracking_text.plan(self.device, self.report, "iosxr", PLATFORM)
        services_lines = services.qos_lines(self.device, self.report) + \
            services.netflow_lines(self.device, self.report, self.port) + \
            services.mirror_lines(self.device, self.report, self.port) + \
            services.tracking_lines(self.device, self.track_plan, self.report, self.port)
        self.sflow()
        self.interfaces()
        self.routes()
        self.ospf()
        self.isis()
        self.ldp()
        self.bgp()
        self.fhrp_lines()
        self.l2vpn()
        self.relay()
        self.multicast()
        self.management()
        self.out[policies_at:policies_at] = self.policies() + services_lines
        self.unwritable()
        partial.device(self.device, self.report, PLATFORM, WRITTEN)
        self.report.unparsed(self.device.unparsed)
        return "\n".join(self.out + ["end"]) + "\n"

    # system ----------------------------------------------------------------------------------------------------------

    def service_vrf(self) -> str:
        vrf = self.device.system.service_vrf
        return f" vrf {vrf}" if vrf else ""

    def system(self) -> None:
        sy = self.device.system
        out = self.out
        if sy.hostname:
            out.append(f"hostname {sy.hostname}")
            self.report.item("system", "hostname")
        for kind, text in (("motd", sy.banner_motd), ("login", sy.banner_login), ("exec", sy.banner_exec)):
            if text:
                self.report.item("system", f"banner {kind}")
                delim = next(c for c in "^#%@~" if c not in text)
                out.append(f"banner {kind} {delim}")
                out += text.split("\n")
                out.append(delim)
        if sy.timezone:
            self.timezone(sy.timezone)
        self.logging()
        if sy.domain_name:
            out.append(f"domain name {sy.domain_name}")
        for domain in sy.dns_search:
            out.append(f"domain list {domain}")
        for host, address in sy.dns_hosts.items():
            out.append(f"domain ipv4 host {host} {address}")
        for server in sy.dns_servers:
            out.append(f"domain{self.service_vrf()} name-server {server}")
        if sy.dns_lookup is False:
            out.append("domain lookup disable")
        if sy.dns_source:
            out.append(f"domain lookup source-interface {self.port(sy.dns_source)}")
        hosts_text.dns_unsupported(self.device, self.report, PLATFORM, lookup=True, search=True, hosts=True,
                                   source=True)
        self.ntp()

    def timezone(self, tz: str) -> None:
        """IOS-XR 7 takes a zone name and an IANA region; older releases a fixed offset."""
        self.report.item("system", "time zone")
        if "/" in tz or tz in ("UTC", "GMT"):
            zone = standard_and_summer(tz) if "/" in tz else None
            name = zone[0] if zone is not None else tz.split("/")[-1][:3].upper()
            self.out.append(f"clock timezone {name} {tz}")
            return
        minutes = offset_minutes(tz)
        if minutes is None:
            self.report.add("system", "time zone", Severity.REVIEW, "timezone",
                            f"'{tz}' is not written; set clock timezone NAME REGION by hand")
            return
        words = tz.split()
        name = words[0] if len(words) >= 2 and words[1].lstrip("-").isdigit() else "UTC"
        sign = "-" if minutes < 0 else ""
        self.out.append(f"clock timezone {name} {sign}{abs(minutes) // 60} {abs(minutes) % 60}")
        self.report.add("system", "time zone", Severity.APPROX, "timezone",
                        "written as a fixed offset; IOS-XR 7 also takes an IANA region (clock timezone NAME REGION), "
                        "which follows summer time")

    def logging(self) -> None:
        sy = self.device.system
        out = self.out
        if sy.logging_level is not None:
            out.append(f"logging trap {_LEVEL_WORDS[sy.logging_level]}")
        if sy.logging_console_level is not None:
            out.append("logging console disable" if sy.logging_console_level < 0 else
                       f"logging console {_LEVEL_WORDS[sy.logging_console_level]}")
        if sy.logging_monitor_level is not None:
            out.append("logging monitor disable" if sy.logging_monitor_level < 0 else
                       f"logging monitor {_LEVEL_WORDS[sy.logging_monitor_level]}")
        if sy.logging_buffer is not None:
            size = min(max(sy.logging_buffer, 307200), 125000000)
            if size != sy.logging_buffer:
                self.report.add("system", "local logging", Severity.APPROX, "logging-buffer",
                                f"IOS-XR keeps 307200 to 125000000 bytes of log; {sy.logging_buffer} is written as "
                                f"{size}")
            out.append(f"logging buffered {size}")
        if sy.logging_buffer_level is not None:
            out.append(f"logging buffered {_LEVEL_WORDS[sy.logging_buffer_level]}")
        if sy.logging_buffer is not None or sy.logging_buffer_level is not None or \
                sy.logging_console_level is not None or sy.logging_monitor_level is not None:
            self.report.item("system", "local logging")
        for what in ("timestamp", "hostname"):
            if getattr(sy, f"logging_{what}"):
                self.report.add("system", "local logging", Severity.APPROX, "logging-format",
                                f"the syslog {what} format is not written: IOS-XR has its own (service timestamps)")
        if sy.logging_facility_levels:
            self.report.add("system", "local logging", Severity.APPROX, "logging-facility",
                            "the per-facility logging levels are not written: IOS-XR sets one level per destination")
        for server in sy.syslog_servers:
            self.report.item("system", f"syslog {server}")
            words = ["logging", server] + self.service_vrf().split()
            if sy.logging_level is not None:
                words += ["severity", _LEVEL_WORDS[sy.logging_level]]
            transport = sy.syslog_transport.get(server)
            if transport is not None:
                protocol, number = transport
                if protocol != "udp":
                    self.report.add("system", f"syslog {server}", Severity.APPROX, "syslog-transport",
                                    f"IOS-XR sends syslog over UDP; {protocol} port {number} is written as UDP port "
                                    f"{number} (TLS needs logging tls-server, set it up by hand)")
                words += ["port", str(number)]
            out.append(" ".join(words))
        if sy.logging_source:
            out.append(f"logging source-interface {self.port(sy.logging_source)}{self.service_vrf()}")

    def ntp(self) -> None:
        sy = self.device.system
        body: List[str] = []
        for number, key in sorted(sy.ntp_keys.items()):
            label = f"ntp key {number}"
            self.report.item("system", label)
            algorithm = key.algorithm
            if algorithm not in ("md5", "sha1", "sha2"):
                self.report.add("system", label, Severity.REVIEW, "ntp-algorithm",
                                f"IOS-XR takes MD5 NTP keys; the {algorithm} key is written as MD5, change it on both "
                                "sides")
                algorithm = "md5"
            body.append(f"authentication-key {number} {algorithm} clear {snmp_text.ntp_key(key, self.report)}")
        if sy.ntp_authenticate:
            body.append("authenticate")
        body += [f"trusted-key {n}" for n, k in sorted(sy.ntp_keys.items()) if k.trusted]
        for server in sy.ntp_servers:
            self.report.item("system", f"ntp server {server}")
            words = ["server"] + self.service_vrf().split() + [server]
            if server in sy.ntp_server_keys:
                words += ["key", str(sy.ntp_server_keys[server])]
            if server == sy.ntp_prefer:
                words.append("prefer")
            body.append(" ".join(words))
        if sy.ntp_source:
            body.append(f"source{self.service_vrf()} {self.port(sy.ntp_source)}")
        if body:
            self.out += ["ntp"] + [IND + b for b in body] + ["!"]

    def users(self) -> None:
        for user in self.device.users:
            label = aaa_text.user_label(user)
            password = aaa_text.password(user, HASHES, self.report)
            if password is None:
                continue
            self.report.item("management", label)
            role = aaa_text.role(user.privilege, ROLES)
            body = [f"group {role}"]
            if user.role:
                if user.role in self.device.roles:
                    self.report.add("management", label, Severity.REVIEW, "role",
                                    f"its role {user.role} is not written (IOS-XR task groups differ); the user gets "
                                    f"group {role}")
                else:
                    body.append(f"group {user.role}")
            kind, value = password
            if kind == "plain":
                body.append(f"secret 0 {value}")
            elif kind in _HASH_NUMBER:
                body.append(f"secret {_HASH_NUMBER[kind]} {value}")
            else:
                self.report.add("management", label, Severity.REVIEW, "no-password",
                                "the user has no password in the source; set one")
            if user.ssh_keys:
                self.report.add("management", label, Severity.REVIEW, "ssh-keys",
                                "IOS-XR imports SSH public keys with 'crypto key import authentication rsa', an exec "
                                "command; they are not written")
            self.out += [f"username {user.name}"] + [IND + b for b in body] + ["!"]
        if self.device.aaa.enable_secret is not None:
            self.report.skip("management", "enable secret", "enable",
                             "IOS-XR has no enable password; the groups of each user set what it may do")
        for name in self.device.roles:
            self.report.skip("management", f"role {name}", "role",
                             "CLI roles are not written: IOS-XR uses task groups and user groups; build them by hand")

    def aaa(self) -> None:
        a = self.device.aaa
        out = self.out
        for name, group in a.groups.items():
            self.report.item("management", f"aaa group {name}")
            word = "tacacs+" if group.protocol == "tacacs" else "radius"
            body = [f"server {s}" for s in group.servers]
            vrf = group.vrf or next((s.vrf for s in a.servers if s.address in group.servers and s.vrf), "")
            if vrf:
                body.append(f"vrf {vrf}")
            out += [f"aaa group server {word} {name}"] + [IND + b for b in body] + ["!"]
        for server in a.servers:
            label = aaa_text.server_label(server)
            self.report.item("management", label)
            key = aaa_text.key(server, self.report)
            if server.protocol == "tacacs":
                head = f"tacacs-server host {server.address} port {server.auth_port or 49}"
            else:
                head = (f"radius-server host {server.address} auth-port {server.auth_port or 1812} "
                        f"acct-port {server.acct_port or 1813}")
            body = [f"key 0 {key}"]
            if server.timeout is not None:
                body.append(f"timeout {server.timeout}")
            if server.vrf and not any(server.address in g.servers and g.vrf for g in a.groups.values()):
                self.report.add("management", label, Severity.APPROX, "aaa-vrf",
                                f"IOS-XR sets the VRF on the server group; VRF {server.vrf} is not written for a "
                                "server outside a group")
            out += [head] + [IND + b for b in body] + ["!"]
        for protocol, source in a.source.items():
            out.append(f"{protocol} source-interface {self.port(source)}{self.service_vrf()}")
        for method in a.methods:
            label = aaa_text.method_label(method)
            self.report.item("management", label)
            if method.service not in ("login", "exec", "commands"):
                self.report.skip("management", label, "aaa-service",
                                 f"IOS-XR has no {method.service} method list; set it up by hand")
                continue
            words = ["aaa", method.kind, method.service, method.name]
            if method.kind == "accounting":
                words.append(method.record or "start-stop")
            methods = []
            for way in method.methods:
                if way.startswith("group:"):
                    name = way[len("group:"):]
                    methods += ["group", {"tacacs": "tacacs+"}.get(name, name)]
                elif way in ("local", "none"):
                    methods.append(way)
                else:
                    self.report.add("management", label, Severity.APPROX, "aaa-method",
                                    f"method {way} has no IOS-XR form; left out")
            if method.level is not None and method.level != 15:
                self.report.add("management", label, Severity.APPROX, "aaa-level",
                                f"IOS-XR has no privilege levels; the list for level {method.level} is written for all "
                                "commands")
            out.append(" ".join(words + methods))
        if a.dot1x:
            self.report.skip("management", "802.1X", "dot1x", "IOS-XR routers do no 802.1X port authentication")
        if a.coa:
            self.report.skip("management", "RADIUS CoA", "coa", "RADIUS change of authorization is not written")
        m = self.device.management
        body = []
        if m.exec_timeout is not None:
            body.append(f"exec-timeout {m.exec_timeout} 0")
        if m.vty_acl:
            if m.vty_acl in self.device.acls:
                body.append(f"access-class ingress {acl_text.safe_name(m.vty_acl)}")
            else:
                self.report.add("management", "remote login ACL", Severity.REVIEW, "acl-missing",
                                f"ACL {m.vty_acl} is applied but not defined; left out")
        if m.console_login:
            self.report.add("management", "console login", Severity.APPROX, "console-login",
                            f"login list {m.console_login} is written as the login list of line console")
            out += ["line console", f"{IND}login authentication {m.console_login}", "!"]
        if body:
            self.report.item("management", "vty")
            out += ["line default"] + [IND + b for b in body] + ["!"]

    def vrfs(self) -> None:
        names = list(dict.fromkeys(self.device.vrfs + [r.vrf for r in self.device.static_routes if r.vrf]))
        for name in names:
            self.report.item("system", f"vrf {name}")
            info = self.device.vrf_info.get(name)
            body: List[str] = []
            v4 = []
            if info is not None:
                if info.rt_import:
                    v4 += ["import route-target"] + [f"{IND}{rt}" for rt in info.rt_import] + ["!"]
                if info.rt_export:
                    v4 += ["export route-target"] + [f"{IND}{rt}" for rt in info.rt_export] + ["!"]
                if info.export_map:
                    v4.append(f"export route-policy {info.export_map}")
                if info.rt_evpn:
                    self.report.add("system", f"vrf {name}", Severity.APPROX, "evpn-rt",
                                    "the route targets are written for the VPN address family; IOS-XR uses the same "
                                    "ones for EVPN once the VRF is in an EVPN-enabled BGP")
                for source in info.leaks:
                    self.report.add("system", f"vrf {name}", Severity.REVIEW, "leaks",
                                    f"the routes leaked from VRF {source} are not written: import that VRF's route "
                                    "target, with an import route policy for the route map")
            body.append("address-family ipv4 unicast")
            body += [IND + line for line in v4] + ["!"]
            if self._vrf_has_ipv6(name):
                body += ["address-family ipv6 unicast"] + [IND + line for line in v4] + ["!"]
            self.out += [f"vrf {name}"] + [IND + b for b in body] + ["!"]
        self._rd_without_bgp()

    def _rd_without_bgp(self) -> None:
        if self.device.bgp is not None:
            return
        for name, info in self.device.vrf_info.items():
            if info.rd:
                self.report.add("system", f"vrf {name}", Severity.APPROX, "rd",
                                f"route distinguisher {info.rd} is not written: IOS-XR sets it under router bgp, and "
                                "the device runs no BGP")

    def _vrf_has_ipv6(self, vrf: str) -> bool:
        d = self.device
        if any(i.vrf == vrf and i.ipv6 for i in d.interfaces.values()):
            return True
        return any(r.vrf == vrf and ":" in r.prefix for r in d.static_routes)

    def snmp(self) -> None:
        sn = self.device.snmp
        out = self.out
        for c in sn.communities:
            label = snmp_text.community_label(self.device, c)
            self.report.item("management", label)
            name = snmp_text.secret(c.name, self.report, "management", label, "community")
            words = ["snmp-server", "community", name, c.access.upper()]
            if c.acl:
                words += ["IPv4", acl_text.safe_name(c.acl)]
            out.append(" ".join(words))
        for g in sn.groups.values():
            self.report.item("management", f"snmp group {g.name}")
            words = ["snmp-server", "group", g.name, "v3", g.level or "priv"]
            if g.read_view:
                words += ["read", g.read_view]
            if g.write_view:
                words += ["write", g.write_view]
            out.append(" ".join(words))
        for u in sn.users:
            label = snmp_text.user_label(u)
            self.report.item("management", label)
            group = u.group or u.name
            if group not in sn.groups:
                out.append(f"snmp-server group {group} v3 {snmp_text.level(u)}")
            words = ["snmp-server", "user", u.name, group, "v3"]
            if u.auth:
                auth = snmp_text.pick(u.auth, ["md5", "sha"], self.report, label)
                words += ["auth", auth, "clear", snmp_text.secret(u.auth_key, self.report, "management", label,
                                                                   "authentication key")]
                if u.priv:
                    priv = snmp_text.pick(u.priv, ["des", "3des", "aes128", "aes192", "aes256"], self.report, label)
                    word = {"des": "des56", "3des": "3des"}.get(priv, f"aes {priv[3:]}")
                    words += ["priv"] + word.split() + ["clear", snmp_text.secret(u.priv_key, self.report,
                                                                                  "management", label, "privacy key")]
            out.append(" ".join(words))
        for view, entries in sn.views.items():
            for oid, included in entries:
                out.append(f"snmp-server view {view} {oid} {'included' if included else 'excluded'}")
        if sn.views:
            self.report.item("management", "SNMP views")
        if sn.engine_id:
            pairs = [sn.engine_id[i:i + 2] for i in range(0, len(sn.engine_id), 2)]
            out.append(f"snmp-server engineID local {':'.join(pairs)}")
        by_vrf: Dict[str, List[str]] = {}
        for h in sn.hosts:
            label = snmp_text.host_label(h)
            self.report.item("management", label)
            secret = snmp_text.secret(h.secret, self.report, "management", label, "community") if h.version != "3" \
                else h.secret
            words = ["host", h.address, "informs" if h.informs else "traps", "version", h.version]
            if h.version == "3":
                words.append(h.level or "priv")
            words.append(secret)
            by_vrf.setdefault(h.vrf or sn.vrf, []).append(" ".join(words))
        for vrf, lines in by_vrf.items():
            if vrf:
                out += [f"snmp-server vrf {vrf}"] + [IND + line for line in lines] + ["!"]
            else:
                out += [f"snmp-server {line}" for line in lines]
        if sn.traps or sn.hosts:
            if sn.trap_types:
                self.report.add("management", "snmp traps", Severity.APPROX, "trap-types",
                                "IOS-XR names its notifications differently; every notification is switched on (the "
                                "source chose " + ", ".join(sn.trap_types) + ")")
            out.append("snmp-server traps")
        if sn.location:
            out.append(f"snmp-server location {sn.location}")
        if sn.contact:
            out.append(f"snmp-server contact {sn.contact}")
        if sn.source:
            out.append(f"snmp-server trap-source {self.port(sn.source)}")

    # ACLs and policies -----------------------------------------------------------------------------------------------

    def acls(self) -> None:
        for acl in self.device.acls.values():
            name = acl_text.safe_name(acl.name)
            label = acl.name if name == acl.name else f"{acl.name} -> {name}"
            self.report.item("acl", label)
            family = "ipv6" if acl.family == 6 else "ipv4"
            lines = acl_text.cisco_lines(acl, self.report, label, "wildcard" if acl.family == 4 else "prefix",
                                         any_protocol=family, icmp6="icmpv6", icmp_names=True)
            self.out += [f"{family} access-list {name}"] + [IND + line for line in lines] + ["!"]

    def policies(self) -> List[str]:
        d = self.device
        routemap_text.items(d, self.report)
        out, self.halves = policy.prefix_set_lines(d, self.report)
        out += policy.list_lines(d, self.report)
        pbr = set(bfd_text.pbr_only(d))
        for rm in d.route_maps.values():
            if rm.name in pbr:
                self.report.skip("policy", routemap_text.label(rm.name, "route-map"), "pbr",
                                 "used for policy-based routing only, which is not written for IOS-XR yet (ABF: an "
                                 "ACL with nexthop); set it up by hand")
            elif rm.entries:
                out += policy.route_policy_lines(rm, self.halves, self.report)
        for lines in self.prefix_policies.values():
            out += lines
        if self.pass_all:
            out += policy.pass_all_lines()
        return out

    # interfaces ------------------------------------------------------------------------------------------------------

    def sflow(self) -> None:
        if self.device.sflow is not None:
            self.report.item("monitor", "sFlow")
            self.report.skip("monitor", "sFlow", "sflow", "IOS-XR has no sFlow; sample with NetFlow instead")

    def interfaces(self) -> None:
        self.domains = {}
        for iface in self.device.interfaces.values():
            self.interface(iface)

    def interface(self, iface: Interface) -> None:
        label = self.label(iface)
        if iface.kind == InterfaceKind.OTHER:
            self.report.skip("interface", label, partial.CODE,
                             "this kind of interface is not written for IOS-XR; configure it by hand")
            return
        if iface.kind == InterfaceKind.TUNNEL and (iface.tunnel_mode == "ipsec" or iface.tunnel_profile):
            self.report.skip("interface", label, "vpn-unsupported",
                             "IOS-XR routers terminate no IPsec tunnels; move it to a router or firewall that does")
            return
        self.report.item("interface", label)
        name = self.port(iface.name)
        if (iface.source_name or iface.name, name) in self.port.renumbered:
            self.report.add("interface", label, Severity.APPROX, "port-renamed",
                            f"named {name} without a port map; check it against the cabling of the new device")
        add = self.adder(label)
        common: List[str] = []
        if iface.description:
            common.append(f"description {iface.description}")
        if iface.mtu:
            common.append(f"mtu {iface.mtu}")
            if iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG, InterfaceKind.SUBINTERFACE):
                add(Severity.APPROX, "mtu", f"IOS-XR counts the Ethernet header in the MTU; {iface.mtu} is written as "
                                           "it is")
        physical = iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG)
        layer2 = physical and iface.mode != SwitchportMode.ROUTED and not iface.lag
        if iface.kind == InterfaceKind.ETHERNET:
            if iface.speed:
                common.append(f"speed {iface.speed}")
            if iface.duplex in ("full", "half"):
                common.append(f"duplex {iface.duplex}")
        if iface.lag:
            lag = self.device.interfaces.get(iface.lag)
            mode = iface.lacp_mode or (lag.lacp_mode if lag else None) or LacpMode.STATIC
            word = {LacpMode.ACTIVE: "active", LacpMode.PASSIVE: "passive"}.get(mode, "on")
            common.append(f"bundle id {iface.lag[len('Port-channel'):]} mode {word}")
        if not iface.lldp_tx or not iface.lldp_rx:
            common += ["lldp"] + ([f"{IND}transmit disable"] if not iface.lldp_tx else []) + \
                ([f"{IND}receive disable"] if not iface.lldp_rx else [])
        if iface.cdp:
            common.append("cdp")
        if stp_text.has_port_settings(iface) or iface.stp_portfast or iface.stp_bpduguard:
            add(Severity.REVIEW, "stp", "the spanning-tree port settings are not written: IOS-XR bridge domains run "
                                        "no spanning tree unless set up under spanning-tree mst; check for loops")
        common += services.interface_qos(self.device, iface, add) + services.interface_mirror(self.device, iface)
        if iface.sflow:
            add(Severity.REVIEW, "sflow", "IOS-XR has no sFlow; sample the port with NetFlow instead")
        in_ospf = any(iface.name in ospf_text.interfaces(self.device, p) for p in self.device.ospf)
        if (iface.bfd_interval or iface.bfd_multiplier) and not in_ospf and iface.kind != InterfaceKind.LAG:
            add(Severity.REVIEW, "bfd", "the BFD timers are not written: IOS-XR sets them per protocol (router ospf, "
                                        "router bgp neighbor), and the interface runs no OSPF")
        if layer2:
            self.layer2(iface, name, common, add)
        else:
            lines = common + ([] if iface.lag else self.layer3(iface, name, add))
            lines.append("shutdown" if iface.shutdown else "")
            self.out += [f"interface {name}"] + [IND + line for line in lines if line] + ["!"]
        partial.port(iface, self.report, label, PLATFORM,
                     WRITTEN if not layer2 else WRITTEN - {"fhrp", "dhcp-relay"})

    def layer2(self, iface: Interface, name: str, common: List[str], add: fhrp.Add) -> None:
        down = ["shutdown"] if iface.shutdown else []
        acls = [a for a in (iface.acl_in, iface.acl_out, iface.acl6_in, iface.acl6_out) if a]
        if acls:
            add(Severity.REVIEW, "l2-acl", f"the ACLs {', '.join(acls)} on a layer 2 port are not written: IOS-XR "
                                           "filters l2transport ports with ethernet-services ACLs; set them by hand")
        if iface.flow and self.device.netflow is not None:
            add(Severity.REVIEW, "flow-l2", "NetFlow on a layer 2 port is not written: IOS-XR monitors l2transport "
                                            "ports with 'flow datalinkframesection monitor'; set it by hand")
        if iface.mode == SwitchportMode.ACCESS:
            vid = iface.access_vlan or 1
            self.out += [f"interface {name} l2transport"] + [IND + line for line in common + down] + ["!"]
            self.domains.setdefault(vid, []).append(name)
            add(Severity.APPROX, "l2transport",
                f"written as an l2transport port in bridge domain {self.domain_name(vid)}; IOS-XR takes tagged "
                "frames on it too")
            return
        defined = sorted(self.device.vlans)
        if iface.allowed_vlans:
            vids = _vlan_ids(iface.allowed_vlans)
            if len(vids) > _MAX_TRUNK_VLANS:
                vids = [v for v in vids if v in self.device.vlans]
                add(Severity.APPROX, "trunk-vlans",
                    f"the trunk carries {iface.allowed_vlans}; a subinterface is written only for the VLANs the "
                    "device defines")
        else:
            vids = defined[:_MAX_TRUNK_VLANS]
            if vids:
                add(Severity.APPROX, "trunk-vlans",
                    "the trunk carries every VLAN; a subinterface is written for each VLAN the device defines")
        native = iface.native_vlan if iface.native_vlan in vids or iface.native_vlan in self.device.vlans else None
        if iface.native_vlan and native is None:
            add(Severity.APPROX, "trunk-native", f"native VLAN {iface.native_vlan} is not on the trunk; left out")
        self.out += [f"interface {name}"] + [IND + line for line in common + down] + ["!"]
        for vid in sorted(set(vids) | ({native} if native else set())):
            sub = f"{name}.{vid}"
            encap = ["encapsulation untagged"] if vid == native else \
                [f"encapsulation dot1q {vid}", "rewrite ingress tag pop 1 symmetric"]
            self.out += [f"interface {sub} l2transport"] + [IND + line for line in encap] + ["!"]
            self.domains.setdefault(vid, []).append(sub)

    def domain_name(self, vid: int) -> str:
        vlan = self.device.vlans.get(vid)
        if vlan is not None and vlan.name:
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in vlan.name)
            return f"VLAN{vid}-{safe}"[:27]
        return f"VLAN{vid}"

    def layer3(self, iface: Interface, name: str, add: fhrp.Add) -> List[str]:
        lines: List[str] = []
        if iface.vrf:
            lines.insert(0, f"vrf {iface.vrf}")
        for n, address in enumerate(iface.ipv4):
            net = ipaddress.ip_interface(address)
            lines.append(f"ipv4 address {net.ip} {net.netmask}" + (" secondary" if n else ""))
        if iface.unnumbered:
            lines.append(f"ipv4 unnumbered {self.port(iface.unnumbered)}")
        if iface.dhcp_client:
            lines.append("ipv4 address dhcp")
        for address in iface.ipv6:
            lines.append(f"ipv6 address {address}")
        if iface.virtual_ipv4 or iface.virtual_ipv6:
            add(Severity.REVIEW, "anycast-gateway",
                "the anycast gateway " + ", ".join(iface.virtual_ipv4 + iface.virtual_ipv6) + " has no IOS-XR form "
                "outside EVPN IRB (host-routing on a BVI); written as nothing, set it up by hand")
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.encapsulation_vlan:
            lines.append(f"encapsulation dot1q {iface.encapsulation_vlan}")
        if iface.kind == InterfaceKind.TUNNEL:
            if iface.tunnel_source:
                source = iface.tunnel_source
                lines.append(f"tunnel source {source if ':' in source or source[:1].isdigit() else self.port(source)}")
            if iface.tunnel_destination:
                lines.append(f"tunnel destination {iface.tunnel_destination}")
        for attr, word, direction in (("acl_in", "ipv4", "ingress"), ("acl_out", "ipv4", "egress"),
                                      ("acl6_in", "ipv6", "ingress"), ("acl6_out", "ipv6", "egress")):
            acl = getattr(iface, attr)
            if acl and acl in self.device.acls:
                lines.append(f"{word} access-group {acl_text.safe_name(acl)} {direction}")
            elif acl:
                add(Severity.REVIEW, "acl-missing", f"ACL {acl} is applied but not defined; left out")
        lines += services.interface_flow(self.device, iface)
        if iface.urpf:
            lines.append(f"ipv4 verify unicast source reachable-via {'rx' if iface.urpf == 'strict' else 'any'}")
        if iface.ip_redirects:
            lines.append("ipv4 redirects")
        if iface.ip_unreachables is False:
            lines.append("ipv4 unreachables disable")
        if iface.proxy_arp:
            lines.append("proxy-arp")
        if iface.mac_address:
            digits = iface.mac_address.replace(":", "")
            lines.append(f"mac-address {digits[0:4]}.{digits[4:8]}.{digits[8:12]}")
        if iface.kind == InterfaceKind.LAG and (iface.bfd_interval or iface.bfd_multiplier):
            lines += ["bfd mode ietf", "bfd address-family ipv4 fast-detect"]
            if iface.bfd_interval:
                lines.append(f"bfd address-family ipv4 minimum-interval {iface.bfd_interval}")
            if iface.bfd_multiplier:
                lines.append(f"bfd address-family ipv4 multiplier {iface.bfd_multiplier}")
        if iface.kind == InterfaceKind.MANAGEMENT and not iface.vrf:
            add(Severity.INFO, "mgmt-vrf", "the management port is in the default VRF, as in the source")
        if iface.kind == InterfaceKind.VLAN:
            vid = int(iface.name[len("Vlan"):]) if iface.name[len("Vlan"):].isdigit() else None
            if vid is not None and vid not in self.device.vlans:
                add(Severity.INFO, "bvi", f"VLAN {vid} is not defined; the bridge domain for BVI{vid} is written all "
                                          "the same")
            if iface.autostate is False:
                add(Severity.APPROX, "autostate", "IOS-XR has no 'no autostate'; a BVI stays up while its bridge "
                                                  "domain has a member up")
        return lines

    # routes ----------------------------------------------------------------------------------------------------------

    def routes(self) -> None:
        by_vrf: Dict[str, Dict[int, List[StaticRoute]]] = {}
        for route in self.device.static_routes:
            family: int = ipaddress.ip_network(route.prefix).version
            by_vrf.setdefault(route.vrf, {}).setdefault(family, []).append(route)
        if not by_vrf:
            return
        body: List[str] = []
        for vrf in sorted(by_vrf, key=lambda v: v != ""):
            block: List[str] = []
            for family in sorted(by_vrf[vrf]):
                block.append(f"address-family {'ipv4' if family == 4 else 'ipv6'} unicast")
                for route in by_vrf[vrf][family]:
                    block.append(IND + self.route(route))
                block.append("!")
            if vrf:
                body += [f"vrf {vrf}"] + [IND + b for b in block] + ["!"]
            else:
                body += block
        self.out += ["router static"] + [IND + b for b in body] + ["!"]

    def route(self, route: StaticRoute) -> str:
        label = f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}"
        self.report.item("route", label)
        words = [str(ipaddress.ip_network(route.prefix))]
        if route.discard:
            words.append("Null0")
        else:
            if route.interface:
                words.append(self.port(route.interface))
            if route.next_hop:
                words.append(route.next_hop)
        if route.distance is not None:
            words.append(str(route.distance))
        if route.tag is not None:
            words += ["tag", str(route.tag)]
        if route.name:
            words += ["description", route.name.replace(" ", "_")]
        track = self.track_plan.route_track(route.track) if route.track else ""
        if track:
            words += ["track", track]
        return " ".join(words)

    # OSPF ------------------------------------------------------------------------------------------------------------

    def redistribute(self, source: str, route_map: Optional[str]) -> str:
        word = source
        if source == "ospf":
            word = f"ospf {self.device.ospf[0].process if self.device.ospf else '1'}"
        if source == "bgp" and self.device.bgp is not None:
            word = f"bgp {self.device.bgp.local_as}"
        return f"redistribute {word}" + (f" route-policy {route_map}" if route_map else "")

    def ospf(self) -> None:
        main = [p for p in self.device.ospf if not p.vrf]
        for p in self.device.ospf:
            if p.vrf and main:
                continue  # written inside the main process
            if p.vrf:
                self.out += [f"router ospf {p.process}", f"{IND}vrf {p.vrf}"] + \
                    [IND * 2 + line for line in self.ospf_body(p)] + [f"{IND}!", "!"]
                continue
            self.out += [f"router ospf {p.process}"] + [IND + line for line in self.ospf_body(p)]
            for q in self.device.ospf:
                if q.vrf and main and p is main[0]:
                    self.out += [f"{IND}vrf {q.vrf}"] + [IND * 2 + line for line in self.ospf_body(q)] + [f"{IND}!"]
            self.out.append("!")

    def ospf_body(self, p: Ospf) -> List[str]:
        label = ospf_text.label(p)
        self.report.item("ospf", label)
        body: List[str] = []
        router_id = p.router_id or (self.device.system.router_id if not p.vrf else "")
        if router_id:
            body.append(f"router-id {router_id}")
            if not p.router_id:
                self.report.add("ospf", label, Severity.APPROX, "router-id",
                                f"IOS-XR sets the router ID per protocol: {router_id} is written as the OSPF router ID")
        if p.log_adjacency:
            body.append("log adjacency changes" + (" detail" if p.log_adjacency == "detail" else ""))
        if p.graceful_restart:
            body.append("nsf cisco")
        if p.reference_bandwidth:
            body.append(f"auto-cost reference-bandwidth {p.reference_bandwidth}")
        if p.spf_timers:
            body.append("timers throttle spf " + " ".join(str(x) for x in p.spf_timers))
        if p.lsa_arrival is not None:
            body.append(f"timers lsa min-arrival {p.lsa_arrival}")
        if p.max_lsa:
            body.append(f"max-lsa {p.max_lsa.split()[0]}")
            if len(p.max_lsa.split()) > 1:
                self.report.add("ospf", label, Severity.APPROX, "max-lsa",
                                f"only the limit of max-lsa {p.max_lsa} is written")
        if p.distribute_list_in:
            body.append(f"distribute-list route-policy {p.distribute_list_in} in")
        if p.bfd_all:
            body.append("bfd fast-detect")
        for source in p.redistribute:
            body.append(self.redistribute(source, p.redistribute_maps.get(source)))
        if p.default_originate:
            body.append("default-information originate" + (" always" if p.default_originate == "always" else ""))
        if p.passive_default:
            body.append("passive enable")
        areas: Dict[str, List[str]] = {}
        for name, area in ospf_text.interfaces(self.device, p).items():
            areas.setdefault(area, []).append(name)
        for area in sorted(set(areas) | set(p.area_types), key=lambda a: int(ipaddress.ip_address(a))):
            body.append(f"area {ospf_text.area_number(area) if area.count('.') == 3 else area}")
            if area in p.area_types:
                body.append(f"{IND}{p.area_types[area]}")
            for name in areas.get(area, []):
                iface = self.device.interfaces.get(name)
                lines: List[str] = []
                if p.passive_default and not p.passive(name):
                    lines.append("passive disable")
                elif not p.passive_default and p.passive(name):
                    lines.append("passive enable")
                if iface is not None:
                    if iface.ospf_cost:
                        lines.append(f"cost {iface.ospf_cost}")
                    if iface.ospf_network:
                        lines.append(f"network {iface.ospf_network}")
                    lines += self.ospf_auth(iface, label)
                    if iface.ospf_bfd or iface.bfd_interval or iface.bfd_multiplier:
                        lines.append("bfd fast-detect")
                        if iface.bfd_interval:
                            lines.append(f"bfd minimum-interval {iface.bfd_interval}")
                        if iface.bfd_multiplier:
                            lines.append(f"bfd multiplier {iface.bfd_multiplier}")
                body.append(f"{IND}interface {self.port(name)}")
                body += [IND * 2 + line for line in lines]
                body.append(f"{IND}!")
            body.append("!")
        return body

    def ospf_auth(self, iface: Interface, label: str) -> List[str]:
        if not iface.ospf_auth:
            return []
        if iface.ospf_auth == "simple":
            self.report.add("ospf", label, Severity.REVIEW, "ospf-auth",
                            f"{iface.source_name or iface.name}: the authentication key is not written; add "
                            "'authentication-key' by hand")
            return ["authentication"]
        lines = ["authentication message-digest"]
        for key_id, algorithm in sorted(iface.ospf_keys.items()):
            if algorithm != "md5":
                self.report.add("ospf", label, Severity.REVIEW, "ospf-auth",
                                f"{iface.source_name or iface.name}: key {key_id} uses {algorithm}; IOS-XR takes "
                                "that through a keychain, set it up by hand")
                continue
            lines.append(f"message-digest-key {key_id} md5 clear {aaa_text.PLACEHOLDER}")
            self.report.add("ospf", label, Severity.REVIEW, "secret-placeholder",
                            f"{iface.source_name or iface.name}: the OSPF key is not converted; replace "
                            f"{aaa_text.PLACEHOLDER} with it")
        return lines

    def isis(self) -> None:
        isis = self.device.isis
        if isis is None:
            return
        from .. import igp as igp_text
        label = igp_text.isis_label(isis)
        self.report.item("isis", label)
        body = [f"net {n}" for n in isis.nets]
        level = {"level-1": "level-1", "level-2": "level-2-only", "level-1-2": "level-1-2"}.get(isis.level)
        if level:
            body.append(f"is-type {level}")
        af: List[str] = []
        if isis.wide_metrics:
            af.append("metric-style wide")
        for source in isis.redistribute:
            route_map = isis.redistribute_maps.get(source)
            af.append(f"redistribute {source}" + (f" route-policy {route_map}" if route_map else ""))
        body += ["address-family ipv4 unicast"] + [IND + a for a in af] + ["!"]
        for iface in self.device.interfaces.values():
            if not iface.isis:
                continue
            lines = []
            if iface.isis_passive:
                lines.append("passive")
            if iface.isis_network == "point-to-point":
                lines.append("point-to-point")
            lines.append("address-family ipv4 unicast")
            if iface.isis_metric is not None:
                lines.append(f"{IND}metric {iface.isis_metric}")
            lines.append("!")
            body += [f"interface {self.port(iface.name)}"] + [IND + line for line in lines] + ["!"]
        self.out += [f"router isis {isis.tag or '1'}"] + [IND + b for b in body] + ["!"]

    def ldp(self) -> None:
        if not mpls_text.has_mpls(self.device):
            return
        self.report.item("mpls", "MPLS and LDP")
        body = []
        address = mpls_text.router_address(self.device)
        if address:
            body.append(f"router-id {address}")
        elif self.device.mpls.router_id_interface:
            mpls_text.router_id_missing(self.device, self.report, "address")
        for iface in mpls_text.interfaces(self.device):
            body += [f"interface {self.port(iface.name)}", "!"]
        self.out += ["mpls ldp"] + [IND + b for b in body] + ["!"]

    # BGP -------------------------------------------------------------------------------------------------------------

    def bgp(self) -> None:
        bgp = self.device.bgp
        if bgp is None:
            return
        label = f"bgp {bgp.local_as}"
        self.report.item("bgp", label)
        body: List[str] = []
        router_id = bgp.router_id or self.device.system.router_id
        if router_id:
            body.append(f"bgp router-id {router_id}")
            if not bgp.router_id:
                self.report.add("bgp", label, Severity.APPROX, "router-id",
                                f"IOS-XR sets the router ID per protocol: {router_id} is written as the BGP router ID")
        if bgp.asdot:
            self.report.add("bgp", label, Severity.APPROX, "asdot",
                            "asdot notation is not written: IOS-XR shows 4-byte AS numbers as asplain unless "
                            "'format asdot' is set in each show command")
        if bgp.graceful_restart:
            body.append("bgp graceful-restart")
        if bgp.graceful_restart_time:
            body.append(f"bgp graceful-restart restart-time {bgp.graceful_restart_time}")
        if bgp.multipath_relax:
            body.append("bgp bestpath as-path multipath-relax")
        if bgp.med_missing_as_worst:
            body.append("bgp bestpath med missing-as-worst")
        if bgp.keepalive is not None:
            body.append(f"timers bgp {bgp.keepalive} {bgp.hold if bgp.hold is not None else 3 * bgp.keepalive}")
        peers = list(bgp.peer_groups.values()) + bgp.neighbors
        for family in ("ipv4", "ipv6"):
            af = self.bgp_af(bgp, family, label)
            used = any(family in self.families(bgp, p) for p in peers)
            if af or used:
                body += [f"address-family {family} unicast"] + [IND + a for a in af] + ["!"]
        if any("evpn" in self.families(bgp, p) for p in peers):
            body += ["address-family l2vpn evpn", "!"]
        for name, group in bgp.peer_groups.items():
            plabel = f"peer group {name}"
            self.report.item("bgp", plabel)
            body += self.neighbor(bgp, group, plabel, f"neighbor-group {name}", None)
        for vname, v in bgp.vrfs.items():  # IOS-XR neighbor groups are the process's, usable in every VRF
            for gname, group in v.peer_groups.items():
                plabel = f"peer group {gname} (vrf {vname})"
                self.report.item("bgp", plabel)
                written = self.group_name(bgp, vname, gname)
                self.report.add("bgp", plabel, Severity.APPROX, "vrf-group",
                                f"written as neighbor group {written} of the BGP process: IOS-XR neighbor groups serve "
                                "every VRF")
                body += self.neighbor(bgp, group, plabel, f"neighbor-group {written}", v)
        for peer in bgp.neighbors:
            plabel = f"neighbor {peer.address}"
            self.report.item("bgp", plabel)
            body += self.neighbor(bgp, peer, plabel, f"neighbor {peer.address}", None)
        for name, v in bgp.vrfs.items():
            body += self.bgp_vrf(bgp, name, v)
        for name, info in self.device.vrf_info.items():
            if info.rd and name not in bgp.vrfs:
                self.report.add("system", f"vrf {name}", Severity.INFO, "rd",
                                f"IOS-XR sets the route distinguisher under router bgp: vrf {name} / rd {info.rd}")
                body += [f"vrf {name}", f"{IND}rd {info.rd}", "!"]
        if bgp.evpn_domain or bgp.evpn_remote_peers or bgp.evpn_host_flap:
            self.report.add("bgp", label, Severity.REVIEW, "evpn-domain",
                            "the EVPN domain gateway and host-flap settings are not written for IOS-XR; set them by "
                            "hand")
        if bgp.ospf_match:
            self.report.add("bgp", label, Severity.APPROX, "ospf-match",
                            "IOS-XR redistributes OSPF with 'match' as well; the route types "
                            + ", ".join(bgp.ospf_match) + " are written")
        self.out += [f"router bgp {bgp.local_as}"] + [IND + b for b in body] + ["!"]

    @staticmethod
    def group_name(bgp: Bgp, vrf: str, group: str) -> str:
        """A VRF's own peer group as a neighbor group of the process: renamed when the process has one of the name."""
        return group if group not in bgp.peer_groups else f"{group}-{vrf}"

    def bgp_af(self, bgp: Bgp, family: str, label: str) -> List[str]:
        version = 4 if family == "ipv4" else 6
        af = [f"network {n}" for n in bgp.networks if ipaddress.ip_network(n).version == version]
        sources = bgp.redistribute if family == "ipv4" else bgp.redistribute6
        for s in sources:
            line = self.redistribute(s, bgp.redistribute_maps.get(s) if family == "ipv4" else None)
            if s == "ospf" and bgp.ospf_match:
                line = line.replace(f"redistribute ospf {self.device.ospf[0].process if self.device.ospf else '1'}",
                                    f"redistribute ospf {self.device.ospf[0].process if self.device.ospf else '1'} "
                                    f"match {' '.join(bgp.ospf_match)}")
            af.append(line)
        af += [bgp_text.aggregate_line(a, False) for a in bgp.aggregates
               if ipaddress.ip_network(a.prefix).version == version]
        if family == "ipv4":
            if bgp.maximum_paths:
                af.append(f"maximum-paths ebgp {bgp.maximum_paths}")
            if bgp.maximum_paths_ibgp:
                af.append(f"maximum-paths ibgp {bgp.maximum_paths_ibgp}")
            if bgp.distance:
                af.append("distance bgp " + " ".join(str(x) for x in bgp.distance))
        return af

    @staticmethod
    def families(bgp: Bgp, peer: BgpNeighbor, vrf: Optional[BgpVrf] = None) -> List[str]:
        group = (vrf.peer_groups if vrf is not None else {}).get(peer.peer_group) or \
            bgp.peer_groups.get(peer.peer_group)
        families = set(peer.families) | (set(group.families) if group is not None else set())
        if not families and bgp_text.family(peer.address):
            families.add(bgp_text.family(peer.address))
        return sorted(families)

    def ebgp(self, bgp: Bgp, peer: BgpNeighbor, vrf: Optional[BgpVrf]) -> bool:
        if not bgp_text.family(peer.address):  # a group: eBGP when its remote AS is another
            return bool(peer.remote_as) and peer.remote_as != bgp.local_as
        effective = bgp_text.effective(bgp, peer, vrf)
        return bool(effective.remote_as) and effective.remote_as != bgp.local_as

    def neighbor(self, bgp: Bgp, p: BgpNeighbor, label: str, head: str, vrf: Optional[BgpVrf]) -> List[str]:
        bgp_text.unwritten(p, set(bgp_text.OPTIONS), self.report, label, PLATFORM)
        body: List[str] = []
        if p.remote_as:
            body.append(f"remote-as {p.remote_as}")
        if p.peer_group:
            own_group = vrf is not None and p.peer_group in vrf.peer_groups and bgp_text.family(p.address)
            vname = next((n for n, x in bgp.vrfs.items() if x is vrf), "")
            written = self.group_name(bgp, vname, p.peer_group) if own_group else p.peer_group
            body.append(f"use neighbor-group {written}")
        if p.description:
            body.append(f"description {p.description}")
        if p.shutdown:
            body.append("shutdown")
        if p.update_source:
            body.append(f"update-source {self.port(p.update_source)}")
        if p.ebgp_multihop:
            body.append(f"ebgp-multihop {p.ebgp_multihop}")
        if p.ttl_security:
            body.append("ttl-security")
            if p.ttl_security != 1:
                self.report.add("bgp", label, Severity.APPROX, "ttl-security",
                                f"IOS-XR TTL security takes directly connected neighbors only; {p.ttl_security} hops "
                                "is written as ttl-security")
        if p.local_as:
            body.append(f"local-as {p.local_as}" + (f" {p.local_as_options}" if p.local_as_options else ""))
        if p.password:
            body.append(f"password clear {p.password}")
        if p.keepalive is not None or p.hold is not None:
            keepalive = p.keepalive if p.keepalive is not None else 60
            body.append(f"timers {keepalive} {p.hold if p.hold is not None else 3 * keepalive}")
        if p.bfd:
            body.append("bfd fast-detect")
        group = (vrf.peer_groups if vrf is not None else {}).get(p.peer_group) or bgp.peer_groups.get(p.peer_group)
        inherited = set(group.families) if group is not None else set()
        # a neighbor whose source names no family is active in its own address's, unless its group decides; a group
        # that names none is active in its members' families
        own = set(p.families) or ({bgp_text.family(p.address)} if bgp_text.family(p.address) and group is None else
                                  set())
        if not own and not bgp_text.family(p.address):
            members = [n for n in (vrf.neighbors if vrf is not None else bgp.neighbors) if n.peer_group == p.address]
            own = {f for n in members for f in n.families}
            if not own and (p.route_map_in or p.route_map_out or p.prefix_list_in or p.prefix_list_out or
                            p.next_hop_self or p.send_community or p.route_reflector_client):
                own = {"ipv4"}
        ebgp = self.ebgp(bgp, p, vrf)
        for family in sorted(own):
            header = {"ipv4": "address-family ipv4 unicast", "ipv6": "address-family ipv6 unicast",
                      "evpn": "address-family l2vpn evpn"}[family]
            options: List[str] = []
            for direction in ("in", "out"):
                options += self.neighbor_policy(p, direction, label, ebgp, group)
            if p.next_hop_self and family != "evpn":
                options.append("next-hop-self")
            if p.send_community and ebgp:
                options.append("send-community-ebgp")
            elif p.send_community:
                self.report.add("bgp", label, Severity.INFO, "send-community",
                                "IOS-XR sends communities to iBGP neighbors without being told")
            if p.route_reflector_client:
                options.append("route-reflector-client")
            if p.maximum_prefix is not None:
                options.append(f"maximum-prefix {p.maximum_prefix}" + (
                    f" {p.maximum_prefix_warning}" if p.maximum_prefix_warning is not None else ""))
            if p.remove_private_as:
                options.append("remove-private-AS" + (" entire-aspath" if "all" in p.remove_private_as_mode else ""))
                if "replace-as" in p.remove_private_as_mode:
                    self.report.add("bgp", label, Severity.APPROX, "remove-private-as",
                                    "IOS-XR removes private AS numbers without replacing them; replace-as left out")
            if p.allowas_in is not None:
                options.append("allowas-in" + (f" {p.allowas_in}" if p.allowas_in else ""))
            body += [header] + [IND + o for o in options] + ["!"]
        return [head] + [IND + b for b in body] + ["!"]

    def neighbor_policy(self, p: BgpNeighbor, direction: str, label: str, ebgp: bool,
                        group: Optional[BgpNeighbor]) -> List[str]:
        route_map = getattr(p, f"route_map_{direction}")
        prefix_list = getattr(p, f"prefix_list_{direction}")
        if prefix_list:
            name = policy.prefix_policy_name(prefix_list, direction)
            self.prefix_policies[name] = policy.prefix_policy_lines(prefix_list, direction, route_map, self.halves)
            self.report.add("bgp", label, Severity.INFO, "prefix-policy",
                            f"prefix list {prefix_list} ({direction}) is applied through route policy {name}")
            return [f"route-policy {name} {direction}"]
        if route_map:
            if route_map not in self.device.route_maps:
                self.report.add("bgp", label, Severity.REVIEW, "rm-missing",
                                f"route map {route_map} is applied but not defined; IOS-XR refuses the session's "
                                "routes without it")
            return [f"route-policy {route_map} {direction}"]
        inherited = group is not None and (getattr(group, f"route_map_{direction}") or
                                           getattr(group, f"prefix_list_{direction}"))
        if ebgp and not inherited:
            self.pass_all = True
            self.report.add("bgp", label, Severity.APPROX, "ebgp-policy",
                            f"IOS-XR takes and sends no routes on an eBGP session without a policy; "
                            f"{policy.PASS_ALL} is applied {direction} to keep the source's behaviour")
            return [f"route-policy {policy.PASS_ALL} {direction}"]
        return []

    def bgp_vrf(self, bgp: Bgp, name: str, v: BgpVrf) -> List[str]:
        vlabel = f"bgp vrf {name}"
        self.report.item("bgp", vlabel)
        body: List[str] = []
        info = self.device.vrf_info.get(name)
        if info is not None and info.rd:
            body.append(f"rd {info.rd}")
        else:
            body.append("rd auto")
            self.report.add("bgp", vlabel, Severity.APPROX, "rd",
                            "IOS-XR needs a route distinguisher for BGP in a VRF; 'rd auto' is written")
        for family in ("ipv4", "ipv6"):
            version = 4 if family == "ipv4" else 6
            af = [f"network {n}" for n in v.networks if ipaddress.ip_network(n).version == version]
            sources = v.redistribute if family == "ipv4" else v.redistribute6
            af += [self.redistribute(s, v.redistribute_maps.get(s) if family == "ipv4" else None) for s in sources]
            af += [bgp_text.aggregate_line(a, False) for a in v.aggregates
                   if ipaddress.ip_network(a.prefix).version == version]
            if family == "ipv4" and v.maximum_paths:
                af.append(f"maximum-paths ebgp {v.maximum_paths}")
            used = any(family in self.families(bgp, p, v) for p in v.neighbors)
            if af or used:
                body += [f"address-family {family} unicast"] + [IND + a for a in af] + ["!"]
        if v.med_missing_as_worst:
            body.insert(1, "bgp bestpath med missing-as-worst")
        if v.ospf_match:
            self.report.add("bgp", vlabel, Severity.APPROX, "ospf-match",
                            "the OSPF route types redistributed are not written for the VRF")
        for peer in v.neighbors:
            plabel = f"neighbor {peer.address} (vrf {name})"
            self.report.item("bgp", plabel)
            body += self.neighbor(bgp, peer, plabel, f"neighbor {peer.address}", v)
        return [f"vrf {name}"] + [IND + b for b in body] + ["!"]

    # first-hop redundancy ------------------------------------------------------------------------------------------

    def fhrp_lines(self) -> None:
        blocks: Dict[str, List[str]] = {"hsrp": [], "vrrp": []}
        for iface in self.device.interfaces.values():
            if not iface.fhrp or (iface.mode != SwitchportMode.ROUTED and iface.kind in (
                    InterfaceKind.ETHERNET, InterfaceKind.LAG)):
                continue
            name = self.port(iface.name)
            groups = fhrp.plan(iface, "iosxr", self.report, name)
            for protocol in ("hsrp", "vrrp"):
                mine = [g for g in groups if g.protocol == protocol]
                if not mine:
                    continue
                body: List[str] = []
                for g in mine:
                    add = fhrp.adder(self.report, name, g)
                    version = g.version if g.version and g.version != 1 and protocol == "hsrp" else \
                        (3 if protocol == "vrrp" and g.version == 3 else None)
                    head = f"{protocol} {g.group}" + (f" version {version}" if version else "")
                    body += [head] + [IND + line for line in self.group_body(g, add)] + ["!"]
                blocks[protocol] += [f"interface {name}", f"{IND}address-family ipv4"] + \
                    [IND * 2 + b for b in body] + [f"{IND}!", "!"]
        for protocol, lines in blocks.items():
            if lines:
                self.out += [f"router {protocol}"] + [IND + line for line in lines] + ["!"]

    def group_body(self, g: FhrpGroup, add: fhrp.Add) -> List[str]:
        body = []
        if g.priority is not None:
            body.append(f"priority {g.priority}")
        if g.protocol == "hsrp" and g.preempts():
            body.append("preempt")
        if g.protocol == "vrrp" and g.preempt is not None:
            body.append("preempt" if g.preempt else "preempt disable")
        if g.hello_ms is not None:
            if g.protocol == "hsrp":
                hold = g.hold_ms if g.hold_ms is not None else 3 * g.hello_ms
                body.append(f"timers {fhrp.interval(g.hello_ms, 1000, add)} {fhrp.interval(hold, 1000, add)}")
            else:
                body.append(f"timer {fhrp.interval(g.hello_ms, 1000, add, 1, 255)}")
        if g.name:
            if g.protocol == "hsrp":
                body.append(f"name {g.name.replace(' ', '_')}")
            else:
                add(Severity.APPROX, "fhrp-name", f"the description '{g.name}' has no place in an IOS-XR VRRP group")
        body += [f"track object {t} {dec}" for t, dec in self.track_plan.fhrp_tracks(g.tracks)]
        body.append(f"address {g.address}")
        body += [f"address {a} secondary" for a in g.secondary]
        if g.shutdown:
            add(Severity.APPROX, "fhrp-shutdown", "the group is shut down in the source; IOS-XR has no shutdown for "
                                                  "a group, so it is written active: remove it if it must stay down")
        return body

    # layer 2 ---------------------------------------------------------------------------------------------------------

    def l2vpn(self) -> None:
        d = self.device
        svis = {int(i.name[4:]) for i in d.interfaces.values() if i.kind == InterfaceKind.VLAN and i.name[4:].isdigit()}
        vids = sorted(set(d.vlans) | set(self.domains) | svis)
        body: List[str] = []
        for vid in vids:
            self.report.item("vlan", str(vid))
            vlan = d.vlans.get(vid)
            name = self.domain_name(vid)
            if vlan is not None and vlan.name and not name.endswith(vlan.name):
                self.report.add("vlan", str(vid), Severity.APPROX, "vlan-name",
                                f"the name is shortened in the bridge domain name {name}")
            lines = [f"interface {member}" for member in self.domains.get(vid, [])]
            lines = [x for line in lines for x in (line, "!")]
            if vid in svis:
                lines.append(f"routed interface BVI{vid}")
            if vlan is not None and vlan.shutdown:
                lines.append("shutdown")
            body += [f"bridge-domain {name}"] + [IND + line for line in lines] + ["!"]
        if body:
            self.out += ["l2vpn", f"{IND}bridge group {BRIDGE_GROUP}"] + [IND * 2 + b for b in body] + \
                [f"{IND}!", "!"]
        if d.stp_mode is not None or d.stp.priority or d.stp.vlan_priority:
            self.report.item("system", "spanning-tree mode")
            self.report.add("system", "spanning-tree mode", Severity.REVIEW, "stp",
                            "spanning tree is not written: IOS-XR bridge domains run none unless 'spanning-tree mst' "
                            "is set up for the ports; check the layer 2 design for loops")

    def relay(self) -> None:
        profiles: Dict[Tuple[str, Tuple[str, ...]], str] = {}
        interfaces: List[str] = []
        for iface in self.device.interfaces.values():
            if not iface.helper_addresses:
                continue
            vrf = iface.helper_vrf or iface.vrf or "default"
            key = (vrf, tuple(iface.helper_addresses))
            if key not in profiles:
                profiles[key] = f"RS-RELAY-{len(profiles) + 1}"
            interfaces.append(f"interface {self.port(iface.name)} relay profile {profiles[key]}")
            if iface.helper_source:
                self.report.add("interface", self.label(iface), Severity.APPROX, "relay-source",
                                "the relay's source interface is not written: IOS-XR relays from the receiving "
                                "interface")
        if not profiles:
            return
        body: List[str] = []
        for (vrf, addresses), name in profiles.items():
            body += [f"profile {name} relay"] + [f"{IND}helper-address vrf {vrf} {a}" for a in addresses] + ["!"]
        self.out += ["dhcp ipv4"] + [IND + b for b in body + interfaces] + ["!"]

    def multicast(self) -> None:
        d = self.device
        if multicast_text.stated(d):
            self.report.skip("vlan", multicast_text.LABEL, "igmp-snooping",
                             "IGMP snooping is set per bridge domain on IOS-XR (igmp snooping profile); not written")
        if not multicast_text.uses_pim(d):
            return
        self.report.item("system", "multicast routing")
        pim_ifaces = [i for i in d.interfaces.values() if i.pim]
        self.out += ["multicast-routing", f"{IND}address-family ipv4", f"{IND * 2}interface all enable", f"{IND}!",
                     "!"]
        body: List[str] = []
        for rp in d.pim_rps:
            groups = d.pim_rp_groups.get(rp, "")
            if groups.startswith("acl "):
                body.append(f"rp-address {rp} {groups[4:]}")
            elif groups:
                body.append(f"rp-address {rp}")
                self.report.add("system", "multicast routing", Severity.REVIEW, "pim-rp",
                                f"RP {rp} serves {groups}: IOS-XR limits an RP with an ACL; write one and add it to "
                                "the rp-address line")
            else:
                body.append(f"rp-address {rp}")
        for iface in pim_ifaces:
            body += [f"interface {self.port(iface.name)}", f"{IND}enable", "!"]
            if iface.pim != "sparse":
                self.report.add("system", "multicast routing", Severity.APPROX, "pim-mode",
                                f"{iface.source_name or iface.name}: IOS-XR runs PIM sparse mode only; "
                                f"{iface.pim} mode is written as sparse")
        if body:
            self.out += ["router pim", f"{IND}address-family ipv4"] + [IND * 2 + b for b in body] + [f"{IND}!", "!"]
        igmp = [i for i in d.interfaces.values() if i.igmp_version is not None]
        if igmp:
            lines: List[str] = []
            for iface in igmp:
                lines += [f"interface {self.port(iface.name)}", f"{IND}version {iface.igmp_version}", "!"]
            self.out += ["router igmp"] + [IND + line for line in lines] + ["!"]
        for what, stated in (("anycast RP", d.pim_anycast), ("MSDP peers", d.msdp_peers),
                             ("multicast routing in VRFs", d.multicast_vrfs)):
            if stated:
                self.report.add("system", "multicast routing", Severity.REVIEW, "pim-options",
                                f"{what} not written for IOS-XR yet; set it up by hand")

    # management ------------------------------------------------------------------------------------------------------

    def management(self) -> None:
        m = self.device.management
        out = self.out
        if m.lldp or m.lldp_timer is not None or m.lldp_holdtime is not None or \
                any(not (i.lldp_tx and i.lldp_rx) for i in self.device.interfaces.values()):
            self.report.item("management", "LLDP")
            body = []
            if m.lldp_timer is not None:
                body.append(f"timer {m.lldp_timer}")
            if m.lldp_holdtime is not None:
                body.append(f"holdtime {m.lldp_holdtime}")
            if m.lldp_mgmt_interface or m.lldp_mgmt_vrf:
                self.report.add("management", "LLDP", Severity.APPROX, "lldp-mgmt",
                                "the LLDP management address is not written; IOS-XR advertises the port's own")
            out += ["lldp"] + [IND + b for b in body] + ["!"]
        if m.cdp:
            self.report.item("management", "CDP")
            out.append("cdp")
        if m.ssh:
            self.report.item("management", "ssh")
            out.append("ssh server v2")
            if m.vrf:
                out.append(f"ssh server vrf {m.vrf}")
        if m.telnet:
            self.report.item("management", "telnet")
            out.append(f"telnet vrf {m.vrf or 'default'} ipv4 server max-servers 10")
        if m.http or m.https:
            self.report.item("management", "http")
            self.report.add("management", "http", Severity.REVIEW, "http",
                            "IOS-XR has no web server for management; use NETCONF or gRPC instead")
        for api, vrf in m.apis.items():
            label = f"api {api}"
            self.report.item("management", label)
            if api == "netconf":
                out += ["netconf-yang agent", f"{IND}ssh", "!"]
                if vrf:
                    self.report.add("management", label, Severity.APPROX, "api-vrf",
                                    f"NETCONF runs over the SSH server, in its VRF; VRF {vrf} is not written")
            elif api == "gnmi":
                out += ["grpc", f"{IND}port 57400"] + ([f"{IND}vrf {vrf}"] if vrf else []) + ["!"]
            else:
                self.report.skip("management", label, "api",
                                 f"IOS-XR has no {api} API; use NETCONF or gRPC instead")
            if api in m.api_acls:
                self.report.add("management", label, Severity.REVIEW, "api-acl",
                                f"the client ACL {m.api_acls[api]} is not written for the API")
        if m.password_min_length is not None:
            self.report.item("management", "password length")
            out += ["aaa password-policy RS-POLICY", f"{IND}min-length {m.password_min_length}", "!"]
            self.report.add("management", "password length", Severity.APPROX, "password-policy",
                            "written as password policy RS-POLICY; apply it to each user with 'password-policy'")
        out.append("!")

    def unwritable(self) -> None:
        """What IOS-XR routers have no place for, reported once each."""
        d, rep = self.device, self.report
        for name in d.event_handlers:
            rep.skip("system", f"event handler {name}", "event-handlers",
                     "IOS-XR runs EEM scripts (event manager) differently; rebuild the handler by hand")
        if d.ecmp_hash:
            rep.add("system", "ECMP hashing", Severity.APPROX, "ecmp-hash",
                    "IOS-XR hashes on addresses and ports by default (cef load-balancing fields); the hash fields are "
                    "not written")
        if d.bfd_multihop is not None or d.bfd_slow_timer is not None:
            rep.add("system", "BFD", Severity.APPROX, "bfd-global",
                    "the BFD multihop and slow timers are not written; IOS-XR sets BFD timers per protocol")
        if d.twamp_port is not None:
            rep.skip("monitor", "TWAMP reflector", "twamp", "the TWAMP reflector is not written for IOS-XR yet")
        if d.control_plane is not None:
            rep.skip("security", "control plane", "copp",
                     "IOS-XR protects its control plane with LPTS; the CoPP policy is not converted")
        if d.system.router_id and not d.ospf and d.bgp is None:
            rep.add("system", "router ID", Severity.REVIEW, "router-id",
                    f"IOS-XR sets the router ID per protocol and the device runs no OSPF or BGP: "
                    f"{d.system.router_id} is not written")
        if d.dhcp_option82 is not None:
            rep.add("system", "DHCP snooping", Severity.APPROX, "option82", "the DHCP option 82 setting is not written")


def emit(device: Device, ports: PortMapper, report: Report) -> str:
    return Writer(device, ports, report).emit()
