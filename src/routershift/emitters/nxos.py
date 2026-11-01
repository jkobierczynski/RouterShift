# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for Cisco NX-OS (Nexus 9000 and 3000, 9.x and 10.x).

NX-OS is close to IOS, with its own habits: every protocol is switched on with a 'feature' line, ports take
prefix lengths, a VRF is a 'vrf context' that also holds its static routes, the management port lives in VRF
management, OSPF is enabled on the interface, BGP neighbors are blocks with their address families inside, and
redistribution always takes a route map. This writer covers the system settings, users, SNMP communities, VLANs,
ports, port-channels, SVIs, VRFs, static routes, ACLs, prefix lists and route maps, HSRP and VRRP, DHCP relay,
OSPF, BGP, spanning tree and LLDP/CDP. Everything else is listed in the report as not written for NX-OS yet.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Set

from .. import aaa as aaa_text
from .. import acl as acl_text
from .. import bgp as bgp_text
from .. import fhrp
from .. import hosts as hosts_text
from .. import ospf as ospf_text
from .. import partial
from .. import routemap as routemap_text
from .. import snmp as snmp_text
from .. import stp as stp_text
from .. import vrfs as vrfs_text
from ..model import (BgpNeighbor, Device, FhrpGroup, Interface, InterfaceKind, LacpMode, Ospf, StaticRoute, StpMode,
                     SwitchportMode)
from ..names import PortMapper
from ..report import Report, Severity
from ..timezones import offset_minutes

PLATFORM = "NX-OS"
IND = "  "
ROLES = [(15, "network-admin"), (0, "network-operator")]
HASHES = ("md5-crypt", "sha256-crypt", "sha512-crypt")
MGMT_VRF = "management"
PERMIT_ALL = "RS-PERMIT-ALL"  # the route map NX-OS needs for redistribution where the source had none
WRITTEN = {"acl", "policy", "dhcp-relay", "fhrp", "speed", "storm", "stp-guards"}
_MGMT_NAMES = {"mgmt-vrf", "mgmt-intf", "management", "mgmt"}


class Writer:
    def __init__(self, device: Device, ports: PortMapper, report: Report) -> None:
        self.device = device
        self.port = ports
        self.report = report
        self.out: List[str] = []
        self.features: Set[str] = set()
        self.mgmt_vrfs = {i.vrf for i in device.interfaces.values() if i.kind == InterfaceKind.MANAGEMENT and i.vrf}
        self.mgmt_vrfs |= {v for v in device.vrfs if v.lower() in _MGMT_NAMES}
        self.permit_all = False
        self.evpn = False  # nv overlay evpn, for the EVPN address family
        self.ospf_tags: Dict[int, str] = {}  # id of an Ospf -> the router ospf tag it is written under

    def vrf(self, name: str) -> str:
        return MGMT_VRF if name in self.mgmt_vrfs else name

    def label(self, iface: Interface) -> str:
        return f"{iface.source_name or iface.name} -> {self.port(iface.name)}"

    def emit(self) -> str:
        body: List[str] = []
        self.out = body
        self.system()
        self.users()
        self.snmp()
        self.acls()
        self.policies()
        self.vlans()
        self.spanning_tree()
        self.vrfs()
        self.routes([r for r in self.device.static_routes if not r.vrf], "")
        for iface in self.device.interfaces.values():
            self.interface(iface)
        self.ospf()
        self.bgp()
        self.vty()
        if self.permit_all:
            self.out += [f"route-map {PERMIT_ALL} permit 10", "!"]
        partial.device(self.device, self.report, PLATFORM, WRITTEN)
        self.report.unparsed(self.device.unparsed)
        head = [f"feature {f}" for f in sorted(self.features)]
        if self.device.management.ssh is False:
            head.append("no feature ssh")
        if self.evpn:
            head.append("nv overlay evpn")
        return "\n".join(head + (["!"] if head else []) + body) + "\n"

    # system ----------------------------------------------------------------------------------------------------------

    def use_vrf(self) -> str:
        vrf = self.device.system.service_vrf
        return f" use-vrf {self.vrf(vrf)}" if vrf else ""

    def system(self) -> None:
        sy = self.device.system
        if sy.hostname:
            self.out.append(f"hostname {sy.hostname}")
            self.report.item("system", "hostname")
        if sy.banner_motd:
            delim = "#" if "#" not in sy.banner_motd else "%"
            self.out += [f"banner motd {delim}", sy.banner_motd, delim]
            self.report.item("system", "banner motd")
        if sy.domain_name:
            self.out.append(f"ip domain-name {sy.domain_name}")
        for domain in sy.dns_search:
            self.out.append(f"ip domain-list {domain}")
        if sy.dns_servers:
            self.out.append(f"ip name-server {' '.join(sy.dns_servers)}{self.use_vrf()}")
        if sy.dns_lookup is not None:
            self.out.append("ip domain-lookup" if sy.dns_lookup else "no ip domain-lookup")
        for host, address in sy.dns_hosts.items():
            self.out.append(f"ip host {host} {address}")
        hosts_text.dns_unsupported(self.device, self.report, PLATFORM, lookup=True, search=True, hosts=True)
        if sy.timezone:
            self.timezone(sy.timezone)
        for number, key in sorted(sy.ntp_keys.items()):
            label = f"ntp key {number}"
            self.report.item("system", label)
            if key.algorithm != "md5":
                self.report.add("system", label, Severity.REVIEW, "ntp-algorithm",
                                f"NX-OS takes MD5 NTP keys only; the {key.algorithm} key is written as MD5, change it on "
                                "both sides")
            self.out.append(f"ntp authentication-key {number} md5 {snmp_text.ntp_key(key, self.report)} 0")
            if key.trusted:
                self.out.append(f"ntp trusted-key {number}")
        if sy.ntp_authenticate:
            self.out.append("ntp authenticate")
        for server in sy.ntp_servers:
            self.report.item("system", f"ntp server {server}")
            words = ["ntp", "server", server]
            if server == sy.ntp_prefer:
                words.append("prefer")
            if server in sy.ntp_server_keys:
                words += ["key", str(sy.ntp_server_keys[server])]
            self.out.append(" ".join(words) + self.use_vrf())
        if sy.ntp_source:
            self.out.append(f"ntp source-interface {self.port(sy.ntp_source)}")
        for server in sy.syslog_servers:
            self.report.item("system", f"syslog {server}")
            level = f" {sy.logging_level}" if sy.logging_level is not None else ""
            self.out.append(f"logging server {server}{level}{self.use_vrf()}")
        if sy.logging_source and sy.syslog_servers:
            self.out.append(f"logging source-interface {self.port(sy.logging_source)}")
        for name, source in sy.transfer_source.items():
            self.report.skip("system", f"{name} source interface", partial.CODE,
                             f"not written for NX-OS yet ({source}); configure it by hand")
        m = self.device.management
        if m.telnet:
            self.features.add("telnet")
            self.report.item("management", "telnet")
        if m.ssh:
            self.report.item("management", "ssh")
        if m.http or m.https:
            self.report.skip("management", "web server", partial.CODE,
                             "NX-OS has no HTTP management server; use NX-API (feature nxapi) by hand if needed")
        if m.lldp or any(not (i.lldp_tx and i.lldp_rx) for i in self.device.interfaces.values()):
            self.features.add("lldp")
            self.report.item("management", "LLDP")
        if m.cdp is False:
            self.out.append("no cdp enable")
            self.report.item("management", "CDP")
        self.out.append("!")

    def timezone(self, tz: str) -> None:
        """NX-OS takes a name and an offset, as IOS does."""
        self.report.item("system", "time zone")
        minutes = offset_minutes(tz)
        if minutes is None:
            self.report.add("system", "time zone", Severity.REVIEW, "timezone",
                            f"NX-OS takes a fixed offset (clock timezone NAME H M); '{tz}' is not written, set it by "
                            "hand with clock summer-time if it has one")
            return
        words = tz.split()
        name = words[0] if len(words) >= 2 and words[1].lstrip("-").isdigit() else "UTC"
        sign = "-" if minutes < 0 else ""
        self.out.append(f"clock timezone {name} {sign}{abs(minutes) // 60} {abs(minutes) % 60}")

    def users(self) -> None:
        for user in self.device.users:
            label = aaa_text.user_label(user)
            password = aaa_text.password(user, HASHES, self.report)
            if password is None:
                continue
            self.report.item("management", label)
            kind, value = password
            role = aaa_text.role(user.privilege, ROLES)
            if kind == "plain":
                self.out.append(f"username {user.name} password {value} role {role}")
            elif kind in HASHES:
                self.out.append(f"username {user.name} password 5 {value} role {role}")
            else:
                self.out.append(f"username {user.name} role {role}")
                self.report.add("management", label, Severity.REVIEW, "no-password",
                                "the user has no password in the source; set one")
        if self.device.aaa.enable_secret is not None:
            self.report.skip("management", "enable secret", "enable",
                             "NX-OS has no enable password; the role of each user sets what it may do")

    def snmp(self) -> None:
        sn = self.device.snmp
        if sn.location:
            self.out.append(f"snmp-server location {sn.location}")
        if sn.contact:
            self.out.append(f"snmp-server contact {sn.contact}")
        for c in sn.communities:
            label = snmp_text.community_label(self.device, c)
            self.report.item("management", label)
            group = "network-admin" if c.access == "rw" else "network-operator"
            self.out.append(f"snmp-server community {c.name} group {group}")
            if c.acl:
                self.report.add("management", label, Severity.REVIEW, partial.CODE,
                                f"the manager list {c.acl} is not written for NX-OS yet (use-acl)")
        rest = [what for what, stated in (("notification hosts", bool(sn.hosts or sn.traps)),
                                          ("SNMPv3 users and groups", bool(sn.users or sn.groups)),
                                          ("the source interface", bool(sn.source))) if stated]
        if rest:
            self.report.skip("management", "SNMP", partial.CODE,
                             f"not written for NX-OS yet: {', '.join(rest)}; configure by hand")

    # ACLs and policies -----------------------------------------------------------------------------------------------

    def acls(self) -> None:
        for acl in self.device.acls.values():
            name = acl_text.safe_name(acl.name)
            label = acl.name if name == acl.name else f"{acl.name} -> {name}"
            self.report.item("acl", label)
            self.out.append(f"{'ipv6' if acl.family == 6 else 'ip'} access-list {name}")
            lines = acl_text.cisco_lines(acl, self.report, label, "prefix",
                                         any_protocol="ipv6" if acl.family == 6 else "ip", icmp6="icmp",
                                         icmp_names=True)
            self.out += [IND + line for line in lines]
            self.out.append("!")

    def policies(self) -> None:
        routemap_text.items(self.device, self.report)
        for pl in self.device.prefix_lists.values():
            self.out += routemap_text.ios_prefix_lines(pl, "ios")
        for rm in self.device.route_maps.values():
            self.out += routemap_text.ios_route_map_lines(rm, "ios", self.report, IND)

    # layer 2 ---------------------------------------------------------------------------------------------------------

    def vlans(self) -> None:
        for vid, vlan in sorted(self.device.vlans.items()):
            self.report.item("vlan", str(vid))
            self.out.append(f"vlan {vid}")
            if vlan.name:
                self.out.append(f"{IND}name {vlan.name.replace(' ', '_')}")
            if vlan.shutdown:
                self.out.append(f"{IND}shutdown")
            if vlan.dhcp_snooping or vlan.arp_inspection or vlan.igmp_querier:
                self.report.add("vlan", str(vid), Severity.REVIEW, partial.CODE,
                                "DHCP snooping, ARP inspection and the IGMP querier are not written for NX-OS yet")
        if self.device.vlans:
            self.out.append("!")

    def spanning_tree(self) -> None:
        dev = self.device
        mode = dev.stp_mode
        if mode is None and not (dev.stp.priority or dev.stp.vlan_priority):
            return
        self.report.item("system", "spanning-tree mode")
        written = StpMode.MSTP if mode in (StpMode.MSTP, StpMode.STP, StpMode.RSTP) else StpMode.RAPID_PVST
        if mode == StpMode.NONE:
            self.report.add("system", "spanning-tree mode", Severity.REVIEW, "stp-off",
                            "NX-OS always runs spanning tree; rapid PVST+ stays on")
            return
        if mode in (StpMode.STP, StpMode.RSTP, StpMode.PVST):
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                            f"NX-OS runs rapid PVST+ or MST; {mode.value} is written as {written.value}")
        self.out.append("spanning-tree mode mst" if written == StpMode.MSTP else "spanning-tree mode rapid-pvst")
        instances, per_vlan = stp_text.priorities(dev, written, self.report)
        for instance, value in sorted(instances.items()):
            self.out.append(f"spanning-tree mst {instance} priority {value}")
        for vid, value in sorted(per_vlan.items()):
            self.out.append(f"spanning-tree vlan {vid} priority {value}")
        if stp_text.region(dev, written, self.report):
            self.out.append("spanning-tree mst configuration")
            if dev.stp.region:
                self.out.append(f"{IND}name {dev.stp.region}")
            if dev.stp.revision is not None:
                self.out.append(f"{IND}revision {dev.stp.revision}")
            for instance, vlans in sorted(dev.stp.instances.items()):
                self.out.append(f"{IND}instance {instance} vlan {stp_text.vlan_text(vlans)}")
        self.out.append("!")

    # VRFs and routes -------------------------------------------------------------------------------------------------

    def vrfs(self) -> None:
        names = list(dict.fromkeys([self.vrf(v) for v in self.device.vrfs] + [
            self.vrf(r.vrf) for r in self.device.static_routes if r.vrf]))
        for name in names:
            sources = [v for v in self.device.vrfs if self.vrf(v) == name] or [name]
            self.report.item("system", f"vrf {sources[0]}")
            self.out.append(f"vrf context {name}")
            info = self.device.vrf_info.get(sources[0])
            if info is not None and (info.rd or info.rt_import or info.rt_export) and name == MGMT_VRF:
                self.report.add("system", f"vrf {sources[0]}", Severity.APPROX, "mgmt-vrf",
                                "it becomes NX-OS VRF management, which takes no route distinguisher or route targets")
            elif info is not None and (info.rd or info.rt_import or info.rt_export):
                if info.rd:
                    self.out.append(f"{IND}rd {info.rd}")
                pairs = vrfs_text.targets(info)
                if pairs:
                    self.out.append(f"{IND}address-family ipv4 unicast")
                    self.out += [f"{IND * 2}route-target {direction} {value}" for direction, value in pairs]
            self.routes([r for r in self.device.static_routes if r.vrf and self.vrf(r.vrf) == name], IND)
        if names:
            self.out.append("!")

    def routes(self, routes: List[StaticRoute], ind: str) -> None:
        for route in routes:
            label = f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}"
            self.report.item("route", label)
            net = ipaddress.ip_network(route.prefix)
            words = ["ip" if net.version == 4 else "ipv6", "route", str(net)]
            if route.discard:
                words.append("Null0")
            else:
                if route.interface:
                    words.append(self.port(route.interface))
                if route.next_hop:
                    words.append(route.next_hop)
            if route.name:
                words += ["name", route.name.replace(" ", "_")]
            if route.distance is not None:
                words.append(str(route.distance))
            if route.track:
                self.report.add("route", label, Severity.REVIEW, partial.CODE,
                                f"tracking (object {route.track}) is not written for NX-OS yet; the route is always on")
            self.out.append(ind + " ".join(words))
        if routes and not ind:
            self.out.append("!")

    # interfaces ------------------------------------------------------------------------------------------------------

    def interface(self, iface: Interface) -> None:
        label = self.label(iface)
        if iface.kind in (InterfaceKind.TUNNEL, InterfaceKind.OTHER):
            self.report.skip("interface", label, partial.CODE,
                             "tunnel interfaces are not written for NX-OS yet; configure it by hand")
            return
        self.report.item("interface", label)
        if (iface.source_name or iface.name, self.port(iface.name)) in self.port.renumbered:
            self.report.add("interface", label, Severity.APPROX, "port-renamed",
                            f"named {self.port(iface.name)} without a port map; check it against the cabling of the new "
                            "device")
        name = self.port(iface.name)
        lines: List[str] = []
        if iface.description:
            lines.append(f"description {iface.description}")
        physical = iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG)
        if iface.kind == InterfaceKind.VLAN:
            self.features.add("interface-vlan")
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.encapsulation_vlan:
            lines.append(f"encapsulation dot1q {iface.encapsulation_vlan}")
        if physical and not iface.lag:
            lines += self.switchport(iface)
        if iface.kind == InterfaceKind.ETHERNET:
            if iface.speed:
                lines.append(f"speed {iface.speed}")
            if iface.duplex in ("full", "half"):
                lines.append(f"duplex {iface.duplex}")
        if iface.mtu:
            lines.append(f"mtu {iface.mtu}")
        if iface.lag:
            lag = self.device.interfaces.get(iface.lag)
            mode = iface.lacp_mode or (lag.lacp_mode if lag else None) or LacpMode.STATIC
            if mode != LacpMode.STATIC:
                self.features.add("lacp")
            word = {LacpMode.ACTIVE: "active", LacpMode.PASSIVE: "passive"}.get(mode, "on")
            lines.append(f"channel-group {iface.lag[len('Port-channel'):]} mode {word}")
        layer3 = iface.mode == SwitchportMode.ROUTED or not physical
        if layer3 and not iface.lag:
            lines += self.layer3(iface, name)
        for key, value in sorted(iface.storm_control.items()):
            if key in ("broadcast", "multicast", "unicast"):
                lines.append(f"storm-control {key} level {value:.2f}")
            else:
                self.report.add("interface", label, Severity.APPROX, "storm",
                                f"NX-OS has no {key} storm control; left out")
        if not iface.lldp_tx:
            lines.append("no lldp transmit")
        if not iface.lldp_rx:
            lines.append("no lldp receive")
        if iface.cdp is False:
            lines.append("no cdp enable")
        if iface.kind == InterfaceKind.MANAGEMENT and not iface.vrf:
            self.report.add("interface", label, Severity.APPROX, "mgmt-vrf",
                            "mgmt0 is always in VRF management on NX-OS; routes for it go in vrf context management")
        lines.append("shutdown" if iface.shutdown else "no shutdown")
        partial.port(iface, self.report, label, PLATFORM, WRITTEN if layer3 else WRITTEN - {"fhrp", "dhcp-relay"})
        self.out.append(f"interface {name}")
        self.out += [IND + line for line in lines]
        self.out.append("!")

    def switchport(self, iface: Interface) -> List[str]:
        if iface.mode == SwitchportMode.ROUTED:
            return ["no switchport"]
        lines = ["switchport"]
        if iface.mode == SwitchportMode.TRUNK:
            lines.append("switchport mode trunk")
            if iface.native_vlan:
                lines.append(f"switchport trunk native vlan {iface.native_vlan}")
            if iface.allowed_vlans:
                lines.append(f"switchport trunk allowed vlan {iface.allowed_vlans}")
        elif iface.access_vlan:
            lines.append(f"switchport access vlan {iface.access_vlan}")
        if iface.stp_portfast:
            lines.append("spanning-tree port type edge" + (" trunk" if iface.mode == SwitchportMode.TRUNK else ""))
        if iface.stp_bpduguard:
            lines.append("spanning-tree bpduguard enable")
        if iface.stp_guard:
            lines.append(f"spanning-tree guard {iface.stp_guard}")
        if iface.stp_bpdufilter:
            lines.append("spanning-tree bpdufilter enable")
        if iface.stp_cost:
            lines.append(f"spanning-tree cost {iface.stp_cost}")
        if iface.stp_port_priority is not None:
            lines.append(f"spanning-tree port-priority {iface.stp_port_priority}")
        if iface.acl_in and iface.acl_in in self.device.acls:
            lines.append(f"ip port access-group {acl_text.safe_name(iface.acl_in)} in")
        return lines

    def layer3(self, iface: Interface, name: str) -> List[str]:
        label = self.label(iface)
        lines: List[str] = []
        vrf = iface.vrf if iface.kind != InterfaceKind.MANAGEMENT else (iface.vrf or MGMT_VRF)
        if vrf:
            lines.append(f"vrf member {self.vrf(vrf)}")
        for n, address in enumerate(iface.ipv4):
            lines.append(f"ip address {address}" + (" secondary" if n else ""))
        if iface.dhcp_client:
            lines.append("ip address dhcp")
        for address in iface.ipv6:
            lines.append(f"ipv6 address {address}")
        for attr, word, direction in (("acl_in", "ip", "in"), ("acl_out", "ip", "out"),
                                      ("acl6_in", "ipv6", "in"), ("acl6_out", "ipv6", "out")):
            acl = getattr(iface, attr)
            if acl and acl in self.device.acls:
                lines.append(f"{word} {'traffic-filter' if word == 'ipv6' else 'access-group'} "
                             f"{acl_text.safe_name(acl)} {direction}")
            elif acl:
                self.report.add("interface", label, Severity.REVIEW, "acl-missing",
                                f"ACL {acl} is applied but not defined; left out")
        if iface.helper_addresses:
            self.features.add("dhcp")
        for helper in iface.helper_addresses:
            lines.append(f"ip dhcp relay address {helper}")
        lines += self.ospf_interface(iface)
        lines += self.fhrp_lines(iface, name)
        return lines

    def fhrp_lines(self, iface: Interface, name: str) -> List[str]:
        lines: List[str] = []
        groups = fhrp.plan(iface, "nxos", self.report, name)
        hsrp = [g for g in groups if g.protocol == "hsrp"]
        if hsrp:
            self.features.add("hsrp")
        if any(g.version == 2 or g.group > 255 for g in hsrp):
            lines.append("hsrp version 2")
        for g in groups:
            add = fhrp.adder(self.report, name, g)
            if g.tracks:
                add(Severity.REVIEW, partial.CODE, "tracking is not written for NX-OS yet")
            body = self.hsrp(g) if g.protocol == "hsrp" else self.vrrp(g, add)
            lines.append(f"{g.protocol} {g.group}")
            lines += [IND + line for line in body]
        return lines

    @staticmethod
    def hsrp(g: FhrpGroup) -> List[str]:
        body = []
        if g.preempts():
            body.append("preempt")
        if g.priority is not None:
            body.append(f"priority {g.priority}")
        if g.hello_ms is not None:
            hold = g.hold_ms if g.hold_ms is not None else 3 * g.hello_ms
            if g.hello_ms % 1000 or hold % 1000:
                body.append(f"timers msec {g.hello_ms} msec {hold}")
            else:
                body.append(f"timers {g.hello_ms // 1000} {hold // 1000}")
        if g.name:
            body.append(f"name {g.name.replace(' ', '_')}")
        body.append(f"ip {g.address}")
        body += [f"ip {a} secondary" for a in g.secondary]
        if g.shutdown:
            body.append("shutdown")
        return body

    def vrrp(self, g: FhrpGroup, add: fhrp.Add) -> List[str]:
        self.features.add("vrrp")
        body = []
        if g.priority is not None:
            body.append(f"priority {g.priority}")
        if g.hello_ms is not None:
            body.append(f"advertisement-interval {fhrp.interval(g.hello_ms, 1000, add, 1, 255)}")
        if not g.preempts():
            body.append("no preempt")
        if g.version == 3:
            add(Severity.APPROX, "fhrp-version", "VRRPv3 written as VRRPv2")
        if g.name:
            add(Severity.APPROX, "fhrp-name", f"the description '{g.name}' has no place in an NX-OS VRRP group")
        body.append(f"address {g.address}")
        body += [f"address {a} secondary" for a in g.secondary]
        body.append("shutdown" if g.shutdown else "no shutdown")
        return body

    # OSPF ------------------------------------------------------------------------------------------------------------

    def tag(self, p: Ospf) -> str:
        """The router ospf tag: each process outside a VRF keeps its number; the VRF processes go under the first."""
        if id(p) not in self.ospf_tags:
            main = [q for q in self.device.ospf if not q.vrf]
            self.ospf_tags[id(p)] = p.process if not p.vrf else (main[0].process if main else p.process)
        return self.ospf_tags[id(p)]

    def ospf_interface(self, iface: Interface) -> List[str]:
        lines: List[str] = []
        for p in self.device.ospf:
            areas = ospf_text.interfaces(self.device, p)
            if iface.name not in areas:
                continue
            lines.append(f"ip router ospf {self.tag(p)} area {areas[iface.name]}")
            if p.passive(iface.name):
                lines.append("ip ospf passive-interface")
            break
        if lines and iface.ospf_cost:
            lines.append(f"ip ospf cost {iface.ospf_cost}")
        if lines and iface.ospf_network == "point-to-point":
            lines.append("ip ospf network point-to-point")
        return lines

    def redistribute(self, source: str, route_map: Optional[str], kind: str, label: str) -> str:
        word = "direct" if source == "connected" else source
        if source == "ospf":
            word = f"ospf {self.device.ospf[0].process if self.device.ospf else '1'}"
        if not route_map:
            self.permit_all = True
            self.report.add(kind, label, Severity.APPROX, "redistribute-map",
                            f"NX-OS redistributes through a route map; {PERMIT_ALL} (permit everything) is written for "
                            f"redistribute {source}")
        return f"redistribute {word} route-map {route_map or PERMIT_ALL}"

    def ospf(self) -> None:
        if not self.device.ospf:
            return
        self.features.add("ospf")
        tags: Dict[str, List[Ospf]] = {}
        for p in self.device.ospf:
            tags.setdefault(self.tag(p), []).append(p)
        for tag, processes in tags.items():
            self.out.append(f"router ospf {tag}")
            for p in sorted(processes, key=lambda q: bool(q.vrf)):
                label = ospf_text.label(p)
                self.report.item("ospf", label)
                ind = IND
                if p.vrf:
                    self.out.append(f"{IND}vrf {self.vrf(p.vrf)}")
                    ind = IND * 2
                    if p.process != tag:
                        self.report.add("ospf", label, Severity.INFO, "ospf-tag",
                                        f"written as vrf {p.vrf} of router ospf {tag}")
                body = []
                if p.router_id:
                    body.append(f"router-id {p.router_id}")
                if p.reference_bandwidth:
                    body.append(f"auto-cost reference-bandwidth {p.reference_bandwidth} Mbps")
                for area, kind in p.area_types.items():
                    body.append(f"area {area} {kind}")
                for source in p.redistribute:
                    body.append(self.redistribute(source, p.redistribute_maps.get(source), "ospf", label))
                if p.default_originate:
                    body.append("default-information originate" + (" always" if p.default_originate == "always"
                                                                    else ""))
                if p.bfd_all:
                    self.report.add("ospf", label, Severity.REVIEW, partial.CODE, "BFD is not written for NX-OS yet")
                self.out += [ind + line for line in body]
            self.out.append("!")

    # BGP -------------------------------------------------------------------------------------------------------------

    def bgp(self) -> None:
        bgp = self.device.bgp
        if bgp is None:
            return
        self.features.add("bgp")
        label = f"bgp {bgp.local_as}"
        self.report.item("bgp", label)
        if bgp.peer_groups:
            self.report.add("bgp", label, Severity.APPROX, "peer-groups",
                            f"the peer groups {', '.join(bgp.peer_groups)} are written into each neighbor; NX-OS "
                            "templates are not used")
        self.out.append(f"router bgp {bgp.local_as}")
        if bgp.router_id:
            self.out.append(f"{IND}router-id {bgp.router_id}")
        af: List[str] = [f"network {n}" for n in bgp.networks if ipaddress.ip_network(n).version == 4]
        af += [self.redistribute(s, bgp.redistribute_maps.get(s), "bgp", label) for s in bgp.redistribute]
        af += [f"maximum-paths {bgp.maximum_paths}"] if bgp.maximum_paths else []
        af += [f"maximum-paths ibgp {bgp.maximum_paths_ibgp}"] if bgp.maximum_paths_ibgp else []
        if af:
            self.out.append(f"{IND}address-family ipv4 unicast")
            self.out += [IND * 2 + line for line in af]
        af6 = [f"network {n}" for n in bgp.networks if ipaddress.ip_network(n).version == 6]
        af6 += [self.redistribute(s, None, "bgp", label) for s in bgp.redistribute6]
        if af6:
            self.out.append(f"{IND}address-family ipv6 unicast")
            self.out += [IND * 2 + line for line in af6]
        for peer in bgp_text.flat(bgp):
            self.report.item("bgp", f"neighbor {peer.address}")
            bgp_text.unwritten(peer, set(bgp_text.OPTIONS), self.report, f"neighbor {peer.address}", "NX-OS")
            self.out += [IND + line for line in self.neighbor(peer)]
        for name, v in bgp.vrfs.items():
            vlabel = f"bgp vrf {name}"
            self.report.item("bgp", vlabel)
            self.out.append(f"{IND}vrf {name}")
            vaf = [f"network {n}" for n in v.networks]
            vaf += [self.redistribute(s, v.redistribute_maps.get(s), "bgp", vlabel) for s in v.redistribute]
            vaf += [f"maximum-paths {v.maximum_paths}"] if v.maximum_paths else []
            if vaf:
                self.out.append(f"{IND * 2}address-family ipv4 unicast")
                self.out += [IND * 3 + line for line in vaf]
            for peer in v.neighbors:
                plabel = f"neighbor {peer.address} (vrf {name})"
                self.report.item("bgp", plabel)
                bgp_text.unwritten(peer, set(bgp_text.OPTIONS), self.report, plabel, "NX-OS")
                self.out += [IND * 2 + line for line in self.neighbor(peer)]
        self.out.append("!")

    def neighbor(self, p: BgpNeighbor) -> List[str]:
        lines = [f"neighbor {p.address}"]
        body: List[str] = []
        if p.remote_as:
            body.append(f"remote-as {p.remote_as}")
        if p.description:
            body.append(f"description {p.description}")
        if p.update_source:
            body.append(f"update-source {self.port(p.update_source)}")
        if p.ebgp_multihop:
            body.append(f"ebgp-multihop {p.ebgp_multihop}")
        if p.bfd:
            self.features.add("bfd")
            body.append("bfd")
        if p.shutdown:
            body.append("shutdown")
        if p.password:
            body.append(f"password 0 {p.password}")
        if p.keepalive is not None or p.hold is not None:
            body.append(f"timers {p.keepalive if p.keepalive is not None else 60} "
                        f"{p.hold if p.hold is not None else 180}")
        if p.remove_private_as:
            body.append("remove-private-as")
        for family in p.families:
            header = {"ipv4": "address-family ipv4 unicast", "ipv6": "address-family ipv6 unicast",
                      "evpn": "address-family l2vpn evpn"}[family]
            options: List[str] = []
            if family == "evpn":
                self.evpn = True
                options.append("send-community extended")
            else:
                if p.send_community:
                    options.append("send-community")
                if p.next_hop_self:
                    options.append("next-hop-self")
                if p.route_reflector_client:
                    options.append("route-reflector-client")
                if p.maximum_prefix is not None:
                    options.append(f"maximum-prefix {p.maximum_prefix}")
                if p.allowas_in is not None:
                    options.append("allowas-in" + (f" {p.allowas_in}" if p.allowas_in else ""))
                for attr, direction in (("route_map_in", "in"), ("route_map_out", "out")):
                    if getattr(p, attr):
                        options.append(f"route-map {getattr(p, attr)} {direction}")
                for attr, direction in (("prefix_list_in", "in"), ("prefix_list_out", "out")):
                    if getattr(p, attr):
                        options.append(f"prefix-list {getattr(p, attr)} {direction}")
            body.append(header)
            body += [IND + o for o in options]
        return lines + [IND + line for line in body]

    # management ------------------------------------------------------------------------------------------------------

    def vty(self) -> None:
        m = self.device.management
        body = []
        if m.exec_timeout is not None:
            body.append(f"exec-timeout {m.exec_timeout}")
        if m.vty_acl:
            if m.vty_acl in self.device.acls:
                body.append(f"access-class {acl_text.safe_name(m.vty_acl)} in")
            else:
                self.report.add("management", "remote login ACL", Severity.REVIEW, "acl-missing",
                                f"ACL {m.vty_acl} is applied but not defined; left out")
        if body:
            self.report.item("management", "vty")
            self.out += ["line vty"] + [IND + line for line in body] + ["!"]


def emit(device: Device, ports: PortMapper, report: Report) -> str:
    return Writer(device, ports, report).emit()

