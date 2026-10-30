# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for HPE Aruba AOS-CX (10.x)."""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Tuple

from .. import acl as acl_text
from .. import bgp as bgp_text
from .. import dhcp as dhcp_text
from .. import nat as nat_text
from .. import vpn as vpn_text
from .. import fhrp
from .. import ospf as ospf_text
from .. import snmp as snmp_text
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
        self.routes()
        self.dhcp()
        nat_text.skip_all(self.device, self.report, "AOS-CX")
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
        for host in s.syslog_servers:
            self.out.append(f"logging {host}{via}")
        if s.syslog_servers:
            rep.item("system", "syslog servers")
        self.snmp()
        self.out.append("!")

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

    def vrfs(self) -> None:
        for name in self.device.vrfs:
            if self.vrf(name) == MGMT_VRF:
                continue  # predefined
            self.out.append(f"vrf {name}")
            self.report.item("system", f"vrf {name}")

    def spanning_tree(self) -> None:
        mode = self.device.stp_mode
        if mode == StpMode.NONE or (mode is None and not self.is_switch):
            return
        if mode is None:
            self.out.append("spanning-tree")
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-default",
                            "the source runs spanning tree in its default mode; AOS-CX has it off until enabled, "
                            "so MSTP is switched on")
            return
        if mode in (StpMode.MSTP, StpMode.RAPID_PVST):
            self.out.append("spanning-tree")
            if mode == StpMode.RAPID_PVST:
                self.out.append("spanning-tree mode rpvst")
            self.report.item("system", "spanning-tree mode")
            return
        target = "rpvst" if mode == StpMode.PVST else "mstp"
        self.out.append("spanning-tree")
        if target == "rpvst":
            self.out.append("spanning-tree mode rpvst")
        self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                        f"{mode.value} is not available on AOS-CX, written as {target}")

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

    def vlans(self) -> None:
        voice = {i.voice_vlan for i in self.device.interfaces.values() if i.voice_vlan is not None}
        for vlan in sorted(self.device.vlans.values(), key=lambda v: v.vlan_id):
            self.out.append(f"vlan {vlan.vlan_id}")
            if vlan.name:
                self.out.append(f"{_IND}name {vlan.name}")
            if vlan.vlan_id in voice:
                self.out.append(f"{_IND}voice")
            if vlan.shutdown:
                self.out.append(f"{_IND}shutdown")
            self.report.item("vlan", str(vlan.vlan_id))

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
        if iface.stp_portfast:
            lines.append("spanning-tree port-type admin-edge")
        if iface.stp_bpduguard:
            lines.append("spanning-tree bpdu-guard")
        self.out.append(f"interface {name}")
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
            lines.append(f"redistribute {source}")
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
        for af in ("ipv4", "ipv6"):
            body: List[str] = []
            for peer in neighbors:
                if af in peer.families:
                    body.append(f"neighbor {peer.address} activate")
                    if peer.next_hop_self:
                        body.append(f"neighbor {peer.address} next-hop-self")
                    if peer.send_community:
                        body.append(f"neighbor {peer.address} send-community standard")
            body += [f"network {p}" for p in bgp.networks if (":" in p) == (af == "ipv6")]
            body += [f"redistribute {r}" for r in (bgp.redistribute6 if af == "ipv6" else bgp.redistribute)]
            if body:
                lines.append(f"address-family {af} unicast")
                lines += [_IND + line for line in body]
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
        return lines

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
