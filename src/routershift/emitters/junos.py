# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for Juniper Junos (EX and QFX switches with the Enhanced Layer 2 Software).

The configuration is written as the curly-brace hierarchy that 'load merge terminal' takes. This first writer
covers the system settings, VLANs, ports, aggregates, addresses, VRFs (routing instances), static routes, OSPF,
BGP, LLDP and spanning tree. Everything else the model holds is listed in the report as not written for Junos yet,
rather than guessed at.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Tuple

from .. import aaa as aaa_text
from .. import bgp as bgp_text
from .. import dhcp as dhcp_text
from .. import hosts as hosts_text
from .. import igp as igp_text
from .. import multicast as multicast_text
from .. import ospf as ospf_text
from .. import routemap as routemap_text
from .. import snmp as snmp_text
from .. import vpn as vpn_text
from .. import vrfs as vrfs_text
from .. import wlan as wlan_text
from ..junostext import Tree, quote
from ..model import BgpNeighbor, Device, Interface, InterfaceKind, LacpMode, StpMode, SwitchportMode
from ..names import PortMapper
from ..report import Report, Severity
from ..timezones import offset_minutes, utc

PLATFORM = "Junos"
LEVELS = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "any"]
CLASSES = [(15, "super-user"), (5, "operator"), (0, "read-only")]
HASHES = ("md5-crypt", "sha256-crypt", "sha512-crypt", "junos")
MGMT_INSTANCE = "mgmt_junos"
_NAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


def vlan_name(name: str, vid: int) -> str:
    """A VLAN name Junos takes: letters, digits, '-', '_' and '.'; VLAN 1 is 'default'."""
    clean = _NAME_CHARS.sub("-", name).strip("-")
    if not clean:
        return "default" if vid == 1 else f"VLAN{vid}"
    return clean if clean[0].isalpha() else f"VLAN-{clean}"


def bandwidth(mbps: int) -> str:
    return f"{mbps // 1000}g" if mbps % 1000 == 0 else f"{mbps}m"


class Writer:
    def __init__(self, device: Device, ports: PortMapper, report: Report) -> None:
        self.device = device
        self.port = ports
        self.report = report
        self.root = Tree()
        for section in ("system", "chassis", "interfaces", "snmp", "routing-options", "protocols", "vlans",
                        "routing-instances"):
            self.root.add(section)
        self.vlan_names: Dict[int, str] = {}
        self.mgmt_vrfs = {i.vrf for i in device.interfaces.values() if i.kind == InterfaceKind.MANAGEMENT and i.vrf}

    def add(self, *path: str) -> None:
        self.root.add(*path)

    def label(self, iface: Interface) -> str:
        return f"{iface.source_name or iface.name} -> {self.port(iface.name)}"

    def instance(self, vrf: str) -> str:
        return MGMT_INSTANCE if vrf in self.mgmt_vrfs else vrf

    def emit(self) -> str:
        self.vlans()
        self.system()
        self.users()
        self.interfaces()
        self.snmp()
        self.routing_instances()
        self.routes()
        self.ospf()
        self.bgp()
        self.lldp()
        self.spanning_tree()
        self.not_yet()
        self.report.unparsed(self.device.unparsed)
        self.root.children = {k: v for k, v in self.root.children.items() if v.children}
        return "\n".join(self.root.render()) + "\n"

    # system ------------------------------------------------------------------------------------------------------

    def system(self) -> None:
        sy = self.device.system
        if sy.hostname:
            self.add("system", f"host-name {quote(sy.hostname)}")
            self.report.item("system", "hostname")
        if sy.domain_name:
            self.add("system", f"domain-name {sy.domain_name}")
        for domain in sy.dns_search:
            self.add("system", f"domain-search {domain}")
        for server in sy.dns_servers:
            self.add("system", "name-server", server)
        for host, address in sy.dns_hosts.items():
            self.add("system", "static-host-mapping", host, f"inet {address}")
        hosts_text.dns_unsupported(self.device, self.report, PLATFORM, search=True, hosts=True)
        if sy.timezone:
            self.timezone(sy.timezone)
        if sy.banner_motd:
            self.report.item("system", "banner")
            text = sy.banner_motd.replace('"', "'").replace("\n", "\\n")
            self.add("system", "login", f'message "{text}"')
        if self.mgmt_vrfs:
            self.add("system", "management-instance")
            self.report.add("system", f"vrf {', '.join(sorted(self.mgmt_vrfs))}", Severity.APPROX, "mgmt-instance",
                            f"the management VRF becomes Junos' management instance {MGMT_INSTANCE}")
        self.ntp()
        self.syslog()
        self.services()
        if sy.service_vrf:
            self.report.add("system", f"services in vrf {sy.service_vrf}", Severity.REVIEW, "service-vrf",
                            "NTP, DNS and syslog are written in the main routing table; add routing-instance "
                            f"{self.instance(sy.service_vrf)} to them by hand if they must leave from the VRF")
        for name, source in sy.transfer_source.items():
            self.report.skip("system", f"{name} source interface", "junos-not-yet",
                             f"not written for Junos yet ({source}); configure it by hand")

    def timezone(self, tz: str) -> None:
        """Junos takes a tz database name; a fixed offset in whole hours becomes Etc/GMT-N (the sign inverted)."""
        self.report.item("system", "time zone")
        minutes = offset_minutes(tz)
        if minutes is None:
            self.add("system", f"time-zone {tz}")
        elif minutes % 60 == 0:
            name = "UTC" if minutes == 0 else f"Etc/GMT{-minutes // 60:+d}"
            self.add("system", f"time-zone {name}")
            self.report.add("system", "time zone", Severity.APPROX, "timezone",
                            f"the fixed offset {utc(minutes)} is written as {name}; summer time is not followed, a "
                            "tz database name such as Europe/Brussels would be")
        else:
            self.report.add("system", "time zone", Severity.REVIEW, "timezone",
                            f"Junos has no time zone for {utc(minutes)}; set one by hand")

    def address_of(self, canonical: str) -> str:
        iface = self.device.interfaces.get(canonical)
        return str(ipaddress.ip_interface(iface.ipv4[0]).ip) if iface is not None and iface.ipv4 else ""

    def source(self, canonical: str, path: Tuple[str, ...], label: str) -> None:
        address = self.address_of(canonical)
        if address:
            self.add(*path, f"source-address {address}")
        else:
            self.report.add("system", label, Severity.REVIEW, "source-address",
                            f"Junos names the source by its address; {canonical} has none, left out")

    def ntp(self) -> None:
        sy = self.device.system
        for number, key in sorted(sy.ntp_keys.items()):
            label = f"ntp key {number}"
            self.report.item("system", label)
            value = snmp_text.ntp_key(key, self.report)
            algorithm = key.algorithm if key.algorithm in ("md5", "sha1", "sha256") else "md5"
            self.add("system", "ntp", f"authentication-key {number} type {algorithm} value {quote(value)}")
            if key.trusted:
                self.add("system", "ntp", f"trusted-key {number}")
        for server in sy.ntp_servers:
            self.report.item("system", f"ntp server {server}")
            words = ["server", server]
            if server in sy.ntp_server_keys:
                words += ["key", str(sy.ntp_server_keys[server])]
            if server == sy.ntp_prefer:
                words.append("prefer")
            self.add("system", "ntp", " ".join(words))
        if sy.ntp_source:
            self.source(sy.ntp_source, ("system", "ntp"), "ntp source")

    def syslog(self) -> None:
        sy = self.device.system
        level = LEVELS[sy.logging_level] if sy.logging_level is not None else "info"
        for server in sy.syslog_servers:
            self.report.item("system", f"syslog {server}")
            self.add("system", "syslog", f"host {server}", f"any {level}")
        if sy.logging_source and sy.syslog_servers:
            self.source(sy.logging_source, ("system", "syslog"), "syslog source")

    def services(self) -> None:
        m = self.device.management
        for name, on, words in (("ssh", m.ssh, ["ssh"]), ("telnet", m.telnet, ["telnet"]),
                                ("http", m.http, ["web-management", "http"]),
                                ("https", m.https, ["web-management", "https", "system-generated-certificate"])):
            if on:
                self.report.item("management", name)
                self.add("system", "services", *words)
        if m.vty_acl:
            self.report.skip("management", f"remote login ACL {m.vty_acl}", "junos-not-yet",
                             "a loopback firewall filter is not written for Junos yet; protect the routing engine "
                             "by hand")
        if m.exec_timeout is not None:
            self.report.skip("management", "session timeout", "junos-not-yet",
                             f"idle-timeout ({m.exec_timeout} minutes) goes in a login class; not written for Junos "
                             "yet")
        if m.cdp:
            self.report.skip("management", "CDP", "cdp", "Junos has no CDP; LLDP is written where it is on")

    def users(self) -> None:
        for user in self.device.users:
            label = aaa_text.user_label(user)
            password = aaa_text.password(user, HASHES, self.report)
            if password is None:
                continue
            self.report.item("management", label)
            path = ("system", "login", f"user {quote(user.name)}")
            self.add(*path, f"class {aaa_text.role(user.privilege, CLASSES)}")
            kind, value = password
            if kind in HASHES:
                self.add(*path, "authentication", f"encrypted-password {quote(value)}")
            elif kind == "plain":
                self.report.add("management", label, Severity.REVIEW, "plain-password",
                                "Junos takes no clear-text password in a configuration; set it with 'set system "
                                f"login user {user.name} authentication plain-text-password'")
        if self.device.aaa.enable_secret is not None:
            self.report.skip("management", "enable secret", "enable", "Junos has no enable password; the login "
                             "class of each user sets what it may do")

    # VLANs and interfaces ----------------------------------------------------------------------------------------

    def vlans(self) -> None:
        used = set()
        vids = set(self.device.vlans) | {int(i.name[len("Vlan"):]) for i in self.device.interfaces.values()
                                         if i.kind == InterfaceKind.VLAN and i.name[len("Vlan"):].isdigit()}
        for vid in sorted(vids):
            vlan = self.device.vlans.get(vid)
            name = vlan_name(vlan.name if vlan else "", vid)
            while name in used:
                name = f"{name}-{vid}"
            used.add(name)
            self.vlan_names[vid] = name
            self.add("vlans", name, f"vlan-id {vid}")
            if vlan is None:
                continue
            self.report.item("vlan", str(vid))
            if vlan.shutdown:
                self.report.add("vlan", str(vid), Severity.REVIEW, "vlan-shutdown",
                                "Junos cannot shut a VLAN down; it is written active")
            if vlan.dhcp_snooping or vlan.arp_inspection or vlan.igmp_querier:
                self.report.add("vlan", str(vid), Severity.REVIEW, "junos-not-yet",
                                "DHCP snooping, ARP inspection and the IGMP querier are not written for Junos yet")

    def members(self, iface: Interface) -> List[str]:
        if iface.mode == SwitchportMode.ACCESS:
            vid = iface.access_vlan or 1
            return [self.vlan_names.get(vid, str(vid))]
        if not iface.allowed_vlans:
            return ["all"]
        words: List[str] = []
        for part in iface.allowed_vlans.split(","):
            part = part.strip()
            words.append(self.vlan_names.get(int(part), part) if part.isdigit() else part)
        if iface.native_vlan and not self.carries(iface.allowed_vlans, iface.native_vlan):
            words.append(self.vlan_names.get(iface.native_vlan, str(iface.native_vlan)))
        return words

    @staticmethod
    def carries(allowed: str, vid: int) -> bool:
        for part in allowed.split(","):
            low, _, high = part.strip().partition("-")
            if low.isdigit() and int(low) <= vid <= int(high or low):
                return True
        return False

    def split(self, iface: Interface) -> Tuple[str, str]:
        """The physical interface and unit a model interface is written as."""
        name = self.port(iface.name)
        if iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG, InterfaceKind.MANAGEMENT) or "." not in name:
            return name, "0"
        ifd, unit = name.rsplit(".", 1)
        return ifd, unit

    def unit_name(self, canonical: str) -> str:
        iface = self.device.interfaces.get(canonical)
        if iface is None:
            return canonical
        ifd, unit = self.split(iface)
        return f"{ifd}.{unit}"

    def interfaces(self) -> None:
        lags = 0
        for iface in self.device.interfaces.values():
            if iface.kind in (InterfaceKind.TUNNEL, InterfaceKind.OTHER):
                self.report.skip("interface", self.label(iface), "junos-not-yet",
                                 "tunnel interfaces are not written for Junos yet; configure it by hand")
                continue
            self.report.item("interface", self.label(iface))
            ifd, unit = self.split(iface)
            top = ("interfaces", ifd)
            physical = iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG)
            if iface.kind == InterfaceKind.LAG:
                lags = max(lags, int(ifd[2:]) + 1 if ifd[2:].isdigit() else lags + 1)
            if physical or iface.kind == InterfaceKind.MANAGEMENT:
                if iface.description:
                    self.add(*top, f"description {quote(iface.description)}")
                if iface.shutdown:
                    self.add(*top, "disable")
                if iface.mtu:
                    self.add(*top, f"mtu {iface.mtu}")
                    self.report.add("interface", self.label(iface), Severity.APPROX, "mtu",
                                    f"Junos counts the Ethernet header in the MTU; {iface.mtu} is written as it is")
            if iface.lag:
                self.add(*top, "ether-options", f"802.3ad {self.port(iface.lag)}")
                self.leftovers(iface)
                continue
            if iface.kind == InterfaceKind.LAG:
                mode = iface.lacp_mode or next((i.lacp_mode for i in self.device.interfaces.values()
                                                if i.lag == iface.name and i.lacp_mode), None)
                if mode in (LacpMode.ACTIVE, LacpMode.PASSIVE):
                    self.add(*top, "aggregated-ether-options", "lacp", mode.value)
            path = top + (f"unit {unit}",)
            if not physical and iface.kind != InterfaceKind.MANAGEMENT:
                if iface.description:
                    self.add(*path, f"description {quote(iface.description)}")
                if iface.shutdown:
                    self.add(*path, "disable")
            if iface.kind == InterfaceKind.SUBINTERFACE:
                self.add("interfaces", ifd, "vlan-tagging")
                if iface.encapsulation_vlan:
                    self.add(*path, f"vlan-id {iface.encapsulation_vlan}")
            if iface.kind == InterfaceKind.VLAN:
                vid = int(iface.name[len("Vlan"):])
                self.add("vlans", self.vlan_names.get(vid, f"VLAN{vid}"), f"l3-interface {ifd}.{unit}")
            if iface.mode != SwitchportMode.ROUTED and physical:
                switching = path + ("family ethernet-switching",)
                self.add(*switching, f"interface-mode {iface.mode.value}")
                for word in self.members(iface):
                    self.add(*switching, "vlan", f"members {word}")
                if iface.mode == SwitchportMode.TRUNK and iface.native_vlan:
                    self.add(*top, f"native-vlan-id {iface.native_vlan}")
            else:
                for n, address in enumerate(iface.ipv4):
                    if n == 0 and len(iface.ipv4) > 1:
                        self.add(*path, "family inet", f"address {address}", "primary")
                    else:
                        self.add(*path, "family inet", f"address {address}")
                if iface.dhcp_client:
                    self.add(*path, "family inet", "dhcp")
                for address in iface.ipv6:
                    self.add(*path, "family inet6", f"address {address}")
                if iface.kind in (InterfaceKind.VLAN, InterfaceKind.LOOPBACK) and not (
                        iface.ipv4 or iface.ipv6 or iface.dhcp_client):
                    self.add(*path, "family inet")
            self.leftovers(iface)
        if lags:
            self.add("chassis", "aggregated-devices", "ethernet", f"device-count {lags}")

    def leftovers(self, iface: Interface) -> None:
        """What a port carries that this writer does not write yet."""
        missing = [what for what, stated in (
            ("ACLs (firewall filters)", bool(iface.acl_in or iface.acl_out or iface.acl6_in or iface.acl6_out)),
            ("DHCP relay", bool(iface.helper_addresses)),
            ("VRRP", bool(iface.fhrp)),
            ("the voice VLAN", iface.voice_vlan is not None),
            ("speed and duplex", bool(iface.speed or iface.duplex not in ("", "auto"))),
            ("QoS", bool(iface.qos_trust or iface.qos_policy_in or iface.qos_policy_out)),
            ("MPLS", iface.mpls),
            ("DHCP snooping, ARP inspection, source guard and port security",
             iface.dhcp_trust or iface.arp_trust or iface.source_guard or iface.port_security),
            ("storm control", bool(iface.storm_control)),
            ("MC-LAG", iface.mlag_id is not None),
            ("NAT", bool(iface.nat)),
            ("BFD", bool(iface.ospf_bfd or iface.bfd_interval or iface.bfd_min_rx or iface.bfd_multiplier)),
            ("IS-IS", iface.isis),
            ("PIM and IGMP", bool(iface.pim or iface.igmp_version)),
            ("sFlow and flow monitoring", bool(iface.sflow or iface.flow)),
            ("PoE", hosts_text.poe_stated(iface)),
            ("policy-based routing", bool(iface.pbr)),
            ("IPsec", bool(iface.crypto_map)),
            ("802.1X and MAC authentication", iface.dot1x or iface.mab),
            ("loop guard and BPDU filter", iface.stp_guard == "loop" or iface.stp_bpdufilter),
        ) if stated]
        if missing:
            self.report.add("interface", self.label(iface), Severity.REVIEW, "junos-not-yet",
                            f"not written for Junos yet: {', '.join(missing)}; configure by hand")
        if iface.cdp:
            self.report.add("interface", self.label(iface), Severity.APPROX, "cdp", "Junos has no CDP")

    # SNMP --------------------------------------------------------------------------------------------------------

    def snmp(self) -> None:
        sn = self.device.snmp
        if sn.location:
            self.add("snmp", f"location {quote(sn.location)}")
        if sn.contact:
            self.add("snmp", f"contact {quote(sn.contact)}")
        for c in sn.communities:
            label = snmp_text.community_label(self.device, c)
            self.report.item("management", label)
            access = "read-write" if c.access == "rw" else "read-only"
            self.add("snmp", f"community {quote(c.name)}", f"authorization {access}")
            if c.acl:
                self.report.add("management", label, Severity.REVIEW, "junos-not-yet",
                                f"the manager list {c.acl} is not written for Junos yet (snmp community clients)")
        rest = [what for what, stated in (("notification hosts", bool(sn.hosts or sn.traps)),
                                          ("SNMPv3 users and groups", bool(sn.users or sn.groups)),
                                          ("the source interface", bool(sn.source))) if stated]
        if rest:
            self.report.skip("management", "SNMP", "junos-not-yet",
                             f"not written for Junos yet: {', '.join(rest)}; configure by hand")

    # routing -----------------------------------------------------------------------------------------------------

    def routing_instances(self) -> None:
        for vrf in self.device.vrfs:
            if vrf in self.mgmt_vrfs:
                continue
            label = f"vrf {vrf}"
            self.report.item("system", label)
            info = self.device.vrf_info.get(vrf)
            path = ("routing-instances", vrf)
            members = [i for i in self.device.interfaces.values()
                       if i.vrf == vrf and i.kind not in (InterfaceKind.TUNNEL, InterfaceKind.OTHER)]
            if info is not None and info.rd and (info.rt_import or info.rt_export):
                self.add(*path, "instance-type vrf")
                for iface in members:
                    self.add(*path, f"interface {self.unit_name(iface.name)}")
                self.add(*path, f"route-distinguisher {info.rd}")
                pairs = vrfs_text.targets(info)
                if len(pairs) == 1 and pairs[0][0] == "both":
                    self.add(*path, f"vrf-target target:{pairs[0][1]}")
                else:
                    imports, exports = info.rt_import[:1], info.rt_export[:1]
                    for direction, values in (("import", imports), ("export", exports)):
                        for value in values:
                            self.add(*path, "vrf-target", f"{direction} target:{value}")
                    if len(info.rt_import) > 1 or len(info.rt_export) > 1:
                        self.report.add("system", label, Severity.REVIEW, "route-targets",
                                        "Junos takes one import and one export target here; the others need "
                                        "vrf-import and vrf-export policies, not written")
            else:
                self.add(*path, "instance-type virtual-router")
                for iface in members:
                    self.add(*path, f"interface {self.unit_name(iface.name)}")
                if info is not None and (info.rd or info.rt_import or info.rt_export):
                    self.report.add("system", label, Severity.REVIEW, "vrf-partial",
                                    "a Junos VRF instance needs both a route distinguisher and route targets; written "
                                    "as a virtual router without them")

    def routes(self) -> None:
        for route in self.device.static_routes:
            label = f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}"
            self.report.item("route", label)
            base: Tuple[str, ...] = ("routing-options",)
            if route.vrf:
                base = ("routing-instances", self.instance(route.vrf), "routing-options")
            net = ipaddress.ip_network(route.prefix)
            path = base + (("static",) if net.version == 4 else ("rib inet6.0", "static")) + (f"route {net}",)
            if route.discard:
                self.add(*path, "discard")
            elif route.next_hop:
                self.add(*path, f"next-hop {route.next_hop}")
                if route.interface:
                    self.report.add("route", label, Severity.APPROX, "route-interface",
                                    f"Junos resolves the next hop itself; the interface {route.interface} is left out")
            elif route.interface:
                self.add(*path, f"next-hop {self.unit_name(route.interface)}")
            if route.distance is not None:
                self.add(*path, f"preference {route.distance}")
            if route.name:
                self.report.add("route", label, Severity.APPROX, "route-name",
                                f"the route's name '{route.name}' has no place on Junos and is left out")
            if route.track:
                self.report.add("route", label, Severity.REVIEW, "junos-not-yet",
                                f"tracking (object {route.track}) is not written for Junos yet; the route is always on")

    def router_id(self) -> str:
        ids = [p.router_id for p in self.device.ospf if not p.vrf and p.router_id]
        if self.device.bgp is not None and self.device.bgp.router_id:
            ids.append(self.device.bgp.router_id)
        if len(set(ids)) > 1:
            self.report.add("system", "router ID", Severity.APPROX, "router-id",
                            f"Junos has one router ID for OSPF and BGP; {ids[0]} is written, not {', '.join(ids[1:])}")
        return ids[0] if ids else ""

    def ospf(self) -> None:
        rid = self.router_id()
        if rid:
            self.add("routing-options", f"router-id {rid}")
        seen: Dict[str, str] = {}
        for p in self.device.ospf:
            label = ospf_text.label(p)
            self.report.item("ospf", label)
            if p.vrf in seen:
                self.report.skip("ospf", label, "ospf-instance",
                                 f"Junos runs one OSPF per routing instance; {seen[p.vrf]} is written, not this one")
                continue
            seen[p.vrf] = label
            base: Tuple[str, ...] = ("protocols", "ospf")
            if p.vrf:
                base = ("routing-instances", self.instance(p.vrf), "protocols", "ospf")
                if p.router_id:
                    self.add("routing-instances", self.instance(p.vrf), "routing-options", f"router-id {p.router_id}")
            if p.reference_bandwidth:
                self.add(*base, f"reference-bandwidth {bandwidth(p.reference_bandwidth)}")
            for area, kind in p.area_types.items():
                words = kind.split()
                if words[0] in ("stub", "nssa") and words[1:] in ([], ["no-summary"]):
                    self.add(*base, f"area {area}", words[0] + (" no-summaries" if words[1:] else ""))
                else:
                    self.report.add("ospf", label, Severity.REVIEW, "area-type",
                                    f"area {area} ({kind}) is written as a normal area")
            for name, area in ospf_text.interfaces(self.device, p).items():
                iface = self.device.interfaces[name]
                path = base + (f"area {area}", f"interface {self.unit_name(name)}")
                self.add(*path)
                if p.passive(name):
                    self.add(*path, "passive")
                if iface.ospf_cost:
                    self.add(*path, f"metric {iface.ospf_cost}")
                if iface.ospf_network == "point-to-point":
                    self.add(*path, "interface-type p2p")
            missing = [what for what, stated in (
                (f"redistribution of {', '.join(p.redistribute)}", bool(p.redistribute)),
                ("the default route", bool(p.default_originate)),
                ("BFD", p.bfd_all)) if stated]
            if missing:
                self.report.add("ospf", label, Severity.REVIEW, "junos-not-yet",
                                f"not written for Junos yet (it takes export policies): {', '.join(missing)}")

    def bgp(self) -> None:
        bgp = self.device.bgp
        if bgp is None:
            return
        label = f"bgp {bgp.local_as}"
        self.report.item("bgp", label)
        self.add("routing-options", f"autonomous-system {bgp.local_as}")
        if bgp.networks or bgp.redistribute:
            what = ", ".join(bgp.networks + [f"redistribute {r}" for r in bgp.redistribute])
            self.report.add("bgp", label, Severity.REVIEW, "junos-not-yet",
                            f"Junos announces routes through export policies; not written yet: {what}")
        for name, group in bgp.peer_groups.items():
            members = [n for n in bgp.neighbors if n.peer_group == name]
            if not members:
                continue
            self.peer(("protocols", "bgp", f"group {name}"), group, label, group_as=group.remote_as)
            kind = "internal" if group.remote_as == bgp.local_as else "external"
            if not group.remote_as:
                remotes = {bgp_text.remote_as(bgp, n) for n in members}
                kind = "internal" if remotes == {bgp.local_as} else "external"
            self.add("protocols", "bgp", f"group {name}", f"type {kind}")
        for neighbor in bgp.neighbors:
            nlabel = f"neighbor {neighbor.address}"
            self.report.item("bgp", nlabel)
            remote = bgp_text.remote_as(bgp, neighbor)
            group_name = neighbor.peer_group
            if not group_name or group_name not in bgp.peer_groups:
                group_name = "IBGP" if remote == bgp.local_as else "EBGP"
                self.add("protocols", "bgp", f"group {group_name}",
                         f"type {'internal' if group_name == 'IBGP' else 'external'}")
                own_as = neighbor.remote_as if group_name == "EBGP" else ""
            else:
                own_as = neighbor.remote_as if neighbor.remote_as != bgp.peer_groups[group_name].remote_as else ""
            path = ("protocols", "bgp", f"group {group_name}", f"neighbor {neighbor.address}")
            self.add(*path)
            self.peer(path, neighbor, nlabel, group_as=own_as)

    def peer(self, path: Tuple[str, ...], p: BgpNeighbor, label: str, group_as: str) -> None:
        bgp = self.device.bgp
        assert bgp is not None
        if p.description:
            self.add(*path, f"description {quote(p.description)}")
        if group_as and group_as != bgp.local_as:
            self.add(*path, f"peer-as {group_as}")
        if p.update_source:
            address = self.address_of(p.update_source)
            if address:
                self.add(*path, f"local-address {address}")
            else:
                self.report.add("bgp", label, Severity.REVIEW, "local-address",
                                f"Junos names the source by its address; {p.update_source} has none, left out")
        if p.ebgp_multihop:
            self.add(*path, "multihop", f"ttl {p.ebgp_multihop}")
        if p.bfd:
            self.add(*path, "bfd-liveness-detection", "minimum-interval 300")
            self.report.add("bgp", label, Severity.APPROX, "bfd", "BFD is written with a 300 ms interval")
        families = p.families
        if families and families != [bgp_text.family(p.address)]:
            for family in families:
                words = {"ipv4": "family inet", "ipv6": "family inet6", "evpn": "family evpn"}[family]
                self.add(*path, words, "signaling" if family == "evpn" else "unicast")
        missing = [what for what, stated in (
            ("next-hop-self", p.next_hop_self), ("shutdown", p.shutdown),
            (f"route maps {p.route_map_in or '-'} in / {p.route_map_out or '-'} out",
             bool(p.route_map_in or p.route_map_out)),
            (f"prefix lists {p.prefix_list_in or '-'} in / {p.prefix_list_out or '-'} out",
             bool(p.prefix_list_in or p.prefix_list_out))) if stated]
        if missing:
            self.report.add("bgp", label, Severity.REVIEW, "junos-not-yet",
                            f"not written for Junos yet (import and export policies): {', '.join(missing)}")

    # LLDP and spanning tree --------------------------------------------------------------------------------------

    def stp_ports(self) -> List[Interface]:
        return [i for i in self.device.interfaces.values()
                if i.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG) and not i.lag]

    def lldp(self) -> None:
        m = self.device.management
        off = [i for i in self.stp_ports() if not (i.lldp_tx and i.lldp_rx)]
        if m.lldp is False:
            self.report.item("management", "LLDP")
            self.add("protocols", "lldp", "disable")
            return
        if m.lldp or off:
            self.report.item("management", "LLDP")
            self.add("protocols", "lldp", "interface all")
        for iface in off:
            self.add("protocols", "lldp", f"interface {self.port(iface.name)}", "disable")
            if iface.lldp_tx or iface.lldp_rx:
                self.report.add("interface", self.label(iface), Severity.APPROX, "lldp-direction",
                                "Junos switches LLDP off both ways on a port; it was off one way")

    def spanning_tree(self) -> None:
        dev = self.device
        mode = dev.stp_mode
        if mode == StpMode.NONE:
            self.report.add("system", "spanning-tree mode", Severity.REVIEW, "stp-off",
                            "Junos runs RSTP unless told otherwise; delete protocols rstp by hand")
            return
        protocol = {StpMode.STP: "rstp", StpMode.RSTP: "rstp", StpMode.MSTP: "mstp", StpMode.RAPID_PVST: "vstp",
                    StpMode.PVST: "vstp"}.get(mode) if mode else None
        ports = [i for i in self.stp_ports() if i.stp_portfast or i.stp_cost or i.stp_port_priority is not None
                 or i.stp_guard == "root" or i.stp_bpduguard]
        if protocol is None and not ports:
            return
        protocol = protocol or "rstp"
        self.report.item("system", "spanning-tree mode")
        if mode in (StpMode.STP, StpMode.PVST):
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                            f"{mode.value} is written as its rapid form, {protocol}")
        self.add("protocols", protocol)
        if protocol == "mstp":
            if dev.stp.region:
                self.add("protocols", "mstp", f"configuration-name {quote(dev.stp.region)}")
            if dev.stp.revision is not None:
                self.add("protocols", "mstp", f"revision-level {dev.stp.revision}")
            for instance, vlans in sorted(dev.stp.instances.items()):
                for vid in vlans:
                    self.add("protocols", "mstp", f"msti {instance}", f"vlan {vid}")
            for instance, value in sorted(dev.stp.priority.items()):
                if instance == 0:
                    self.add("protocols", "mstp", f"bridge-priority {value}")
                else:
                    self.add("protocols", "mstp", f"msti {instance}", f"bridge-priority {value}")
        elif protocol == "vstp":
            for vid, value in sorted(dev.stp.vlan_priority.items()):
                self.add("protocols", "vstp", f"vlan {vid}", f"bridge-priority {value}")
            if not dev.stp.vlan_priority:
                self.add("protocols", "vstp", "vlan all")
        elif 0 in dev.stp.priority:
            self.add("protocols", "rstp", f"bridge-priority {dev.stp.priority[0]}")
        for iface in ports:
            path = ("protocols", protocol, f"interface {self.port(iface.name)}")
            if iface.stp_portfast:
                self.add(*path, "edge")
            if iface.stp_cost:
                self.add(*path, f"cost {iface.stp_cost}")
            if iface.stp_port_priority is not None:
                self.add(*path, f"priority {iface.stp_port_priority}")
            if iface.stp_guard == "root":
                self.add(*path, "no-root-port")
            if iface.stp_bpduguard:
                self.add("protocols", "layer2-control", "bpdu-block", f"interface {self.port(iface.name)}")

    # the rest ----------------------------------------------------------------------------------------------------

    def not_yet(self) -> None:
        dev, report = self.device, self.report

        def skip(kind: str, label: str, what: str) -> None:
            report.skip(kind, label, "junos-not-yet", f"{what} not written for Junos yet; configure by hand")

        for name in dev.acls:
            skip("acl", name, "firewall filters are")
        routemap_text.unsupported(dev, report, PLATFORM)
        for pool in dev.dhcp_pools:
            skip("dhcp", dhcp_text.label(pool), "the DHCP server is")
        for n, rule in enumerate(dev.nat_rules, 1):
            skip("nat", f"rule {n} ({rule.kind})", "NAT is")
        if vpn_text.has_vpn(dev):
            for p in dev.ipsec_peers:
                skip("vpn", vpn_text.peer_label(p), "IPsec is")
        for policy in dev.qos_policies:
            skip("qos", f"policy {policy}", "class of service is")
        for session in dev.mirror_sessions:
            skip("monitor", f"mirror session {session.name}", "port mirroring (analyzer) is")
        if dev.sflow is not None:
            skip("monitor", "sFlow", "sFlow is")
        if dev.netflow is not None:
            skip("monitor", "NetFlow", "flow monitoring is")
        wlan_text.unsupported(dev, report, PLATFORM)
        if dev.mpls.ldp or any(i.mpls for i in dev.interfaces.values()):
            skip("mpls", "MPLS and LDP", "MPLS and LDP are")
        if dev.rip is not None:
            skip("rip", igp_text.RIP_LABEL, "RIP is")
        if dev.isis is not None:
            skip("isis", igp_text.isis_label(dev.isis), "IS-IS is")
        if dev.mlag is not None:
            skip("interface", "multi-chassis LAG", "MC-LAG is")
        if dev.vxlan is not None:
            skip("interface", "VXLAN", "VXLAN is")
        for sla in dev.ip_slas:
            skip("track", f"ip sla {sla}", "real-time performance monitoring (RPM) is")
        for track in dev.tracks:
            skip("track", f"track {track}", "object tracking is")
        if multicast_text.stated(dev) or dev.multicast_routing or dev.pim_rps:
            skip("vlan", multicast_text.LABEL, "IGMP snooping and PIM are")
        if dev.dhcp_snooping:
            skip("vlan", "DHCP snooping", "DHCP snooping is")
        aaa = dev.aaa
        for server in aaa.servers:
            skip("management", aaa_text.server_label(server), "RADIUS and TACACS+ servers are")
        for method in aaa.methods:
            skip("management", aaa_text.method_label(method), "authentication order and 802.1X are")


def emit(device: Device, ports: PortMapper, report: Report) -> str:
    return Writer(device, ports, report).emit()
