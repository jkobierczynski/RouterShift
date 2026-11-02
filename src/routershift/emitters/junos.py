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
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .. import aaa as aaa_text
from .. import bgp as bgp_text
from .. import stp as stp_text
from .. import dhcp as dhcp_text
from .. import evpn as evpn_text
from .. import fhrp as fhrp_text
from .. import hosts as hosts_text
from .. import l2sec as l2sec_text
from .. import multicast as multicast_text
from .. import junospolicy
from .. import junosqos
from .. import junossec
from .. import junosauto, junosmon
from .. import junosrouting
from .. import bfd as bfd_text
from .. import junosmgmt
from .. import ospf as ospf_text
from .. import partial
from .. import snmp as snmp_text
from .. import vrfs as vrfs_text
from ..junostext import Tree, quote
from ..model import (AclAction, BgpAggregate, BgpNeighbor, Device, FhrpGroup, Interface, InterfaceKind, LacpMode, StpMode,
                     SwitchportMode, VrfInfo)
from ..names import PortMapper
from ..report import Report, Severity
from ..timezones import offset_minutes, utc

PLATFORM = "Junos"
LEVELS = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "any"]
CLASSES = [(15, "super-user"), (5, "operator"), (0, "read-only")]
HASHES = ("md5-crypt", "sha256-crypt", "sha512-crypt", "junos")
MGMT_INSTANCE = "mgmt_junos"
# What partial.device need not report: the device-wide features this writer writes
WRITTEN = {"acl", "policy", "dhcp", "l2sec", "aaa", "mlag", "vxlan", "multicast", "qos", "monitor", "track"}
# What partial.port need not report
PORT_WRITTEN = {"dhcp-relay", "fhrp", "voice", "speed", "l2sec", "storm", "poe", "dot1x", "stp-guards", "mlag",
                "multicast", "qos", "monitor", "bfd", "pbr"}
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
        for section in ("system", "chassis", "interfaces", "snmp", "forwarding-options", "routing-options",
                        "protocols", "policy-options", "class-of-service", "firewall", "access", "switch-options",
                        "multi-chassis", "poe", "vlans", "routing-instances"):
            self.root.add(section)
        self.vlan_names: Dict[int, str] = {}
        self.prefix_kinds: Dict[str, str] = {}
        self.communities: Dict[str, List[str]] = {}
        self.filter_names: Dict[str, str] = {}
        self.rid: Optional[str] = None
        self.pbr_filters: Dict[str, str] = {}
        self.bfd_ports: Set[str] = set()  # ports whose BFD timers a session carries
        self.bfd_multihop_used = False
        self.relays: List[Interface] = []
        self.trusted: List[Tuple[Interface, str]] = []
        self.guarded: List[Interface] = []
        self.authenticators: List[Tuple[Interface, str]] = []
        self.anycast_units: Set[Tuple[str, ...]] = set()
        self.mgmt_vrfs = {i.vrf for i in device.interfaces.values() if i.kind == InterfaceKind.MANAGEMENT and i.vrf}

    def add(self, *path: str) -> None:
        self.root.add(*path)

    def label(self, iface: Interface) -> str:
        return f"{iface.source_name or iface.name} -> {self.port(iface.name)}"

    @property
    def mgmt(self) -> junosmgmt.MgmtWriter:
        return junosmgmt.MgmtWriter(self.device, self.add, self.report, self.address_of, self.instance,
                                    sorted(self.mgmt_vrfs), lambda acl: getattr(self, "filter_names", {}).get(acl, acl))

    def instance(self, vrf: str) -> str:
        return MGMT_INSTANCE if vrf in self.mgmt_vrfs else vrf

    def emit(self) -> str:
        self.vlans()
        self.system()
        self.users()
        self.policy()
        self.interfaces()
        self.snmp()
        self.routing_instances()
        self.routes()
        self.ospf()
        self.bgp()
        self.evpn()
        self.mclag()
        self.lldp()
        self.spanning_tree()
        self.snooping()
        self.multicast()
        self.cos()
        self.security()
        junosmon.MonitorWriter(self.device, self.add, self.report, self.port, self.unit_name, self.instance).write()
        junosrouting.ecmp(self.device, self.add, self.report)
        junosrouting.bfd_global(self.device, self.report, self.bfd_multihop_used)
        self.unused_bfd()
        junosauto.write_ptp(self.device, self.add, self.report, self.unit_name)
        junosauto.write_events(self.device, self.add, self.report, self.port)
        self.dhcp_relay()
        self.dhcp_server()
        self.aaa()
        self.dot1x()
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
        self.mgmt.banners()
        if self.mgmt_vrfs:
            self.add("system", "management-instance")
            self.report.add("system", f"vrf {', '.join(sorted(self.mgmt_vrfs))}", Severity.APPROX, "mgmt-instance",
                            f"the management VRF becomes Junos' management instance {MGMT_INSTANCE}")
        self.ntp()
        self.syslog()
        self.services()
        if sy.service_vrf:
            instance = self.instance(sy.service_vrf)
            for server in sy.dns_servers:
                self.add("system", "name-server", server, f"routing-instance {instance}")
            for server in sy.syslog_servers:
                self.add("system", "syslog", f"host {server}", f"routing-instance {instance}")
            self.report.item("system", f"services in vrf {sy.service_vrf}")
            self.report.add("system", f"services in vrf {sy.service_vrf}", Severity.APPROX, "service-vrf",
                            f"DNS, NTP and syslog servers are reached through routing-instance {instance}; check the "
                            "release takes it on name-server")
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
            if sy.service_vrf:
                words += ["routing-instance", self.instance(sy.service_vrf)]
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
        self.mgmt.syslog_transport()
        self.mgmt.logging()

    def services(self) -> None:
        m = self.device.management
        for name, on, words in (("ssh", m.ssh, ["ssh"]), ("telnet", m.telnet, ["telnet"]),
                                ("http", m.http, ["web-management", "http"]),
                                ("https", m.https, ["web-management", "https", "system-generated-certificate"])):
            if on:
                self.report.item("management", name)
                self.add("system", "services", *words)
        self.mgmt.apis()
        if m.cdp:
            self.report.skip("management", "CDP", "cdp", "Junos has no CDP; LLDP is written where it is on")

    def users(self) -> None:
        self.mgmt.users()

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

    def members(self, iface: Interface) -> List[str]:
        if iface.mode == SwitchportMode.ACCESS:
            vid = iface.access_vlan or 1
            return [self.vlan_names.get(vid, str(vid))]
        grouped = {v: x.trunk_groups for v, x in self.device.vlans.items() if x.trunk_groups}
        if grouped:
            # EOS trunk groups: a VLAN of a group rides only the trunks of that group, and such a trunk carries only
            # the VLANs of its groups. Junos has none, so the trunk lists the VLANs it carries.
            if iface.trunk_groups:
                vids = [v for v, groups in grouped.items() if set(groups) & set(iface.trunk_groups)]
            else:
                vids = [v for v in sorted(self.device.vlans) if v not in grouped]
            if iface.allowed_vlans:
                vids = [v for v in vids if self.carries(iface.allowed_vlans, v)]
            if iface.native_vlan and iface.native_vlan not in vids:
                vids.append(iface.native_vlan)
            return [self.vlan_names.get(v, str(v)) for v in sorted(vids)]
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
            if (iface.source_name or iface.name, self.port(iface.name)) in self.port.renumbered:
                self.report.add("interface", self.label(iface), Severity.APPROX, "port-renamed",
                                f"named {self.port(iface.name)} without a port map; check it against the cabling of the new "
                                "device")
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
            if physical and iface.kind == InterfaceKind.ETHERNET:
                self.ether_options(iface, top)
            if iface.lag:
                self.add(*top, "ether-options", f"802.3ad {self.port(iface.lag)}")
                self.leftovers(iface)
                continue
            if iface.kind == InterfaceKind.LAG:
                mode = iface.lacp_mode or next((i.lacp_mode for i in self.device.interfaces.values()
                                                if i.lag == iface.name and i.lacp_mode), None)
                if mode in (LacpMode.ACTIVE, LacpMode.PASSIVE):
                    self.add(*top, "aggregated-ether-options", "lacp", mode.value)
                self.segment(iface, top)
            path = top + (f"unit {unit}",)
            if not physical and iface.kind != InterfaceKind.MANAGEMENT:
                if iface.description:
                    self.add(*path, f"description {quote(iface.description)}")
                if iface.shutdown:
                    self.add(*path, "disable")
                if iface.mtu:
                    self.add(*path, "family inet", f"mtu {iface.mtu}")
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
                self.switching(iface, f"{ifd}.{unit}", switching)
                self.switch_filters(iface, switching)
            else:
                self.layer3(iface, path)
            if physical:
                self.poe(iface)
            self.leftovers(iface)
        if lags:
            self.add("chassis", "aggregated-devices", "ethernet", f"device-count {lags}")

    def segment(self, iface: Interface, top: Tuple[str, ...]) -> None:
        """EVPN multihoming: the ethernet segment of a LAG and the LACP system ID both switches share."""
        if iface.evpn_esi:
            self.add(*top, "esi", evpn_text.junos_esi(iface.evpn_esi))
            self.add(*top, "esi", "single-active" if iface.evpn_single_active else "all-active")
            if iface.evpn_df_preference is not None:
                self.add(*top, "esi", "df-election-type", "preference", f"value {iface.evpn_df_preference}")
            if iface.evpn_es_rt:
                self.report.add("interface", self.label(iface), Severity.APPROX, "es-import",
                                f"Junos derives the ES-import route target from the ESI; {iface.evpn_es_rt} is not "
                                "written")
        if iface.lacp_system_id:
            self.add(*top, "aggregated-ether-options", "lacp", f"system-id {evpn_text.junos_mac(iface.lacp_system_id)}")

    def ether_options(self, iface: Interface, top: Tuple[str, ...]) -> None:
        if iface.speed:
            self.add(*top, "ether-options", f"speed {bandwidth(iface.speed)}")
        if iface.duplex in ("full", "half"):
            self.add(*top, "ether-options", f"link-mode {iface.duplex}-duplex")

    def layer3(self, iface: Interface, path: Tuple[str, ...]) -> None:
        """The addresses of a routed interface, with its gateway redundancy, relay and hardening."""
        label = self.label(iface)
        groups = fhrp_text.plan(iface, "junos", self.report, iface.source_name or iface.name)
        anycast = [g for g in groups if g.protocol == "anycast"]
        virtual = list(iface.virtual_ipv4) + [g.address for g in anycast]
        addresses = list(iface.ipv4)
        shared_mac = self.device.anycast_mac or next((g.mac for g in anycast if g.mac), "")
        if virtual and not addresses:
            # an anycast gateway alone: the address and MAC are the same on every switch of the fabric
            addresses = [a if "/" in a else f"{a}/32" for a in virtual]
            virtual = []
            if shared_mac:
                self.add(*path, f"mac {shared_mac}")
                self.anycast_units.add(path)
        for n, address in enumerate(addresses):
            where = path + ("family inet", f"address {address}")
            self.add(*where)
            if n == 0 and len(addresses) > 1:
                self.add(*where, "primary")
            net = ipaddress.ip_interface(address).network
            for vip in virtual:
                if ipaddress.ip_interface(vip).ip in net:
                    self.add(*where, f"virtual-gateway-address {ipaddress.ip_interface(vip).ip}")
            for g in groups:
                if g.protocol == "vrrp" and (ipaddress.ip_address(g.address) in net or n == 0 and not any(
                        ipaddress.ip_address(g.address) in ipaddress.ip_interface(a).network for a in addresses)):
                    self.vrrp(iface, g, where)
        if virtual and shared_mac:
            self.add(*path, f"virtual-gateway-v4-mac {shared_mac}")
        if iface.dhcp_client:
            self.add(*path, "family inet", "dhcp")
        ipv6 = list(iface.ipv6)
        if iface.virtual_ipv6 and not ipv6:
            ipv6 = list(iface.virtual_ipv6)
        elif iface.virtual_ipv6:
            for vip in iface.virtual_ipv6:
                net6 = next((a for a in ipv6 if ipaddress.ip_interface(vip).ip in ipaddress.ip_interface(a).network),
                            ipv6[0])
                self.add(*path, "family inet6", f"address {net6}", f"virtual-gateway-address "
                         f"{ipaddress.ip_interface(vip).ip}")
            if shared_mac:
                self.add(*path, f"virtual-gateway-v6-mac {shared_mac}")
        for address in ipv6:
            self.add(*path, "family inet6", f"address {address}")
        self.interface_filters(iface, path)
        if iface.kind in (InterfaceKind.VLAN, InterfaceKind.LOOPBACK) and not (
                addresses or ipv6 or iface.dhcp_client or iface.unnumbered):
            self.add(*path, "family inet")
        if iface.unnumbered:
            self.add(*path, "family inet", f"unnumbered-address {self.unit_name(iface.unnumbered)}")
        if iface.urpf:
            self.add(*path, "family inet", "rpf-check" + (" mode loose" if iface.urpf == "loose" else ""))
            if iface.ipv6:
                self.add(*path, "family inet6", "rpf-check" + (" mode loose" if iface.urpf == "loose" else ""))
        if iface.ip_redirects is False:
            self.add(*path, "family inet", "no-redirects")
        if iface.proxy_arp:
            self.add(*path, "proxy-arp unrestricted")
        if iface.ip_unreachables is not None:
            self.report.add("interface", label, Severity.APPROX, "unreachables",
                            f"Junos has no per-interface switch for ICMP unreachables ({'on' if iface.ip_unreachables else 'off'}); "
                            "it sends them unless a filter discards the packets with reject")
        if iface.mac_address:
            self.add(*path, f"mac {iface.mac_address}")
        if iface.autostate is False:
            self.report.add("interface", label, Severity.APPROX, "autostate",
                            "Junos has no 'no autostate': the irb unit goes down when no port of its VLAN is up")
        if iface.helper_addresses:
            self.relays.append(iface)

    def vrrp(self, iface: Interface, g: FhrpGroup, where: Tuple[str, ...]) -> None:
        add = fhrp_text.adder(self.report, iface.source_name or iface.name, g)
        path = where + (f"vrrp-group {g.group}",)
        self.add(*path, f"virtual-address {g.address}")
        for address in g.secondary:
            self.add(*path, f"virtual-address {address}")
        if g.priority is not None:
            self.add(*path, f"priority {g.priority}")
        if g.preempt is False:
            self.add(*path, "no-preempt")
        if g.hello_ms is not None:
            if g.hello_ms % 1000 == 0:
                self.add(*path, f"advertise-interval {g.hello_ms // 1000}")
            else:
                self.add(*path, f"fast-interval {g.hello_ms}")
        if g.version == 3:
            self.add("protocols", "vrrp", "version-3")
        if g.shutdown:
            add(Severity.REVIEW, "fhrp-shutdown", "Junos cannot shut a VRRP group down; it is written active")
        if g.name:
            add(Severity.APPROX, "fhrp-name", f"Junos VRRP groups have no name; '{g.name}' is left out")
        if g.mac:
            add(Severity.APPROX, "fhrp-mac", "the virtual MAC is VRRP's own on Junos")
        for track, decrement in g.tracks.items():
            target = self.device.tracks.get(track)
            if target is not None and target.interface:
                tracked = self.device.interfaces.get(target.interface)
                name = self.port(target.interface) if tracked is not None and tracked.lag else \
                    self.unit_name(target.interface)  # a LAG member has no unit of its own
                self.add(*path, "track", f"interface {name}", f"priority-cost {decrement}")
            else:
                add(Severity.REVIEW, "fhrp-track", f"tracking object {track} is not written: Junos VRRP tracks "
                    "interfaces and routes; add it by hand")
        self.add(*path, "accept-data")

    def switching(self, iface: Interface, unit: str, switching: Tuple[str, ...]) -> None:
        """Layer 2 settings of a switch port: voice VLAN, storm control, port security, trust, 802.1X."""
        label = self.label(iface)
        if iface.voice_vlan is not None:
            self.add("switch-options", "voip", f"interface {unit}", f"vlan {self.vlan_names.get(iface.voice_vlan, iface.voice_vlan)}")
        if iface.storm_control:
            self.add(*switching, f"storm-control {self.storm_profile(iface, label)}")
        if iface.port_security:
            path = ("switch-options", f"interface {unit}")
            self.add(*path, "interface-mac-limit", str(iface.port_security_max or 1))
            action = {"shutdown": "shutdown", "restrict": "drop-and-log", "protect": "drop"}.get(
                iface.port_security_violation or "shutdown", "shutdown")
            self.add(*path, "interface-mac-limit", f"packet-action {action}")
        if iface.dhcp_trust or iface.arp_trust:
            self.trusted.append((iface, unit))
            if iface.dhcp_trust != iface.arp_trust:
                self.report.add("interface", label, Severity.APPROX, "trust",
                                "Junos trusts a port for DHCP snooping and ARP inspection together")
        if iface.source_guard:
            self.guarded.append(iface)
        if iface.dot1x or iface.mab:
            self.authenticators.append((iface, unit))

    def storm_profile(self, iface: Interface, label: str) -> str:
        kinds = l2sec_text.storm(iface, "unknown-unicast", ["broadcast", "multicast", "unknown-unicast"], self.report,
                                 label, PLATFORM)
        level = min(kinds.values()) if kinds else 0.0
        if len(set(kinds.values())) > 1:
            self.report.add("interface", label, Severity.APPROX, "storm-level",
                            f"Junos sets one level for the kinds a profile limits; {l2sec_text.level_text(level)}% "
                            "(the lowest) is written for all")
        name = "SC-" + l2sec_text.level_text(level).replace(".", "_") + "".join(
            "-" + k[0].upper() for k in ("broadcast", "multicast", "unknown-unicast") if k in kinds)
        base = ("forwarding-options", f"storm-control-profiles {name}", "all")
        self.add(*base, f"bandwidth-percentage {l2sec_text.level_text(level)}")
        for kind in ("broadcast", "multicast", "unknown-unicast"):
            if kind not in kinds:
                self.add(*base, f"no-{kind}")
        return name

    def poe(self, iface: Interface) -> None:
        if iface.poe is None and not iface.poe_priority and iface.poe_max_mw is None:
            return
        path = ("poe", f"interface {self.port(iface.name)}")
        if iface.poe is False:
            self.add(*path, "disable")
            return
        self.add(*path)
        if iface.poe_priority:
            priority = "high" if iface.poe_priority in ("high", "critical") else "low"
            self.add(*path, f"priority {priority}")
            if iface.poe_priority not in ("high", "low"):
                self.report.add("interface", self.label(iface), Severity.APPROX, "poe-priority",
                                f"Junos PoE priorities are low and high; {iface.poe_priority} is written as {priority}")
        if iface.poe_max_mw is not None:
            watts = iface.poe_max_mw / 1000
            self.add(*path, f"maximum-power {watts:g}")

    def interface_filters(self, iface: Interface, path: Tuple[str, ...]) -> None:
        if iface.pbr and iface.pbr not in self.pbr_filters:
            self.report.add("interface", self.label(iface), Severity.REVIEW, "pbr",
                            f"route map {iface.pbr} also filters routes, or has no entry filter-based forwarding can "
                            "hold: policy-based routing is not written for this port; configure it by hand")
        for family, acl, qos, direction in (("inet", iface.acl_in, iface.qos_policy_in, "input"),
                                            ("inet", iface.acl_out, iface.qos_policy_out, "output"),
                                            ("inet6", iface.acl6_in, "", "input"),
                                            ("inet6", iface.acl6_out, "", "output")):
            names = [self.filter_names.get(acl, acl)] if acl else []
            if family == "inet" and direction == "input" and iface.pbr in self.pbr_filters:
                names.append(self.pbr_filters[iface.pbr])
            names += [qos] if qos else []
            if len(names) == 1:
                self.add(*path, f"family {family}", "filter", f"{direction} {names[0]}")
            elif len(names) > 1:  # an ACL and a QoS or PBR policy: Junos runs the filters of a list in turn
                for name in names:
                    self.add(*path, f"family {family}", "filter", f"{direction}-list {name}")
                self.report.add("interface", self.label(iface), Severity.REVIEW, "filter-list",
                                f"the {direction} filters {', '.join(names)} are a filter list: Junos stops at the "
                                "first filter that accepts or forwards a packet, so check the later ones still see "
                                "the packets they should, or merge the terms into one filter")

    @staticmethod
    def is_switch_port(iface: Interface) -> bool:
        return iface.mode != SwitchportMode.ROUTED and iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG)

    def switch_filters(self, iface: Interface, switching: Tuple[str, ...]) -> None:
        """The ACL, MAC ACL or QoS policy of a switch port, as an ethernet-switching filter: a port takes one each
        way."""
        label = self.label(iface)
        for acl, mac, qos, acl6, direction in (
                (iface.acl_in, iface.mac_acl_in, iface.qos_policy_in, iface.acl6_in, "input"),
                (iface.acl_out, iface.mac_acl_out, iface.qos_policy_out, iface.acl6_out, "output")):
            names = [n for n in (self.filter_names.get(acl, acl) if acl else "", mac, qos) if n]
            if names:
                self.add(*switching, "filter", f"{direction} {names[0]}")
            if names[1:]:
                self.report.add("interface", label, Severity.REVIEW, "switch-filters",
                                f"a Junos switch port takes one {direction} filter: {names[0]} is applied, "
                                + ", ".join(names[1:]) + " not; merge their terms into one filter")
            if acl6:
                self.report.add("interface", label, Severity.REVIEW, "switch-filters",
                                f"the IPv6 ACL {acl6} has no ethernet-switching form; not applied")

    def leftovers(self, iface: Interface) -> None:
        """What a port carries that this writer does not write yet."""
        written = set(PORT_WRITTEN) | {"acl"}
        partial.port(iface, self.report, self.label(iface), PLATFORM, written)
        if iface.cdp:
            self.report.add("interface", self.label(iface), Severity.APPROX, "cdp", "Junos has no CDP")

    # routing policy and firewall filters --------------------------------------------------------------------------

    def policy(self) -> None:
        dev = self.device
        self.prefix_kinds = junospolicy.prefix_lists(dev, self.add, self.report)
        self.communities = junospolicy.lists(dev, self.add, self.report)
        pbr_only = set(bfd_text.pbr_only(dev))
        junospolicy.policies(dev, self.add, self.report, self.prefix_kinds, self.communities, skip=pbr_only)
        switching = {i.acl_in for i in dev.interfaces.values() if self.is_switch_port(i)} | \
            {i.acl_out for i in dev.interfaces.values() if self.is_switch_port(i)}
        self.filter_names = junospolicy.filters(dev, self.add, self.report, sorted(switching - {""}))
        junossec.mac_filters(dev, self.add, self.report)
        self.pbr_filters = junosrouting.pbr(dev, self.add, self.report, lambda name: dev.interfaces[name].vrf,
                                            self.instance)

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
        self.mgmt.snmp()

    # routing -----------------------------------------------------------------------------------------------------

    def routing_instances(self) -> None:
        vx = self.device.vxlan
        for vrf in self.device.vrfs:
            if vrf in self.mgmt_vrfs:
                continue
            label = f"vrf {vrf}"
            self.report.item("system", label)
            info = self.device.vrf_info.get(vrf)
            path = ("routing-instances", vrf)
            members = [i for i in self.device.interfaces.values()
                       if i.vrf == vrf and i.kind not in (InterfaceKind.TUNNEL, InterfaceKind.OTHER)]
            l3vni = vx.vrf_vnis.get(vrf) if vx is not None else None
            if info is not None and info.rd and (info.rt_import or info.rt_export):
                self.add(*path, "instance-type vrf")
                for iface in members:
                    self.add(*path, f"interface {self.unit_name(iface.name)}")
                self.add(*path, f"route-distinguisher {info.rd}")
                self.targets(vrf, info, label)
            else:
                self.add(*path, "instance-type virtual-router")
                for iface in members:
                    self.add(*path, f"interface {self.unit_name(iface.name)}")
                if info is not None and (info.rd or info.rt_import or info.rt_export):
                    self.report.add("system", label, Severity.REVIEW, "vrf-partial",
                                    "a Junos VRF instance needs both a route distinguisher and route targets; written "
                                    "as a virtual router without them")
            if l3vni is not None:
                evpn = path + ("protocols", "evpn", "ip-prefix-routes")
                self.add(*evpn, "advertise direct-nexthop")
                self.add(*evpn, "encapsulation vxlan")
                self.add(*evpn, f"vni {l3vni}")
            if info is not None and info.leaks:
                name = f"{vrf}-LEAK"
                base = ("policy-options", f"policy-statement {name}")
                for source, rmap in info.leaks.items():
                    term = base + (f"term {source}",)
                    self.add(*term, "from", f"instance {self.instance(source)}")
                    if rmap:
                        self.add(*term, "from", f"policy {rmap}")
                    self.add(*term, "then accept")
                self.add(*base, f"term {junospolicy.IMPLICIT}", "then reject")
                self.add(*path, "routing-options", f"instance-import {name}")
                self.report.add("system", label, Severity.APPROX, "leak",
                                "the routes leaked from VRF " + ", ".join(info.leaks) + " are imported with the "
                                f"instance-import policy {name}")

    def targets(self, vrf: str, info: VrfInfo, label: str) -> None:
        """The route targets of a VRF: vrf-target where one import and one export do, else vrf-import and
        vrf-export policies; an export route map is called from the export policy."""
        path = ("routing-instances", vrf)
        pairs = vrfs_text.targets(info)
        simple = len(info.rt_import) <= 1 and len(info.rt_export) <= 1 and not info.export_map
        if simple and len(pairs) == 1 and pairs[0][0] == "both":
            self.add(*path, f"vrf-target target:{pairs[0][1]}")
            return
        if simple:
            for direction, values in (("import", info.rt_import), ("export", info.rt_export)):
                for value in values:
                    self.add(*path, "vrf-target", f"{direction} target:{value}")
            return
        for direction, values in (("import", info.rt_import), ("export", info.rt_export)):
            name = f"{vrf}-{direction.upper()}"
            community = f"{vrf}-RT-{direction.upper()}"
            for value in values:
                self.add("policy-options", f"community {community}", f"members target:{value}")
            base = ("policy-options", f"policy-statement {name}")
            term = base + ("term targets",)
            if direction == "import":
                self.add(*term, "from", f"community {community}")
                self.add(*term, "then accept")
            else:
                if info.export_map:
                    self.add(*term, "from", f"policy {info.export_map}")
                if values:
                    self.add(*term, "then", f"community add {community}")
                self.add(*term, "then accept")
            self.add(*base, f"term {junospolicy.IMPLICIT}", "then reject")
            self.add(*path, f"vrf-{direction} {name}")

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
            if route.tag is not None:
                self.add(*path, f"tag {route.tag}")
            if route.name:
                self.report.add("route", label, Severity.APPROX, "route-name",
                                f"the route's name '{route.name}' has no place on Junos and is left out")
            if route.track:
                self.report.add("route", label, Severity.REVIEW, "route-track",
                                f"Junos does not track static routes (object {route.track}); the route is always on. "
                                "IP monitoring (services ip-monitoring) can swap its next hop on a failed RPM probe")

    def unused_bfd(self) -> None:
        for iface in self.device.interfaces.values():
            if bfd_text.has_timers(iface) and iface.name not in self.bfd_ports:
                self.report.add("interface", self.label(iface), Severity.APPROX, "bfd-timers",
                                "Junos sets BFD timers per protocol session and no OSPF or BGP session on this port "
                                "runs BFD; the timers are left out")

    def router_id(self) -> str:
        if self.rid is not None:
            return self.rid
        ids = [self.device.system.router_id] if self.device.system.router_id else []
        ids += [p.router_id for p in self.device.ospf if not p.vrf and p.router_id]
        if self.device.bgp is not None and self.device.bgp.router_id:
            ids.append(self.device.bgp.router_id)
        if self.device.system.router_id:
            self.report.item("system", "router ID")
        if len(set(ids)) > 1:
            self.report.add("system", "router ID", Severity.APPROX, "router-id",
                            f"Junos has one router ID for OSPF and BGP; {ids[0]} is written, not {', '.join(ids[1:])}")
        self.rid = ids[0] if ids else ""
        return self.rid

    def ospf(self) -> None:
        rid = self.router_id()
        if rid:
            self.add("routing-options", f"router-id {rid}")
        seen: Dict[str, str] = {}
        bfd_ports = set(bfd_text.ospf_interfaces(self.device))
        junosrouting.graceful_restart(self.device, self.add, self.instance)
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
                junosrouting.ospf_interface(self.device, iface, path, self.add, self.report, self.label(iface),
                                            name in bfd_ports)
                if name in bfd_ports:
                    self.bfd_ports.add(name)
            if p.redistribute or p.default_originate:
                name = f"{p.vrf}-OSPF-EXPORT" if p.vrf else "OSPF-EXPORT"
                junospolicy.export_policy(self.add, name, p.redistribute, p.redistribute_maps,
                                          default=p.default_originate)
                self.add(*base, f"export {name}")
                if p.default_originate == "always":
                    where = ("routing-instances", self.instance(p.vrf), "routing-options") if p.vrf else \
                        ("routing-options",)
                    self.add(*where, "generate", "route 0.0.0.0/0", "discard")
                    self.report.add("ospf", label, Severity.APPROX, "default-always",
                                    "default-information originate always is written as a generated default route "
                                    "that OSPF exports")
            junosrouting.ospf_options(self.device, p, base, self.add, self.report, label)

    def bgp(self) -> None:
        bgp = self.device.bgp
        if bgp is None:
            return
        label = f"bgp {bgp.local_as}"
        self.report.item("bgp", label)
        self.add("routing-options", f"autonomous-system {bgp.local_as}" + (" asdot-notation" if bgp.asdot else ""))
        if bgp.keepalive is not None or bgp.hold is not None:
            hold = bgp.hold if bgp.hold is not None else 3 * (bgp.keepalive or 60)
            self.add("protocols", "bgp", f"hold-time {hold}")
            if bgp.keepalive is not None and bgp.keepalive * 3 != hold:
                self.report.add("bgp", label, Severity.APPROX, "bgp-timers",
                                f"Junos sets the hold time only and sends keepalives at a third of it; keepalive "
                                f"{bgp.keepalive} becomes {hold // 3}")
        if bgp.graceful_restart:
            self.add("routing-options", "graceful-restart")
            if bgp.graceful_restart_time:
                self.add("routing-options", "graceful-restart", f"restart-duration {bgp.graceful_restart_time}")
        if bgp.distance and bgp.distance[2] != 200:
            self.report.add("bgp", label, Severity.APPROX, "bgp-distance",
                            f"Junos has no distance for local BGP routes; {bgp.distance[2]} is left out")
        if bgp.med_missing_as_worst or any(v.med_missing_as_worst for v in bgp.vrfs.values()):
            self.report.add("bgp", label, Severity.APPROX, "med-missing",
                            "Junos has no 'missing-as-worst': a route without MED counts as MED 0")
        if bgp.maximum_paths or bgp.maximum_paths_ibgp:
            self.add("protocols", "bgp", "multipath" + (" multiple-as" if bgp.multipath_relax else ""))
            self.load_balance()
            self.report.add("bgp", label, Severity.APPROX, "multipath",
                            f"maximum-paths {bgp.maximum_paths or bgp.maximum_paths_ibgp} is written as multipath: "
                            "Junos installs as many equal paths as the platform allows")
        evpn_text.junos_domains(bgp, self.report)
        self.families_note(label, bgp.redistribute, bgp.redistribute6)
        self.bgp_instance("", bgp.peer_groups, bgp.neighbors, bgp.networks, bgp.redistribute + bgp.redistribute6,
                          bgp.redistribute_maps, bgp.aggregates, bgp.ospf_match, label)
        for name, v in bgp.vrfs.items():
            vlabel = f"bgp vrf {name}"
            self.report.item("bgp", vlabel)
            used = {n.peer_group for n in v.neighbors}
            groups = {k: g for k, g in bgp.peer_groups.items() if k in used}
            groups.update(v.peer_groups)
            if v.maximum_paths:
                self.add("routing-instances", self.instance(name), "protocols", "bgp", "multipath")
            self.families_note(vlabel, v.redistribute, v.redistribute6)
            self.bgp_instance(name, groups, v.neighbors, v.networks, v.redistribute + v.redistribute6,
                              v.redistribute_maps, v.aggregates, v.ospf_match, vlabel)

    def families_note(self, label: str, v4: List[str], v6: List[str]) -> None:
        if v6 and set(v4) != set(v6):
            self.report.add("bgp", label, Severity.APPROX, "redistribute6",
                            f"one export policy serves IPv4 and IPv6 on Junos: the IPv4 sources ({', '.join(v4) or '-'})"
                            f" and the IPv6 ones ({', '.join(v6)}) are exported in both families")

    def bgp_instance(self, vrf: str, groups: Dict[str, BgpNeighbor], neighbors: List[BgpNeighbor],
                     networks: List[str], redistribute: List[str], maps: Dict[str, str],
                     aggregates: List[BgpAggregate], ospf_match: List[str], label: str) -> None:
        """BGP in the main routing table or in a VRF's routing instance."""
        bgp = self.device.bgp
        assert bgp is not None
        base: Tuple[str, ...] = ("protocols", "bgp")
        options: Tuple[str, ...] = ("routing-options",)
        if vrf:
            base = ("routing-instances", self.instance(vrf)) + base
            options = ("routing-instances", self.instance(vrf)) + options
        for a in aggregates:
            net = ipaddress.ip_network(a.prefix)
            rib = options + (("rib inet6.0" if not vrf else f"rib {self.instance(vrf)}.inet6.0",) if net.version == 6
                             else ())
            self.add(*rib, "aggregate", f"route {net}", "full" if a.as_set else "brief")
        sources = list(dict.fromkeys(redistribute))
        if networks or sources or aggregates:
            name = f"{vrf}-BGP-EXPORT" if vrf else "BGP-EXPORT"
            junospolicy.export_policy(self.add, name, sources, maps, networks, ospf_match=ospf_match,
                                      aggregates=aggregates)
            self.add(*base, f"export {name}")
            if any(n.route_map_out or n.prefix_list_out or n.next_hop_self for n in list(groups.values()) + neighbors):
                self.report.add("bgp", label, Severity.APPROX, "bgp-export",
                                f"the redistribution and network statements are the export policy {name}; a group "
                                "or neighbor with its own export policy does not use it on Junos, and exports every "
                                "route its policy accepts, whatever protocol it comes from")
        dev = self.device
        if dev.community_lists or any("community" in e.sets for rm in dev.route_maps.values() for e in rm.entries):
            quiet = [g.address for g in groups.values() if not g.send_community
                     and any(n.peer_group == g.address and not n.send_community for n in neighbors)]
            quiet += [n.address for n in neighbors if not n.peer_group and not n.send_community]
            if quiet:
                self.report.add("bgp", label, Severity.APPROX, "send-community",
                                "Junos sends communities to every peer; the source sent none to " + ", ".join(quiet)
                                + ": strip them with 'then community delete' in their export policy if that matters")
        local = bgp.local_as
        for name, group in groups.items():
            members = [n for n in neighbors if n.peer_group == name]
            if not members:
                continue
            path = base + (f"group {name}",)
            fallback = sorted({bgp_text.family(n.address) for n in members} - {""})
            self.peer(path, group, label, group_as=group.remote_as, fallback=fallback, members=members)
            kind = "internal" if group.remote_as == local else "external"
            if not group.remote_as:
                remotes = {n.remote_as or group.remote_as for n in members}
                kind = "internal" if remotes == {local} else "external"
            self.add(*path, f"type {kind}")
            self.preference(path, kind)
        for neighbor in neighbors:
            nlabel = f"neighbor {neighbor.address}" + (f" vrf {vrf}" if vrf else "")
            self.report.item("bgp", nlabel)
            pgroup = groups.get(neighbor.peer_group)
            remote = neighbor.remote_as or (pgroup.remote_as if pgroup is not None else "")
            if pgroup is None:
                group_name = "IBGP" if remote == local else "EBGP"
                kind = "internal" if group_name == "IBGP" else "external"
                self.add(*base, f"group {group_name}", f"type {kind}")
                self.preference(base + (f"group {group_name}",), kind)
                own_as = neighbor.remote_as if group_name == "EBGP" else ""
            else:
                group_name = neighbor.peer_group
                own_as = neighbor.remote_as if neighbor.remote_as != pgroup.remote_as else ""
            path = base + (f"group {group_name}", f"neighbor {neighbor.address}")
            self.add(*path)
            self.peer(path, neighbor, nlabel, group_as=own_as)

    def preference(self, path: Tuple[str, ...], kind: str) -> None:
        bgp = self.device.bgp
        if bgp is not None and bgp.distance:
            value = bgp.distance[0] if kind == "external" else bgp.distance[1]
            self.add(*path, f"preference {value}")

    def peer(self, path: Tuple[str, ...], p: BgpNeighbor, label: str, group_as: str,
             fallback: Sequence[str] = (), members: Sequence[BgpNeighbor] = ()) -> None:
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
            timers, source, ports = junosrouting.bgp_timers(self.device, p, members)
            junosrouting.detection(self.add, path, timers)
            self.bfd_ports.update(ports)
            self.bfd_multihop_used = self.bfd_multihop_used or source == "multihop"
            if not source:
                self.report.add("bgp", label, Severity.APPROX, "bfd",
                                "Junos needs a BFD interval and the source sets none for this session: 300 ms x3 "
                                "written (the EOS default)")
        if p.password:
            self.add(*path, f"authentication-key {quote(p.password)}")
        if p.hold is not None or p.keepalive is not None:
            hold = p.hold if p.hold is not None else 3 * (p.keepalive or 60)
            self.add(*path, f"hold-time {hold}")
            if p.keepalive is not None and p.keepalive * 3 != hold:
                self.report.add("bgp", label, Severity.APPROX, "bgp-timers",
                                f"Junos sets the hold time only and sends keepalives at a third of it; keepalive "
                                f"{p.keepalive} becomes {hold // 3}")
        if p.remove_private_as:
            mode = {"all": " all", "all replace-as": " all replace"}.get(p.remove_private_as_mode, "")
            self.add(*path, f"remove-private{mode}")
        if p.route_reflector_client:
            self.add(*path, f"cluster {self.router_id() or bgp.router_id or '0.0.0.1'}")
        if p.local_as:
            options = {"no-prepend": " private", "no-prepend replace-as": " private no-prepend-global-as"}.get(
                p.local_as_options, "")
            self.add(*path, f"local-as {p.local_as}{options}")
        written = {"password", "timers", "remove_private_as", "remove_private_as_mode", "route_reflector_client",
                   "local_as", "maximum_prefix", "maximum_prefix_warning"}
        bgp_text.unwritten(p, written, self.report, label, "Junos")
        families = p.families or ([bgp_text.family(p.address)] if bgp_text.family(p.address) else list(fallback))
        stated = p.families and p.families != [bgp_text.family(p.address)]
        for family in families:
            words = {"ipv4": "family inet", "ipv6": "family inet6", "evpn": "family evpn"}[family]
            sub = "signaling" if family == "evpn" else "unicast"
            if stated or p.maximum_prefix and family != "evpn":
                self.add(*path, words, sub)
            if p.maximum_prefix and family != "evpn":
                self.add(*path, words, sub, "prefix-limit", f"maximum {p.maximum_prefix}")
                if p.maximum_prefix_warning:
                    self.add(*path, words, sub, "prefix-limit", f"teardown {p.maximum_prefix_warning}")
        if p.maximum_prefix and p.maximum_prefix_warning:
            self.report.add("bgp", label, Severity.APPROX, "prefix-limit",
                            f"Junos warns at {p.maximum_prefix_warning}% and tears the session down at the limit; "
                            "the source may only have warned")
        if p.next_hop_self:
            self.add("policy-options", "policy-statement NEXT-HOP-SELF", "then", "next-hop self")
            self.add(*path, "export NEXT-HOP-SELF")
        for direction, plist, rmap in (("import", p.prefix_list_in, p.route_map_in),
                                       ("export", p.prefix_list_out, p.route_map_out)):
            if plist:
                self.add(*path, f"{direction} {junospolicy.prefix_policy(self.add, plist, self.prefix_kinds)}")
            if rmap:
                self.add(*path, f"{direction} {rmap}")
        if p.shutdown:
            self.report.add("bgp", label, Severity.REVIEW, "bgp-shutdown",
                            "the session is shut down in the source; deactivate it on Junos (deactivate protocols "
                            "bgp group ...) by hand")

    def load_balance(self) -> None:
        """Junos installs one path in the forwarding table unless a policy tells it to balance."""
        self.add("policy-options", "policy-statement LOAD-BALANCE", "then", "load-balance per-packet")
        self.add("routing-options", "forwarding-table", "export LOAD-BALANCE")

    # EVPN and VXLAN, MC-LAG -------------------------------------------------------------------------------------

    def evpn(self) -> None:
        dev = self.device
        vx = dev.vxlan
        if vx is None:
            return
        label = "VXLAN"
        self.report.item("interface", label)
        source = self.unit_name(vx.source_interface) if vx.source_interface else ""
        if source:
            self.add("switch-options", f"vtep-source-interface {source}")
        if vx.udp_port not in (None, 4789):
            self.report.add("interface", label, Severity.REVIEW, "vxlan-port",
                            f"Junos uses UDP port 4789 for VXLAN; port {vx.udp_port} is not written")
        for vid, vni in sorted(vx.vlan_vnis.items()):
            self.add("vlans", self.vlan_names.get(vid, f"VLAN{vid}"), "vxlan", f"vni {vni}")
            if vid in vx.mcast_groups:
                self.add("vlans", self.vlan_names.get(vid, f"VLAN{vid}"), "vxlan",
                         f"multicast-group {vx.mcast_groups[vid]}")
        if vx.mcast_groups:
            self.report.add("interface", label, Severity.APPROX, "vxlan-mcast",
                            "the multicast groups are written per VLAN (vxlan multicast-group); Junos takes them only "
                            "where the platform replicates by multicast, and EVPN fabrics replicate by ingress "
                            "replication")
        if vx.flood_vteps:
            for vtep in vx.flood_vteps:
                self.add("switch-options", f"remote-vtep-list {vtep}")
            for vid in vx.vlan_vnis:
                if vid not in vx.evpn_vlans:
                    self.add("vlans", self.vlan_names.get(vid, f"VLAN{vid}"), "vxlan", "ingress-node-replication")
        if vx.evpn_vlans:
            base = ("protocols", "evpn")
            self.add(*base, "encapsulation vxlan")
            vnis = [vx.vlan_vnis[v] for v in vx.evpn_vlans if v in vx.vlan_vnis]
            for vni in vnis:
                self.add(*base, f"extended-vni-list {vni}")
            if dev.anycast_mac and any(i.virtual_ipv4 or i.virtual_ipv6 for i in dev.interfaces.values()):
                self.add(*base, "default-gateway no-gateway-community")
            vtep = self.address_of(vx.source_interface) if vx.source_interface else ""
            rds = [i.rd for i in vx.evpn_instances.values() if i.rd]
            rd = f"{vtep or self.router_id() or '0.0.0.0'}:1"
            self.add("switch-options", f"route-distinguisher {rd}")
            self.add("switch-options", "vrf-target auto")
            if rds:
                self.report.add("interface", label, Severity.APPROX, "evpn-rd",
                                f"Junos' default switch has one route distinguisher ({rd}); the instances' own ("
                                + ", ".join(rds) + ") are not written")
            for inst in vx.evpn_instances.values():
                imports, exports = inst.rt_import, inst.rt_export
                for vid in inst.vlans:
                    vni_id = vx.vlan_vnis.get(vid)
                    if vni_id is None:
                        continue
                    path = base + ("vni-options", f"vni {vni_id}")
                    if imports == exports and len(imports) == 1:
                        self.add(*path, f"vrf-target target:{imports[0]}")
                    else:
                        for value in exports[:1]:
                            self.add(*path, "vrf-target", f"export target:{value}")
                        if imports[1:] or exports[1:] or imports != exports:
                            self.report.add("interface", label, Severity.REVIEW, "evpn-rt",
                                            f"instance {inst.name}: Junos sets one target per VNI; the import "
                                            f"targets {', '.join(imports) or '-'} need a vrf-import policy in "
                                            "switch-options, not written")
                if inst.igmp:
                    self.report.add("interface", label, Severity.APPROX, "evpn-igmp",
                                    f"instance {inst.name}: IGMP joins become EVPN routes on Junos when IGMP snooping "
                                    "runs in the VLANs (protocols igmp-snooping); 'redistribute igmp' has no line of "
                                    "its own")
        bgp = dev.bgp
        if bgp is not None and bgp.evpn_host_flap:
            window, moves, expiry = bgp.evpn_host_flap
            dup = ("protocols", "evpn", "duplicate-mac-detection")
            self.add(*dup, f"detection-window {window}")
            self.add(*dup, f"detection-threshold {moves}")
            if expiry:
                self.add(*dup, f"auto-recovery-time {max(1, round(expiry / 60))}")
                if expiry % 60:
                    self.report.add("bgp", f"bgp {bgp.local_as}", Severity.APPROX, "host-flap",
                                    f"Junos recovers a duplicate MAC after whole minutes; {expiry} s is rounded")
        if vx.mlag_shared_mac:
            self.report.add("interface", label, Severity.APPROX, "vxlan-mlag-mac",
                            "the MLAG pair's shared router MAC (encapsulation mac-address mlag-system-id) has no "
                            "Junos equivalent: Junos fabrics multihome with ESI LAGs")
        if vx.qos_propagation:
            self.report.add("interface", label, Severity.APPROX, "vxlan-qos",
                            "VXLAN QoS propagation (" + ", ".join(vx.qos_propagation) + ") is left out: Junos copies "
                            "the DSCP of the inner header into the outer one by itself")

    def mclag(self) -> None:
        """An MLAG pair as Junos MC-LAG: ICCP between the peers, the peer link as the ICL, mc-ae on each shared LAG."""
        m = self.device.mlag
        if m is None or m.stack:
            if m is not None:
                self.report.skip("interface", "multi-chassis LAG", "stackwise",
                                 "StackWise Virtual makes two switches one; Junos does that with a Virtual Chassis, "
                                 "which is set up outside the configuration")
            return
        label = "multi-chassis LAG"
        self.report.item("interface", label)
        local = self.address_of(m.local_interface) if m.local_interface else ""
        if local:
            self.add("protocols", "iccp", f"local-ip-addr {local}")
        if m.peer_address:
            peer = ("protocols", "iccp", f"peer {m.peer_address}")
            self.add(*peer, "redundancy-group-id-list 1")
            self.add(*peer, "liveness-detection", "minimum-interval 1000")
            if m.heartbeat:
                self.add(*peer, "backup-liveness-detection", f"backup-peer-ip {m.heartbeat}")
            if m.peer_link:
                self.add("multi-chassis", f"multi-chassis-protection {m.peer_address}",
                         f"interface {self.port(m.peer_link)}")
        self.add("switch-options", "service-id 1")
        for iface in self.device.interfaces.values():
            if iface.mlag_id is None or iface.kind != InterfaceKind.LAG:
                continue
            top = ("interfaces", self.port(iface.name), "aggregated-ether-options")
            mc = top + ("mc-ae",)
            self.add(*mc, f"mc-ae-id {iface.mlag_id}")
            self.add(*mc, "redundancy-group 1")
            self.add(*mc, f"chassis-id {0 if m.role != 'secondary' else 1}")
            self.add(*mc, "mode active-active")
            self.add(*mc, f"status-control {'standby' if m.role == 'secondary' else 'active'}")
            if m.reload_delay:
                self.add(*mc, f"init-delay-time {m.reload_delay}")
            if not iface.lacp_system_id:
                self.add(*top, "lacp", f"system-id 00:00:00:00:{iface.mlag_id // 256:02x}:{iface.mlag_id % 256:02x}")
                self.add(*top, "lacp", f"admin-key {iface.mlag_id}")
        self.report.add("interface", label, Severity.APPROX, "mclag",
                        f"MLAG domain {m.domain or '-'} is written as Junos MC-LAG (ICCP, mc-ae): this switch is "
                        "chassis-id 0 with status-control active, so give the peer chassis-id 1 and standby; the LACP "
                        "system IDs and admin keys are made up and must match on both")
        if m.dual_primary_delay is not None or m.reload_delay_non_mlag:
            self.report.add("interface", label, Severity.APPROX, "mclag-options",
                            "dual-primary detection and the reload delay of the other ports have no MC-LAG "
                            "equivalent; prefer-status-control-active and the ICCP backup liveness come closest")

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
                 or i.stp_guard or i.stp_bpduguard or i.stp_bpdufilter]
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
            for vid, value in sorted(stp_text.defined_vlan_priorities(dev, self.report).items()):
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
            if iface.stp_guard == "loop":
                self.add(*path, "bpdu-timeout-action block")
            if iface.stp_bpdufilter:
                self.add("protocols", "layer2-control", "bpdu-block", f"interface {self.port(iface.name)}", "drop")
            if iface.stp_bpduguard:
                self.add("protocols", "layer2-control", "bpdu-block", f"interface {self.port(iface.name)}")

    # layer 2 security, DHCP, AAA and 802.1X ----------------------------------------------------------------------

    def port_vlans(self, iface: Interface) -> List[int]:
        if iface.mode == SwitchportMode.ACCESS:
            return [iface.access_vlan or 1]
        if not iface.allowed_vlans:
            return sorted(self.device.vlans)
        vids: List[int] = []
        for part in iface.allowed_vlans.split(","):
            low, _, high = part.strip().partition("-")
            if low.isdigit():
                vids += [v for v in range(int(low), int(high or low) + 1) if v in self.vlan_names]
        return vids

    # security ----------------------------------------------------------------------------------------------------

    def security(self) -> None:
        dev = self.device

        def loopback_unit(vrf: str) -> Optional[str]:
            lo = next((i for i in dev.interfaces.values() if i.kind == InterfaceKind.LOOPBACK and i.vrf == vrf), None)
            return self.unit_name(lo.name).split(".", 1)[1] if lo is not None else None

        re_filters: Dict[str, List[str]] = {}  # lo0.N / me0.0 -> input filters guarding the routing engine

        def apply(unit: str, name: str) -> None:
            re_filters.setdefault(unit, []).append(name)

        junossec.control_plane(dev, self.add, apply, self.report, sorted(self.mgmt_vrfs), loopback_unit,
                               lambda acl: self.filter_names.get(acl, acl))
        login = self.mgmt.login_filter()
        if login is not None:
            apply(f"{login[1]}.0", login[0])
        for unit, names in re_filters.items():
            ifd, number = unit.split(".")
            path = ("interfaces", ifd, f"unit {number}", "family inet", "filter")
            if len(names) == 1:
                self.add(*path, f"input {names[0]}")
            else:
                for name in names:
                    self.add(*path, f"input-list {name}")
        junossec.macsec(dev, self.add, self.report, self.port)
        junossec.coa(dev, self.add, self.report)

    # class of service --------------------------------------------------------------------------------------------

    def cos(self) -> None:
        dev = self.device
        families: Dict[str, Set[str]] = {}
        for iface in dev.interfaces.values():
            switch = self.is_switch_port(iface)
            for name in (iface.qos_policy_in, iface.qos_policy_out):
                if name:
                    families.setdefault(name, set()).add("ethernet-switching" if switch else "inet")
        junosqos.policy_filters(dev, self.add, self.report, families)
        junosqos.CosWriter(dev, self.add, self.report, self.port).write()

    # multicast ---------------------------------------------------------------------------------------------------

    def multicast(self) -> None:
        """PIM and IGMP on routed interfaces, rendezvous points, anycast RP, MSDP, and IGMP snooping with its
        querier."""
        dev = self.device
        label = "multicast routing"
        if multicast_text.uses_pim(dev) or dev.multicast_vrfs or dev.msdp_peers:
            self.report.item("system", label)
        for vrf_name in [""] + list(dev.multicast_vrfs):
            base: Tuple[str, ...] = ("protocols",)
            if vrf_name:
                base = ("routing-instances", self.instance(vrf_name)) + base
                m = dev.multicast_vrfs[vrf_name]
                routing, rps, rp_groups = m.routing, m.rps, m.rp_groups
            else:
                routing, rps, rp_groups = dev.multicast_routing, dev.pim_rps, dev.pim_rp_groups
            ifaces = [i for i in dev.interfaces.values() if (i.pim or i.igmp_version is not None)
                      and i.vrf == vrf_name and not i.shutdown]
            for iface in ifaces:
                unit = self.unit_name(iface.name)
                if iface.pim:
                    self.add(*base, "pim", f"interface {unit}", f"mode {iface.pim}")
                if iface.igmp_version is not None:
                    self.add(*base, "igmp", f"interface {unit}", f"version {iface.igmp_version}")
            for rp in rps:
                if rp in dev.pim_anycast and not vrf_name and self.owns(rp, dev.pim_anycast[rp]):
                    continue  # written as the local RP below
                groups = rp_groups.get(rp, "")
                path = base + ("pim", "rp", "static", f"address {rp}")
                self.add(*path)
                self.rp_groups(path, groups, label)
            if routing and not ifaces and not rps:
                self.add(*base, "pim", "interface all", "mode sparse")
                self.report.add("system", label, Severity.APPROX, "pim-all",
                                ("VRF " + vrf_name + ": " if vrf_name else "") + "Junos routes multicast where PIM "
                                "runs; with no PIM interface in the source, PIM is written on every interface")
        for rp, peers in dev.pim_anycast.items():
            own = self.owns(rp, peers)
            if not own:
                self.report.add("system", label, Severity.REVIEW, "anycast-rp",
                                f"anycast RP {rp} ({', '.join(peers)}): Junos sets the RP set only on the RPs "
                                "themselves (pim rp local ... anycast-pim); this switch owns none of the addresses, so "
                                "it is left out and the RP is written as a static one")
                continue
            path = ("protocols", "pim", "rp", "local")
            self.add(*path, f"address {rp}")
            self.rp_groups(path, dev.pim_rp_groups.get(rp, ""), label)
            for peer in peers:
                self.add(*path, "anycast-pim", "rp-set", f"address {peer}")
            self.add(*path, "anycast-pim", f"local-address {own}")
        for peer, via in dev.msdp_peers.items():
            path = ("protocols", "msdp", f"peer {peer}")
            self.add(*path)
            source = dev.interfaces.get(via) if via else None
            if source is not None and source.ipv4:
                self.add(*path, f"local-address {source.ipv4[0].split('/')[0]}")
        self.igmp_snooping()

    def owns(self, rp: str, peers: List[str]) -> str:
        """The address of the anycast RP set (or the RP address) that is one of this switch's own, or ""."""
        mine = {a.split("/")[0]: a for i in self.device.interfaces.values() for a in i.ipv4}
        return next((a for a in peers + [rp] if a in mine), "")

    def rp_groups(self, path: Tuple[str, ...], groups: str, label: str) -> None:
        if groups.startswith("acl "):
            acl = self.device.acls.get(groups[4:])
            prefixes = [e.source for e in acl.entries if e.action == AclAction.PERMIT and e.source != "any"] \
                if acl is not None else []
            if acl is None or not prefixes or any(e.action == AclAction.DENY for e in acl.entries):
                self.report.add("system", label, Severity.REVIEW, "rp-groups",
                                f"the RP's groups come from {groups}, which is not a plain list of group prefixes; "
                                "set group-ranges by hand")
                return
            for prefix in prefixes:
                self.add(*path, f"group-ranges {prefix}")
        elif groups:
            self.add(*path, f"group-ranges {groups}")

    def igmp_snooping(self) -> None:
        dev = self.device
        snooped = multicast_text.snooped(dev)
        if not snooped and not multicast_text.stated(dev):
            return
        self.report.item("vlan", multicast_text.LABEL)
        base = ("protocols", "igmp-snooping")
        every = dev.igmp_snooping and all(v.igmp_snooping is not False for v in dev.vlans.values())
        if every:
            self.add(*base, "vlan all")
        for vid in snooped:
            vlan = dev.vlans[vid]
            name = self.vlan_names.get(vid, f"VLAN{vid}")
            if not every:
                self.add(*base, f"vlan {name}")
            if not (dev.igmp_querier or vlan.igmp_querier):
                continue
            address = vlan.igmp_querier_address or dev.igmp_querier_address
            if not address:
                svi = dev.interfaces.get(f"Vlan{vid}")
                address = svi.ipv4[0].split("/")[0] if svi is not None and svi.ipv4 else ""
            if not address:
                self.report.add("vlan", multicast_text.LABEL, Severity.REVIEW, "igmp-querier",
                                f"VLAN {vid}: the Junos querier needs a source address and the VLAN has none; set "
                                "l2-querier source-address by hand")
                continue
            self.add(*base, f"vlan {name}", "l2-querier", f"source-address {address}")
            version = vlan.igmp_querier_version or dev.igmp_querier_version
            if version and version != 2:
                self.report.add("vlan", multicast_text.LABEL, Severity.APPROX, "igmp-querier",
                                f"VLAN {vid}: the querier version ({version}) is not written; the Junos querier "
                                "sends the version of the hosts it hears")
        if dev.igmp_snooping is False or any(v.igmp_snooping is False for v in dev.vlans.values()):
            self.report.add("vlan", multicast_text.LABEL, Severity.APPROX, "igmp-off",
                            "Junos snoops only the VLANs listed under igmp-snooping; the VLANs where the source "
                            "switched snooping off are simply not listed")

    def snooping(self) -> None:
        dev = self.device
        snooped = l2sec_text.snooping_vlans_written(dev, self.report)
        inspected = l2sec_text.inspection_vlans(dev)
        guarded = {v for i in self.guarded for v in self.port_vlans(i)}
        vlans = sorted(set(snooped) | set(inspected) | guarded)
        for vid in vlans:
            base = ("vlans", self.vlan_names.get(vid, f"VLAN{vid}"), "forwarding-options", "dhcp-security")
            self.add(*base)
            if vid in inspected:
                self.add(*base, "arp-inspection")
            if vid in guarded:
                self.add(*base, "ip-source-guard")
            if dev.dhcp_option82:
                self.add(*base, "option-82")
            for iface, unit in self.trusted:
                if vid in self.port_vlans(iface):
                    self.add(*base, "group TRUSTED", "overrides trusted")
                    self.add(*base, "group TRUSTED", f"interface {unit}")
            for iface in self.device.interfaces.values():
                if iface.mode == SwitchportMode.TRUNK and not iface.lag and not (iface.dhcp_trust or iface.arp_trust) \
                        and vid in self.port_vlans(iface):
                    unit = self.unit_name(iface.name)
                    self.add(*base, "group UNTRUSTED", "overrides untrusted")  # Junos trusts trunk ports by default
                    self.add(*base, "group UNTRUSTED", f"interface {unit}")
        for vid in vlans:
            if vid not in snooped:
                self.report.add("vlan", str(vid), Severity.APPROX, "snooping-implied",
                                "Junos inspects ARP and guards sources against DHCP snooping, so the VLAN snoops DHCP "
                                "too")
        for iface in self.guarded:
            others = sorted({self.port(i.name) for i in self.device.interfaces.values() if i.mode ==
                             SwitchportMode.ACCESS and not i.source_guard and set(self.port_vlans(i)) &
                             set(self.port_vlans(iface))})
            self.report.add("interface", self.label(iface), Severity.APPROX, "source-guard",
                            "Junos guards source addresses per VLAN" + (
                                f": {', '.join(others)} in the same VLAN are guarded too" if others else ""))
        if dev.dhcp_option82 is not None and not vlans:
            self.report.add("system", "DHCP snooping", Severity.REVIEW, "option82",
                            "Junos inserts option 82 per snooped VLAN, and no VLAN snoops; left out")
        elif dev.dhcp_option82 is not None:
            self.report.item("system", "DHCP snooping")

    def dhcp_relay(self) -> None:
        groups: Dict[Tuple[str, Tuple[str, ...]], List[Interface]] = {}
        for iface in self.relays:
            groups.setdefault((iface.vrf, tuple(iface.helper_addresses)), []).append(iface)
        numbers: Dict[str, int] = {}
        for (vrf, servers), members in groups.items():
            numbers[vrf] = numbers.get(vrf, 0) + 1
            name = f"RELAY-{numbers[vrf]}"
            base: Tuple[str, ...] = ("forwarding-options", "dhcp-relay")
            if vrf:
                base = ("routing-instances", self.instance(vrf)) + base
            for server in servers:
                self.add(*base, f"server-group {name}", server)
            self.add(*base, f"group {name}", f"active-server-group {name}")
            for iface in members:
                self.add(*base, f"group {name}", f"interface {self.unit_name(iface.name)}")
                if iface.helper_source:
                    self.add(*base, f"group {name}", f"relay-source {self.unit_name(iface.helper_source)}")
                if iface.helper_vrf and iface.helper_vrf != iface.vrf:
                    self.report.add("interface", self.label(iface), Severity.REVIEW, "relay-vrf",
                                    f"the DHCP servers are in VRF {iface.helper_vrf}: the relay is written in the "
                                    f"interface's own routing instance, so leak the routes to the servers into it")

    def dhcp_server(self) -> None:
        for pool in self.device.dhcp_pools:
            label = dhcp_text.label(pool)
            self.report.item("dhcp", label)
            base: Tuple[str, ...] = ("access", "address-assignment", f"pool {pool.name}", "family inet")
            if pool.vrf:
                base = ("routing-instances", self.instance(pool.vrf)) + base
            if not pool.network:
                self.report.skip("dhcp", label, "dhcp-network", "a Junos pool needs a network; the pool has none")
                continue
            self.add(*base, f"network {pool.network}")
            for n, (low, high) in enumerate(pool.ranges, 1):
                self.add(*base, f"range R{n}", f"low {low}")
                self.add(*base, f"range R{n}", f"high {high}")
            attrs = base + ("dhcp-attributes",)
            for router in pool.default_routers:
                self.add(*attrs, "router", router)
            for server in pool.dns_servers:
                self.add(*attrs, "name-server", server)
            if pool.domain_name:
                self.add(*attrs, f"domain-name {pool.domain_name}")
            if pool.lease_seconds is not None:
                self.add(*attrs, f"maximum-lease-time {pool.lease_seconds or 'infinite'}")
            net = ipaddress.ip_network(pool.network)
            served = [i for i in self.device.interfaces.values() if i.vrf == pool.vrf and any(
                ipaddress.ip_interface(a).network == net for a in i.ipv4)]
            where: Tuple[str, ...] = ("system", "services", "dhcp-local-server")
            if pool.vrf:
                where = ("routing-instances", self.instance(pool.vrf)) + where
            for iface in served:
                self.add(*where, "group DHCP-SERVER", f"interface {self.unit_name(iface.name)}")
            if not served:
                self.report.add("dhcp", label, Severity.REVIEW, "dhcp-interface",
                                "no interface is in the pool's network; add the interface that serves it to "
                                "system services dhcp-local-server by hand")

    def aaa(self) -> None:
        a = self.device.aaa
        order: List[str] = []
        for server in a.servers:
            label = aaa_text.server_label(server)
            self.report.item("management", label)
            word = "radius-server" if server.protocol == "radius" else "tacplus-server"
            path = ("system", f"{word} {server.address}")
            self.add(*path, f"secret {quote(aaa_text.key(server, self.report))}")
            if server.auth_port is not None:
                self.add(*path, f"port {server.auth_port}")
            if server.acct_port is not None and server.protocol == "radius":
                self.add(*path, f"accounting-port {server.acct_port}")
            if server.timeout is not None:
                self.add(*path, f"timeout {server.timeout}")
            source = a.source.get(server.protocol)
            if source:
                address = self.address_of(source)
                if address:
                    self.add(*path, f"source-address {address}")
                else:
                    self.report.add("management", label, Severity.REVIEW, "source-address",
                                    f"Junos names the source by its address; {source} has none, left out")
            if server.vrf:
                self.add(*path, f"routing-instance {self.instance(server.vrf)}")
        for method in a.methods:
            label = aaa_text.method_label(method)
            self.report.item("management", label)
            if method.kind == "authentication" and method.service == "login" and method.name == "default":
                for m in method.methods:
                    protocol = aaa_text.protocol_of(self.device, m)
                    word = {"radius": "radius", "tacacs": "tacplus", "": "password" if m == "local" else ""}[protocol]
                    if word and word not in order:
                        order.append(word)
                    if m.startswith("group:") and m[6:] not in ("radius", "tacacs"):
                        group = a.groups.get(m[6:])
                        everyone = {s.address for s in a.servers if s.protocol == protocol}
                        if group is not None and set(group.servers) != everyone:
                            self.report.add("management", label, Severity.APPROX, "aaa-group",
                                            f"Junos asks every {protocol} server; group {group.name} named only "
                                            f"{', '.join(group.servers)}")
                    if m in ("none", "enable", "if-authenticated"):
                        self.report.add("management", label, Severity.APPROX, "aaa-method",
                                        f"Junos has no '{m}' login method; left out")
            elif method.kind == "authentication" and method.service == "dot1x":
                pass  # the access profile of 802.1X
            elif method.kind == "accounting" and method.service in ("exec", "commands"):
                protocol = next((aaa_text.protocol_of(self.device, m) for m in method.methods
                                 if aaa_text.protocol_of(self.device, m)), "")
                if protocol:
                    events = "login" if method.service == "exec" else "interactive-commands"
                    self.add("system", "accounting", f"events {events}")
                    self.add("system", "accounting", f"destination {'radius' if protocol == 'radius' else 'tacplus'}")
            else:
                self.report.add("management", label, Severity.APPROX, "aaa-method",
                                f"Junos has no {method.kind} {method.service} method list"
                                + (": the login class the server names decides what the user may run"
                                   if method.kind == "authorization" else "; left out"))
        for word in order:
            self.add("system", f"authentication-order {word}")

    def dot1x(self) -> None:
        if not self.authenticators:
            return
        base = ("protocols", "dot1x", "authenticator")
        self.add(*base, "authentication-profile-name dot1x")
        servers = [s for s in self.device.aaa.servers if s.protocol == "radius"]
        self.add("access", "profile dot1x", "authentication-order radius")
        for server in servers:
            self.add("access", "profile dot1x", "radius", "authentication-server", server.address)
            self.add("access", f"radius-server {server.address}", f"secret {quote(aaa_text.key(server, self.report))}")
        modes = {"single-host": "single-secure", "multi-host": "single", "multi-auth": "multiple",
                 "multi-domain": "multiple"}
        for iface, unit in self.authenticators:
            path = base + (f"interface {unit}",)
            label = self.label(iface)
            if iface.dot1x:
                mode = modes.get(iface.dot1x_host_mode or "single-host", "single-secure")
                self.add(*path, f"supplicant {mode}")
                if iface.dot1x_host_mode == "multi-domain":
                    self.report.add("interface", label, Severity.APPROX, "dot1x-mode",
                                    "multi-domain is written as supplicant multiple: the phone authenticates like any "
                                    "other client")
            if iface.mab:
                self.add(*path, "mac-radius" + ("" if iface.dot1x else " restrict"))
            if iface.dot1x_reauth:
                self.add(*path, f"reauthentication {iface.dot1x_reauth_period or 3600}")
            else:
                self.add(*path, "no-reauthentication")
            if iface.dot1x_fail_vlan is not None:
                self.add(*path, f"server-reject-vlan {self.vlan_names.get(iface.dot1x_fail_vlan, iface.dot1x_fail_vlan)}")

    # the rest ----------------------------------------------------------------------------------------------------

    def not_yet(self) -> None:
        partial.device(self.device, self.report, PLATFORM, WRITTEN)


def emit(device: Device, ports: PortMapper, report: Report) -> str:
    return Writer(device, ports, report).emit()
