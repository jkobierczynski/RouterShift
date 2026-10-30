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
from typing import Dict, List, Optional, Set, Tuple

from .. import acl as acl_text
from .. import dhcp as dhcp_text
from .. import nat as nat_text
from .. import fhrp
from .. import ospf as ospf_text
from ..model import Device, FhrpGroup, Interface, InterfaceKind, LacpMode, StaticRoute, StpMode, SwitchportMode, Vlan
from ..names import PortMapper
from ..parsers.ioslike import _vlan_ids
from ..report import Report, Severity
from ..timezones import offset_minutes

_IND = "   "
_PORT = re.compile(r"^(.*?)(\d+)$")
_TRANSIT_VLANS = range(3999, 3000, -1)  # where a routed port's VLAN is taken from


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
        self.interfaces()
        self.routes()
        self.vlan_blocks()
        self.spanning_tree()
        self.dhcp()
        nat_text.skip_all(self.device, self.report, "AOS-S")
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
        if s.ntp_servers:
            self.out += ["timesync sntp", "sntp unicast"]
            self.out += [f"sntp server priority {n} {server}" for n, server in enumerate(s.ntp_servers, 1)]
            rep.item("system", "ntp servers")
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
        if mode is None:
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-default",
                            "the source runs spanning tree in its default mode; AOS-S has it off until enabled, so "
                            "MSTP is switched on")
        elif mode == StpMode.RSTP:
            self.out.append("spanning-tree force-version rstp-operation")
            self.report.item("system", "spanning-tree mode")
        elif mode == StpMode.RAPID_PVST:
            self.out.append("spanning-tree mode rapid-pvst")
            self.report.item("system", "spanning-tree mode")
        elif mode == StpMode.MSTP:
            self.report.item("system", "spanning-tree mode")
        else:
            self.out.append("spanning-tree mode rapid-pvst")
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                            f"{mode.value} is not available on AOS-S, written as rapid-pvst")
        edge = [self.port(i.name) for i in self.device.interfaces.values() if i.stp_portfast and not i.lag]
        guard = [self.port(i.name) for i in self.device.interfaces.values() if i.stp_bpduguard and not i.lag]
        if edge:
            self.out.append(f"spanning-tree {port_list(edge)} admin-edge-port")
        if guard:
            self.out.append(f"spanning-tree {port_list(guard)} bpdu-protection")


def emit(device: Device, ports: PortMapper, report: Report) -> str:
    return Writer(device, ports, report).emit()
