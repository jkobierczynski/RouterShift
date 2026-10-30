# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for HPE Comware 7, as lines for the system view."""

from __future__ import annotations

import ipaddress
from typing import Callable, List, Tuple

from .. import acl as acl_text
from ..model import AclAction, AclEntry, Device, Interface, InterfaceKind, LacpMode, StaticRoute, StpMode, SwitchportMode
from ..names import PortMapper
from ..parsers.comware import ranges
from ..parsers.ioslike import _vlan_ids
from ..report import Report, Severity
from ..timezones import offset_minutes

_IND = " "


def vlan_words(model_list: str) -> str:
    """The model's ``10,20,30-40`` as Comware's ``10 20 30 to 40``."""
    return " ".join(part.replace("-", " to ") for part in ranges(_vlan_ids(model_list)).split(","))


class Writer:
    def __init__(self, device: Device, ports: PortMapper, report: Report) -> None:
        self.device = device
        self.port = ports
        self.report = report
        self.out: List[str] = []
        self.is_switch = bool(device.vlans) or any(
            i.mode != SwitchportMode.ROUTED for i in device.interfaces.values())

    def emit(self) -> str:
        self.system()
        self.vrfs()
        self.vlans()
        self.spanning_tree()
        self.acls()
        order = {InterfaceKind.LAG: 0}
        for iface in sorted(self.device.interfaces.values(), key=lambda i: order.get(i.kind, 1)):
            self.interface(iface)
        self.routes()
        self.out.append("return")
        self.report.unparsed(self.device.unparsed)
        return "\n".join(self.out) + "\n"

    def block_end(self) -> None:
        self.out.append("#")

    # system ----------------------------------------------------------------------------------------------------------

    def system(self) -> None:
        s = self.device.system
        rep = self.report
        if s.hostname:
            self.out.append(f"{_IND}sysname {s.hostname}")
            rep.item("system", "hostname")
        if s.timezone:
            minutes = offset_minutes(s.timezone)
            if minutes is None:
                rep.add("system", "time zone", Severity.REVIEW, "timezone",
                        f"time zone '{s.timezone}' has no fixed offset; Comware takes 'clock timezone NAME add "
                        "HH:MM:SS' and 'clock summer-time'; set it by hand")
            else:
                name = s.timezone.split()[0] if " " in s.timezone else "UTC"
                sign = "minus" if minutes < 0 else "add"
                m = abs(minutes)
                self.out.append(f"{_IND}clock timezone {name} {sign} {m // 60:02d}:{m % 60:02d}:00")
                rep.item("system", "time zone")
        vpn = f" vpn-instance {s.service_vrf}" if s.service_vrf else ""
        if s.domain_name:
            self.out.append(f"{_IND}dns domain {s.domain_name}")
            rep.item("system", "domain name")
        for server in s.dns_servers:
            self.out.append(f"{_IND}dns server {server}{vpn}")
        if s.dns_servers:
            rep.item("system", "name servers")
        if s.ntp_servers:
            self.out.append(f"{_IND}ntp-service enable")
            self.out += [f"{_IND}ntp-service unicast-server {server}{vpn}" for server in s.ntp_servers]
            rep.item("system", "ntp servers")
        for host in s.syslog_servers:
            self.out.append(f"{_IND}info-center loghost{vpn} {host}")
        if s.syslog_servers:
            rep.item("system", "syslog servers")
        if s.banner_motd:
            delim = "%" if "%" not in s.banner_motd else "^"
            self.out += [f"{_IND}header motd {delim}", s.banner_motd, delim]
            rep.item("system", "banner motd")
        self.block_end()

    def vrfs(self) -> None:
        # the management VRF too: Comware binds its management port to a VPN instance like any other interface
        for name in self.device.vrfs:
            self.out.append(f"ip vpn-instance {name}")
            self.block_end()
            self.report.item("system", f"vrf {name}")

    def vlans(self) -> None:
        for vlan in sorted(self.device.vlans.values(), key=lambda v: v.vlan_id):
            self.out.append(f"vlan {vlan.vlan_id}")
            if vlan.name:
                self.out.append(f"{_IND}name {vlan.name}")
            if vlan.shutdown:
                self.out.append(f"{_IND}shutdown")
            self.block_end()
            self.report.item("vlan", str(vlan.vlan_id))

    def spanning_tree(self) -> None:
        mode = self.device.stp_mode
        if mode == StpMode.NONE or (mode is None and not self.is_switch):
            return
        if mode is None:
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-default",
                            "the source runs spanning tree in its default mode; written as Comware's default, MSTP")
        else:
            word = {StpMode.STP: "stp", StpMode.RSTP: "rstp", StpMode.MSTP: "mstp",
                    StpMode.RAPID_PVST: "pvst", StpMode.PVST: "pvst"}[mode]
            if word != "mstp":
                self.out.append(f"{_IND}stp mode {word}")
            if mode == StpMode.PVST:
                self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                                "PVST+ written as Comware PVST, which runs the rapid protocol")
            else:
                self.report.item("system", "spanning-tree mode")
        guarded = [i for i in self.device.interfaces.values() if i.stp_bpduguard]
        if guarded:
            self.out.append(f"{_IND}stp bpdu-protection")
            edge = [i for i in self.device.interfaces.values() if i.stp_portfast]
            if any(not i.stp_bpduguard for i in edge):
                self.report.add("system", "bpdu guard", Severity.APPROX, "bpdu-protection",
                                "Comware sets BPDU protection for all edge ports at once; edge ports without BPDU guard "
                                "on the source get it too")
        self.out.append(f"{_IND}stp global enable")
        self.block_end()

    # access lists ----------------------------------------------------------------------------------------------------

    def acls(self) -> None:
        for acl in self.device.acls.values():
            name = acl_text.safe_name(acl.name)
            label = acl.name if name == acl.name else f"{acl.name} -> {name}"
            self.report.item("acl", label)
            self.out.append(f"acl {'ipv6 ' if acl.family == 6 else ''}advanced name {name}")
            pending: List[str] = []  # remarks, written as the comment of the next rule
            for seq, entry, src, dst in acl_text.numbered(acl, step=5):
                if entry.unsupported:
                    self.report.add("acl", label, Severity.REVIEW, "acl-entry",
                                    f"entry '{entry.unsupported}' not converted; add it by hand after rule "
                                    f"{seq - 5}")
                    continue
                if entry.action == AclAction.REMARK:
                    pending.append(entry.remark)
                    continue
                self.out.append(f"{_IND}rule {seq} {self._rule(entry, acl.family, src, dst)}")
                if pending:
                    self.out.append(f"{_IND}rule {seq} comment {' '.join(pending)}")
                    pending = []
            self.block_end()

    def _rule(self, entry: AclEntry, family: int, src: Tuple[str, List[int]], dst: Tuple[str, List[int]]) -> str:
        words = [entry.action.value]
        proto = entry.protocol
        if proto == "ip":
            proto = "ipv6" if family == 6 else "ip"
        words.append(proto)
        for side, address, ports in (("source", entry.source, src), ("destination", entry.destination, dst)):
            if address != "any":
                net = ipaddress.ip_network(address)
                if net.version == 4:
                    words += [side, str(net.network_address), str(net.hostmask)]
                else:
                    words += [side, str(net.network_address), str(net.prefixlen)]
            if ports[0]:
                words += [f"{side}-port"] + acl_text.cisco_ports(ports)
        if entry.icmp_type is not None:
            words += ["icmp6-type" if family == 6 else "icmp-type", str(entry.icmp_type)]
        if entry.established:
            words.append("established")
        if entry.log:
            words.append("logging")
        return " ".join(words)

    # interfaces ------------------------------------------------------------------------------------------------------

    def interface(self, iface: Interface) -> None:
        name = self.port(iface.name)
        label = f"{iface.source_name or iface.name} -> {name}"
        self.report.item("interface", label)

        def add(severity: Severity, code: str, message: str) -> None:
            self.report.add("interface", label, severity, code, message)

        lines: List[str] = []
        if iface.kind == InterfaceKind.ETHERNET:
            lines.append("port link-mode route" if iface.mode == SwitchportMode.ROUTED else "port link-mode bridge")
        if iface.description:
            lines.append(f"description {iface.description}")
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.encapsulation_vlan is not None:
            lines.append(f"vlan-type dot1q vid {iface.encapsulation_vlan}")
        if iface.speed is not None:
            lines.append(f"speed {iface.speed}")
            add(Severity.APPROX, "speed", "forced speed: check that the port takes it")
        if iface.duplex in ("full", "half"):
            lines.append(f"duplex {iface.duplex}")
        if iface.mtu is not None:
            if iface.mode == SwitchportMode.ROUTED or iface.kind in (InterfaceKind.VLAN, InterfaceKind.SUBINTERFACE):
                lines.append(f"mtu {iface.mtu}")
            else:
                lines.append(f"jumbo-frame enable {iface.mtu}")
        if iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG):
            lines += self._layer2(iface, add)
        if iface.lag:
            lines.append(f"port link-aggregation group {iface.lag[len('Port-channel'):]}")
            if iface.lacp_mode == LacpMode.PASSIVE:
                lines.append("lacp mode passive")
        if iface.kind == InterfaceKind.LAG:
            modes = {m.lacp_mode for m in self.device.interfaces.values() if m.lag == iface.name}
            if modes - {LacpMode.STATIC, None}:
                lines.append("link-aggregation mode dynamic")
        if iface.vrf:
            lines.append(f"ip binding vpn-instance {iface.vrf}")
        if iface.dhcp_client:
            lines.append("ip address dhcp-alloc")
        for n, cidr in enumerate(iface.ipv4):
            net = ipaddress.ip_interface(cidr)
            lines.append(f"ip address {net.ip} {net.netmask}" + (" sub" if n else ""))
        for cidr in iface.ipv6:
            lines.append(f"ipv6 address {cidr}")
        for attr, v6, direction in (("acl_in", "", "inbound"), ("acl_out", "", "outbound"),
                                    ("acl6_in", "ipv6 ", "inbound"), ("acl6_out", "ipv6 ", "outbound")):
            acl_name = getattr(iface, attr)
            if acl_name and acl_name in self.device.acls:
                lines.append(f"packet-filter {v6}name {acl_text.safe_name(acl_name)} {direction}")
            elif acl_name:
                add(Severity.REVIEW, "acl-missing", f"ACL {acl_name} is applied but not defined; left out")
        if iface.helper_addresses:
            lines.append("dhcp select relay")
            lines += [f"dhcp relay server-address {helper}" for helper in iface.helper_addresses]
        if iface.stp_portfast:
            lines.append("stp edged-port")
        lines.append("shutdown" if iface.shutdown else "undo shutdown")
        self.out.append(f"interface {name}")
        self.out += [_IND + line for line in lines]
        self.block_end()
        if (iface.source_name or iface.name, name) in self.port.renumbered:
            add(Severity.APPROX, "port-renamed",
                f"named {name} without a port map; check it against the cabling of the new device")

    def _layer2(self, iface: Interface, add: Callable[[Severity, str, str], None]) -> List[str]:
        if iface.mode == SwitchportMode.ROUTED:
            return []
        source = self.device.interfaces.get(iface.lag) if iface.lag else iface
        if source is None:
            return []
        if source.mode == SwitchportMode.ACCESS:
            data = source.access_vlan or 1
            if source.voice_vlan is not None:
                if iface is source:
                    add(Severity.APPROX, "voice-vlan",
                        f"access VLAN {data} with voice VLAN {source.voice_vlan} written as a hybrid port (untagged "
                        f"{data}, tagged {source.voice_vlan}), the Comware way; phones learn the VLAN by LLDP")
                return ["port link-type hybrid", f"port hybrid vlan {source.voice_vlan} tagged",
                        f"port hybrid vlan {data} untagged", f"port hybrid pvid vlan {data}",
                        f"voice-vlan {source.voice_vlan} enable"]
            return [] if data == 1 else [f"port access vlan {data}"]
        lines = ["port link-type trunk"]
        if source.allowed_vlans:
            allowed = _vlan_ids(source.allowed_vlans)
            if 1 not in allowed:
                lines.append("undo port trunk permit vlan 1")
            lines.append(f"port trunk permit vlan {vlan_words(source.allowed_vlans)}")
        else:
            lines.append("port trunk permit vlan all")
        if source.native_vlan not in (None, 1):
            lines.append(f"port trunk pvid vlan {source.native_vlan}")
        return lines

    # routing ---------------------------------------------------------------------------------------------------------

    def routes(self) -> None:
        for route in self.device.static_routes:
            label = f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}"
            self.report.item("route", label)
            self.out.append(_IND + self._route(route, label))
        if self.device.static_routes:
            self.block_end()

    def _route(self, route: StaticRoute, label: str) -> str:
        net = ipaddress.ip_network(route.prefix)
        words = ["ip" if net.version == 4 else "ipv6", "route-static"]
        if route.vrf:
            words += ["vpn-instance", route.vrf]
        words += [str(net.network_address), str(net.prefixlen)]
        if route.discard:
            words.append("NULL0")
        else:
            if route.interface:
                words.append(self.port(route.interface))
            if route.next_hop:
                words.append(route.next_hop)
        if route.distance is not None:
            words += ["preference", str(route.distance)]
        if route.name:
            words += ["description", route.name]
        return " ".join(words)


def emit(device: Device, ports: PortMapper, report: Report) -> str:
    return Writer(device, ports, report).emit()
