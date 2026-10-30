# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for HPE Aruba AOS-CX (10.x)."""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List

from .. import acl as acl_text
from ..model import Device, Interface, InterfaceKind, LacpMode, StaticRoute, StpMode, SwitchportMode
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
        # a LAG exists before the ports that join it
        order = {InterfaceKind.MANAGEMENT: 0, InterfaceKind.LAG: 1}
        for iface in sorted(self.device.interfaces.values(), key=lambda i: order.get(i.kind, 2)):
            self.interface(iface)
        self.routes()
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
        if s.ntp_servers:
            self.out += [f"ntp server {server} iburst" for server in s.ntp_servers]
            self.out.append("ntp enable")
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
        self.out.append("!")

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
        if iface.stp_portfast:
            lines.append("spanning-tree port-type admin-edge")
        if iface.stp_bpduguard:
            lines.append("spanning-tree bpdu-guard")
        self.out.append(f"interface {name}")
        self.out += [_IND + line for line in lines]
        if (iface.source_name or iface.name, name) in self.port.renumbered:
            add(Severity.APPROX, "port-renamed",
                f"named {name} without a port map; check it against the cabling of the new device")

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
