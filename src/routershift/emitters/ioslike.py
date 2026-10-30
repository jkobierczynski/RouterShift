# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for Cisco IOS / IOS XE and Arista EOS: one class, the dialect picks the spelling."""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List

from .. import acl as acl_text
from .. import fhrp
from ..model import (AclAction, Device, FhrpGroup, Interface, InterfaceKind, LacpMode, StaticRoute, StpMode,
                     SwitchportMode)
from ..names import PortMapper
from ..report import Report, Severity
from ..timezones import offset_minutes

_IOS_MGMT_VRF = "Mgmt-vrf"  # fixed name of the management VRF of a Catalyst
_IOS_MAX_MTU = 9198

_STP = {
    "ios": {StpMode.PVST: "pvst", StpMode.RAPID_PVST: "rapid-pvst", StpMode.MSTP: "mst"},
    "eos": {StpMode.RAPID_PVST: "rapid-pvst", StpMode.MSTP: "mstp", StpMode.RSTP: "rstp", StpMode.NONE: "none"},
}
_STP_FALLBACK = {StpMode.RSTP: StpMode.RAPID_PVST, StpMode.PVST: StpMode.RAPID_PVST, StpMode.STP: StpMode.RAPID_PVST}

_Add = Callable[[Severity, str, str], None]

_EOS_SPEED = {10: "10full", 100: "100full", 1000: "1000full", 10000: "10000full", 25000: "25gfull",
              40000: "40gfull", 50000: "50gfull", 100000: "100gfull"}


class Writer:
    def __init__(self, device: Device, target: str, ports: PortMapper, report: Report) -> None:
        self.device = device
        self.target = target
        self.ios = target == "ios"
        self.port = ports
        self.report = report
        self.out: List[str] = []
        self.ind = " " if self.ios else "   "  # indentation of a line inside a block
        self.vrf_names: Dict[str, str] = {}
        self.is_switch = bool(device.vlans) or any(
            i.mode != SwitchportMode.ROUTED for i in device.interfaces.values())

    def vrf(self, name: str) -> str:
        return self.vrf_names.get(name, name)

    def emit(self) -> str:
        self._plan_vrfs()
        self.groups = {i.name: fhrp.plan(i, self.target, self.report, self.port(i.name))
                       for i in self.device.interfaces.values() if i.fhrp}
        self.vrrp_v3 = self.ios and any(
            g.protocol == "vrrp" and g.version == 3 for gs in self.groups.values() for g in gs)
        self.system()
        self.spanning_tree()
        self.vrfs()
        self.vlans()
        for iface in self.device.interfaces.values():
            self.interface(iface)
        self.routing()
        self.acls()
        self.services()
        self.banner()
        self.out.append("end")
        self.unparsed()
        return "\n".join(self.out) + "\n"

    # ---------------------------------------------------------------------------------------------------------------

    def _plan_vrfs(self) -> None:
        if not self.ios:
            return
        for iface in self.device.interfaces.values():
            if iface.kind == InterfaceKind.MANAGEMENT and iface.vrf and iface.vrf != _IOS_MGMT_VRF:
                self.vrf_names[iface.vrf] = _IOS_MGMT_VRF
                self.report.add("system", f"vrf {iface.vrf}", Severity.APPROX, "mgmt-vrf",
                                f"management VRF {iface.vrf} becomes {_IOS_MGMT_VRF}, the name IOS XE fixes for it")

    def system(self) -> None:
        s = self.device.system
        rep = self.report
        if s.hostname:
            self.out.append(f"hostname {s.hostname}")
            rep.item("system", "hostname")
        if s.domain_name:
            self.out.append(f"ip domain name {s.domain_name}" if self.ios else f"dns domain {s.domain_name}")
            rep.item("system", "domain name")
        if s.dns_servers:
            via = f"vrf {self.vrf(s.service_vrf)} " if s.service_vrf else ""
            self.out.append(f"ip name-server {via}" + " ".join(s.dns_servers))
            rep.item("system", "name servers")
        if self.vrrp_v3:
            self.out.append("fhrp version vrrp v3")
        self._anycast_mac()
        self.out.append("!")

    def spanning_tree(self) -> None:
        mode = self.device.stp_mode
        if mode is None:
            return
        table = _STP[self.target]
        if mode in table:
            self.out += [f"spanning-tree mode {table[mode]}", "!"]
            self.report.item("system", "spanning-tree mode")
            return
        if mode == StpMode.NONE:
            self.report.add("system", "spanning-tree mode", Severity.REVIEW, "stp-none",
                            "spanning tree is off on the source; IOS cannot switch it off globally, left at its default")
            return
        fallback = _STP_FALLBACK[mode]
        self.out += [f"spanning-tree mode {table[fallback]}", "!"]
        self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                        f"{mode.value} is not available, written as {fallback.value}")

    def vrfs(self) -> None:
        for name in self.device.vrfs:
            target = self.vrf(name)
            if self.ios and target == _IOS_MGMT_VRF:
                continue  # predefined
            if self.ios:
                self.out.append(f"vrf definition {target}")
                self.out += [" address-family ipv4", " exit-address-family"]
                if self._vrf_has_ipv6(name):
                    self.out += [" address-family ipv6", " exit-address-family"]
            else:
                self.out.append(f"vrf instance {target}")
            self.out.append("!")
            self.report.item("system", f"vrf {name}")

    def _vrf_has_ipv6(self, vrf: str) -> bool:
        return any(i.vrf == vrf and i.ipv6 for i in self.device.interfaces.values()) or any(
            r.vrf == vrf and ":" in r.prefix for r in self.device.static_routes)

    def vlans(self) -> None:
        for vlan in sorted(self.device.vlans.values(), key=lambda v: v.vlan_id):
            self.out.append(f"vlan {vlan.vlan_id}")
            if vlan.name:
                self.out.append(f"{self.ind}name {vlan.name}")
            if vlan.shutdown:
                self.out.append(f"{self.ind}state suspend")
            self.out.append("!")
            self.report.item("vlan", str(vlan.vlan_id))

    # interfaces ------------------------------------------------------------------------------------------------------

    def interface(self, iface: Interface) -> None:
        name = self.port(iface.name)
        label = f"{iface.source_name or iface.name} -> {name}"
        self.report.item("interface", label)

        def add(severity: Severity, code: str, message: str) -> None:
            self.report.add("interface", label, severity, code, message)

        lines: List[str] = []
        if iface.description:
            lines.append(f"description {iface.description}")
        is_l2_capable = iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG)
        if is_l2_capable:
            lines += self._switchport(iface, add)
        if iface.lag:
            word = {LacpMode.ACTIVE: "active", LacpMode.PASSIVE: "passive"}.get(iface.lacp_mode or LacpMode.STATIC, "on")
            lines.append(f"channel-group {iface.lag[len('Port-channel'):]} mode {word}")
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.encapsulation_vlan is not None:
            vid = iface.encapsulation_vlan
            lines.append(f"encapsulation dot1Q {vid}" if self.ios else f"encapsulation dot1q vlan {vid}")
        if iface.vrf:
            vrf = self.vrf(iface.vrf)
            lines.append(f"vrf forwarding {vrf}" if self.ios else f"vrf {vrf}")
        lines += self._addresses(iface)
        lines += self._acl_bindings(iface, add)
        lines += self._fhrp(iface, name)
        if iface.mtu is not None:
            mtu = iface.mtu
            if self.ios and mtu > _IOS_MAX_MTU:
                mtu = _IOS_MAX_MTU
                add(Severity.APPROX, "mtu", f"MTU {iface.mtu} lowered to {mtu}, the largest a Catalyst 9000 port takes")
            lines.append(f"mtu {mtu}")
        lines += self._speed(iface, add)
        if iface.stp_portfast:
            trunk = iface.mode == SwitchportMode.TRUNK
            lines.append("spanning-tree portfast trunk" if self.ios and trunk else "spanning-tree portfast")
        if iface.stp_bpduguard is not None:
            lines.append(f"spanning-tree bpduguard {'enable' if iface.stp_bpduguard else 'disable'}")
        lines.append("shutdown" if iface.shutdown else "no shutdown")
        self.out.append(f"interface {name}")
        self.out += [self.ind + line for line in lines]
        self.out.append("!")
        if (iface.source_name or iface.name, name) in self.port.renumbered:
            add(Severity.APPROX, "port-renamed",
                f"named {name} without a port map; check it against the cabling of the new device")

    def _switchport(self, iface: Interface, add: "_Add") -> List[str]:
        lines: List[str] = []
        if iface.mode == SwitchportMode.ROUTED:
            if iface.kind == InterfaceKind.LAG or not self.ios or self.is_switch:
                lines.append("no switchport")
            return lines
        if iface.lag:
            lag = self.device.interfaces.get(iface.lag)
            if not self.ios or lag is None:
                return lines  # the LAG carries the switchport settings
            iface = lag  # IOS wants the members configured like their port-channel
        if self.ios:
            lines.append("switchport")
        if iface.mode == SwitchportMode.ACCESS:
            if self.ios:
                lines.append("switchport mode access")
            if iface.access_vlan is not None:
                lines.append(f"switchport access vlan {iface.access_vlan}")
            if iface.voice_vlan is not None:
                if self.ios:
                    lines.append(f"switchport voice vlan {iface.voice_vlan}")
                else:
                    lines.append(f"switchport phone vlan {iface.voice_vlan}")
                    add(Severity.APPROX, "voice-vlan",
                        "voice VLAN written as 'switchport phone vlan'; EOS also needs 'switchport phone trunk' "
                        "and LLDP-MED on releases before 4.27")
        else:
            lines.append("switchport mode trunk")
            if iface.native_vlan is not None:
                lines.append(f"switchport trunk native vlan {iface.native_vlan}")
            if iface.allowed_vlans:
                lines.append(f"switchport trunk allowed vlan {iface.allowed_vlans}")
        return lines

    def _addresses(self, iface: Interface) -> List[str]:
        lines: List[str] = []
        if iface.dhcp_client:
            lines.append("ip address dhcp")
        for n, cidr in enumerate(iface.ipv4):
            suffix = " secondary" if n else ""
            if self.ios:
                net = ipaddress.ip_interface(cidr)
                lines.append(f"ip address {net.ip} {net.netmask}{suffix}")
            else:
                lines.append(f"ip address {cidr}{suffix}")
        for cidr in iface.ipv6:
            lines.append(f"ipv6 address {cidr}")
        for helper in iface.helper_addresses:
            lines.append(f"ip helper-address {helper}")
        return lines

    def _speed(self, iface: Interface, add: "_Add") -> List[str]:
        if iface.speed is None:
            if iface.duplex in ("full", "half") and self.ios:
                return [f"duplex {iface.duplex}"]
            return []
        if self.ios:
            lines = [f"speed {iface.speed}"]
            if iface.duplex in ("full", "half"):
                lines.append(f"duplex {iface.duplex}")
            return lines
        word = _EOS_SPEED.get(iface.speed)
        if word is None:
            add(Severity.REVIEW, "speed", f"speed {iface.speed} Mbit/s has no EOS setting; left at auto")
            return []
        if iface.duplex == "half":
            word = word.replace("full", "half")
        add(Severity.APPROX, "speed", "forced speed: check that the transceiver and EOS release take it")
        return [f"speed forced {word}"]

    def _acl_bindings(self, iface: Interface, add: "_Add") -> List[str]:
        lines = []
        for attr, direction in (("acl_in", "in"), ("acl_out", "out"), ("acl6_in", "in"), ("acl6_out", "out")):
            name = getattr(iface, attr)
            if not name:
                continue
            if name not in self.device.acls:
                add(Severity.REVIEW, "acl-missing", f"ACL {name} is applied but not defined; left out")
                continue
            if attr.startswith("acl6"):
                word = "ipv6 traffic-filter" if self.ios else "ipv6 access-group"
            else:
                word = "ip access-group"
            lines.append(f"{word} {acl_text.safe_name(name)} {direction}")
        return lines

    # first-hop redundancy --------------------------------------------------------------------------------------------

    def _anycast_mac(self) -> None:
        if self.ios:
            return
        anycast = [g for gs in self.groups.values() for g in gs if g.protocol == "anycast"]
        macs = sorted({g.mac for g in anycast if g.mac})
        if macs:
            self.out.append(f"ip virtual-router mac-address {macs[0]}")
        if len(macs) > 1:
            self.report.add("fhrp", "virtual MAC", Severity.REVIEW, "fhrp-mac",
                            f"EOS takes one virtual-router MAC; {macs[0]} written, {', '.join(macs[1:])} left out")
        elif anycast and not macs:
            self.report.add("fhrp", "virtual MAC", Severity.REVIEW, "fhrp-mac",
                            "the source has no anycast MAC; add 'ip virtual-router mac-address'")

    def _fhrp(self, iface: Interface, name: str) -> List[str]:
        lines: List[str] = []
        groups = self.groups.get(iface.name, [])
        hsrp = [g for g in groups if g.protocol == "hsrp"]
        if any(g.version == 2 or g.group > 255 for g in hsrp):
            lines.append("standby version 2")
        for group in groups:
            add = fhrp.adder(self.report, name, group)
            if group.protocol == "hsrp":
                lines += self._hsrp(group, add)
            elif group.protocol == "anycast":
                lines += [f"ip virtual-router address {a}" for a in [group.address] + group.secondary]
            elif self.vrrp_v3:
                lines += self._vrrp_v3(group)
            else:
                lines += self._vrrp(group, add)
        return lines

    @staticmethod
    def _ms(ms: int) -> str:
        return f"msec {ms}" if ms % 1000 else str(ms // 1000)

    def _hsrp(self, g: FhrpGroup, add: fhrp.Add) -> List[str]:
        pre = f"standby {g.group}"
        lines = [f"{pre} ip {g.address}"] + [f"{pre} ip {a} secondary" for a in g.secondary]
        if g.priority is not None:
            lines.append(f"{pre} priority {g.priority}")
        if g.preempts():
            lines.append(f"{pre} preempt")
        if g.hello_ms is not None:
            hold = g.hold_ms if g.hold_ms is not None else 3 * g.hello_ms
            lines.append(f"{pre} timers {self._ms(g.hello_ms)} {self._ms(hold)}")
        if g.name:
            lines.append(f"{pre} name {g.name.replace(' ', '_')}")
        if g.shutdown:
            lines.append(f"{pre} shutdown")
        return lines

    def _vrrp(self, g: FhrpGroup, add: fhrp.Add) -> List[str]:
        pre = f"vrrp {g.group}"
        family = "ip" if self.ios else "ipv4"
        lines = [f"{pre} {family} {g.address}"] + [f"{pre} {family} {a} secondary" for a in g.secondary]
        if g.priority is not None:
            lines.append(f"{pre} priority {g.priority}" if self.ios else f"{pre} priority-level {g.priority}")
        if not g.preempts():
            lines.append(f"no {pre} preempt")
        if g.hello_ms is not None:
            if self.ios:
                lines.append(f"{pre} timers advertise {self._ms(g.hello_ms)}")
            else:
                lines.append(f"{pre} advertisement interval {fhrp.interval(g.hello_ms, 1000, add, 1, 255)}")
        if g.version == 3:
            if self.ios:
                add(Severity.APPROX, "fhrp-version", "VRRPv3 written as VRRPv2")
            else:
                lines.append(f"{pre} ipv4 version 3")
        if g.name:
            lines.append(f"{pre} description {g.name}" if self.ios else f"{pre} session description {g.name}")
        if g.shutdown:
            lines.append(f"{pre} shutdown" if self.ios else f"{pre} disabled")
        return lines

    def _vrrp_v3(self, g: FhrpGroup) -> List[str]:
        body = [f"address {g.address} primary"] + [f"address {a} secondary" for a in g.secondary]
        if g.priority is not None:
            body.append(f"priority {g.priority}")
        if not g.preempts():
            body.append("no preempt")
        if g.hello_ms is not None:
            body.append(f"timers advertise {g.hello_ms}")
        if g.version != 3:
            body.append("vrrpv2")
        if g.name:
            body.append(f"description {g.name}")
        if g.shutdown:
            body.append("shutdown")
        return [f"vrrp {g.group} address-family ipv4"] + [f"{self.ind}{line}" for line in body] + [
            f"{self.ind}exit-vrrp"]

    # access lists ----------------------------------------------------------------------------------------------------

    def acls(self) -> None:
        for acl in self.device.acls.values():
            name = acl_text.safe_name(acl.name)
            label = acl.name if name == acl.name else f"{acl.name} -> {name}"
            self.report.item("acl", label)
            if acl.family == 6:
                self.out.append(f"ipv6 access-list {name}")
            else:
                self.out.append(f"ip access-list extended {name}" if self.ios else f"ip access-list {name}")
            style = "wildcard" if self.ios and acl.family == 4 else "prefix"
            for seq, entry, src, dst in acl_text.numbered(acl):
                if entry.unsupported:
                    seq_word = "" if self.ios else f"{seq} "
                    self.out.append(f"{self.ind}{seq_word}remark RouterShift could not convert: {entry.unsupported}")
                    self.report.add("acl", label, Severity.REVIEW, "acl-entry",
                                    f"entry '{entry.unsupported}' not converted; its place is marked by a remark")
                    continue
                words = acl_text.cisco_entry(entry, acl.family, src, dst, style,
                                             any_protocol="ipv6" if acl.family == 6 else "ip",
                                             icmp6="icmp" if self.ios else "icmpv6", icmp_names=True)
                if self.ios and entry.action == AclAction.REMARK:
                    self.out.append(f"{self.ind}{' '.join(words)}")
                elif self.ios and acl.family == 6:
                    self.out.append(f"{self.ind}sequence {seq} {' '.join(words)}")
                else:
                    self.out.append(f"{self.ind}{seq} {' '.join(words)}")
            self.out.append("!")

    # routing ---------------------------------------------------------------------------------------------------------

    def routing(self) -> None:
        l3 = any(i.ipv4 or i.dhcp_client for i in self.device.interfaces.values() if i.kind != InterfaceKind.MANAGEMENT)
        v6 = any(i.ipv6 for i in self.device.interfaces.values()) or any(
            ":" in r.prefix for r in self.device.static_routes)
        if l3 or self.device.static_routes:
            self.out.append("ip routing")
            if not self.ios:
                for vrf in self.device.vrfs:
                    self.out.append(f"ip routing vrf {self.vrf(vrf)}")
        if v6:
            self.out.append("ipv6 unicast-routing")
        for route in self.device.static_routes:
            self.out.append(self._route(route))
        self.out.append("!")

    def _route(self, route: StaticRoute) -> str:
        net = ipaddress.ip_network(route.prefix)
        family = "ip" if net.version == 4 else "ipv6"
        words = [family, "route"]
        if route.vrf:
            words += ["vrf", self.vrf(route.vrf)]
        if net.version == 4 and self.ios:
            words += [str(net.network_address), str(net.netmask)]
        else:
            words.append(str(net))
        if route.discard:
            words.append("Null0")
        else:
            if route.interface:
                words.append(self.port(route.interface))
            if route.next_hop:
                words.append(route.next_hop)
        if route.distance is not None:
            words.append(str(route.distance))
        if route.name:
            words += ["name", route.name.replace(" ", "_")]  # one word
        self.report.item("route", f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}")
        return " ".join(words)

    # services --------------------------------------------------------------------------------------------------------

    def services(self) -> None:
        s = self.device.system
        vrf = self.vrf(s.service_vrf) if s.service_vrf else ""
        for server in s.ntp_servers:
            self.out.append(f"ntp server vrf {vrf} {server}" if vrf else f"ntp server {server}")
        if s.ntp_servers:
            self.report.item("system", "ntp servers")
        for host in s.syslog_servers:
            if not vrf:
                self.out.append(f"logging host {host}")
            else:
                self.out.append(f"logging host {host} vrf {vrf}" if self.ios else f"logging vrf {vrf} host {host}")
        if s.syslog_servers:
            self.report.item("system", "syslog servers")
        if s.timezone:
            self._timezone(s.timezone)
        self.out.append("!")

    def _timezone(self, tz: str) -> None:
        words = tz.split()
        ios_style = len(words) >= 2 and words[1].lstrip("-").isdigit()
        tz_database = "/" in tz or tz.upper() == "UTC"
        if self.ios and ios_style or not self.ios and tz_database:
            if not self.ios and "/" in tz:  # tz database names are capitalised on EOS: America/New_York
                tz = "/".join("_".join(p[:1].upper() + p[1:] for p in part.split("_")) for part in tz.split("/"))
            self.out.append(f"clock timezone {tz}")
            self.report.item("system", "time zone")
            return
        minutes = offset_minutes(tz)
        if self.ios and minutes is not None:
            sign = "-" if minutes < 0 else ""
            self.out.append(f"clock timezone UTC {sign}{abs(minutes) // 60} {abs(minutes) % 60}")
            self.report.add("system", "time zone", Severity.APPROX, "timezone",
                            f"time zone '{tz}' written as a fixed offset; add 'clock summer-time' if it has one")
            return
        self.report.add("system", "time zone", Severity.REVIEW, "timezone",
                        f"time zone '{tz}' cannot be translated reliably (IOS takes a name and an offset, EOS a "
                        "zone of the tz database); set it by hand")

    def banner(self) -> None:
        text = self.device.system.banner_motd
        if not text:
            return
        if self.ios:
            delim = "^C" if "^C" not in text else "%"
            self.out += [f"banner motd {delim}", text, delim]
        else:
            self.out += ["banner motd", text, "EOF"]
        self.report.item("system", "banner motd")

    def unparsed(self) -> None:
        self.report.unparsed(self.device.unparsed)


def emit(device: Device, target: str, ports: PortMapper, report: Report) -> str:
    return Writer(device, target, ports, report).emit()
