# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for Cisco IOS / IOS XE and Arista EOS: one class, the dialect picks the spelling."""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List

from .. import acl as acl_text
from .. import bgp as bgp_text
from .. import dhcp as dhcp_text
from .. import fhrp
from .. import nat as nat_text
from .. import ospf as ospf_text
from .. import snmp as snmp_text
from .. import vpn as vpn_text
from ..model import (AclAction, Bgp, BgpNeighbor, Device, DhcpPool, IkePolicy, IpsecPeer, NatRule, SnmpGroup, FhrpGroup, Interface, InterfaceKind, LacpMode, Ospf,
                     StaticRoute, StpMode, SwitchportMode)
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
        self.nat_outside: Dict[str, List[NatRule]] = {}
        for rule in self.device.nat_rules:
            if nat_text.needs_acl(rule):
                continue
            for name in nat_text.outside(self.device, rule):
                self.nat_outside.setdefault(name, []).append(rule)
        self.system()
        self.spanning_tree()
        self.vrfs()
        self.vlans()
        self.vpn()
        for iface in self.device.interfaces.values():
            self.interface(iface)
        self.routing()
        self.acls()
        self.nat()
        self.dhcp()
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
        lines += self._nat_interface(iface)
        lines += self._tunnel(iface, add)
        lines += self._ospf_interface(iface)
        if not self.ios and any(self._serves(pool, iface) for pool in self.device.dhcp_pools):
            lines.append("dhcp server ipv4")
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

    # NAT --------------------------------------------------------------------------------------------------------------

    def _nat_interface(self, iface: Interface) -> List[str]:
        if self.ios:
            side = iface.nat or ("outside" if iface.name in self.nat_outside else "")
            return [f"ip nat {side}"] if side else []
        lines = []
        for rule in self.nat_outside.get(iface.name, []):
            label = nat_text.label(rule)
            acl = acl_text.safe_name(rule.acl)
            if rule.kind == "dynamic" and rule.pool:
                lines.append(f"ip nat source dynamic access-list {acl} pool {rule.pool}" +
                             (" overload" if rule.overload else ""))
            elif rule.kind == "dynamic":
                lines.append(f"ip nat source dynamic access-list {acl} overload")
            elif rule.protocol:
                self.report.skip("nat", label, "nat-port",
                                 "static port forwarding is not written for EOS; add 'ip nat source static' by hand")
            else:
                lines.append(f"ip nat source static {rule.local} {rule.translated}")
        return lines

    def nat(self) -> None:
        for pool in self.device.nat_pools.values():
            if not pool.prefix_len:
                self.report.add("nat", f"pool {pool.name}", Severity.REVIEW, "nat-mask",
                                "the source gives no mask for the pool; /24 is written, check it")
            self.out.append(f"ip nat pool {pool.name} {pool.first} {pool.last} prefix-length {pool.prefix_len or 24}")
        for rule in self.device.nat_rules:
            label = nat_text.label(rule)
            if nat_text.needs_acl(rule):
                self.report.skip("nat", label, "nat-acl", "the rule translates every source; write an ACL for the "
                                 "inside networks and add the rule by hand")
                continue
            self.report.item("nat", label)
            if rule.acl and rule.acl not in self.device.acls:
                self.report.add("nat", label, Severity.REVIEW, "acl-missing", f"ACL {rule.acl} is not defined")
            if not nat_text.outside(self.device, rule):
                self.report.add("nat", label, Severity.REVIEW, "nat-outside",
                                "no outside interface is marked; the rule has nowhere to apply")
            if self.ios:
                self.out.append(self._ios_nat(rule))
        if self.ios and nat_text.inside_unknown(self.device):
            self.report.add("nat", "inside interfaces", Severity.REVIEW, "nat-inside",
                            "the source does not mark inside interfaces; add 'ip nat inside' to them")
        if self.device.nat_rules or self.device.nat_pools:
            self.out.append("!")

    def _ios_nat(self, rule: NatRule) -> str:
        vrf = f" vrf {self.vrf(rule.vrf)}" if rule.vrf else ""
        if rule.kind == "static":
            if rule.protocol:
                return (f"ip nat inside source static {rule.protocol} {rule.local} {rule.local_port} "
                        f"{rule.translated} {rule.translated_port}{vrf}")
            return f"ip nat inside source static {rule.local} {rule.translated}{vrf}"
        acl = acl_text.safe_name(rule.acl)
        if rule.pool:
            return f"ip nat inside source list {acl} pool {rule.pool}" + (" overload" if rule.overload else "") + vrf
        outside = nat_text.outside(self.device, rule)
        if len(outside) > 1:
            self.report.add("nat", nat_text.label(rule), Severity.REVIEW, "nat-outside",
                            f"IOS overloads onto one interface; {self.port(outside[0])} is used, not "
                            + ", ".join(self.port(n) for n in outside[1:]))
        where = self.port(outside[0]) if outside else "OUTSIDE-INTERFACE"
        return f"ip nat inside source list {acl} interface {where} overload{vrf}"

    # IPsec ------------------------------------------------------------------------------------------------------------

    def _tunnel(self, iface: Interface, add: _Add) -> List[str]:
        lines = []
        if iface.crypto_map and self.ios:
            lines.append(f"crypto map {iface.crypto_map}")
        elif iface.crypto_map:
            add(Severity.REVIEW, "vpn-crypto-map", f"crypto map {iface.crypto_map} not applied: EOS has no crypto maps")
        if iface.kind != InterfaceKind.TUNNEL:
            return lines
        if not self.ios and iface.tunnel_mode:
            lines.append(f"tunnel mode {iface.tunnel_mode}")
        if iface.tunnel_source:
            source = iface.tunnel_source
            if not vpn_text.is_address(source):
                source = self.port(source) if self.ios else f"interface {self.port(source)}"
            lines.append(f"tunnel source {source}")
        if iface.tunnel_destination:
            lines.append(f"tunnel destination {iface.tunnel_destination}")
        if self.ios and iface.tunnel_mode == "ipsec":
            lines.append("tunnel mode ipsec ipv4")
        if iface.tunnel_profile:
            lines.append(f"tunnel {'protection ' if self.ios else ''}ipsec profile {iface.tunnel_profile}")
        return lines

    def vpn(self) -> None:
        if not vpn_text.has_vpn(self.device):
            return
        for policy in self.device.ike_policies.values():
            label = vpn_text.policy_label(policy)
            self.report.item("vpn", label)
            if policy.authentication != "pre-share":
                self.report.add("vpn", label, Severity.REVIEW, "vpn-auth",
                                f"authentication {policy.authentication} is not converted; pre-shared keys are written")
        if self.ios:
            self._ios_vpn()
        else:
            self._eos_vpn()

    def _ios_vpn(self) -> None:
        peers = self.device.ipsec_peers
        v1 = [p for p in self.device.ike_policies.values() if p.version == 1]
        v2 = [p for p in self.device.ike_policies.values() if p.version == 2]
        priorities = {p.name: p.name if p.name.isdigit() else str(10 * (n + 1)) for n, p in enumerate(v1)}
        for policy in v1:
            label = vpn_text.policy_label(policy)
            if priorities[policy.name] != policy.name:
                self.report.add("vpn", label, Severity.APPROX, "vpn-renumbered",
                                f"written as ISAKMP policy {priorities[policy.name]}; IOS numbers its policies")
            self.out.append(f"crypto isakmp policy {priorities[policy.name]}")
            self.out += [self.ind + line for line in self._ios_ike_lines(policy, label)]
            self.out.append("!")
        for address in sorted({a for p in peers if p.ike_version == 1 for a in vpn_text.peers_of(self.device, p)}):
            key = vpn_text.key_for(self.device, address, self.report, f"IKEv1 key {address}")
            self.out.append(f"crypto isakmp key {key} address {address}")
        v2_peers = [p for p in peers if p.ike_version == 2]
        if v2_peers:
            for policy in v2:
                self.out.append(f"crypto ikev2 proposal {policy.name}")
                self.out += [self.ind + line for line in self._ios_ike_lines(policy, vpn_text.policy_label(policy))]
                self.out.append("!")
            if v2:
                self.out.append("crypto ikev2 policy IKEV2-POLICY")
                self.out += [f"{self.ind}proposal {policy.name}" for policy in v2]
                self.out.append("!")
            addresses = sorted({a for p in v2_peers for a in vpn_text.peers_of(self.device, p)})
            if addresses:
                self.out.append("crypto ikev2 keyring IKEV2-KEYS")
                for address in addresses:
                    key = vpn_text.key_for(self.device, address, self.report, f"IKEv2 key {address}")
                    self.out += [f"{self.ind}peer {address}", f"{self.ind * 2}address {address}",
                                 f"{self.ind * 2}pre-shared-key {key}"]
                self.out.append("!")
            lifetime = next((p.lifetime for p in v2 if p.lifetime), None)
            for p in v2_peers:
                self.out.append(f"crypto ikev2 profile {self._ikev2_profile(p)}")
                self.out += [f"{self.ind}match identity remote address {a} 255.255.255.255"
                             for a in vpn_text.peers_of(self.device, p)]
                self.out += [f"{self.ind}authentication remote pre-share", f"{self.ind}authentication local pre-share",
                             f"{self.ind}keyring local IKEV2-KEYS"]
                if lifetime:
                    self.out.append(f"{self.ind}lifetime {lifetime}")
                self.out.append("!")
        for transform in self.device.ipsec_transforms.values():
            label = f"transform {transform.name}"
            self.report.item("vpn", label)
            words = [vpn_text.pick(vpn_text.IOS_ESP_ENC, transform.encryption, self.report, label)]
            if transform.integrity:
                words.append(vpn_text.pick(vpn_text.IOS_ESP_INT, transform.integrity, self.report, label))
            self.out.append(f"crypto ipsec transform-set {transform.name} {' '.join(words)}")
            self.out += [f"{self.ind}mode {transform.mode}", "!"]
        for p in peers:
            label = vpn_text.peer_label(p)
            self.report.item("vpn", label)
            self._check_peer(p, label)
            self.out.append(f"crypto ipsec profile {p.name}" if p.profile else f"crypto map {p.name} {p.seq} ipsec-isakmp")
            lines = [f"set peer {p.peer}"] if p.peer else []
            if p.transforms:
                lines.append("set transform-set " + " ".join(p.transforms))
            if p.pfs_group:
                lines.append(f"set pfs group{p.pfs_group}")
            if p.lifetime is not None:
                lines.append(f"set security-association lifetime seconds {p.lifetime}")
            if p.ike_version == 2:
                lines.append(f"set ikev2-profile {self._ikev2_profile(p)}")
            if p.acl:
                lines.append(f"match address {acl_text.safe_name(p.acl)}")
            self.out += [self.ind + line for line in lines]
            self.out.append("!")

    @staticmethod
    def _ikev2_profile(p: IpsecPeer) -> str:
        return f"IKEV2-{p.name}" + (f"-{p.seq}" if not p.profile else "")

    def _ios_ike_lines(self, policy: IkePolicy, label: str) -> List[str]:
        lines = []
        if policy.version == 1:
            for attr in ("encryption", "integrity", "dh_groups"):
                if len(getattr(policy, attr)) > 1:
                    self.report.add("vpn", label, Severity.APPROX, "vpn-one-algorithm",
                                    f"an ISAKMP policy takes one {attr.replace('_', ' ')}; the first is written")
            if policy.encryption:
                lines.append("encryption " + vpn_text.pick(vpn_text.IOS_ISAKMP_ENC, policy.encryption[0],
                                                           self.report, label))
            if policy.integrity:
                lines.append("hash " + vpn_text.pick(vpn_text.IOS_HASH, policy.integrity[0], self.report, label))
            lines.append("authentication pre-share")
            if policy.dh_groups:
                lines.append(f"group {policy.dh_groups[0]}")
            if policy.lifetime is not None:
                lines.append(f"lifetime {policy.lifetime}")
            return lines
        if policy.encryption:
            lines.append("encryption " + " ".join(vpn_text.pick(vpn_text.IOS_IKEV2_ENC, e, self.report, label)
                                                  for e in policy.encryption))
        if policy.integrity:
            lines.append("integrity " + " ".join(vpn_text.pick(vpn_text.IOS_IKEV2_INT, i, self.report, label)
                                                 for i in policy.integrity))
        if policy.dh_groups:
            lines.append("group " + " ".join(str(g) for g in policy.dh_groups))
        return lines

    def _check_peer(self, p: IpsecPeer, label: str) -> None:
        if p.acl and p.acl not in self.device.acls:
            self.report.add("vpn", label, Severity.REVIEW, "acl-missing", f"ACL {p.acl} is not defined")
        missing = [t for t in p.transforms if t not in self.device.ipsec_transforms]
        if missing:
            self.report.add("vpn", label, Severity.REVIEW, "vpn-transform",
                            "transform " + ", ".join(missing) + " is not defined")
        if not vpn_text.policies_for(self.device, p):
            self.report.add("vpn", label, Severity.REVIEW, "vpn-ike",
                            f"no IKEv{p.ike_version} proposal is defined for it")

    def _eos_vpn(self) -> None:
        lines: List[str] = []
        for policy in self.device.ike_policies.values():
            label = vpn_text.policy_label(policy)
            lines.append(f"ike policy {policy.name}")
            if policy.version == 1:
                lines.append(f"{self.ind}version 1")
            for attr in ("encryption", "integrity", "dh_groups"):
                if len(getattr(policy, attr)) > 1:
                    self.report.add("vpn", label, Severity.APPROX, "vpn-one-algorithm",
                                    f"an EOS IKE policy takes one {attr.replace('_', ' ')}; the first is written")
            if policy.encryption:
                lines.append(f"{self.ind}encryption " + vpn_text.pick(vpn_text.EOS_ENC, policy.encryption[0],
                                                                      self.report, label))
            if policy.integrity:
                lines.append(f"{self.ind}integrity " + vpn_text.pick(vpn_text.EOS_INT, policy.integrity[0],
                                                                     self.report, label))
            if policy.dh_groups:
                lines.append(f"{self.ind}dh-group {policy.dh_groups[0]}")
            hours = vpn_text.lifetime_hours(policy.lifetime)
            if hours is not None:
                if hours * 3600 != policy.lifetime:
                    self.report.add("vpn", label, Severity.APPROX, "vpn-lifetime",
                                    f"lifetime rounded to {hours} hours, as EOS counts in hours")
                lines.append(f"{self.ind}ike-lifetime {hours}")
        profiles = [p for p in self.device.ipsec_peers if p.profile]
        for p in self.device.ipsec_peers:
            if not p.profile:
                self.report.skip("vpn", vpn_text.peer_label(p), "vpn-crypto-map",
                                 "EOS protects traffic on tunnel interfaces only; build a tunnel interface with an "
                                 "IPsec profile for this peer")
        sa_names: Dict[str, str] = {}
        for transform in self.device.ipsec_transforms.values():
            users = [p for p in profiles if p.transforms[:1] == [transform.name]]
            settings = {(p.pfs_group, p.lifetime) for p in users}
            for p in users:
                sa_names[p.name] = transform.name if len(settings) == 1 else f"{transform.name}-{p.name}"
            for name, p in {sa_names[p.name]: p for p in users}.items():
                label = f"transform {transform.name}"
                self.report.item("vpn", label)
                lines.append(f"sa policy {name}")
                lines.append(f"{self.ind}esp encryption " + vpn_text.pick(vpn_text.EOS_ESP_ENC, transform.encryption,
                                                                          self.report, label))
                if transform.integrity:
                    lines.append(f"{self.ind}esp integrity " + vpn_text.pick(vpn_text.EOS_INT, transform.integrity,
                                                                             self.report, label))
                if p.pfs_group:
                    lines.append(f"{self.ind}pfs dh-group {p.pfs_group}")
                hours = vpn_text.lifetime_hours(p.lifetime)
                if hours is not None:
                    if hours * 3600 != p.lifetime:
                        self.report.add("vpn", label, Severity.APPROX, "vpn-lifetime",
                                        f"SA lifetime rounded to {hours} hours, as EOS counts in hours")
                    lines.append(f"{self.ind}sa lifetime {hours} hours")
                if transform.mode != "tunnel":
                    self.report.add("vpn", label, Severity.REVIEW, "vpn-mode",
                                    f"{transform.mode} mode is not written; EOS runs tunnel mode")
        for p in profiles:
            label = vpn_text.peer_label(p)
            self.report.item("vpn", label)
            self._check_peer(p, label)
            lines.append(f"profile {p.name}")
            policies = vpn_text.policies_for(self.device, p)
            if len(policies) > 1:
                self.report.add("vpn", label, Severity.APPROX, "vpn-one-policy",
                                f"an EOS profile takes one IKE policy; {policies[0].name} is written")
            if policies:
                lines.append(f"{self.ind}ike-policy {policies[0].name}")
            if len(p.transforms) > 1:
                self.report.add("vpn", label, Severity.APPROX, "vpn-one-transform",
                                f"an EOS profile takes one SA policy; {p.transforms[0]} is written")
            if p.name in sa_names:
                lines.append(f"{self.ind}sa-policy {sa_names[p.name]}")
            lines.append(f"{self.ind}connection start")
            addresses = vpn_text.peers_of(self.device, p)
            keys = {vpn_text.key_for(self.device, a, self.report, label) for a in addresses}
            if len(keys) > 1:
                self.report.add("vpn", label, Severity.REVIEW, "vpn-key",
                                "the tunnels using this profile have different keys; one profile per key is needed")
            key = sorted(keys)[0] if keys else vpn_text.key_for(self.device, "", self.report, label)
            lines.append(f"{self.ind}shared-key {key}")
        if lines:
            self.out.append("ip security")
            self.out += [self.ind + line for line in lines]
            self.out.append("!")

    # DHCP server ------------------------------------------------------------------------------------------------------

    @staticmethod
    def _serves(pool: DhcpPool, iface: Interface) -> bool:
        return bool(pool.network) and pool.vrf == iface.vrf and any(
            ipaddress.ip_interface(a).ip in ipaddress.ip_network(pool.network) for a in iface.ipv4)

    def dhcp(self) -> None:
        if self.ios:
            for pool in self.device.dhcp_pools:
                self._ios_pool(pool)
            return
        for vrf in sorted({p.vrf for p in self.device.dhcp_pools}):
            pools = [p for p in self.device.dhcp_pools if p.vrf == vrf]
            self.out.append("dhcp server" + (f" vrf {self.vrf(vrf)}" if vrf else ""))
            domains = [p.domain_name for p in pools if p.domain_name]
            if domains:
                self.out.append(f"{self.ind}dns domain name ipv4 {domains[0]}")
            for pool in pools:
                self._eos_subnet(pool, domains[0] if domains else "")
            self.out.append("!")

    def _ios_pool(self, pool: DhcpPool) -> None:
        label = dhcp_text.label(pool)
        if not pool.network:
            self.report.skip("dhcp", label, "dhcp-network", "a pool without a network (a host binding) is not written")
            return
        self.report.item("dhcp", label)
        vrf = f"vrf {self.vrf(pool.vrf)} " if pool.vrf else ""
        for first, last in dhcp_text.exclusions(pool):
            self.out.append(f"ip dhcp excluded-address {vrf}{first}" + (f" {last}" if last != first else ""))
        self.out.append(f"ip dhcp pool {pool.name.replace(' ', '_')}")
        lines: List[str] = []
        if pool.vrf:
            lines.append(f"vrf {self.vrf(pool.vrf)}")
        if pool.network:
            net = ipaddress.ip_network(pool.network)
            lines.append(f"network {net.network_address} {net.netmask}")
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
            lines.append(f"lease {days} {hours} {minutes}")
        self.out += [self.ind + line for line in lines]
        self.out.append("!")

    def _eos_subnet(self, pool: DhcpPool, domain: str) -> None:
        label = dhcp_text.label(pool)
        self.report.item("dhcp", label)

        def add(severity: Severity, code: str, message: str) -> None:
            self.report.add("dhcp", label, severity, code, message)

        if not pool.network:
            self.report.skip("dhcp", label, "dhcp-network", "a pool without a network (a host binding) is not written")
            return
        lines = [f"name {pool.name.replace(' ', '_')}"]
        lines += [f"range {first} {last}" for first, last in pool.ranges]
        lines += [f"default-gateway {router}" for router in pool.default_routers[:1]]
        if len(pool.default_routers) > 1:
            add(Severity.APPROX, "dhcp-router", "EOS hands out one gateway; the others are left out")
        if pool.dns_servers:
            lines.append("dns server " + " ".join(pool.dns_servers))
        if pool.domain_name and pool.domain_name != domain:
            add(Severity.APPROX, "dhcp-domain", f"EOS takes one domain name per VRF; {domain} is handed out")
        if pool.lease_seconds == 0:
            add(Severity.APPROX, "dhcp-lease", "an infinite lease is written as 2000 days; check the EOS release takes it")
            lines.append("lease time 2000 days 0 hours 0 minutes")
        elif pool.lease_seconds is not None:
            days, hours, minutes = dhcp_text.lease_parts(pool.lease_seconds)
            lines.append(f"lease time {days} days {hours} hours {minutes} minutes")
        self.out.append(f"{self.ind}subnet {pool.network}")
        self.out += [self.ind * 2 + line for line in lines]

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
        for p in self.device.ospf:
            self.ospf(p)
        if self.device.bgp is not None:
            self.bgp(self.device.bgp)

    def _area(self, dotted: str) -> str:
        return ospf_text.area_number(dotted) if self.ios else dotted

    def _ospf_interface(self, iface: Interface) -> List[str]:
        lines = []
        for p in self.device.ospf:
            if iface.name in p.interface_areas:
                area = self._area(p.interface_areas[iface.name])
                lines.append(f"ip ospf {p.process} area {area}" if self.ios else f"ip ospf area {area}")
        if iface.ospf_cost is not None:
            lines.append(f"ip ospf cost {iface.ospf_cost}")
        if iface.ospf_network:
            lines.append(f"ip ospf network {iface.ospf_network}")
        return lines

    def ospf(self, p: Ospf) -> None:
        label = ospf_text.label(p)
        self.report.item("ospf", label)
        header = f"router ospf {p.process}" + (f" vrf {self.vrf(p.vrf)}" if p.vrf else "")
        lines: List[str] = []
        if p.router_id:
            lines.append(f"router-id {p.router_id}")
        if p.reference_bandwidth is not None:
            lines.append(f"auto-cost reference-bandwidth {p.reference_bandwidth}")
        if p.passive_default:
            lines.append("passive-interface default")
            lines += [f"no passive-interface {self.port(n)}" for n in p.active_interfaces]
        else:
            lines += [f"passive-interface {self.port(n)}" for n in p.passive_interfaces]
        for network in p.networks:
            net = ipaddress.ip_network(network.prefix)
            where = f"{net.network_address} {net.hostmask}" if self.ios else str(net)
            lines.append(f"network {where} area {self._area(network.area)}")
        for area, kind in p.area_types.items():
            lines.append(f"area {self._area(area)} {kind}")
        for source in p.redistribute:
            if source == "bgp":
                if self.device.bgp is None:
                    self.report.add("ospf", label, Severity.REVIEW, "ospf-redistribute",
                                    "redistribution of BGP left out: there is no BGP process")
                    continue
                source = f"bgp {self.device.bgp.local_as}" if self.ios else "bgp"
            lines.append(f"redistribute {source}" + (" subnets" if self.ios else ""))
        if p.default_originate:
            lines.append("default-information originate" + (" always" if p.default_originate == "always" else ""))
        self.out.append(header)
        self.out += [self.ind + line for line in lines]
        self.out.append("!")

    def bgp(self, bgp: Bgp) -> None:
        self.report.item("bgp", f"bgp {bgp.local_as}")
        ind = self.ind
        lines: List[str] = []
        if bgp.router_id:
            lines.append(f"bgp router-id {bgp.router_id}" if self.ios else f"router-id {bgp.router_id}")
        lines.append("no bgp default ipv4-unicast")  # every neighbor is activated where it belongs
        for group in bgp.peer_groups.values():
            lines.append(f"neighbor {group.address} {'peer-group' if self.ios else 'peer group'}")
            lines += self._bgp_neighbor(group)
        for neighbor in bgp.neighbors:
            self.report.item("bgp", f"neighbor {neighbor.address}")
            if neighbor.peer_group:
                word = "peer-group" if self.ios else "peer group"
                lines.append(f"neighbor {neighbor.address} {word} {neighbor.peer_group}")
            lines += self._bgp_neighbor(neighbor)
        if not self.ios:
            for peer in list(bgp.peer_groups.values()) + bgp.neighbors:
                lines += self._bgp_af_options(peer)
        for af in ("ipv4", "ipv6"):
            body: List[str] = []
            for prefix in bgp.networks:
                net = ipaddress.ip_network(prefix)
                if (net.version == 6) != (af == "ipv6"):
                    continue
                if self.ios and net.version == 4:
                    body.append(f"network {net.network_address} mask {net.netmask}")
                else:
                    body.append(f"network {net}")
            for source in bgp.redistribute6 if af == "ipv6" else bgp.redistribute:
                body.append(self._bgp_redistribute(source))
            for group in bgp.peer_groups.values():  # IOS takes a group's options per address family
                if self.ios and any(af in n.families for n in bgp.neighbors if n.peer_group == group.address):
                    body += self._bgp_af_options(group)
            for peer in bgp.neighbors:
                if af in peer.families:
                    body.append(f"neighbor {peer.address} activate")
                    if self.ios:
                        body += self._bgp_af_options(peer)
            if not body:
                continue
            lines.append(f"address-family {af}" + (" unicast" if self.ios else ""))
            lines += [ind + line for line in body]
            if self.ios:
                lines.append("exit-address-family")
        self.out.append(f"router bgp {bgp.local_as}")
        self.out += [ind + line for line in lines]
        self.out.append("!")

    def _bgp_neighbor(self, peer: BgpNeighbor) -> List[str]:
        pre = f"neighbor {peer.address}"
        lines = []
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
        return lines

    @staticmethod
    def _bgp_af_options(peer: BgpNeighbor) -> List[str]:
        lines = []
        if peer.next_hop_self:
            lines.append(f"neighbor {peer.address} next-hop-self")
        if peer.send_community:
            lines.append(f"neighbor {peer.address} send-community")
        return lines

    def _bgp_redistribute(self, source: str) -> str:
        if source == "ospf" and self.ios:
            return f"redistribute ospf {self.device.ospf[0].process if self.device.ospf else 1}"
        return f"redistribute {source}"

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

    _NTP_ALGORITHMS = {"ios": {"md5": "md5", "sha1": "hmac-sha1", "sha256": "hmac-sha2-256"},
                       "eos": {"md5": "md5", "sha1": "sha1"}}

    def _ntp(self, vrf: str) -> None:
        s = self.device.system
        for key in s.ntp_keys.values():
            label = f"ntp key {key.number}"
            self.report.item("system", label)
            algorithms = self._NTP_ALGORITHMS[self.target]
            algorithm = algorithms.get(key.algorithm)
            if algorithm is None:
                algorithm = algorithms["sha1"]
                self.report.add("system", label, Severity.REVIEW, "ntp-algorithm",
                                f"{key.algorithm} is not offered; sha1 is written, so the servers must use it too")
            self.out.append(f"ntp authentication-key {key.number} {algorithm} {snmp_text.ntp_key(key, self.report)}")
            if key.trusted:
                self.out.append(f"ntp trusted-key {key.number}")
        if s.ntp_authenticate:
            self.out.append("ntp authenticate")
        if s.ntp_source and s.ntp_servers:
            self.out.append(f"ntp {'source' if self.ios else 'local-interface'} {self.port(s.ntp_source)}")
        for server in s.ntp_servers:
            words = ["ntp server"] + (["vrf", vrf] if vrf else []) + [server]
            if server in s.ntp_server_keys:
                words += ["key", str(s.ntp_server_keys[server])]
            if server == s.ntp_prefer:
                words.append("prefer")
            self.out.append(" ".join(words))
        if s.ntp_servers:
            self.report.item("system", "ntp servers")

    _SNMP_AUTH = {"ios": ["md5", "sha", "sha256"], "eos": ["md5", "sha", "sha256", "sha384", "sha512"]}
    _SNMP_PRIV = {"ios": ["des", "3des", "aes128", "aes192", "aes256"], "eos": ["des", "aes128", "aes192", "aes256"]}

    def _snmp(self) -> None:
        s = self.device.snmp
        rep = self.report
        for c in s.communities:
            label = snmp_text.community_label(self.device, c)
            rep.item("management", label)
            name = snmp_text.secret(c.name, rep, "management", label, "community")
            words = ["snmp-server community", name, c.access.upper() if self.ios else c.access]
            if c.acl and c.acl in self.device.acls:
                words.append(acl_text.safe_name(c.acl))
            elif c.acl:
                rep.add("management", label, Severity.REVIEW, "acl-missing", f"ACL {c.acl} is not defined; left out")
            self.out.append(" ".join(words))
        if s.location:
            self.out.append(f"snmp-server location {s.location}")
            rep.item("management", "snmp location")
        if s.contact:
            self.out.append(f"snmp-server contact {s.contact}")
            rep.item("management", "snmp contact")
        groups = dict(s.groups)
        for u in s.users:
            if u.group not in groups:
                groups[u.group or u.name] = SnmpGroup(u.group or u.name, snmp_text.level(u))
        for g in groups.values():
            words = [f"snmp-server group {g.name} v3 {g.level}"]
            words += [f"read {g.read_view}"] if g.read_view else []
            words += [f"write {g.write_view}"] if g.write_view else []
            if g.read_view or g.write_view:
                rep.add("management", f"SNMPv3 group {g.name}", Severity.REVIEW, "snmp-view",
                        "MIB views are not converted; define them by hand")
            rep.item("management", f"SNMPv3 group {g.name}")
            self.out.append(" ".join(words))
        for u in s.users:
            label = snmp_text.user_label(u)
            rep.item("management", label)
            keys = snmp_text.user_keys(u, rep)
            words = [f"snmp-server user {u.name} {u.group or u.name} v3"]
            if u.auth:
                auth = snmp_text.pick(u.auth, self._SNMP_AUTH[self.target], rep, label)
                words.append(f"auth {'sha-2 256' if self.ios and auth == 'sha256' else auth} {keys[0]}")
            if u.priv:
                priv = snmp_text.pick(u.priv, self._SNMP_PRIV[self.target], rep, label)
                if priv.startswith("aes"):
                    priv = f"aes {priv[3:]}" if self.ios else "aes" if priv == "aes128" else priv
                words.append(f"priv {priv} {keys[1]}")
            self.out.append(" ".join(words))
        if s.traps:
            self.out.append("snmp-server enable traps")
        for h in s.hosts:
            label = snmp_text.host_label(h)
            rep.item("management", label)
            words = ["snmp-server host", h.address] + (["vrf", self.vrf(h.vrf)] if h.vrf else [])
            words += ["informs"] if h.informs else ([] if self.ios else ["traps"])
            words += ["version", h.version] + ([h.level] if h.version == "3" and h.level else [])
            words.append(h.secret if h.version == "3" else snmp_text.secret(h.secret, rep, "management", label,
                                                                            "community"))
            self.out.append(" ".join(words))
        if s.source:
            self.out.append(f"snmp-server {'trap-source' if self.ios else 'local-interface'} {self.port(s.source)}")
        if s.vrf and not self.ios:
            self.out.append(f"snmp-server vrf {self.vrf(s.vrf)}")
        elif s.vrf:
            rep.add("management", "snmp vrf", Severity.REVIEW, "snmp-vrf",
                    f"IOS has no agent VRF setting; SNMP answers in every VRF, including {s.vrf}")

    def services(self) -> None:
        s = self.device.system
        vrf = self.vrf(s.service_vrf) if s.service_vrf else ""
        self._ntp(vrf)
        self._snmp()
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
