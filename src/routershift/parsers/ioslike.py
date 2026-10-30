# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reader for the Cisco-style CLI that IOS, IOS XE and Arista EOS share.

The two dialects differ in details (a mask or a prefix length after ``ip address``,
``vrf forwarding`` or ``vrf``, ``ip domain-name`` or ``dns domain``); the reader takes
either spelling from either platform, so it also copes with configurations that were
pasted together by hand.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Optional, Tuple

from .. import acl as acl_text
from .. import fhrp
from .. import ospf as ospf_text
from .. import confparse, names
from ..confparse import Node
from ..errors import ParseError
from ..model import (Acl, Device, FhrpGroup, Interface, InterfaceKind, LacpMode, Origin, Ospf, OspfNetwork,
                     StaticRoute, StpMode, SwitchportMode, Unparsed, Vlan)

# Lines that only describe the file or the software, not the device's behaviour.
_NOISE = ("Building configuration", "Current configuration", "version ", "end", "boot-start-marker",
          "boot-end-marker", "! Command:", "! device:", "! boot system")

_MGMT_VRFS = {"mgmt-vrf", "mgmt-intf", "management", "mgmt"}


def _vlan_ids(text: str) -> List[int]:
    result: List[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            first, last = part.split("-", 1)
            result.extend(range(int(first), int(last) + 1))
        else:
            result.append(int(part))
    return result


def _cidr(address: str, mask: str) -> str:
    return str(ipaddress.ip_interface(f"{address}/{mask}"))


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


class _Reader:
    def __init__(self, platform: str) -> None:
        self.device = Device(platform=platform)
        self.switch_defaults = platform == "eos"  # physical ports start as switchports
        self._explicit_mode: Dict[str, bool] = {}  # "no switchport" seen
        self._switchport_seen: Dict[str, bool] = {}  # any switchport line seen
        self._varp_mac = ""  # EOS: ip virtual-router mac-address
        self._vrrp_v3 = False  # IOS XE: fhrp version vrrp v3
        self._ospf_areas: List[Tuple[str, str, str]] = []  # interface, process ("" = the interface's VRF), area

    def unparsed(self, node: Node, section: str = "") -> None:
        self.device.unparsed.append(Unparsed(node.line, node.text, section))
        for child in node.children:
            self.unparsed(child, section or node.text)

    # global ----------------------------------------------------------------------------------------------------------

    def read(self, text: str) -> Device:
        roots, banners = confparse.read(text)
        for banner in banners:
            if banner.kind == "motd":
                self.device.system.banner_motd = banner.text
            else:
                self.device.unparsed.append(Unparsed(banner.line, f"banner {banner.kind}", "banner"))
        if not roots:
            raise ParseError("no configuration lines found")
        # IOS: a switch is a device that has switchports at all.
        if self.device.platform == "ios":
            self.switch_defaults = any(
                c.text.startswith("switchport") for n in roots if n.text.startswith("interface ") for c in n.children)
        handlers: Dict[str, Callable[[Node], bool]] = {
            "hostname": self.hostname,
            "ip": self.ip,
            "ipv6": self.ipv6,
            "dns": self.dns,
            "ntp": self.ntp,
            "logging": self.logging,
            "clock": self.clock,
            "vlan": self.vlan,
            "interface": self.interface,
            "vrf": self.vrf,
            "spanning-tree": self.spanning_tree,
            "access-list": self.numbered_acl,
            "fhrp": self.fhrp_version,
            "router": self.router,
        }
        for node in roots:
            if node.text.startswith(_NOISE) or node.text == "end":
                continue
            handler = handlers.get(node.words[0])
            try:
                understood = handler is not None and handler(node)
            except (ValueError, IndexError):  # a value out of form: kept for the report
                understood = False
            if not understood:
                self.unparsed(node)
        self._finish()
        return self.device

    def hostname(self, node: Node) -> bool:
        self.device.system.hostname = node.words[1] if len(node.words) > 1 else ""
        return True

    def dns(self, node: Node) -> bool:  # EOS: dns domain example.com
        if len(node.words) == 3 and node.words[1] == "domain":
            self.device.system.domain_name = node.words[2]
            return True
        return False

    def ntp(self, node: Node) -> bool:
        w = node.words
        if len(w) >= 3 and w[1] == "server":
            args = w[2:]
            if args[0] == "vrf" and len(args) >= 3:
                self.device.system.service_vrf = args[1]
                args = args[2:]
            self.device.system.ntp_servers.append(args[0])
            return len(args) == 1 or args[1:] in (["prefer"], ["iburst"], ["prefer", "iburst"], ["iburst", "prefer"])
        return False

    def logging(self, node: Node) -> bool:
        w = node.words
        args = w[2:] if len(w) >= 3 and w[1] == "host" else w[1:]
        if args and args[0] == "vrf" and len(args) >= 3:  # EOS: logging vrf X host Y
            self.device.system.service_vrf = args[1]
            args = args[2:]
        if args[:1] == ["host"]:
            args = args[1:]
        if len(args) == 3 and args[1] == "vrf":  # IOS: logging host Y vrf X
            self.device.system.service_vrf = args[2]
            args = args[:1]
        if len(args) == 1 and _is_address(args[0]):
            self.device.system.syslog_servers.append(args[0])
            return True
        return False

    def clock(self, node: Node) -> bool:
        if len(node.words) >= 3 and node.words[1] == "timezone":
            self.device.system.timezone = " ".join(node.words[2:])
            return True
        return False

    def ip(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["routing"]:
            return True  # implied by the presence of layer 3 configuration
        if w[1:2] in (["domain-name"], ["domain"]) and len(w) >= 3:
            name = w[3] if w[2] == "name" and len(w) == 4 else w[2]
            self.device.system.domain_name = name
            return True
        if w[1:2] == ["name-server"]:
            args = w[2:]
            if args and args[0] == "vrf" and len(args) >= 2:
                self.device.system.service_vrf = args[1]
                args = args[2:]
            self.device.system.dns_servers.extend(args)
            return True
        if w[1:2] == ["route"]:
            return self.route(node, w[2:], 4)
        if w[1:2] == ["access-list"] and len(w) >= 3:
            return self.acl(node, 4)
        if w[1:3] == ["virtual-router", "mac-address"] and len(w) == 4:  # EOS VARP
            self._varp_mac = fhrp.mac(w[3])
            return True
        if w[1:2] == ["vrf"] and len(w) == 3:  # IOS classic: ip vrf NAME
            self._add_vrf(w[2])
            return all(c.words[0] in ("rd", "route-target", "description") for c in node.children)
        return False

    def ipv6(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["unicast-routing"]:
            return True
        if w[1:2] == ["route"]:
            return self.route(node, w[2:], 6)
        if w[1:2] == ["access-list"] and len(w) >= 3:
            return self.acl(node, 6)
        return False

    def fhrp_version(self, node: Node) -> bool:
        if node.words[1:] == ["version", "vrrp", "v3"]:
            self._vrrp_v3 = True
            return True
        return node.words[1:] == ["version", "vrrp", "v2"]

    # routing protocols -----------------------------------------------------------------------------------------------

    def router(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["ospf"] and len(w) in (3, 5) and (len(w) == 3 or w[3] == "vrf"):
            return self.ospf(node, w[2], w[4] if len(w) == 5 else "")
        return False

    def ospf(self, node: Node, number: str, vrf: str) -> bool:
        p = ospf_text.process(self.device, number, vrf)
        p.vrf = vrf
        p.origin = Origin(node.line, node.text)
        if vrf:
            self._add_vrf(vrf)
        for child in node.children:
            try:
                understood = self.ospf_line(p, child.words)
            except (ValueError, IndexError):
                understood = False
            if not understood:
                self.unparsed(child, node.text)
        return True

    @staticmethod
    def ospf_line(p: Ospf, w: List[str]) -> bool:
        n = len(w)
        if w[0] == "router-id" and n == 2:
            p.router_id = str(ipaddress.IPv4Address(w[1]))
        elif w[0] == "network" and n in (4, 5) and w[-2] == "area":
            prefix = acl_text.wildcard_prefix(w[1], w[2]) if n == 5 else str(ipaddress.ip_network(w[1], strict=False))
            p.networks.append(OspfNetwork(prefix, ospf_text.area(w[-1])))
        elif w == ["passive-interface", "default"]:
            p.passive_default = True
        elif w[0] == "passive-interface" and n >= 2:
            p.passive_interfaces.append(names.canonical(" ".join(w[1:]))[0])
        elif w[:2] == ["no", "passive-interface"] and n >= 3:
            p.active_interfaces.append(names.canonical(" ".join(w[2:]))[0])
        elif w[0] == "area" and n in (3, 4) and w[2] in ("stub", "nssa") and w[3:] in ([], ["no-summary"]):
            p.area_types[ospf_text.area(w[1])] = " ".join(w[2:])
        elif w[0] == "redistribute" and n >= 2 and w[1] in ospf_text.REDISTRIBUTE:
            rest = w[3:] if w[1] == "bgp" else w[2:]
            if rest not in ([], ["subnets"]):
                return False  # a route map or metric
            p.redistribute.append(w[1])
        elif w[:2] == ["default-information", "originate"] and w[2:] in ([], ["always"]):
            p.default_originate = "always" if n == 3 else "on"
        elif w[:2] == ["auto-cost", "reference-bandwidth"] and n == 3:
            p.reference_bandwidth = int(w[2])
        elif w[0] == "log-adjacency-changes" or w == ["max-lsa", "12000"]:
            pass  # logging, and the EOS default
        else:
            return False
        return True

    # access lists ----------------------------------------------------------------------------------------------------

    def acl(self, node: Node, family: int) -> bool:
        """ip access-list [standard|extended] NAME (IOS, EOS), ipv6 access-list NAME."""
        w = node.words[2:]
        standard = w[0] == "standard"
        if w[0] in ("standard", "extended"):
            w = w[1:]
        if len(w) != 1:
            return False
        acl = self.device.acls.setdefault(w[0], Acl(w[0], family=family))
        for child in node.children:
            words = child.words
            sequence: Optional[int] = None
            if words[0] == "sequence" and len(words) > 1:  # IOS IPv6
                words = words[1:]
            if words[0].isdigit():
                sequence, words = int(words[0]), words[1:]
            if words[:1] == ["statistics"] or words[:1] == ["counters"]:
                continue
            try:
                entry = acl_text.read_entry(words, family, wildcards=True, standard=standard)
            except (acl_text.Unsupported, ValueError, IndexError):
                entry = acl_text.unsupported_entry(child.text, sequence)
            entry.sequence, entry.origin = sequence, Origin(child.line, child.text)
            acl.entries.append(entry)
        return True

    def numbered_acl(self, node: Node) -> bool:
        """access-list 10 permit 10.0.0.0 0.0.0.255, access-list 101 permit tcp any any eq 80 (IOS)."""
        w = node.words
        if len(w) < 3 or not w[1].isdigit():
            return False
        number = int(w[1])
        standard = number < 100 or 1300 <= number < 2000
        acl = self.device.acls.setdefault(w[1], Acl(w[1]))
        try:
            entry = acl_text.read_entry(w[2:], 4, wildcards=True, standard=standard)
        except (acl_text.Unsupported, ValueError, IndexError):
            entry = acl_text.unsupported_entry(node.text)
        entry.origin = Origin(node.line, node.text)
        acl.entries.append(entry)
        return True

    def _add_vrf(self, name: str) -> None:
        if name not in self.device.vrfs:
            self.device.vrfs.append(name)

    def vrf(self, node: Node) -> bool:
        w = node.words
        # IOS XE: vrf definition NAME; EOS: vrf instance NAME (or vrf definition on older releases)
        if len(w) == 3 and w[1] in ("definition", "instance"):
            self._add_vrf(w[2])
            for child in node.children:
                if child.words[0] in ("rd", "description", "address-family", "exit-address-family"):
                    if child.words[0] == "address-family" and any(
                            c.words[0] != "exit-address-family" for c in child.children):
                        self.unparsed(child, node.text)
                    continue
                self.unparsed(child, node.text)
            return True
        return False

    def spanning_tree(self, node: Node) -> bool:
        w = node.words
        if len(w) == 3 and w[1] == "mode":
            modes = {"pvst": StpMode.PVST, "rapid-pvst": StpMode.RAPID_PVST, "mst": StpMode.MSTP,
                     "mstp": StpMode.MSTP, "rstp": StpMode.RSTP, "none": StpMode.NONE}
            if w[2] in modes:
                self.device.stp_mode = modes[w[2]]
                return True
        return False

    def vlan(self, node: Node) -> bool:
        w = node.words
        if len(w) != 2:
            return False
        try:
            ids = _vlan_ids(w[1])
        except ValueError:
            return False
        for vid in ids:
            vlan = self.device.vlans.setdefault(vid, Vlan(vid, origin=Origin(node.line, node.text)))
            for child in node.children:
                if child.words[0] == "name" and len(child.words) >= 2:
                    vlan.name = " ".join(child.words[1:])
                elif child.text in ("shutdown", "state suspend"):
                    vlan.shutdown = True
                elif vid == ids[0]:
                    self.unparsed(child, node.text)
        return True

    def route(self, node: Node, args: List[str], family: int) -> bool:
        vrf = ""
        if args[:1] == ["vrf"] and len(args) >= 2:
            vrf, args = args[1], args[2:]
        if not args:
            return False
        try:
            if family == 4 and "/" not in args[0]:
                prefix = str(ipaddress.ip_network(f"{args[0]}/{args[1]}", strict=False))
                args = args[2:]
            else:
                prefix = str(ipaddress.ip_network(args[0], strict=False))
                args = args[1:]
        except (ValueError, IndexError):
            return False
        route = StaticRoute(prefix, vrf=vrf, origin=Origin(node.line, node.text))
        ok = True
        while args:
            word = args.pop(0)
            if _is_address(word) and not route.next_hop:
                route.next_hop = word
            elif word.isdigit() and route.distance is None:
                route.distance = int(word)
            elif word == "name" and args:
                route.name = args.pop(0)
            elif word.lower().startswith("null"):
                route.discard = True
            elif not route.interface and not route.next_hop:
                canon, _, _ = names.canonical(word)
                route.interface = canon
            else:
                ok = False  # tag, track, permanent, ...: kept for the report
        self.device.static_routes.append(route)
        if not ok:
            self.device.unparsed.append(Unparsed(node.line, node.text, "ip route (options not converted)"))
        return True

    # interfaces ------------------------------------------------------------------------------------------------------

    def interface(self, node: Node) -> bool:
        source = " ".join(node.words[1:])
        canon, kind, media = names.canonical(source)
        iface = Interface(canon, kind, source_name=source, media=media, origin=Origin(node.line, node.text))
        if kind == InterfaceKind.SUBINTERFACE:
            iface.parent = canon.rsplit(".", 1)[0]
        if kind == InterfaceKind.ETHERNET and self.switch_defaults:
            iface.mode = SwitchportMode.ACCESS
        self.device.interfaces[canon] = iface
        trunk_vlans: Optional[List[str]] = None
        hsrp_version: Optional[int] = None
        for child in node.children:
            if child.words[0] == "switchport":
                self._switchport_seen[canon] = True
            if child.words[:2] == ["standby", "version"] and len(child.words) == 3 and child.words[2] in ("1", "2"):
                hsrp_version = int(child.words[2])
                continue
            if child.words[0] == "vrrp" and child.words[2:] == ["address-family", "ipv4"]:
                self._vrrp_block(iface, child)
                continue
            try:
                understood = self.interface_line(iface, child.words)
            except (ValueError, IndexError):
                understood = False
            if not understood:
                self.unparsed(child, node.text)
            w = child.words
            if w[:4] == ["switchport", "trunk", "allowed", "vlan"] and len(w) >= 5:
                if w[4] == "add" and trunk_vlans is not None:
                    trunk_vlans.extend(w[5:])
                elif w[4] not in ("add", "remove", "except"):
                    trunk_vlans = [w[4]] if w[4] not in ("all",) else []
        if trunk_vlans is not None:
            iface.allowed_vlans = ",".join(trunk_vlans)
        for group in iface.fhrp:
            if group.protocol == "hsrp":
                group.version = hsrp_version
        return True

    # first-hop redundancy --------------------------------------------------------------------------------------------

    @staticmethod
    def _fhrp_group(iface: Interface, protocol: str, number: int) -> FhrpGroup:
        for group in iface.fhrp:
            if group.protocol == protocol and group.group == number:
                return group
        group = FhrpGroup(protocol, number)
        iface.fhrp.append(group)
        return group

    @staticmethod
    def _virtual_ip(group: FhrpGroup, args: List[str]) -> bool:
        if not args or len(args) > 2 or args[1:] not in ([], ["secondary"]):
            return False
        address = str(ipaddress.IPv4Address(args[0]))
        if args[1:] or group.address:
            group.secondary.append(address)
        else:
            group.address = address
        return True

    def _hsrp(self, iface: Interface, w: List[str]) -> bool:
        """standby [N] ip|priority|preempt|timers|name|shutdown ..."""
        number = int(w[0]) if w and w[0].isdigit() else 0
        if w and w[0].isdigit():
            w = w[1:]
        if not w:
            return False
        group = self._fhrp_group(iface, "hsrp", number)
        if w[0] == "ip":
            return self._virtual_ip(group, w[1:])
        if w[0] == "priority" and len(w) == 2:
            group.priority = int(w[1])
        elif w[0] == "preempt":
            group.preempt = True
            return len(w) == 1  # a delay is listed for review
        elif w[0] == "timers" and len(w) >= 3:
            times: List[int] = []
            args = w[1:]
            while args:
                if args[0] == "msec" and len(args) >= 2:
                    times.append(int(args[1]))
                    args = args[2:]
                else:
                    times.append(int(args[0]) * 1000)
                    args = args[1:]
            if len(times) != 2:
                return False
            group.hello_ms, group.hold_ms = times
        elif w[0] == "name" and len(w) == 2:
            group.name = w[1]
        elif w == ["shutdown"]:
            group.shutdown = True
        else:
            return False
        return True

    def _vrrp(self, iface: Interface, w: List[str]) -> bool:
        """vrrp N ... in the IOS classic and EOS spellings."""
        if not w or not w[0].isdigit() or len(w) < 2:
            return False
        group = self._fhrp_group(iface, "vrrp", int(w[0]))
        w = w[1:]
        n = len(w)
        if w[0] in ("ip", "ipv4") and n >= 2:
            if w[1:] == ["version", "3"] or w[1:] == ["version", "2"]:
                group.version = int(w[2])
                return True
            return self._virtual_ip(group, w[1:])
        if w[0] == "version" and n == 2:
            group.version = int(w[1])
        elif w[0] in ("priority", "priority-level") and n == 2:
            group.priority = int(w[1])
        elif w[0] == "preempt":
            group.preempt = True
            return n == 1
        elif w[:2] == ["timers", "advertise"] and n in (3, 4):
            group.hello_ms = int(w[3]) if w[2] == "msec" and n == 4 else int(w[2]) * 1000
            return n == 3 or w[2] == "msec"
        elif w[:2] == ["advertisement", "interval"] and n == 3:
            group.hello_ms = int(w[2]) * 1000
        elif w[0] == "description" and n >= 2:
            group.name = " ".join(w[1:])
        elif w[:2] == ["session", "description"] and n >= 3:
            group.name = " ".join(w[2:])
        elif w in (["shutdown"], ["disabled"]):
            group.shutdown = True
        else:
            return False
        return True

    def _vrrp_block(self, iface: Interface, node: Node) -> None:
        """IOS XE VRRPv3: vrrp N address-family ipv4, with its settings inside."""
        group = self._fhrp_group(iface, "vrrp", int(node.words[1]))
        group.version = 3
        group.preempt = True
        for child in node.children:
            w = child.words
            n = len(w)
            if w[0] == "address" and n in (2, 3) and w[2:] in ([], ["primary"], ["secondary"]):
                address = str(ipaddress.IPv4Address(w[1]))
                if w[2:] == ["secondary"]:
                    group.secondary.append(address)
                else:
                    group.address = address
            elif w[0] == "priority" and n == 2:
                group.priority = int(w[1])
            elif w == ["no", "preempt"]:
                group.preempt = False
            elif w == ["preempt"]:
                group.preempt = True
            elif w[:2] == ["timers", "advertise"] and n == 3:
                group.hello_ms = int(w[2])
            elif w == ["vrrpv2"]:
                group.version = 2
            elif w[0] == "description" and n >= 2:
                group.name = " ".join(w[1:])
            elif w == ["shutdown"]:
                group.shutdown = True
            elif w == ["exit-vrrp"]:
                pass
            else:
                self.unparsed(child, node.text)

    def interface_line(self, iface: Interface, w: List[str]) -> bool:
        n = len(w)
        if w[0] == "description":
            iface.description = " ".join(w[1:])
        elif w == ["shutdown"]:
            iface.shutdown = True
        elif w == ["no", "shutdown"]:
            iface.shutdown = False
        elif w[0] == "mtu" and n == 2:
            iface.mtu = int(w[1])
        elif w[0] == "speed" and n >= 2:
            return self._speed(iface, w[1:])
        elif w[0] == "duplex" and n == 2:
            iface.duplex = w[1]
        elif w == ["switchport"]:
            if iface.mode == SwitchportMode.ROUTED:
                iface.mode = SwitchportMode.ACCESS
        elif w == ["no", "switchport"]:
            iface.mode = SwitchportMode.ROUTED
            self._explicit_mode[iface.name] = True
        elif w[:2] == ["switchport", "mode"] and n == 3 and w[2] in ("access", "trunk"):
            iface.mode = SwitchportMode(w[2])
        elif w[:3] == ["switchport", "access", "vlan"] and n == 4:
            iface.access_vlan = int(w[3])
            if iface.mode == SwitchportMode.ROUTED:
                iface.mode = SwitchportMode.ACCESS
        elif w[:4] == ["switchport", "trunk", "native", "vlan"] and n == 5:
            iface.native_vlan = int(w[4])
        elif w[:4] == ["switchport", "trunk", "allowed", "vlan"] and n >= 5:
            return w[4] not in ("remove", "except", "none")
        elif w[:3] == ["switchport", "trunk", "encapsulation"]:
            pass  # dot1q is the only encapsulation left
        elif w[:3] in (["switchport", "voice", "vlan"], ["switchport", "phone", "vlan"]) and n == 4:
            iface.voice_vlan = int(w[3])
        elif w[:2] == ["switchport", "nonegotiate"]:
            pass
        elif w[0] == "channel-group" and n >= 2:
            lag = f"Port-channel{w[1]}"
            iface.lag = lag
            if lag not in self.device.interfaces:
                self.device.interfaces[lag] = Interface(lag, InterfaceKind.LAG, source_name="")
            if n == 4 and w[2] == "mode":
                modes = {"active": LacpMode.ACTIVE, "passive": LacpMode.PASSIVE, "on": LacpMode.STATIC}
                if w[3] not in modes:
                    return False
                iface.lacp_mode = modes[w[3]]
        elif w[:2] in (["vrf", "forwarding"], ["ip", "vrf"]) and n >= 3:
            iface.vrf = w[-1]
            self._add_vrf(iface.vrf)
        elif w[0] == "vrf" and n == 2:
            iface.vrf = w[1]
            self._add_vrf(iface.vrf)
        elif w[:2] == ["ip", "address"] and n >= 3:
            return self._ip_address(iface, w[2:])
        elif w[:2] == ["ipv6", "address"] and n >= 3:
            if n != 3 or w[2] in ("autoconfig", "dhcp"):
                return False
            iface.ipv6.append(str(ipaddress.ip_interface(w[2])))
        elif w == ["ipv6", "enable"]:
            pass
        elif w[:2] == ["ip", "access-group"] and n == 4 and w[3] in ("in", "out"):
            setattr(iface, f"acl_{w[3]}", w[2])
        elif w[:2] in (["ipv6", "traffic-filter"], ["ipv6", "access-group"]) and n == 4 and w[3] in ("in", "out"):
            setattr(iface, f"acl6_{w[3]}", w[2])
        elif w[:2] == ["ip", "helper-address"] and n >= 3:
            iface.helper_addresses.append(w[-1])
            return n == 3
        elif w[:2] == ["encapsulation", "dot1Q"] or w[:2] == ["encapsulation", "dot1q"]:
            tag = w[3] if n >= 4 and w[2] == "vlan" else w[2] if n >= 3 else ""
            if not tag.isdigit():
                return False
            iface.encapsulation_vlan = int(tag)
        elif w[:2] == ["ip", "ospf"] and n >= 4 and w[-2] == "area" and n in (4, 5):
            self._ospf_areas.append((iface.name, w[2] if n == 5 else "", ospf_text.area(w[-1])))
        elif w[:3] == ["ip", "ospf", "cost"] and n == 4:
            iface.ospf_cost = int(w[3])
        elif w[:3] == ["ip", "ospf", "network"] and n == 4 and w[3] in ("point-to-point", "broadcast"):
            iface.ospf_network = w[3]
        elif w[0] == "standby" and n >= 2:
            return self._hsrp(iface, w[1:])
        elif w[0] == "vrrp" and n >= 2:
            return self._vrrp(iface, w[1:])
        elif w[:2] == ["no", "vrrp"] and n == 4 and w[3] == "preempt":
            self._fhrp_group(iface, "vrrp", int(w[2])).preempt = False
        elif w[:3] == ["ip", "virtual-router", "address"] and n == 4:  # EOS VARP
            group = self._fhrp_group(iface, "anycast", 0)
            address = w[3].split("/")[0]
            return self._virtual_ip(group, [address] if not group.address else [address, "secondary"])
        elif w[:2] == ["spanning-tree", "portfast"] and (n == 2 or w[2:] in (["edge"], ["trunk"])):
            iface.stp_portfast = True
        elif w[:2] == ["spanning-tree", "bpduguard"] and n == 3:
            iface.stp_bpduguard = w[2] == "enable"
        else:
            return False
        return True

    def _speed(self, iface: Interface, args: List[str]) -> bool:
        value = args[-1].lower()
        if value == "auto":
            return True
        if value.endswith("full") or value.endswith("half"):
            iface.duplex = "full" if value.endswith("full") else "half"
            value = value[:-4]
        units = {"g": 1000, "m": 1}
        if value[-1:] in units and value[:-1].replace(".", "").isdigit():
            iface.speed = int(float(value[:-1]) * units[value[-1]])
            return True
        if value.isdigit():
            iface.speed = int(value)
            return True
        return False

    def _ip_address(self, iface: Interface, args: List[str]) -> bool:
        if args[0] == "dhcp":
            iface.dhcp_client = True
            return len(args) == 1
        secondary = args[-1] == "secondary"
        if secondary:
            args = args[:-1]
        try:
            value = _cidr(args[0], args[1]) if len(args) == 2 else str(ipaddress.ip_interface(args[0]))
        except ValueError:
            return False
        if secondary:
            iface.ipv4.append(value)
        else:
            iface.ipv4.insert(0, value)
        return len(args) in (1, 2)

    def _finish(self) -> None:
        for iface in self.device.interfaces.values():
            for group in iface.fhrp:
                if group.protocol == "anycast":
                    group.mac = self._varp_mac
                elif group.protocol == "vrrp" and self._vrrp_v3 and group.version is None:
                    group.version = 3
        for iface in self.device.interfaces.values():
            # A routed port that carries no layer 3 address on a router is still routed; on IOS a physical port with an
            # address but without "no switchport" is routed as well (a router).
            if iface.kind != InterfaceKind.ETHERNET:
                if iface.kind in (InterfaceKind.LAG,) and self.switch_defaults and not (iface.ipv4 or iface.ipv6):
                    if not self._explicit_mode.get(iface.name):
                        iface.mode = self._lag_mode(iface)
                continue
            # A port with an address and no switchport line is routed: a router, or the management port of a switch.
            if (iface.ipv4 or iface.ipv6 or iface.dhcp_client) and not self._switchport_seen.get(iface.name):
                iface.mode = SwitchportMode.ROUTED
            if iface.vrf.lower() in _MGMT_VRFS and iface.mode == SwitchportMode.ROUTED and not iface.lag:
                iface.kind = InterfaceKind.MANAGEMENT
        # Management ports are Management1, Management2, ... whatever the source called them.
        renamed: Dict[str, Interface] = {}
        old_to_new: Dict[str, str] = {}
        count = 0
        for iface in self.device.interfaces.values():
            if iface.kind == InterfaceKind.MANAGEMENT:
                count += 1
                old_to_new[iface.name] = iface.name = f"Management{count}"
            renamed[iface.name] = iface
        self.device.interfaces = renamed
        for route in self.device.static_routes:
            route.interface = old_to_new.get(route.interface, route.interface)
        ospf_text.attach(self.device, [(old_to_new.get(n, n), p, a) for n, p, a in self._ospf_areas], {})
        for p in self.device.ospf:
            ospf_text.rename(p, old_to_new)

    def _lag_mode(self, lag: Interface) -> SwitchportMode:
        if lag.mode != SwitchportMode.ROUTED:
            return lag.mode
        members = [i for i in self.device.interfaces.values() if i.lag == lag.name]
        return members[0].mode if members else SwitchportMode.ACCESS


def parse(text: str, platform: str) -> Device:
    return _Reader(platform).read(text)
