# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reader for HPE Comware 7 (FlexFabric, 5130/5140/5510/5710/5940...) ``display current-configuration``.

Comware's spelling differs from the Cisco style throughout: ``undo`` for ``no``,
``port link-type access|trunk|hybrid``, VLAN lists with ``to`` (``10 20 30 to 40``),
``Bridge-Aggregation`` for port-channels, ``Vlan-interface`` for SVIs, VPN instances
for VRFs and ``ip route-static`` with a prefix length or a mask. Blocks are
separated by ``#`` and global lines are indented by one space.

A trunk permits only VLAN 1 until it says otherwise, and a hybrid port lists its
untagged and tagged VLANs itself; the reader turns hybrid ports into access ports
with a voice VLAN or trunks.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from .. import acl as acl_text
from .. import confparse
from ..confparse import Node
from ..errors import ParseError
from ..model import (Acl, AclAction, AclEntry, Device, FhrpGroup, Interface, InterfaceKind, LacpMode, Origin, StaticRoute, StpMode, SwitchportMode,
                     Unparsed, Vlan)
from .ioslike import _cidr, _is_address

_PREFIXES: List[Tuple[str, InterfaceKind, str]] = [
    ("M-GigabitEthernet", InterfaceKind.MANAGEMENT, ""),
    ("HundredGigE", InterfaceKind.ETHERNET, "100g"),
    ("FortyGigE", InterfaceKind.ETHERNET, "40g"),
    ("Twenty-FiveGigE", InterfaceKind.ETHERNET, "25g"),
    ("Ten-GigabitEthernet", InterfaceKind.ETHERNET, "10g"),
    ("GigabitEthernet", InterfaceKind.ETHERNET, "1g"),
    ("Bridge-Aggregation", InterfaceKind.LAG, ""),
    ("Route-Aggregation", InterfaceKind.LAG, ""),
    ("Vlan-interface", InterfaceKind.VLAN, ""),
    ("LoopBack", InterfaceKind.LOOPBACK, ""),
    ("Tunnel", InterfaceKind.TUNNEL, ""),
    ("NULL", InterfaceKind.OTHER, ""),
]
_ABBREVIATIONS = {
    "mge": "M-GigabitEthernet", "hge": "HundredGigE", "fge": "FortyGigE", "wge": "Twenty-FiveGigE",
    "xge": "Ten-GigabitEthernet", "ge": "GigabitEthernet", "bagg": "Bridge-Aggregation", "ragg": "Route-Aggregation",
    "vlan-int": "Vlan-interface", "loop": "LoopBack",
}
_NAME = re.compile(r"^([A-Za-z-]+?)\s*(\d[\d/.:]*)$")
_NOISE = ("version ", "return")


def canonical(name: str) -> Tuple[str, InterfaceKind, str]:
    m = _NAME.match(name.strip())
    if not m:
        return name, InterfaceKind.OTHER, ""
    prefix = _ABBREVIATIONS.get(m.group(1).lower(), m.group(1))
    number = m.group(2)
    for full, kind, media in _PREFIXES:
        if full.lower() != prefix.lower():
            continue
        if kind == InterfaceKind.ETHERNET:
            return f"Ethernet{number}", InterfaceKind.SUBINTERFACE if "." in number else kind, media
        if kind == InterfaceKind.LAG:
            return f"Port-channel{number}", InterfaceKind.SUBINTERFACE if "." in number else kind, ""
        if kind == InterfaceKind.VLAN:
            return f"Vlan{number}", kind, ""
        if kind == InterfaceKind.LOOPBACK:
            return f"Loopback{number}", kind, ""
        if kind == InterfaceKind.MANAGEMENT:
            return "Management1", kind, ""
        return f"{full}{number}", kind, media
    return name, InterfaceKind.OTHER, ""


def vlan_list(words: List[str]) -> List[int]:
    """``10 20 30 to 40`` as VLAN IDs."""
    result: List[int] = []
    i = 0
    while i < len(words):
        if i + 2 < len(words) and words[i + 1] == "to":
            result.extend(range(int(words[i]), int(words[i + 2]) + 1))
            i += 3
        else:
            result.append(int(words[i]))
            i += 1
    return result


def ranges(vlans: List[int]) -> str:
    """VLAN IDs as the model's ``10,20,30-40``."""
    parts: List[str] = []
    ordered = sorted(set(vlans))
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        parts.append(str(ordered[i]) if i == j else f"{ordered[i]}-{ordered[j]}")
        i = j + 1
    return ",".join(parts)


class _Reader:
    def __init__(self) -> None:
        self.device = Device(platform="comware")
        self._permit: Dict[str, List[int]] = {}
        self._hybrid_untagged: Dict[str, List[int]] = {}
        self._hybrid_tagged: Dict[str, List[int]] = {}
        self._pvid: Dict[str, int] = {}
        self._link_type: Dict[str, str] = {}
        self._dynamic_lags: Set[str] = set()
        self._bpdu_protection = False
        self._vrrp_version = 3  # the Comware 7 default

    def unparsed(self, node: Node, section: str = "") -> None:
        self.device.unparsed.append(Unparsed(node.line, node.text, section))
        for child in node.children:
            self.unparsed(child, section or node.text)

    def read(self, text: str) -> Device:
        roots, banners = confparse.read(text, comment="#", banner_word="header")
        if not roots:
            raise ParseError("no configuration lines found")
        for banner in banners:
            if banner.kind == "motd":
                self.device.system.banner_motd = banner.text
            else:
                self.device.unparsed.append(Unparsed(banner.line, f"header {banner.kind}", "banner"))
        handlers: Dict[str, Callable[[Node], bool]] = {
            "sysname": self.sysname,
            "clock": self.clock,
            "dns": self.dns,
            "ntp-service": self.ntp,
            "info-center": self.info_center,
            "ip": self.ip,
            "ipv6": self.ipv6,
            "vlan": self.vlan,
            "stp": self.stp,
            "interface": self.interface,
            "acl": self.acl,
            "vrrp": self.vrrp_version,
        }
        for node in roots:
            if node.text.startswith(_NOISE):
                continue
            handler = handlers.get(node.words[0])
            try:
                understood = handler is not None and handler(node)
            except (ValueError, IndexError):
                understood = False
            if not understood:
                self.unparsed(node)
        self._finish()
        return self.device

    # global ----------------------------------------------------------------------------------------------------------

    def sysname(self, node: Node) -> bool:
        self.device.system.hostname = node.words[1]
        return len(node.words) == 2

    def clock(self, node: Node) -> bool:
        # clock timezone CET add 01:00:00
        w = node.words
        if w[1:2] == ["timezone"] and len(w) == 5 and w[3] in ("add", "minus"):
            h, m, _ = (int(x) for x in w[4].split(":"))
            sign = "-" if w[3] == "minus" else ""
            self.device.system.timezone = f"{w[2]} {sign}{h} {m}"
            return True
        return False

    def _vpn(self, args: List[str]) -> List[str]:
        if "vpn-instance" in args:
            i = args.index("vpn-instance")
            self.device.system.service_vrf = args[i + 1]
            return args[:i] + args[i + 2:]
        return args

    def dns(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["domain"] and len(w) == 3:
            self.device.system.domain_name = w[2]
            return True
        if w[1:2] == ["server"]:
            self.device.system.dns_servers.extend(self._vpn(w[2:]))
            return True
        return False

    def ntp(self, node: Node) -> bool:
        w = node.words
        if w[1:] == ["enable"]:
            return True
        if w[1:2] == ["unicast-server"] and len(w) >= 3:
            args = self._vpn(w[2:])
            self.device.system.ntp_servers.append(args[0])
            return len(args) == 1 or args[1:] == ["priority"]
        return False

    def info_center(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["loghost"]:
            args = self._vpn(w[2:])
            if len(args) == 1 and _is_address(args[0]):
                self.device.system.syslog_servers.append(args[0])
                return True
        return w[1:] == ["enable"]

    def ip(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["vpn-instance"] and len(w) == 3:
            if w[2] not in self.device.vrfs:
                self.device.vrfs.append(w[2])
            for child in node.children:
                if child.words[0] not in ("route-distinguisher", "description"):
                    self.unparsed(child, node.text)
            return True
        if w[1:2] == ["route-static"]:
            return self.route(node, w[2:], 4)
        return False

    def ipv6(self, node: Node) -> bool:
        if node.words[1:2] == ["route-static"]:
            return self.route(node, node.words[2:], 6)
        return False

    def route(self, node: Node, args: List[str], family: int) -> bool:
        vrf = ""
        if args[:1] == ["vpn-instance"]:
            vrf, args = args[1], args[2:]
        mask = args[1]
        prefix = str(ipaddress.ip_network(f"{args[0]}/{mask}", strict=False))
        route = StaticRoute(prefix, vrf=vrf, origin=Origin(node.line, node.text))
        rest = args[2:]
        ok = True
        while rest:
            word = rest.pop(0)
            if word.upper().startswith("NULL"):
                route.discard = True
            elif word == "preference" and rest:
                route.distance = int(rest.pop(0))
            elif word == "description" and rest:
                route.name = " ".join(rest)
                rest = []
            elif _is_address(word) and not route.next_hop:
                route.next_hop = word
            elif not route.interface and not route.next_hop:
                route.interface, _, _ = canonical(word)
            else:
                ok = False
        self.device.static_routes.append(route)
        if not ok:
            self.device.unparsed.append(Unparsed(node.line, node.text, "ip route-static (options not converted)"))
        return True

    def vlan(self, node: Node) -> bool:
        w = node.words
        ids = vlan_list(w[1:]) if len(w) >= 2 else []
        if not ids:
            return False
        for vid in ids:
            vlan = self.device.vlans.setdefault(vid, Vlan(vid, origin=Origin(node.line, node.text)))
            for child in node.children:
                if child.words[0] == "name" and len(child.words) >= 2:
                    vlan.name = child.text.split(None, 1)[1]
                elif child.text == "shutdown":
                    vlan.shutdown = True
                elif vid == ids[0]:
                    self.unparsed(child, node.text)
        return True

    def stp(self, node: Node) -> bool:
        w = node.words
        if w[1:] in (["global", "enable"], ["enable"]):
            if self.device.stp_mode is None:
                self.device.stp_mode = StpMode.MSTP  # the Comware default mode
            return True
        if w[1:2] == ["mode"] and len(w) == 3:
            modes = {"stp": StpMode.STP, "rstp": StpMode.RSTP, "mstp": StpMode.MSTP, "pvst": StpMode.RAPID_PVST}
            if w[2] in modes:
                self.device.stp_mode = modes[w[2]]
                return True
        if w[1:] == ["bpdu-protection"]:
            self._bpdu_protection = True
            return True
        if w[1:] == ["global", "disable"] or w[:3] == ["undo", "stp", "global"]:
            self.device.stp_mode = StpMode.NONE
            return True
        return False

    # access lists ----------------------------------------------------------------------------------------------------

    def acl(self, node: Node) -> bool:
        """acl [ipv6] advanced|basic name NAME, acl [ipv6] advanced 3000, acl number 3000 [name NAME]."""
        w = node.words[1:]
        family = 4
        if w[:1] == ["ipv6"]:
            family, w = 6, w[1:]
        name = ""
        standard = False
        if w[:1] == ["number"] and len(w) >= 2:
            name, standard = w[1], 2000 <= int(w[1]) < 3000
            w = w[2:]
        elif w[:1] in (["advanced"], ["basic"]) and len(w) >= 2:
            standard = w[0] == "basic"
            if w[1] == "name" and len(w) >= 3:
                name, w = w[2], w[3:]
            else:
                name, w = w[1], w[2:]
        if w[:1] == ["name"] and len(w) == 2:
            name, w = w[1], []
        if not name or w:
            return False
        acl = self.device.acls.setdefault(name, Acl(name, family=family))
        comments: Dict[int, str] = {}
        for child in node.children:
            c = child.words
            if c[0] == "description":
                continue
            if c[0] != "rule":
                self.unparsed(child, node.text)
                continue
            sequence: Optional[int] = None
            args = c[1:]
            if args and args[0].isdigit():
                sequence, args = int(args[0]), args[1:]
            if args[:1] == ["comment"] and sequence is not None:
                comments[sequence] = " ".join(args[1:])
                continue
            try:
                entry = self._rule(args, family, standard)
            except (acl_text.Unsupported, ValueError, IndexError, KeyError):
                entry = acl_text.unsupported_entry(child.text)
            entry.sequence, entry.origin = sequence, Origin(child.line, child.text)
            acl.entries.append(entry)
        # A rule's comment comes before it, as a remark
        for seq, text in comments.items():
            at = next((i for i, e in enumerate(acl.entries) if e.sequence == seq), len(acl.entries))
            acl.entries.insert(at, AclEntry(AclAction.REMARK, remark=text))
        return True

    def _rule(self, args: List[str], family: int, standard: bool) -> AclEntry:
        """rule permit tcp source 10.0.0.0 0.0.0.255 destination-port eq 443 logging."""
        tokens = acl_text.Tokens(args)
        action = tokens.take()
        if action not in ("permit", "deny"):
            raise acl_text.Unsupported(action)
        entry = AclEntry(AclAction(action))
        if not standard and tokens.peek() and tokens.peek() not in ("source", "logging", "counting"):
            proto = tokens.take()
            entry.protocol = {"ipv6": "ip", "icmpv6": "icmpv6"}.get(proto, proto)
            if entry.protocol not in acl_text.PROTOCOLS and not entry.protocol.isdigit():
                raise acl_text.Unsupported(proto)
        while tokens.words:
            word = tokens.take()
            if word in ("source", "destination"):
                address = tokens.take()
                if address == "any":
                    value = "any"
                elif "/" in address:
                    value = str(ipaddress.ip_network(address, strict=False))
                elif ":" in address:
                    value = str(ipaddress.ip_network(f"{address}/{tokens.take()}", strict=False))
                else:
                    value = acl_text.wildcard_prefix(address, tokens.take())
                setattr(entry, word, value)
            elif word in ("source-port", "destination-port"):
                ports = acl_text.read_ports(tokens)
                setattr(entry, "src_ports" if word == "source-port" else "dst_ports", ports)
            elif word == "icmp-type" or word == "icmp6-type":
                kind = tokens.take()
                entry.icmp_type = int(kind) if kind.isdigit() else acl_text.ICMP_TYPES[kind]
            elif word == "established":
                entry.established = True
            elif word == "logging":
                entry.log = True
            elif word == "counting":
                pass
            else:
                raise acl_text.Unsupported(word)
        return entry

    # interfaces ------------------------------------------------------------------------------------------------------

    def vrrp_version(self, node: Node) -> bool:
        if node.words[1:2] == ["version"] and node.words[2:] in (["2"], ["3"]):
            self._vrrp_version = int(node.words[2])
            return True
        return False

    def _vrrp(self, iface: Interface, w: List[str], preempt: bool = True) -> bool:
        """vrrp vrid N virtual-ip|priority|preempt-mode|timer advertise|shutdown"""
        if len(w) < 2 or not w[0].isdigit():
            return False
        number = int(w[0])
        group = next((g for g in iface.fhrp if g.group == number), None)
        if group is None:
            group = FhrpGroup("vrrp", number)
            iface.fhrp.append(group)
        w = w[1:]
        n = len(w)
        if w[0] == "virtual-ip" and n == 2:
            address = str(ipaddress.IPv4Address(w[1]))
            if group.address:
                group.secondary.append(address)
            else:
                group.address = address
        elif w[0] == "preempt-mode":
            group.preempt = preempt
            return n == 1 or w[1:] == ["delay", "0"]
        elif not preempt:
            return False
        elif w[0] == "priority" and n == 2:
            group.priority = int(w[1])
        elif w[:2] == ["timer", "advertise"] and n == 3:
            group.hello_ms = int(w[2]) * 10  # centiseconds
        elif w == ["shutdown"]:
            group.shutdown = True
        else:
            return False
        return True

    def interface(self, node: Node) -> bool:
        source = " ".join(node.words[1:])
        canon, kind, media = canonical(source)
        if source.upper() == "NULL0" and not node.children:
            return True  # always there
        iface = Interface(canon, kind, source_name=source, media=media, origin=Origin(node.line, node.text))
        if kind == InterfaceKind.SUBINTERFACE:
            iface.parent = canon.rsplit(".", 1)[0]
        if kind == InterfaceKind.ETHERNET or source.startswith("Bridge-Aggregation"):
            iface.mode = SwitchportMode.ACCESS  # bridge mode is the default on a switch
        self.device.interfaces[canon] = iface
        for child in node.children:
            try:
                understood = self.interface_line(iface, child.words)
            except (ValueError, IndexError):
                understood = False
            if not understood:
                self.unparsed(child, node.text)
        return True

    def interface_line(self, iface: Interface, w: List[str]) -> bool:
        n = len(w)
        name = iface.name
        if w[0] == "description":
            iface.description = " ".join(w[1:])
        elif w == ["shutdown"]:
            iface.shutdown = True
        elif w == ["undo", "shutdown"]:
            iface.shutdown = False
        elif w[:2] == ["port", "link-mode"] and n == 3:
            iface.mode = SwitchportMode.ROUTED if w[2] == "route" else SwitchportMode.ACCESS
        elif w[:2] == ["port", "link-type"] and n == 3 and w[2] in ("access", "trunk", "hybrid"):
            self._link_type[name] = w[2]
        elif w[:3] == ["port", "access", "vlan"] and n == 4:
            iface.access_vlan = int(w[3])
        elif w[:4] == ["port", "trunk", "permit", "vlan"]:
            if w[4:] == ["all"]:
                self._permit[name] = []
            else:
                self._permit.setdefault(name, [1]).extend(vlan_list(w[4:]))
        elif w[:5] == ["undo", "port", "trunk", "permit", "vlan"]:
            removed = set(vlan_list(w[5:]))
            self._permit[name] = [v for v in self._permit.get(name, [1]) if v not in removed]
        elif w[:4] in (["port", "trunk", "pvid", "vlan"], ["port", "hybrid", "pvid", "vlan"]) and n == 5:
            self._pvid[name] = int(w[4])
        elif w[:3] == ["port", "hybrid", "vlan"] and w[-1] in ("tagged", "untagged"):
            target = self._hybrid_tagged if w[-1] == "tagged" else self._hybrid_untagged
            target.setdefault(name, []).extend(vlan_list(w[3:-1]))
        elif w[0] == "voice-vlan" and n == 3 and w[2] == "enable":
            iface.voice_vlan = int(w[1])
        elif w[:3] == ["port", "link-aggregation", "group"] and n == 4:
            iface.lag = f"Port-channel{w[3]}"
            if iface.lag not in self.device.interfaces:
                self.device.interfaces[iface.lag] = Interface(iface.lag, InterfaceKind.LAG,
                                                              mode=SwitchportMode.ACCESS)
        elif w[:2] == ["link-aggregation", "mode"] and n == 3 and w[2] in ("dynamic", "static"):
            if w[2] == "dynamic":
                self._dynamic_lags.add(name)
        elif w[:2] == ["lacp", "mode"] and w[2:] == ["passive"]:
            iface.lacp_mode = LacpMode.PASSIVE
        elif w[:3] == ["ip", "binding", "vpn-instance"] and n == 4:
            iface.vrf = w[3]
            if w[3] not in self.device.vrfs:
                self.device.vrfs.append(w[3])
        elif w[:2] == ["ip", "address"] and n >= 3:
            if w[2] in ("dhcp-alloc", "dhcp"):
                iface.dhcp_client = True
                return n == 3
            secondary = w[-1] == "sub"
            args = w[2:-1] if secondary else w[2:]
            value = _cidr(args[0], args[1]) if len(args) == 2 else str(ipaddress.ip_interface(args[0]))
            if secondary:
                iface.ipv4.append(value)
            else:
                iface.ipv4.insert(0, value)
            return len(args) in (1, 2)
        elif w[:2] == ["ipv6", "address"] and n == 3 and "/" in w[2]:
            iface.ipv6.append(str(ipaddress.ip_interface(w[2])))
        elif w == ["dhcp", "select", "relay"]:
            pass
        elif w[:3] == ["dhcp", "relay", "server-address"] and n == 4:
            iface.helper_addresses.append(w[3])
        elif w[0] == "packet-filter" and w[-1] in ("inbound", "outbound"):
            v6 = w[1:2] == ["ipv6"]
            args = w[2:-1] if v6 else w[1:-1]
            if args[:1] == ["name"]:
                args = args[1:]
            if len(args) != 1:
                return False
            setattr(iface, f"acl{'6' if v6 else ''}_{'in' if w[-1] == 'inbound' else 'out'}", args[0])
        elif w[:2] == ["vrrp", "vrid"]:
            return self._vrrp(iface, w[2:])
        elif w[:3] == ["undo", "vrrp", "vrid"]:
            return self._vrrp(iface, w[3:], preempt=False)
        elif w[:3] == ["vlan-type", "dot1q", "vid"] and n == 4:
            iface.encapsulation_vlan = int(w[3])
        elif w[0] == "speed" and n == 2:
            if w[1] != "auto":
                iface.speed = int(w[1])
        elif w[0] == "duplex" and n == 2:
            if w[1] != "auto":
                iface.duplex = w[1]
        elif w[:2] == ["jumbo-frame", "enable"] and n in (2, 3):
            iface.mtu = int(w[2]) if n == 3 else 9216
        elif w[0] == "mtu" and n == 2:
            iface.mtu = int(w[1])
        elif w[:2] == ["stp", "edged-port"] and w[2:] in ([], ["enable"]):
            iface.stp_portfast = True
        else:
            return False
        return True

    def _finish(self) -> None:
        for iface in self.device.interfaces.values():
            for group in iface.fhrp:
                group.version = self._vrrp_version
        for iface in self.device.interfaces.values():
            name = iface.name
            if iface.kind == InterfaceKind.LAG and iface.source_name.startswith("Route-Aggregation"):
                iface.mode = SwitchportMode.ROUTED
            if iface.mode == SwitchportMode.ROUTED or iface.kind not in (InterfaceKind.ETHERNET, InterfaceKind.LAG):
                continue
            if iface.stp_portfast and self._bpdu_protection:
                iface.stp_bpduguard = True
            link = self._link_type.get(name, "access")
            if link == "trunk":
                iface.mode = SwitchportMode.TRUNK
                iface.native_vlan = self._pvid.get(name)
                permit = self._permit.get(name, [1])
                iface.allowed_vlans = ranges(permit)  # "" = all
            elif link == "hybrid":
                self._hybrid(iface)
            else:
                iface.mode = SwitchportMode.ACCESS
        for iface in self.device.interfaces.values():
            if iface.kind == InterfaceKind.LAG:
                lacp = LacpMode.ACTIVE if iface.name in self._dynamic_lags else LacpMode.STATIC
                for member in self.device.interfaces.values():
                    if member.lag == iface.name and member.lacp_mode is None:
                        member.lacp_mode = lacp

    def _hybrid(self, iface: Interface) -> None:
        name = iface.name
        pvid: Optional[int] = self._pvid.get(name, 1)
        untagged = sorted(set(self._hybrid_untagged.get(name, [])))
        tagged = sorted(set(self._hybrid_tagged.get(name, [])))
        if iface.voice_vlan is not None and tagged == [iface.voice_vlan] and untagged in ([pvid], []):
            iface.mode = SwitchportMode.ACCESS
            iface.access_vlan = pvid
            return
        iface.mode = SwitchportMode.TRUNK
        iface.native_vlan = pvid if pvid in untagged else None
        iface.allowed_vlans = ranges(tagged + untagged) or "1"
        extra = [v for v in untagged if v != pvid]
        if extra:
            self.device.unparsed.append(Unparsed(iface.origin.line, f"port hybrid vlan {ranges(extra)} untagged",
                                                 f"{iface.source_name}: more than one untagged VLAN; only the PVID "
                                                 "stays untagged on a trunk"))


def parse(text: str) -> Device:
    return _Reader().read(text)
