# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reader for HPE Aruba AOS-S (ProCurve / ProVision, 16.x) ``show running-config``.

AOS-S is VLAN-centric: a port's VLANs are not set on the port but listed in each
VLAN (``untagged 1-3,Trk1`` / ``tagged 49``). The reader turns that around into
access and trunk ports. Other differences from the Cisco style:

* Ports are numbered ``1``, ``A1`` (modular chassis) or ``1/1`` (stacks);
  link aggregations are trunks ``Trk1`` made by ``trunk 49-50 trk1 lacp``.
* Layer 3 lives on VLANs only; there are no routed ports and no VRFs.
* The out-of-band management port is the ``oobm`` block.
* Time zones are a fixed offset in minutes (``time timezone 60``).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from .. import confparse
from ..confparse import Node
from ..errors import ParseError
from ..model import (Device, Interface, InterfaceKind, LacpMode, Origin, StaticRoute, StpMode, SwitchportMode,
                     Unparsed, Vlan)
from ..timezones import utc
from .ioslike import _cidr, _is_address

OOBM_VRF = "oobm"

_NOISE = (";", "Running configuration", "exit", "module ", "flexible-module ", "stacking", "member ")
_PORT = re.compile(r"^(.*?)(\d+)$")


def unquote(text: str) -> str:
    return text[1:-1] if len(text) >= 2 and text[0] == text[-1] == '"' else text


def ports(text: str) -> List[str]:
    """The ports of a port list: ``1-3,5,A1-A4,Trk1,1/1-1/4``."""
    result: List[str] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" not in part:
            result.append(part)
            continue
        first, last = part.split("-", 1)
        m1, m2 = _PORT.match(first), _PORT.match(last)
        if not m1 or not m2 or m1.group(1).lower() != m2.group(1).lower():
            raise ValueError(f"port range {part}")
        result.extend(f"{m1.group(1)}{n}" for n in range(int(m1.group(2)), int(m2.group(2)) + 1))
    return result


def canonical(name: str) -> Tuple[str, InterfaceKind]:
    if name.lower().startswith("trk") and name[3:].isdigit():
        return f"Port-channel{name[3:]}", InterfaceKind.LAG
    return f"Ethernet{name}", InterfaceKind.ETHERNET


def _port_key(name: str) -> Tuple[str, int]:
    m = _PORT.match(name)
    return (m.group(1), int(m.group(2))) if m else (name, 0)


class _Reader:
    def __init__(self) -> None:
        self.device = Device(platform="aoss")
        self.untagged: Dict[str, int] = {}  # canonical port -> VLAN
        self.no_untagged: Set[str] = set()
        self.tagged: Dict[str, List[int]] = {}
        self.voice_vlans: Set[int] = set()
        self.routing = False
        self.default_gateway: Optional[StaticRoute] = None

    def unparsed(self, node: Node, section: str = "") -> None:
        self.device.unparsed.append(Unparsed(node.line, node.text, section))
        for child in node.children:
            if child.text != "exit":
                self.unparsed(child, section or node.text)

    def port(self, name: str) -> Interface:
        canon, kind = canonical(name)
        if canon not in self.device.interfaces:
            self.device.interfaces[canon] = Interface(canon, kind, source_name=name if kind == InterfaceKind.ETHERNET
                                                      else f"Trk{canon[len('Port-channel'):]}")
        return self.device.interfaces[canon]

    def read(self, text: str) -> Device:
        roots, banners = confparse.read(text)
        if not roots:
            raise ParseError("no configuration lines found")
        for banner in banners:
            if banner.kind == "motd":
                self.device.system.banner_motd = banner.text
            else:
                self.device.unparsed.append(Unparsed(banner.line, f"banner {banner.kind}", "banner"))
        handlers: Dict[str, Callable[[Node], bool]] = {
            "hostname": self.hostname,
            "time": self.time,
            "sntp": self.sntp,
            "ntp": self.ntp,
            "timesync": lambda node: len(node.words) == 2,
            "ip": self.ip,
            "ipv6": self.ipv6,
            "logging": self.logging,
            "trunk": self.trunk,
            "oobm": self.oobm,
            "interface": self.interface,
            "vlan": self.vlan,
            "spanning-tree": self.spanning_tree,
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

    def hostname(self, node: Node) -> bool:
        self.device.system.hostname = unquote(node.text.split(None, 1)[1])
        return True

    def time(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["timezone"] and len(w) == 3:
            self.device.system.timezone = utc(int(w[2]))
            return True
        return False

    def sntp(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["server"]:
            args = w[2:]
            if args[:1] == ["priority"]:
                args = args[2:]
            self.device.system.ntp_servers.append(args[0])
            return len(args) == 1
        return w[1:] in (["unicast"], ["broadcast"])

    def ntp(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["server"] and len(w) >= 3:
            self.device.system.ntp_servers.append(w[2])
            return all(word in ("iburst", "burst") for word in w[3:])
        return w[1:] in (["enable"], ["unicast"])

    def logging(self, node: Node) -> bool:
        if len(node.words) == 2 and _is_address(node.words[1]):
            self.device.system.syslog_servers.append(node.words[1])
            return True
        return False

    def ip(self, node: Node) -> bool:
        w = node.words
        if w[1:] == ["routing"]:
            self.routing = True
            return True
        if w[1:3] == ["dns", "domain-name"] and len(w) == 4:
            self.device.system.domain_name = unquote(w[3])
            return True
        if w[1:3] == ["dns", "server-address"]:
            args = w[3:]
            if args[:1] == ["priority"]:
                args = args[2:]
            self.device.system.dns_servers.extend(args)
            return True
        if w[1:2] == ["default-gateway"] and len(w) == 3:
            self.default_gateway = StaticRoute("0.0.0.0/0", next_hop=w[2], origin=Origin(node.line, node.text))
            return True
        if w[1:2] == ["route"] and len(w) >= 5:
            prefix = str(ipaddress.ip_network(f"{w[2]}/{w[3]}", strict=False))
            return self.route(node, prefix, w[4:])
        return False

    def ipv6(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["route"] and len(w) >= 4:
            return self.route(node, str(ipaddress.ip_network(w[2], strict=False)), w[3:])
        return w[1:] in (["unicast-routing"],)

    def route(self, node: Node, prefix: str, args: List[str]) -> bool:
        route = StaticRoute(prefix, origin=Origin(node.line, node.text))
        ok = True
        while args:
            word = args.pop(0)
            if word in ("blackhole", "reject"):
                route.discard = True
            elif word == "distance" and args:
                route.distance = int(args.pop(0))
            elif word == "name" and args:
                route.name = unquote(" ".join(args))  # quoted, possibly with spaces; always last
                args = []
            elif word == "vlan" and args:
                route.interface = f"Vlan{args.pop(0)}"
            elif _is_address(word) and not route.next_hop:
                route.next_hop = word
            else:
                ok = False
        self.device.static_routes.append(route)
        if not ok:
            self.device.unparsed.append(Unparsed(node.line, node.text, "ip route (options not converted)"))
        return True

    def trunk(self, node: Node) -> bool:
        w = node.words
        if len(w) not in (3, 4):
            return False
        lag = self.port(w[2][0].upper() + w[2][1:])
        kind = w[3] if len(w) == 4 else "trunk"
        if kind not in ("lacp", "trunk", "dt-lacp", "dt-trunk"):
            return False
        for name in ports(w[1]):
            member = self.port(name)
            member.lag = lag.name
            member.lacp_mode = LacpMode.ACTIVE if "lacp" in kind else LacpMode.STATIC
        return not kind.startswith("dt-")  # distributed trunks: kept for the report

    def oobm(self, node: Node) -> bool:
        mgmt = Interface("Management1", InterfaceKind.MANAGEMENT, source_name="oobm", vrf=OOBM_VRF,
                         origin=Origin(node.line, node.text))
        self.device.interfaces[mgmt.name] = mgmt
        self.device.vrfs.append(OOBM_VRF)
        for child in node.children:
            w = child.words
            if w == ["exit"]:
                continue
            if w[:2] == ["ip", "address"] and len(w) == 4:
                mgmt.ipv4.append(_cidr(w[2], w[3]))
            elif w[:2] == ["ip", "address"] and w[2:] in (["dhcp-bootp"], ["dhcp"]):
                mgmt.dhcp_client = True
            elif w[:2] == ["ip", "default-gateway"] and len(w) == 3:
                self.device.static_routes.append(StaticRoute("0.0.0.0/0", next_hop=w[2], vrf=OOBM_VRF,
                                                             origin=Origin(child.line, child.text)))
            elif w in (["enable"], ["interface", "enable"]):
                pass
            elif w in (["disable"], ["interface", "disable"]):
                mgmt.shutdown = True
            else:
                self.unparsed(child, node.text)
        return True

    def interface(self, node: Node) -> bool:
        if len(node.words) == 3 and node.words[1] == "loopback":
            loop = Interface(f"Loopback{node.words[2]}", InterfaceKind.LOOPBACK, source_name=f"loopback {node.words[2]}",
                             origin=Origin(node.line, node.text))
            self.device.interfaces[loop.name] = loop
            for child in node.children:
                w = child.words
                if w[:2] == ["ip", "address"] and len(w) == 3:
                    loop.ipv4.append(str(ipaddress.ip_interface(w[2])))
                elif w[:2] == ["ip", "address"] and len(w) == 4:
                    loop.ipv4.append(_cidr(w[2], w[3]))
                elif w != ["exit"]:
                    self.unparsed(child, node.text)
            return True
        if len(node.words) != 2:
            return False
        for name in ports(node.words[1]):
            iface = self.port(name)
            iface.origin = Origin(node.line, node.text)
            for child in node.children:
                if not self.interface_line(iface, child.words) and name == ports(node.words[1])[0]:
                    self.unparsed(child, node.text)
        return True

    def interface_line(self, iface: Interface, w: List[str]) -> bool:
        if w == ["exit"] or w == ["enable"]:
            return True
        if w == ["disable"]:
            iface.shutdown = True
        elif w[0] == "name" and len(w) >= 2:
            iface.description = unquote(" ".join(w[1:]))
        elif w[0] == "speed-duplex" and len(w) == 2:
            if w[1] == "auto":
                return True
            m = re.match(r"^(\d+)-(full|half)$", w[1])
            if not m:
                return False
            iface.speed, iface.duplex = int(m.group(1)), m.group(2)
        else:
            return False
        return True

    def vlan(self, node: Node) -> bool:
        w = node.words
        if len(w) != 2 or not w[1].isdigit():
            return False
        vid = int(w[1])
        vlan = self.device.vlans.setdefault(vid, Vlan(vid, origin=Origin(node.line, node.text)))
        svi: Optional[Interface] = None

        def l3() -> Interface:
            nonlocal svi
            if svi is None:
                svi = Interface(f"Vlan{vid}", InterfaceKind.VLAN, source_name=f"vlan {vid}",
                                origin=Origin(node.line, node.text))
                self.device.interfaces[svi.name] = svi
            return svi

        for child in node.children:
            c = child.words
            try:
                if c == ["exit"]:
                    continue
                if c[0] == "name" and len(c) >= 2:
                    vlan.name = unquote(child.text.split(None, 1)[1])
                elif c[0] == "untagged" and len(c) == 2:
                    for name in ports(c[1]):
                        self.untagged[self.port(name).name] = vid
                elif c[:2] == ["no", "untagged"] and len(c) == 3:
                    self.no_untagged.update(self.port(name).name for name in ports(c[2]))
                elif c[0] == "tagged" and len(c) == 2:
                    for name in ports(c[1]):
                        self.tagged.setdefault(self.port(name).name, []).append(vid)
                elif c == ["voice"]:
                    self.voice_vlans.add(vid)
                elif c[:2] == ["ip", "address"] and c[2:] in (["dhcp-bootp"], ["dhcp"]):
                    l3().dhcp_client = True
                elif c[:2] == ["ip", "address"] and len(c) == 4:
                    l3().ipv4.append(_cidr(c[2], c[3]))
                elif c[:2] == ["ip", "address"] and len(c) == 3 and "/" in c[2]:
                    l3().ipv4.append(str(ipaddress.ip_interface(c[2])))
                elif c[:2] == ["ipv6", "address"] and len(c) == 3 and "/" in c[2]:
                    l3().ipv6.append(str(ipaddress.ip_interface(c[2])))
                elif c[:2] == ["ip", "helper-address"] and len(c) == 3:
                    l3().helper_addresses.append(c[2])
                elif c in (["no", "ip", "address"], ["ipv6", "enable"]):
                    pass
                else:
                    self.unparsed(child, node.text)
            except (ValueError, IndexError):
                self.unparsed(child, node.text)
        return True

    def spanning_tree(self, node: Node) -> bool:
        w = node.words
        if w == ["spanning-tree"]:
            if self.device.stp_mode is None:
                self.device.stp_mode = StpMode.MSTP
            return True
        if w[1:] == ["force-version", "rstp-operation"]:
            self.device.stp_mode = StpMode.RSTP
            return True
        if w[1:3] == ["mode", "rapid-pvst"]:
            self.device.stp_mode = StpMode.RAPID_PVST
            return True
        if w[1:] == ["mode", "mstp"]:
            self.device.stp_mode = StpMode.MSTP
            return True
        if len(w) == 3 and w[2] in ("admin-edge-port", "bpdu-protection"):
            for name in ports(w[1]):
                iface = self.port(name)
                if w[2] == "admin-edge-port":
                    iface.stp_portfast = True
                else:
                    iface.stp_bpduguard = True
            return True
        return False

    # VLAN membership to ports ----------------------------------------------------------------------------------------

    def _finish(self) -> None:
        for iface in self.device.interfaces.values():
            if iface.kind not in (InterfaceKind.ETHERNET, InterfaceKind.LAG):
                continue
            if iface.lag:
                iface.mode = SwitchportMode.ACCESS  # the trunk carries the VLANs
                continue
            untagged = self.untagged.get(iface.name)
            if untagged is None and iface.name not in self.no_untagged:
                untagged = 1  # every port starts untagged in VLAN 1
            tagged = sorted(set(self.tagged.get(iface.name, [])))
            voice = [v for v in tagged if v in self.voice_vlans]
            if not tagged:
                iface.mode = SwitchportMode.ACCESS
                iface.access_vlan = untagged
            elif untagged is not None and voice == tagged and len(voice) == 1:
                iface.mode = SwitchportMode.ACCESS
                iface.access_vlan, iface.voice_vlan = untagged, voice[0]
            else:
                iface.mode = SwitchportMode.TRUNK
                iface.native_vlan = untagged
                allowed = sorted(set(tagged) | ({untagged} if untagged is not None else set()))
                iface.allowed_vlans = ",".join(str(v) for v in allowed)
                if untagged is None:
                    self.device.unparsed.append(Unparsed(iface.origin.line, f"no untagged {iface.source_name}",
                                                         "a trunk without an untagged VLAN (native VLAN 1 on the "
                                                         "Cisco-style platforms): tag the native VLAN by hand"))
        if self.default_gateway and not any(r.prefix == "0.0.0.0/0" and not r.vrf for r in self.device.static_routes):
            self.device.static_routes.insert(0, self.default_gateway)
        # Ports in the order of the switch, LAGs after them
        physical = sorted((i for i in self.device.interfaces.values() if i.kind == InterfaceKind.ETHERNET),
                          key=lambda i: _port_key(i.source_name))
        others = [i for i in self.device.interfaces.values() if i.kind != InterfaceKind.ETHERNET]
        order = {InterfaceKind.MANAGEMENT: 0, InterfaceKind.ETHERNET: 1, InterfaceKind.LAG: 2}
        self.device.interfaces = {i.name: i for i in sorted(physical + others, key=lambda i: order.get(i.kind, 3))}


def parse(text: str) -> Device:
    return _Reader().read(text)
