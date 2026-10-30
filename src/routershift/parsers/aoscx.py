# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reader for HPE Aruba AOS-CX (10.x) ``show running-config``.

AOS-CX differs from the Cisco style in ways that matter to the model:

* Physical ports are named ``member/slot/port`` and start **shut down**; the
  configuration says ``no shutdown`` for every port that is up.
* ``routing`` / ``no routing`` decides whether a port is layer 3 or layer 2, and
  layer 2 ports take ``vlan access N`` / ``vlan trunk native N`` / ``vlan trunk allowed L``.
* LACP is configured on the LAG (``lacp mode active``), not on its members.
* The management port is ``interface mgmt``, always in VRF ``mgmt``, with its
  address as ``ip static`` and its gateway as ``default-gateway``.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Optional, Tuple

from .. import acl as acl_text
from .. import fhrp
from .. import confparse
from ..confparse import Node
from ..errors import ParseError
from ..model import (Acl, Device, FhrpGroup, Interface, InterfaceKind, LacpMode, Origin, StaticRoute, StpMode,
                     SwitchportMode, Unparsed, Vlan)
from .ioslike import _is_address, _vlan_ids

MGMT_VRF = "mgmt"

# Lines without meaning on another platform, or set by the software itself.
_NOISE = ("Current configuration", "!Version", "!export-password", "led locator", "end")


def canonical(name: str) -> Tuple[str, InterfaceKind]:
    """Canonical name and kind of an AOS-CX interface name (the words after ``interface``)."""
    words = name.split()
    if len(words) == 2:
        prefix = {"lag": ("Port-channel", InterfaceKind.LAG), "vlan": ("Vlan", InterfaceKind.VLAN),
                  "loopback": ("Loopback", InterfaceKind.LOOPBACK), "tunnel": ("Tunnel", InterfaceKind.TUNNEL)}
        if words[0] in prefix:
            word, kind = prefix[words[0]]
            return f"{word}{words[1]}", kind
    if name == "mgmt":
        return "Management1", InterfaceKind.MANAGEMENT
    if name[:1].isdigit():
        if "." in name:
            return f"Ethernet{name}", InterfaceKind.SUBINTERFACE
        return f"Ethernet{name}", InterfaceKind.ETHERNET
    return name, InterfaceKind.OTHER


class _Reader:
    def __init__(self) -> None:
        self.device = Device(platform="aoscx")
        self._routing: Dict[str, bool] = {}  # explicit routing / no routing per interface
        self._lag_lacp: Dict[str, LacpMode] = {}
        self._voice_vlans: List[int] = []

    def unparsed(self, node: Node, section: str = "") -> None:
        self.device.unparsed.append(Unparsed(node.line, node.text, section))
        for child in node.children:
            self.unparsed(child, section or node.text)

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
            "clock": self.clock,
            "ip": self.ip,
            "ipv6": self.ipv6,
            "ntp": self.ntp,
            "logging": self.logging,
            "vrf": self.vrf,
            "vlan": self.vlan,
            "spanning-tree": self.spanning_tree,
            "interface": self.interface,
            "access-list": self.acl,
            "router": self.router,
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
        self.device.system.hostname = node.words[1]
        return len(node.words) == 2

    def clock(self, node: Node) -> bool:
        if node.words[1:2] == ["timezone"] and len(node.words) == 3:
            self.device.system.timezone = node.words[2]
            return True
        return False

    def _service_vrf(self, args: List[str]) -> List[str]:
        """The arguments without a trailing ``vrf NAME``, noting the VRF."""
        if len(args) >= 2 and args[-2] == "vrf":
            self.device.system.service_vrf = args[-1]
            return args[:-2]
        return args

    def ip(self, node: Node) -> bool:
        w = node.words
        if w[1:3] == ["dns", "domain-name"] and len(w) == 4:
            self.device.system.domain_name = w[3]
            return True
        if w[1:3] == ["dns", "server-address"]:
            self.device.system.dns_servers.extend(self._service_vrf(w[3:]))
            return True
        if w[1:2] == ["route"]:
            return self.route(node, w[2:])
        return False

    def ipv6(self, node: Node) -> bool:
        if node.words[1:2] == ["route"]:
            return self.route(node, node.words[2:])
        return False

    def ntp(self, node: Node) -> bool:
        w = node.words
        if w == ["ntp", "enable"]:
            return True
        if w[1:2] == ["vrf"] and len(w) == 3:
            self.device.system.service_vrf = w[2]
            return True
        if w[1:2] == ["server"] and len(w) >= 3:
            self.device.system.ntp_servers.append(w[2])
            return all(word in ("iburst", "prefer") for word in w[3:])
        return False

    def logging(self, node: Node) -> bool:
        args = self._service_vrf(node.words[1:])
        if len(args) == 1 and _is_address(args[0]):
            self.device.system.syslog_servers.append(args[0])
            return True
        return False

    def vrf(self, node: Node) -> bool:
        if len(node.words) != 2:
            return False
        if node.words[1] != "default" and node.words[1] not in self.device.vrfs:
            self.device.vrfs.append(node.words[1])
        for child in node.children:
            if child.words[0] not in ("rd",):
                self.unparsed(child, node.text)
        return True

    def vlan(self, node: Node) -> bool:
        ids = _vlan_ids(node.words[1]) if len(node.words) == 2 else []
        if not ids:
            return False
        for vid in ids:
            vlan = self.device.vlans.setdefault(vid, Vlan(vid, origin=Origin(node.line, node.text)))
            for child in node.children:
                if child.words[0] == "name" and len(child.words) >= 2:
                    vlan.name = " ".join(child.words[1:])
                elif child.text == "shutdown":
                    vlan.shutdown = True
                elif child.text == "voice":
                    self._voice_vlans.append(vid)
                elif child.text == "no shutdown":
                    pass
                elif vid == ids[0]:
                    self.unparsed(child, node.text)
        return True

    def spanning_tree(self, node: Node) -> bool:
        w = node.words
        if w == ["spanning-tree"]:
            if self.device.stp_mode is None:
                self.device.stp_mode = StpMode.MSTP  # the AOS-CX default mode
            return True
        if w[1:2] == ["mode"] and len(w) == 3 and w[2] in ("mstp", "rpvst"):
            self.device.stp_mode = StpMode.MSTP if w[2] == "mstp" else StpMode.RAPID_PVST
            return True
        return False

    def route(self, node: Node, args: List[str]) -> bool:
        route = StaticRoute(str(ipaddress.ip_network(args[0], strict=False)), origin=Origin(node.line, node.text))
        rest = args[1:]
        ok = True
        while rest:
            word = rest.pop(0)
            if word == "vrf" and rest:
                route.vrf = rest.pop(0)
            elif word == "distance" and rest:
                route.distance = int(rest.pop(0))
            elif word == "tag" and rest:
                rest.pop(0)
                ok = False
            elif word in ("blackhole", "reject", "nullroute"):
                route.discard = True
            elif _is_address(word) and not route.next_hop:
                route.next_hop = word
            elif not route.interface:
                route.interface, _ = canonical(word)
            else:
                ok = False
        self.device.static_routes.append(route)
        if not ok:
            self.device.unparsed.append(Unparsed(node.line, node.text, "ip route (options not converted)"))
        return True

    def acl(self, node: Node) -> bool:
        """access-list ip NAME / access-list ipv6 NAME, entries "10 permit tcp 10.0.0.0/255.255.255.0 any eq 443"."""
        w = node.words
        if len(w) != 3 or w[1] not in ("ip", "ipv6"):
            return False
        family = 6 if w[1] == "ipv6" else 4
        acl = self.device.acls.setdefault(w[2], Acl(w[2], family=family))
        acl_text.read_block(acl, node.children, wildcards=False)
        return True

    # interfaces ------------------------------------------------------------------------------------------------------

    def router(self, node: Node) -> bool:
        return node.words == ["router", "vrrp", "enable"]  # implied by the groups

    def interface(self, node: Node) -> bool:
        source = " ".join(node.words[1:])
        canon, kind = canonical(source)
        iface = Interface(canon, kind, source_name=source, origin=Origin(node.line, node.text))
        if kind in (InterfaceKind.ETHERNET, InterfaceKind.SUBINTERFACE):
            iface.shutdown = True  # ports start shut down on AOS-CX
        if kind == InterfaceKind.SUBINTERFACE:
            iface.parent = canon.rsplit(".", 1)[0]
        if kind == InterfaceKind.MANAGEMENT:
            iface.vrf = MGMT_VRF
            if MGMT_VRF not in self.device.vrfs:
                self.device.vrfs.append(MGMT_VRF)
        self.device.interfaces[canon] = iface
        for child in node.children:
            if child.words[0] == "vrrp" and child.words[2:] == ["address-family", "ipv4"]:
                self._vrrp(iface, child)
                continue
            try:
                understood = self.interface_line(iface, child.words)
            except (ValueError, IndexError):
                understood = False
            if not understood:
                self.unparsed(child, node.text)
        return True

    def _vrrp(self, iface: Interface, node: Node) -> None:
        """vrrp N address-family ipv4, with its settings inside; a group is shut down until 'no shutdown'."""
        group = FhrpGroup("vrrp", int(node.words[1]), shutdown=True, origin=Origin(node.line, node.text))
        iface.fhrp.append(group)
        for child in node.children:
            w = child.words
            n = len(w)
            if w[0] == "address" and n == 3 and w[2] in ("primary", "secondary"):
                address = str(ipaddress.IPv4Address(w[1]))
                if w[2] == "primary":
                    group.address = address
                else:
                    group.secondary.append(address)
            elif w[0] == "priority" and n == 2:
                group.priority = int(w[1])
            elif w == ["no", "preempt"]:
                group.preempt = False
            elif w == ["preempt"]:
                group.preempt = True
            elif w[0] == "version" and n == 2 and w[1] in ("2", "3"):
                group.version = int(w[1])
            elif w[:2] == ["timers", "advertise"] and n == 3:
                group.hello_ms = int(w[2])
            elif w == ["shutdown"]:
                group.shutdown = True
            elif w == ["no", "shutdown"]:
                group.shutdown = False
            else:
                self.unparsed(child, node.text)

    def _active_gateway(self, iface: Interface, w: List[str]) -> bool:
        """active-gateway ip mac M / active-gateway ip A [mac M]"""
        group = next((g for g in iface.fhrp if g.protocol == "anycast"), None)
        if group is None:
            group = FhrpGroup("anycast")
            iface.fhrp.append(group)
        if w[0] == "mac" and len(w) == 2:
            group.mac = fhrp.mac(w[1])
            return True
        address = str(ipaddress.IPv4Address(w[0]))
        if group.address:
            group.secondary.append(address)
        else:
            group.address = address
        if w[1:2] == ["mac"] and len(w) == 3:
            group.mac = fhrp.mac(w[2])
            return True
        return len(w) == 1

    def interface_line(self, iface: Interface, w: List[str]) -> bool:
        n = len(w)
        if w[0] == "description":
            iface.description = " ".join(w[1:])
        elif w == ["shutdown"]:
            iface.shutdown = True
        elif w == ["no", "shutdown"]:
            iface.shutdown = False
        elif w == ["routing"]:
            self._routing[iface.name] = True
        elif w == ["no", "routing"]:
            self._routing[iface.name] = False
        elif w[0] == "mtu" and n == 2:
            iface.mtu = int(w[1])
        elif w[0] == "speed" and n == 2:
            return self._speed(iface, w[1])
        elif w[:2] == ["vlan", "access"] and n == 3:
            iface.access_vlan = int(w[2])
            iface.mode = SwitchportMode.ACCESS
        elif w[:3] == ["vlan", "trunk", "native"] and n >= 4:
            iface.native_vlan = int(w[3])
            iface.mode = SwitchportMode.TRUNK
            return n == 4  # "tag" (native VLAN tagged) has no equivalent in the model
        elif w[:3] == ["vlan", "trunk", "allowed"] and n == 4:
            vlans = "" if w[3] == "all" else w[3]
            iface.allowed_vlans = ",".join(p for p in (iface.allowed_vlans, vlans) if p)
            iface.mode = SwitchportMode.TRUNK
        elif w[0] == "lag" and n == 2:
            iface.lag = f"Port-channel{w[1]}"
            if iface.lag not in self.device.interfaces:
                self.device.interfaces[iface.lag] = Interface(iface.lag, InterfaceKind.LAG)
        elif w[:2] == ["lacp", "mode"] and n == 3 and w[2] in ("active", "passive"):
            self._lag_lacp[iface.name] = LacpMode(w[2])
        elif w[:2] == ["vrf", "attach"] and n == 3:
            iface.vrf = w[2]
            if w[2] not in self.device.vrfs:
                self.device.vrfs.append(w[2])
        elif w[:2] == ["ip", "address"] and n in (3, 4):
            if n == 4 and w[3] != "secondary":
                return False
            value = str(ipaddress.ip_interface(w[2]))
            if n == 4:
                iface.ipv4.append(value)
            else:
                iface.ipv4.insert(0, value)
        elif w[:2] == ["ip", "static"] and n == 3:  # mgmt
            iface.ipv4.insert(0, str(ipaddress.ip_interface(w[2])))
        elif w == ["ip", "dhcp"]:
            iface.dhcp_client = True
        elif w[:2] == ["ipv6", "address"] and n == 3 and "/" in w[2]:
            iface.ipv6.append(str(ipaddress.ip_interface(w[2])))
        elif w[:2] == ["apply", "access-list"] and n == 5 and w[2] in ("ip", "ipv6") and w[4] in (
                "in", "out", "routed-in", "routed-out"):
            setattr(iface, f"acl{'6' if w[2] == 'ipv6' else ''}_{w[4].replace('routed-', '')}", w[3])
        elif w[:2] == ["ip", "helper-address"] and n >= 3:
            iface.helper_addresses.append(w[2])
            if n == 5 and w[3] == "vrf":
                return False  # relay through another VRF: not in the model
            return n == 3
        elif w[0] == "default-gateway" and n == 2:  # mgmt
            self.device.static_routes.append(StaticRoute("0.0.0.0/0" if ":" not in w[1] else "::/0",
                                                         next_hop=w[1], vrf=iface.vrf or MGMT_VRF))
        elif w[:2] == ["encapsulation", "dot1q"] and n == 3:
            iface.encapsulation_vlan = int(w[2])
        elif w[:2] == ["active-gateway", "ip"] and n >= 3:
            return self._active_gateway(iface, w[2:])
        elif w[:2] == ["spanning-tree", "port-type"] and n == 3 and w[2] in ("admin-edge", "admin-network"):
            iface.stp_portfast = w[2] == "admin-edge"
        elif w == ["spanning-tree", "bpdu-guard"]:
            iface.stp_bpduguard = True
        else:
            return False
        return True

    def _speed(self, iface: Interface, value: str) -> bool:
        # 10.x: "speed 1000-full", "speed 100-half", "speed auto"
        if value == "auto":
            return True
        number, _, duplex = value.partition("-")
        if not number.isdigit() or duplex not in ("", "full", "half"):
            return False
        iface.speed = int(number)
        iface.duplex = duplex
        return True

    def _finish(self) -> None:
        for iface in self.device.interfaces.values():
            self._voice_port(iface)
        for iface in self.device.interfaces.values():
            if iface.kind not in (InterfaceKind.ETHERNET, InterfaceKind.LAG):
                continue
            routed = self._routing.get(iface.name)
            if routed is None:
                routed = bool(iface.ipv4 or iface.ipv6 or iface.dhcp_client)
            if routed:
                iface.mode = SwitchportMode.ROUTED
            elif iface.mode == SwitchportMode.ROUTED:
                iface.mode = SwitchportMode.ACCESS  # layer 2 without VLAN settings: access VLAN 1
            if iface.kind == InterfaceKind.LAG:
                lacp: Optional[LacpMode] = self._lag_lacp.get(iface.name, LacpMode.STATIC)
                for member in self.device.interfaces.values():
                    if member.lag == iface.name:
                        member.lacp_mode = lacp
        for iface in self.device.interfaces.values():
            if iface.lag and iface.lacp_mode is None:
                iface.lacp_mode = LacpMode.STATIC


    def _voice_port(self, iface: Interface) -> None:
        """A trunk whose native VLAN is the data VLAN and that only adds a voice VLAN is an access port with a
        voice VLAN on the Cisco-style platforms."""
        if iface.mode != SwitchportMode.TRUNK or iface.native_vlan is None or not iface.allowed_vlans:
            return
        try:
            allowed = set(_vlan_ids(iface.allowed_vlans))
        except ValueError:
            return
        voice = [v for v in allowed if v in self._voice_vlans and v != iface.native_vlan]
        if len(voice) == 1 and allowed == {iface.native_vlan, voice[0]}:
            iface.mode = SwitchportMode.ACCESS
            iface.access_vlan, iface.voice_vlan = iface.native_vlan, voice[0]
            iface.native_vlan, iface.allowed_vlans = None, ""


def parse(text: str) -> Device:
    return _Reader().read(text)
