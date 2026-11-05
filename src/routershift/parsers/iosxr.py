# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reader for Cisco IOS-XR (ASR 9000, NCS 5500/540, 8000; 7.x) ``show running-config``.

IOS-XR looks like IOS but is built differently:

* Ports are named rack/slot/module/port (``TenGigE0/0/0/4``), LAGs are ``Bundle-EtherN`` (members join with
  ``bundle id N mode active``), the management port is ``MgmtEth0/RP0/CPU0/0``.
* Addresses take a mask (``ipv4 address A M``); the VRF comes first in an interface.
* Routing protocols hold their interfaces: OSPF areas, IS-IS, MPLS LDP, HSRP and VRRP list the interfaces they run on.
* Static routes live under ``router static``, per VRF and address family.
* Policies are RPL: prefix sets, community sets, AS-path sets and route policies (see iosxrpolicy.py). BGP neighbors
  are blocks with their address families inside; neighbor groups play the part of peer groups.
* There are no VLANs or switchports. Layer 2 is bridge domains (``l2vpn / bridge group / bridge-domain``) of
  ``l2transport`` interfaces, routed through a ``BVI``. A bridge domain named ``VLANn`` (as RouterShift writes it)
  or carrying ``encapsulation dot1q n`` subinterfaces is read as VLAN n: a whole-port member is an access port, tagged
  subinterface members make the port a trunk, an ``encapsulation untagged`` member is its native VLAN.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, Dict, List, Optional, Tuple

from .. import aaa as aaa_text
from .. import bgp as bgp_text
from .. import confparse
from .. import iosxrabf as abf
from .. import iosxrl2 as l2
from .. import iosxrpolicy as policy
from .. import iosxrservices as services
from .. import iosxrrouting as xrrouting
from .. import mgmt as mgmt_text
from .. import multicast as multicast_text
from ..acl import read_block
from ..stp import vlan_text
from ..confparse import Node
from ..errors import ParseError
from ..model import (Acl, AaaGroup, AaaMethod, AaaServer, BgpNeighbor, BgpVrf, Device, FhrpGroup, Interface,
                     InterfaceKind, Isis, LacpMode, LocalUser, NtpKey, Origin, Ospf, SnmpCommunity, SnmpGroup,
                     SnmpHost, SnmpUser, StaticRoute, SwitchportMode, Unparsed, Vlan, VrfInfo)
from .ioslike import _vlan_ids

# IOS-XR port prefixes, longest first, with the speed class
_PHYSICAL: List[Tuple[str, str]] = [
    ("FourHundredGigE", "400g"), ("HundredGigE", "100g"), ("FiftyGigE", "50g"), ("FortyGigE", "40g"),
    ("TwentyFiveGigE", "25g"), ("TenGigE", "10g"), ("GigabitEthernet", "1g"), ("FastEthernet", "100m"),
]
_LOGICAL: List[Tuple[str, str, InterfaceKind]] = [
    ("Bundle-Ether", "Port-channel", InterfaceKind.LAG), ("BVI", "Vlan", InterfaceKind.VLAN),
    ("Loopback", "Loopback", InterfaceKind.LOOPBACK), ("tunnel-ip", "Tunnel", InterfaceKind.TUNNEL),
    ("Null", "Null", InterfaceKind.OTHER),
]
HASH_TYPES = {"5": "md5-crypt", "8": "iosxr-sha256", "9": "iosxr-scrypt", "10": "sha512-crypt"}
ADMIN_GROUPS = ("root-lr", "root-system", "netadmin", "sysadmin", "cisco-support", "serviceadmin")
OPERATOR_GROUPS = ("operator", "read-only-tg")
_NOISE = ("!!", "end", "Building configuration", "ipv6 enable")
_VPN_REASON = ("MPLS L3VPN (VPNv4) peering",
               "VPNv4/VPNv6 address families are not converted yet; activate them on the target")


def _mask_prefix(address: str, mask: str) -> str:
    return str(ipaddress.ip_interface(f"{address}/{mask}"))


class _Reader:
    def __init__(self) -> None:
        self.device = Device(platform="iosxr")
        self._mgmt: Dict[str, str] = {}
        self._l2: Dict[str, Tuple[Node, str]] = {}  # l2transport interface (XR name) -> its node, encapsulation
        self._bundles: Dict[str, Tuple[str, LacpMode]] = {}  # canonical member -> (canonical bundle, mode)
        self._reason: Optional[Tuple[str, str]] = None
        self._rip: List[str] = []  # the interfaces under router rip
        self.flows = services.FlowReader(self.device, self.name, self.unparsed)
        self._abf = abf.Reader(self.device)
        self._l2s = l2.Reader(self.device)

    # names -----------------------------------------------------------------------------------------------------------

    def canonical(self, name: str) -> Tuple[str, InterfaceKind, str]:
        """Canonical name, kind and speed class of an IOS-XR interface name."""
        base, _, sub = name.partition(".")
        if base.startswith("MgmtEth"):
            if base not in self._mgmt:
                self._mgmt[base] = f"Management{len(self._mgmt) + 1}"
            return self._mgmt[base] + (f".{sub}" if sub else ""), (
                InterfaceKind.SUBINTERFACE if sub else InterfaceKind.MANAGEMENT), ""
        for prefix, media in _PHYSICAL:
            if base.startswith(prefix) and re.match(r"^\d[\d/]*$", base[len(prefix):]):
                number = base[len(prefix):]
                if sub:
                    return f"Ethernet{number}.{sub}", InterfaceKind.SUBINTERFACE, media
                return f"Ethernet{number}", InterfaceKind.ETHERNET, media
        for prefix, word, kind in _LOGICAL:
            if base.startswith(prefix) and base[len(prefix):].isdigit():
                if sub:
                    return f"{word}{base[len(prefix):]}.{sub}", InterfaceKind.SUBINTERFACE, ""
                return f"{word}{base[len(prefix):]}", kind, ""
        return name, InterfaceKind.OTHER, ""

    def name(self, text: str) -> str:
        return self.canonical(text)[0]

    def iface(self, xr_name: str, origin: Optional[Origin] = None) -> Interface:
        canonical, kind, media = self.canonical(xr_name)
        found = self.device.interfaces.get(canonical)
        if found is None:
            found = Interface(canonical, kind, source_name=xr_name, media=media)
            if kind == InterfaceKind.SUBINTERFACE:
                found.parent = canonical.rsplit(".", 1)[0]
            if origin is not None:
                found.origin = origin
            self.device.interfaces[canonical] = found
        return found

    # plumbing --------------------------------------------------------------------------------------------------------

    def unparsed(self, node: Node, section: str = "") -> None:
        group, reason = self._reason or ("", "")
        self.device.unparsed.append(Unparsed(node.line, node.text, section, group, reason))
        for child in node.children:
            self.unparsed(child, section or node.text)
        if not section:
            self._reason = None

    def children(self, node: Node, handler: Callable[[List[str], Node], bool], section: str = "") -> None:
        for child in node.children:
            try:
                ok = handler(child.words, child)
            except (ValueError, IndexError, KeyError):
                ok = False
            if not ok:
                self.unparsed(child, section or node.text)
            self._reason = None

    def read(self, text: str) -> Device:
        roots, banners = confparse.read(text)
        if not roots:
            raise ParseError("no configuration lines found")
        s = self.device.system
        for banner in banners:
            if banner.kind == "motd":
                s.banner_motd = banner.text
            elif banner.kind == "login":
                s.banner_login = banner.text
            elif banner.kind == "exec":
                s.banner_exec = banner.text
            else:
                self.device.unparsed.append(Unparsed(banner.line, f"banner {banner.kind}", "banner"))
        handlers: Dict[str, Callable[[Node], bool]] = {
            "hostname": lambda n: len(n.words) == 2 and self._set(s, "hostname", n.words[1]),
            "clock": self.clock,
            "logging": self.logging,
            "domain": self.domain,
            "username": self.username,
            "aaa": self.aaa,
            "tacacs-server": self.aaa_server,
            "radius-server": self.aaa_server,
            "tacacs": self.aaa_source,
            "radius": self.aaa_source,
            "line": self.line,
            "vty-pool": lambda n: n.words[:2] == ["vty-pool", "default"],
            "vrf": self.vrf,
            "ntp": self.ntp,
            "snmp-server": self.snmp,
            "ipv4": self.acl,
            "ipv6": self.acl,
            "prefix-set": lambda n: policy.read_prefix_set(self.device, n),
            "community-set": lambda n: policy.read_community_set(self.device, n),
            "as-path-set": lambda n: policy.read_as_path_set(self.device, n),
            "route-policy": lambda n: policy.read_route_policy(self.device, n),
            "end-set": lambda n: n.words == ["end-set"],
            "end-policy": lambda n: n.words == ["end-policy"],
            "interface": self.interface,
            "router": self.router,
            "mpls": self.mpls,
            "l2vpn": self.l2vpn,
            "spanning-tree": lambda n: l2.read_mst(self.device, n, self.iface, self.unparsed),
            "igmp": lambda n: n.words[:3] == ["igmp", "snooping", "profile"] and len(n.words) == 4 and
            self._l2s.profile(n.words[3], [c.words for c in n.children]),
            "lldp": self.lldp,
            "cdp": lambda n: n.words == ["cdp"] and self._set(self.device.management, "cdp", True),
            "ssh": self.ssh,
            "telnet": self.telnet,
            "netconf-yang": self.netconf,
            "grpc": self.grpc,
            "multicast-routing": self.multicast_routing,
            "dhcp": self.dhcp,
            "pool": lambda n: xrrouting.read_pool(self.device, n, self.children),
            "class-map": lambda n: services.read_class_map(self.device, n, self.unparsed),
            "policy-map": lambda n: services.read_policy_map(self.device, n, self.unparsed),
            "flow": self.flows.node,
            "sampler-map": self.flows.node,
            "monitor-session": lambda n: services.read_monitor_session(self.device, n, self.name, self.unparsed),
            "ipsla": lambda n: services.read_ipsla(self.device, n, self.unparsed),
            "track": lambda n: services.read_track(self.device, n, self.name, self.unparsed),
        }
        for node in roots:
            if node.text.startswith(_NOISE):
                continue
            handler = handlers.get(node.words[0])
            try:
                understood = handler is not None and handler(node)
            except (ValueError, IndexError, KeyError):
                understood = False
            if not understood:
                self.unparsed(node)
        self._finish()
        return self.device

    @staticmethod
    def _set(obj: object, attr: str, value: object) -> bool:
        setattr(obj, attr, value)
        return True

    # system ----------------------------------------------------------------------------------------------------------

    def clock(self, node: Node) -> bool:
        """clock timezone NAME REGION (7.x: an IANA region) or clock timezone NAME OFFSET"""
        w = node.words
        if w[1:2] != ["timezone"] or len(w) < 4:
            return False
        if "/" in w[3] or w[3] in ("UTC", "GMT"):
            self.device.system.timezone = w[3]
        else:
            self.device.system.timezone = " ".join(w[2:])
        return True

    def logging(self, node: Node) -> bool:
        s = self.device.system
        w = node.words
        if len(w) >= 2 and _is_address(w[1]):
            s.syslog_servers.append(w[1])
            args = w[2:]
            while args:
                if args[0] == "vrf" and len(args) >= 2:
                    if args[1] != "default":
                        s.service_vrf = s.service_vrf or args[1]
                    args = args[2:]
                elif args[0] == "severity" and len(args) >= 2:
                    s.logging_level = mgmt_text.level(args[1])
                    args = args[2:]
                elif args[0] == "port" and len(args) >= 2:
                    if int(args[1]) != 514:
                        s.syslog_transport[w[1]] = ("udp", int(args[1]))
                    args = args[2:]
                else:
                    return False
            return True
        if w[1:2] == ["trap"] and len(w) == 3:
            s.logging_level = mgmt_text.level(w[2])
            return s.logging_level is not None
        if w[1:2] == ["buffered"] and len(w) == 3:
            if w[2].isdigit():
                s.logging_buffer = int(w[2])
            else:
                s.logging_buffer_level = mgmt_text.level(w[2])
            return True
        if w[1:2] in (["console"], ["monitor"]) and len(w) == 3:
            value = -1 if w[2] == "disable" else mgmt_text.level(w[2])
            setattr(s, f"logging_{w[1]}_level", value)
            return value is not None
        if w[1:2] == ["source-interface"] and len(w) in (3, 5):
            s.logging_source = self.name(w[2])
            if len(w) == 5 and w[3] == "vrf" and w[4] != "default":
                s.service_vrf = s.service_vrf or w[4]
            return True
        if w[1:3] == ["hostnameprefix"] or w[1:2] == ["format"]:
            return False
        return False

    def domain(self, node: Node) -> bool:
        s = self.device.system
        w = node.words[1:]
        if w[:1] == ["vrf"] and len(w) >= 3:
            if w[1] != "default":
                s.service_vrf = s.service_vrf or w[1]
            w = w[2:]
        if w[:1] == ["name"] and len(w) == 2:
            s.domain_name = w[1]
            return True
        if w[:1] == ["list"] and len(w) == 2:
            s.dns_search.append(w[1])
            return True
        if w[:1] == ["name-server"] and len(w) == 2:
            s.dns_servers.append(w[1])
            return True
        if w == ["lookup", "disable"]:
            s.dns_lookup = False
            return True
        if w[:2] == ["lookup", "source-interface"] and len(w) == 3:
            s.dns_source = self.name(w[2])
            return True
        if w[:1] == ["ipv4"] and w[1:2] == ["host"] and len(w) == 4:
            s.dns_hosts[w[2]] = w[3]
            return True
        return False

    def username(self, node: Node) -> bool:
        if len(node.words) != 2:
            return False
        user = LocalUser(node.words[1], origin=Origin(node.line, node.text))
        groups: List[str] = []

        def child(w: List[str], n: Node) -> bool:
            if w[0] == "group" and len(w) == 2:
                groups.append(w[1])
                return True
            if w[0] in ("secret", "password") and len(w) == 3:
                kind, value = w[1], w[2]
                if kind == "0":
                    user.password = value
                elif kind == "7" and w[0] == "password":
                    user.password = aaa_text.decode_type7(value)
                elif kind in HASH_TYPES:
                    user.password_hash, user.hash_type = value, HASH_TYPES[kind]
                else:
                    return False
                return True
            if w[0] == "secret" and len(w) == 2:
                user.password = w[1]
                return True
            return False

        self.children(node, child)
        if any(g in ADMIN_GROUPS for g in groups):
            user.privilege = 15
        elif any(g in OPERATOR_GROUPS for g in groups):
            user.privilege = 1
        others = [g for g in groups if g not in ADMIN_GROUPS + OPERATOR_GROUPS]
        if others:
            user.role = others[0]
        self.device.users.append(user)
        return True

    def aaa(self, node: Node) -> bool:
        a = self.device.aaa
        w = node.words
        origin = Origin(node.line, node.text)
        if w[1:3] == ["group", "server"] and len(w) == 5 and w[3] in ("radius", "tacacs+"):
            group = AaaGroup("radius" if w[3] == "radius" else "tacacs", w[4], origin=origin)
            a.groups[group.name] = group

            def child(c: List[str], n: Node) -> bool:
                if c[0] == "server" and len(c) == 2:
                    group.servers.append(c[1])
                    return True
                if c[0] == "vrf" and len(c) == 2:
                    group.vrf = c[1]
                    return True
                return False

            self.children(node, child)
            return True
        if w[1:2] == ["password-policy"] and len(w) == 3:
            def rule(c: List[str], n: Node) -> bool:
                if c[0] == "min-length" and len(c) == 2:
                    self.device.management.password_min_length = int(c[1])
                    return True
                return False
            self.children(node, rule)
            return True
        if w[1] in ("authentication", "authorization", "accounting") and len(w) >= 5:
            method = AaaMethod(w[1], w[2], origin=origin)
            args = w[3:]
            if method.service == "commands" and method.kind == "authorization":
                method.level = 15
            if method.service not in ("login", "exec", "commands", "dot1x"):
                return False
            method.name, args = args[0], args[1:]
            if method.kind == "accounting":
                if not args or args[0] not in ("start-stop", "stop-only"):
                    return False
                method.record, args = args[0], args[1:]
                if method.service == "commands":
                    method.level = 15
            while args:
                if args[0] == "group" and len(args) >= 2:
                    method.methods.append(f"group:{ {'tacacs+': 'tacacs'}.get(args[1], args[1]) }".replace(" ", ""))
                    args = args[2:]
                elif args[0] in ("local", "none"):
                    method.methods.append(args[0])
                    args = args[1:]
                else:
                    return False
            a.methods.append(method)
            return True
        return False

    def aaa_server(self, node: Node) -> bool:
        """tacacs-server host A [port N] [key ...] (or radius-server host A auth-port N acct-port N), with the key
        on the line or inside the block."""
        w = node.words
        if w[1:2] != ["host"] or len(w) < 3:
            return False
        server = AaaServer("radius" if w[0] == "radius-server" else "tacacs", w[2], origin=Origin(node.line, node.text))

        def options(args: List[str]) -> bool:
            while args:
                if args[0] in ("port", "auth-port") and len(args) >= 2:
                    server.auth_port, args = int(args[1]), args[2:]
                elif args[0] == "acct-port" and len(args) >= 2:
                    server.acct_port, args = int(args[1]), args[2:]
                elif args[0] == "timeout" and len(args) >= 2:
                    server.timeout, args = int(args[1]), args[2:]
                elif args[0] == "key" and len(args) >= 2:
                    if len(args) >= 3 and args[1] in ("0", "7"):
                        server.key = args[2] if args[1] == "0" else aaa_text.decode_type7(args[2])
                        args = args[3:]
                    else:
                        server.key, args = args[1], args[2:]
                else:
                    return False
            return True

        if not options(w[3:]):
            return False
        self.children(node, lambda c, n: options(c))
        if server.protocol == "tacacs" and server.auth_port == 49:
            server.auth_port = None
        if server.protocol == "radius" and server.auth_port == 1812:
            server.auth_port = None
        if server.protocol == "radius" and server.acct_port == 1813:
            server.acct_port = None
        self.device.aaa.servers.append(server)
        return True

    def aaa_source(self, node: Node) -> bool:
        """tacacs|radius source-interface IF [vrf V]"""
        w = node.words
        if w[1:2] != ["source-interface"] or len(w) not in (3, 5):
            return False
        protocol = "radius" if w[0] == "radius" else "tacacs"
        self.device.aaa.source[protocol] = self.name(w[2])
        return True

    def line(self, node: Node) -> bool:
        m = self.device.management
        if node.words == ["line", "console"]:
            def console(c: List[str], n: Node) -> bool:
                if c[:2] == ["login", "authentication"] and len(c) == 3:
                    m.console_login = c[2]
                    return True
                return False
            self.children(node, console)
            return True
        if node.words not in (["line", "default"], ["line", "template", "vty"]):
            return False

        def child(c: List[str], n: Node) -> bool:
            if c[0] == "exec-timeout" and len(c) == 3:
                m.exec_timeout = int(c[1]) + (1 if int(c[2]) else 0)
                return True
            if c[:2] == ["access-class", "ingress"] and len(c) == 3:
                m.vty_acl = c[2]
                return True
            if c[:2] == ["transport", "input"]:
                words = set(c[2:])
                if "telnet" not in words and "all" not in words:
                    m.telnet = m.telnet if m.telnet else None
                return True
            if c[:2] == ["login", "authentication"] and len(c) == 3:
                return c[2] == "default"
            return False

        self.children(node, child)
        return True

    def vrf(self, node: Node) -> bool:
        if len(node.words) != 2:
            return False
        name = node.words[1]
        if name not in self.device.vrfs:
            self.device.vrfs.append(name)
        info = self.device.vrf_info.setdefault(name, VrfInfo())

        def af(c: List[str], n: Node) -> bool:
            if c[:2] in (["import", "route-target"], ["export", "route-target"]):
                targets = [x.words[0] for x in n.children]
                (info.rt_import if c[0] == "import" else info.rt_export).extend(targets)
                return all(len(x.words) == 1 for x in n.children)
            if c[:2] == ["export", "route-policy"] and len(c) == 3:
                info.export_map = c[2]
                return True
            return False

        def child(c: List[str], n: Node) -> bool:
            if c[0] == "address-family" and c[1:] in (["ipv4", "unicast"], ["ipv6", "unicast"]):
                self.children(n, af, node.text)
                return True
            if c[0] == "description":
                return True
            return False

        self.children(node, child)
        if info == VrfInfo():
            del self.device.vrf_info[name]
        return True

    def ntp(self, node: Node) -> bool:
        s = self.device.system
        if node.words != ["ntp"]:
            return False

        def child(c: List[str], n: Node) -> bool:
            if c[0] == "authentication-key" and len(c) >= 4:
                number = int(c[1])
                algorithm = c[2]
                if c[3] == "clear" and len(c) == 5:
                    key = c[4]
                elif c[3] == "encrypted" and len(c) == 5:
                    key = aaa_text.decode_type7(c[4])
                else:
                    return False
                s.ntp_keys[number] = NtpKey(number, algorithm, key, s.ntp_keys.get(number, NtpKey(number)).trusted)
                return True
            if c[0] == "trusted-key" and len(c) == 2:
                s.ntp_keys.setdefault(int(c[1]), NtpKey(int(c[1]))).trusted = True
                return True
            if c == ["authenticate"]:
                s.ntp_authenticate = True
                return True
            if c[0] == "server":
                args = c[1:]
                if args[:1] == ["vrf"]:
                    if args[1] != "default":
                        s.service_vrf = s.service_vrf or args[1]
                    args = args[2:]
                address, args = args[0], args[1:]
                s.ntp_servers.append(address)
                while args:
                    if args[0] == "prefer":
                        s.ntp_prefer, args = address, args[1:]
                    elif args[0] == "key" and len(args) >= 2:
                        s.ntp_server_keys[address], args = int(args[1]), args[2:]
                    elif args[0] in ("iburst", "burst"):
                        args = args[1:]
                    else:
                        return False
                return True
            if c[0] == "source" and len(c) in (2, 4):
                s.ntp_source = self.name(c[-1])
                return True
            return False

        self.children(node, child)
        return True

    def snmp(self, node: Node) -> bool:
        sn = self.device.snmp
        w = node.words
        origin = Origin(node.line, node.text)
        if w[1:2] == ["community"] and len(w) >= 3:
            community = SnmpCommunity(w[2], origin=origin)
            args = w[3:]
            if args[:1] in (["clear"], ["encrypted"]):
                args = args[1:]
            while args:
                if args[0] in ("RO", "RW"):
                    community.access, args = args[0].lower(), args[1:]
                elif args[0] in ("IPv4", "SDROwner", "SystemOwner") and len(args) >= 2 and args[0] == "IPv4":
                    community.acl, args = args[1], args[2:]
                elif args[0] in ("SDROwner", "SystemOwner"):
                    args = args[1:]
                elif len(args) == 1 and args[0] not in ("RO", "RW"):
                    community.acl, args = args[0], []
                else:
                    return False
            sn.communities.append(community)
            return True
        if w[1:2] == ["location"]:
            sn.location = " ".join(w[2:])
            return True
        if w[1:2] == ["contact"]:
            sn.contact = " ".join(w[2:])
            return True
        if w[1:2] == ["traps"]:
            sn.traps = True
            if len(w) > 2:
                sn.trap_types.append(" ".join(w[2:]))
            return True
        if w[1:2] == ["host"]:
            return self._snmp_host(w[2:], "", origin)
        if w[1:2] == ["vrf"] and len(w) == 3:
            vrf = w[2]
            self.children(node, lambda c, n: c[0] == "host" and self._snmp_host(c[1:], vrf, Origin(n.line, n.text)))
            return True
        if w[1:2] == ["group"] and len(w) >= 4:
            group = SnmpGroup(w[2], origin=origin)
            if w[3] != "v3":
                return False
            args = w[4:]
            if args[:1] in (["noauth"], ["auth"], ["priv"]):
                group.level, args = args[0], args[1:]
            while args:
                if args[0] in ("read", "write") and len(args) >= 2:
                    setattr(group, f"{args[0]}_view", args[1])
                    args = args[2:]
                elif args[0] == "notify" and len(args) >= 2:
                    args = args[2:]
                else:
                    return False
            sn.groups[group.name] = group
            return True
        if w[1:2] == ["user"] and len(w) >= 5 and w[4] == "v3":
            user = SnmpUser(w[2], w[3], origin=origin)
            args = w[5:]
            while args:
                if args[0] == "auth" and len(args) >= 4:
                    user.auth = args[1]
                    user.auth_key = args[3] if args[2] == "clear" else ""
                    args = args[4:]
                elif args[0] == "priv" and len(args) >= 4:
                    user.priv = {"aes": "aes128", "3des": "3des", "des56": "des"}.get(args[1], args[1])
                    if user.priv == "aes128" and len(args) >= 5 and args[2] in ("128", "192", "256"):
                        user.priv = f"aes{args[2]}"
                        args = args[1:]
                    user.priv_key = args[3] if args[2] == "clear" else ""
                    args = args[4:]
                elif args[0] in ("SDROwner", "SystemOwner"):
                    args = args[1:]
                else:
                    return False
            sn.users.append(user)
            return True
        if w[1:2] == ["view"] and len(w) == 5 and w[4] in ("included", "excluded"):
            sn.views.setdefault(w[2], []).append((w[3], w[4] == "included"))
            return True
        if w[1:2] == ["engineID"] and w[2:3] == ["local"] and len(w) == 4:
            sn.engine_id = w[3].replace(":", "")
            return True
        if w[1:2] == ["trap-source"] and len(w) == 3:
            sn.source = self.name(w[2])
            return True
        return False

    def _snmp_host(self, w: List[str], vrf: str, origin: Origin) -> bool:
        """A traps|informs version 1|2c|3 [noauth|auth|priv] SECRET [udp-port N]"""
        if len(w) < 5 or w[1] not in ("traps", "informs") or w[2] != "version":
            return False
        host = SnmpHost(w[0], vrf=vrf if vrf != "default" else "", informs=w[1] == "informs", origin=origin)
        host.version = w[3]
        args = w[4:]
        if host.version == "3" and args[:1] in (["noauth"], ["auth"], ["priv"]):
            host.level, args = args[0], args[1:]
        if args[:1] in (["clear"], ["encrypted"]):
            args = args[1:]
        if len(args) != 1:
            return False
        host.secret = args[0]
        self.device.snmp.hosts.append(host)
        self.device.snmp.traps = True
        return True

    def acl(self, node: Node) -> bool:
        w = node.words
        if w[1:2] != ["access-list"] or len(w) != 3:
            if node.words[:2] == ["ipv6", "enable"]:
                return True
            return False
        acl = Acl(w[2], family=6 if w[0] == "ipv6" else 4)
        if acl.family == 4:
            self._abf.strip(acl.name, node.children)
        for child in node.children:
            parts = child.text.split()
            # the IOS reader takes "ip" for any protocol; IOS-XR writes ipv4 / ipv6
            child.text = " ".join("ip" if x in ("ipv4", "ipv6") and i in (1, 2) else x for i, x in enumerate(parts))
        read_block(acl, node.children, wildcards=True)
        self.device.acls[acl.name] = acl
        return True

    # interfaces ------------------------------------------------------------------------------------------------------

    def interface(self, node: Node) -> bool:
        w = node.words
        if len(w) == 3 and w[2] == "l2transport":
            encap = ""
            for child in node.children:
                if child.words[:2] == ["encapsulation", "dot1q"] and len(child.words) == 3:
                    encap = child.words[2]
                elif child.words == ["encapsulation", "untagged"]:
                    encap = "untagged"
            self._l2[w[1]] = (node, encap)
            return True
        if len(w) != 2:
            return False
        iface = self.iface(w[1], Origin(node.line, node.text))
        if iface.kind == InterfaceKind.OTHER:
            return False
        self.children(node, lambda c, n: self._interface_line(iface, c, n))
        return True

    def _interface_line(self, iface: Interface, c: List[str], n: Node) -> bool:
        if c[0] == "service-policy" and len(c) == 3 and c[1] in ("input", "output"):
            setattr(iface, "qos_policy_in" if c[1] == "input" else "qos_policy_out", c[2])
            return True
        if c[0] == "flow":
            return self.flows.interface(iface, c)
        if c[0] == "monitor-session":
            return services.read_interface_mirror(self.device, iface, c)
        if c[0] == "description":
            iface.description = n.text.split(None, 1)[1] if len(c) > 1 else ""
            return True
        if c == ["shutdown"]:
            iface.shutdown = True
            return True
        if c[0] == "mtu" and len(c) == 2:
            iface.mtu = int(c[1])
            return True
        if c[0] == "vrf" and len(c) == 2:
            iface.vrf = c[1]
            if c[1] not in self.device.vrfs:
                self.device.vrfs.append(c[1])
            return True
        if c[:2] == ["ipv4", "address"] and len(c) in (4, 5):
            if len(c) == 5 and c[4] != "secondary":
                return False
            iface.ipv4.append(_mask_prefix(c[2], c[3]))
            return True
        if c[:2] == ["ipv4", "unnumbered"] and len(c) == 3:
            iface.unnumbered = self.name(c[2])
            return True
        if c[:2] == ["ipv6", "address"] and len(c) == 3 and "/" in c[2]:
            iface.ipv6.append(str(ipaddress.ip_interface(c[2])))
            return True
        if c == ["ipv6", "enable"]:
            return True
        if c[0] in ("ipv4", "ipv6") and c[1:2] == ["access-group"] and len(c) == 4 and c[3] in ("ingress", "egress"):
            attr = ("acl" if c[0] == "ipv4" else "acl6") + ("_in" if c[3] == "ingress" else "_out")
            setattr(iface, attr, c[2])
            return True
        if c[:2] == ["bundle", "id"] and len(c) == 5 and c[3] == "mode":
            mode = {"active": LacpMode.ACTIVE, "passive": LacpMode.PASSIVE, "on": LacpMode.STATIC}.get(c[4])
            if mode is None:
                return False
            iface.lag = f"Port-channel{c[2]}"
            iface.lacp_mode = mode
            return True
        if c[0] == "speed" and len(c) == 2:
            iface.speed = int(c[1])
            return True
        if c[0] == "duplex" and len(c) == 2:
            iface.duplex = c[1]
            return True
        if c == ["negotiation", "auto"] or c[:1] == ["load-interval"]:
            return True
        if c[:2] == ["encapsulation", "dot1q"] and len(c) == 3:
            iface.encapsulation_vlan = int(c[2])
            return True
        if c == ["ipv4", "unreachables", "disable"]:
            iface.ip_unreachables = False
            return True
        if c == ["ipv4", "redirects"]:
            iface.ip_redirects = True
            return True
        if c == ["proxy-arp"]:
            iface.proxy_arp = True
            return True
        if c[:5] == ["ipv4", "verify", "unicast", "source", "reachable-via"] and len(c) == 6:
            iface.urpf = {"rx": "strict", "any": "loose"}.get(c[5], "")
            return bool(iface.urpf)
        if c[0] == "service-policy" and len(c) == 3 and c[1] in ("input", "output"):
            setattr(iface, f"qos_policy_{'in' if c[1] == 'input' else 'out'}", c[2])
            return True
        if c[0] == "mac-address" and len(c) == 2:
            iface.mac_address = _mac(c[1])
            return True
        if c[0] == "lldp" and len(c) == 1:
            for child in n.children:
                if child.words == ["transmit", "disable"]:
                    iface.lldp_tx = False
                elif child.words == ["receive", "disable"]:
                    iface.lldp_rx = False
                else:
                    self.unparsed(child, f"interface {iface.source_name}")
            return True
        if c == ["cdp"]:
            iface.cdp = True
            return True
        if c[:2] == ["tunnel", "source"] and len(c) == 3:
            iface.tunnel_source = c[2] if _is_address(c[2]) else self.name(c[2])
            iface.tunnel_mode = iface.tunnel_mode or "gre"
            return True
        if c[:2] == ["tunnel", "destination"] and len(c) == 3:
            iface.tunnel_destination = c[2]
            iface.tunnel_mode = iface.tunnel_mode or "gre"
            return True
        if c[:2] == ["tunnel", "mode"] and c[2:3] == ["gre"]:
            iface.tunnel_mode = "gre"
            return True
        if c[0] == "flow" and len(c) >= 5 and c[1] == "ipv4" and c[2] == "monitor":
            direction = c[-1]
            if direction not in ("ingress", "egress"):
                return False
            word = "input" if direction == "ingress" else "output"
            iface.flow = word if iface.flow in ("", word) else "both"
            return True
        if c[:2] == ["bfd", "mode"] or c[:3] == ["bfd", "address-family", "ipv4"]:
            return self._bfd_line(iface, c)
        return False

    def _bfd_line(self, iface: Interface, c: List[str]) -> bool:
        """Bundle BFD: bfd address-family ipv4 fast-detect | minimum-interval N | multiplier N | destination A"""
        rest = c[3:]
        if c[:2] == ["bfd", "mode"] or rest == ["fast-detect"] or rest[:1] == ["destination"]:
            self._reason = ("BFD over bundle members", "BFD on the members of a bundle (BoB) is not converted; set it "
                            "up on the target's LAG by hand")
            return False
        if rest[:1] == ["minimum-interval"] and len(rest) == 2:
            iface.bfd_interval = iface.bfd_min_rx = int(rest[1])
            return True
        if rest[:1] == ["multiplier"] and len(rest) == 2:
            iface.bfd_multiplier = int(rest[1])
            return True
        return False

    def l2vpn(self, node: Node) -> bool:
        """l2vpn / bridge group G / bridge-domain BD / interface X, routed interface BVIn"""
        if node.words != ["l2vpn"]:
            return False

        def domain(c: List[str], n: Node) -> bool:
            if c[0] != "bridge-domain" or len(c) != 2:
                return False
            return self._bridge_domain(c[1], n)

        def child(c: List[str], n: Node) -> bool:
            if c[:2] == ["bridge", "group"] and len(c) == 3:
                self.children(n, domain, node.text)
                return True
            return False

        self.children(node, child)
        return True

    def _bridge_domain(self, name: str, node: Node) -> bool:
        m = re.match(r"^VLAN(\d+)(?:[-_](.+))?$", name, re.IGNORECASE)
        members: List[str] = []
        bvi = ""
        storm: List[Node] = []  # storm control for every port of the bridge domain
        profile = ""
        for child in node.children:
            c = child.words
            if c[0] == "interface" and len(c) == 2:
                members.append(c[1])
                base = self.name(c[1].split(".")[0])
                for sub in child.children:
                    if not self._l2s.storm(base, sub):
                        self.unparsed(sub, f"bridge-domain {name}")
            elif c[:2] == ["routed", "interface"] and len(c) == 3:
                bvi = c[2]
            elif c[0] == "storm-control" and len(c) == 4 and c[2] == "kbps":
                storm.append(child)
            elif c[:3] == ["igmp", "snooping", "profile"] and len(c) == 4:
                profile = c[3]
            else:
                self.unparsed(child, f"bridge-domain {name}")
        tags = {self._l2[x][1] for x in members if x in self._l2 and self._l2[x][1] not in ("", "untagged")}
        vid: Optional[int] = None
        if m:
            vid = int(m.group(1))
        elif len(tags) == 1:
            vid = int(tags.pop())
        elif bvi and bvi[3:].isdigit():
            vid = int(bvi[3:])
        if vid is None or not 1 <= vid <= 4094:
            return False
        vlan = self.device.vlans.setdefault(vid, Vlan(vid, origin=Origin(node.line, node.text)))
        if m and m.group(2):
            vlan.name = m.group(2)
        self._l2s.domains.append(vid)
        if profile:
            self._l2s.vlan_profiles[vid] = profile
        for line in storm:
            if not members or not all(self._l2s.storm(self.name(x.split(".")[0]), line) for x in members):
                self.unparsed(line, f"bridge-domain {name}")
        for member in members:
            l2 = self._l2.get(member)
            if l2 is None:
                return False
            _, encap = l2
            base = member.split(".")[0] if "." in member else member
            port = self.iface(base, Origin(l2[0].line, l2[0].text))
            if "." not in member and encap == "":
                port.mode = SwitchportMode.ACCESS
                port.access_vlan = vid if vid != 1 else None  # None: the default VLAN
                self._port_lines(port, l2[0])
            else:
                port.mode = SwitchportMode.TRUNK
                allowed = _vlan_ids(port.allowed_vlans) if port.allowed_vlans else []
                port.allowed_vlans = ",".join(str(v) for v in sorted(set(allowed + [vid])))
                if encap == "untagged":
                    port.native_vlan = vid
                if "." not in member:
                    self._port_lines(port, l2[0])
            l2[0].text = ""  # read
        if bvi:
            svi = self.device.interfaces.get(self.name(bvi))
            if svi is not None and svi.name != f"Vlan{vid}":
                del self.device.interfaces[svi.name]
                svi.name = f"Vlan{vid}"
                self.device.interfaces[svi.name] = svi
        return True

    def _port_lines(self, port: Interface, node: Node) -> None:
        """The settings of a whole-port l2transport interface (description, shutdown, mtu, speed, LLDP)."""
        for child in node.children:
            c = child.words
            if c[:2] == ["encapsulation", "untagged"] or c[:2] == ["rewrite", "ingress"]:
                continue
            try:
                ok = c[0] in ("description", "shutdown", "mtu", "speed", "duplex", "lldp", "cdp", "negotiation",
                             "service-policy", "monitor-session") and \
                    self._interface_line(port, c, child)
            except (ValueError, IndexError):
                ok = False
            if not ok:
                self.unparsed(child, f"interface {port.source_name} l2transport")

    # routing ---------------------------------------------------------------------------------------------------------

    def router(self, node: Node) -> bool:
        w = node.words
        if w[1:] == ["static"]:
            self.children(node, lambda c, n: self._static(c, n, ""))
            return True
        if w[1:2] == ["ospf"] and len(w) == 3:
            self._ospf(node, w[2])
            return True
        if w[1:2] == ["bgp"] and len(w) == 3:
            self._bgp(node, w[2])
            return True
        if w[1:2] == ["isis"] and len(w) == 3:
            self._isis(node, w[2])
            return True
        if w[1:] in (["hsrp"], ["vrrp"]):
            self._fhrp(node, w[1])
            return True
        if w[1:] == ["pim"]:
            self._pim(node)
            return True
        if w[1:] == ["igmp"]:
            self._igmp(node)
            return True
        if w[1:] == ["rip"]:
            return xrrouting.read_rip(self.device, node, self.name, self.children, self._rip)
        return False

    def _static(self, c: List[str], n: Node, vrf: str) -> bool:
        if c[0] == "vrf" and len(c) == 2 and not vrf:
            self.children(n, lambda cc, nn: self._static(cc, nn, c[1]), f"router static / vrf {c[1]}")
            return True
        if c[0] == "address-family" and c[1:] in (["ipv4", "unicast"], ["ipv6", "unicast"]):
            self.children(n, lambda cc, nn: self._route(cc, nn, vrf), "router static")
            return True
        return False

    def _route(self, c: List[str], n: Node, vrf: str) -> bool:
        """PREFIX [IF] [NEXT-HOP] [DISTANCE] [tag N] [description TEXT] [track T]"""
        route = StaticRoute(str(ipaddress.ip_network(c[0], strict=False)), vrf=vrf, origin=Origin(n.line, n.text))
        args = c[1:]
        if args and args[0].startswith("Null"):
            route.discard, args = True, args[1:]
        elif args and not _is_address(args[0]) and not args[0].isdigit() and args[0] not in ("tag", "description"):
            route.interface, args = self.name(args[0]), args[1:]
        if args and _is_address(args[0]):
            route.next_hop, args = args[0], args[1:]
        if args and args[0].isdigit():
            route.distance, args = int(args[0]), args[1:]
        while args:
            if args[0] == "tag" and len(args) >= 2:
                route.tag, args = int(args[1]), args[2:]
            elif args[0] == "description" and len(args) >= 2:
                route.name, args = args[1], args[2:]
            elif args[0] == "track" and len(args) >= 2:
                route.track, args = args[1], args[2:]
            else:
                return False
        if not (route.discard or route.interface or route.next_hop):
            return False
        self.device.static_routes.append(route)
        return True

    def _ospf(self, node: Node, process: str, vrf: str = "") -> None:
        p = Ospf(process=process, vrf=vrf, origin=Origin(node.line, node.text))
        self.device.ospf.append(p)
        section = f"router ospf {process}" + (f" vrf {vrf}" if vrf else "")

        def area_iface(area: str, name: str, n: Node) -> None:
            iface = self.iface(name)
            p.interface_areas[iface.name] = area

            def line(c: List[str], nn: Node) -> bool:
                if c[:2] == ["passive", "enable"] or c == ["passive"]:
                    p.passive_interfaces.append(iface.name)
                    return True
                if c[:2] == ["passive", "disable"]:
                    p.active_interfaces.append(iface.name)
                    return True
                if c[0] == "cost" and len(c) == 2:
                    iface.ospf_cost = int(c[1])
                    return True
                if c[0] == "network" and len(c) == 2 and c[1] in ("point-to-point", "broadcast"):
                    iface.ospf_network = c[1]
                    return True
                if c[:2] == ["bfd", "fast-detect"]:
                    iface.ospf_bfd = True
                    return True
                if c[:2] == ["bfd", "minimum-interval"] and len(c) == 3:
                    iface.bfd_interval = iface.bfd_min_rx = int(c[2])
                    return True
                if c[:2] == ["bfd", "multiplier"] and len(c) == 3:
                    iface.bfd_multiplier = int(c[2])
                    return True
                if c[0] == "authentication" and len(c) in (1, 2):
                    iface.ospf_auth = "message-digest" if c[1:] == ["message-digest"] else "simple"
                    return True
                if c[0] == "message-digest-key" and len(c) >= 4 and c[2] == "md5":
                    iface.ospf_auth = iface.ospf_auth or "message-digest"
                    iface.ospf_keys[int(c[1])] = "md5"
                    return True
                return False

            self.children(n, line, section)

        def area(number: str, n: Node) -> None:
            dotted = str(ipaddress.ip_address(int(number))) if number.isdigit() else number

            def line(c: List[str], nn: Node) -> bool:
                if c[0] == "interface" and len(c) == 2:
                    area_iface(dotted, c[1], nn)
                    return True
                if c[0] in ("stub", "nssa"):
                    p.area_types[dotted] = " ".join(c).replace("stub no-summary", "stub no-summary")
                    return True
                return False

            self.children(n, line, section)

        def line(c: List[str], n: Node) -> bool:
            if c[0] == "router-id" and len(c) == 2:
                p.router_id = c[1]
                return True
            if c[0] == "area" and len(c) == 2:
                area(c[1], n)
                return True
            if c[0] == "redistribute" and len(c) >= 2 and c[1] in ("connected", "static", "bgp"):
                p.redistribute.append(c[1])
                rest = c[2:] if c[1] != "bgp" else c[3:]
                if rest[:1] == ["route-policy"] and len(rest) == 2:
                    p.redistribute_maps[c[1]] = rest[1]
                    return True
                return not rest
            if c[:2] == ["auto-cost", "reference-bandwidth"] and len(c) == 3:
                p.reference_bandwidth = int(c[2])
                return True
            if c[:1] == ["default-information"] and c[1:2] == ["originate"]:
                p.default_originate = "always" if "always" in c else "on"
                return True
            if c[0] == "passive" and len(c) == 2:
                p.passive_default = c[1] == "enable"
                return True
            if c[:2] == ["bfd", "fast-detect"]:
                p.bfd_all = True
                return True
            if c[0] == "nsf" and len(c) <= 2:
                p.graceful_restart = True
                return True
            if c[:2] == ["log", "adjacency"]:
                p.log_adjacency = "detail" if "detail" in c else "on"
                return True
            if c[:3] == ["timers", "throttle", "spf"] and len(c) == 6:
                p.spf_timers = (int(c[3]), int(c[4]), int(c[5]))
                return True
            if c[:3] == ["timers", "lsa", "min-arrival"] and len(c) == 4:
                p.lsa_arrival = int(c[3])
                return True
            if c[:2] == ["distribute-list", "route-policy"] and len(c) == 4 and c[3] == "in":
                p.distribute_list_in = c[2]
                return True
            if c[0] == "max-lsa" and len(c) >= 2:
                p.max_lsa = " ".join(c[1:])
                return True
            if c[0] == "vrf" and len(c) == 2 and not vrf:
                self._ospf(n, process, c[1])
                return True
            return False

        self.children(node, line, section)

    def _bgp(self, node: Node, local_as: str) -> None:
        b = bgp_text.Builder(local_as)
        b.default_ipv4 = False
        b.bgp.origin = Origin(node.line, node.text)
        self.device.bgp = b.bgp
        section = node.text

        def global_af(af: str, c: List[str], n: Node, target: object) -> bool:
            if c[0] == "network" and len(c) in (2, 4):
                getattr(target, "networks").append(str(ipaddress.ip_network(c[1], strict=False)))
                return len(c) == 2 or c[2] == "route-policy"
            if c[0] == "redistribute" and len(c) >= 2 and c[1] in ("connected", "static", "ospf"):
                lst = getattr(target, "redistribute" if af == "ipv4" else "redistribute6")
                lst.append(c[1])
                rest = c[2:] if c[1] != "ospf" else c[3:]
                if rest[:1] == ["match"]:
                    getattr(target, "ospf_match").extend(x for x in rest[1:] if x not in ("route-policy",)
                                                         and not x.startswith("RS"))
                    rest = []
                if rest[:1] == ["route-policy"] and len(rest) == 2:
                    if af == "ipv4":
                        getattr(target, "redistribute_maps")[c[1]] = rest[1]
                    return True
                return not rest
            if c[0] == "aggregate-address" and len(c) >= 2:
                return bgp_text.read_aggregate(getattr(target, "aggregates"), c[1:])
            if c[0] == "maximum-paths" and len(c) == 3 and c[1] in ("ebgp", "ibgp", "eibgp"):
                if c[1] == "ibgp" and hasattr(target, "maximum_paths_ibgp"):
                    setattr(target, "maximum_paths_ibgp", int(c[2]))
                else:
                    setattr(target, "maximum_paths", int(c[2]))
                return True
            if c[:2] == ["distance", "bgp"] and len(c) == 5 and hasattr(target, "distance"):
                setattr(target, "distance", (int(c[2]), int(c[3]), int(c[4])))
                return True
            return False

        def peer_lines(peer: BgpNeighbor, c: List[str], n: Node, vrf: Optional[BgpVrf]) -> bool:
            if c[0] == "remote-as" and len(c) == 2:
                peer.remote_as = c[1]
                return True
            if c[:2] == ["use", "neighbor-group"] and len(c) == 3:
                peer.peer_group = c[2]
                return True
            if c[0] == "description":
                peer.description = n.text.split(None, 1)[1] if len(c) > 1 else ""
                return True
            if c[0] == "update-source" and len(c) == 2:
                peer.update_source = self.name(c[1])
                return True
            if c == ["shutdown"]:
                peer.shutdown = True
                return True
            if c[0] == "ebgp-multihop":
                peer.ebgp_multihop = int(c[1]) if len(c) == 2 else 255
                return True
            if c[0] == "password" and len(c) == 3:
                peer.password = c[2] if c[1] == "clear" else aaa_text.decode_type7(c[2]) or aaa_text.PLACEHOLDER
                return True
            if c[0] == "timers" and len(c) == 3:
                peer.keepalive, peer.hold = int(c[1]), int(c[2])
                return True
            if c[:2] == ["bfd", "fast-detect"]:
                peer.bfd = True
                return True
            if c[:2] in (["bfd", "minimum-interval"], ["bfd", "multiplier"]):
                return True
            if c[0] == "local-as" and len(c) >= 2:
                peer.local_as = c[1]
                peer.local_as_options = " ".join(c[2:])
                return True
            if c[0] == "ttl-security":
                peer.ttl_security = 1
                return True
            if c[0] == "address-family" and len(c) == 3:
                families = {("ipv4", "unicast"): "ipv4", ("ipv6", "unicast"): "ipv6", ("l2vpn", "evpn"): "evpn"}
                af = families.get((c[1], c[2]))
                if af is None:
                    self._reason = _VPN_REASON if c[1] in ("vpnv4", "vpnv6") else None
                    return False
                b.activate(peer.address, af)
                self.children(n, lambda cc, nn: peer_af(peer, cc), section)
                return True
            return False

        def peer_af(peer: BgpNeighbor, c: List[str]) -> bool:
            if c[0] == "route-policy" and len(c) == 3 and c[2] in ("in", "out"):
                setattr(peer, f"route_map_{c[2]}", c[1])
                return True
            if c == ["next-hop-self"]:
                peer.next_hop_self = True
                return True
            if c[0] in ("send-community-ebgp", "send-extended-community-ebgp"):
                peer.send_community = True
                return True
            if c == ["route-reflector-client"]:
                peer.route_reflector_client = True
                return True
            if c[0] == "maximum-prefix" and len(c) >= 2:
                peer.maximum_prefix = int(c[1])
                if len(c) >= 3 and c[2].isdigit():
                    peer.maximum_prefix_warning = int(c[2])
                return True
            if c[0] == "remove-private-AS":
                peer.remove_private_as = True
                peer.remove_private_as_mode = "all" if "entire-aspath" in c else ""
                return True
            if c[0] == "allowas-in":
                peer.allowas_in = int(c[1]) if len(c) == 2 else 3
                return True
            if c[:1] == ["soft-reconfiguration"]:
                return True
            return False

        def vrf_block(name: str, n: Node) -> None:
            v = b.bgp.vrfs.setdefault(name, BgpVrf())
            if name not in self.device.vrfs:
                self.device.vrfs.append(name)

            def line(c: List[str], nn: Node) -> bool:
                if c[0] == "rd" and len(c) == 2:
                    self.device.vrf_info.setdefault(name, VrfInfo()).rd = c[1]
                    return True
                if c[0] == "address-family" and c[1:] in (["ipv4", "unicast"], ["ipv6", "unicast"]):
                    af = c[1]
                    self.children(nn, lambda cc, x: global_af(af, cc, x, v), section)
                    return True
                if c[0] in ("neighbor", "neighbor-group") and len(c) == 2:
                    group = c[0] == "neighbor-group"
                    peer = BgpNeighbor(c[1])
                    (v.peer_groups.__setitem__(c[1], peer) if group else v.neighbors.append(peer))
                    self.children(nn, lambda cc, x: vrf_peer(peer, cc, x), section)
                    return True
                if c[:2] == ["bgp", "router-id"]:
                    return True
                if c[:4] == ["bgp", "bestpath", "med", "missing-as-worst"]:
                    v.med_missing_as_worst = True
                    return True
                return False

            def vrf_peer(peer: BgpNeighbor, c: List[str], nn: Node) -> bool:
                if c[0] == "address-family" and len(c) == 3 and c[1:] in (["ipv4", "unicast"], ["ipv6", "unicast"]):
                    peer.families = sorted(set(peer.families) | {c[1]})
                    self.children(nn, lambda cc, x: peer_af(peer, cc), section)
                    return True
                if c[0] == "address-family":
                    return False
                return peer_lines(peer, c, nn, v)

            self.children(n, line, section)

        def line(c: List[str], n: Node) -> bool:
            bg = b.bgp
            if c[:2] == ["bgp", "router-id"] and len(c) == 3:
                bg.router_id = c[2]
                return True
            if c[:2] == ["bgp", "graceful-restart"]:
                bg.graceful_restart = True
                if c[2:3] == ["restart-time"] and len(c) == 4:
                    bg.graceful_restart_time = int(c[3])
                return len(c) in (2, 4)
            if c[:4] == ["bgp", "bestpath", "as-path", "multipath-relax"]:
                bg.multipath_relax = True
                return True
            if c[:4] == ["bgp", "bestpath", "med", "missing-as-worst"]:
                bg.med_missing_as_worst = True
                return True
            if c[:2] == ["timers", "bgp"] and len(c) == 4:
                bg.keepalive, bg.hold = int(c[2]), int(c[3])
                return True
            if c[0] == "address-family" and c[1:] in (["ipv4", "unicast"], ["ipv6", "unicast"]):
                af = c[1]
                self.children(n, lambda cc, x: global_af(af, cc, x, bg), section)
                return True
            if c[0] == "address-family" and c[1:] == ["l2vpn", "evpn"]:
                return not n.children
            if c[0] == "address-family" and c[1:2] in (["vpnv4"], ["vpnv6"]):
                self._reason = _VPN_REASON
                return False
            if c[0] == "neighbor-group" and len(c) == 2:
                peer = b.peer(c[1], group=True)
                b.declared.add(c[1])
                self.children(n, lambda cc, x: peer_lines(peer, cc, x, None), section)
                return True
            if c[0] == "neighbor" and len(c) == 2:
                peer = b.peer(c[1])
                self.children(n, lambda cc, x: peer_lines(peer, cc, x, None), section)
                return True
            if c[0] == "vrf" and len(c) == 2:
                vrf_block(c[1], n)
                return True
            return False

        self.children(node, line, section)
        b.finish()

    def _isis(self, node: Node, tag: str) -> None:
        isis = Isis(tag=tag, origin=Origin(node.line, node.text))
        self.device.isis = isis

        def iface_line(iface: Interface, c: List[str], n: Node) -> bool:
            if c == ["passive"]:
                iface.isis_passive = True
                return True
            if c == ["point-to-point"]:
                iface.isis_network = "point-to-point"
                return True
            if c[0] == "address-family" and c[1:] == ["ipv4", "unicast"]:
                def af(cc: List[str], nn: Node) -> bool:
                    if cc[0] == "metric" and len(cc) == 2:
                        iface.isis_metric = int(cc[1])
                        return True
                    return False
                self.children(n, af, node.text)
                return True
            return False

        def line(c: List[str], n: Node) -> bool:
            if c[0] == "net" and len(c) == 2:
                isis.nets.append(c[1])
                return True
            if c[0] == "is-type" and len(c) == 2:
                isis.level = {"level-1": "level-1", "level-2-only": "level-2", "level-1-2": "level-1-2"}.get(c[1], "")
                return bool(isis.level)
            if c[0] == "address-family" and c[1:] == ["ipv4", "unicast"]:
                def af(cc: List[str], nn: Node) -> bool:
                    if cc[:2] == ["metric-style", "wide"]:
                        isis.wide_metrics = True
                        return True
                    if cc[0] == "redistribute" and len(cc) >= 2 and cc[1] in ("connected", "static"):
                        isis.redistribute.append(cc[1])
                        if cc[2:3] == ["route-policy"] and len(cc) == 4:
                            isis.redistribute_maps[cc[1]] = cc[3]
                            return True
                        return len(cc) == 2
                    return False
                self.children(n, af, node.text)
                return True
            if c[0] == "interface" and len(c) == 2:
                iface = self.iface(c[1])
                iface.isis = True
                self.children(n, lambda cc, nn: iface_line(iface, cc, nn), node.text)
                return True
            return False

        self.children(node, line)

    def _fhrp(self, node: Node, protocol: str) -> None:
        """router hsrp|vrrp / interface X / address-family ipv4 / hsrp N [version 2] | vrrp N [version 3]"""
        def group_line(g: FhrpGroup, c: List[str]) -> bool:
            if c[0] == "address" and len(c) == 2:
                g.address = c[1]
                return True
            if c[0] == "address" and len(c) == 3 and c[2] == "secondary":
                g.secondary.append(c[1])
                return True
            if c[0] == "priority" and len(c) == 2:
                g.priority = int(c[1])
                return True
            if c[:2] == ["preempt", "disable"]:
                g.preempt = False
                return True
            if c[0] == "preempt" and (len(c) == 1 or c[1] == "delay"):
                g.preempt = True
                return True
            if c[0] == "timers" and protocol == "hsrp" and len(c) == 3:
                g.hello_ms, g.hold_ms = int(c[1]) * 1000, int(c[2]) * 1000
                return True
            if c[0] == "timer" and protocol == "vrrp" and len(c) == 2:
                g.hello_ms = int(c[1]) * 1000
                return True
            if c[0] == "name" and len(c) == 2:
                g.name = c[1]
                return True
            if c[0] == "track" and c[1:2] == ["object"] and len(c) == 4:
                g.tracks[c[2]] = int(c[3])
                return True
            return False

        def af_line(iface: Interface, c: List[str], n: Node) -> bool:
            if c[0] != protocol or len(c) not in (2, 4):
                return False
            g = FhrpGroup(protocol, int(c[1]), origin=Origin(n.line, n.text))
            if len(c) == 4:
                if c[2] != "version":
                    return False
                g.version = int(c[3])
            self.children(n, lambda cc, nn: group_line(g, cc), node.text)
            iface.fhrp.append(g)
            return True

        def iface_line(iface: Interface, c: List[str], n: Node) -> bool:
            if c[0] == "address-family" and c[1:] == ["ipv4"]:
                self.children(n, lambda cc, nn: af_line(iface, cc, nn), node.text)
                return True
            return False

        def line(c: List[str], n: Node) -> bool:
            if c[0] == "interface" and len(c) == 2:
                iface = self.iface(c[1])
                self.children(n, lambda cc, nn: iface_line(iface, cc, nn), node.text)
                return True
            return False

        self.children(node, line)

    def _pim(self, node: Node) -> None:
        def af(c: List[str], n: Node) -> bool:
            if c[0] == "rp-address" and len(c) in (2, 3):
                self.device.pim_rps.append(c[1])
                if len(c) == 3:
                    self.device.pim_rp_groups[c[1]] = f"acl {c[2]}"
                return True
            if c[0] == "interface" and len(c) == 2:
                iface = self.iface(c[1])
                iface.pim = "sparse"
                return all(x.words == ["enable"] for x in n.children)
            return False

        def line(c: List[str], n: Node) -> bool:
            if c[0] == "address-family" and c[1:] == ["ipv4"]:
                self.children(n, af, node.text)
                return True
            return af(c, n)

        self.children(node, line)

    def _igmp(self, node: Node) -> None:
        def line(c: List[str], n: Node) -> bool:
            if c[0] == "interface" and len(c) == 2:
                iface = self.iface(c[1])
                for child in n.children:
                    if child.words[0] == "version" and len(child.words) == 2:
                        iface.igmp_version = int(child.words[1])
                    else:
                        self.unparsed(child, node.text)
                return True
            return False

        self.children(node, line)

    def multicast_routing(self, node: Node) -> bool:
        self.device.multicast_routing = True

        def af(c: List[str], n: Node) -> bool:
            if c[:2] == ["interface", "all"] and c[2:] == ["enable"]:
                return True
            if c[0] == "interface" and len(c) == 2:
                return True
            return False

        def line(c: List[str], n: Node) -> bool:
            if c[0] == "address-family" and c[1:] == ["ipv4"]:
                self.children(n, af, node.text)
                return True
            return False

        self.children(node, line)
        return True

    def mpls(self, node: Node) -> bool:
        if node.words != ["mpls", "ldp"]:
            return False
        mp = self.device.mpls
        mp.ldp = True

        def line(c: List[str], n: Node) -> bool:
            if c[0] == "router-id" and len(c) == 2:
                mp.router_id = c[1]
                return True
            if c[0] == "interface" and len(c) == 2:
                self.iface(c[1]).mpls = True
                return not n.children
            return False

        self.children(node, line)
        return True

    def dhcp(self, node: Node) -> bool:
        """dhcp ipv4 / profile NAME relay / helper-address [vrf V] A / interface X relay profile NAME"""
        if node.words != ["dhcp", "ipv4"]:
            return False
        profiles: Dict[str, List[Tuple[str, str]]] = {}

        def profile_line(name: str, c: List[str]) -> bool:
            if c[0] == "helper-address":
                vrf = ""
                args = c[1:]
                if args[:1] == ["vrf"] and len(args) >= 3:
                    vrf, args = args[1], args[2:]
                if len(args) != 1:
                    return False
                profiles[name].append((args[0], "" if vrf == "default" else vrf))
                return True
            return False

        def line(c: List[str], n: Node) -> bool:
            if c[0] == "profile" and len(c) == 3 and c[2] == "server":
                xrrouting.read_server_profile(self.device, c[1], n, self.children)
                return True
            if c[0] == "interface" and len(c) == 5 and c[2:4] == ["server", "profile"]:
                return True
            if c[0] == "profile" and len(c) == 3 and c[2] == "relay":
                profiles[c[1]] = []
                self.children(n, lambda cc, nn: profile_line(c[1], cc), node.text)
                return True
            if c[0] == "interface" and len(c) == 5 and c[2:4] == ["relay", "profile"] and c[4] in profiles:
                iface = self.iface(c[1])
                for address, vrf in profiles[c[4]]:
                    iface.helper_addresses.append(address)
                    if vrf and vrf != iface.vrf:
                        iface.helper_vrf = vrf
                return True
            return False

        self.children(node, line)
        return True

    # management ------------------------------------------------------------------------------------------------------

    def lldp(self, node: Node) -> bool:
        m = self.device.management
        m.lldp = True

        def line(c: List[str], n: Node) -> bool:
            if c[0] == "timer" and len(c) == 2:
                m.lldp_timer = int(c[1])
                return True
            if c[0] == "holdtime" and len(c) == 2:
                m.lldp_holdtime = int(c[1])
                return True
            if c[:2] == ["management", "enable"] or c == ["reinit", "2"]:
                return True
            return False

        if node.words != ["lldp"]:
            return False
        self.children(node, line)
        return True

    def ssh(self, node: Node) -> bool:
        m = self.device.management
        w = node.words
        if w[1:] == ["server", "v2"]:
            m.ssh = True
            return True
        if w[1:3] == ["server", "vrf"] and len(w) >= 4:
            m.ssh = True
            if w[3] != "default":
                m.vrf = w[3]
            return len(w) == 4 or w[4:5] == ["ipv4"]
        if w[1:3] == ["timeout"]:
            return True
        return False

    def telnet(self, node: Node) -> bool:
        w = node.words
        if w[:1] == ["telnet"] and "server" in w:
            self.device.management.telnet = True
            return True
        return False

    def netconf(self, node: Node) -> bool:
        if node.words != ["netconf-yang", "agent"]:
            return False
        if [c.words for c in node.children] != [["ssh"]]:
            return False
        self.device.management.apis["netconf"] = ""
        return True

    def grpc(self, node: Node) -> bool:
        if node.words != ["grpc"]:
            return False
        m = self.device.management
        m.apis["gnmi"] = ""

        def line(c: List[str], n: Node) -> bool:
            if c[0] == "vrf" and len(c) == 2:
                m.apis["gnmi"] = c[1]
                return True
            if c[0] in ("port", "no-tls", "address-family"):
                return True
            return False

        self.children(node, line)
        return True

    # the end ---------------------------------------------------------------------------------------------------------

    def _finish(self) -> None:
        d = self.device
        xrrouting.finish_rip(d, self._rip)
        for name, (node, _) in self._l2.items():
            if node.text:
                self.unparsed(node)
        for iface in d.interfaces.values():
            if iface.kind == InterfaceKind.LAG and iface.lacp_mode is None:
                members = [m for m in d.interfaces.values() if m.lag == iface.name]
                if members and members[0].lacp_mode is not None:
                    iface.lacp_mode = members[0].lacp_mode
        for iface in d.interfaces.values():  # LAG members carry the layer 2 settings of their LAG
            lag = d.interfaces.get(iface.lag) if iface.lag else None
            if lag is not None and lag.mode != SwitchportMode.ROUTED:
                iface.mode, iface.access_vlan, iface.native_vlan = lag.mode, lag.access_vlan, lag.native_vlan
        for iface in d.interfaces.values():
            if iface.mode == SwitchportMode.TRUNK and iface.allowed_vlans:
                iface.allowed_vlans = vlan_text(_vlan_ids(iface.allowed_vlans))
        for iface in d.interfaces.values():
            lag = d.interfaces.get(iface.lag) if iface.lag else None
            if lag is not None and lag.mode == SwitchportMode.TRUNK:
                iface.allowed_vlans = lag.allowed_vlans
        for server in d.aaa.servers:  # IOS-XR sets the VRF on the server group
            group = next((g for g in d.aaa.groups.values() if server.address in g.servers and g.vrf
                          and g.protocol == server.protocol), None)
            if group is not None:
                server.vrf = group.vrf
        if d.netflow is None and self.flows.monitors:  # a flow monitor no interface uses
            self.flows.monitor(next(iter(self.flows.monitors)))
        for node in self._l2s.finish():
            self.unparsed(node, "l2vpn")
        abf_maps = self._abf.finish()
        for iface in d.interfaces.values():
            if iface.acl_in in abf_maps:
                iface.pbr, iface.acl_in = abf_maps[iface.acl_in], ""
        policy.finish(d)
        multicast_text.finish(d)


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _mac(text: str) -> str:
    digits = text.replace(".", "").replace(":", "").lower()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def parse(text: str) -> Device:
    return _Reader().read(text)
