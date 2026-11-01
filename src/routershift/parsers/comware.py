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

from .. import aaa as aaa_text
from .. import acl as acl_text
from .. import bgp as bgp_text
from .. import confparse
from .. import dhcp as dhcp_text
from .. import ospf as ospf_text
from .. import mgmt as mgmt_text
from .. import vrfs as vrfs_text
from .. import igp as igp_text
from .. import monitor as monitor_text
from .. import tracking as tracking_text
from .. import bfd as bfd_text
from .. import routemap as routemap_text
from .. import qos as qos_text
from .. import vpn as vpn_text
from ..confparse import Node
from ..errors import ParseError
from ..model import (BgpVrf, IpSla, Netflow, Sflow, AaaGroup, AaaMethod, AaaServer, Acl, AclAction, AclEntry, Device, DhcpPool, FhrpGroup, IkePolicy, IpsecPeer, IpsecTransform,
                     NtpKey, PreSharedKey, SnmpCommunity, SnmpGroup, SnmpHost, SnmpUser, Interface, InterfaceKind, LacpMode, LocalUser,
                     NatPool, NatRule, Origin, QosAction, QosClass, QosPolicy, Ospf, Rip, Isis, Wlan, OspfNetwork, StaticRoute, StpMode, SwitchportMode, Unparsed, Vlan)
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

# Comware user roles for the privilege levels (level-N roles cover the rest)
COMWARE_ROLES = [(15, "network-admin"), (1, "network-operator")]


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
        self._ospf_areas: List[Tuple[str, str, str]] = []
        self._dhcp_excluded: Dict[str, List[Tuple[str, str]]] = {}  # VRF -> forbidden ranges
        self._ike_profiles: Dict[str, Tuple[List[str], List[str]]] = {}  # name -> (proposals, remote addresses)
        self._peer_profiles: List[Tuple[IpsecPeer, str]] = []
        self._pfs: Dict[str, int] = {}  # transform set -> PFS group
        self._nat_groups: Dict[str, str] = {}  # address-group number -> pool name
        self._nas_ip: Dict[str, Tuple[str, int]] = {}  # protocol -> (source address, line)
        self._domains: Dict[str, List[AaaMethod]] = {}
        self._default_domain = "system"
        self._reauth_period: Optional[int] = None
        self._max_users: Dict[Tuple[str, str], int] = {}  # (port, dot1x|mac-authentication) -> max-user
        self._port_based: Set[str] = set()
        self._behaviors: Dict[str, QosAction] = {}
        self._policy_pairs: List[Tuple[QosPolicy, str, str, Node]] = []  # policy, classifier, behavior, line

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
            "route-policy": self.route_policy,
            "policy-based-route": self.policy_based_route,
            "rip": self.rip,
            "igmp-snooping": self.igmp_snooping,
            "multicast": self.multicast,
            "pim": self.pim,
            "isis": self.isis,
            "vlan": self.vlan,
            "stp": self.stp,
            "interface": self.interface,
            "acl": self.acl,
            "vrrp": self.vrrp_version,
            "ospf": self.ospf,
            "bgp": self.bgp,
            "dhcp": self.dhcp,
            "nat": self.nat,
            "ike": self.ike,
            "snmp-agent": self.snmp,
            "ipsec": self.ipsec,
            "local-user": self.local_user,
            "super": self.super_password,
            "radius": self.aaa_scheme,
            "hwtacacs": self.aaa_scheme,
            "domain": self.domain,
            "line": self.line,
            "dot1x": self.dot1x,
            "mac-authentication": self.dot1x,
            "tftp": self.transfer,
            "traffic": self.traffic,
            "qos": self.qos_policy,
            "mpls": self.mpls,
            "wlan": self.wlan,
            "ftp": self.transfer,
            "ssh": self.server,
            "telnet": self.server,
            "lldp": self.server,
            "undo": self.undo,
            "port-security": lambda node: node.words == ["port-security", "enable"],
            "mirroring-group": self.mirroring_group,
            "sflow": self.sflow,
            "nqa": self.nqa,
            "track": self.track,
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
            s = self.device.system
            if s.domain_name:  # the domains after the first are tried in turn
                s.dns_search.append(w[2])
            else:
                s.domain_name = w[2]
            return True
        if w[1:2] == ["source-interface"] and len(w) == 3:
            self.device.system.dns_source = canonical(w[2])[0]
            return True
        if w[1:2] == ["server"]:
            self.device.system.dns_servers.extend(self._vpn(w[2:]))
            return True
        return False

    def ntp(self, node: Node) -> bool:
        w = node.words
        if w[1:] == ["enable"]:
            return True
        s = self.device.system
        if w[1:2] == ["unicast-server"] and len(w) >= 3:
            server = w[2]
            s.ntp_servers.append(server)
            options = w[3:]
            while options:
                if options[0] == "priority":
                    s.ntp_prefer = server
                elif options[0] == "vpn-instance" and len(options) >= 2:
                    s.service_vrf, options = options[1], options[1:]
                elif options[0] == "authentication-keyid" and len(options) >= 2:
                    s.ntp_server_keys[server], options = int(options[1]), options[1:]
                elif options[0] == "source" and len(options) >= 2:
                    s.ntp_source, options = canonical(options[1])[0], options[1:]
                else:
                    return False
                options = options[1:]
            return True
        if w[1:] == ["authentication", "enable"]:
            s.ntp_authenticate = True
            return True
        if w[1] == "authentication-keyid" and len(w) == 7 and w[3] == "authentication-mode":
            # ntp-service authentication-keyid 1 authentication-mode md5 simple|cipher KEY
            key = s.ntp_keys.setdefault(int(w[2]), NtpKey(int(w[2])))
            key.algorithm = {"hmac-sha-1": "sha1", "hmac-sha-256": "sha256"}.get(w[4], w[4])
            key.key = w[6] if w[5] == "simple" else ""
            return key.algorithm in ("md5", "sha1", "sha256") and w[5] in ("simple", "cipher")
        if w[1:3] == ["reliable", "authentication-keyid"] and len(w) == 4:
            s.ntp_keys.setdefault(int(w[3]), NtpKey(int(w[3]))).trusted = True
            return True
        if w[1] == "source" and len(w) == 3:
            s.ntp_source = canonical(w[2])[0]
            return True
        return False

    def snmp(self, node: Node) -> bool:
        w = node.words
        s = self.device.snmp
        origin = Origin(node.line, node.text)
        if len(w) == 1:
            return True  # snmp-agent: the agent runs
        if w[1] == "community" and len(w) >= 4 and w[2] in ("read", "write"):
            args = w[3:]
            encrypted = args[0] == "cipher"
            if args[0] in ("simple", "cipher"):
                args = args[1:]
            community = SnmpCommunity("" if encrypted else args[0], "ro" if w[2] == "read" else "rw", origin=origin)
            args = args[1:]
            if args[:1] == ["acl"] and len(args) >= 2:
                community.acl, args = args[-1], args[2 + (args[1] == "name"):]
            s.communities.append(community)
            return not args
        if w[1] == "sys-info" and len(w) >= 4 and w[2] in ("location", "contact"):
            setattr(s, w[2], node.text.split(None, 3)[3])
            return True
        if w[1:3] == ["sys-info", "version"]:
            return True
        if w[1:3] == ["trap", "enable"]:
            s.traps = True
            return True
        if w[1:3] == ["trap", "source"] and len(w) == 4:
            s.source = canonical(w[3])[0]
            return True
        if w[1] == "target-host" and len(w) >= 9 and w[3:5] == ["address", "udp-domain"]:
            # target-host trap|inform address udp-domain A [vpn-instance V] params securityname NAME [v1|v2c|v3 [level]]
            host = SnmpHost(str(ipaddress.ip_address(w[5])), "1", informs=w[2] == "inform", origin=origin)
            args = w[6:]
            if args[:1] == ["vpn-instance"] and len(args) >= 2:
                host.vrf, args = args[1], args[2:]
            if args[:2] != ["params", "securityname"] or len(args) < 3:
                return False
            host.secret, args = args[2], args[3:]
            if args[:1] in (["v1"], ["v2c"], ["v3"]):
                host.version, args = args[0][1:], args[1:]
            if host.version == "3":
                host.level = {"authentication": "auth", "privacy": "priv"}.get(args[0], "") if args else "noauth"
                args = args[1:]
            s.hosts.append(host)
            return not args and w[2] in ("trap", "inform")
        if w[1:3] == ["group", "v3"] and len(w) >= 4:
            group = SnmpGroup(w[3], "noauth", origin=origin)
            args = w[4:]
            if args[:1] in (["authentication"], ["privacy"]):
                group.level, args = ("auth" if args[0] == "authentication" else "priv"), args[1:]
            while len(args) >= 2 and args[0] in ("read-view", "write-view"):
                setattr(group, f"{args[0][:-5]}_view", args[1])
                args = args[2:]
            s.groups[group.name] = group
            return not args
        if w[1:3] == ["usm-user", "v3"] and len(w) >= 5:
            # usm-user v3 U G [simple|cipher] [authentication-mode A KEY [privacy-mode P KEY]]
            user = SnmpUser(w[3], w[4], origin=origin)
            args = w[5:]
            encrypted = args[:1] == ["cipher"]
            if args[:1] in (["simple"], ["cipher"]):
                args = args[1:]
            if args[:1] == ["authentication-mode"] and len(args) >= 3:
                user.auth, user.auth_key, args = args[1], ("" if encrypted else args[2]), args[3:]
            if args[:1] == ["privacy-mode"] and len(args) >= 3:
                user.priv = {"des56": "des", "3des": "3des"}.get(args[1], args[1])
                user.priv_key, args = ("" if encrypted else args[2]), args[3:]
            s.users.append(user)
            return not args
        return False

    # users and AAA -----------------------------------------------------------------------------------------------------

    @staticmethod
    def _password(user: LocalUser, w: List[str]) -> bool:
        """simple|hash|cipher VALUE"""
        if len(w) != 2:
            return False
        if w[0] == "simple":
            user.password = w[1]
        elif w[0] in ("hash", "cipher"):
            user.password_hash, user.hash_type = w[1], f"comware-{w[0]}"
        else:
            return False
        return True

    @staticmethod
    def role_level(role: str) -> Optional[int]:
        if role.startswith("level-") and role[len("level-"):].isdigit():
            return int(role[len("level-"):])
        return aaa_text.privilege(role, COMWARE_ROLES)

    def local_user(self, node: Node) -> bool:
        """local-user U [class manage]: password, service-type, authorization-attribute user-role"""
        w = node.words
        if w[2:] not in ([], ["class", "manage"]):
            return False
        user = LocalUser(w[1], origin=Origin(node.line, node.text))
        self.device.users.append(user)
        for child in node.children:
            c = child.words
            if c[0] == "password" and self._password(user, c[1:]):
                continue
            if c[0] == "service-type" or c[:2] == ["authorization-attribute", "work-directory"]:
                continue
            if c[:2] == ["authorization-attribute", "user-role"] and len(c) == 3:
                level = self.role_level(c[2])
                if level is not None:
                    user.privilege = max(level, user.privilege or 0)
                    continue
            self.unparsed(child, node.text)
        return True

    def super_password(self, node: Node) -> bool:
        """super password [role R] simple|hash|cipher X: the password to raise the role"""
        w = node.words
        args = w[2:]
        if args[:1] == ["role"] and len(args) >= 2:
            if args[1] != "network-admin":
                return False
            args = args[2:]
        user = LocalUser("enable", 15, origin=Origin(node.line, node.text))
        self.device.aaa.enable_secret = user
        return w[1] == "password" and self._password(user, args)

    def aaa_scheme(self, node: Node) -> bool:
        """radius|hwtacacs scheme S (a server group) or radius|hwtacacs nas-ip A"""
        w = node.words
        protocol = "radius" if w[0] == "radius" else "tacacs"
        if w[1] == "nas-ip" and len(w) == 3:
            self._nas_ip[protocol] = (w[2], node.line)
            return True
        if w[1] != "scheme" or len(w) != 3:
            return False
        a = self.device.aaa
        group = AaaGroup(protocol, w[2], origin=Origin(node.line, node.text))
        a.groups[group.name] = group
        timeout: Optional[int] = None
        found: List[AaaServer] = []
        for child in node.children:
            c = child.words
            if c[0] in ("primary", "secondary") and len(c) >= 3:
                server = self._scheme_server(protocol, c[1:], child, found)
                if server is not None:
                    if server.address not in group.servers:
                        group.servers.append(server.address)
                    continue
            elif c[0] == "vpn-instance" and len(c) == 2:
                group.vrf = c[1]
                continue
            elif c[:2] == ["timer", "response-timeout"] and len(c) == 3:
                timeout = int(c[2])
                continue
            elif c[0] == "nas-ip" and len(c) == 2:
                self._nas_ip[protocol] = (c[1], child.line)
                continue
            elif c[0] in ("user-name-format", "key"):  # key: the scheme-wide key, read below
                if c[0] == "key" and len(c) == 4 and c[2] in ("simple", "cipher"):
                    for server in found:
                        server.key = server.key or (c[3] if c[2] == "simple" else "")
                continue
            self.unparsed(child, node.text)
        for server in found:
            server.timeout = timeout
            server.vrf = server.vrf or group.vrf
        return True

    def _scheme_server(self, protocol: str, c: List[str], child: Node, found: List[AaaServer]) -> Optional[AaaServer]:
        """authentication|authorization|accounting A [port] [key simple|cipher K] [vpn-instance V]"""
        role, address, args = c[0], c[1], c[2:]
        if role not in ("authentication", "authorization", "accounting") or not _is_address(address):
            return None
        server = next((s for s in found if s.address == address), None)
        if server is None:
            server = AaaServer(protocol, address, origin=Origin(child.line, child.text))
            found.append(server)
            existing = next((s for s in self.device.aaa.servers if s.protocol == protocol and s.address == address), None)
            if existing is None:
                self.device.aaa.servers.append(server)
            else:  # the same server in another scheme
                found[-1] = server = existing
        port: Optional[int] = None
        while args:
            if args[0].isdigit():
                port, args = int(args[0]), args[1:]
            elif args[0] == "key" and len(args) >= 3 and args[1] in ("simple", "cipher"):
                server.key = args[2] if args[1] == "simple" else server.key
                args = args[3:]
            elif args[0] == "vpn-instance" and len(args) >= 2:
                server.vrf, args = args[1], args[2:]
            else:
                return None
        if port is not None:
            if role == "accounting" and protocol == "radius":
                server.acct_port = None if port == 1813 else port
            elif role == "authentication" or protocol == "tacacs":
                server.auth_port = None if port == (1812 if protocol == "radius" else 49) else port
        return server

    _DOMAIN = {("authentication", "login"): ("authentication", "login"),
               ("authentication", "super"): ("authentication", "enable"),
               ("authorization", "login"): ("authorization", "exec"),
               ("authorization", "command"): ("authorization", "commands"),
               ("accounting", "login"): ("accounting", "exec"),
               ("accounting", "command"): ("accounting", "commands"),
               ("authentication", "lan-access"): ("authentication", "dot1x")}

    def domain(self, node: Node) -> bool:
        """domain NAME: the method lists of an ISP domain; domain default enable NAME"""
        w = node.words
        if w[1:3] == ["default", "enable"] and len(w) == 4:
            self._default_domain = w[3]
            return True
        if len(w) != 2:
            return False
        methods = self._domains.setdefault(w[1], [])
        for child in node.children:
            c = child.words
            if c[:2] in (["authorization", "lan-access"], ["accounting", "lan-access"]):
                continue  # goes with authentication lan-access
            kind = self._DOMAIN.get((c[0], c[1])) if len(c) >= 3 else None
            words = self._methods(c[2:]) if kind else None
            if kind is None or not words:
                if c[0] != "state":
                    self.unparsed(child, node.text)
                continue
            m = AaaMethod(kind[0], kind[1], words, origin=Origin(child.line, child.text))
            if kind[1] == "commands":
                m.level = 15
            if kind[0] == "accounting":
                m.record = "start-stop"
            methods.append(m)
        return True

    def traffic(self, node: Node) -> bool:
        """traffic classifier NAME [operator and|or]: if-match dscp|acl; traffic behavior NAME: remark dscp, car"""
        w = node.words
        if w[1] == "classifier" and len(w) in (3, 5):
            if len(w) == 5 and (w[3] != "operator" or w[4] not in ("and", "or")):
                return False
            qos_class = QosClass(w[2], match_all=len(w) == 3 or w[4] == "and", origin=Origin(node.line, node.text))
            self.device.qos_classes[qos_class.name] = qos_class
            for child in node.children:
                c = child.words
                try:
                    if c[:2] == ["if-match", "dscp"] and len(c) >= 3:
                        qos_class.dscp += [qos_text.dscp(x) for x in c[2:]]
                        continue
                    if c[:2] == ["if-match", "acl"] and len(c) in (3, 4) and (len(c) == 3 or c[2] == "name"):
                        qos_class.acl = c[-1]
                        continue
                except ValueError:
                    pass
                self.unparsed(child, node.text)
            return True
        if w[1] == "behavior" and len(w) == 3:
            action = QosAction("")
            self._behaviors[w[2]] = action
            for child in node.children:
                c = child.words
                if c[:2] == ["remark", "dscp"] and len(c) == 3:
                    action.set_dscp = qos_text.dscp(c[2])
                elif c[:2] == ["car", "cir"] and len(c) >= 3 and self._car(action, c[2:]):
                    pass
                else:
                    self.unparsed(child, node.text)
            return True
        return False

    @staticmethod
    def _car(action: QosAction, w: List[str]) -> bool:
        """car cir KBPS [cbs N] [ebs N] [green pass] [red discard]"""
        action.police_kbps = int(w[0])
        args = w[1:]
        red = "discard"
        while args:
            if args[0] in ("cbs", "ebs") and len(args) >= 2:
                args = args[2:]
            elif args[0] in ("green", "yellow", "red") and len(args) >= 2:
                if args[0] == "red":
                    red = args[1]
                elif args[1] != "pass":
                    return False
                args = args[2:]
            else:
                return False
        return red == "discard"

    def qos_policy(self, node: Node) -> bool:
        """qos policy NAME: classifier C behavior B"""
        w = node.words
        if w[1] != "policy" or len(w) != 3:
            return False
        policy = QosPolicy(w[2], origin=Origin(node.line, node.text))
        self.device.qos_policies[policy.name] = policy
        for child in node.children:
            c = child.words
            if c[0] == "classifier" and len(c) == 4 and c[2] == "behavior":
                self._policy_pairs.append((policy, c[1], c[3], child))
            else:
                self.unparsed(child, node.text)
        return True

    def dot1x(self, node: Node) -> bool:
        """dot1x; mac-authentication; dot1x timer reauth-period N; dot1x authentication-method eap|chap|pap"""
        w = node.words
        if w == ["dot1x"]:
            self.device.aaa.dot1x = True
            return True
        if w == ["mac-authentication"] or w[:2] == ["dot1x", "authentication-method"] and len(w) == 3:
            return True
        if w[:3] == ["dot1x", "timer", "reauth-period"] and len(w) == 4:
            self._reauth_period = int(w[3])
            return True
        return False

    def transfer(self, node: Node) -> bool:
        """tftp|ftp client source interface X"""
        w = node.words
        if w[1:4] == ["client", "source", "interface"] and len(w) in (5, 6):
            self.device.system.transfer_source[w[0]] = canonical("".join(w[4:]))[0]
            return True
        return False

    def dot1x_line(self, iface: Interface, w: List[str]) -> bool:
        n = len(w)
        if w == ["dot1x"]:
            iface.dot1x = True
        elif w == ["mac-authentication"]:
            iface.mab = True
        elif w[:2] == ["dot1x", "port-method"] and n == 3 and w[2] in ("macbased", "portbased"):
            if w[2] == "portbased":
                self._port_based.add(iface.name)
        elif w == ["dot1x", "re-authenticate"]:
            iface.dot1x_reauth = True
        elif w[1:2] == ["max-user"] and n == 3:
            self._max_users[(iface.name, w[0])] = int(w[2])
        else:
            return False
        return True

    def line(self, node: Node) -> bool:
        """line vty|class ...: AAA ('authentication-mode scheme') is what the method lists describe; the VTY lines
        also say which protocols come in and the idle timeout."""
        if node.words[1] not in ("vty", "class", "aux", "console"):
            return False
        m = self.device.management
        vty = node.words[1] == "vty"
        for child in node.children:
            c = child.words
            if c == ["authentication-mode", "scheme"]:
                continue
            if vty and c[:2] == ["protocol", "inbound"] and len(c) == 3 and c[2] in ("ssh", "telnet", "all"):
                m.ssh = c[2] in ("ssh", "all") if m.ssh is not False else m.ssh
                m.telnet = c[2] in ("telnet", "all") if m.telnet is not False else m.telnet
            elif vty and c[0] == "idle-timeout" and len(c) in (2, 3) and all(x.isdigit() for x in c[1:]):
                m.exec_timeout = int(c[1]) + (1 if c[2:] and int(c[2]) else 0)
            else:
                self.unparsed(child, node.text)
        return True

    def server(self, node: Node) -> bool:
        """ssh server enable, telnet server enable, lldp global enable."""
        w = node.words
        if w in (["ssh", "server", "enable"], ["telnet", "server", "enable"], ["lldp", "global", "enable"]):
            setattr(self.device.management, w[0], True)
            return True
        return False

    def undo(self, node: Node) -> bool:
        w = node.words[1:]
        m = self.device.management
        if w in (["ssh", "server", "enable"], ["telnet", "server", "enable"], ["lldp", "global", "enable"]):
            setattr(m, w[0], False)
            return True
        if w in (["ip", "http", "enable"], ["ip", "https", "enable"]):
            setattr(m, w[1], False)
            return True
        if w[:1] == ["stp"]:
            return self.stp(node)
        return False

    @staticmethod
    def _methods(words: List[str]) -> Optional[List[str]]:
        methods = []
        while words:
            if words[0] in ("radius-scheme", "hwtacacs-scheme") and len(words) >= 2:
                methods.append(f"group:{words[1]}")
                words = words[2:]
            elif words[0] in ("local", "none"):
                methods.append(words[0])
                words = words[1:]
            else:
                return None
        return methods

    def _finish_qos(self) -> None:
        for policy, classifier, behavior, line in self._policy_pairs:
            template = self._behaviors.get(behavior)
            if template is None:
                self.unparsed(line, f"qos policy {policy.name}: behavior {behavior} is not defined")
                continue
            name = qos_text.DEFAULT_CLASS if classifier == "default-class" else classifier
            policy.actions.append(QosAction(name, template.set_dscp, template.police_kbps))

    def _finish_aaa(self) -> None:
        a = self.device.aaa
        for iface in self.device.interfaces.values():
            if iface.dot1x_reauth:
                iface.dot1x_reauth_period = self._reauth_period
            if iface.dot1x or iface.mab:
                # MAC-based access (the default) lets each client log in, up to max-user; port-based opens the port
                limit = self._max_users.get((iface.name, "dot1x" if iface.dot1x else "mac-authentication"), 4096)
                iface.dot1x_host_mode = "multi-host" if iface.name in self._port_based and iface.dot1x else \
                    "single-host" if limit == 1 else "multi-auth"
        for name, methods in self._domains.items():
            for m in methods:
                m.name = "default" if name == self._default_domain else name
                a.methods.append(m)
        for protocol, (address, line) in self._nas_ip.items():
            source = next((i.name for i in self.device.interfaces.values()
                           if any(ipaddress.ip_interface(x).ip == ipaddress.ip_address(address) for x in i.ipv4)), "")
            if source:
                a.source[protocol] = source
            else:
                self.device.unparsed.append(Unparsed(line, f"{'radius' if protocol == 'radius' else 'hwtacacs'} nas-ip "
                                                        f"{address}", "no interface has the source address"))

    def info_center(self, node: Node) -> bool:
        w = node.words
        if w[1:3] == ["loghost", "source"] and len(w) == 4:
            self.device.system.logging_source = canonical(w[3])[0]
            return True
        if w[1:4] == ["source", "default", "loghost"] and len(w) == 6 and w[4] == "level" \
                and mgmt_text.level(w[5]) is not None:
            self.device.system.logging_level = mgmt_text.level(w[5])
            return True
        if w[1:2] == ["loghost"]:
            args = self._vpn(w[2:])
            if len(args) == 1 and _is_address(args[0]):
                self.device.system.syslog_servers.append(args[0])
                return True
        return w[1:] == ["enable"]

    def route_policy(self, node: Node) -> bool:
        """route-policy NAME permit|deny node N, with if-match and apply lines."""
        w = node.words
        if len(w) != 5 or w[2] not in ("permit", "deny") or w[3] != "node" or not w[4].isdigit():
            return False
        e = routemap_text.entry(routemap_text.route_map(self.device, w[1]), int(w[4]), w[2])
        for child in node.children:
            try:
                ok = routemap_text.comware_route_policy_line(e, child.words)
            except ValueError:
                ok = False
            if not ok:
                self.unparsed(child, node.text)
        return True

    def igmp_snooping(self, node: Node) -> bool:
        """igmp-snooping: switched on for the device; the VLANs say where it runs."""
        if node.words != ["igmp-snooping"]:
            return False
        for child in node.children:
            self.unparsed(child, node.text)
        return True

    def multicast(self, node: Node) -> bool:
        if node.words != ["multicast", "routing"]:
            return False
        self.device.multicast_routing = True
        for child in node.children:
            self.unparsed(child, node.text)
        return True

    def pim(self, node: Node) -> bool:
        """pim with static-rp A."""
        if node.words != ["pim"]:
            return False
        for child in node.children:
            c = child.words
            if c[0] == "static-rp" and len(c) == 2:
                self.device.pim_rps.append(str(ipaddress.IPv4Address(c[1])))
            else:
                self.unparsed(child, node.text)
        return True

    def rip(self, node: Node) -> bool:
        """rip [N] with version, network, silent-interface, import-route, ..."""
        if len(node.words) > 2 or self.device.rip is not None:
            return False
        rip = self.device.rip = Rip(origin=Origin(node.line, node.text))
        return self._igp_children(node, lambda c: igp_text.comware_rip_line(rip, c, lambda n: canonical(n)[0]))

    def isis(self, node: Node) -> bool:
        """isis [N] with network-entity, is-level, cost-style, import-route."""
        if len(node.words) > 2 or self.device.isis is not None:
            return False
        isis = self.device.isis = Isis(node.words[1] if len(node.words) == 2 else "",
                                       origin=Origin(node.line, node.text))
        return self._igp_children(node, lambda c: igp_text.comware_isis_line(isis, c))

    def _igp_children(self, node: Node, read: Callable[[List[str]], bool]) -> bool:
        for child in node.children:
            if child.words[:2] == ["address-family", "ipv4"] and len(child.words) <= 3:
                for line in child.children:  # (nothing inside is converted yet)
                    self.unparsed(line, f"{node.text} / {child.text}")
                continue
            try:
                ok = read(child.words)
            except (ValueError, IndexError):
                ok = False
            if not ok:
                self.unparsed(child, node.text)
        return True

    def policy_based_route(self, node: Node) -> bool:
        """policy-based-route NAME permit|deny node N with if-match acl and apply next-hop, read as a route map."""
        w = node.words
        if len(w) != 5 or w[2] not in ("permit", "deny") or w[3] != "node" or not w[4].isdigit():
            return False
        rm = routemap_text.route_map(self.device, w[1])
        e = routemap_text.entry(rm, int(w[4]), w[2])
        for child in node.children:
            c = child.words
            if c[:2] == ["if-match", "acl"] and len(c) in (3, 4) and (len(c) == 3 or c[2] == "name"):
                e.match_acls.append(c[-1])
            elif c[:2] == ["apply", "next-hop"] and len(c) == 3:
                e.sets["next-hop"] = str(ipaddress.ip_address(c[2]))
            else:
                self.unparsed(child, node.text)
        return True

    def ip(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["host"] and len(w) == 4:
            self.device.system.dns_hosts[w[2]] = str(ipaddress.ip_address(w[3]))
            return True
        if w[1:3] == ["netstream", "export"] and not node.children:
            return self.netstream_export(node, w[3:])
        if w[1:2] == ["prefix-list"]:
            return routemap_text.comware_prefix_entry(self.device, w)
        if w[1:] in (["http", "enable"], ["https", "enable"]):
            setattr(self.device.management, w[1], True)
            return True
        if w[1:2] == ["vpn-instance"] and len(w) == 3:
            if w[2] not in self.device.vrfs:
                self.device.vrfs.append(w[2])
            info = vrfs_text.info(self.device, w[2])
            for child in node.children:
                c = child.words
                if c[0] == "route-distinguisher" and len(c) == 2:
                    info.rd = c[1]
                elif c[0] == "vpn-target" and len(c) >= 2:
                    kinds = {"import-extcommunity": "import", "export-extcommunity": "export", "both": "both"}
                    direction = kinds.get(c[-1], "")
                    values = c[1:-1] if direction else c[1:]
                    for value in values:
                        vrfs_text.route_target(info, direction or "both", value)
                elif c[0] != "description":
                    self.unparsed(child, node.text)
            return True
        if w[1:2] == ["route-static"]:
            return self.route(node, w[2:], 4)
        return False

    def ipv6(self, node: Node) -> bool:
        if node.words[1:2] == ["prefix-list"]:
            return routemap_text.comware_prefix_entry(self.device, node.words)
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
            elif word == "track" and rest:
                route.track = rest.pop(0)
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
                elif child.text == "arp detection enable":
                    vlan.arp_inspection = True
                elif child.text == "igmp-snooping enable":
                    vlan.igmp_snooping = True
                elif child.text == "igmp-snooping querier":
                    vlan.igmp_querier = True
                elif vid == ids[0]:
                    self.unparsed(child, node.text)
        return True

    def wlan(self, node: Node) -> bool:
        """wlan service-template NAME: ssid, vlan, akm mode psk|dot1x, preshared-key, service-template enable."""
        w = node.words
        if w[1] != "service-template" or len(w) != 3:
            return False
        wl = Wlan(w[2], ssid=w[2], security="open", enabled=False, origin=Origin(node.line, node.text))
        for child in node.children:
            c = child.words
            if c[0] == "ssid" and len(c) == 2:
                wl.ssid = c[1]
            elif c[0] == "vlan" and len(c) == 2 and c[1].isdigit():
                wl.vlan = int(c[1])
            elif c[:2] == ["akm", "mode"] and len(c) == 3 and c[2] in ("psk", "dot1x"):
                wl.security = c[2]
            elif c[0] == "preshared-key" and len(c) == 4 and c[1] in ("pass-phrase", "raw-key") \
                    and c[2] in ("simple", "cipher"):
                wl.psk = c[3] if c[2] == "simple" else ""
            elif c in (["cipher-suite", "ccmp"], ["security-ie", "rsn"],
                       ["client-security", "authentication-mode", "dot1x"]):
                pass
            elif c in (["service-template", "enable"], ["undo", "service-template", "enable"]):
                wl.enabled = c[0] != "undo"
            else:
                self.unparsed(child, node.text)
        self.device.wlans.append(wl)
        return True

    def mpls(self, node: Node) -> bool:
        """mpls lsr-id A.B.C.D, and the mpls ldp view (lsr-id may be given there too)."""
        w = node.words
        m = self.device.mpls
        m.origin = Origin(node.line, node.text)
        if w[1] == "lsr-id" and len(w) == 3:
            m.router_id = str(ipaddress.ip_address(w[2]))
            return True
        if w[1:] == ["ldp"]:
            m.ldp = True
            for child in node.children:
                if child.words[0] == "lsr-id" and len(child.words) == 2:
                    m.router_id = str(ipaddress.ip_address(child.words[1]))
                else:
                    self.unparsed(child, node.text)
            return True
        return False

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
        stp = self.device.stp
        if w[1] == "priority" and len(w) == 3:
            stp.priority[0] = int(w[2])
            return True
        if w[1] == "instance" and len(w) == 5 and w[3] == "priority":
            stp.priority[int(w[2])] = int(w[4])
            return True
        if w[1] == "vlan" and len(w) >= 5 and w[-2] == "priority":  # stp vlan 10 20 to 30 priority N
            for vlan in vlan_list(w[2:-2]):
                stp.vlan_priority[vlan] = int(w[-1])
            return True
        if w[1:] == ["region-configuration"]:
            for child in node.children:
                c = child.words
                if c[0] == "region-name" and len(c) == 2:
                    stp.region = c[1]
                elif c[0] == "revision-level" and len(c) == 2:
                    stp.revision = int(c[1])
                elif c[0] == "instance" and len(c) >= 4 and c[2] == "vlan":
                    stp.instances.setdefault(int(c[1]), []).extend(vlan_list(c[3:]))
                elif c != ["active", "region-configuration"]:
                    self.unparsed(child, node.text)
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

    def dhcp(self, node: Node) -> bool:
        """dhcp enable, dhcp snooping enable, dhcp server forbidden-ip, dhcp server ip-pool NAME."""
        w = node.words
        if w[1:] == ["enable"]:
            return True
        if w[1:] == ["snooping", "enable"]:
            self.device.dhcp_snooping = True
            return True
        if w[1:3] == ["server", "forbidden-ip"] and len(w) >= 4:
            args = w[3:]
            vrf = ""
            if args[-2:-1] == ["vpn-instance"]:
                vrf, args = args[-1], args[:-2]
            if len(args) not in (1, 2):
                return False
            addresses = [str(ipaddress.IPv4Address(a)) for a in args]
            self._dhcp_excluded.setdefault(vrf, []).append((addresses[0], addresses[-1]))
            return True
        if w[1:3] != ["server", "ip-pool"] or len(w) != 4:
            return False
        pool = DhcpPool(w[3], origin=Origin(node.line, node.text))
        self.device.dhcp_pools.append(pool)
        for child in node.children:
            c = child.words
            try:
                if c[0] == "network" and len(c) == 4 and c[2] == "mask":
                    pool.network = str(ipaddress.ip_network(f"{c[1]}/{c[3]}"))
                elif c[:2] == ["address", "range"] and len(c) == 4:
                    pool.ranges.append((str(ipaddress.IPv4Address(c[2])), str(ipaddress.IPv4Address(c[3]))))
                elif c[0] == "gateway-list" and len(c) >= 2:
                    pool.default_routers += [str(ipaddress.IPv4Address(a)) for a in c[1:]]
                elif c[0] == "dns-list" and len(c) >= 2:
                    pool.dns_servers += [str(ipaddress.IPv4Address(a)) for a in c[1:]]
                elif c[0] == "domain-name" and len(c) == 2:
                    pool.domain_name = c[1]
                elif c == ["expired", "unlimited"]:
                    pool.lease_seconds = 0
                elif c[0] == "expired" and len(c) in (3, 5, 7):
                    units = {unit: int(value) for unit, value in zip(c[1::2], c[2::2])}
                    pool.lease_seconds = dhcp_text.lease_seconds(units.get("day", 0), units.get("hour", 0),
                                                                 units.get("minute", 0))
                elif c[0] == "vpn-instance" and len(c) == 2:
                    pool.vrf = c[1]
                else:
                    self.unparsed(child, node.text)
            except ValueError:
                self.unparsed(child, node.text)
        return True

    def ike(self, node: Node) -> bool:
        """ike proposal N, ike keychain K, ike profile P (IKEv1)."""
        w = node.words
        if w[1] == "proposal" and len(w) == 3:
            policy = IkePolicy(w[2], 1, ["des"], ["sha1"], [1], origin=Origin(node.line, node.text))
            self.device.ike_policies[w[2]] = policy
            self._children(node, lambda c: self._ike_proposal_line(policy, c.words))
            return True
        if w[1] == "keychain" and len(w) == 3:
            self._children(node, lambda c: self._keychain_line(c))
            return True
        if w[1] == "profile" and len(w) == 3:
            proposals: List[str] = []
            remotes: List[str] = []
            self._ike_profiles[w[2]] = (proposals, remotes)
            self._children(node, lambda c: self._ike_profile_line(c.words, proposals, remotes))
            return True
        return False

    def _children(self, node: Node, line: Callable[[Node], bool]) -> None:
        for child in node.children:
            try:
                understood = line(child)
            except (ValueError, IndexError):
                understood = False
            if not understood:
                self.unparsed(child, node.text)

    @staticmethod
    def _ike_proposal_line(policy: IkePolicy, w: List[str]) -> bool:
        if w[0] == "encryption-algorithm" and len(w) == 2:
            policy.encryption = [vpn_text.read(vpn_text.COMWARE_ENC, w[1])]
        elif w[0] == "authentication-algorithm" and len(w) == 2:
            policy.integrity = [vpn_text.read(vpn_text.COMWARE_IKE_INT, w[1])]
        elif w[0] == "dh" and len(w) == 2 and w[1].startswith("group"):
            policy.dh_groups = [int(w[1][len("group"):])]
        elif w[:2] == ["sa", "duration"] and len(w) == 3:
            policy.lifetime = int(w[2])
        elif w[0] == "authentication-method" and len(w) == 2:
            policy.authentication = w[1]
        else:
            return False
        return True

    def _keychain_line(self, node: Node) -> bool:
        """pre-shared-key address A [M] key simple|cipher K"""
        w = node.words
        if w[:2] != ["pre-shared-key", "address"] or "key" not in w or len(w) < 6:
            return False
        address = str(ipaddress.IPv4Address(w[2]))
        kind, key = w[-2:]
        if kind not in ("simple", "cipher"):
            return False
        self.device.psks[address] = PreSharedKey(address, key if kind == "simple" else "", Origin(node.line, node.text))
        return True

    @staticmethod
    def _ike_profile_line(w: List[str], proposals: List[str], remotes: List[str]) -> bool:
        if w[0] == "keychain" and len(w) == 2:
            pass  # keys are looked up by address
        elif w[:4] == ["match", "remote", "identity", "address"] and len(w) in (5, 6):
            remotes.append(str(ipaddress.IPv4Address(w[4])))
        elif w[0] == "proposal" and len(w) >= 2:
            proposals.extend(w[1:])
        elif w[0] == "local-identity" and w[1:2] == ["address"]:
            pass
        else:
            return False
        return True

    def ipsec(self, node: Node) -> bool:
        """ipsec transform-set TS, ipsec policy MAP SEQ isakmp, ipsec profile P [isakmp]."""
        w = node.words
        origin = Origin(node.line, node.text)
        if w[1] == "transform-set" and len(w) == 3:
            transform = IpsecTransform(w[2], origin=origin)
            self.device.ipsec_transforms[w[2]] = transform
            self._children(node, lambda c: self._transform_line(transform, c.words))
            return True
        if w[1] == "policy" and len(w) == 5 and w[4] == "isakmp":
            peer = IpsecPeer(w[2], int(w[3]), origin=origin)
        elif w[1] == "profile" and len(w) in (3, 4) and w[3:] in ([], ["isakmp"]):
            peer = IpsecPeer(w[2], origin=origin)
        else:
            return False
        self.device.ipsec_peers.append(peer)
        self._children(node, lambda c: self._ipsec_policy_line(peer, c.words))
        return True

    def _transform_line(self, transform: IpsecTransform, w: List[str]) -> bool:
        if w[:2] == ["esp", "encryption-algorithm"] and len(w) == 3:
            transform.encryption = vpn_text.read(vpn_text.COMWARE_ESP_ENC, w[2])
        elif w[:2] == ["esp", "authentication-algorithm"] and len(w) == 3:
            transform.integrity = vpn_text.read(vpn_text.COMWARE_ESP_INT, w[2])
        elif w[0] == "encapsulation-mode" and w[1:] in (["tunnel"], ["transport"]):
            transform.mode = w[1]
        elif w == ["protocol", "esp"]:
            pass
        elif w[0] == "pfs" and len(w) == 2 and w[1].startswith("dh-group"):
            self._pfs[transform.name] = int(w[1][len("dh-group"):])
        else:
            return False
        return True

    def _ipsec_policy_line(self, peer: IpsecPeer, w: List[str]) -> bool:
        if w[0] == "transform-set" and len(w) >= 2:
            peer.transforms = w[1:]
        elif w[:2] == ["security", "acl"] and len(w) in (3, 4) and not peer.profile:
            peer.acl = w[3] if w[2] == "name" and len(w) == 4 else w[2]
        elif w[0] == "remote-address" and len(w) == 2 and not peer.profile:
            peer.peer = str(ipaddress.IPv4Address(w[1]))
        elif w[0] == "ike-profile" and len(w) == 2:
            self._peer_profiles.append((peer, w[1]))
        elif w[:3] == ["sa", "duration", "time-based"] and len(w) == 4:
            peer.lifetime = int(w[3])
        else:
            return False
        return True

    def nat(self, node: Node) -> bool:
        """nat address-group N [name X] / address A B; nat static outbound A [vpn-instance V] B."""
        w = node.words
        if w[1] == "address-group" and len(w) in (3, 5) and w[2].isdigit():
            name = w[4] if len(w) == 5 and w[3] == "name" else w[2]
            if len(w) == 5 and w[3] != "name":
                return False
            self._nat_groups[w[2]] = name
            for child in node.children:
                c = child.words
                if c[0] == "address" and len(c) == 3 and name not in self.device.nat_pools:
                    first, last = (str(ipaddress.IPv4Address(a)) for a in c[1:])
                    self.device.nat_pools[name] = NatPool(name, first, last)
                else:
                    self.unparsed(child, node.text)
            return True
        if w[1:3] == ["static", "outbound"] and len(w) in (5, 7):
            vrf = w[5] if len(w) == 7 and w[4] == "vpn-instance" else ""
            if len(w) == 7 and not vrf:
                return False
            rule = NatRule("static", str(ipaddress.IPv4Address(w[3])), str(ipaddress.IPv4Address(w[-1])), vrf=vrf,
                           origin=Origin(node.line, node.text))
            self.device.nat_rules.append(rule)
            return True
        return False

    def nat_interface(self, iface: Interface, w: List[str]) -> bool:
        """nat outbound [ACL|name ACL] [address-group G] [no-pat]; nat static enable; nat server ... (outside)."""
        if w == ["nat", "static", "enable"]:
            iface.nat = "outside"
            return True
        if w[1] == "outbound":
            rule = NatRule("dynamic", interface=iface.name, overload=True)
            args = w[2:]
            if args[:1] == ["name"] and len(args) >= 2:
                rule.acl, args = args[1], args[2:]
            elif args[:1] and args[0].isdigit():
                rule.acl, args = args[0], args[1:]
            if args[:1] == ["address-group"] and len(args) >= 2:
                group = args[2] if args[1] == "name" else args[1]
                rule.pool = group  # the number, named in _finish
                args = args[3:] if args[1] == "name" else args[2:]
            if args == ["no-pat"]:
                rule.overload = False
            elif args:
                return False
        elif w[1] == "server":
            rule = NatRule("static", interface=iface.name)
            args = w[2:]
            if args[:1] == ["protocol"] and len(args) >= 8 and args[1] in ("tcp", "udp"):
                rule.protocol = args[1]
                args = args[2:]
            if args[:1] != ["global"] or "inside" not in args:
                return False
            split = args.index("inside")
            outside, inside = args[1:split], args[split + 1:]
            if inside[-2:-1] == ["vpn-instance"]:
                rule.vrf, inside = inside[-1], inside[:-2]
            if len(outside) != len(inside) or len(outside) != (2 if rule.protocol else 1):
                return False
            rule.translated, rule.local = (str(ipaddress.IPv4Address(a[0])) for a in (outside, inside))
            if rule.protocol:
                rule.translated_port, rule.local_port = int(outside[1]), int(inside[1])
        else:
            return False
        iface.nat = "outside"
        self.device.nat_rules.append(rule)
        return True

    def bgp(self, node: Node) -> bool:
        """bgp AS, with groups, peers and address families inside."""
        if len(node.words) != 2 or self.device.bgp is not None:
            return False
        b = bgp_text.Builder(node.words[1])
        b.default_ipv4 = False  # Comware enables each peer in the address family
        b.bgp.origin = Origin(node.line, node.text)
        vrfs: Dict[str, bgp_text.Builder] = {}
        self._bgp_block(b, node.children, node.text, vrfs)
        self.device.bgp = b.finish()
        for name, vb in vrfs.items():
            vrf_bgp = vb.finish()
            self.device.bgp.vrfs[name] = BgpVrf(vrf_bgp.neighbors, vrf_bgp.networks, vrf_bgp.redistribute,
                                                vrf_bgp.redistribute_maps, vrf_bgp.maximum_paths)
        return True

    def _bgp_block(self, b: bgp_text.Builder, children: List[Node], section: str,
                   vrfs: Optional[Dict[str, bgp_text.Builder]]) -> None:
        for child in children:
            w = child.words
            af = ""
            if w[:2] == ["ip", "vpn-instance"] and len(w) == 3 and vrfs is not None:
                vb = vrfs[w[2]] = bgp_text.Builder(b.bgp.local_as)
                vb.default_ipv4 = False
                self._bgp_block(vb, child.children, f"{section} / {child.text}", None)
                continue
            if w[0] == "address-family" and w[1:] in (["ipv4"], ["ipv4", "unicast"], ["ipv6"], ["ipv6", "unicast"]):
                af = w[1]
            elif w[0] == "address-family":
                self.unparsed(child, section)
                continue
            for line in child.children if af else [child]:
                try:
                    understood = self.bgp_line(b, line.words, af)
                except (ValueError, IndexError):
                    understood = False
                if not understood:
                    self.unparsed(line, f"{section} / {child.text}" if af else section)

    @staticmethod
    def bgp_line(b: bgp_text.Builder, w: List[str], af: str) -> bool:
        n = len(w)
        bgp = b.bgp
        if w[0] == "router-id" and n == 2:
            bgp.router_id = str(ipaddress.IPv4Address(w[1]))
        elif w[0] == "group" and n in (2, 3) and w[2:] in ([], ["external"], ["internal"]):
            group = b.peer(w[1], group=True)
            if w[2:] == ["internal"]:
                group.remote_as = group.remote_as or bgp.local_as
        elif w[0] == "network" and n in (2, 3) and af:
            bgp.networks.append(str(ipaddress.ip_network(f"{w[1]}/{w[2]}" if n == 3 else w[1])))
        elif w[0] == "import-route" and n >= 2 and w[1] in ("direct", "static", "ospf") and af:
            rest = w[3:] if w[1] == "ospf" and n >= 3 and w[2].isdigit() else w[2:]
            if rest[:1] == ["route-policy"] and len(rest) == 2 and af == "ipv4":
                bgp.redistribute_maps["connected" if w[1] == "direct" else w[1]] = rest[1]
            elif rest:
                return False
            (bgp.redistribute6 if af == "ipv6" else bgp.redistribute).append(
                "connected" if w[1] == "direct" else w[1])
        elif w[0] == "balance" and n in (2, 3) and w[-1].isdigit() and af == "ipv4":
            if n == 3 and w[1] == "ibgp":
                bgp.maximum_paths_ibgp = int(w[2])
            elif n == 2 or w[1] in ("ebgp", "eibgp"):
                bgp.maximum_paths = int(w[-1])
            else:
                return False
        elif w[:2] == ["undo", "peer"] and n == 4 and w[3] == "enable":
            b.activate(w[2], af or "ipv4", on=False)
        elif w[0] == "peer" and n >= 3:
            peer = b.peer(w[1])
            args = w[2:]
            if args[0] == "as-number" and len(args) == 2:
                peer.remote_as = args[1]
            elif args[0] == "group" and len(args) in (2, 4) and args[2:3] in ([], ["as-number"]):
                peer.peer_group = args[1]
                b.peer(args[1], group=True)
                if len(args) == 4:
                    peer.remote_as = args[3]
            elif args[0] == "description" and len(args) >= 2:
                peer.description = " ".join(args[1:])
            elif args[0] == "connect-interface" and len(args) == 2:
                peer.update_source = canonical(args[1])[0]
            elif args[0] == "ebgp-max-hop" and len(args) in (1, 2):
                peer.ebgp_multihop = int(args[1]) if len(args) == 2 else 64
            elif args == ["ignore"]:
                peer.shutdown = True
            elif args == ["enable"]:
                b.activate(w[1], af or "ipv4")
            elif args == ["next-hop-local"]:
                peer.next_hop_self = True
            elif args == ["advertise-community"]:
                peer.send_community = True
            elif args == ["bfd"]:
                peer.bfd = True
            elif args[0] == "password" and len(args) == 3 and args[1] in ("simple", "cipher"):
                peer.password = args[2] if args[1] == "simple" else aaa_text.PLACEHOLDER
            elif args[:2] == ["timer", "keepalive"] and len(args) == 5 and args[3] == "hold":
                peer.keepalive, peer.hold = int(args[2]), int(args[4])
            elif args == ["reflect-client"]:
                peer.route_reflector_client = True
            elif args[0] == "route-limit" and len(args) == 2:
                peer.maximum_prefix = int(args[1])
            elif args == ["public-as-only"]:
                peer.remove_private_as = True
            elif args[0] == "allow-as-loop" and len(args) in (1, 2):
                peer.allowas_in = int(args[1]) if len(args) == 2 else 0
            elif routemap_text.neighbor_policy(peer, args):
                pass
            else:
                return False
        else:
            return False
        return True

    def ospf(self, node: Node) -> bool:
        """ospf N [router-id A] [vpn-instance V], areas inside with their network statements."""
        w = node.words[1:]
        number, router_id, vrf = "1", "", ""
        if w and w[0].isdigit():
            number, w = w[0], w[1:]
        while w:
            if w[0] == "router-id" and len(w) >= 2:
                router_id, w = str(ipaddress.IPv4Address(w[1])), w[2:]
            elif w[0] == "vpn-instance" and len(w) >= 2:
                vrf, w = w[1], w[2:]
            else:
                return False
        p = ospf_text.process(self.device, number, vrf)
        p.vrf, p.router_id, p.origin = vrf, router_id, Origin(node.line, node.text)
        for child in node.children:
            try:
                understood = self.ospf_line(p, child)
            except (ValueError, IndexError):
                understood = False
            if not understood:
                self.unparsed(child, node.text)
        return True

    def ospf_line(self, p: Ospf, node: Node) -> bool:
        w = node.words
        n = len(w)
        if w[0] == "area" and n == 2:
            dotted = ospf_text.area(w[1])
            for child in node.children:
                c = child.words
                if c[0] == "network" and len(c) == 3:
                    p.networks.append(OspfNetwork(acl_text.wildcard_prefix(c[1], c[2]), dotted))
                elif c[0] in ("stub", "nssa") and c[1:] in ([], ["no-summary"]):
                    p.area_types[dotted] = " ".join(c)
                else:
                    self.unparsed(child, node.text)
        elif w == ["silent-interface", "all"]:
            p.passive_default = True
        elif w[0] == "silent-interface" and n == 2:
            p.passive_interfaces.append(canonical(w[1])[0])
        elif w[:2] == ["undo", "silent-interface"] and n == 3:
            p.active_interfaces.append(canonical(w[2])[0])
        elif w[0] == "import-route" and n in (2, 4) and w[1] in ("direct", "static", "bgp") and \
                w[2:3] in ([], ["route-policy"]):
            p.redistribute.append("connected" if w[1] == "direct" else w[1])
            if n == 4:
                p.redistribute_maps[p.redistribute[-1]] = w[3]
        elif w[0] == "default-route-advertise" and w[1:] in ([], ["always"]):
            p.default_originate = "always" if n == 2 else "on"
        elif w[0] == "bandwidth-reference" and n == 2:
            p.reference_bandwidth = int(w[1])
        else:
            return False
        return True

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
        elif w[0] == "track" and n in (4, 5) and w[2:4] == ["priority", "reduced"]:
            group.tracks[w[1]] = int(w[4]) if n == 5 else tracking_text.DEFAULT_DECREMENT
        elif w == ["shutdown"]:
            group.shutdown = True
        else:
            return False
        return True

    def interface(self, node: Node) -> bool:
        words = node.words[1:]
        tunnel_mode = ""
        if len(words) == 3 and words[1] == "mode":  # interface Tunnel0 mode ipsec
            words, tunnel_mode = words[:1], words[2]
        source = " ".join(words)
        canon, kind, media = canonical(source)
        if source.upper() == "NULL0" and not node.children:
            return True  # always there
        iface = Interface(canon, kind, source_name=source, media=media, origin=Origin(node.line, node.text))
        if kind == InterfaceKind.SUBINTERFACE:
            iface.parent = canon.rsplit(".", 1)[0]
        if kind == InterfaceKind.ETHERNET or source.startswith("Bridge-Aggregation"):
            iface.mode = SwitchportMode.ACCESS  # bridge mode is the default on a switch
        self.device.interfaces[canon] = iface
        if tunnel_mode in ("gre", "ipsec"):
            iface.tunnel_mode = tunnel_mode
        elif tunnel_mode:
            self.unparsed(node)
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
        if w[0] in ("mirroring-group", "sflow") or w[:2] == ["ip", "netstream"]:
            return self.monitor_line(iface, w)
        if w[0] == "poe" or w == ["undo", "poe", "enable"]:
            return self.poe_line(iface, w)
        if w[0] in ("dot1x", "mac-authentication"):
            return self.dot1x_line(iface, w)
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
        elif w[:3] == ["qos", "apply", "policy"] and n == 5 and w[4] in ("inbound", "outbound"):
            setattr(iface, f"qos_policy_{'in' if w[4] == 'inbound' else 'out'}", w[3])
        elif w[:2] == ["qos", "trust"] and n == 3 and w[2] in ("dscp", "dot1p"):
            iface.qos_trust = "cos" if w[2] == "dot1p" else "dscp"
        elif w[:2] == ["lldp", "admin-status"] and n == 3 and w[2] in ("tx", "rx", "disable", "txrx"):
            iface.lldp_tx, iface.lldp_rx = w[2] in ("tx", "txrx"), w[2] in ("rx", "txrx")
        elif w in (["dhcp", "snooping", "trust"], ["arp", "detection", "trust"]):
            setattr(iface, "dhcp_trust" if w[0] == "dhcp" else "arp_trust", True)
        elif w == ["ip", "verify", "source", "ip-address", "mac-address"]:
            iface.source_guard = True
        elif w == ["port-security", "port-mode", "autolearn"]:
            iface.port_security = True
            iface.port_security_violation = iface.port_security_violation or "protect"  # no intrusion mode: drop
        elif w[:2] == ["port-security", "max-mac-count"] and n == 3:
            iface.port_security_max = int(w[2])
        elif w[:2] == ["port-security", "intrusion-mode"] and n == 3 and w[2] in ("disableport", "blockmac"):
            iface.port_security_violation = "shutdown" if w[2] == "disableport" else "restrict"
        elif w[0] in ("broadcast-suppression", "multicast-suppression", "unicast-suppression") and n == 2:
            kind = w[0].split("-")[0]
            iface.storm_control["unknown-unicast" if kind == "unicast" else kind] = float(w[1])
        elif w == ["undo", "lldp", "enable"]:
            iface.lldp_tx = iface.lldp_rx = False
        elif w in (["mpls", "enable"], ["mpls", "ldp", "enable"]):
            iface.mpls = True
            if w[1] == "ldp":
                self.device.mpls.ldp = True
        elif w[0] == "packet-filter" and w[-1] in ("inbound", "outbound"):
            v6 = w[1:2] == ["ipv6"]
            args = w[2:-1] if v6 else w[1:-1]
            if args[:1] == ["name"]:
                args = args[1:]
            if len(args) != 1:
                return False
            setattr(iface, f"acl{'6' if v6 else ''}_{'in' if w[-1] == 'inbound' else 'out'}", args[0])
        elif w[0] == "ospf" and n == 4 and w[1].isdigit() and w[2] == "area":
            self._ospf_areas.append((iface.name, w[1], ospf_text.area(w[3])))
        elif w[:2] == ["ospf", "cost"] and n == 3:
            iface.ospf_cost = int(w[2])
        elif w[:2] == ["ospf", "network-type"] and n == 3 and w[2] in ("p2p", "broadcast"):
            iface.ospf_network = "point-to-point" if w[2] == "p2p" else "broadcast"
        elif w in (["pim", "sm"], ["pim", "dm"]):
            iface.pim = "sparse" if w[1] == "sm" else "dense"
        elif w == ["igmp", "enable"]:
            pass  # written wherever PIM or an IGMP version is
        elif w[:2] == ["igmp", "version"] and n == 3 and w[2] in ("1", "2", "3"):
            iface.igmp_version = int(w[2])
        elif w == ["ospf", "bfd", "enable"]:
            iface.ospf_bfd = True
        elif w[:2] == ["isis", "enable"] and n in (2, 3):
            iface.isis = True
        elif w == ["isis", "silent"]:
            iface.isis = iface.isis_passive = True
        elif w[:2] == ["isis", "cost"] and n in (3, 4) and w[3:] in ([], ["level-1"], ["level-2"]):
            iface.isis_metric = int(w[2])
        elif w == ["isis", "circuit-type", "p2p"]:
            iface.isis_network = "point-to-point"
        elif bfd_text.separate_line(iface, w):
            pass
        elif w[:2] == ["ip", "policy-based-route"] and n == 3:
            iface.pbr = w[2]
        elif w[0] == "nat" and n >= 2:
            return self.nat_interface(iface, w)
        elif w[:3] == ["ipsec", "apply", "policy"] and n == 4:
            iface.crypto_map = w[3]
        elif w[0] == "source" and n == 2 and iface.kind == InterfaceKind.TUNNEL:
            iface.tunnel_source = w[1] if _is_address(w[1]) else canonical(w[1])[0]
        elif w[0] == "destination" and n == 2 and iface.kind == InterfaceKind.TUNNEL:
            iface.tunnel_destination = str(ipaddress.IPv4Address(w[1]))
        elif w[:4] == ["tunnel", "protection", "ipsec", "profile"] and n == 5:
            iface.tunnel_profile = w[4]
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
        elif w in (["stp", "root-protection"], ["stp", "loop-protection"]):
            iface.stp_guard = w[1][:-len("-protection")]
        elif w == ["stp", "port", "bpdu-filter", "enable"]:
            iface.stp_bpdufilter = True
        elif w[:2] == ["stp", "cost"] and n == 3:
            iface.stp_cost = int(w[2])
        elif w[:3] == ["stp", "port", "priority"] and n == 4:
            iface.stp_port_priority = int(w[3])
        else:
            return False
        return True

    # port mirroring, sFlow, NetStream ---------------------------------------------------------------------------------

    # NQA and tracking -------------------------------------------------------------------------------------------------

    @staticmethod
    def _nqa_name(admin: str, tag: str) -> str:
        return tag if admin == "admin" else f"{admin}-{tag}"

    def nqa(self, node: Node) -> bool:
        """nqa agent enable; nqa schedule A T start-time now lifetime forever; nqa entry A T / type icmp-echo / ..."""
        w = node.words
        if w == ["nqa", "agent", "enable"]:
            return True
        if w[1:2] == ["schedule"] and len(w) == 8:
            return w[4:] == ["start-time", "now", "lifetime", "forever"]
        if w[1:2] != ["entry"] or len(w) != 4:
            return False
        sla = IpSla(self._nqa_name(w[2], w[3]), origin=Origin(node.line, node.text))
        for child in node.children:
            if child.words != ["type", "icmp-echo"]:
                self.unparsed(child, node.text)
                continue
            for line in child.children:
                c = line.words
                n = len(c)
                if c[:2] == ["destination", "ip"] and n == 3:
                    sla.target = str(ipaddress.ip_address(c[2]))
                elif c[0] == "frequency" and n == 2:
                    sla.frequency = max(1, int(c[1]) // 1000)  # milliseconds
                elif c[:2] == ["probe", "timeout"] and n == 3:
                    sla.timeout_ms = int(c[2])
                elif c[:2] == ["source", "interface"] and n == 3:
                    sla.source_interface = canonical(c[2])[0]
                elif c[:2] == ["source", "ip"] and n == 3:
                    sla.source_address = str(ipaddress.ip_address(c[2]))
                elif c[0] == "vpn-instance" and n == 2:
                    sla.vrf = c[1]
                elif c[:2] == ["reaction", "1"] and "probe-fail" in c:  # what the track follows
                    pass
                else:
                    self.unparsed(line, f"{node.text} / {child.text}")
        if not sla.target:
            return False
        self.device.ip_slas[sla.name] = sla
        return True

    def track(self, node: Node) -> bool:
        """track N nqa entry A T reaction 1 | interface X [protocol ipv4] [delay positive U negative D]."""
        w = node.words
        if len(w) < 4 or not w[1].isdigit() or node.children:
            return False
        rest = w[2:]
        sla = interface = ""
        if rest[:2] == ["nqa", "entry"] and len(rest) >= 6 and rest[4:6] == ["reaction", "1"]:
            sla, rest = self._nqa_name(rest[2], rest[3]), rest[6:]
        elif rest[0] == "interface" and len(rest) >= 2:
            interface, rest = canonical(rest[1])[0], rest[2:]
            if rest[:2] == ["protocol", "ipv4"]:
                rest = rest[2:]
        else:
            return False
        delays: Dict[str, int] = {}
        if rest[:1] == ["delay"]:
            pairs = rest[1:]
            if len(pairs) not in (2, 4) or not set(pairs[::2]) <= {"positive", "negative"}:
                return False
            delays = {k: int(v) for k, v in zip(pairs[::2], pairs[1::2])}
        elif rest:
            return False
        t = tracking_text.track(self.device, w[1], node.line, node.text)
        t.sla, t.interface = sla, interface
        t.delay_up, t.delay_down = delays.get("positive"), delays.get("negative")
        return True

    def mirroring_group(self, node: Node) -> bool:
        """mirroring-group N local; mirroring-group N mirroring-port P.. both|inbound|outbound; ... monitor-port P."""
        w = node.words
        n = len(w)
        if n < 3 or not w[1].isdigit() or node.children:
            return False
        if w[2:] == ["local"]:
            monitor_text.session(self.device, w[1], node.line, node.text)
            return True
        if w[2] == "mirroring-port" and n >= 5 and monitor_text.direction(w[-1]) is not None and "to" not in w:
            s = monitor_text.session(self.device, w[1], node.line, node.text)
            for port in w[3:-1]:
                s.sources[canonical(port)[0]] = monitor_text.direction(w[-1]) or "both"
            return True
        if w[2] == "monitor-port" and n == 4:
            monitor_text.session(self.device, w[1], node.line, node.text).destination = canonical(w[3])[0]
            return True
        return False

    def _sflow(self, node: Optional[Node] = None) -> Sflow:
        if self.device.sflow is None:
            self.device.sflow = Sflow(origin=Origin(node.line, node.text) if node else Origin())
        return self.device.sflow

    def sflow(self, node: Node) -> bool:
        """sflow agent ip A; sflow collector N [vpn-instance V] ip A [port P] [description TEXT]."""
        w = node.words
        if w[1:3] == ["agent", "ip"] and len(w) == 4:
            self._sflow(node).agent = str(ipaddress.ip_address(w[3]))
            return True
        if w[1:2] == ["collector"] and len(w) >= 5 and w[2].isdigit():
            rest = w[3:]
            if rest[:1] == ["description"]:
                return False
            vrf = ""
            if rest[:1] == ["vpn-instance"]:
                vrf, rest = rest[1], rest[2:]
            if rest[:1] != ["ip"] or len(rest) < 2:
                return False
            address, rest = str(ipaddress.ip_address(rest[1])), rest[2:]
            port = None
            if rest[:1] == ["port"]:
                port, rest = int(rest[1]), rest[2:]
            if rest and rest[0] != "description":
                return False
            self._sflow(node).collectors.append(monitor_text.collector(address, port, vrf))
            return True
        return False

    def netstream_export(self, node: Node, w: List[str]) -> bool:
        """ip netstream export host A PORT [vpn-instance V]; version N; source interface X."""
        nf = self.device.netflow
        if nf is None:
            nf = self.device.netflow = Netflow(origin=Origin(node.line, node.text))
        if w[:1] == ["host"] and len(w) in (3, 5) and w[3:4] in ([], ["vpn-instance"]):
            nf.collectors.append(monitor_text.collector(str(ipaddress.ip_address(w[1])), int(w[2]),
                                                        w[4] if len(w) == 5 else ""))
        elif w[:1] == ["version"] and len(w) == 2 and w[1] in ("5", "9", "10"):
            nf.version = int(w[1])
        elif w[:2] == ["source", "interface"] and len(w) == 3:
            nf.source_interface = canonical(w[2])[0]
        else:
            return False
        return True

    @staticmethod
    def poe_line(iface: Interface, w: List[str]) -> bool:
        """poe enable, undo poe enable, poe priority P, poe max-power MW."""
        if w in (["poe", "enable"], ["undo", "poe", "enable"]):
            iface.poe = w[0] == "poe"
        elif w[:2] == ["poe", "priority"] and len(w) == 3 and w[2] in ("low", "high", "critical"):
            iface.poe_priority = w[2]
        elif w[:2] == ["poe", "max-power"] and len(w) == 3:
            iface.poe_max_mw = int(w[2])
        else:
            return False
        return True

    def monitor_line(self, iface: Interface, w: List[str]) -> bool:
        n = len(w)
        if w[0] == "mirroring-group" and n == 4 and w[1].isdigit() and w[2] == "mirroring-port" and \
                monitor_text.direction(w[3]) is not None:
            monitor_text.session(self.device, w[1]).sources[iface.name] = monitor_text.direction(w[3]) or "both"
        elif w[0] == "mirroring-group" and n == 3 and w[1].isdigit() and w[2] == "monitor-port":
            monitor_text.session(self.device, w[1]).destination = iface.name
        elif w[:2] == ["sflow", "sampling-rate"] and n == 3:
            sf = self._sflow()
            if sf.sample_rate not in (None, int(w[2])):
                return False
            sf.sample_rate = int(w[2])
            iface.sflow = True
        elif w[:3] == ["sflow", "counter", "interval"] and n == 4:
            sf = self._sflow()
            if sf.polling_interval not in (None, int(w[3])):
                return False
            sf.polling_interval = int(w[3])
            iface.sflow = True
        elif w[:3] in (["sflow", "flow", "collector"], ["sflow", "counter", "collector"]) and n == 4:
            iface.sflow = True
        elif w[:2] == ["ip", "netstream"] and n == 3 and w[2] in ("inbound", "outbound"):
            way = "input" if w[2] == "inbound" else "output"
            iface.flow = way if iface.flow in ("", way) else "both"
        else:
            return False
        return True

    def _finish(self) -> None:
        ospf_text.attach(self.device, self._ospf_areas, {})
        monitor_text.finish(self.device)
        self._finish_aaa()
        self._finish_qos()
        for peer, profile in self._peer_profiles:
            proposals, remotes = self._ike_profiles.get(profile, ([], []))
            peer.ike_policies = list(proposals)
            if remotes and not peer.peer and not peer.profile:
                peer.peer = remotes[0]
        for peer in self.device.ipsec_peers:
            if peer.transforms and peer.transforms[0] in self._pfs:
                peer.pfs_group = self._pfs[peer.transforms[0]]
        for rule in self.device.nat_rules:
            rule.pool = self._nat_groups.get(rule.pool, rule.pool)
        for nat_pool in self.device.nat_pools.values():  # an address group has no mask; take it from the interface
            for iface in self.device.interfaces.values():
                for address in iface.ipv4:
                    if ipaddress.IPv4Address(nat_pool.first) in ipaddress.ip_interface(address).network:
                        nat_pool.prefix_len = ipaddress.ip_interface(address).network.prefixlen
        for pool in self.device.dhcp_pools:
            if pool.network:
                pool.ranges = dhcp_text.subtract(pool.network, pool.ranges, self._dhcp_excluded.get(pool.vrf, []))
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
