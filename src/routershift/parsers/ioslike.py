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
from .. import bgp as bgp_text
from .. import fhrp
from .. import ospf as ospf_text
from .. import mgmt as mgmt_text
from .. import qos as qos_text
from .. import confparse, names
from .. import dhcp as dhcp_text
from .. import vpn as vpn_text
from .. import aaa as aaa_text
from ..confparse import Node
from ..errors import ParseError
from ..model import (AaaGroup, AaaMethod, AaaServer, Acl, Device, LocalUser, DhcpPool, FhrpGroup, IkePolicy, IpsecPeer, IpsecTransform, NtpKey, PreSharedKey,
                     SnmpCommunity, SnmpGroup, SnmpHost, SnmpUser, NatPool, NatRule, Interface, InterfaceKind, LacpMode, Origin, Ospf, OspfNetwork, Wlan,
                     QosAction, QosClass, QosPolicy, StaticRoute, StpMode, SwitchportMode, Unparsed, Vlan)

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


_EOS_ROLES = [(15, "network-admin"), (1, "network-operator")]


class _Reader:
    def __init__(self, platform: str) -> None:
        self.device = Device(platform=platform)
        self.switch_defaults = platform == "eos"  # physical ports start as switchports
        self._explicit_mode: Dict[str, bool] = {}  # "no switchport" seen
        self._switchport_seen: Dict[str, bool] = {}  # any switchport line seen
        self._varp_mac = ""  # EOS: ip virtual-router mac-address
        self._vrrp_v3 = False  # IOS XE: fhrp version vrrp v3
        self._ospf_areas: List[Tuple[str, str, str]] = []  # interface, process ("" = the interface's VRF), area
        self._dhcp_excluded: Dict[str, List[Tuple[str, str]]] = {}  # VRF -> excluded ranges
        self._ikev2_lifetime: Optional[int] = None
        self._server_names: Dict[str, str] = {}  # IOS AAA server name -> address
        self._eos_sa: Dict[str, IpsecPeer] = {}  # EOS SA policy -> its PFS group and lifetime
        self._eos_keys: Dict[str, str] = {}  # EOS profile -> shared key
        self._wlan_profiles: Dict[str, Optional[int]] = {}  # IOS XE wireless policy profile -> VLAN
        self._wlan_tags: Dict[str, str] = {}  # WLAN -> policy profile, from the policy tags

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
            "dhcp": self.eos_dhcp,
            "service": lambda node: node.words == ["service", "dhcp"],
            "crypto": self.crypto,
            "snmp-server": self.snmp,
            "username": self.username,
            "enable": self.enable,
            "aaa": self.aaa,
            "radius": self.aaa_server,
            "tacacs": self.aaa_server,
            "radius-server": self.aaa_host,
            "tacacs-server": self.aaa_host,
            "dot1x": self.dot1x,
            "class-map": self.class_map,
            "policy-map": self.policy_map,
            "mls": lambda node: node.words == ["mls", "qos"],
            "mpls": self.mpls,
            "wlan": self.wlan,
            "wireless": self.wireless,
            "line": self.line,
            "lldp": self.discovery,
            "cdp": self.discovery,
            "no": self.no_global,
            "management": self.management,
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
        s = self.device.system
        if len(w) >= 3 and w[1] == "server":
            args = w[2:]
            if args[0] == "vrf" and len(args) >= 3:
                s.service_vrf = args[1]
                args = args[2:]
            server = args[0]
            s.ntp_servers.append(server)
            options = args[1:]
            while options:
                if options[0] == "prefer":
                    s.ntp_prefer = server
                elif options[0] == "key" and len(options) >= 2:
                    s.ntp_server_keys[server] = int(options[1])
                    options = options[1:]
                elif options[0] in ("source", "local-interface") and len(options) >= 2:
                    s.ntp_source = names.canonical(options[1])[0]
                    options = options[1:]
                elif options[0] != "iburst":
                    return False
                options = options[1:]
            return True
        if w[1:] == ["authenticate"]:
            s.ntp_authenticate = True
            return True
        if w[1] == "authentication-key" and len(w) >= 5:
            # IOS: ntp authentication-key 1 md5 KEY [7]; EOS: ntp authentication-key 1 md5 [0|7] KEY
            algorithm, rest = {"hmac-sha1": "sha1", "hmac-sha2-256": "sha256"}.get(w[3], w[3]), w[4:]
            if len(rest) == 2 and rest[1] == "7":
                key, encrypted = rest[0], True
            elif len(rest) == 2 and rest[0] in ("0", "7"):
                key, encrypted = rest[1], rest[0] == "7"
            elif len(rest) == 1:
                key, encrypted = rest[0], False
            else:
                return False
            ntp_key = self._ntp_key(int(w[2]))
            ntp_key.algorithm, ntp_key.key = algorithm, "" if encrypted else key
            return algorithm in ("md5", "sha1", "sha256")
        if w[1] == "trusted-key" and len(w) == 3:
            self._ntp_key(int(w[2])).trusted = True
            return True
        if w[1] in ("source", "local-interface") and len(w) >= 3:
            s.ntp_source = names.canonical(" ".join(w[2:]))[0]
            return True
        return False

    def _ntp_key(self, number: int) -> NtpKey:
        return self.device.system.ntp_keys.setdefault(number, NtpKey(number))

    def snmp(self, node: Node) -> bool:
        w = node.words
        s = self.device.snmp
        origin = Origin(node.line, node.text)
        if w[1] == "community" and len(w) >= 3:
            community = SnmpCommunity(w[2], origin=origin)
            args = w[3:]
            if args[:1] == ["view"] and len(args) >= 2:
                return False
            if args and args[0].lower() in ("ro", "rw"):
                community.access, args = args[0].lower(), args[1:]
            if len(args) > 1:
                return False
            community.acl = args[0] if args else ""
            s.communities.append(community)
            return True
        if w[1] in ("location", "contact") and len(w) >= 3:
            setattr(s, w[1], node.text.split(None, 2)[2])
            return True
        if w[1:3] == ["enable", "traps"]:
            s.traps = True
            return True
        if w[1] in ("trap-source", "local-interface") and len(w) == 3:
            s.source = names.canonical(w[2])[0]
            return True
        if w[1] == "source-interface" and len(w) == 4:
            s.source = names.canonical(w[3])[0]
            return w[2] in ("traps", "informs", "all")
        if w[1] == "vrf" and len(w) == 3:
            s.vrf = w[2]
            return True
        if w[1] == "host" and len(w) >= 4:
            return self._snmp_host(w[2:], origin)
        if w[1] == "group" and len(w) >= 5 and w[3] == "v3":
            group = SnmpGroup(w[2], w[4], origin=origin)
            args = w[5:]
            while len(args) >= 2 and args[0] in ("read", "write"):
                setattr(group, f"{args[0]}_view", args[1])
                args = args[2:]
            s.groups[group.name] = group
            return not args and group.level in ("noauth", "auth", "priv")
        if w[1] == "user" and len(w) >= 5 and w[4] == "v3":
            return self._snmp_user(w[2], w[3], w[5:], origin)
        return False

    def _snmp_host(self, args: List[str], origin: Origin) -> bool:
        host = SnmpHost(str(ipaddress.ip_address(args[0])), origin=origin)
        args = args[1:]
        if args[:1] == ["vrf"] and len(args) >= 2:
            host.vrf, args = args[1], args[2:]
        if args[:1] in (["informs"], ["traps"]):
            host.informs, args = args[0] == "informs", args[1:]
        if args[:1] == ["version"] and len(args) >= 2:
            host.version, args = args[1], args[2:]
            if host.version == "3" and args:
                host.level, args = args[0], args[1:]
        if not args or host.version not in ("1", "2c", "3"):
            return False
        host.secret = args[0]
        self.device.snmp.hosts.append(host)
        return True  # trap types after the community narrow what is sent; every type is written

    def _snmp_user(self, name: str, group: str, args: List[str], origin: Origin) -> bool:
        """[localized ID] auth md5|sha|sha-2 256 KEY [priv des|3des|aes 128 KEY] (EOS: aes, aes256)"""
        user = SnmpUser(name, group, origin=origin)
        localized = args[:1] == ["localized"]  # EOS: keys localized to the engine ID, useless elsewhere
        if localized:
            args = args[2:]
        if args[:1] == ["auth"] and len(args) >= 3:
            if args[1] == "sha-2" and len(args) >= 4:
                user.auth, args = f"sha{args[2]}", args[3:]
            else:
                user.auth, args = args[1], args[2:]
            user.auth_key, args = ("" if localized else args[0]), args[1:]
        if args[:1] == ["priv"] and len(args) >= 3:
            algorithm, args = args[1], args[2:]
            if algorithm == "aes" and args[0] in ("128", "192", "256") and len(args) >= 2:
                algorithm, args = f"aes{args[0]}", args[1:]
            user.priv = "aes128" if algorithm == "aes" else algorithm
            user.priv_key, args = ("" if localized else args[0]), args[1:]
        self.device.snmp.users.append(user)
        return not args and user.auth in ("", "md5", "sha", "sha256", "sha384", "sha512") and user.priv in (
            "", "des", "3des", "aes128", "aes192", "aes256")

    def logging(self, node: Node) -> bool:
        w = node.words
        s = self.device.system
        if len(w) == 3 and w[1] == "trap" and mgmt_text.level(w[2]) is not None:
            s.logging_level = mgmt_text.level(w[2])
            return True
        if len(w) == 3 and w[1] == "source-interface":
            s.logging_source = names.canonical(w[2])[0]
            return True
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
        m = self.device.management
        if w[1:] == ["ssh", "version", "2"]:
            m.ssh = True
            return True
        if w[1:] in (["http", "server"], ["http", "secure-server"]):
            setattr(m, "http" if w[2] == "server" else "https", True)
            return True
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
        if w[1:] == ["security"]:
            return self.eos_security(node)
        if w[1] in ("radius", "tacacs") and w[-2] == "source-interface" and len(w) in (4, 6):
            # IOS: ip radius source-interface X; EOS: ip radius [vrf V] source-interface X
            self.device.aaa.source["radius" if w[1] == "radius" else "tacacs"] = names.canonical(w[-1])[0]
            return len(w) == 4 or w[2] == "vrf"
        if w[1] in ("tftp", "ftp") and w[-2] == "source-interface" and len(w) in (4, 5):
            # IOS: ip tftp source-interface X; EOS: ip tftp client source-interface X
            self.device.system.transfer_source[w[1]] = names.canonical(w[-1])[0]
            return len(w) == 4 or w[2] == "client"
        if w[1:3] == ["nat", "pool"] and len(w) == 8 and w[6] in ("netmask", "prefix-length"):
            length = w[7] if w[6] == "prefix-length" else str(ipaddress.ip_network(f"0.0.0.0/{w[7]}").prefixlen)
            first, last = str(ipaddress.IPv4Address(w[4])), str(ipaddress.IPv4Address(w[5]))
            self.device.nat_pools[w[3]] = NatPool(w[3], first, last, int(length))
            return True
        if w[1:4] == ["nat", "inside", "source"] and len(w) >= 6:
            return self.ios_nat(node, w[4:])
        if w[1:3] == ["dhcp", "pool"] and len(w) == 4:
            return self.dhcp_pool(node, w[3])
        if w[1:3] == ["dhcp", "excluded-address"] and len(w) >= 4:
            args, vrf = w[3:], ""
            if args[0] == "vrf" and len(args) >= 3:
                vrf, args = args[1], args[2:]
            if len(args) not in (1, 2):
                return False
            addresses = [str(ipaddress.IPv4Address(a)) for a in args]
            self._dhcp_excluded.setdefault(vrf, []).append((addresses[0], addresses[-1]))
            return True
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

    # NAT --------------------------------------------------------------------------------------------------------------

    def ios_nat(self, node: Node, w: List[str]) -> bool:
        """ip nat inside source list ACL interface X overload | pool P [overload]; static [tcp|udp] A [p] B [q]"""
        rule = NatRule("dynamic", origin=Origin(node.line, node.text))
        if w[-2:-1] == ["vrf"]:
            rule.vrf, w = w[-1], w[:-2]
        if w[-1:] == ["extendable"]:
            w = w[:-1]
        if w[0] == "list" and len(w) >= 4:
            rule.acl = w[1]
            rule.overload = w[-1] == "overload"
            rest = w[2:-1] if rule.overload else w[2:]
            if rest[0] == "pool" and len(rest) == 2:
                rule.pool = rest[1]
            elif rest[0] == "interface" and len(rest) >= 2:
                rule.interface = names.canonical(" ".join(rest[1:]))[0]
            else:
                return False
        elif w[0] == "static" and len(w) in (3, 6) and (len(w) == 3 or w[1] in ("tcp", "udp")):
            rule.kind = "static"
            if len(w) == 6:
                rule.protocol = w[1]
                rule.local, rule.local_port = str(ipaddress.IPv4Address(w[2])), int(w[3])
                rule.translated, rule.translated_port = str(ipaddress.IPv4Address(w[4])), int(w[5])
            else:
                rule.local, rule.translated = str(ipaddress.IPv4Address(w[1])), str(ipaddress.IPv4Address(w[2]))
        else:
            return False
        self.device.nat_rules.append(rule)
        return True

    def eos_nat(self, iface: Interface, w: List[str]) -> bool:
        """ip nat source dynamic access-list ACL overload | pool P; ip nat source static A B (on the outside)"""
        rule = NatRule("dynamic", interface=iface.name, vrf=iface.vrf)
        if w[:2] == ["dynamic", "access-list"] and len(w) in (4, 5, 6):
            rule.acl = w[2]
            if w[3:] == ["overload"]:
                rule.overload = True
            elif w[3] == "pool" and len(w) >= 5 and w[5:] in ([], ["overload"]):
                rule.pool, rule.overload = w[4], len(w) == 6
            else:
                return False
        elif w[0] == "static" and len(w) == 3:
            rule.kind = "static"
            rule.local, rule.translated = str(ipaddress.IPv4Address(w[1])), str(ipaddress.IPv4Address(w[2]))
        else:
            return False
        iface.nat = "outside"
        self.device.nat_rules.append(rule)
        return True

    # users and AAA ----------------------------------------------------------------------------------------------------

    def _type7(self, value: str) -> str:
        """IOS type 7 reads back to the clear text; EOS's type 7 is its own, so it stays unknown."""
        return aaa_text.decode_type7(value) if self.device.platform == "ios" else ""

    @staticmethod
    def _password(user: LocalUser, args: List[str], platform: str) -> bool:
        """secret|password [0|5|7|8|9|sha512] VALUE, as IOS and EOS write it."""
        kind, args = args[0], args[1:]
        form = args[0] if len(args) == 2 else "0"
        value = args[-1]
        if form == "0":
            user.password = value
        elif form == "7" and kind == "password" and platform == "ios":
            user.password = aaa_text.decode_type7(value)
            return bool(user.password)
        elif form in ("5", "sha512"):
            user.password_hash, user.hash_type = value, aaa_text.hash_type(value)
        elif form in ("8", "9"):
            user.password_hash, user.hash_type = value, f"ios-type{form}"
        else:
            return False
        return len(args) in (1, 2)

    def username(self, node: Node) -> bool:
        """username U [privilege N] [role R] [secret|password [type] X | nopassword]"""
        w = node.words
        user = LocalUser(w[1], origin=Origin(node.line, node.text))
        args = w[2:]
        while args:
            if args[0] == "privilege" and len(args) >= 2:
                user.privilege, args = int(args[1]), args[2:]
            elif args[0] == "role" and len(args) >= 2:
                role = aaa_text.privilege(args[1], _EOS_ROLES)
                if role is None:
                    return False
                user.privilege = user.privilege if user.privilege is not None else role
                args = args[2:]
            elif args[0] in ("secret", "password"):
                self.device.users.append(user)
                return self._password(user, args, self.device.platform)
            elif args == ["nopassword"]:
                args = []
            else:
                return False
        self.device.users.append(user)
        return True

    def enable(self, node: Node) -> bool:
        """enable secret [type] X; EOS: enable password [sha512] X"""
        w = node.words
        if w[1] not in ("secret", "password") or len(w) < 3:
            return False
        user = LocalUser("enable", 15, origin=Origin(node.line, node.text))
        self.device.aaa.enable_secret = user
        return self._password(user, w[1:], self.device.platform)

    def aaa(self, node: Node) -> bool:
        w = node.words
        a = self.device.aaa
        origin = Origin(node.line, node.text)
        if w[1:] in (["new-model"], ["session-id", "common"]) or w[1] == "root":
            return w[1] != "root"
        if w[1:3] == ["group", "server"] and len(w) == 5 and w[3] in ("radius", "tacacs+"):
            group = AaaGroup("radius" if w[3] == "radius" else "tacacs", w[4], origin=origin)
            a.groups[group.name] = group
            for child in node.children:
                c = child.words
                if c[:2] == ["server", "name"] and len(c) == 3:
                    group.servers.append(f"name:{c[2]}")  # resolved in _finish, as the servers may come later
                elif c[0] == "server" and len(c) in (2, 4):  # EOS: server A [vrf V]
                    group.servers.append(c[1])
                    group.vrf = c[3] if len(c) == 4 and c[2] == "vrf" else group.vrf
                elif c[:3] == ["ip", "vrf", "forwarding"] and len(c) == 4:
                    group.vrf = c[3]
                elif c[0] in ("ip",) and c[1] in ("radius", "tacacs") and c[2:3] == ["source-interface"]:
                    a.source[group.protocol] = names.canonical(c[-1])[0]
                else:
                    self.unparsed(child, node.text)
            return True
        if w[1] in ("authentication", "authorization", "accounting") and len(w) >= 4:
            method = AaaMethod(w[1], w[2], origin=origin)
            args = w[3:]
            if method.service == "commands":
                level = args[0]
                method.level = 15 if level == "all" else int(level)
                args = args[1:]
            if method.service not in ("login", "enable", "exec", "commands", "dot1x") or not args:
                return False
            method.name, args = args[0], args[1:]
            if method.kind == "accounting":
                if not args or args[0] not in ("start-stop", "stop-only"):
                    return False
                method.record, args = args[0], args[1:]
            while args:
                if args[0] == "group" and len(args) >= 2:
                    name = {"tacacs+": "tacacs"}.get(args[1], args[1])
                    method.methods.append(f"group:{name}")
                    args = args[2:]
                elif args[0] in ("local", "none", "enable", "if-authenticated", "local-case"):
                    method.methods.append("local" if args[0] == "local-case" else args[0])
                    args = args[1:]
                else:
                    return False
            a.methods.append(method)
            return True
        return False

    # QoS -------------------------------------------------------------------------------------------------------------

    def class_map(self, node: Node) -> bool:
        """IOS: class-map [match-any|match-all] NAME; EOS: class-map type qos [match-any] NAME"""
        w = node.words[1:]
        if w[:2] == ["type", "qos"]:
            w = w[2:]
        match_all = w[0] != "match-any"  # IOS defaults to match-all
        if w[0] in ("match-any", "match-all"):
            w = w[1:]
        if len(w) != 1:
            return False
        qos_class = QosClass(w[0], match_all=match_all, origin=Origin(node.line, node.text))
        self.device.qos_classes[qos_class.name] = qos_class
        for child in node.children:
            c = child.words
            try:
                if c[:2] == ["match", "dscp"] or c[:3] == ["match", "ip", "dscp"]:
                    qos_class.dscp += [qos_text.dscp(x) for x in c[2 + (c[1] == "ip"):]]
                    continue
                if c[:2] == ["match", "access-group"] and len(c) in (3, 4) or \
                        c[:3] == ["match", "ip", "access-group"] and len(c) == 4:
                    qos_class.acl = c[-1]
                    continue
            except ValueError:
                pass
            self.unparsed(child, node.text)
        return True

    def policy_map(self, node: Node) -> bool:
        """IOS: policy-map NAME; EOS: policy-map type quality-of-service NAME"""
        w = node.words[1:]
        if w[:2] == ["type", "quality-of-service"]:
            w = w[2:]
        if len(w) != 1:
            return False
        policy = QosPolicy(w[0], origin=Origin(node.line, node.text))
        self.device.qos_policies[policy.name] = policy
        for child in node.children:
            if child.words[0] != "class" or len(child.words) != 2:
                self.unparsed(child, node.text)
                continue
            action = QosAction(child.words[1])
            policy.actions.append(action)
            for line in child.children:
                try:
                    understood = self._qos_action(action, line)
                except (ValueError, IndexError):
                    understood = False
                if not understood:
                    self.unparsed(line, f"{node.text} / {child.text}")
        return True

    @staticmethod
    def _qos_action(action: QosAction, node: Node) -> bool:
        """set [ip] dscp X; IOS: police [cir] BPS [BC] [conform-action transmit] [exceed-action drop];
        EOS: police rate|cir N [bps|kbps|mbps] [burst-size N kbytes]"""
        w = node.words
        if w[:2] == ["set", "dscp"] and len(w) == 3 or w[:3] == ["set", "ip", "dscp"] and len(w) == 4:
            action.set_dscp = qos_text.dscp(w[-1])
            return True
        if w[0] != "police" or len(w) < 2:
            return False
        args = w[1:]
        if args[0] in ("cir", "rate"):
            args = args[1:]
        rate, args = int(args[0]), args[1:]
        unit = 1000  # bps, the IOS unit
        if args and args[0] in ("bps", "kbps", "mbps", "gbps"):
            unit = {"bps": 1000, "kbps": 1, "mbps": 1, "gbps": 1}[args[0]]
            rate *= {"bps": 1, "kbps": 1, "mbps": 1000, "gbps": 1000000}[args[0]]
            args = args[1:]
        action.police_kbps = max(1, rate // unit)
        actions = {"transmit"}
        while args:
            if args[0] in ("bc", "burst-size") and len(args) >= 2:
                args = args[2 + (args[2:3] in (["bytes"], ["kbytes"], ["mbytes"])):]
            elif args[0].isdigit():
                args = args[1:]  # IOS: the burst
            elif args[0] in ("conform-action", "exceed-action") and len(args) >= 2:
                actions.add(f"{args[0]}:{args[1]}")
                args = args[2:]
            else:
                return False
        exceed = [a for a in actions if a.startswith("exceed-action:")]
        children = {" ".join(c.words) for c in node.children}
        return all(a == "exceed-action:drop" for a in exceed) and children <= {"conform-action transmit",
                                                                               "exceed-action drop"}

    def dot1x(self, node: Node) -> bool:
        if node.words[1:] == ["system-auth-control"]:
            self.device.aaa.dot1x = True
            return True
        return False

    def dot1x_line(self, iface: Interface, w: List[str]) -> bool:
        """IOS: authentication|access-session ..., dot1x pae authenticator, mab; EOS: dot1x ..."""
        n = len(w)
        if w in (["dot1x", "pae", "authenticator"],):
            iface.dot1x = True
        elif w in (["authentication", "port-control", "auto"], ["access-session", "port-control", "auto"],
                   ["dot1x", "port-control", "auto"]):
            pass  # the port authenticates: what with is said by the dot1x and mab lines
        elif w == ["mab"] or w == ["dot1x", "mac", "based", "authentication"]:
            iface.mab = True
        elif w[0] in ("authentication", "access-session") and w[1:2] == ["host-mode"] and n == 3 and \
                w[2] in ("single-host", "multi-host", "multi-auth", "multi-domain"):
            iface.dot1x_host_mode = w[2]
        elif w[:2] == ["dot1x", "host-mode"] and n in (3, 4) and w[2] in ("single-host", "multi-host"):
            # EOS: multi-host authenticated = every host logs in
            iface.dot1x_host_mode = "multi-auth" if w[3:] == ["authenticated"] else w[2]
        elif w in (["authentication", "periodic"], ["dot1x", "reauthentication"]):
            iface.dot1x_reauth = True
        elif w[:3] == ["authentication", "timer", "reauthenticate"] and n == 4:
            iface.dot1x_reauth_period = int(w[3])
        elif w[:3] == ["dot1x", "timeout", "reauth-period"] and n == 4:
            iface.dot1x_reauth_period = int(w[3])
        else:
            return False
        return True

    def aaa_server(self, node: Node) -> bool:
        """IOS: radius server NAME / tacacs server NAME, with address, ports, key and timeout inside."""
        w = node.words
        if w[1] != "server" or len(w) != 3:
            return False
        server = AaaServer("radius" if w[0] == "radius" else "tacacs", "", w[2], origin=Origin(node.line, node.text))
        for child in node.children:
            c = child.words
            try:
                if c[:2] == ["address", "ipv4"] and len(c) >= 3:
                    server.address = str(ipaddress.ip_address(c[2]))
                    rest = c[3:]
                    while len(rest) >= 2 and rest[0] in ("auth-port", "acct-port"):
                        setattr(server, rest[0].replace("-", "_"), int(rest[1]))
                        rest = rest[2:]
                    if rest:
                        self.unparsed(child, node.text)
                elif c[0] == "key" and len(c) in (2, 3):
                    server.key = c[-1] if len(c) == 2 or c[1] == "0" else self._type7(c[2]) if c[1] == "7" else ""
                elif c[0] == "port" and len(c) == 2:
                    server.auth_port = int(c[1])
                elif c[0] == "timeout" and len(c) == 2:
                    server.timeout = int(c[1])
                else:
                    self.unparsed(child, node.text)
            except ValueError:
                self.unparsed(child, node.text)
        if not server.address:
            return False
        self._server_names[server.name] = server.address
        self.device.aaa.servers.append(server)
        return True

    def aaa_host(self, node: Node) -> bool:
        """radius-server|tacacs-server host A [vrf V] [auth-port N] [acct-port N] [port N] [timeout N] [key [0|7] K]"""
        w = node.words
        protocol = "radius" if w[0] == "radius-server" else "tacacs"
        if w[1] != "host" or len(w) < 3:
            return w[1] in ("timeout", "retransmit", "deadtime") and len(w) == 3
        server = AaaServer(protocol, str(ipaddress.ip_address(w[2])), origin=Origin(node.line, node.text))
        args = w[3:]
        while args:
            if args[0] == "key" and len(args) >= 2:
                form = args[1] if len(args) == 3 else "0"
                server.key = args[-1] if form == "0" else self._type7(args[-1]) if form == "7" else ""
                args = []
            elif len(args) >= 2 and args[0] in ("vrf", "auth-port", "acct-port", "port", "timeout"):
                if args[0] == "vrf":
                    server.vrf = args[1]
                else:
                    attribute = {"port": "auth_port"}.get(args[0], args[0].replace("-", "_"))
                    setattr(server, attribute, int(args[1]))
                args = args[2:]
            else:
                return False
        self.device.aaa.servers.append(server)
        return True

    # IPsec ------------------------------------------------------------------------------------------------------------

    def tunnel_line(self, iface: Interface, w: List[str]) -> bool:
        """tunnel source|destination|mode; IOS 'tunnel protection ipsec profile P', EOS 'tunnel ipsec profile P'."""
        if w[0] == "source" and len(w) >= 2:
            rest = w[2:] if w[1] == "interface" else w[1:]  # EOS: tunnel source interface Ethernet1
            iface.tunnel_source = w[1] if _is_address(w[1]) else names.canonical(" ".join(rest))[0]
        elif w[0] == "destination" and len(w) == 2:
            iface.tunnel_destination = str(ipaddress.IPv4Address(w[1]))
        elif w[0] == "mode" and w[1:] in (["gre"], ["gre", "ip"], ["ipsec"], ["ipsec", "ipv4"]):
            iface.tunnel_mode = w[1]
        elif w[:3] == ["protection", "ipsec", "profile"] and len(w) == 4:
            iface.tunnel_profile = w[3]
        elif w[:2] == ["ipsec", "profile"] and len(w) == 3:
            iface.tunnel_profile = w[2]
        else:
            return False
        return True

    def crypto(self, node: Node) -> bool:
        w = node.words
        origin = Origin(node.line, node.text)
        if w[1:3] == ["isakmp", "policy"] and len(w) == 4:
            policy = IkePolicy(w[3], 1, ["des"], ["sha1"], [1], origin=origin, authentication="rsa-sig")
            self.device.ike_policies[w[3]] = policy
            self._children(node, lambda c: self._isakmp_line(policy, c))
            return True
        if w[1:3] == ["isakmp", "key"] and len(w) in (6, 7, 8):
            args = w[3:]
            encrypted = args[0] in ("6", "7") and len(args) >= 4
            if args[0] in ("0", "6", "7") and len(args) >= 4:
                args = args[1:]
            if args[1] != "address":
                return False
            address = str(ipaddress.IPv4Address(args[2]))
            self.device.psks[address] = PreSharedKey(address, "" if encrypted else args[0], origin)
            return True
        if w[1:3] == ["ikev2", "proposal"] and len(w) == 4:
            policy = IkePolicy(w[3], 2, origin=origin)
            self.device.ike_policies[w[3]] = policy
            self._children(node, lambda c: self._ikev2_proposal_line(policy, c))
            return True
        if w[1:3] == ["ikev2", "policy"] and len(w) == 4:
            return all(c.words[0] in ("proposal", "match") for c in node.children)  # every proposal is offered
        if w[1:3] == ["ikev2", "keyring"] and len(w) == 4:
            for entry in node.children:
                self._keyring_peer(entry)
            return True
        if w[1:3] == ["ikev2", "profile"] and len(w) == 4:
            self._children(node, self._ikev2_profile_line)
            return True
        if w[1:3] == ["ipsec", "transform-set"] and len(w) >= 5:
            transform = IpsecTransform(w[3], origin=origin)
            self._esp(transform, w[4:])
            self.device.ipsec_transforms[w[3]] = transform
            self._children(node, lambda c: self._transform_mode(transform, c.words))
            return True
        if w[1:3] == ["ipsec", "profile"] and len(w) == 4:
            peer = IpsecPeer(w[3], origin=origin)
            self.device.ipsec_peers.append(peer)
            self._children(node, lambda c: self._crypto_set(peer, c.words))
            return True
        if w[1] == "map" and len(w) == 5 and w[4] == "ipsec-isakmp":
            peer = IpsecPeer(w[2], int(w[3]), origin=origin)
            self.device.ipsec_peers.append(peer)
            self._children(node, lambda c: self._crypto_set(peer, c.words))
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
    def _transform_mode(transform: IpsecTransform, w: List[str]) -> bool:
        if w[0] == "mode" and w[1:] in (["tunnel"], ["transport"]):
            transform.mode = w[1]
            return True
        return False

    def _ikev2_profile_line(self, node: Node) -> bool:
        """The peer, its keys and pre-shared authentication; the peer and keys come from the map and the keyring."""
        w = node.words
        if w[:4] == ["match", "identity", "remote", "address"] and len(w) in (5, 6):
            return True
        if w[0] == "authentication" and w[1:] in (["local", "pre-share"], ["remote", "pre-share"]):
            return True
        if w[:2] == ["keyring", "local"] and len(w) == 3:
            return True
        if w[0] == "lifetime" and len(w) == 2:
            self._ikev2_lifetime = int(w[1])
            return True
        return False

    @staticmethod
    def _isakmp_line(policy: IkePolicy, node: Node) -> bool:
        w = node.words
        if w[0] == "encryption" and len(w) in (2, 3):
            policy.encryption = [vpn_text.read(vpn_text.IOS_ISAKMP_ENC, " ".join(w[1:]))]
        elif w[0] == "hash" and len(w) == 2:
            policy.integrity = [vpn_text.read(vpn_text.IOS_HASH, w[1])]
        elif w[0] == "group" and len(w) == 2:
            policy.dh_groups = [int(w[1])]
        elif w[0] == "lifetime" and len(w) == 2:
            policy.lifetime = int(w[1])
        elif w[0] == "authentication" and len(w) == 2:
            policy.authentication = w[1]
        else:
            return False
        return True

    @staticmethod
    def _ikev2_proposal_line(policy: IkePolicy, node: Node) -> bool:
        w = node.words
        if w[0] == "encryption":
            policy.encryption = [vpn_text.read(vpn_text.IOS_IKEV2_ENC, word) for word in w[1:]]
        elif w[0] == "integrity":
            policy.integrity = [vpn_text.read(vpn_text.IOS_IKEV2_INT, word) for word in w[1:]]
        elif w[0] == "group":
            policy.dh_groups = [int(word) for word in w[1:]]
        elif w[0] == "prf":
            pass  # follows the integrity algorithm
        else:
            return False
        return True

    def _keyring_peer(self, node: Node) -> None:
        """peer NAME / address A [M] / pre-shared-key [local|remote] [0|6] KEY"""
        address, key, encrypted = "", "", False
        for child in node.children:
            c = child.words
            if c[0] == "address" and len(c) in (2, 3):
                address = str(ipaddress.IPv4Address(c[1]))
            elif c[0] == "pre-shared-key" and len(c) >= 2:
                args = [a for a in c[1:] if a not in ("local", "remote")]
                encrypted = args[0] == "6" and len(args) == 2
                key = args[-1]
            elif c[0] != "description":
                self.unparsed(child, node.text)
        if node.words[0] != "peer" or not address:
            self.unparsed(node)
            return
        self.device.psks[address] = PreSharedKey(address, "" if encrypted else key, Origin(node.line, node.text))

    def _esp(self, transform: IpsecTransform, words: List[str]) -> None:
        """esp-aes 256 esp-sha256-hmac, esp-gcm 256, ..."""
        n = 0
        while n < len(words):
            word = words[n]
            if n + 1 < len(words) and words[n + 1].isdigit():
                word, n = f"{word} {words[n + 1]}", n + 1
            if word in vpn_text.IOS_ESP_ENC.values():
                transform.encryption = vpn_text.read(vpn_text.IOS_ESP_ENC, word)
            elif word in ("esp-aes 128", "esp-gcm 128"):
                transform.encryption = vpn_text.read(vpn_text.IOS_ESP_ENC, word[:-4])
            else:
                transform.integrity = vpn_text.read(vpn_text.IOS_ESP_INT, word)
            n += 1

    def _crypto_set(self, peer: IpsecPeer, w: List[str]) -> bool:
        if w[:2] == ["set", "peer"] and len(w) == 3 and not peer.peer:
            peer.peer = str(ipaddress.IPv4Address(w[2]))
        elif w[:2] == ["set", "transform-set"] and len(w) >= 3:
            peer.transforms = w[2:]
        elif w[:2] == ["set", "pfs"] and len(w) == 3 and w[2].startswith("group"):
            peer.pfs_group = int(w[2][len("group"):])
        elif w[:2] == ["set", "pfs"] and len(w) == 2:
            peer.pfs_group = 2  # the IOS default group
        elif w[:4] == ["set", "security-association", "lifetime", "seconds"] and len(w) == 5:
            peer.lifetime = int(w[4])
        elif w[:2] == ["set", "ikev2-profile"] and len(w) == 3:
            peer.ike_version = 2
        elif w[:2] == ["set", "isakmp-profile"] and len(w) == 3:
            return False
        elif w[:2] == ["match", "address"] and len(w) == 3 and not peer.profile:
            peer.acl = w[2]
        else:
            return False
        return True

    def eos_security(self, node: Node) -> bool:
        """ip security / ike policy, sa policy, profile."""
        for child in node.children:
            w = child.words
            origin = Origin(child.line, child.text)
            try:
                if w[:2] == ["ike", "policy"] and len(w) == 3:
                    policy = IkePolicy(w[2], 2, ["aes-128"], ["sha1"], [14], origin=origin)
                    self.device.ike_policies[w[2]] = policy
                    self._children(child, lambda c: self._eos_ike_line(policy, c.words))
                elif w[:2] == ["sa", "policy"] and len(w) == 3:
                    transform = IpsecTransform(w[2], "aes-128", "sha1", origin=origin)
                    self.device.ipsec_transforms[w[2]] = transform
                    sa = IpsecPeer(w[2])  # holds PFS and lifetime until the profiles take them
                    self._eos_sa[w[2]] = sa
                    self._children(child, lambda c: self._eos_sa_line(transform, sa, c.words))
                elif w[0] == "profile" and len(w) == 2:
                    peer = IpsecPeer(w[1], origin=origin, ike_version=2)
                    self.device.ipsec_peers.append(peer)
                    self._children(child, lambda c: self._eos_profile_line(peer, c.words))
                elif w[:2] == ["key", "controller"]:
                    self.unparsed(child, node.text)
                else:
                    self.unparsed(child, node.text)
            except (ValueError, IndexError):
                self.unparsed(child, node.text)
        return True

    @staticmethod
    def _eos_ike_line(policy: IkePolicy, w: List[str]) -> bool:
        if w[0] == "encryption" and len(w) == 2:
            policy.encryption = [vpn_text.read(vpn_text.EOS_ENC, w[1])]
        elif w[0] == "integrity" and len(w) == 2:
            policy.integrity = [vpn_text.read(vpn_text.EOS_INT, w[1])]
        elif w[0] == "dh-group" and len(w) == 2:
            policy.dh_groups = [int(w[1])]
        elif w[0] == "ike-lifetime" and len(w) == 2:
            policy.lifetime = int(w[1]) * 3600
        elif w[0] == "version" and len(w) == 2 and w[1] in ("1", "2"):
            policy.version = int(w[1])
        else:
            return False
        return True

    @staticmethod
    def _eos_sa_line(transform: IpsecTransform, sa: IpsecPeer, w: List[str]) -> bool:
        if w[:2] == ["esp", "encryption"] and len(w) == 3:
            transform.encryption = vpn_text.read(vpn_text.EOS_ESP_ENC, w[2])
            if "gcm" in w[2]:
                transform.integrity = ""
        elif w[:2] == ["esp", "integrity"] and len(w) == 3:
            transform.integrity = vpn_text.read(vpn_text.EOS_INT, w[2])
        elif w[:2] == ["pfs", "dh-group"] and len(w) == 3:
            sa.pfs_group = int(w[2])
        elif w[:2] == ["sa", "lifetime"] and len(w) == 4 and w[3] == "hours":
            sa.lifetime = int(w[2]) * 3600
        else:
            return False
        return True

    def _eos_profile_line(self, peer: IpsecPeer, w: List[str]) -> bool:
        if w[0] == "ike-policy" and len(w) == 2:
            peer.ike_policies = [w[1]]
        elif w[0] == "sa-policy" and len(w) == 2:
            peer.transforms = [w[1]]
        elif w[0] == "shared-key" and len(w) in (2, 3):
            self._eos_keys[peer.name] = "" if w[1] == "7" and len(w) == 3 else w[-1]
        elif w[:2] in (["connection", "start"], ["connection", "add"]):
            pass
        else:
            return False
        return True

    def _finish_aaa(self) -> None:
        for group in self.device.aaa.groups.values():
            group.servers = [self._server_names.get(s[len("name:"):], s[len("name:"):]) if s.startswith("name:") else s
                             for s in group.servers]
            for server in self.device.aaa.servers:  # IOS sets the VRF on the group: the servers are reached in it
                if server.address in group.servers and server.protocol == group.protocol and not server.vrf:
                    server.vrf = group.vrf

    def _finish_vpn(self) -> None:
        for policy in self.device.ike_policies.values():
            if policy.version == 2 and policy.lifetime is None:
                policy.lifetime = self._ikev2_lifetime
        for peer in self.device.ipsec_peers:
            sa = self._eos_sa.get(peer.transforms[0]) if peer.transforms else None
            if sa is not None:
                peer.pfs_group, peer.lifetime = sa.pfs_group, sa.lifetime
            pinned = [self.device.ike_policies[n] for n in peer.ike_policies if n in self.device.ike_policies]
            if pinned:  # EOS: the profile runs the IKE version of its policy
                peer.ike_version = pinned[0].version
            if peer.name in self._eos_keys:
                for address in vpn_text.peers_of(self.device, peer):
                    self.device.psks[address] = PreSharedKey(address, self._eos_keys[peer.name], peer.origin)
        for iface in self.device.interfaces.values():
            if iface.kind == InterfaceKind.TUNNEL and iface.tunnel_destination and not iface.tunnel_mode:
                iface.tunnel_mode = "gre"

    # DHCP server ------------------------------------------------------------------------------------------------------

    def dhcp_pool(self, node: Node, name: str) -> bool:
        """IOS: ip dhcp pool NAME"""
        pool = DhcpPool(name, origin=Origin(node.line, node.text))
        self.device.dhcp_pools.append(pool)
        for child in node.children:
            w = child.words
            n = len(w)
            try:
                if w[0] == "network" and n == 3:
                    mask = w[2].lstrip("/")
                    pool.network = str(ipaddress.ip_network(f"{w[1]}/{mask}"))
                elif w[0] == "default-router" and n >= 2:
                    pool.default_routers += [str(ipaddress.IPv4Address(a)) for a in w[1:]]
                elif w[0] == "dns-server" and n >= 2:
                    pool.dns_servers += [str(ipaddress.IPv4Address(a)) for a in w[1:]]
                elif w[0] == "domain-name" and n == 2:
                    pool.domain_name = w[1]
                elif w == ["lease", "infinite"]:
                    pool.lease_seconds = 0
                elif w[0] == "lease" and 2 <= n <= 4:
                    pool.lease_seconds = dhcp_text.lease_seconds(*(int(v) for v in w[1:]))
                elif w[0] == "vrf" and n == 2:
                    pool.vrf = w[1]
                else:
                    self.unparsed(child, node.text)
            except ValueError:
                self.unparsed(child, node.text)
        return True

    def eos_dhcp(self, node: Node) -> bool:
        """EOS: dhcp server [vrf V], with subnets inside."""
        w = node.words
        if w[1:2] != ["server"] or len(w) not in (2, 4) or (len(w) == 4 and w[2] != "vrf"):
            return False
        vrf = w[3] if len(w) == 4 else ""
        lease: Optional[int] = None
        domain = ""
        dns: List[str] = []
        pools: List[DhcpPool] = []
        for child in node.children:
            c = child.words
            try:
                if c[:3] == ["lease", "time", "ipv4"]:
                    lease = self._eos_lease(c[3:])
                elif c[:4] == ["dns", "domain", "name", "ipv4"] and len(c) == 5:
                    domain = c[4]
                elif c[:3] == ["dns", "server", "ipv4"] and len(c) >= 4:
                    dns = [str(ipaddress.IPv4Address(a)) for a in c[3:]]
                elif c[0] == "subnet" and len(c) == 2:
                    pools.append(self._eos_subnet(child, vrf))
                else:
                    self.unparsed(child, node.text)
            except (ValueError, IndexError):
                self.unparsed(child, node.text)
        for pool in pools:
            pool.lease_seconds = pool.lease_seconds if pool.lease_seconds is not None else lease
            pool.domain_name = pool.domain_name or domain
            pool.dns_servers = pool.dns_servers or list(dns)
        self.device.dhcp_pools += pools
        return True

    @staticmethod
    def _eos_lease(w: List[str]) -> int:
        """1 days 0 hours 0 minutes"""
        values = {unit: int(value) for value, unit in zip(w[::2], w[1::2])}
        return dhcp_text.lease_seconds(values.get("days", 0), values.get("hours", 0), values.get("minutes", 0))

    def _eos_subnet(self, node: Node, vrf: str) -> DhcpPool:
        network = str(ipaddress.ip_network(node.words[1]))
        pool = DhcpPool(f"subnet-{network}", network=network, vrf=vrf, origin=Origin(node.line, node.text))
        for child in node.children:
            c = child.words
            try:
                if c[0] == "range" and len(c) == 3:
                    pool.ranges.append((str(ipaddress.IPv4Address(c[1])), str(ipaddress.IPv4Address(c[2]))))
                elif c[0] == "default-gateway" and len(c) == 2:
                    pool.default_routers.append(str(ipaddress.IPv4Address(c[1])))
                elif c[:2] == ["dns", "server"] and len(c) >= 3:
                    pool.dns_servers = [str(ipaddress.IPv4Address(a)) for a in c[2:]]
                elif c[0] == "name" and len(c) == 2:
                    pool.name = c[1]
                elif c[:2] == ["lease", "time"]:
                    pool.lease_seconds = self._eos_lease(c[2:])
                else:
                    self.unparsed(child, node.text)
            except (ValueError, IndexError):
                self.unparsed(child, node.text)
        return pool

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
        if w[1:2] == ["bgp"] and len(w) == 3 and self.device.bgp is None:
            return self.bgp(node, w[2])
        return False

    def bgp(self, node: Node, local_as: str) -> bool:
        b = bgp_text.Builder(local_as)
        b.bgp.origin = Origin(node.line, node.text)
        for child in node.children:
            w = child.words
            af = ""
            if w[0] == "address-family" and w[1:] in (["ipv4"], ["ipv4", "unicast"], ["ipv6"], ["ipv6", "unicast"]):
                af = w[1]
            elif w[0] == "address-family":
                self.unparsed(child, node.text)
                continue
            for line in child.children if af else [child]:
                if line.words == ["exit-address-family"]:
                    continue
                try:
                    understood = self.bgp_line(b, line.words, af)
                except (ValueError, IndexError):
                    understood = False
                if not understood:
                    self.unparsed(line, child.text if af else node.text)
        self.device.bgp = b.finish()
        return True

    @staticmethod
    def bgp_line(b: bgp_text.Builder, w: List[str], af: str) -> bool:
        n = len(w)
        bgp = b.bgp
        if w[0] in ("bgp", "router-id") and w[-2:-1] == ["router-id"] and n in (2, 3):
            bgp.router_id = str(ipaddress.IPv4Address(w[-1]))
        elif w in (["bgp", "log-neighbor-changes"], ["no", "synchronization"], ["no", "auto-summary"]):
            pass
        elif w == ["no", "bgp", "default", "ipv4-unicast"]:
            b.default_ipv4 = False
        elif w[0] == "network" and n in (2, 4):
            if n == 4 and w[2] == "mask":
                prefix = str(ipaddress.ip_network(f"{w[1]}/{w[3]}"))
            elif n == 2 and "/" in w[1]:
                prefix = str(ipaddress.ip_network(w[1]))
            else:
                return False
            bgp.networks.append(prefix)
        elif w[0] == "redistribute" and n >= 2 and w[1] in bgp_text.REDISTRIBUTE:
            rest = w[3:] if w[1] == "ospf" and n >= 3 and w[2].isdigit() else w[2:]
            if rest:
                return False  # a route map or metric
            (bgp.redistribute6 if af == "ipv6" else bgp.redistribute).append(w[1])
        elif w[:2] == ["no", "neighbor"] and n == 4 and w[3] == "activate":
            b.activate(w[2], af or "ipv4", on=False)
        elif w[0] == "neighbor" and n >= 3:
            return ioslike_neighbor(b, w[1], w[2:], af)
        else:
            return False
        return True

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
        stp = self.device.stp
        if len(w) == 3 and w[1] == "mode":
            modes = {"pvst": StpMode.PVST, "rapid-pvst": StpMode.RAPID_PVST, "mst": StpMode.MSTP,
                     "mstp": StpMode.MSTP, "rstp": StpMode.RSTP, "none": StpMode.NONE}
            if w[2] in modes:
                self.device.stp_mode = modes[w[2]]
                return True
        if w[1:] == ["extend", "system-id"]:
            return True  # the IOS default
        if w[1] in ("vlan", "vlan-id") and len(w) == 5 and w[3] == "priority":
            # IOS: spanning-tree vlan 10,20 priority N; EOS: spanning-tree vlan-id 10 priority N
            for vlan in _vlan_ids(w[2]):
                stp.vlan_priority[vlan] = int(w[4])
            return True
        if w[1] == "mst" and len(w) == 5 and w[3] == "priority":
            for instance in _vlan_ids(w[2]):
                stp.priority[instance] = int(w[4])
            return True
        if w[1] == "priority" and len(w) == 3:  # EOS rstp
            stp.priority[0] = int(w[2])
            return True
        if w[1:] == ["mst", "configuration"]:
            for child in node.children:
                c = child.words
                if c[0] == "name" and len(c) == 2:
                    stp.region = c[1]
                elif c[0] == "revision" and len(c) == 2:
                    stp.revision = int(c[1])
                elif c[0] == "instance" and len(c) == 4 and c[2] == "vlan":
                    stp.instances.setdefault(int(c[1]), []).extend(_vlan_ids(c[3]))
                else:
                    self.unparsed(child, node.text)
            return True
        return False

    def line(self, node: Node) -> bool:
        """IOS: line vty 0 15 with transport input, access-class and exec-timeout; other lines stay unread."""
        w = node.words
        if w[1:2] != ["vty"]:
            return False
        m = self.device.management
        for child in node.children:
            c = child.words
            if c[:2] == ["transport", "input"] and len(c) >= 3:
                allowed = set(c[2:])
                if not allowed <= {"ssh", "telnet", "all", "none"}:
                    self.unparsed(child, node.text)
                    continue
                m.ssh = bool(allowed & {"ssh", "all"})
                m.telnet = bool(allowed & {"telnet", "all"})
            elif c[0] == "access-class" and len(c) in (3, 4) and c[2] == "in" and c[3:] in ([], ["vrf-also"]):
                m.vty_acl = c[1]
            elif c[0] == "exec-timeout" and len(c) in (2, 3) and all(x.isdigit() for x in c[1:]):
                m.exec_timeout = int(c[1]) + (1 if c[2:] and int(c[2]) else 0)
            else:
                self.unparsed(child, node.text)
        return True

    def discovery(self, node: Node) -> bool:
        """lldp run, cdp run (the no forms come through no_global)."""
        if node.words[1:] == ["run"]:
            setattr(self.device.management, node.words[0], True)
            return True
        return False

    def no_global(self, node: Node) -> bool:
        w = node.words
        m = self.device.management
        if w[1:] in (["lldp", "run"], ["cdp", "run"]):
            setattr(m, w[1], False)
            return True
        if w[1:] in (["ip", "http", "server"], ["ip", "http", "secure-server"]):
            setattr(m, "http" if w[3] == "server" else "https", False)
            return True
        return False

    def management(self, node: Node) -> bool:
        """EOS: management ssh (shutdown, idle-timeout, ip access-group, vrf V with no shutdown) and management
        telnet."""
        w = node.words
        m = self.device.management
        if w[1:] not in (["ssh"], ["telnet"]):
            return False
        server = w[1]
        setattr(m, server, True)
        for child in node.children:
            c = child.words
            if c in (["shutdown"], ["no", "shutdown"]):
                setattr(m, server, c[0] == "no")
            elif server == "ssh" and c[0] == "idle-timeout" and len(c) == 2 and c[1].isdigit():
                m.exec_timeout = int(c[1])
            elif server == "ssh" and c[:2] == ["ip", "access-group"] and len(c) in (4, 6) and c[-1] == "in":
                m.vty_acl = c[2]
            elif server == "ssh" and c[0] == "vrf" and len(c) == 2 \
                    and all(g.words in (["no", "shutdown"],) for g in child.children):
                m.vrf = c[1]
            else:
                self.unparsed(child, node.text)
        return True

    def wlan(self, node: Node) -> bool:
        """IOS XE controller: wlan NAME ID SSID, with WPA2 802.1X unless told otherwise."""
        w = node.words
        if len(w) != 4 or not w[2].isdigit():
            return False
        wl = Wlan(w[1], ssid=w[3], wlan_id=int(w[2]), origin=Origin(node.line, node.text))
        wpa, akm_psk, akm_dot1x = True, False, True
        for child in node.children:
            c = child.words
            if c in (["no", "security", "wpa"], ["no", "security", "wpa", "wpa2"]):
                wpa = False
            elif c == ["no", "security", "wpa", "wpa2", "ciphers", "aes"] and not wpa:
                pass
            elif c[:3] == ["security", "wpa", "akm"] and len(c) == 4 and c[3] in ("psk", "dot1x"):
                akm_psk, akm_dot1x = (True, akm_dot1x) if c[3] == "psk" else (akm_psk, True)
            elif c[:4] == ["no", "security", "wpa", "akm"] and len(c) == 5 and c[4] in ("psk", "dot1x"):
                akm_psk, akm_dot1x = (False, akm_dot1x) if c[4] == "psk" else (akm_psk, False)
            elif c[:5] == ["security", "wpa", "psk", "set-key", "ascii"] and len(c) == 7 and c[5] in ("0", "8"):
                wl.psk = c[6] if c[5] == "0" else ""
            elif c in (["shutdown"], ["no", "shutdown"]):
                wl.enabled = c[0] == "no"
            else:
                self.unparsed(child, node.text)
        wl.security = "open" if not wpa else "dot1x" if akm_dot1x else "psk" if akm_psk else "open"
        self.device.wlans.append(wl)
        return True

    def wireless(self, node: Node) -> bool:
        """IOS XE controller: wireless profile policy P (vlan N) and wireless tag policy T (wlan W policy P)."""
        w = node.words
        if w[1:3] == ["profile", "policy"] and len(w) == 4:
            self._wlan_profiles[w[3]] = None
            for child in node.children:
                c = child.words
                if c[0] == "vlan" and len(c) == 2 and c[1].isdigit():
                    self._wlan_profiles[w[3]] = int(c[1])
                elif c not in (["shutdown"], ["no", "shutdown"]):
                    self.unparsed(child, node.text)
            return True
        if w[1:3] == ["tag", "policy"] and len(w) == 4:
            for child in node.children:
                c = child.words
                if c[0] == "wlan" and len(c) == 4 and c[2] == "policy":
                    self._wlan_tags[c[1]] = c[3]
                else:
                    self.unparsed(child, node.text)
            return True
        return False

    def mpls(self, node: Node) -> bool:
        """IOS: mpls label protocol ldp, mpls ldp router-id IFACE [force]; EOS: mpls ip, and the mpls ldp block with
        router-id [interface] X and [no] shutdown."""
        w = node.words
        m = self.device.mpls
        m.origin = Origin(node.line, node.text)
        if w[1:] == ["ip"]:
            return True  # label switching on (the IOS default)
        if w[1:] == ["label", "protocol", "ldp"]:
            m.ldp = True
            return True
        if w[1:3] == ["ldp", "router-id"] and len(w) in (4, 5) and w[4:] in ([], ["force"]):
            m.router_id_interface = names.canonical(w[3])[0]
            m.ldp = True
            return True
        if w[1:] == ["ldp"]:
            m.ldp = True
            for child in node.children:
                c = child.words
                if c[0] == "router-id" and len(c) == 2:
                    m.router_id = c[1]
                elif c[:2] == ["router-id", "interface"] and len(c) == 3:
                    m.router_id_interface = names.canonical(c[2])[0]
                elif c in (["no", "shutdown"], ["interface", "disabled", "default"]):
                    pass
                elif c == ["shutdown"]:
                    m.ldp = False
                else:
                    self.unparsed(child, node.text)
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
        elif w[:2] == ["ip", "nat"] and w[2:] in (["inside"], ["outside"]):
            iface.nat = w[2]
        elif w[:3] == ["ip", "nat", "source"] and n >= 5:
            return self.eos_nat(iface, w[3:])
        elif w[:2] == ["crypto", "map"] and n == 3:
            iface.crypto_map = w[2]
        elif w[0] == "tunnel" and n >= 3:
            return self.tunnel_line(iface, w[1:])
        elif w[:3] == ["dhcp", "server", "ipv4"] and n == 3:
            pass  # EOS: the interface serves the subnet it is in
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
        elif w[:2] == ["spanning-tree", "guard"] and n == 3 and w[2] in ("root", "loop", "none"):
            iface.stp_guard = "" if w[2] == "none" else w[2]
        elif w[:2] == ["spanning-tree", "bpdufilter"] and n == 3 and w[2] in ("enable", "enabled", "disable",
                                                                               "disabled"):
            iface.stp_bpdufilter = w[2].startswith("enable")
        elif w[:2] == ["spanning-tree", "cost"] and n == 3:
            iface.stp_cost = int(w[2])
        elif w[:2] == ["spanning-tree", "port-priority"] and n == 3:
            iface.stp_port_priority = int(w[2])
        elif w[0] in ("authentication", "access-session", "dot1x", "mab") and n >= 1:
            return self.dot1x_line(iface, w)
        elif w[0] == "service-policy" and n in (3, 5):
            # IOS: service-policy input|output P; EOS: service-policy type qos input P
            args = w[3:] if w[1:3] == ["type", "qos"] else w[1:]
            if len(args) != 2 or args[0] not in ("input", "output"):
                return False
            setattr(iface, "qos_policy_in" if args[0] == "input" else "qos_policy_out", args[1])
        elif w[:3] == ["mls", "qos", "trust"] and n == 4 and w[3] in ("dscp", "cos"):
            iface.qos_trust = w[3]
        elif w[:2] == ["qos", "trust"] and n == 3 and w[2] in ("dscp", "cos", "disabled"):
            iface.qos_trust = "none" if w[2] == "disabled" else w[2]
        elif w in (["no", "lldp", "transmit"], ["no", "lldp", "receive"]):
            setattr(iface, "lldp_tx" if w[2] == "transmit" else "lldp_rx", False)
        elif w in (["cdp", "enable"], ["no", "cdp", "enable"]):
            iface.cdp = w[0] == "cdp"
        elif w == ["mpls", "ip"] or w == ["mpls", "ldp", "interface"]:
            # IOS: mpls ip (label switching and LDP); EOS: mpls ldp interface (mpls ip is the EOS default)
            if self.device.platform == "ios" or w[1] == "ldp":
                iface.mpls = True
                self.device.mpls.ldp = True
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
        self._finish_vpn()
        for wl in self.device.wlans:
            wl.vlan = self._wlan_profiles.get(self._wlan_tags.get(wl.name, ""))
        self._finish_aaa()
        for iface in self.device.interfaces.values():
            if (iface.dot1x or iface.mab) and not iface.dot1x_host_mode:
                iface.dot1x_host_mode = "single-host"  # the IOS and EOS default
        for pool in self.device.dhcp_pools:
            if pool.network:
                pool.ranges = dhcp_text.subtract(pool.network, pool.ranges, self._dhcp_excluded.get(pool.vrf, []))
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


def ioslike_neighbor(b: bgp_text.Builder, name: str, w: List[str], af: str) -> bool:
    """neighbor NAME ... in the IOS and EOS spellings."""
    n = len(w)
    if w in (["peer-group"], ["peer", "group"]):
        b.peer(name, group=True)
        return True
    peer = b.peer(name)
    if w[0] == "peer-group" and n == 2 or w[:2] == ["peer", "group"] and n == 3:
        peer.peer_group = w[-1]
        b.peer(w[-1], group=True)
    elif w[0] == "remote-as" and n == 2:
        peer.remote_as = w[1]
    elif w[0] == "description" and n >= 2:
        peer.description = " ".join(w[1:])
    elif w[0] == "update-source" and n >= 2:
        peer.update_source = names.canonical(" ".join(w[1:]))[0]
    elif w[0] == "ebgp-multihop" and n in (1, 2):
        peer.ebgp_multihop = int(w[1]) if n == 2 else 255
    elif w == ["shutdown"]:
        peer.shutdown = True
    elif w == ["next-hop-self"]:
        peer.next_hop_self = True
    elif w[0] == "send-community" and w[1:] in ([], ["both"], ["standard"]):
        peer.send_community = True
    elif w == ["activate"]:
        b.activate(name, af or "ipv4")
    else:
        return False
    return True


def parse(text: str, platform: str) -> Device:
    return _Reader(platform).read(text)
