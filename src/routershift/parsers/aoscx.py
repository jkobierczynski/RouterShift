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
import re
from typing import Callable, Dict, List, Optional, Tuple

from .. import acl as acl_text
from .. import bgp as bgp_text
from .. import dhcp as dhcp_text
from .. import fhrp
from .. import ospf as ospf_text
from .. import aaa as aaa_text
from .. import mgmt as mgmt_text
from .. import qos as qos_text
from .. import confparse
from ..confparse import Node
from ..errors import ParseError
from ..model import (AaaGroup, AaaMethod, AaaServer, Acl, Device, LocalUser, DhcpPool, FhrpGroup, NtpKey, SnmpCommunity, SnmpHost, SnmpUser, Interface, InterfaceKind, LacpMode, Origin, Ospf, QosAction, QosClass,
                     QosPolicy, StaticRoute, StpMode, SwitchportMode, Unparsed, Vlan)
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


AOSCX_ROLES = [(15, "administrators"), (1, "operators")]


class _Reader:
    def __init__(self) -> None:
        self.device = Device(platform="aoscx")
        self._routing: Dict[str, bool] = {}  # explicit routing / no routing per interface
        self._lag_lacp: Dict[str, LacpMode] = {}
        self._ospf_areas: List[Tuple[str, str, str]] = []
        self._ospf_passive: Dict[str, bool] = {}
        self._voice_vlans: List[int] = []
        self._class_acls: List[Tuple[QosClass, Acl]] = []
        self._client_limit: Dict[str, int] = {}  # port access, per port
        self._auth_mode: Dict[str, str] = {}

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
            "dhcp-server": self.dhcp_server,
            "snmp-server": self.snmp,
            "snmpv3": self.snmpv3,
            "user": self.user,
            "radius-server": self.aaa_host,
            "tacacs-server": self.aaa_host,
            "aaa": self.aaa,
            "class": self.qos_class,
            "policy": self.qos_policy,
            "dhcpv4-snooping": lambda node: node.words == ["dhcpv4-snooping"] and self._snooping(),
            "ssh": self.server,
            "https-server": self.server,
            "cli-session": self.cli_session,
            "lldp": lambda node: node.words == ["lldp"] and self._set_lldp(True),
            "no": lambda node: node.words == ["no", "lldp"] and self._set_lldp(False),
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
        if w[1] == "source-interface" and len(w) >= 5 and w[2] in ("tftp", "syslog") and w[3] == "interface":
            end = w.index("vrf") if "vrf" in w else len(w)
            name = re.sub(r"^(vlan|loopback)(\d)", r"\1 \2", " ".join(w[4:end]))
            if w[2] == "tftp":
                self.device.system.transfer_source["tftp"] = canonical(name)[0]
            else:
                self.device.system.logging_source = canonical(name)[0]
            return end in (5, 6) and len(w) in (end, end + 2)
        if w[1] == "source-interface" and len(w) >= 5 and w[2] in ("radius", "tacacs", "all") and w[3] == "interface":
            # ip source-interface radius|tacacs|all interface X [vrf V]
            # X is 1/1/1, vlan10 or loopback0 (or "vlan 10")
            end = w.index("vrf") if "vrf" in w else len(w)
            name = re.sub(r"^(vlan|loopback)(\d)", r"\1 \2", " ".join(w[4:end]))
            for protocol in (["radius", "tacacs"] if w[2] == "all" else [w[2]]):
                self.device.aaa.source[protocol] = canonical(name)[0]
            return end in (5, 6) and len(w) in (end, end + 2)
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
        s = self.device.system
        if w[1:2] == ["server"] and len(w) >= 3:
            s.ntp_servers.append(w[2])
            options = w[3:]
            while options:
                if options[0] == "prefer":
                    s.ntp_prefer = w[2]
                elif options[0] in ("key", "version") and len(options) >= 2:
                    if options[0] == "key":
                        s.ntp_server_keys[w[2]] = int(options[1])
                    options = options[1:]
                elif options[0] != "iburst":
                    return False
                options = options[1:]
            return True
        if w[1:] == ["authentication"]:
            s.ntp_authenticate = True
            return True
        if w[1] == "authentication-key" and len(w) >= 5:
            # ntp authentication-key 1 md5|sha1 [plaintext|ciphertext] KEY [trusted]
            key = s.ntp_keys.setdefault(int(w[2]), NtpKey(int(w[2])))
            args = w[4:]
            if args[-1:] == ["trusted"]:
                key.trusted, args = True, args[:-1]
            key.algorithm = w[3]
            encrypted = args[:1] == ["ciphertext"]
            if args[:1] in (["plaintext"], ["ciphertext"]):
                args = args[1:]
            key.key = "" if encrypted else args[0]
            return len(args) == 1 and w[3] in ("md5", "sha1")
        if w[1] == "trusted-key" and len(w) == 3:
            s.ntp_keys.setdefault(int(w[2]), NtpKey(int(w[2]))).trusted = True
            return True
        return False

    def snmp(self, node: Node) -> bool:
        w = node.words
        s = self.device.snmp
        origin = Origin(node.line, node.text)
        if w[1] == "vrf" and len(w) == 3:
            s.vrf = w[2]
            return True
        if w[1] in ("system-location", "system-contact") and len(w) >= 3:
            setattr(s, w[1][len("system-"):], node.text.split(None, 2)[2])
            return True
        if w[1] == "community" and len(w) == 3:
            community = SnmpCommunity(w[2], origin=origin)
            s.communities.append(community)
            for child in node.children:
                if child.words[:1] == ["access-level"] and child.words[1:] in (["ro"], ["rw"]):
                    community.access = child.words[1]
                else:
                    self.unparsed(child, node.text)
            return True
        if w[1] == "host" and len(w) >= 7 and w[3] in ("trap", "inform") and w[4] == "version":
            # snmp-server host A trap|inform version v2c [community NAME] [port N] [vrf V] / v3 user U
            host = SnmpHost(str(ipaddress.ip_address(w[2])), w[5].lstrip("v"), informs=w[3] == "inform",
                            origin=origin)
            args = w[6:]
            while len(args) >= 2:
                if args[0] in ("community", "user"):
                    host.secret = args[1]
                elif args[0] == "vrf":
                    host.vrf = args[1]
                elif args[0] != "port":
                    return False
                args = args[2:]
            s.hosts.append(host)
            return not args and host.version in ("1", "2c", "3")
        return False

    def user(self, node: Node) -> bool:
        """user U group G password plaintext|ciphertext X"""
        w = node.words
        if len(w) != 7 or w[2] != "group" or w[4] != "password" or w[5] not in ("plaintext", "ciphertext"):
            return False
        privilege = aaa_text.privilege(w[3], AOSCX_ROLES)
        user = LocalUser(w[1], privilege, origin=Origin(node.line, node.text))
        if w[5] == "plaintext":
            user.password = w[6]
        else:
            user.password_hash, user.hash_type = w[6], "aoscx-ciphertext"
        self.device.users.append(user)
        return privilege is not None

    def _key(self, args: List[str]) -> str:
        """key plaintext|ciphertext K: the key, '' when encrypted."""
        return args[2] if args[1] == "plaintext" else ""

    def aaa_host(self, node: Node) -> bool:
        """radius-server|tacacs-server host A [key plaintext|ciphertext K] [auth-port N] [acct-port N] [port N]
        [timeout N] [vrf V]"""
        w = node.words
        if w[1] != "host" or len(w) < 3:
            return False
        server = AaaServer("radius" if w[0] == "radius-server" else "tacacs", str(ipaddress.ip_address(w[2])),
                           origin=Origin(node.line, node.text))
        args = w[3:]
        while args:
            if args[0] == "key" and len(args) >= 3:
                server.key, args = self._key(args), args[3:]
            elif args[0] == "vrf" and len(args) >= 2:
                server.vrf, args = args[1], args[2:]
            elif args[0] in ("auth-port", "acct-port", "port", "timeout") and len(args) >= 2:
                setattr(server, {"port": "auth_port"}.get(args[0], args[0].replace("-", "_")), int(args[1]))
                args = args[2:]
            else:
                return False
        self.device.aaa.servers.append(server)
        return True

    def aaa(self, node: Node) -> bool:
        w = node.words
        a = self.device.aaa
        origin = Origin(node.line, node.text)
        if w[1:3] == ["group", "server"] and len(w) == 5 and w[3] in ("radius", "tacacs"):
            group = AaaGroup(w[3], w[4], origin=origin)
            a.groups[group.name] = group
            for child in node.children:
                c = child.words
                if c[0] == "server" and len(c) >= 2:
                    group.servers.append(str(ipaddress.ip_address(c[1])))
                    rest = c[2:]
                    if rest[-2:-1] == ["vrf"]:
                        group.vrf, rest = rest[-1], rest[:-2]
                    if rest[:1] == ["port"]:
                        rest = rest[2:]
                    if rest:
                        self.unparsed(child, node.text)
                else:
                    self.unparsed(child, node.text)
            return True
        if w[1:4] == ["authentication", "port-access", "dot1x"] and w[4:] == ["authenticator"] or \
                w[1:] == ["authentication", "port-access", "mac-auth"]:
            for child in node.children:
                c = child.words
                if c == ["enable"]:
                    a.dot1x = a.dot1x or w[3] == "dot1x"
                elif c[:2] == ["radius", "server-group"] and len(c) == 3:
                    if not any(m.service == "dot1x" for m in a.methods):
                        a.methods.append(AaaMethod("authentication", "dot1x", [f"group:{c[2]}"], origin=origin))
                else:
                    self.unparsed(child, node.text)
            return True
        # aaa authentication login NAME ..., aaa authorization commands NAME ..., aaa accounting all-mgmt NAME start-stop
        if w[1:3] in (["authentication", "login"], ["authorization", "commands"], ["accounting", "all-mgmt"]) \
                and len(w) >= 5:
            args = w[4:]
            methods = []
            record = ""
            if w[1] == "accounting":
                record, args = args[0], args[1:]
            while args:
                if args[0] == "group" and len(args) >= 2:
                    methods += [f"group:{name}" for name in args[1:] if name not in ("local", "none")]
                    methods += [name for name in args[1:] if name in ("local", "none")]
                    args = []
                elif args[0] in ("local", "none"):
                    methods.append(args[0])
                    args = args[1:]
                else:
                    return False
            if w[1] == "accounting":  # one list for exec sessions and commands
                a.methods.append(AaaMethod("accounting", "exec", methods, w[3], record=record, origin=origin))
                a.methods.append(AaaMethod("accounting", "commands", list(methods), w[3], 15, record, origin))
            else:
                a.methods.append(AaaMethod(w[1], w[2], methods, w[3], 15 if w[2] == "commands" else None,
                                           origin=origin))
            return True
        return False

    def snmpv3(self, node: Node) -> bool:
        """snmpv3 user U [auth md5|sha AUTH-PASS] [priv des|aes PRIV-PASS]; a pass is
        'auth-pass plaintext|ciphertext KEY'."""
        w = node.words
        if w[1] != "user" or len(w) < 3:
            return False
        user = SnmpUser(w[2], origin=Origin(node.line, node.text))
        args = w[3:]
        for kind in ("auth", "priv"):
            if args[:1] == [kind] and len(args) >= 5 and args[2] == f"{kind}-pass":
                algorithm = "aes128" if args[1] == "aes" else args[1]
                key = "" if args[3] == "ciphertext" else args[4]
                if kind == "auth":
                    user.auth, user.auth_key = algorithm, key
                else:
                    user.priv, user.priv_key = algorithm, key
                args = args[5:]
        self.device.snmp.users.append(user)
        return not args

    def server(self, node: Node) -> bool:
        """ssh server vrf V, https-server vrf V."""
        w = node.words
        args = w[2:] if w[:2] == ["ssh", "server"] else w[1:] if w[0] == "https-server" else []
        if len(args) != 2 or args[0] != "vrf":
            return False
        m = self.device.management
        setattr(m, "ssh" if w[0] == "ssh" else "https", True)
        if w[0] == "ssh" and (not m.vrf or args[1] != "default"):
            m.vrf = "" if args[1] == "default" else args[1]
        return True

    def cli_session(self, node: Node) -> bool:
        """cli-session with 'timeout M' (minutes)."""
        for child in node.children:
            if child.words[0] == "timeout" and len(child.words) == 2 and child.words[1].isdigit():
                self.device.management.exec_timeout = int(child.words[1])
            else:
                self.unparsed(child, node.text)
        return True

    def _snooping(self) -> bool:
        self.device.dhcp_snooping = True
        return True

    def _set_lldp(self, on: bool) -> bool:
        self.device.management.lldp = on
        return True

    def logging(self, node: Node) -> bool:
        args = self._service_vrf(node.words[1:])
        if len(args) == 3 and args[1] == "severity" and mgmt_text.level(args[2]) is not None:
            self.device.system.logging_level = mgmt_text.level(args[2])
            args = args[:1]
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
                elif child.text == "dhcpv4-snooping":
                    vlan.dhcp_snooping = True
                elif child.text == "arp inspection":
                    vlan.arp_inspection = True
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
        stp = self.device.stp
        # priorities are multipliers of 4096: spanning-tree [instance N | vlan LIST] priority M
        if w[1] == "priority" and len(w) == 3:
            stp.priority[0] = int(w[2]) * 4096
            return True
        if w[1] == "instance" and len(w) == 5 and w[3] == "priority":
            stp.priority[int(w[2])] = int(w[4]) * 4096
            return True
        if w[1] == "vlan" and len(w) == 5 and w[3] == "priority":
            for vlan in _vlan_ids(w[2]):
                stp.vlan_priority[vlan] = int(w[4]) * 4096
            return True
        if w[1] == "instance" and len(w) == 5 and w[3] == "vlan":
            stp.instances.setdefault(int(w[2]), []).extend(_vlan_ids(w[4]))
            return True
        if w[1] == "config-name" and len(w) == 3:
            stp.region = w[2]
            return True
        if w[1] == "config-revision" and len(w) == 3:
            stp.revision = int(w[2])
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

    # QoS -------------------------------------------------------------------------------------------------------------

    def qos_class(self, node: Node) -> bool:
        """class ip NAME, entries '10 match any any any dscp 46' or ACL-like '20 match udp any any range 5000 5100'"""
        w = node.words
        if len(w) != 3 or w[1] != "ip":
            return False
        qos_class = QosClass(w[2], origin=Origin(node.line, node.text))
        self.device.qos_classes[qos_class.name] = qos_class
        for child in qos_text.read_class(qos_class, node.children, "dscp", False, self._class_acls):
            self.unparsed(child, node.text)
        return True

    def qos_policy(self, node: Node) -> bool:
        """policy NAME, entries '10 class ip C action dscp 46 action cir kbps 2000 cbs 250000 exceed drop'"""
        w = node.words
        if len(w) != 2:
            return False
        policy = QosPolicy(w[1], origin=Origin(node.line, node.text))
        self.device.qos_policies[policy.name] = policy
        for child in node.children:
            c = child.words
            action = QosAction(c[3]) if len(c) >= 4 and c[0].isdigit() and c[1:3] == ["class", "ip"] else None
            args = c[4:]
            while action is not None and args:
                if args[:2] == ["action", "dscp"] and len(args) >= 3:
                    action.set_dscp, args = qos_text.dscp(args[2]), args[3:]
                elif args[:3] == ["action", "cir", "kbps"] and len(args) >= 4:
                    action.police_kbps, args = int(args[3]), args[4:]
                    if args[:1] == ["cbs"]:
                        args = args[2:]
                    if args[:2] != ["exceed", "drop"]:
                        action = None
                    args = args[2:]
                else:
                    action = None
            if action is None:
                self.unparsed(child, node.text)
            else:
                policy.actions.append(action)
        return True

    # interfaces ------------------------------------------------------------------------------------------------------

    def dhcp_server(self, node: Node) -> bool:
        """dhcp-server vrf V, with pools inside."""
        w = node.words
        if len(w) != 3 or w[1] != "vrf":
            return False
        vrf = "" if w[2] == "default" else w[2]
        for child in node.children:
            if child.words == ["enable"]:
                continue
            if child.words[0] == "pool" and len(child.words) == 2:
                self._dhcp_pool(child, vrf)
            else:
                self.unparsed(child, node.text)
        return True

    def _dhcp_pool(self, node: Node, vrf: str) -> None:
        pool = DhcpPool(node.words[1], vrf=vrf, origin=Origin(node.line, node.text))
        self.device.dhcp_pools.append(pool)
        for child in node.children:
            c = child.words
            try:
                if c == ["exit"]:
                    continue
                if c[0] == "range" and len(c) == 5 and c[3] == "prefix-len":
                    first, last = str(ipaddress.IPv4Address(c[1])), str(ipaddress.IPv4Address(c[2]))
                    pool.ranges.append((first, last))
                    pool.network = str(ipaddress.ip_network(f"{first}/{c[4]}", strict=False))
                elif c[0] == "default-router" and len(c) >= 2:
                    pool.default_routers += [str(ipaddress.IPv4Address(a)) for a in c[1:]]
                elif c[0] == "dns-server" and len(c) >= 2:
                    pool.dns_servers += [str(ipaddress.IPv4Address(a)) for a in c[1:]]
                elif c[0] == "domain-name" and len(c) == 2:
                    pool.domain_name = c[1]
                elif c == ["lease", "infinite"]:
                    pool.lease_seconds = 0
                elif c[0] == "lease" and len(c) == 2:
                    days, hours, minutes = (int(v) for v in c[1].split(":"))
                    pool.lease_seconds = dhcp_text.lease_seconds(days, hours, minutes)
                else:
                    self.unparsed(child, node.text)
            except ValueError:
                self.unparsed(child, node.text)

    def router(self, node: Node) -> bool:
        w = node.words
        if w == ["router", "vrrp", "enable"]:
            return True  # implied by the groups
        if w[1:2] == ["ospf"] and len(w) in (3, 5) and (len(w) == 3 or w[3] == "vrf"):
            vrf = w[4] if len(w) == 5 else ""
            p = ospf_text.process(self.device, w[2], vrf)
            p.vrf = vrf
            p.origin = Origin(node.line, node.text)
            for child in node.children:
                try:
                    understood = self.ospf_line(p, child.words)
                except (ValueError, IndexError):
                    understood = False
                if not understood:
                    self.unparsed(child, node.text)
            return True
        if w[1:2] == ["bgp"] and len(w) == 3 and self.device.bgp is None:
            self.bgp(node, w[2])
            return True
        return False

    def bgp(self, node: Node, local_as: str) -> None:
        b = bgp_text.Builder(local_as)
        b.default_ipv4 = False  # AOS-CX lists "neighbor X activate" in the address family
        b.bgp.origin = Origin(node.line, node.text)
        for child in node.children:
            w = child.words
            af = ""
            if w[0] == "address-family" and w[1:] in (["ipv4", "unicast"], ["ipv6", "unicast"]):
                af = w[1]
            elif w[0] == "address-family":
                self.unparsed(child, node.text)
                continue
            for line in child.children if af else [child]:
                try:
                    understood = self.bgp_line(b, line.words, af)
                except (ValueError, IndexError):
                    understood = False
                if not understood:
                    self.unparsed(line, child.text if af else node.text)
        self.device.bgp = b.finish()

    @staticmethod
    def bgp_line(b: bgp_text.Builder, w: List[str], af: str) -> bool:
        n = len(w)
        if w == ["exit-address-family"]:
            return True
        if w[:2] == ["bgp", "router-id"] and n == 3:
            b.bgp.router_id = str(ipaddress.IPv4Address(w[2]))
            return True
        if w[0] == "network" and n == 2 and af:
            b.bgp.networks.append(str(ipaddress.ip_network(w[1])))
            return True
        if w[0] == "redistribute" and n == 2 and w[1] in bgp_text.REDISTRIBUTE and af:
            (b.bgp.redistribute6 if af == "ipv6" else b.bgp.redistribute).append(w[1])
            return True
        if w[:2] == ["no", "neighbor"] and n == 4 and w[3] == "activate":
            b.activate(w[2], af or "ipv4", on=False)
            return True
        if w[0] != "neighbor" or n < 3:
            return False
        peer = b.peer(w[1])
        args = w[2:]
        if args[0] == "remote-as" and len(args) == 2:
            peer.remote_as = args[1]
        elif args[0] == "description" and len(args) >= 2:
            peer.description = " ".join(args[1:])
        elif args[0] == "update-source" and len(args) >= 2:
            peer.update_source = canonical(" ".join(args[1:]))[0]
        elif args[0] == "ebgp-multihop" and len(args) in (1, 2):
            peer.ebgp_multihop = int(args[1]) if len(args) == 2 else 255
        elif args == ["shutdown"]:
            peer.shutdown = True
        elif args == ["activate"]:
            b.activate(w[1], af or "ipv4")
        elif args == ["next-hop-self"]:
            peer.next_hop_self = True
        elif args[0] == "send-community" and args[1:] in ([], ["standard"], ["both"]):
            peer.send_community = True
        else:
            return False
        return True

    @staticmethod
    def ospf_line(p: Ospf, w: List[str]) -> bool:
        n = len(w)
        if w[0] == "router-id" and n == 2:
            p.router_id = str(ipaddress.IPv4Address(w[1]))
        elif w == ["passive-interface", "default"]:
            p.passive_default = True
        elif w[0] == "area" and n == 2:
            ospf_text.area(w[1])  # declared; its interfaces say they are in it
        elif w[0] == "area" and n in (3, 4) and w[2] in ("stub", "nssa") and w[3:] in ([], ["no-summary"]):
            p.area_types[ospf_text.area(w[1])] = " ".join(w[2:])
        elif w[0] == "redistribute" and n == 2 and w[1] in ospf_text.REDISTRIBUTE:
            p.redistribute.append(w[1])
        elif w[:2] == ["default-information", "originate"] and w[2:] in ([], ["always"]):
            p.default_originate = "always" if n == 3 else "on"
        elif w[0] == "reference-bandwidth" and n == 2:
            p.reference_bandwidth = int(w[1])
        else:
            return False
        return True

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
            if child.words[:3] == ["aaa", "authentication", "port-access"] and self._port_access(iface, child):
                continue
            if child.words == ["port-access", "port-security"]:
                iface.port_security = True
                for c in child.children:
                    if c.words[0] == "client-limit" and len(c.words) == 2 and c.words[1].isdigit():
                        iface.port_security_max = int(c.words[1])
                    elif c.words != ["enable"]:
                        self.unparsed(c, child.text)
                continue
            try:
                understood = self.interface_line(iface, child.words)
            except (ValueError, IndexError):
                understood = False
            if not understood:
                self.unparsed(child, node.text)
        return True

    def _port_access(self, iface: Interface, node: Node) -> bool:
        """aaa authentication port-access client-limit N | auth-mode M | dot1x authenticator {...} | mac-auth {...}"""
        w = node.words[3:]
        if w[:1] == ["client-limit"] and len(w) == 2:
            self._client_limit[iface.name] = int(w[1])
            return True
        if w[:1] == ["auth-mode"] and len(w) == 2 and w[1] in ("client-mode", "device-mode", "multi-domain"):
            self._auth_mode[iface.name] = w[1]
            return True
        if w not in (["dot1x", "authenticator"], ["mac-auth"]):
            return False
        for child in node.children:
            c = child.words
            if c == ["enable"]:
                if w == ["mac-auth"]:
                    iface.mab = True
                else:
                    iface.dot1x = True
            elif c == ["reauth"] and w != ["mac-auth"]:
                iface.dot1x_reauth = True
            elif c[0] == "reauth-period" and len(c) == 2 and w != ["mac-auth"]:
                iface.dot1x_reauth_period = int(c[1])
            else:
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
        elif w[:2] == ["apply", "policy"] and n == 4 and w[3] in ("in", "out", "routed-in", "routed-out"):
            setattr(iface, f"qos_policy_{w[3].replace('routed-', '')}", w[2])
        elif w[:2] == ["qos", "trust"] and n == 3 and w[2] in ("dscp", "cos", "none"):
            iface.qos_trust = w[2]
        elif w in (["dhcpv4-snooping", "trust"], ["arp", "inspection", "trust"]):
            setattr(iface, "dhcp_trust" if w[0] == "dhcpv4-snooping" else "arp_trust", True)
        elif w == ["ipv4", "source-lockdown"]:
            iface.source_guard = True
        elif w in (["no", "lldp", "transmit"], ["no", "lldp", "receive"]):
            setattr(iface, "lldp_tx" if w[2] == "transmit" else "lldp_rx", False)
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
        elif w[:2] == ["ip", "ospf"] and n == 5 and w[3] == "area":
            self._ospf_areas.append((iface.name, w[2], ospf_text.area(w[4])))
        elif w == ["ip", "ospf", "passive"]:
            self._ospf_passive[iface.name] = True
        elif w == ["no", "ip", "ospf", "passive"]:
            self._ospf_passive[iface.name] = False
        elif w[:3] == ["ip", "ospf", "cost"] and n == 4:
            iface.ospf_cost = int(w[3])
        elif w[:3] == ["ip", "ospf", "network"] and n == 4 and w[3] in ("point-to-point", "broadcast"):
            iface.ospf_network = w[3]
        elif w[:2] == ["active-gateway", "ip"] and n >= 3:
            return self._active_gateway(iface, w[2:])
        elif w[:2] == ["spanning-tree", "port-type"] and n == 3 and w[2] in ("admin-edge", "admin-network"):
            iface.stp_portfast = w[2] == "admin-edge"
        elif w == ["spanning-tree", "bpdu-guard"]:
            iface.stp_bpduguard = True
        elif w in (["spanning-tree", "root-guard"], ["spanning-tree", "loop-guard"]):
            iface.stp_guard = w[1][:-len("-guard")]
        elif w == ["spanning-tree", "bpdu-filter"]:
            iface.stp_bpdufilter = True
        elif w[:2] == ["spanning-tree", "cost"] and n == 3:
            iface.stp_cost = int(w[2])
        elif w[:2] == ["spanning-tree", "port-priority"] and n == 3:
            iface.stp_port_priority = int(w[2]) * 16  # a multiplier of 16
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
        qos_text.adopt(self.device, self._class_acls)
        for iface in self.device.interfaces.values():
            self._voice_port(iface)
            if iface.dot1x or iface.mab:
                # client mode (the default) with one client is single-host; device mode opens the port to all
                mode = self._auth_mode.get(iface.name, "client-mode")
                limit = self._client_limit.get(iface.name, 1)
                iface.dot1x_host_mode = {"device-mode": "multi-host", "multi-domain": "multi-domain"}.get(
                    mode, "single-host" if limit == 1 else "multi-auth")
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
        ospf_text.attach(self.device, self._ospf_areas, self._ospf_passive)


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
