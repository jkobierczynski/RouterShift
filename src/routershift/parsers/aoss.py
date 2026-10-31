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

from .. import acl as acl_text
from .. import confparse
from .. import dhcp as dhcp_text
from .. import ospf as ospf_text
from .. import mgmt as mgmt_text
from .. import qos as qos_text
from ..confparse import Node
from ..errors import ParseError
from ..model import (AaaGroup, AaaMethod, AaaServer, Acl, Device, LocalUser, DhcpPool, FhrpGroup, NtpKey, SnmpCommunity, SnmpGroup, SnmpHost, SnmpUser, Interface, InterfaceKind, LacpMode, Origin, QosAction, QosClass, QosPolicy,
                     StaticRoute, StpMode, SwitchportMode, Unparsed, Vlan)
from ..timezones import utc
from .ioslike import _cidr, _is_address, _vlan_ids

OOBM_VRF = "oobm"

_NOISE = (";", "Running configuration", "exit", "module ", "flexible-module ", "stacking", "member ")
_PORT = re.compile(r"^(.*?)(\d+)$")


def unquote(text: str) -> str:
    return text[1:-1] if len(text) >= 2 and text[0] == text[-1] == '"' else text


_AOSS_ACTIONS = {"send-disable": "shutdown", "send-alarm": "restrict", "none": "protect"}


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
        self.router_id = ""
        self.router_id_line: Optional[Node] = None
        self.ospf_areas: List[Tuple[str, str, str]] = []
        self.ospf_passive: Dict[str, bool] = {}
        self._snmp_groups: List[Tuple[str, str]] = []  # (user, group)
        self._aaa_keys: Dict[str, str] = {}  # protocol -> the key of servers that have none of their own
        self._class_acls: List[Tuple[QosClass, Acl]] = []
        self._client_limit: Dict[Tuple[str, str], int] = {}  # (port, authenticator|mac-based) -> client limit

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
            "snmp-server": self.snmp,
            "snmpv3": self.snmpv3,
            "password": self.password,
            "radius-server": self.aaa_host,
            "tacacs-server": self.aaa_host,
            "aaa": self.aaa,
            "ip": self.ip,
            "ipv6": self.ipv6,
            "logging": self.logging,
            "trunk": self.trunk,
            "oobm": self.oobm,
            "interface": self.interface,
            "access-list": self.numbered_acl,
            "vlan": self.vlan,
            "spanning-tree": self.spanning_tree,
            "class": self.qos_class,
            "policy": self.qos_policy,
            "router": self.router,
            "dhcp-server": self.dhcp_server,
            "telnet-server": self.server,
            "web-management": self.server,
            "console": self.console,
            "lldp": self.lldp,
            "cdp": lambda node: node.words == ["cdp", "run"] and self._set("cdp", True),
            "no": self.no_global,
            "dhcp-snooping": self.snooping,
            "arp-protect": self.snooping,
            "port-security": self.port_security,
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
        s = self.device.system
        if w[1:2] == ["server"] and len(w) >= 3:
            s.ntp_servers.append(w[2])
            options = w[3:]
            if options[:1] == ["key"] and len(options) >= 2:
                s.ntp_server_keys[w[2]] = int(options[1])
                options = options[2:]
            return all(word in ("iburst", "burst") for word in options)
        if w[1:3] == ["authentication", "key-id"] and len(w) >= 8 and w[4] == "authentication-mode" \
                and w[6] == "key-value":
            # ntp authentication key-id 1 authentication-mode md5 key-value "KEY" [trusted]
            key = s.ntp_keys.setdefault(int(w[3]), NtpKey(int(w[3])))
            key.algorithm, key.key = w[5], w[7].strip('"')
            key.trusted = w[8:] == ["trusted"]
            s.ntp_authenticate = True  # AOS-S checks authentication whenever keys exist
            return len(w) in (8, 9) and w[5] in ("md5", "sha1")
        return w[1:] in (["enable"], ["unicast"])

    def snmp(self, node: Node) -> bool:
        w = [word.strip('"') for word in node.words]
        s = self.device.snmp
        origin = Origin(node.line, node.text)
        if w[1] == "community" and len(w) >= 3:
            words = set(w[3:])
            if not words <= {"operator", "manager", "restricted", "unrestricted"}:
                return False
            s.communities.append(SnmpCommunity(w[2], "ro" if "restricted" in words else "rw", origin=origin))
            return True
        if w[1] in ("location", "contact") and len(w) >= 3:
            setattr(s, w[1], node.text.split(None, 2)[2].strip('"'))
            return True
        if w[1:3] == ["enable", "traps"]:
            s.traps = True
            return True
        if w[1] == "host" and len(w) >= 5 and w[3] == "community":
            # snmp-server host A community "X" [trap-level all|critical|not-info|debug|none] [inform]
            host = SnmpHost(str(ipaddress.ip_address(w[2])), secret=w[4], origin=origin)
            args = w[5:]
            if args[:1] == ["trap-level"] and len(args) >= 2:
                args = args[2:]
            if args == ["inform"]:
                host.informs, args = True, []
            s.hosts.append(host)
            s.traps = True  # AOS-S sends notifications to every host it has
            return not args
        return False

    def password(self, node: Node) -> bool:
        """password manager|operator [user-name "U" plaintext|sha1 "X"]"""
        w = [unquote(word) for word in node.words]
        if w[1] not in ("manager", "operator"):
            return False
        if len(w) == 2:
            return True  # a password is set but not shown
        if len(w) != 6 or w[2] != "user-name" or w[4] not in ("plaintext", "sha1"):
            return False
        user = LocalUser(w[3], 15 if w[1] == "manager" else 1, origin=Origin(node.line, node.text))
        if w[4] == "plaintext":
            user.password = w[5]
        else:
            user.password_hash, user.hash_type = w[5], "aoss-sha1"
        self.device.users.append(user)
        return True

    def aaa_host(self, node: Node) -> bool:
        """radius-server|tacacs-server host A [key "K"] [auth-port N] [acct-port N] [timeout N]; ... key "K" (all)"""
        w = [unquote(word) for word in node.words]
        protocol = "radius" if w[0] == "radius-server" else "tacacs"
        if w[1] == "key" and len(w) == 3:
            self._aaa_keys[protocol] = w[2]
            return True
        if w[1] in ("timeout", "retransmit", "dead-time") and len(w) == 3:
            return True
        if w[1] != "host" or len(w) < 3:
            return False
        server = AaaServer(protocol, str(ipaddress.ip_address(w[2])), origin=Origin(node.line, node.text))
        args = w[3:]
        while len(args) >= 2:
            if args[0] == "key":
                server.key = args[1]
            elif args[0] in ("auth-port", "acct-port", "timeout"):
                setattr(server, args[0].replace("-", "_"), int(args[1]))
            else:
                return False
            args = args[2:]
        self.device.aaa.servers.append(server)
        return not args

    def aaa(self, node: Node) -> bool:
        w = [unquote(word) for word in node.words]
        a = self.device.aaa
        origin = Origin(node.line, node.text)
        if w[1] == "server-group" and len(w) == 6 and w[2] in ("radius", "tacacs") and w[4] == "host":
            group = a.groups.setdefault(w[3], AaaGroup(w[2], w[3], origin=origin))
            group.servers.append(str(ipaddress.ip_address(w[5])))
            return True
        if w[1] == "authentication" and len(w) >= 5 and w[2] in ("ssh", "telnet", "console", "web", "webui") \
                and w[3] in ("login", "enable"):
            # aaa authentication ssh login PRIMARY [server-group G] [SECONDARY]
            methods = self._methods(w[4:])
            if methods is None:
                return False
            a.methods.append(AaaMethod("authentication", w[3], methods, "default" if w[2] == "ssh" else w[2],
                                       origin=origin))
            return True
        if w[1] == "accounting" and len(w) >= 5 and w[2] in ("exec", "commands") \
                and w[3] in ("start-stop", "stop-only", "interim-update"):
            methods = self._methods(w[4:])
            if methods is None:
                return False
            a.methods.append(AaaMethod("accounting", w[2], methods, level=15 if w[2] == "commands" else None,
                                       record="start-stop" if w[3] != "stop-only" else "stop-only", origin=origin))
            return True
        if w[1:3] == ["port-access", "authenticator"] and w[3:] == ["active"]:
            a.dot1x = True
            return True
        if w[1:3] in (["port-access", "authenticator"], ["port-access", "mac-based"]) and len(w) >= 4:
            # aaa port-access authenticator|mac-based PORTS [client-limit|addr-limit N | reauth-period N]
            for name in ports(w[3]):
                iface = self.port(name)
                if w[4:] == []:
                    if w[2] == "authenticator":
                        iface.dot1x = True
                    else:
                        iface.mab = True
                elif w[4] in ("client-limit", "addr-limit") and len(w) == 6:
                    self._client_limit[(iface.name, w[2])] = int(w[5])
                elif w[4] == "reauth-period" and len(w) == 6 and w[2] == "authenticator":
                    iface.dot1x_reauth = int(w[5]) > 0
                    iface.dot1x_reauth_period = int(w[5]) or None
                else:
                    return False
            return True
        if w[1:4] == ["authentication", "port-access", "eap-radius"]:
            server_group = w[5] if w[4:5] == ["server-group"] and len(w) == 6 else "radius"
            a.methods.append(AaaMethod("authentication", "dot1x", [f"group:{server_group}"], origin=origin))
            return len(w) in (4, 6)
        if w[1:4] == ["authentication", "mac-based", "chap-radius"]:
            return True  # MAC authentication against the same servers
        if w[1:3] == ["authorization", "commands"] and len(w) >= 4:
            methods = self._methods(w[3:])
            if methods is None:
                return False
            a.methods.append(AaaMethod("authorization", "commands", methods, level=15, origin=origin))
            return True
        return False

    @staticmethod
    def _methods(words: List[str]) -> Optional[List[str]]:
        methods = []
        while words:
            if words[0] in ("radius", "tacacs"):
                if words[1:2] == ["server-group"] and len(words) >= 3:
                    methods.append(f"group:{words[2]}")
                    words = words[3:]
                else:
                    methods.append(f"group:{words[0]}")
                    words = words[1:]
            elif words[0] in ("local", "none"):
                methods.append(words[0])
                words = words[1:]
            else:
                return None
        return methods

    def snmpv3(self, node: Node) -> bool:
        """snmpv3 enable; snmpv3 user "U" [auth md5|sha "KEY" [priv des|aes "KEY"]]; snmpv3 group G user "U" sec-model
        ver3"""
        w = [word.strip('"') for word in node.words]
        if w[1:] in (["enable"],):
            return True
        if w[1] == "user" and len(w) >= 3:
            user = SnmpUser(w[2], origin=Origin(node.line, node.text))
            args = w[3:]
            if args[:1] == ["auth"] and len(args) >= 3:
                user.auth, user.auth_key, args = args[1], args[2], args[3:]
            if args[:1] == ["priv"] and len(args) >= 3:
                user.priv, user.priv_key, args = ("aes128" if args[1] == "aes" else args[1]), args[2], args[3:]
            self.device.snmp.users.append(user)
            return not args
        if w[1] == "group" and len(w) == 7 and w[3] == "user" and w[5:] == ["sec-model", "ver3"]:
            self._snmp_groups.append((w[4], w[2]))
            return True
        return False

    def _set(self, name: str, value: bool) -> bool:
        setattr(self.device.management, name, value)
        return True

    def server(self, node: Node) -> bool:
        """telnet-server, web-management plaintext|ssl (the no forms come through no_global)."""
        w = node.words
        if w == ["telnet-server"]:
            return self._set("telnet", True)
        if w in (["web-management", "plaintext"], ["web-management", "ssl"]):
            return self._set("http" if w[1] == "plaintext" else "https", True)
        return False

    def console(self, node: Node) -> bool:
        """console idle-timeout SECONDS (remote sessions too); kept in minutes."""
        w = node.words
        if w[1:2] == ["idle-timeout"] and len(w) == 3 and w[2].isdigit():
            self.device.management.exec_timeout = -(-int(w[2]) // 60)
            return True
        return False

    def snooping(self, node: Node) -> bool:
        """dhcp-snooping | arp-protect [vlan V V | trust PORTS]"""
        w = node.words
        dhcp = w[0] == "dhcp-snooping"
        if len(w) == 1:
            if dhcp:
                self.device.dhcp_snooping = True
            return True
        if w[1] == "vlan" and len(w) >= 3:
            for vid in [v for word in w[2:] for v in _vlan_ids(word)]:
                vlan = self.device.vlans.setdefault(vid, Vlan(vid))
                setattr(vlan, "dhcp_snooping" if dhcp else "arp_inspection", True)
            return True
        if w[1] == "trust" and len(w) == 3:
            for name in ports(w[2]):
                setattr(self.port(name), "dhcp_trust" if dhcp else "arp_trust", True)
            return True
        return False

    def port_security(self, node: Node) -> bool:
        """port-security PORTS learn-mode static [address-limit N] [action none|send-alarm|send-disable]"""
        w = node.words
        if len(w) < 4 or w[2:4] != ["learn-mode", "static"]:
            return False
        args = w[4:]
        limit: Optional[int] = None
        violation = "protect"  # action none: the AOS-S default drops without telling
        while args:
            if args[0] == "address-limit" and len(args) >= 2:
                limit = int(args[1])
            elif args[0] == "action" and len(args) >= 2 and args[1] in _AOSS_ACTIONS:
                violation = _AOSS_ACTIONS[args[1]]
            else:
                return False
            args = args[2:]
        for name in ports(w[1]):
            iface = self.port(name)
            iface.port_security, iface.port_security_max, iface.port_security_violation = True, limit, violation
        return True

    def lldp(self, node: Node) -> bool:
        """lldp run, lldp admin-status PORTS txonly|rxonly|disable."""
        w = node.words
        if w == ["lldp", "run"]:
            return self._set("lldp", True)
        if w[1:2] == ["admin-status"] and len(w) == 4 and w[3] in ("txonly", "rxonly", "disable", "tx_rx"):
            for name in ports(w[2]):
                iface = self.port(name)
                iface.lldp_tx = w[3] in ("txonly", "tx_rx")
                iface.lldp_rx = w[3] in ("rxonly", "tx_rx")
            return True
        return False

    def no_global(self, node: Node) -> bool:
        w = node.words[1:]
        if w in (["ip", "ssh"], ["telnet-server"], ["lldp", "run"], ["cdp", "run"]):
            return self._set({"ip": "ssh", "telnet-server": "telnet", "lldp": "lldp", "cdp": "cdp"}[w[0]], False)
        if w in (["web-management", "plaintext"], ["web-management", "ssl"]):
            return self._set("http" if w[1] == "plaintext" else "https", False)
        return False

    def logging(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["severity"] and len(w) == 3 and w[2] in mgmt_text.AOSS.values():
            self.device.system.logging_level = mgmt_text.level(w[2])
            return True
        if len(node.words) == 2 and _is_address(node.words[1]):
            self.device.system.syslog_servers.append(node.words[1])
            return True
        return False

    def ip(self, node: Node) -> bool:
        w = node.words
        if w[1] == "source-lockdown" and len(w) == 3:
            for name in ports(w[2]):
                self.port(name).source_guard = True
            return True
        if w[1:] == ["ssh"]:
            return self._set("ssh", True)
        if w[1] == "source-interface" and len(w) == 5 and w[2] in ("radius", "tacacs", "tftp", "syslog") \
                and w[3] in ("vlan", "loopback"):
            source = f"{'Vlan' if w[3] == 'vlan' else 'Loopback'}{w[4]}"
            if w[2] == "syslog":
                self.device.system.logging_source = source
            elif w[2] == "tftp":
                self.device.system.transfer_source["tftp"] = source
            else:
                self.device.aaa.source[w[2]] = source
            return True
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
        if w[1:2] == ["router-id"] and len(w) == 3:
            self.router_id = str(ipaddress.IPv4Address(w[2]))
            self.router_id_line = node
            return True
        if w[1:2] == ["default-gateway"] and len(w) == 3:
            self.default_gateway = StaticRoute("0.0.0.0/0", next_hop=w[2], origin=Origin(node.line, node.text))
            return True
        if w[1:2] == ["access-list"] and len(w) == 4 and w[2] in ("standard", "extended"):
            return self.acl(node, 4, w[2] == "standard", unquote(w[3]))
        if w[1:2] == ["route"] and len(w) >= 5:
            prefix = str(ipaddress.ip_network(f"{w[2]}/{w[3]}", strict=False))
            return self.route(node, prefix, w[4:])
        return False

    def ipv6(self, node: Node) -> bool:
        w = node.words
        if w[1:2] == ["access-list"] and len(w) == 3:
            return self.acl(node, 6, False, unquote(w[2]))
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

    def acl(self, node: Node, family: int, standard: bool, name: str) -> bool:
        acl = self.device.acls.setdefault(name, Acl(name, family=family))
        acl_text.read_block(acl, node.children, wildcards=True, standard=standard)
        return True

    def qos_class(self, node: Node) -> bool:
        """class ipv4 "NAME", entries '10 match ip any any ip-dscp 46' or ACL-like '20 match udp any any range 5000 5100'"""
        w = [unquote(word) for word in node.words]
        if len(w) != 3 or w[1] != "ipv4":
            return False
        qos_class = QosClass(w[2], origin=Origin(node.line, node.text))
        self.device.qos_classes[qos_class.name] = qos_class
        for child in qos_text.read_class(qos_class, node.children, "ip-dscp", True, self._class_acls):
            self.unparsed(child, node.text)
        return True

    def qos_policy(self, node: Node) -> bool:
        """policy qos "NAME", entries '10 class ipv4 "C" action dscp 46 action rate-limit kbps 2000' and
        'default-class action ...'"""
        w = [unquote(word) for word in node.words]
        if len(w) != 3 or w[1] != "qos":
            return False
        policy = QosPolicy(w[2], origin=Origin(node.line, node.text))
        self.device.qos_policies[policy.name] = policy
        for child in node.children:
            c = [unquote(word) for word in child.words]
            if c == ["exit"]:
                continue
            action: Optional[QosAction] = None
            if len(c) >= 4 and c[0].isdigit() and c[1:3] == ["class", "ipv4"]:
                action, args = QosAction(c[3]), c[4:]
            elif c[:1] == ["default-class"] or c[1:2] == ["default-class"]:
                args = c[c.index("default-class") + 1:]
                action = QosAction(qos_text.DEFAULT_CLASS)
            while action is not None and args:
                if args[:2] == ["action", "dscp"] and len(args) >= 3:
                    action.set_dscp, args = qos_text.dscp(args[2]), args[3:]
                elif args[:3] == ["action", "rate-limit", "kbps"] and len(args) >= 4:
                    action.police_kbps, args = int(args[3]), args[4:]
                else:
                    action = None
            if action is None:
                self.unparsed(child, node.text)
            else:
                policy.actions.append(action)
        return True

    def numbered_acl(self, node: Node) -> bool:
        w = node.words
        if len(w) < 3 or not w[1].isdigit():
            return False
        acl = self.device.acls.setdefault(w[1], Acl(w[1]))
        try:
            entry = acl_text.read_entry(w[2:], 4, wildcards=True, standard=int(w[1]) < 100)
        except (acl_text.Unsupported, ValueError, IndexError):
            entry = acl_text.unsupported_entry(node.text)
        entry.origin = Origin(node.line, node.text)
        acl.entries.append(entry)
        return True

    def _access_group(self, iface: Interface, w: List[str]) -> bool:
        """ip access-group "NAME" in|out, ipv6 access-group "NAME" in|out."""
        if len(w) != 4 or w[3] not in ("in", "out"):
            return False
        setattr(iface, f"acl{'6' if w[0] == 'ipv6' else ''}_{w[3]}", unquote(w[2]))
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
        elif w[1:2] == ["access-group"] and w[0] in ("ip", "ipv6"):
            return self._access_group(iface, w)
        elif w[0] == "service-policy" and len(w) == 3 and w[2] in ("in", "out"):
            setattr(iface, f"qos_policy_{w[2]}", unquote(w[1]))
        elif w[:2] == ["qos", "trust"] and len(w) == 3 and w[2] in ("dscp", "dot1p", "none"):
            iface.qos_trust = "cos" if w[2] == "dot1p" else w[2]
        elif w[0] == "broadcast-limit" and len(w) == 2:
            iface.storm_control["broadcast"] = float(w[1])
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
                elif c[1:2] == ["access-group"] and c[0] in ("ip", "ipv6") and c[-1] in ("in", "out"):
                    self._access_group(l3(), c)
                elif c[:2] == ["ip", "helper-address"] and len(c) == 3:
                    l3().helper_addresses.append(c[2])
                elif c[:2] == ["ip", "ospf"] and len(c) in (4, 5) and c[-2] == "area":
                    self.ospf_areas.append((l3().name, "", ospf_text.area(c[-1])))
                elif c == ["ip", "ospf", "passive"]:
                    self.ospf_passive[l3().name] = True
                elif c[:3] == ["ip", "ospf", "cost"] and len(c) == 4:
                    l3().ospf_cost = int(c[3])
                elif c[:2] == ["vrrp", "vrid"] and len(c) == 3:
                    self._vrrp(l3(), child)
                elif c in (["no", "ip", "address"], ["ipv6", "enable"]):
                    pass
                else:
                    self.unparsed(child, node.text)
            except (ValueError, IndexError):
                self.unparsed(child, node.text)
        return True

    def dhcp_server(self, node: Node) -> bool:
        """dhcp-server pool "NAME", and dhcp-server enable."""
        w = node.words
        if w[1:] == ["enable"]:
            return True
        if w[1:2] != ["pool"] or len(w) < 3:
            return False
        pool = DhcpPool(unquote(node.text.split(None, 2)[2]), origin=Origin(node.line, node.text))
        self.device.dhcp_pools.append(pool)
        for child in node.children:
            c = [unquote(word) for word in child.words]
            try:
                if c == ["exit"]:
                    continue
                if c[0] == "network" and len(c) == 3:
                    pool.network = str(ipaddress.ip_network(f"{c[1]}/{c[2]}"))
                elif c[0] == "range" and len(c) == 3:
                    pool.ranges.append((str(ipaddress.IPv4Address(c[1])), str(ipaddress.IPv4Address(c[2]))))
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
        return True

    def router(self, node: Node) -> bool:
        """router vrrp / ipv4 enable (implied by the groups); router ospf, the one OSPF process."""
        if node.words == ["router", "vrrp"]:
            return all(c.words in (["ipv4", "enable"], ["exit"]) for c in node.children)
        if node.words != ["router", "ospf"]:
            return False
        p = ospf_text.process(self.device, "1")
        p.origin = Origin(node.line, node.text)
        for child in node.children:
            w = child.words
            n = len(w)
            try:
                if w in (["enable"], ["exit"]):
                    continue
                if w[0] == "area" and n == 2:
                    ospf_text.area(w[1])
                elif w[0] == "area" and n in (4, 5) and w[2] == "stub" and w[4:] in ([], ["no-summary"]):
                    p.area_types[ospf_text.area(w[1])] = "stub" + (" no-summary" if n == 5 else "")
                elif w[0] == "redistribute" and n == 2 and w[1] in ("connected", "static"):
                    p.redistribute.append(w[1])
                else:
                    self.unparsed(child, node.text)
            except ValueError:
                self.unparsed(child, node.text)
        return True

    def _vrrp(self, svi: Interface, node: Node) -> None:
        """vrrp vrid N inside a VLAN; the group stays off until 'enable'."""
        group = FhrpGroup("vrrp", int(node.words[2]), shutdown=True, origin=Origin(node.line, node.text))
        svi.fhrp.append(group)
        for child in node.children:
            w = child.words
            n = len(w)
            try:
                if w in (["exit"], ["owner"], ["backup"]):
                    pass  # the owner is the router whose own address is the virtual one
                elif w[0] == "virtual-ip-address" and n in (2, 3):
                    address = str(ipaddress.IPv4Address(w[1]))
                    if group.address:
                        group.secondary.append(address)
                    else:
                        group.address = address
                elif w[0] == "priority" and n == 2:
                    group.priority = int(w[1])
                elif w == ["preempt-mode"]:
                    group.preempt = True
                elif w == ["no", "preempt-mode"]:
                    group.preempt = False
                elif w[0] == "advertise-interval" and n == 2:
                    group.hello_ms = int(w[1]) * 1000
                elif w == ["enable"]:
                    group.shutdown = False
                else:
                    self.unparsed(child, node.text)
            except ValueError:
                self.unparsed(child, node.text)

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
        stp = self.device.stp
        # priorities are multipliers: of 4096 for the bridge, of 16 for a port
        if w[1] == "priority" and len(w) == 3:
            stp.priority[0] = int(w[2]) * 4096
            return True
        if w[1] in ("instance", "vlan") and len(w) == 5 and w[3] == "priority":
            if w[1] == "instance":
                stp.priority[int(w[2])] = int(w[4]) * 4096
            else:
                for vlan in _vlan_ids(w[2]):
                    stp.vlan_priority[vlan] = int(w[4]) * 4096
            return True
        if w[1] == "instance" and len(w) >= 5 and w[3] == "vlan":
            stp.instances.setdefault(int(w[2]), []).extend(_vlan_ids(",".join(w[4:])))
            return True
        if w[1] == "config-name" and len(w) == 3:
            stp.region = unquote(w[2])
            return True
        if w[1] == "config-revision" and len(w) == 3:
            stp.revision = int(w[2])
            return True
        if len(w) == 3 and w[2] in ("root-guard", "bpdu-filter"):
            for name in ports(w[1]):
                if w[2] == "root-guard":
                    self.port(name).stp_guard = "root"
                else:
                    self.port(name).stp_bpdufilter = True
            return True
        if len(w) == 4 and w[2] in ("path-cost", "priority"):
            for name in ports(w[1]):
                if w[2] == "path-cost":
                    self.port(name).stp_cost = int(w[3])
                else:
                    self.port(name).stp_port_priority = int(w[3]) * 16
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
        qos_text.adopt(self.device, self._class_acls)
        for iface in self.device.interfaces.values():
            if iface.dot1x or iface.mab:
                # an authenticator without a client limit opens the port for all once one client logs in; MAC
                # authentication takes one address unless told otherwise
                limit = self._client_limit.get((iface.name, "authenticator" if iface.dot1x else "mac-based"),
                                               None if iface.dot1x else 1)
                iface.dot1x_host_mode = "multi-host" if limit is None else "single-host" if limit == 1 else "multi-auth"
        for server in self.device.aaa.servers:
            server.key = server.key or self._aaa_keys.get(server.protocol, "")
        snmp = self.device.snmp
        for name, group in self._snmp_groups:
            level = "priv" if group.endswith("priv") else "noauth" if group.endswith("noauth") else "auth"
            snmp.groups.setdefault(group, SnmpGroup(group, level))
            for user in snmp.users:
                if user.name == name:
                    user.group = group
        ospf_text.attach(self.device, self.ospf_areas, self.ospf_passive)
        if self.router_id and self.device.ospf:
            self.device.ospf[0].router_id = self.router_id
        elif self.router_id_line is not None:
            self.unparsed(self.router_id_line)  # only routing protocols use it
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
