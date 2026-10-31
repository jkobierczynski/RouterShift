# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Reader for Juniper Junos (EX and QFX switches with the Enhanced Layer 2 Software, MX and SRX routing).

Both forms of a configuration are read: the curly-brace hierarchy of 'show configuration' and the 'set' lines of
'show configuration | display set'. Each leaf becomes a word list as its set command names it, and the reader
works on those. Interface names become the canonical ones: ge-0/0/1 is Ethernet0/0/1, aeN is Port-channel(N+1),
irb.N is the VLAN interface of the VLAN whose l3-interface it is, lo0.N is LoopbackN, me0/em0/fxp0 is
Management0. A unit other than 0 (or any unit of a port with vlan-tagging) is a subinterface.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from .. import aaa as aaa_text
from .. import bgp as bgp_text
from .. import ospf as ospf_text
from .. import vrfs as vrfs_text
from .. import vxlan as vxlan_text
from ..junostext import Statement, read
from ..model import (BgpNeighbor, Device, Interface, InterfaceKind, LacpMode, LocalUser, NtpKey, SnmpCommunity,
                     StaticRoute, StpMode, SwitchportMode, Unparsed, Vlan)

_MEDIA = {"ge": "1g", "xe": "10g", "et": "100g", "mge": "2.5g", "fe": "100m"}
_PHYSICAL = re.compile(r"^(ge|xe|et|mge|fe)-(\d+/\d+/\d+(?::\d+)?)$")
_LAG = re.compile(r"^ae(\d+)$")
_MANAGEMENT = ("me0", "em0", "fxp0")
LEVELS = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "any"]
CLASSES = {"super-user": 15, "operator": 5, "read-only": 1, "unauthorized": 0}
_STP = {"rstp": StpMode.RSTP, "stp": StpMode.STP, "mstp": StpMode.MSTP, "vstp": StpMode.RAPID_PVST}


def physical_name(ifd: str) -> Optional[Tuple[str, InterfaceKind, str]]:
    """Canonical name, kind and media of a Junos port or aggregate (no unit); None for anything else."""
    m = _PHYSICAL.match(ifd)
    if m:
        return f"Ethernet{m.group(2)}", InterfaceKind.ETHERNET, _MEDIA[m.group(1)]
    m = _LAG.match(ifd)
    if m:
        return f"Port-channel{int(m.group(1)) + 1}", InterfaceKind.LAG, ""
    return None


def bandwidth(word: str) -> Optional[int]:
    """Mbit/s of a Junos bandwidth: 100g, 10000m, 1000000000."""
    m = re.match(r"^(\d+)([kmg]?)$", word.lower())
    if not m:
        return None
    bps = int(m.group(1)) * {"": 1, "k": 10 ** 3, "m": 10 ** 6, "g": 10 ** 9}[m.group(2)]
    return bps // 10 ** 6


def priority(word: str) -> Optional[int]:
    """A bridge priority: 4096, or 4k."""
    m = re.match(r"^(\d+)(k?)$", word.lower())
    return int(m.group(1)) * (1024 if m.group(2) else 1) if m else None


def target(word: str) -> str:
    return word[len("target:"):] if word.startswith("target:") else ""


class Reader:
    def __init__(self, text: str) -> None:
        self.statements = read(text)
        self.device = Device(platform="junos")
        self.vlan_names: Dict[str, int] = {}
        self.l3_units: Dict[str, str] = {}  # "irb.10" -> the VLAN whose layer 3 interface it is
        self.units: Dict[str, str] = {}  # unit name ("ge-0/0/1.0", "irb.10") -> canonical interface
        self.ifds: Dict[str, str] = {}  # port or aggregate ("ge-0/0/1", "ae0") -> canonical interface
        self.tagged: Set[str] = set()  # ports with vlan-tagging: every unit is a subinterface
        self.members: Dict[str, List[str]] = {}  # canonical interface -> VLAN members as written
        self.member_lines: Dict[str, Statement] = {}
        self.lacp: Dict[str, LacpMode] = {}  # aggregate -> mode
        self.router_ids: Dict[str, str] = {}  # routing instance ("" = the main one) -> router ID
        self.ospf_numbers: Dict[str, str] = {}
        self.local_as = ""
        self.bgp_groups: Dict[str, BgpNeighbor] = {}
        self.bgp_neighbors: Dict[str, BgpNeighbor] = {}
        self.bgp_types: Dict[str, str] = {}  # group -> internal / external
        self.bgp_families: Dict[str, List[str]] = {}  # group or neighbor -> families stated
        self.bgp_line = 0
        self.irb_vlans: Dict[str, int] = {}
        self.edge_bpdu_block = False

    # -------------------------------------------------------------------------------------------------------------

    def parse(self) -> Device:
        active = []
        for s in self.statements:
            if s.inactive:
                self.unparsed(s, "inactive in the source")
            elif s.words and s.words[0] != "version":
                active.append(s)
        for s in active:
            if s.words[0] == "interfaces" and len(s.words) >= 3 and s.words[2] in ("vlan-tagging",
                                                                                    "flexible-vlan-tagging"):
                self.tagged.add(s.words[1])
        # VLANs first (interfaces name them), then interfaces (everything else names those)
        rest = []
        for s in active:
            if s.words[0] == "vlans":
                self.handle(s, self.vlan)
            else:
                rest.append(s)
        self.irb_vlans = {unit: self.vlan_names[name] for unit, name in self.l3_units.items()
                          if name in self.vlan_names}
        later = []
        for s in rest:
            if s.words[0] == "interfaces":
                self.handle(s, self.interface)
            else:
                later.append(s)
        handlers: Dict[str, Callable[[Statement], bool]] = {
            "system": self.system, "routing-options": lambda s: self.routing_options(s, s.words[1:], ""),
            "routing-instances": self.routing_instance, "protocols": lambda s: self.protocols(s, s.words[1:], ""),
            "snmp": self.snmp, "chassis": self.chassis,
        }
        # routing instances first: their interfaces belong to them before OSPF reads them
        later.sort(key=lambda s: s.words[0] != "routing-instances" or "protocols" in s.words[:3])
        for s in later:
            self.handle(s, handlers.get(s.words[0], lambda _: False))
        self.finish()
        return self.device

    def handle(self, s: Statement, handler: Callable[[Statement], bool]) -> None:
        try:
            done = handler(s)
        except (ValueError, IndexError, KeyError):
            done = False
        if not done:
            self.unparsed(s)

    def unparsed(self, s: Statement, section: str = "") -> None:
        self.device.unparsed.append(Unparsed(s.line, s.text, section))

    # VLANs -------------------------------------------------------------------------------------------------------

    def vlan(self, s: Statement) -> bool:
        w = s.words
        if len(w) < 3:
            return False
        name, rest = w[1], w[2:]
        if rest[0] == "vlan-id" and len(rest) == 2:
            vid = int(rest[1])
            self.vlan_names[name] = vid
            self.device.vlans.setdefault(vid, Vlan(vid, name=name))
            return True
        if rest[0] == "l3-interface" and len(rest) == 2:
            self.l3_units[rest[1]] = name
            return True
        return False

    def vlan_id(self, word: str) -> List[str]:
        """VLAN IDs and ranges of a members word: a name, a number or a range."""
        if word in self.vlan_names:
            return [str(self.vlan_names[word])]
        if re.match(r"^\d+(-\d+)?$", word):
            return [word]
        raise KeyError(word)

    # interfaces --------------------------------------------------------------------------------------------------

    def iface(self, name: str, kind: InterfaceKind, source: str, media: str = "") -> Interface:
        if name not in self.device.interfaces:
            self.device.interfaces[name] = Interface(name, kind, source_name=source, media=media)
        return self.device.interfaces[name]

    def port(self, ifd: str) -> Optional[Interface]:
        found = physical_name(ifd)
        if found is None:
            return None
        name, kind, media = found
        self.ifds[ifd] = name
        return self.iface(name, kind, ifd, media)

    def unit(self, ifd: str, unit: str) -> Optional[Interface]:
        """The interface a logical unit is in the model."""
        full = f"{ifd}.{unit}"
        if ifd in ("irb", "vlan"):
            vid = self.irb_vlans.get(f"irb.{unit}", self.irb_vlans.get(full, int(unit)))
            iface = self.iface(f"Vlan{vid}", InterfaceKind.VLAN, full)
        elif ifd == "lo0":
            iface = self.iface(f"Loopback{unit}", InterfaceKind.LOOPBACK, full)
        elif ifd in _MANAGEMENT and unit == "0":
            iface = self.iface("Management0", InterfaceKind.MANAGEMENT, full)
        else:
            parent = self.port(ifd)
            if parent is None:
                return None
            if unit == "0" and ifd not in self.tagged:
                iface = parent
            else:
                iface = self.iface(f"{parent.name}.{unit}", InterfaceKind.SUBINTERFACE, full, parent.media)
                iface.parent = parent.name
        self.units[full] = iface.name
        return iface

    def interface(self, s: Statement) -> bool:
        w = s.words
        if len(w) < 3:
            return False
        ifd, rest = w[1], w[2:]
        if rest[0] == "unit" and len(rest) >= 2:
            iface = self.unit(ifd, rest[1])
            return iface is not None and (len(rest) == 2 or self.unit_line(s, iface, rest[2:]))
        if ifd in _MANAGEMENT or ifd in ("irb", "lo0", "vlan"):
            return False
        port = self.port(ifd)
        if port is None:
            return False
        if rest[0] == "description" and len(rest) == 2:
            port.description = rest[1]
        elif rest == ["disable"]:
            port.shutdown = True
        elif rest[0] == "mtu" and len(rest) == 2:
            port.mtu = int(rest[1])
        elif rest[0] in ("vlan-tagging", "flexible-vlan-tagging") and len(rest) == 1:
            pass
        elif rest[0] == "native-vlan-id" and len(rest) == 2:
            port.native_vlan = int(rest[1])
        elif rest[0] in ("ether-options", "gigether-options") and rest[1:2] == ["802.3ad"] and len(rest) == 3:
            lag = physical_name(rest[2])
            if lag is None:
                return False
            port.lag = lag[0]
            self.iface(lag[0], InterfaceKind.LAG, rest[2])
            self.ifds[rest[2]] = lag[0]
        elif rest[:2] == ["aggregated-ether-options", "lacp"] and len(rest) == 3 and rest[2] in ("active", "passive"):
            self.lacp[port.name] = LacpMode(rest[2])
        else:
            return False
        return True

    def unit_line(self, s: Statement, iface: Interface, rest: List[str]) -> bool:
        if rest[0] == "description" and len(rest) == 2:
            iface.description = iface.description or rest[1]
        elif rest == ["disable"]:
            iface.shutdown = True
        elif rest[0] == "vlan-id" and len(rest) == 2 and iface.kind == InterfaceKind.SUBINTERFACE:
            iface.encapsulation_vlan = int(rest[1])
        elif rest[0] == "family" and len(rest) >= 2:
            return self.family(s, iface, rest[1], rest[2:])
        else:
            return False
        return True

    def family(self, s: Statement, iface: Interface, family: str, rest: List[str]) -> bool:
        if family in ("inet", "inet6"):
            addresses = iface.ipv4 if family == "inet" else iface.ipv6
            if not rest:
                return True
            if rest == ["dhcp"] and family == "inet":
                iface.dhcp_client = True
                return True
            if rest[0] == "address" and len(rest) >= 2:
                if rest[1] not in addresses:
                    addresses.append(rest[1])
                if rest[2:] == ["primary"]:
                    addresses.remove(rest[1])
                    addresses.insert(0, rest[1])
                    return True
                return len(rest) == 2
            return False
        if family == "ethernet-switching":
            if iface.mode == SwitchportMode.ROUTED:
                iface.mode = SwitchportMode.ACCESS
            if not rest:
                return True
            if rest[0] in ("interface-mode", "port-mode") and len(rest) == 2 and rest[1] in ("access", "trunk"):
                iface.mode = SwitchportMode(rest[1])
                return True
            if rest[:2] == ["vlan", "members"] and len(rest) == 3:
                self.members.setdefault(iface.name, []).append(rest[2])
                self.member_lines[iface.name] = s
                return True
            if rest[0] == "native-vlan-id" and len(rest) == 2:
                iface.native_vlan = int(rest[1])
                return True
        return False

    # system ------------------------------------------------------------------------------------------------------

    def system(self, s: Statement) -> bool:
        w = s.words[1:]
        sy = self.device.system
        if not w:
            return False
        if w[0] == "host-name" and len(w) == 2:
            sy.hostname = w[1]
        elif w[0] == "domain-name" and len(w) == 2:
            sy.domain_name = w[1]
        elif w[0] == "domain-search" and len(w) == 2:
            sy.dns_search.append(w[1])
        elif w[0] == "time-zone" and len(w) == 2:
            sy.timezone = w[1]
        elif w[0] == "name-server" and len(w) in (2, 4):
            if len(w) == 4:
                if w[2] != "routing-instance":
                    return False
                sy.service_vrf = w[3]
            sy.dns_servers.append(w[1])
        elif w[0] == "static-host-mapping" and len(w) == 4 and w[2] == "inet":
            sy.dns_hosts[w[1]] = w[3]
        elif w[0] == "login":
            return self.login(w[1:])
        elif w[0] == "ntp":
            return self.ntp(w[1:])
        elif w[0] == "syslog":
            return self.syslog(w[1:])
        elif w[0] == "services" and len(w) >= 2:
            m = self.device.management
            if w[1:] == ["ssh"]:
                m.ssh = True
            elif w[1:] == ["telnet"]:
                m.telnet = True
            elif w[1] == "web-management" and len(w) >= 3 and w[2] in ("http", "https"):
                if w[2] == "http" and len(w) == 3:
                    m.http = True
                elif w[2] == "https" and w[3:] in ([], ["system-generated-certificate"]):
                    m.https = True
                else:
                    return False
            else:
                return False
        elif w == ["management-instance"]:
            pass
        else:
            return False
        return True

    def login(self, w: List[str]) -> bool:
        if w[0] == "message" and len(w) == 2:
            self.device.system.banner_motd = w[1].replace("\\n", "\n")
            return True
        if w[0] != "user" or len(w) < 3:
            return False
        user = next((u for u in self.device.users if u.name == w[1]), None)
        if user is None:
            user = LocalUser(w[1])
            self.device.users.append(user)
        rest = w[2:]
        if rest[0] == "uid" and len(rest) == 2:
            return True  # the local numbering of accounts
        if rest[0] == "class" and len(rest) == 2 and rest[1] in CLASSES:
            user.privilege = CLASSES[rest[1]]
            return True
        if rest[:2] == ["authentication", "encrypted-password"] and len(rest) == 3:
            user.password_hash = rest[2]
            user.hash_type = aaa_text.hash_type(rest[2]) or "junos"
            return True
        return False

    def ntp(self, w: List[str]) -> bool:
        sy = self.device.system
        if w[0] == "server" and len(w) >= 2:
            address, rest = w[1], w[2:]
            while rest:
                if rest[0] == "prefer":
                    sy.ntp_prefer = address
                    rest = rest[1:]
                elif rest[0] == "key" and len(rest) >= 2:
                    sy.ntp_server_keys[address] = int(rest[1])
                    rest = rest[2:]
                elif rest[0] == "routing-instance" and len(rest) >= 2:
                    sy.service_vrf = rest[1]
                    rest = rest[2:]
                else:
                    return False
            if address not in sy.ntp_servers:
                sy.ntp_servers.append(address)
            return True
        if w[0] == "authentication-key" and len(w) >= 4:
            number = int(w[1])
            key = sy.ntp_keys.setdefault(number, NtpKey(number))
            rest = w[2:]
            while rest:
                if rest[0] == "type" and len(rest) >= 2:
                    key.algorithm = {"sha1": "sha1", "sha256": "sha256"}.get(rest[1], "md5")
                elif rest[0] == "value" and len(rest) >= 2:
                    key.key = ""  # held as a $9$ secret
                else:
                    return False
                rest = rest[2:]
            return True
        if w[0] == "trusted-key" and len(w) == 2:
            number = int(w[1])
            sy.ntp_keys.setdefault(number, NtpKey(number)).trusted = True
            sy.ntp_authenticate = True
            return True
        if w[0] == "source-address" and len(w) == 2:
            sy.ntp_source = vxlan_text.interface_of(self.device, w[1])
            return bool(sy.ntp_source)
        return False

    def syslog(self, w: List[str]) -> bool:
        sy = self.device.system
        if w[0] == "host" and len(w) >= 3:
            if w[1] not in sy.syslog_servers:
                sy.syslog_servers.append(w[1])
            if w[2] == "routing-instance" and len(w) == 4:
                sy.service_vrf = w[3]
                return True
            if w[2] == "any" and len(w) == 4 and w[3] in LEVELS:
                sy.logging_level = LEVELS.index(w[3])
                return True
            return False
        if w[0] == "source-address" and len(w) == 2:
            sy.logging_source = vxlan_text.interface_of(self.device, w[1])
            return bool(sy.logging_source)
        return False

    # SNMP and chassis --------------------------------------------------------------------------------------------

    def snmp(self, s: Statement) -> bool:
        w = s.words[1:]
        sn = self.device.snmp
        if w[0] == "location" and len(w) == 2:
            sn.location = w[1]
        elif w[0] == "contact" and len(w) == 2:
            sn.contact = w[1]
        elif w[0] == "community" and len(w) == 4 and w[2] == "authorization":
            access = {"read-only": "ro", "read-write": "rw"}.get(w[3])
            if access is None:
                return False
            sn.communities.append(SnmpCommunity(w[1], access))
        else:
            return False
        return True

    def chassis(self, s: Statement) -> bool:
        # the number of aggregates the chassis allows: written again from the aggregates there are
        return s.words[1:4] == ["aggregated-devices", "ethernet", "device-count"] and len(s.words) == 5

    # routing -----------------------------------------------------------------------------------------------------

    def routing_options(self, s: Statement, w: List[str], vrf: str) -> bool:
        if w[0] == "router-id" and len(w) == 2:
            self.router_ids[vrf] = w[1]
            return True
        if w[0] == "autonomous-system" and len(w) == 2 and not vrf:
            self.local_as = w[1]
            self.bgp_line = self.bgp_line or s.line
            return True
        if w[:2] == ["static", "route"] and len(w) >= 4:
            prefix, rest = w[2], w[3:]
            routes = [r for r in self.device.static_routes if r.prefix == prefix and r.vrf == vrf]
            if rest[0] == "next-hop" and len(rest) == 2:
                if re.match(r"^[\d.]+$|:", rest[1]):
                    route = StaticRoute(prefix, next_hop=rest[1], vrf=vrf)
                else:
                    name = self.units.get(rest[1]) or self.units.get(f"{rest[1]}.0")
                    if name is None:
                        return False
                    route = StaticRoute(prefix, interface=name, vrf=vrf)
                blank = next((r for r in routes if not r.next_hop and not r.interface and not r.discard), None)
                if blank is not None:  # made by a preference read first
                    blank.next_hop, blank.interface = route.next_hop, route.interface
                else:
                    route.distance = routes[0].distance if routes else None
                    self.device.static_routes.append(route)
                return True
            if rest[0] in ("discard", "reject") and len(rest) == 1:
                self.device.static_routes.append(StaticRoute(prefix, discard=True, vrf=vrf))
                return True
            if rest[0] == "preference" and len(rest) == 2:
                if not routes:
                    routes = [StaticRoute(prefix, vrf=vrf)]
                    self.device.static_routes += routes
                for r in routes:
                    r.distance = int(rest[1])
                return True
        return False

    def routing_instance(self, s: Statement) -> bool:
        w = s.words
        if len(w) < 4:
            return False
        vrf, rest = w[1], w[2:]
        if rest[0] == "instance-type" and len(rest) == 2 and rest[1] in ("vrf", "virtual-router"):
            if vrf not in self.device.vrfs:
                self.device.vrfs.append(vrf)
            return True
        if rest[0] == "interface" and len(rest) == 2:
            name = self.units.get(rest[1])
            if name is None:
                return False
            self.device.interfaces[name].vrf = vrf
            return True
        if rest[0] == "route-distinguisher" and len(rest) == 2:
            vrfs_text.info(self.device, vrf).rd = rest[1]
            return True
        if rest[0] == "vrf-target":
            if len(rest) == 2 and target(rest[1]):
                return vrfs_text.route_target(vrfs_text.info(self.device, vrf), "both", target(rest[1]))
            if len(rest) == 3 and target(rest[2]):
                return vrfs_text.route_target(vrfs_text.info(self.device, vrf), rest[1], target(rest[2]))
            return False
        if rest[0] == "routing-options":
            return self.routing_options(s, rest[1:], vrf)
        if rest[0] == "protocols" and len(rest) >= 2 and rest[1] == "ospf":
            return self.protocols(s, rest[1:], vrf)
        return False

    def protocols(self, s: Statement, w: List[str], vrf: str) -> bool:
        if w[0] == "ospf" and len(w) >= 2:
            return self.ospf(w[1:], vrf)
        if w[0] == "bgp" and len(w) >= 2 and not vrf:
            self.bgp_line = self.bgp_line or s.line
            return self.bgp(w[1:])
        if w[0] == "lldp":
            m = self.device.management
            if w[1:] in ([], ["interface", "all"]):
                m.lldp = True
                return True
            if w[1:] == ["disable"]:
                m.lldp = False
                return True
            if len(w) == 4 and w[1] == "interface" and w[3] == "disable":
                iface = self.stp_port(w[2])
                if iface is None:
                    return False
                iface.lldp_tx = iface.lldp_rx = False
                return True
            return False
        if w[0] in _STP:
            return self.stp(w[0], w[1:])
        if w[:3] == ["layer2-control", "bpdu-block", "interface"] and len(w) == 4:
            iface = self.stp_port(w[3])
            if iface is None:
                return False
            iface.stp_bpduguard = True
            return True
        return False

    def stp_port(self, name: str) -> Optional[Interface]:
        canonical = self.ifds.get(name) or self.units.get(name) or self.units.get(f"{name}.0")
        return self.device.interfaces.get(canonical) if canonical else None

    def stp(self, protocol: str, w: List[str]) -> bool:
        dev = self.device
        dev.stp_mode = _STP[protocol]
        if not w:
            return True
        if w[0] == "bridge-priority" and len(w) == 2 and protocol != "vstp":
            dev.stp.priority[0] = priority(w[1]) or 0
            return True
        if w == ["bpdu-block-on-edge"]:
            self.edge_bpdu_block = True
            return True
        if w[0] == "interface" and len(w) >= 3:
            iface = self.stp_port(w[1])
            if iface is None:
                return False
            rest = w[2:]
            if rest == ["edge"]:
                iface.stp_portfast = True
            elif rest == ["no-root-port"]:
                iface.stp_guard = "root"
            elif rest[0] == "cost" and len(rest) == 2:
                iface.stp_cost = int(rest[1])
            elif rest[0] == "priority" and len(rest) == 2:
                iface.stp_port_priority = int(rest[1])
            else:
                return False
            return True
        if protocol == "mstp":
            if w[0] == "configuration-name" and len(w) == 2:
                dev.stp.region = w[1]
                return True
            if w[0] == "revision-level" and len(w) == 2:
                dev.stp.revision = int(w[1])
                return True
            if w[0] == "msti" and len(w) == 4 and w[2] == "vlan":
                vlans = dev.stp.instances.setdefault(int(w[1]), [])
                for part in self.vlan_id(w[3]):
                    low, _, high = part.partition("-")
                    vlans += range(int(low), int(high or low) + 1)
                return True
            if w[0] == "msti" and len(w) == 4 and w[2] == "bridge-priority":
                dev.stp.priority[int(w[1])] = priority(w[3]) or 0
                return True
        if protocol == "vstp" and w[0] == "vlan" and len(w) >= 2:
            if len(w) == 2:
                return True
            if w[2] == "bridge-priority" and len(w) == 4:
                for part in self.vlan_id(w[1]):
                    low, _, high = part.partition("-")
                    for vid in range(int(low), int(high or low) + 1):
                        dev.stp.vlan_priority[vid] = priority(w[3]) or 0
                return True
        return False

    def ospf(self, w: List[str], vrf: str) -> bool:
        if vrf not in self.ospf_numbers:  # the main instance's process is 1, the VRFs' 2, 3, ...
            self.ospf_numbers[vrf] = str(2 + sum(1 for v in self.ospf_numbers if v)) if vrf else "1"
        p = ospf_text.process(self.device, self.ospf_numbers[vrf], vrf)
        if w[0] == "reference-bandwidth" and len(w) == 2:
            p.reference_bandwidth = bandwidth(w[1])
            return p.reference_bandwidth is not None
        if w[0] != "area" or len(w) < 3:
            return False
        area = ospf_text.area(w[1])
        rest = w[2:]
        if rest[0] in ("stub", "nssa"):
            if rest[1:] in ([], ["no-summaries"]):
                p.area_types[area] = rest[0] + (" no-summary" if rest[1:] else "")
                return True
            return False
        if rest[0] == "interface" and len(rest) >= 2:
            name = self.units.get(rest[1]) or self.units.get(f"{rest[1]}.0")
            if name is None:
                return False
            iface = self.device.interfaces[name]
            p.interface_areas[name] = area
            more = rest[2:]
            if not more:
                return True
            if more == ["passive"]:
                if name not in p.passive_interfaces:
                    p.passive_interfaces.append(name)
            elif more[0] == "metric" and len(more) == 2:
                iface.ospf_cost = int(more[1])
            elif more == ["interface-type", "p2p"]:
                iface.ospf_network = "point-to-point"
            else:
                return False
            return True
        return False

    def bgp(self, w: List[str]) -> bool:
        if w[0] != "group" or len(w) < 3:
            return False
        group = self.bgp_groups.setdefault(w[1], BgpNeighbor(w[1]))
        rest = w[2:]
        if rest[0] == "type" and len(rest) == 2 and rest[1] in ("internal", "external"):
            self.bgp_types[w[1]] = rest[1]
            return True
        if rest[0] == "neighbor" and len(rest) >= 2:
            neighbor = self.bgp_neighbors.setdefault(rest[1], BgpNeighbor(rest[1], peer_group=w[1]))
            return len(rest) == 2 or self.bgp_setting(neighbor, rest[2:])
        return self.bgp_setting(group, rest)

    def bgp_setting(self, peer: BgpNeighbor, w: List[str]) -> bool:
        if w[0] == "peer-as" and len(w) == 2:
            peer.remote_as = w[1]
        elif w[0] == "description" and len(w) == 2:
            peer.description = w[1]
        elif w[0] == "local-address" and len(w) == 2:
            peer.update_source = vxlan_text.interface_of(self.device, w[1])
            return bool(peer.update_source)
        elif w[0] == "multihop":
            if w[1:] == []:
                peer.ebgp_multihop = 64
            elif w[1:2] == ["ttl"] and len(w) == 3:
                peer.ebgp_multihop = int(w[2])
            else:
                return False
        elif w[0] == "bfd-liveness-detection" and len(w) >= 2:
            peer.bfd = True
        elif w[0] == "family" and len(w) >= 2:
            family = {("inet", "unicast"): "ipv4", ("inet6", "unicast"): "ipv6",
                      ("evpn", "signaling"): "evpn"}.get((w[1], w[2] if len(w) > 2 else ""))
            if family is None or len(w) != 3:
                return False
            self.bgp_families.setdefault(peer.address, []).append(family)
        else:
            return False
        return True

    # the end -----------------------------------------------------------------------------------------------------

    def finish(self) -> None:
        dev = self.device
        for name, words in self.members.items():
            iface = dev.interfaces[name]
            try:
                ids = [i for word in words if word != "all" for i in self.vlan_id(word)]
            except KeyError:
                self.unparsed(self.member_lines[name], "a VLAN member that no vlans entry names")
                continue
            if iface.mode == SwitchportMode.ACCESS:
                iface.access_vlan = int(ids[0]) if ids and ids[0].isdigit() else None
            else:
                iface.allowed_vlans = "" if "all" in words else ",".join(ids)
        for iface in dev.interfaces.values():
            if iface.lag:
                iface.lacp_mode = self.lacp.get(iface.lag, LacpMode.STATIC)
            elif iface.kind == InterfaceKind.LAG:
                iface.lacp_mode = self.lacp.get(iface.name, LacpMode.STATIC)
            if self.edge_bpdu_block and iface.stp_portfast:
                iface.stp_bpduguard = True
        for p in dev.ospf:
            p.router_id = self.router_ids.get(p.vrf, "")
        if self.local_as:
            self.finish_bgp()

    def finish_bgp(self) -> None:
        builder = bgp_text.Builder(self.local_as)
        bgp = builder.bgp
        bgp.router_id = self.router_ids.get("", "")
        bgp.origin.line = self.bgp_line
        for name, group in self.bgp_groups.items():
            if self.bgp_types.get(name) == "internal" and not group.remote_as:
                group.remote_as = self.local_as
            group.send_community = True  # Junos sends communities unless an export policy strips them
            group.families = sorted(set(self.bgp_families.get(name, [])))
            bgp.peer_groups[name] = group
        for address, neighbor in self.bgp_neighbors.items():
            neighbor.send_community = neighbor.peer_group not in bgp.peer_groups
            stated = self.bgp_families.get(address) or self.bgp_families.get(neighbor.peer_group)
            neighbor.families = sorted(set(stated or [bgp_text.family(address)]))
            bgp.neighbors.append(neighbor)
        self.device.bgp = bgp


def parse(text: str) -> Device:
    return Reader(text).parse()
