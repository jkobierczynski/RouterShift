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
from .. import dhcp as dhcp_text
from .. import evpn as evpn_text
from .. import fhrp as fhrp_text
from .. import junospolicy
from .. import junosqos
from .. import junossec
from .. import junosmon
from .. import junosmgmt
from .. import monitor as monitor_text
from .. import qos as qos_text
from .. import security as security_text
from .. import multicast as multicast_text
from .. import ospf as ospf_text
from .. import vrfs as vrfs_text
from .. import vxlan as vxlan_text
from ..junostext import Statement, read
from ..model import (Acl, AaaMethod, AaaServer, Bgp, BgpAggregate, BgpNeighbor, BgpVrf, Device, DhcpPool, EvpnInstance,
                     FhrpGroup, Interface, InterfaceKind, LacpMode, LocalUser, Mlag, NtpKey, SnmpCommunity, StaticRoute,
                     QosClass, StpMode, SwitchportMode, Track, Unparsed, Vlan, Vxlan)

_MEDIA = {"ge": "1g", "xe": "10g", "et": "100g", "mge": "2.5g", "fe": "100m"}
_PHYSICAL = re.compile(r"^(ge|xe|et|mge|fe)-(\d+/\d+/\d+(?::\d+)?)$")
_LAG = re.compile(r"^ae(\d+)$")
_MANAGEMENT = ("me0", "em0", "fxp0")
LEVELS = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "any"]
CLASSES = {"super-user": 15, "operator": 5, "read-only": 1, "unauthorized": 0}
MGMT_INSTANCE = "mgmt_junos"
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
        self.bgp_groups: Dict[str, Dict[str, BgpNeighbor]] = {}  # routing instance -> groups
        self.bgp_neighbors: Dict[str, Dict[str, BgpNeighbor]] = {}
        self.bgp_types: Dict[Tuple[str, str], str] = {}  # (instance, group) -> internal / external
        self.bgp_families: Dict[Tuple[str, str], List[str]] = {}  # (instance, group or neighbor) -> families
        self.bgp_line = 0
        self.irb_vlans: Dict[str, int] = {}
        self.edge_bpdu_block = False
        self.policy = junospolicy.Reader(self.device)
        self.bgp_policies: Dict[Tuple[str, str, str], List[str]] = {}  # (instance, peer, import|export) -> policies
        self.bgp_export: Dict[str, List[str]] = {}  # routing instance -> export policies
        self.bgp_multipath: Dict[str, bool] = {}  # routing instance -> multiple-as
        self.bgp_hold: Optional[int] = None
        self.bgp_preference: Dict[Tuple[str, str], int] = {}
        self.graceful_restart = False
        self.restart_duration: Optional[int] = None
        self.asdot = False
        self.aggregate_routes: Dict[Tuple[str, str], bool] = {}  # (instance, prefix) -> as-set
        self.instance_imports: Dict[str, List[str]] = {}
        self.vrf_policies: Dict[str, List[Tuple[str, str, Statement]]] = {}
        self.vni_targets: Dict[int, Dict[str, str]] = {}  # VNI -> both|import|export -> target
        self.switch_target = ""
        self.cos = junosqos.CosReader(self.device)
        self.filter_lists: Dict[Tuple[str, str], List[str]] = {}  # (interface, input|output) -> filters
        self.macsec_ports: Dict[str, str] = {}  # port -> connectivity association
        self.mon = junosmon.MonitorReader(self.device)
        self.lldp_timers: Dict[str, int] = {}
        self.mgmt = junosmgmt.MgmtReader(self.device)
        self.login_filter: Optional[Tuple[str, Optional[Interface]]] = None
        self.lldp_address = ""
        self.rp_ranges: Dict[Tuple[str, str], List[str]] = {}  # (VRF, RP) -> group ranges
        self.local_rp = ""
        self.local_rp_ranges: List[str] = []
        self.anycast_set: List[str] = []
        self.msdp_sources: Dict[str, str] = {}  # MSDP peer -> local-address  # switch-options vrf-target: the target of VNIs without their own
        self.vlan_vxlan: Dict[str, Dict[str, str]] = {}  # VLAN name -> vni / multicast-group / ingress
        self.esi: Dict[str, Dict[str, str]] = {}  # aggregate -> esi settings
        self.mc_ae: Dict[str, Dict[str, str]] = {}  # aggregate -> mc-ae settings
        self.iccp: Dict[str, str] = {}
        self.protection: Dict[str, str] = {}  # peer -> interface
        self.evpn_vnis: List[str] = []
        self.host_flap: Dict[str, int] = {}
        self.ospf_exports: Dict[str, List[str]] = {}  # routing instance -> export policies of its OSPF
        self.generated: List[Statement] = []  # generate route 0.0.0.0/0 discard (for default-information always)
        self.load_balance: List[str] = []
        self.unit_macs: Dict[str, str] = {}  # canonical interface -> the MAC of its unit
        self.anycast_marked: Set[str] = set()  # units whose addresses are virtual-gateway-address anycast gateways
        self.virtual_mac = ""
        self.unnumbered: Dict[str, str] = {}  # canonical interface -> unit it borrows from
        self.storm_profiles: Dict[str, Dict[str, object]] = {}
        self.storm_ports: Dict[str, str] = {}  # canonical interface -> profile
        self.voip: Dict[str, str] = {}  # unit -> VLAN word
        self.mac_limits: Dict[str, Tuple[int, str]] = {}  # unit -> (limit, action)
        self.snooping: Dict[str, Dict[str, object]] = {}  # VLAN name -> dhcp-security settings
        self.trust_groups: Dict[Tuple[str, str], List[str]] = {}  # (VLAN, group) -> units
        self.trust_kind: Dict[Tuple[str, str], str] = {}  # (VLAN, group) -> trusted / untrusted
        self.relay_servers: Dict[Tuple[str, str], List[str]] = {}  # (instance, server group) -> addresses
        self.relay_active: Dict[Tuple[str, str], str] = {}  # (instance, group) -> server group
        self.relay_units: Dict[Tuple[str, str], List[str]] = {}
        self.relay_source: Dict[Tuple[str, str], str] = {}
        self.dot1x_ports: Dict[str, Dict[str, str]] = {}  # unit -> settings
        self.aaa_line = 0
        self.vrrp_tracks: List[Tuple[FhrpGroup, str, int]] = []
        self.management_instance = False
        self.vrrp_v3 = False
        self.accounting: List[str] = []
        self.accounting_to = ""
        self.aaa_sources: Dict[str, str] = {}
        self.pool_ranges: Dict[Tuple[str, str], Dict[str, Dict[str, str]]] = {}

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
            "policy-options": lambda s: self.policy.policy_options(s.line, s.words[1:]),
            "firewall": self.firewall,
            "class-of-service": lambda s: self.cos.statement(s.words[1:]),
            "services": self.services,
            "security": lambda s: s.words[1:2] == ["macsec"] and len(s.words) > 3 and
            junossec.read_macsec(self.device, s.words[2:], self.macsec_ports),
            "forwarding-options": lambda s: self.forwarding_options(s, s.words[1:], ""),
            "switch-options": self.switch_options, "poe": self.poe_line, "multi-chassis": self.multi_chassis, "access": lambda s: self.access(s.words[1:], ""),
        }
        # routing instances first: their interfaces belong to them before OSPF reads them
        later.sort(key=lambda s: s.words[0] != "routing-instances" or "protocols" in s.words[:3])
        for s in later:
            self.handle(s, handlers.get(s.words[0], lambda _: False))
        self.finish()
        return self.device

    def services(self, s: Statement) -> bool:
        w = s.words[1:]
        if w[0] == "rpm" and len(w) >= 3:
            return self.mon.rpm(w[1:])
        # the template inline J-Flow exports with: J-Flow's own IPv4 template
        return w[:1] == ["flow-monitoring"] and len(w) == 5 and w[1] in ("version9", "version-ipfix") and \
            w[2] == "template" and w[4] == "ipv4-template"

    def firewall(self, s: Statement) -> bool:
        if s.words[1:2] == ["policer"] and len(s.words) >= 4:
            return self.cos.policer(s.words[2:])
        return self.policy.firewall(s.line, s.words[1:])

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
        if rest[0] == "vxlan" and len(rest) >= 2:
            vx_settings = self.vlan_vxlan.setdefault(name, {})
            if rest[1] in ("vni", "multicast-group") and len(rest) == 3:
                vx_settings[rest[1]] = rest[2]
                return True
            if rest[1:] == ["ingress-node-replication"]:
                vx_settings["ingress"] = "on"
                return True
            return False
        if rest[:2] == ["forwarding-options", "dhcp-security"]:
            settings = self.snooping.setdefault(name, {})
            more = rest[2:]
            if not more:
                return True
            if more in (["arp-inspection"], ["ip-source-guard"], ["option-82"]):
                settings[more[0]] = True
                return True
            if more[0] == "group" and len(more) >= 3:
                key = (name, more[1])
                if more[2:] in (["overrides", "trusted"], ["overrides", "untrusted"]):
                    self.trust_kind[key] = more[3]
                    return True
                if more[2] == "interface" and len(more) == 4:
                    self.trust_groups.setdefault(key, []).append(more[3])
                    return True
            return False
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
        if ifd in _MANAGEMENT + ("lo0",) and (rest[0] == "description" and len(rest) == 2 or rest == ["disable"]):
            mgmt = self.unit(ifd, "0")  # said of the whole interface: its one unit
            return mgmt is not None and self.unit_line(s, mgmt, rest)
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
        elif rest[:2] == ["aggregated-ether-options", "lacp"] and len(rest) == 4 and rest[2] in ("system-id",
                                                                                                  "admin-key"):
            self.esi.setdefault(port.name, {})[rest[2]] = rest[3]
        elif rest[:2] == ["aggregated-ether-options", "mc-ae"] and len(rest) == 4:
            self.mc_ae.setdefault(port.name, {})[rest[2]] = rest[3]
        elif rest[0] == "esi" and len(rest) >= 2:
            settings = self.esi.setdefault(port.name, {})
            if len(rest) == 2 and rest[1] in ("all-active", "single-active"):
                settings["mode"] = rest[1]
            elif len(rest) == 2 and ":" in rest[1]:
                settings["esi"] = rest[1]
            elif rest[1:4] == ["df-election-type", "preference", "value"] and len(rest) == 5:
                settings["preference"] = rest[4]
            else:
                return False
        elif rest[0] in ("ether-options", "gigether-options") and len(rest) == 3 and rest[1] == "speed" or \
                rest[0] == "speed" and len(rest) == 2:
            port.speed = bandwidth(rest[-1])
            return port.speed is not None
        elif rest[0] in ("ether-options", "gigether-options") and rest[1:2] == ["link-mode"] and len(rest) == 3 or \
                rest[0] == "link-mode" and len(rest) == 2:
            mode = {"full-duplex": "full", "half-duplex": "half", "automatic": "auto"}.get(rest[-1])
            if mode is None:
                return False
            port.duplex = mode
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
        elif rest[0] == "mac" and len(rest) == 2:
            self.unit_macs[iface.name] = fhrp_text.mac(rest[1])
        elif rest[0] in ("virtual-gateway-v4-mac", "virtual-gateway-v6-mac") and len(rest) == 2:
            self.virtual_mac = fhrp_text.mac(rest[1])
        elif rest == ["virtual-gateway-accept-data"]:
            pass
        elif rest[0] == "proxy-arp" and rest[1:] in ([], ["restricted"], ["unrestricted"]):
            iface.proxy_arp = True
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
            if rest[0] == "filter" and len(rest) == 3 and rest[1] in ("input", "output"):
                attr = ("acl" if family == "inet" else "acl6") + ("_in" if rest[1] == "input" else "_out")
                setattr(iface, attr, rest[2])
                return True
            if rest[0] == "sampling" and len(rest) == 2 and rest[1] in ("input", "output") and family == "inet":
                junosmon.MonitorReader.flow_port(iface, rest[1])
                return True
            if rest[0] == "filter" and len(rest) == 3 and rest[1] in ("input-list", "output-list") and \
                    family == "inet":
                self.filter_lists.setdefault((iface.name, rest[1][:-5]), []).append(rest[2])
                return True
            if rest[0] == "address" and len(rest) >= 2:
                if rest[1] not in addresses:
                    addresses.append(rest[1])
                if rest[2:] == ["primary"]:
                    addresses.remove(rest[1])
                    addresses.insert(0, rest[1])
                    return True
                if rest[2:3] == ["virtual-gateway-address"] and len(rest) == 4:
                    length = rest[1].split("/")[1]
                    (iface.virtual_ipv4 if family == "inet" else iface.virtual_ipv6).append(f"{rest[3]}/{length}")
                    return True
                if rest[2:3] == ["vrrp-group"] and len(rest) >= 5 and family == "inet":
                    return self.vrrp(iface, int(rest[3]), rest[4:])
                return len(rest) == 2
            if rest[0] == "mtu" and len(rest) == 2 and family == "inet":
                iface.mtu = int(rest[1])
                return True
            if rest[0] == "unnumbered-address" and len(rest) == 2 and family == "inet":
                self.unnumbered[iface.name] = rest[1]
                return True
            if rest[0] == "rpf-check" and rest[1:] in ([], ["mode", "loose"]):
                iface.urpf = "loose" if rest[1:] else "strict"
                return True
            if rest == ["no-redirects"] and family == "inet":
                iface.ip_redirects = False
                return True
            return False
        if family == "ethernet-switching":
            if iface.mode == SwitchportMode.ROUTED:
                iface.mode = SwitchportMode.ACCESS
            if not rest:
                return True
            if rest[0] == "filter" and len(rest) == 3 and rest[1] in ("input", "output"):
                setattr(iface, "acl_in" if rest[1] == "input" else "acl_out", rest[2])
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
            if rest[0] == "storm-control" and len(rest) == 2:
                self.storm_ports[iface.name] = rest[1]
                return True
        return False

    def vrrp(self, iface: Interface, number: int, w: List[str]) -> bool:
        group = next((g for g in iface.fhrp if g.protocol == "vrrp" and g.group == number), None)
        if group is None:
            group = FhrpGroup("vrrp", number)
            iface.fhrp.append(group)
        if w[0] == "virtual-address" and len(w) == 2:
            if not group.address:
                group.address = w[1]
            elif w[1] != group.address and w[1] not in group.secondary:
                group.secondary.append(w[1])
        elif w[0] == "priority" and len(w) == 2:
            group.priority = int(w[1])
        elif w == ["no-preempt"]:
            group.preempt = False
        elif w == ["preempt"]:
            group.preempt = True
        elif w[0] == "advertise-interval" and len(w) == 2:
            group.hello_ms = int(w[1]) * 1000
        elif w[0] == "fast-interval" and len(w) == 2:
            group.hello_ms = int(w[1])
        elif w == ["accept-data"]:
            pass
        elif w[:2] == ["track", "interface"] and len(w) == 5 and w[3] == "priority-cost":
            self.vrrp_tracks.append((group, w[2], int(w[4])))
        else:
            return False
        return True

    # system ------------------------------------------------------------------------------------------------------

    def system(self, s: Statement) -> bool:
        w = s.words[1:]
        sy = self.device.system
        if not w:
            return False
        if w[:2] == ["ddos-protection", "protocols"]:
            return junossec.read_ddos(self.device, w[2:])
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
            api = next((k for k, words in junosmgmt.API_KEYS.items() if w[1:] == list(words)), None)
            if api is not None:
                m.apis[api] = ""  # the instance is the management one when there is one, set when all is read
            elif w[1:] == ["ssh"]:
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
            self.management_instance = True
        elif w[0] in ("radius-server", "tacplus-server") and len(w) >= 2:
            return self.aaa_server("radius" if w[0] == "radius-server" else "tacacs", w[1], w[2:], s.line)
        elif w[0] == "authentication-order" and len(w) == 2:
            method = next((m for m in self.device.aaa.methods if m.kind == "authentication" and m.service == "login"),
                          None)
            if method is None:
                method = AaaMethod("authentication", "login")
                method.origin.line = s.line
                self.device.aaa.methods.append(method)
            word = {"radius": "group:radius", "tacplus": "group:tacacs", "password": "local"}.get(w[1])
            if word is None:
                return False
            method.methods.append(word)
        elif w[:2] == ["accounting", "events"] and len(w) == 3 and w[2] in ("login", "interactive-commands"):
            self.accounting.append(w[2])
        elif w[:2] == ["accounting", "destination"] and len(w) >= 3 and w[2] in ("radius", "tacplus"):
            self.accounting_to = w[2]
        elif w[:3] == ["services", "dhcp-local-server", "group"] and len(w) == 6 and w[4] == "interface":
            pass  # the interfaces of the pools' networks serve them
        else:
            return False
        return True

    def aaa_server(self, protocol: str, address: str, w: List[str], line: int) -> bool:
        a = self.device.aaa
        server = next((x for x in a.servers if x.protocol == protocol and x.address == address), None)
        if server is None:
            server = AaaServer(protocol, address)
            server.origin.line = line
            a.servers.append(server)
        if not w:
            return True
        if w[0] == "secret" and len(w) == 2:
            server.key = "" if w[1].startswith("$9$") or w[1] == aaa_text.PLACEHOLDER else w[1]
        elif w[0] == "port" and len(w) == 2:
            server.auth_port = int(w[1])
        elif w[0] == "accounting-port" and len(w) == 2:
            server.acct_port = int(w[1])
        elif w[0] == "timeout" and len(w) == 2:
            server.timeout = int(w[1])
        elif w[0] == "source-address" and len(w) == 2:
            self.aaa_sources[protocol] = w[1]
        elif w[0] == "routing-instance" and len(w) == 2:
            server.vrf = w[1]
        else:
            return False
        return True

    def login(self, w: List[str]) -> bool:
        handled = self.mgmt.login(w)
        if handled is not None:
            return handled
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
            if w[2] in ("port", "transport") and len(w) == 4:
                protocol, port = sy.syslog_transport.get(w[1], ("udp", 514))
                if w[2] == "port":
                    port = int(w[3])
                elif w[3] in ("tcp", "tls", "udp"):
                    protocol = w[3]
                else:
                    return False
                sy.syslog_transport[w[1]] = (protocol, port)
                return True
            if w[2] == "any" and len(w) == 4 and w[3] in LEVELS:
                sy.logging_level = LEVELS.index(w[3])
                return True
            return False
        if w[0] == "source-address" and len(w) == 2:
            sy.logging_source = vxlan_text.interface_of(self.device, w[1])
            return bool(sy.logging_source)
        if w[:2] == ["file", "messages"] and len(w) == 4 and w[2] == "any" and w[3] in LEVELS:
            sy.logging_buffer_level = LEVELS.index(w[3])
            return True
        if w[0] == "console" and len(w) == 3 and w[1] == "any" and w[2] in LEVELS:
            sy.logging_console_level = LEVELS.index(w[2])
            return True
        if w[:2] == ["user", "*"] and len(w) == 4 and w[2] == "any" and w[3] in LEVELS:
            sy.logging_monitor_level = LEVELS.index(w[3])
            return True
        if w == ["time-format", "millisecond"]:
            sy.logging_timestamp = "msec"
            return True
        return False

    # forwarding options, switch options, PoE, access ----------------------------------------------------------------

    def forwarding_options(self, s: Statement, w: List[str], vrf: str) -> bool:
        if w[:2] == ["sampling", "instance"] and len(w) >= 5 and not vrf:
            return self.mon.sampling(w[3:])
        if w[0] == "analyzer" and len(w) >= 4 and not vrf:
            return self.mon.analyzer(w[1:])
        if w[0] == "storm-control-profiles" and len(w) >= 4 and w[2] == "all":
            profile = self.storm_profiles.setdefault(w[1], {})
            rest = w[3:]
            if rest[0] == "bandwidth-percentage" and len(rest) == 2:
                profile["level"] = float(rest[1])
            elif rest[0] in ("no-broadcast", "no-multicast", "no-unknown-unicast", "no-registered-multicast",
                             "no-unregistered-multicast") and len(rest) == 1:
                profile[rest[0]] = True
            else:
                return False
            return True
        if w[0] == "dhcp-relay" and len(w) >= 3:
            rest = w[1:]
            if rest[0] == "server-group" and len(rest) == 3:
                self.relay_servers.setdefault((vrf, rest[1]), []).append(rest[2])
                return True
            if rest[0] == "group" and len(rest) == 4:
                key = (vrf, rest[1])
                if rest[2] == "active-server-group":
                    self.relay_active[key] = rest[3]
                elif rest[2] == "interface":
                    self.relay_units.setdefault(key, []).append(rest[3])
                elif rest[2] == "relay-source":
                    self.relay_source[key] = rest[3]
                else:
                    return False
                return True
        return False

    def switch_options(self, s: Statement) -> bool:
        w = s.words[1:]
        if w[0] == "vtep-source-interface" and len(w) == 2:
            iface = self.canonical(w[1])
            self.vxlan().source_interface = iface.name if iface else w[1]
            return iface is not None
        if w[0] == "route-distinguisher" and len(w) == 2 or w in (["vrf-target", "auto"],) or \
                w[0] == "service-id" and len(w) == 2:
            return True  # the default switch's own: one for all instances
        if w[0] == "vrf-target" and len(w) == 2 and w[1].startswith("target:"):
            self.switch_target = w[1][len("target:"):]
            return True
        if w[0] == "remote-vtep-list" and len(w) == 2:
            self.vxlan().flood_vteps.append(w[1])
            return True
        if w[:2] == ["voip", "interface"] and len(w) == 5 and w[3] == "vlan":
            self.voip[w[2]] = w[4]
            return True
        if w[:2] == ["voip", "interface"] and len(w) == 5 and w[3] == "forwarding-class":
            return True
        if w[0] == "interface" and len(w) >= 4 and w[2] == "interface-mac-limit":
            limit, action = self.mac_limits.get(w[1], (1, "shutdown"))
            if len(w) == 4 and w[3].isdigit():
                limit = int(w[3])
            elif w[3:4] == ["packet-action"] and len(w) == 5:
                action = w[4]
            else:
                return False
            self.mac_limits[w[1]] = (limit, action)
            return True
        return False

    def multi_chassis(self, s: Statement) -> bool:
        w = s.words[1:]
        if w[0] == "multi-chassis-protection" and len(w) == 4 and w[2] == "interface":
            self.protection[w[1]] = w[3]
            return True
        return False

    def poe_line(self, s: Statement) -> bool:
        w = s.words[1:]
        if w[0] != "interface" or len(w) < 2:
            return False
        iface = self.stp_port(w[1])
        if iface is None:
            return False
        rest = w[2:]
        if not rest:
            iface.poe = True
        elif rest == ["disable"]:
            iface.poe = False
        elif rest[0] == "priority" and len(rest) == 2 and rest[1] in ("low", "high"):
            iface.poe_priority = rest[1]
        elif rest[0] == "maximum-power" and len(rest) == 2:
            iface.poe_max_mw = int(float(rest[1]) * 1000)
        else:
            return False
        return True

    def access(self, w: List[str], vrf: str) -> bool:
        if w[0] == "radius-disconnect-port" and len(w) == 2 and not vrf:
            self.device.aaa.coa = True
            return True
        if w[0] == "profile" and len(w) >= 3:
            # the access profile 802.1X uses: its servers are the system's RADIUS servers
            return w[2] in ("authentication-order", "radius") or w[2:3] == ["radius-server"]
        if w[0] == "radius-server" and len(w) >= 2:
            return self.aaa_server("radius", w[1], w[2:], 0)
        if w[:2] == ["address-assignment", "pool"] and len(w) >= 5 and w[3] == "family" and w[4] == "inet":
            pool = next((p for p in self.device.dhcp_pools if p.name == w[2] and p.vrf == vrf), None)
            if pool is None:
                pool = DhcpPool(w[2], vrf=vrf)
                self.device.dhcp_pools.append(pool)
            rest = w[5:]
            if not rest:
                return True
            if rest[0] == "network" and len(rest) == 2:
                pool.network = rest[1]
            elif rest[0] == "range" and len(rest) == 4 and rest[2] in ("low", "high"):
                self.pool_ranges.setdefault((vrf, pool.name), {}).setdefault(rest[1], {})[rest[2]] = rest[3]
            elif rest[0] == "dhcp-attributes" and len(rest) == 3:
                if rest[1] == "router":
                    pool.default_routers.append(rest[2])
                elif rest[1] == "name-server":
                    pool.dns_servers.append(rest[2])
                elif rest[1] == "domain-name":
                    pool.domain_name = rest[2]
                elif rest[1] == "maximum-lease-time":
                    pool.lease_seconds = 0 if rest[2] == "infinite" else int(rest[2])
                else:
                    return False
            else:
                return False
            return True
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
            return self.mgmt.snmp(w)
        return True

    def chassis(self, s: Statement) -> bool:
        if s.words[1:3] == ["fpc", "0"] and len(s.words) == 5 and s.words[3] == "sampling-instance":
            return True  # the J-Flow sampling instance bound to the line card
        # the number of aggregates the chassis allows: written again from the aggregates there are
        return s.words[1:4] == ["aggregated-devices", "ethernet", "device-count"] and len(s.words) == 5

    # routing -----------------------------------------------------------------------------------------------------

    def routing_options(self, s: Statement, w: List[str], vrf: str) -> bool:
        if w[0] == "router-id" and len(w) == 2:
            self.router_ids[vrf] = w[1]
            return True
        if w[0] == "autonomous-system" and len(w) in (2, 3) and not vrf and w[2:] in ([], ["asdot-notation"]):
            self.local_as = w[1]
            self.asdot = len(w) == 3
            self.bgp_line = self.bgp_line or s.line
            return True
        if w[0] == "graceful-restart" and not vrf:
            self.graceful_restart = True
            if w[1:2] == ["restart-duration"] and len(w) == 3:
                self.restart_duration = int(w[2])
                return True
            return len(w) == 1
        if w[0] == "aggregate" and len(w) >= 3 and w[1] == "route":
            return w[3:] in ([], ["brief"], ["full"]) and self.aggregate_route(vrf, w[2], w[3:] == ["full"])
        if w[:2] == ["forwarding-table", "export"] and len(w) == 3 and not vrf:
            self.load_balance.append(w[2])
            return True
        if w[:3] == ["generate", "route", "0.0.0.0/0"] and w[3:] in ([], ["discard"]):
            self.generated.append(s)
            return True
        if w[0] == "instance-import" and len(w) == 2 and vrf:
            self.instance_imports.setdefault(vrf, []).append(w[1])
            return True
        if w[0] == "rib" and len(w) >= 3 and w[1].endswith("inet6.0"):  # IPv6 routes: rib inet6.0 static ...
            return self.routing_options(s, w[2:], vrf)
        if w[:2] == ["static", "route"] and len(w) >= 4:
            prefix, rest = w[2], w[3:]
            routes = [r for r in self.device.static_routes if r.prefix == prefix and r.vrf == vrf]
            if rest[0] == "next-hop" and len(rest) == 2:
                if re.match(r"^[\d.]+$", rest[1]) or ":" in rest[1]:
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

    def vxlan(self) -> Vxlan:
        if self.device.vxlan is None:
            self.device.vxlan = Vxlan()
        return self.device.vxlan

    def aggregate_route(self, vrf: str, prefix: str, as_set: bool) -> bool:
        self.aggregate_routes[(vrf, prefix)] = as_set
        return True

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
        if rest[0] in ("vrf-import", "vrf-export") and len(rest) == 2:
            self.vrf_policies.setdefault(vrf, []).append((rest[0][4:], rest[1], s))
            return True
        if rest[:3] == ["protocols", "evpn", "ip-prefix-routes"] and len(rest) >= 4:
            more = rest[3:]
            if more[0] == "vni" and len(more) == 2:
                self.vxlan().vrf_vnis[vrf] = int(more[1])
                vrfs_text.info(self.device, vrf).rt_evpn = True
                return True
            return more in (["advertise", "direct-nexthop"], ["encapsulation", "vxlan"])
        if rest[0] == "vrf-target":
            if len(rest) == 2 and target(rest[1]):
                return vrfs_text.route_target(vrfs_text.info(self.device, vrf), "both", target(rest[1]))
            if len(rest) == 3 and target(rest[2]):
                return vrfs_text.route_target(vrfs_text.info(self.device, vrf), rest[1], target(rest[2]))
            return False
        if rest[0] == "routing-options":
            return self.routing_options(s, rest[1:], vrf)
        if rest[0] == "protocols" and len(rest) >= 2 and rest[1] in ("ospf", "bgp", "pim", "igmp"):
            return self.protocols(s, rest[1:], vrf)
        if rest[0] == "forwarding-options":
            return self.forwarding_options(s, rest[1:], vrf)
        if rest[0] == "access":
            return self.access(rest[1:], vrf)
        if rest[:3] == ["system", "services", "dhcp-local-server"]:
            return True
        return False

    def multicast(self, w: List[str], vrf: str) -> bool:
        """protocols pim / igmp / msdp / igmp-snooping, in the main instance or a VRF's."""
        dev = self.device
        if w[0] == "pim":
            if vrf:
                m = multicast_text.vrf(dev, vrf)
                m.routing = True
                rps, rp_groups = m.rps, m.rp_groups
            else:
                dev.multicast_routing = True
                rps, rp_groups = dev.pim_rps, dev.pim_rp_groups
            more = w[1:]
            if not more:
                return True
            if more[0] == "interface" and len(more) == 4 and more[2] == "mode" and \
                    more[3] in multicast_text.PIM_MODES:
                if more[1] == "all":
                    return more[3] == "sparse"  # PIM everywhere: multicast routing on
                iface = self.canonical(more[1])
                if iface is None:
                    return False
                iface.pim = more[3]
                return True
            if more[:3] == ["rp", "static", "address"] and len(more) >= 4:
                rp = more[3]
                if rp not in rps:
                    rps.append(rp)
                if len(more) == 4:
                    return True
                if more[4] == "group-ranges" and len(more) == 6:
                    self.rp_ranges.setdefault((vrf, rp), []).append(more[5])
                    return True
                return False
            if more[:2] == ["rp", "local"] and len(more) >= 4 and not vrf:
                if more[2] == "address" and len(more) == 4:
                    self.local_rp = more[3]
                    if more[3] not in rps:
                        rps.append(more[3])
                    return True
                if more[2] == "group-ranges" and len(more) == 4:
                    self.local_rp_ranges.append(more[3])
                    return True
                if more[2:4] == ["anycast-pim", "rp-set"] and len(more) == 6 and more[4] == "address":
                    self.anycast_set.append(more[5])
                    return True
                return more[2:3] == ["anycast-pim"] and more[3:4] == ["local-address"] and len(more) == 5
            return False
        if w[0] == "igmp" and len(w) == 5 and w[1] == "interface" and w[3] == "version" and w[4].isdigit():
            iface = self.canonical(w[2])
            if iface is None:
                return False
            iface.igmp_version = int(w[4])
            return True
        if w[0] == "msdp" and not vrf and len(w) >= 3 and w[1] == "peer":
            if len(w) == 3:
                dev.msdp_peers.setdefault(w[2], "")
                return True
            if w[3] == "local-address" and len(w) == 5:
                self.msdp_sources[w[2]] = w[4]
                dev.msdp_peers.setdefault(w[2], "")
                return True
            return False
        if w[0] == "igmp-snooping" and not vrf and len(w) >= 3 and w[1] == "vlan":
            if w[2] == "all" and len(w) == 3:
                dev.igmp_snooping = True
                return True
            vid = self.vlan_names.get(w[2])
            if vid is None or vid not in dev.vlans:
                return False
            vlan = dev.vlans[vid]
            if len(w) == 3:
                vlan.igmp_snooping = True
                return True
            if w[3:5] == ["l2-querier", "source-address"] and len(w) == 6:
                vlan.igmp_querier = True
                vlan.igmp_querier_address = w[5]
                return True
            return False
        return False

    def finish_multicast(self) -> None:
        dev = self.device
        for (vrf, rp), ranges in self.rp_ranges.items():
            groups = dev.pim_rp_groups if not vrf else multicast_text.vrf(dev, vrf).rp_groups
            groups[rp] = ranges[0]
            if ranges[1:]:
                dev.unparsed.append(Unparsed(0, f"set protocols pim rp static address {rp} group-ranges "
                                             f"{ranges[1]}", "RouterShift keeps one group range per RP"))
        if self.local_rp:
            if self.local_rp_ranges:
                dev.pim_rp_groups[self.local_rp] = self.local_rp_ranges[0]
            if self.anycast_set:
                dev.pim_anycast[self.local_rp] = list(self.anycast_set)
        for peer, address in self.msdp_sources.items():
            iface = vxlan_text.interface_of(dev, address)
            dev.msdp_peers[peer] = iface

    def protocols(self, s: Statement, w: List[str], vrf: str) -> bool:
        if w[0] == "ospf" and len(w) >= 2:
            return self.ospf(w[1:], vrf)
        if w[0] == "bgp" and len(w) >= 2:
            self.bgp_line = self.bgp_line or s.line
            return self.bgp(w[1:], vrf)
        if w[0] in ("pim", "igmp", "msdp", "igmp-snooping"):
            return self.multicast(w, vrf)
        if w[0] == "sflow" and len(w) >= 2 and not vrf:
            return self.mon.sflow(w[1:])
        if w[0] == "lldp":
            m = self.device.management
            if w[1:] in ([], ["interface", "all"]):
                m.lldp = True
                return True
            if w[1:] == ["disable"]:
                m.lldp = False
                return True
            if w[1] in ("advertisement-interval", "hold-multiplier") and len(w) == 3:
                self.lldp_timers[w[1]] = int(w[2])
                return True
            if w[1] == "management-address" and len(w) == 3:
                self.lldp_address = w[2]
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
        if w[:3] == ["layer2-control", "bpdu-block", "interface"] and len(w) in (4, 5):
            iface = self.stp_port(w[3])
            if iface is None or w[4:] not in ([], ["drop"]):
                return False
            if w[4:] == ["drop"]:
                iface.stp_bpdufilter = True
            else:
                iface.stp_bpduguard = True
            return True
        if w[:2] == ["dot1x", "authenticator"] and len(w) >= 3:
            return self.dot1x(w[2:])
        if w[0] == "evpn" and len(w) >= 2 and not vrf:
            return self.evpn(w[1:])
        if w[0] == "iccp" and len(w) >= 3 and not vrf:
            if w[1] == "local-ip-addr" and len(w) == 3:
                self.iccp["local"] = w[2]
                return True
            if w[1] == "peer" and len(w) >= 4:
                self.iccp["peer"] = w[2]
                more = w[3:]
                if more[:2] == ["backup-liveness-detection", "backup-peer-ip"] and len(more) == 3:
                    self.iccp["heartbeat"] = more[2]
                    return True
                return more[0] in ("redundancy-group-id-list", "liveness-detection",
                                   "session-establishment-hold-time")
            return False
        if w == ["vrrp", "version-3"]:
            self.vrrp_v3 = True
            return True
        return False

    def evpn(self, w: List[str]) -> bool:
        if w in (["encapsulation", "vxlan"], ["default-gateway", "no-gateway-community"]):
            return True
        if w[0] == "extended-vni-list" and len(w) == 2:
            self.evpn_vnis.append(w[1])
            return True
        if w[0] == "vni-options" and len(w) >= 5 and w[1] == "vni" and w[3] == "vrf-target":
            targets = self.vni_targets.setdefault(int(w[2]), {})
            if len(w) == 5 and target(w[4]):
                targets["both"] = target(w[4])
                return True
            if len(w) == 6 and w[4] in ("import", "export") and target(w[5]):
                targets[w[4]] = target(w[5])
                return True
            return False
        if w[0] == "duplicate-mac-detection" and len(w) == 3:
            self.host_flap[w[1]] = int(w[2])
            return w[1] in ("detection-window", "detection-threshold", "auto-recovery-time")
        return False

    def dot1x(self, w: List[str]) -> bool:
        if w[0] == "authentication-profile-name" and len(w) == 2:
            self.device.aaa.dot1x = True
            return True
        if w[0] == "interface" and len(w) >= 2:
            settings = self.dot1x_ports.setdefault(w[1], {})
            rest = w[2:]
            if not rest:
                return True
            if rest[0] == "supplicant" and len(rest) == 2 and rest[1] in ("single", "single-secure", "multiple"):
                settings["supplicant"] = rest[1]
            elif rest[0] == "mac-radius" and rest[1:] in ([], ["restrict"]):
                settings["mac-radius"] = "restrict" if rest[1:] else "on"
            elif rest[0] == "reauthentication" and len(rest) == 2:
                settings["reauth"] = rest[1]
            elif rest == ["no-reauthentication"]:
                settings["reauth"] = ""
            elif rest[0] in ("server-reject-vlan", "server-fail-vlan") and len(rest) == 2:
                settings["fail"] = rest[1]
            else:
                return False
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
            elif rest == ["bpdu-timeout-action", "block"]:
                iface.stp_guard = "loop"
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
        if w[0] == "export" and len(w) == 2:
            self.ospf_exports.setdefault(vrf, []).append(w[1])
            return True
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

    def bgp(self, w: List[str], vrf: str = "") -> bool:
        if w[0] == "export" and len(w) == 2:
            self.bgp_export.setdefault(vrf, []).append(w[1])
            return True
        if w[0] == "multipath" and w[1:] in ([], ["multiple-as"]):
            self.bgp_multipath[vrf] = w[1:] == ["multiple-as"]
            return True
        if w[0] == "hold-time" and len(w) == 2 and not vrf:
            self.bgp_hold = int(w[1])
            return True
        if w[0] != "group" or len(w) < 3:
            return False
        groups = self.bgp_groups.setdefault(vrf, {})
        group = groups.setdefault(w[1], BgpNeighbor(w[1]))
        rest = w[2:]
        if rest[0] == "type" and len(rest) == 2 and rest[1] in ("internal", "external"):
            self.bgp_types[(vrf, w[1])] = rest[1]
            return True
        if rest[0] == "preference" and len(rest) == 2:
            self.bgp_preference[(vrf, w[1])] = int(rest[1])
            return True
        if rest[0] == "neighbor" and len(rest) >= 2:
            neighbors = self.bgp_neighbors.setdefault(vrf, {})
            neighbor = neighbors.setdefault(rest[1], BgpNeighbor(rest[1], peer_group=w[1]))
            return len(rest) == 2 or self.bgp_setting(neighbor, rest[2:], vrf)
        return self.bgp_setting(group, rest, vrf)

    def bgp_setting(self, peer: BgpNeighbor, w: List[str], vrf: str = "") -> bool:
        if w[0] in ("import", "export") and len(w) == 2:
            self.bgp_policies.setdefault((vrf, peer.address, w[0]), []).append(w[1])
            return True
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
        elif w[0] == "authentication-key" and len(w) == 2:
            peer.password = w[1] if not w[1].startswith("$9$") else aaa_text.PLACEHOLDER
        elif w[0] == "hold-time" and len(w) == 2:
            peer.hold = int(w[1])
            peer.keepalive = peer.hold // 3
        elif w[0] == "remove-private" and w[1:] in ([], ["all"], ["all", "replace"]):
            peer.remove_private_as = True
            peer.remove_private_as_mode = {1: "all", 2: "all replace-as"}.get(len(w) - 1, "")
        elif w[0] == "cluster" and len(w) == 2:
            peer.route_reflector_client = True
        elif w[0] == "local-as" and len(w) >= 2:
            peer.local_as = w[1]
            options = w[2:]
            if options == ["private"]:
                peer.local_as_options = "no-prepend"
            elif options == ["private", "no-prepend-global-as"]:
                peer.local_as_options = "no-prepend replace-as"
            elif options:
                return False
        elif w[0] == "family" and len(w) >= 3:
            family = {("inet", "unicast"): "ipv4", ("inet6", "unicast"): "ipv6",
                      ("evpn", "signaling"): "evpn"}.get((w[1], w[2]))
            if family is None:
                return False
            more = w[3:]
            if more[:1] == ["prefix-limit"] and len(more) == 3 and more[1] in ("maximum", "teardown"):
                if more[1] == "maximum":
                    peer.maximum_prefix = int(more[2])
                else:
                    peer.maximum_prefix_warning = int(more[2])
            elif more:
                return False
            families = self.bgp_families.setdefault((vrf, peer.address), [])
            if family not in families:
                families.append(family)
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
        if self.management_instance:
            # the management port is in its own routing instance, mgmt_junos
            for iface in dev.interfaces.values():
                if iface.kind == InterfaceKind.MANAGEMENT:
                    iface.vrf = MGMT_INSTANCE
                    if MGMT_INSTANCE not in dev.vrfs:
                        dev.vrfs.insert(0, MGMT_INSTANCE)
        self.finish_ports()
        self.finish_multicast()
        self.finish_services()
        self.finish_fabric()
        self.finish_exports()
        if self.local_as:
            self.finish_bgp()
        unread = lambda line, text, why: dev.unparsed.append(Unparsed(line, text, why))  # noqa: E731
        self.policy.finish(unread)
        self.finish_cos(unread)

    def finish_cos(self, unread: Callable[[int, str, str], None]) -> None:
        dev = self.device
        pending: List[Tuple[QosClass, Acl]] = []
        for (family, _), policy in self.policy.qos_filters.items():
            self.cos.policy(family, policy, unread, pending)
        qos_text.adopt(dev, pending)
        self.cos.finish(unread, self.canonical)
        for (name, direction), filters in self.filter_lists.items():
            iface = dev.interfaces[name]
            for f in filters:
                if f.endswith(junosmgmt.LOGIN_SUFFIX) and f[:-len(junosmgmt.LOGIN_SUFFIX)] in dev.acls:
                    self.login_filter = (f, iface)
                    continue
                if f in dev.qos_policies:
                    setattr(iface, f"qos_policy_{'in' if direction == 'input' else 'out'}", f)
                elif not getattr(iface, f"acl_{'in' if direction == 'input' else 'out'}"):
                    setattr(iface, f"acl_{'in' if direction == 'input' else 'out'}", f)
                else:
                    unread(0, f"set interfaces {name} family inet filter {direction}-list {f}",
                           "RouterShift keeps one ACL and one QoS policy per direction")
        self.mon.finish(self.canonical, lambda a: vxlan_text.interface_of(dev, a), unread)
        monitor_text.finish(dev)
        m = dev.management
        if "advertisement-interval" in self.lldp_timers:
            m.lldp_timer = self.lldp_timers["advertisement-interval"]
        if "hold-multiplier" in self.lldp_timers:
            m.lldp_holdtime = (m.lldp_timer or 30) * self.lldp_timers["hold-multiplier"]
        if self.lldp_address:
            m.lldp_mgmt_interface = vxlan_text.interface_of(dev, self.lldp_address)
            if not m.lldp_mgmt_interface:
                unread(0, f"set protocols lldp management-address {self.lldp_address}",
                       "an address no interface of the switch holds")
        for name, policy in self.policy.mac_filters.items():
            junossec.read_mac_filter(dev, policy, unread)
        for iface in dev.interfaces.values():
            for way in ("in", "out"):
                acl = getattr(iface, f"acl_{way}")
                if acl and acl in dev.qos_policies and acl not in dev.acls:
                    setattr(iface, f"qos_policy_{way}", acl)
                    setattr(iface, f"acl_{way}", "")
                elif acl and acl in dev.mac_acls and acl not in dev.acls:
                    setattr(iface, f"mac_acl_{way}", acl)
                    setattr(iface, f"acl_{way}", "")
            # the loopback's input filter guards the routing engine; so does the management port's
            if iface.kind in (InterfaceKind.LOOPBACK, InterfaceKind.MANAGEMENT) and iface.acl_in:
                cp = security_text.control_plane(dev)
                cp.acls[iface.vrf if iface.vrf or iface.kind == InterfaceKind.LOOPBACK else MGMT_INSTANCE] = \
                    iface.acl_in
                iface.acl_in = ""
        if dev.control_plane is not None:
            cp = dev.control_plane
            for vrf, acl in list(cp.acls.items()):
                if acl.endswith(junosmgmt.LOGIN_SUFFIX) and acl[:-len(junosmgmt.LOGIN_SUFFIX)] in dev.acls:
                    del cp.acls[vrf]
                    self.login_filter = (acl, None)
            cp.acls = dict(sorted(cp.acls.items(), key=lambda kv: kv[0] != ""))
            if not cp.acls and not cp.classes:
                dev.control_plane = None
        if self.login_filter is not None:
            # the filter RouterShift writes for the remote-login ACL: the ACL itself again
            name = self.login_filter[0]
            dev.management.vty_acl = name[:-len(junosmgmt.LOGIN_SUFFIX)]
            dev.acls.pop(name, None)
        self.mgmt.finish(lambda a: vxlan_text.interface_of(dev, a), unread)
        m = dev.management
        if self.management_instance:
            if m.ssh or m.vty_acl:
                m.vrf = MGMT_INSTANCE
            for api in m.apis:
                m.apis[api] = MGMT_INSTANCE
        for port, profile in self.macsec_ports.items():
            secured = self.canonical(port)
            if secured is None:
                unread(0, f"set security macsec interfaces {port} connectivity-association {profile}",
                       "an interface RouterShift does not know")
            else:
                secured.macsec_profile = profile

    def canonical(self, unit: str) -> Optional[Interface]:
        name = self.units.get(unit) or self.units.get(f"{unit}.0") or self.ifds.get(unit)
        return self.device.interfaces.get(name) if name else None

    def finish_ports(self) -> None:
        dev = self.device
        # anycast gateways: the same MAC on several units (or EVPN's default gateway without its community)
        macs = list(self.unit_macs.values())
        shared = {m for m in macs if macs.count(m) > 1}
        for name, mac in self.unit_macs.items():
            iface = dev.interfaces[name]
            if mac in shared:
                dev.anycast_mac = mac
                iface.virtual_ipv4, iface.ipv4 = iface.ipv4, []
                iface.virtual_ipv6, iface.ipv6 = iface.ipv6, []
            else:
                iface.mac_address = mac
        if self.virtual_mac:
            dev.anycast_mac = self.virtual_mac
        for name, unit in self.unnumbered.items():
            target = self.canonical(unit)
            dev.interfaces[name].unnumbered = target.name if target else unit
        for vgroup, vunit, cost in self.vrrp_tracks:
            tracked = self.canonical(vunit)
            if tracked is not None:
                track = f"{tracked.name}-track"
                dev.tracks.setdefault(track, Track(track, interface=tracked.name))
                vgroup.tracks[track] = cost
        if self.vrrp_v3:
            for iface in dev.interfaces.values():
                for g in iface.fhrp:
                    g.version = 3
        for name, profile in self.storm_ports.items():
            settings = self.storm_profiles.get(profile, {})
            level = settings.get("level")
            if isinstance(level, float):
                for kind in ("broadcast", "multicast", "unknown-unicast"):
                    if not settings.get(f"no-{kind}"):
                        dev.interfaces[name].storm_control[kind] = level
        for unit, word in self.voip.items():
            voice = self.canonical(unit)
            if voice is not None:
                voice.voice_vlan = int(self.vlan_id(word)[0])
        for unit, (limit, action) in self.mac_limits.items():
            secured = self.canonical(unit)
            if secured is not None:
                secured.port_security = True
                secured.port_security_max = limit
                secured.port_security_violation = {"drop-and-log": "restrict", "drop": "protect", "log": "restrict",
                                                 "shutdown": "shutdown"}.get(action, "shutdown")
        untrusted: Set[str] = set()
        for key, units in self.trust_groups.items():
            kind = self.trust_kind.get(key, "")
            for unit in units:
                member = self.canonical(unit)
                if member is None:
                    continue
                if kind == "trusted":
                    member.dhcp_trust = member.arp_trust = True
                elif kind == "untrusted":
                    untrusted.add(member.name)
        for name, settings in self.snooping.items():
            vid = self.vlan_names.get(name)
            if vid is None:
                continue
            snooped = dev.vlans[vid]
            snooped.dhcp_snooping = True
            dev.dhcp_snooping = True
            snooped.arp_inspection = bool(settings.get("arp-inspection"))
            if settings.get("option-82"):
                dev.dhcp_option82 = True
            for iface in dev.interfaces.values():
                carried = self.members.get(iface.name, [])
                if iface.mode == SwitchportMode.TRUNK and iface.name not in untrusted and not iface.lag and (
                        "all" in carried or name in carried or str(vid) in carried):
                    iface.dhcp_trust = iface.arp_trust = True  # Junos trusts trunk ports unless told otherwise
                if settings.get("ip-source-guard") and iface.mode == SwitchportMode.ACCESS and (
                        name in carried or str(vid) in carried):
                    iface.source_guard = True
        modes = {"single-secure": "single-host", "single": "multi-host", "multiple": "multi-auth"}
        for unit, port_settings in self.dot1x_ports.items():
            auth = self.canonical(unit)
            if auth is None:
                continue
            auth.dot1x = port_settings.get("mac-radius") != "restrict"
            auth.mab = "mac-radius" in port_settings
            if auth.dot1x:
                auth.dot1x_host_mode = modes.get(port_settings.get("supplicant", "single-secure"), "single-host")
            reauth = port_settings.get("reauth", "")
            auth.dot1x_reauth = bool(reauth)
            auth.dot1x_reauth_period = int(reauth) if reauth.isdigit() else None
            if "fail" in port_settings:
                auth.dot1x_fail_vlan = int(self.vlan_id(port_settings["fail"])[0])

    def finish_fabric(self) -> None:
        """VXLAN, EVPN, multihoming, MC-LAG, and the route targets and leaks of VRFs."""
        dev = self.device
        for vrf, policies in self.vrf_policies.items():
            info = vrfs_text.info(dev, vrf)
            for direction, name, statement in policies:
                found = self.policy.vrf_policy(name, direction)
                if found is None:
                    self.unparsed(statement, "a VRF policy RouterShift cannot read as route targets")
                    continue
                vrf_rts, rmap = found
                for value in vrf_rts:
                    vrfs_text.route_target(info, direction, value)
                if rmap:
                    info.export_map = rmap
        for name, settings in self.vlan_vxlan.items():
            vid = self.vlan_names.get(name)
            if vid is None or "vni" not in settings:
                continue
            vx = self.vxlan()
            vx.vlan_vnis[vid] = int(settings["vni"])
            if "multicast-group" in settings:
                vx.mcast_groups[vid] = settings["multicast-group"]
            if "ingress" not in settings and (self.evpn_vnis or self.vni_targets):
                if "all" in self.evpn_vnis or settings["vni"] in self.evpn_vnis or int(settings["vni"]) in \
                        self.vni_targets:
                    vx.evpn_vlans.append(vid)
        if dev.vxlan is not None:
            vx = dev.vxlan
            vx.evpn_vlans.sort()
            by_vni = {vni: vid for vid, vni in vx.vlan_vnis.items()}
            rts: Dict[Tuple[str, str], List[int]] = {}
            own = dict(self.vni_targets)
            if self.switch_target:
                for vid in vx.evpn_vlans:
                    own.setdefault(vx.vlan_vnis[vid], {"both": self.switch_target})
            for vni, targets in sorted(own.items()):
                vid = by_vni.get(vni)
                if vid is None:
                    continue
                imp = targets.get("both") or targets.get("import", "")
                exp = targets.get("both") or targets.get("export", "")
                rts.setdefault((imp, exp), []).append(vid)
            for n, ((imp, exp), vids) in enumerate(rts.items(), 1):
                owner = next((v for v, info in dev.vrf_info.items() if exp and exp in info.rt_export), "")
                name = owner if owner and owner not in vx.evpn_instances else f"EVPN-{n}"
                vx.evpn_instances[name] = EvpnInstance(name, vids, bundle=len(vids) > 1,
                                                       rt_import=[imp] if imp else [], rt_export=[exp] if exp else [])
        for name, settings in self.esi.items():
            iface = dev.interfaces[name]
            if "esi" in settings:
                iface.evpn_esi = evpn_text.esi_from_junos(settings["esi"])
                iface.evpn_single_active = settings.get("mode") == "single-active"
                if "preference" in settings:
                    iface.evpn_df_preference = int(settings["preference"])
            if "system-id" in settings and name not in self.mc_ae:
                iface.lacp_system_id = evpn_text.lacp_from_junos(settings["system-id"])
        if self.iccp or self.mc_ae:
            m = dev.mlag = Mlag()
            m.peer_address = self.iccp.get("peer", "")
            m.heartbeat = self.iccp.get("heartbeat", "")
            local = self.iccp.get("local", "")
            m.local_interface = vxlan_text.interface_of(dev, local) if local else ""
            link = self.protection.get(m.peer_address, "")
            m.peer_link = self.ifds.get(link, "")
            for name, settings in self.mc_ae.items():
                iface = dev.interfaces[name]
                if "mc-ae-id" in settings:
                    iface.mlag_id = int(settings["mc-ae-id"])
                if settings.get("status-control") == "standby":
                    m.role = "secondary"
                if "init-delay-time" in settings:
                    m.reload_delay = int(settings["init-delay-time"])
        for vrf, names in self.instance_imports.items():
            for name in names:
                leaks = self.policy.leak_policy(name)
                if leaks is None:
                    dev.unparsed.append(Unparsed(0, f"set routing-instances {vrf} routing-options instance-import "
                                                 f"{name}", "an instance-import policy RouterShift cannot read"))
                    continue
                vrfs_text.info(dev, vrf).leaks.update(leaks)

    def finish_services(self) -> None:
        dev = self.device
        for (vrf, group), units in self.relay_units.items():
            servers = self.relay_servers.get((vrf, self.relay_active.get((vrf, group), group)), [])
            source = self.canonical(self.relay_source.get((vrf, group), ""))
            for unit in units:
                iface = self.canonical(unit)
                if iface is not None:
                    iface.helper_addresses = list(servers)
                    iface.helper_source = source.name if source else ""
        for (vrf, name), ranges in self.pool_ranges.items():
            pool = next(p for p in dev.dhcp_pools if p.name == name and p.vrf == vrf)
            pool.ranges = [(r["low"], r["high"]) for r in ranges.values() if "low" in r and "high" in r]
        a = dev.aaa
        for protocol, address in self.aaa_sources.items():
            name = vxlan_text.interface_of(dev, address)
            if name:
                a.source[protocol] = name
        if self.accounting and self.accounting_to:
            protocol = "group:radius" if self.accounting_to == "radius" else "group:tacacs"
            for event in self.accounting:
                a.methods.append(AaaMethod("accounting", "exec" if event == "login" else "commands", [protocol],
                                           record="start-stop"))

    def finish_exports(self) -> None:
        """Export policies RouterShift writes for redistribution are read back as redistribution."""
        always = False
        for name in self.load_balance:
            policy = self.policy.policies.get(name)
            if policy is not None and all(t.thens == [["load-balance", "per-packet"]] and not t.froms
                                          for t in policy.terms.values()):
                self.policy.used_as_export[name] = "forwarding-table"
            else:
                self.device.unparsed.append(Unparsed(self.bgp_line, f"set routing-options forwarding-table export "
                                                     f"{name}", "a forwarding-table policy RouterShift cannot hold"))
        for vrf, names in self.ospf_exports.items():
            p = next((p for p in self.device.ospf if p.vrf == vrf), None)
            for name in names:
                found = self.policy.export(name)
                if p is None or found is None:
                    self.device.unparsed.append(Unparsed(0, f"set protocols ospf export {name}",
                                                         "an OSPF export policy RouterShift cannot read as "
                                                         "redistribution"))
                    continue
                sources, maps, _, default, _, _ = found
                p.redistribute += [x for x in sources if x not in p.redistribute]
                p.redistribute_maps.update(maps)
                p.default_originate = p.default_originate or default
                always = always or default == "always"
        if not always:
            for s in self.generated:
                self.unparsed(s, "a generated route")

    def finish_bgp(self) -> None:
        builder = bgp_text.Builder(self.local_as)
        bgp = builder.bgp
        bgp.router_id = self.router_ids.get("", "")
        bgp.origin.line = self.bgp_line
        if self.bgp_hold is not None:
            bgp.hold, bgp.keepalive = self.bgp_hold, self.bgp_hold // 3
        bgp.graceful_restart = self.graceful_restart
        bgp.graceful_restart_time = self.restart_duration
        bgp.asdot = self.asdot
        for vrf in sorted(set(self.bgp_groups) | set(self.bgp_neighbors) | set(self.bgp_export), key=bool):
            groups, neighbors = self.bgp_instance(bgp, vrf)
            exports = self.bgp_export.get(vrf, [])
            target = bgp if not vrf else bgp.vrfs.setdefault(vrf, BgpVrf())
            if vrf:
                vrf_bgp = bgp.vrfs[vrf]
                # a group named like a global peer group, with its settings, is that peer group used in the VRF
                vrf_bgp.peer_groups.update({k: g for k, g in groups.items() if bgp.peer_groups.get(k) != g})
                vrf_bgp.neighbors += neighbors
                if vrf in self.bgp_multipath:
                    vrf_bgp.maximum_paths = 64
            else:
                bgp.peer_groups.update(groups)
                bgp.neighbors += neighbors
            for name in exports:
                found = self.policy.export(name)
                if found is None:
                    self.device.unparsed.append(Unparsed(self.bgp_line, f"set protocols bgp export {name}",
                                                         "a BGP export policy RouterShift cannot read as "
                                                         "redistribution"))
                    continue
                sources, maps, networks, _, _, ospf_match = found
                v4 = [x for x in sources if x != "connected6"]
                target.redistribute += [x for x in v4 if x not in target.redistribute]
                target.redistribute_maps.update(maps)
                target.networks += networks
                target.ospf_match = ospf_match
                for agg in self.policy.aggregates.get(name, []):
                    agg.as_set = self.aggregate_routes.get((vrf, agg.prefix), False)
                    target.aggregates.append(agg)
        if "" in self.bgp_multipath:
            bgp.maximum_paths = 64  # Junos installs as many equal paths as the platform allows
            bgp.multipath_relax = self.bgp_multipath[""]
        external = [v for (vrf, g), v in self.bgp_preference.items() if self.bgp_types.get((vrf, g)) == "external"]
        internal = [v for (vrf, g), v in self.bgp_preference.items() if self.bgp_types.get((vrf, g)) == "internal"]
        if external or internal:
            bgp.distance = (external[0] if external else 20, internal[0] if internal else 200, 200)
        if self.host_flap:
            bgp.evpn_host_flap = (self.host_flap.get("detection-window", 180),
                                  self.host_flap.get("detection-threshold", 5),
                                  self.host_flap.get("auto-recovery-time", 0) * 60)
        self.device.bgp = bgp

    def bgp_instance(self, bgp: Bgp, vrf: str) -> Tuple[Dict[str, BgpNeighbor], List[BgpNeighbor]]:
        """The groups and neighbors of BGP in one routing instance. Groups RouterShift writes for neighbors without a
        peer group (IBGP, EBGP) are not peer groups of the source."""
        groups: Dict[str, BgpNeighbor] = {}
        neighbors: List[BgpNeighbor] = []
        made_up = {"IBGP", "EBGP"}
        for name, group in self.bgp_groups.get(vrf, {}).items():
            if self.bgp_types.get((vrf, name)) == "internal" and not group.remote_as:
                group.remote_as = self.local_as
            group.send_community = True  # Junos sends communities unless an export policy strips them
            group.families = sorted(set(self.bgp_families.get((vrf, name), [])))
            if name in made_up and group == BgpNeighbor(name, remote_as=group.remote_as, send_community=True,
                                                        families=group.families):
                continue
            groups[name] = group
        for address, neighbor in self.bgp_neighbors.get(vrf, {}).items():
            if neighbor.peer_group in made_up and neighbor.peer_group not in groups:
                if self.bgp_types.get((vrf, neighbor.peer_group)) == "internal" and not neighbor.remote_as:
                    neighbor.remote_as = self.local_as
                neighbor.peer_group = ""
            neighbor.send_community = neighbor.peer_group not in groups
            stated = self.bgp_families.get((vrf, address)) or self.bgp_families.get((vrf, neighbor.peer_group))
            neighbor.families = sorted(set(stated or [bgp_text.family(address)]))
            neighbors.append(neighbor)
        for name, group in groups.items():
            members = [n for n in neighbors if n.peer_group == name]
            own = {bgp_text.family(n.address) for n in members}
            if len(own) > 1 and set(group.families) == own:  # families of a mixed group: each member keeps its own
                group.families = []
                for n in members:
                    if not self.bgp_families.get((vrf, n.address)):
                        n.families = [bgp_text.family(n.address)]
        for peer in list(groups.values()) + neighbors:
            for direction in ("import", "export"):
                suffix = "in" if direction == "import" else "out"
                for name in self.bgp_policies.get((vrf, peer.address, direction), []):
                    plist = name[len(junospolicy.PREFIX_POLICY):]
                    if name.startswith(junospolicy.PREFIX_POLICY) and plist in self.policy.route_filters:
                        setattr(peer, f"prefix_list_{suffix}", plist)
                    elif name == "NEXT-HOP-SELF" and self.policy.next_hop_self(name):
                        peer.next_hop_self = True
                    else:
                        setattr(peer, f"route_map_{suffix}", name)
        return groups, neighbors


def parse(text: str) -> Device:
    return Reader(text).parse()
