# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Vendor-neutral model of a switch or router configuration.

Every parser normalises to these semantics and every emitter may rely on them:

* Interfaces carry a **canonical name** (``Ethernet1/0/1``, ``Port-channel10``,
  ``Vlan20``, ``Loopback0``, ``Management0``) and keep the name the source used
  in ``source_name``. Emitters map the canonical name to their own naming
  through a port map the user can override; they never parse ``source_name``.
* Addresses and prefixes are in CIDR notation (``10.0.0.1/24``, ``2001:db8::1/64``);
  masks and wildcards of the source are converted when parsed.
* VLAN lists use ``10,20,30-40``; an empty list on a trunk means all VLANs.
* Speeds are in Mbit/s; ``None`` everywhere means "the platform's default",
  which an emitter leaves out instead of writing its own default.
* Lines the parser did not understand are kept in ``Device.unparsed`` with their
  context so the report can list them: nothing in the source is dropped silently.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class InterfaceKind(str, Enum):
    ETHERNET = "ethernet"
    LAG = "lag"  # Port-channel, ae, Trk, Bridge-Aggregation, lag
    VLAN = "vlan"  # SVI, irb, Vlan-interface
    LOOPBACK = "loopback"
    MANAGEMENT = "management"
    TUNNEL = "tunnel"
    SUBINTERFACE = "subinterface"
    OTHER = "other"


class SwitchportMode(str, Enum):
    ROUTED = "routed"  # layer 3 port
    ACCESS = "access"
    TRUNK = "trunk"


class LacpMode(str, Enum):
    ACTIVE = "active"
    PASSIVE = "passive"
    STATIC = "static"  # "mode on": no LACP


class AclAction(str, Enum):
    PERMIT = "permit"
    DENY = "deny"
    REMARK = "remark"


class StpMode(str, Enum):
    STP = "stp"
    RSTP = "rstp"
    RAPID_PVST = "rapid-pvst"
    PVST = "pvst"
    MSTP = "mstp"
    NONE = "none"


@dataclass
class Origin:
    """Where an item came from in the source configuration, for the report."""

    line: int = 0
    text: str = ""


@dataclass
class System:
    hostname: str = ""
    domain_name: str = ""
    banner_motd: str = ""
    timezone: str = ""  # IANA name where the source allows it, else as written
    dns_servers: List[str] = field(default_factory=list)
    ntp_servers: List[str] = field(default_factory=list)
    syslog_servers: List[str] = field(default_factory=list)


@dataclass
class Vlan:
    vlan_id: int
    name: str = ""
    shutdown: bool = False
    origin: Origin = field(default_factory=Origin)


@dataclass
class Interface:
    name: str  # canonical
    kind: InterfaceKind
    source_name: str = ""
    description: str = ""
    shutdown: bool = False
    mtu: Optional[int] = None
    speed: Optional[int] = None
    duplex: str = ""  # "", "full", "half", "auto"
    mode: SwitchportMode = SwitchportMode.ROUTED
    access_vlan: Optional[int] = None
    native_vlan: Optional[int] = None
    allowed_vlans: str = ""  # trunk only; "" = all
    voice_vlan: Optional[int] = None
    lag: str = ""  # canonical name of the LAG this port is a member of
    lacp_mode: Optional[LacpMode] = None
    parent: str = ""  # subinterface: canonical name of the parent
    encapsulation_vlan: Optional[int] = None  # subinterface: dot1q tag
    vrf: str = ""
    ipv4: List[str] = field(default_factory=list)  # first is primary
    ipv6: List[str] = field(default_factory=list)
    dhcp_client: bool = False
    helper_addresses: List[str] = field(default_factory=list)
    acl_in: str = ""
    acl_out: str = ""
    stp_portfast: Optional[bool] = None
    stp_bpduguard: Optional[bool] = None
    origin: Origin = field(default_factory=Origin)


@dataclass
class StaticRoute:
    prefix: str
    next_hop: str = ""  # address, or "" with only an interface
    interface: str = ""
    distance: Optional[int] = None
    vrf: str = ""
    name: str = ""
    discard: bool = False  # null route
    origin: Origin = field(default_factory=Origin)


@dataclass
class OspfNetwork:
    prefix: str
    area: str  # dotted form, "0.0.0.0"


@dataclass
class Ospf:
    process: str = "1"
    router_id: str = ""
    vrf: str = ""
    networks: List[OspfNetwork] = field(default_factory=list)
    interface_areas: Dict[str, str] = field(default_factory=dict)  # interface -> area
    passive_interfaces: List[str] = field(default_factory=list)
    passive_default: bool = False
    redistribute: List[str] = field(default_factory=list)  # "connected", "static", "bgp"
    origin: Origin = field(default_factory=Origin)


@dataclass
class BgpNeighbor:
    address: str
    remote_as: str
    description: str = ""
    update_source: str = ""
    peer_group: str = ""
    shutdown: bool = False
    route_map_in: str = ""
    route_map_out: str = ""
    address_families: List[str] = field(default_factory=lambda: ["ipv4-unicast"])


@dataclass
class Bgp:
    local_as: str
    router_id: str = ""
    vrf: str = ""
    neighbors: List[BgpNeighbor] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)
    redistribute: List[str] = field(default_factory=list)
    origin: Origin = field(default_factory=Origin)


@dataclass
class AclEntry:
    action: AclAction
    sequence: Optional[int] = None
    protocol: str = "ip"  # "ip", "tcp", "udp", "icmp" or a number
    source: str = "any"  # "any" or CIDR
    destination: str = "any"
    src_ports: str = ""  # "80,443,1000-2000"
    dst_ports: str = ""
    established: bool = False
    log: bool = False
    remark: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class Acl:
    name: str
    family: int = 4  # 4 or 6
    entries: List[AclEntry] = field(default_factory=list)


@dataclass
class Snmp:
    communities: Dict[str, str] = field(default_factory=dict)  # community -> "ro" / "rw"; secrets stay out of reports
    location: str = ""
    contact: str = ""
    trap_hosts: List[str] = field(default_factory=list)


@dataclass
class LocalUser:
    name: str
    privilege: Optional[int] = None  # 15 = full administrator
    password_hash: str = ""  # carried only when the target accepts the same hash
    hash_type: str = ""


@dataclass
class Unparsed:
    """A line or block of the source no parser section claimed."""

    line: int
    text: str
    section: str = ""


@dataclass
class Device:
    platform: str = ""  # source platform key: "ios", "eos", "junos", "aoscx", ...
    system: System = field(default_factory=System)
    vrfs: List[str] = field(default_factory=list)
    vlans: Dict[int, Vlan] = field(default_factory=dict)
    interfaces: Dict[str, Interface] = field(default_factory=dict)
    static_routes: List[StaticRoute] = field(default_factory=list)
    ospf: List[Ospf] = field(default_factory=list)
    bgp: Optional[Bgp] = None
    acls: Dict[str, Acl] = field(default_factory=dict)
    stp_mode: Optional[StpMode] = None
    snmp: Snmp = field(default_factory=Snmp)
    users: List[LocalUser] = field(default_factory=list)
    unparsed: List[Unparsed] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"
