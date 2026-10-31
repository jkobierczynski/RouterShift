# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Vendor-neutral model of a switch or router configuration.

Every parser normalises to these semantics and every emitter may rely on them:

* Interfaces carry a **canonical name** (``Ethernet1/0/1``, ``Port-channel10``,
  ``Vlan20``, ``Loopback0``, ``Management1``) and keep the name the source used
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
from typing import Any, Dict, List, Optional, Tuple


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
    # VRF through which the device reaches its DNS, NTP and syslog servers ("" = the default VRF).
    service_vrf: str = ""
    ntp_prefer: str = ""  # the preferred NTP server
    ntp_server_keys: Dict[str, int] = field(default_factory=dict)  # NTP server -> authentication key number
    ntp_keys: Dict[int, "NtpKey"] = field(default_factory=dict)
    ntp_authenticate: bool = False  # only take time from authenticated servers
    ntp_source: str = ""  # canonical name of the interface NTP packets leave from
    transfer_source: Dict[str, str] = field(default_factory=dict)  # "tftp" / "ftp" -> canonical source interface
    logging_level: Optional[int] = None  # severity sent to the syslog servers, 0 (emergencies) to 7 (debugging)
    logging_source: str = ""  # canonical name of the interface syslog packets leave from


@dataclass
class VrfInfo:
    """What a VRF shares with others: its route distinguisher and the route targets it imports and exports."""
    rd: str = ""
    rt_import: List[str] = field(default_factory=list)
    rt_export: List[str] = field(default_factory=list)


@dataclass
class Mlag:
    """A pair of switches that share LAGs (EOS MLAG, AOS-CX VSX). The peer link and local interface are canonical
    names."""
    domain: str = ""
    peer_link: str = ""
    peer_address: str = ""  # the peer's address on the peer link (EOS) or keepalive (AOS-CX)
    local_interface: str = ""  # the SVI on the peer link (EOS) or the keepalive source (AOS-CX)
    role: str = ""  # primary or secondary (AOS-CX)


@dataclass
class Management:
    """How the device is managed: its login servers and their limits, and neighbor discovery. None means the
    source does not say, and the target keeps its own default."""
    ssh: Optional[bool] = None
    telnet: Optional[bool] = None
    http: Optional[bool] = None
    https: Optional[bool] = None
    vrf: str = ""  # the VRF the SSH and HTTPS servers listen in, where the platform names one
    vty_acl: str = ""  # IPv4 ACL that limits who may log in remotely
    exec_timeout: Optional[int] = None  # idle timeout of remote sessions, in minutes (0 = never)
    lldp: Optional[bool] = None
    cdp: Optional[bool] = None


@dataclass
class NtpKey:
    number: int
    algorithm: str = "md5"  # md5, sha1, sha256
    key: str = ""  # "" when the source holds it encrypted, which no other platform can read
    trusted: bool = False


@dataclass
class Vlan:
    vlan_id: int
    name: str = ""
    shutdown: bool = False
    dhcp_snooping: bool = False  # DHCP snooping on the VLAN
    arp_inspection: bool = False  # dynamic ARP inspection on the VLAN
    origin: Origin = field(default_factory=Origin)


@dataclass
class Interface:
    name: str  # canonical
    kind: InterfaceKind
    source_name: str = ""
    # Nominal speed class of a physical port as its name tells it ("1g", "10g", "25g", "40g", "100g"), so a
    # writer that names ports by speed (IOS) picks the right prefix; "" when the name does not say.
    media: str = ""
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
    acl_in: str = ""  # IPv4 ACLs applied to the interface
    acl_out: str = ""
    acl6_in: str = ""  # IPv6 ACLs
    acl6_out: str = ""
    stp_portfast: Optional[bool] = None
    stp_bpduguard: Optional[bool] = None
    stp_guard: str = ""  # "root" or "loop"
    stp_bpdufilter: bool = False
    stp_cost: Optional[int] = None
    stp_port_priority: Optional[int] = None  # 0-240 in steps of 16; None = the default, 128
    qos_trust: str = ""  # "dscp", "cos" or "none"; "" = the platform default
    qos_policy_in: str = ""  # QosPolicy names
    qos_policy_out: str = ""
    mpls: bool = False  # MPLS label switching with LDP on the interface
    lldp_tx: bool = True  # LLDP sends on the port (where LLDP runs)
    lldp_rx: bool = True  # LLDP listens on the port
    cdp: Optional[bool] = None  # CDP on the port, where stated
    dhcp_trust: bool = False  # trusted for DHCP snooping (a port towards a DHCP server)
    arp_trust: bool = False  # trusted for ARP inspection
    source_guard: bool = False  # IP source guard: only addresses DHCP snooping has seen
    port_security: bool = False
    port_security_max: Optional[int] = None  # MAC addresses allowed
    port_security_violation: str = ""  # shutdown, restrict (drop and report) or protect (drop)
    storm_control: Dict[str, float] = field(default_factory=dict)  # broadcast|multicast|unicast|unknown-unicast -> %
    mlag_id: Optional[int] = None  # the multi-chassis LAG this port-channel is (EOS mlag N, AOS-CX multi-chassis)
    fhrp: List["FhrpGroup"] = field(default_factory=list)
    nat: str = ""  # "inside", "outside" or ""
    ospf_cost: Optional[int] = None
    ospf_network: str = ""  # "", "point-to-point", "broadcast"
    crypto_map: str = ""  # policy-based IPsec applied on the interface
    tunnel_source: str = ""  # tunnel: a canonical interface name or an address
    tunnel_destination: str = ""
    tunnel_mode: str = ""  # tunnel: "gre" or "ipsec"
    tunnel_profile: str = ""  # tunnel: the IPsec profile protecting it (an IpsecPeer name)
    dot1x: bool = False  # 802.1X authenticator on the port
    mab: bool = False  # MAC authentication for clients without 802.1X
    dot1x_host_mode: str = ""  # "single-host", "multi-host" (one login opens the port), "multi-auth", "multi-domain"
    dot1x_reauth: bool = False
    dot1x_reauth_period: Optional[int] = None  # seconds; None = the platform default
    origin: Origin = field(default_factory=Origin)


@dataclass
class FhrpGroup:
    """A first-hop redundancy group on an interface (IPv4)."""

    # "hsrp", "vrrp", or "anycast": a gateway address every router of the pair answers on with a shared MAC, without
    # an election (Arista VARP, AOS-CX active gateway)
    protocol: str
    group: int = 0  # anycast: 0
    address: str = ""  # virtual IP, no prefix length
    secondary: List[str] = field(default_factory=list)
    priority: Optional[int] = None  # None: the default, 100
    preempt: Optional[bool] = None  # None: the protocol's default (HSRP off, VRRP on)
    hello_ms: Optional[int] = None  # HSRP hello / VRRP advertisement interval
    hold_ms: Optional[int] = None  # HSRP only
    version: Optional[int] = None  # None: the platform default (HSRP 1, VRRP 2)
    name: str = ""  # HSRP name, VRRP description
    shutdown: bool = False
    mac: str = ""  # anycast: the shared virtual MAC, "xx:xx:xx:xx:xx:xx"
    origin: Origin = field(default_factory=Origin)

    def preempts(self) -> bool:
        return self.preempt if self.preempt is not None else self.protocol != "hsrp"


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
    prefix: str  # CIDR
    area: str  # dotted form, "0.0.0.0"


@dataclass
class Ospf:
    """An OSPFv2 process. Interface names are canonical; areas are in dotted form."""

    process: str = "1"
    router_id: str = ""
    vrf: str = ""
    networks: List[OspfNetwork] = field(default_factory=list)  # network statements, in order
    interface_areas: Dict[str, str] = field(default_factory=dict)  # interface -> area, set on the interface
    passive_default: bool = False
    passive_interfaces: List[str] = field(default_factory=list)  # passive although the default is not
    active_interfaces: List[str] = field(default_factory=list)  # not passive although the default is
    area_types: Dict[str, str] = field(default_factory=dict)  # area -> "stub", "stub no-summary", "nssa", ...
    redistribute: List[str] = field(default_factory=list)  # "connected", "static", "bgp"
    redistribute_maps: Dict[str, str] = field(default_factory=dict)  # source -> route map that filters it
    default_originate: str = ""  # "", "on", "always"
    reference_bandwidth: Optional[int] = None  # Mbit/s
    origin: Origin = field(default_factory=Origin)

    def passive(self, interface: str) -> bool:
        if self.passive_default:
            return interface not in self.active_interfaces
        return interface in self.passive_interfaces


@dataclass
class BgpNeighbor:
    """A BGP neighbor, or a peer group (address = the group's name)."""

    address: str
    remote_as: str = ""
    description: str = ""
    update_source: str = ""  # canonical interface name
    peer_group: str = ""
    shutdown: bool = False
    ebgp_multihop: Optional[int] = None  # TTL
    next_hop_self: bool = False
    send_community: bool = False
    families: List[str] = field(default_factory=list)  # address families it is active in: "ipv4", "ipv6"
    route_map_in: str = ""  # route map on received routes, in every address family the neighbor is active in
    route_map_out: str = ""
    prefix_list_in: str = ""
    prefix_list_out: str = ""


@dataclass
class Bgp:
    local_as: str
    router_id: str = ""
    peer_groups: Dict[str, BgpNeighbor] = field(default_factory=dict)
    neighbors: List[BgpNeighbor] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)  # IPv4 and IPv6 prefixes
    redistribute: List[str] = field(default_factory=list)  # IPv4: "connected", "static", "ospf"
    redistribute6: List[str] = field(default_factory=list)  # IPv6
    redistribute_maps: Dict[str, str] = field(default_factory=dict)  # IPv4 source -> route map that filters it
    origin: Origin = field(default_factory=Origin)


@dataclass
class PrefixEntry:
    seq: int
    action: AclAction  # permit or deny
    prefix: str  # CIDR
    ge: Optional[int] = None  # prefix lengths from (greater or equal) ...
    le: Optional[int] = None  # ... up to (less or equal)


@dataclass
class PrefixList:
    name: str
    family: str = "ipv4"  # "ipv4" or "ipv6"
    entries: List[PrefixEntry] = field(default_factory=list)
    origin: Origin = field(default_factory=Origin)


@dataclass
class RouteMapEntry:
    """One numbered entry (IOS sequence, Comware node). Sets use neutral keys: local-preference, metric, weight, tag,
    next-hop, origin (igp, incomplete), as-path-prepend (AS numbers, space separated), community (space separated)."""

    seq: int
    action: AclAction  # permit or deny
    match_prefix_lists: List[str] = field(default_factory=list)  # IPv4
    match_prefix_lists6: List[str] = field(default_factory=list)  # IPv6
    match_acls: List[str] = field(default_factory=list)
    match_tags: List[int] = field(default_factory=list)
    sets: Dict[str, str] = field(default_factory=dict)
    community_additive: bool = False  # the communities are added to the ones the route has
    description: str = ""


@dataclass
class RouteMap:
    name: str
    entries: List[RouteMapEntry] = field(default_factory=list)
    origin: Origin = field(default_factory=Origin)


@dataclass
class AclEntry:
    action: AclAction
    sequence: Optional[int] = None
    protocol: str = "ip"  # "ip" (any protocol, either family), "tcp", "udp", "icmp", "icmpv6" or a number
    source: str = "any"  # "any" or CIDR
    destination: str = "any"
    src_ports: str = ""  # "80,443,1000-2000"; "" = any
    dst_ports: str = ""
    icmp_type: Optional[int] = None
    established: bool = False
    log: bool = False
    remark: str = ""  # REMARK entries
    # Non-empty: the entry as the source wrote it, which the model cannot hold (object groups, non-contiguous
    # wildcards, "neq", ...). Writers keep its place with a comment and the report asks a person to translate it.
    unsupported: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class Acl:
    name: str
    family: int = 4  # 4 or 6
    entries: List[AclEntry] = field(default_factory=list)


@dataclass
class IkePolicy:
    """An IKE proposal: IOS 'crypto isakmp policy' or 'crypto ikev2 proposal', Comware 'ike proposal', EOS 'ike policy'.

    Algorithms use neutral names: encryption des, 3des, aes-128, aes-192, aes-256, aes-gcm-128, aes-gcm-256;
    integrity md5, sha1, sha256, sha384, sha512.
    """

    name: str
    version: int = 1
    encryption: List[str] = field(default_factory=list)
    integrity: List[str] = field(default_factory=list)
    dh_groups: List[int] = field(default_factory=list)
    lifetime: Optional[int] = None  # seconds; None = the default, a day
    authentication: str = "pre-share"  # anything else (certificates) is reported
    origin: Origin = field(default_factory=Origin)


@dataclass
class IpsecTransform:
    """How ESP protects the traffic: IOS transform set, Comware transform set, the ESP half of an EOS SA policy."""

    name: str
    encryption: str = ""
    integrity: str = ""  # "" with GCM
    mode: str = "tunnel"  # or "transport"
    origin: Origin = field(default_factory=Origin)


@dataclass
class IpsecPeer:
    """One IPsec connection: a crypto map entry (policy-based), or an IPsec profile used by tunnel interfaces."""

    name: str  # crypto map or profile name
    seq: int = 0  # crypto map sequence; 0 for a profile
    peer: str = ""  # remote address; a profile takes it from the tunnel destination
    acl: str = ""  # crypto map: the traffic to protect
    transforms: List[str] = field(default_factory=list)
    pfs_group: int = 0  # 0 = no PFS
    lifetime: Optional[int] = None  # SA lifetime in seconds; None = the default, an hour
    ike_version: int = 1
    ike_policies: List[str] = field(default_factory=list)  # pinned proposals; empty = any the device has
    origin: Origin = field(default_factory=Origin)

    @property
    def profile(self) -> bool:
        return self.seq == 0


@dataclass
class PreSharedKey:
    peer: str  # the remote address; 0.0.0.0 = any
    key: str = ""  # "" when the source holds it encrypted, which no other platform can read
    origin: Origin = field(default_factory=Origin)


@dataclass
class NatPool:
    name: str
    first: str
    last: str
    prefix_len: int = 0  # 0 = unknown (Comware address groups have no mask)


@dataclass
class NatRule:
    """Source NAT of traffic going from the inside to the outside."""

    kind: str  # "static" (one address, or one port, to another) or "dynamic" (sources picked by an ACL)
    local: str = ""  # static: the inside address
    translated: str = ""  # static: the address it becomes
    protocol: str = ""  # static port forwarding: "tcp" or "udp"
    local_port: Optional[int] = None
    translated_port: Optional[int] = None
    acl: str = ""  # dynamic: the sources
    pool: str = ""  # dynamic: the addresses to use; "" = the outside interface's own address
    overload: bool = False  # dynamic: PAT
    interface: str = ""  # the outside interface it applies on (canonical); "" = every outside interface
    vrf: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class DhcpPool:
    """A DHCP server pool. Addresses are handed out from ``ranges``; platforms that exclude addresses instead
    (IOS, Comware) are read into ranges and written back as exclusions."""

    name: str
    network: str = ""  # CIDR
    ranges: List[Tuple[str, str]] = field(default_factory=list)  # first, last
    default_routers: List[str] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=list)
    domain_name: str = ""
    lease_seconds: Optional[int] = None  # None: the platform default; 0: infinite
    vrf: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class Snmp:
    communities: List["SnmpCommunity"] = field(default_factory=list)
    location: str = ""
    contact: str = ""
    hosts: List["SnmpHost"] = field(default_factory=list)  # where notifications go
    traps: bool = False  # notifications switched on
    groups: Dict[str, "SnmpGroup"] = field(default_factory=dict)
    users: List["SnmpUser"] = field(default_factory=list)
    source: str = ""  # canonical name of the interface SNMP packets leave from
    vrf: str = ""  # VRF the agent answers in, where the platform sets one for all of SNMP


@dataclass
class SnmpCommunity:
    """An SNMPv1/v2c community. Its name is a secret: reports never show it."""

    name: str
    access: str = "ro"  # "ro" or "rw"
    acl: str = ""  # standard ACL of the managers allowed to use it
    origin: Origin = field(default_factory=Origin)


@dataclass
class SnmpHost:
    address: str
    version: str = "2c"  # "1", "2c" or "3"
    secret: str = ""  # v1/v2c: the community (a secret); v3: the user name
    level: str = ""  # v3: "noauth", "auth" or "priv"
    informs: bool = False  # informs (acknowledged) instead of traps
    vrf: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class SnmpGroup:
    name: str
    level: str = "priv"  # "noauth", "auth" or "priv"
    read_view: str = ""  # "" = the platform default (everything)
    write_view: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class SnmpUser:
    """An SNMPv3 user. Its keys are secrets: reports never show them."""

    name: str
    group: str = ""
    auth: str = ""  # "", "md5", "sha", "sha256", "sha384", "sha512"
    auth_key: str = ""  # "" when the source holds it encrypted or localized
    priv: str = ""  # "", "des", "aes128", "aes192", "aes256"
    priv_key: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class LocalUser:
    name: str
    privilege: Optional[int] = None  # 15 = full administrator, 1 = read-only operator
    password: str = ""  # clear text, when the source has it (or a reversible type 7)
    password_hash: str = ""  # carried only when the target accepts the same hash
    hash_type: str = ""  # "md5-crypt" ($1$), "sha512-crypt" ($6$), or a platform's own form ("ios-scrypt", ...)
    origin: Origin = field(default_factory=Origin)


@dataclass
class AaaServer:
    """A RADIUS or TACACS+ server. Its key is a secret: reports never show it."""

    protocol: str  # "radius" or "tacacs"
    address: str
    name: str = ""  # IOS 'radius server NAME', Comware scheme
    key: str = ""  # "" when the source holds it encrypted
    auth_port: Optional[int] = None  # RADIUS authentication / TACACS+ port; None = the default (1812 / 49)
    acct_port: Optional[int] = None  # RADIUS accounting; None = 1813
    timeout: Optional[int] = None
    vrf: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class AaaGroup:
    protocol: str  # "radius" or "tacacs"
    name: str
    servers: List[str] = field(default_factory=list)  # addresses
    vrf: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class AaaMethod:
    """A method list: how logins are checked, commands authorized and sessions accounted.

    Methods are "group:NAME" (a server group), "group:radius" / "group:tacacs" (every server of that protocol),
    "local", "enable", "none" or "if-authenticated".
    """

    kind: str  # "authentication", "authorization" or "accounting"
    service: str  # "login", "enable", "exec", "commands" or "dot1x" (port authentication)
    methods: List[str] = field(default_factory=list)
    name: str = "default"
    level: Optional[int] = None  # commands: the privilege level
    record: str = ""  # accounting: "start-stop" or "stop-only"
    origin: Origin = field(default_factory=Origin)


@dataclass
class Aaa:
    servers: List[AaaServer] = field(default_factory=list)
    groups: Dict[str, AaaGroup] = field(default_factory=dict)
    methods: List[AaaMethod] = field(default_factory=list)
    source: Dict[str, str] = field(default_factory=dict)  # protocol -> canonical source interface
    enable_secret: Optional[LocalUser] = None  # IOS/EOS enable secret, as a user named "enable"
    dot1x: bool = False  # 802.1X port authentication switched on for the device


@dataclass
class QosClass:
    """Traffic matched by DSCP value or by an access list."""

    name: str
    dscp: List[int] = field(default_factory=list)
    acl: str = ""
    match_all: bool = False  # IOS match-all: every condition must hold (only matters with more than one)
    origin: Origin = field(default_factory=Origin)


@dataclass
class QosAction:
    """What a policy does with the traffic of one class."""

    qos_class: str  # QosClass name; "class-default" = everything else
    set_dscp: Optional[int] = None
    police_kbps: Optional[int] = None  # committed rate; traffic above it is dropped


@dataclass
class QosPolicy:
    name: str
    actions: List[QosAction] = field(default_factory=list)
    origin: Origin = field(default_factory=Origin)


@dataclass
class Wlan:
    """A wireless network (SSID) on a controller: its VLAN and security."""
    name: str
    ssid: str = ""
    wlan_id: Optional[int] = None
    vlan: Optional[int] = None
    security: str = "dot1x"  # open, psk (WPA2-PSK) or dot1x (WPA2-Enterprise)
    psk: str = ""  # "" when the source holds it encrypted
    enabled: bool = True
    origin: Origin = field(default_factory=Origin)


@dataclass
class Mpls:
    """MPLS label switching with LDP. The router ID is an address or an interface (canonical name)."""
    ldp: bool = False
    router_id: str = ""
    router_id_interface: str = ""
    origin: Origin = field(default_factory=Origin)


@dataclass
class Stp:
    """Spanning tree beyond its mode: bridge priorities and the MST region."""

    priority: Dict[int, int] = field(default_factory=dict)  # MST instance (0: the common tree, or the one tree of
    # STP/RSTP) -> bridge priority, 0-61440 in steps of 4096
    vlan_priority: Dict[int, int] = field(default_factory=dict)  # PVST: VLAN -> bridge priority
    region: str = ""  # MST region name
    revision: Optional[int] = None
    instances: Dict[int, List[int]] = field(default_factory=dict)  # MST instance -> VLANs


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
    vrf_info: Dict[str, VrfInfo] = field(default_factory=dict)
    vlans: Dict[int, Vlan] = field(default_factory=dict)
    interfaces: Dict[str, Interface] = field(default_factory=dict)
    static_routes: List[StaticRoute] = field(default_factory=list)
    ospf: List[Ospf] = field(default_factory=list)
    bgp: Optional[Bgp] = None
    acls: Dict[str, Acl] = field(default_factory=dict)
    prefix_lists: Dict[str, PrefixList] = field(default_factory=dict)
    route_maps: Dict[str, RouteMap] = field(default_factory=dict)
    dhcp_pools: List[DhcpPool] = field(default_factory=list)
    nat_pools: Dict[str, NatPool] = field(default_factory=dict)
    nat_rules: List[NatRule] = field(default_factory=list)
    ike_policies: Dict[str, IkePolicy] = field(default_factory=dict)
    ipsec_transforms: Dict[str, IpsecTransform] = field(default_factory=dict)
    ipsec_peers: List[IpsecPeer] = field(default_factory=list)
    psks: Dict[str, PreSharedKey] = field(default_factory=dict)  # by peer address
    stp_mode: Optional[StpMode] = None
    stp: Stp = field(default_factory=Stp)
    mpls: Mpls = field(default_factory=Mpls)
    wlans: List[Wlan] = field(default_factory=list)
    management: Management = field(default_factory=Management)
    dhcp_snooping: bool = False  # DHCP snooping switched on
    mlag: Optional[Mlag] = None
    qos_classes: Dict[str, QosClass] = field(default_factory=dict)
    qos_policies: Dict[str, QosPolicy] = field(default_factory=dict)
    snmp: Snmp = field(default_factory=Snmp)
    users: List[LocalUser] = field(default_factory=list)
    aaa: Aaa = field(default_factory=Aaa)
    unparsed: List[Unparsed] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"
