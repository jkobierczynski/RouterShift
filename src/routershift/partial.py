# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""For writers that cover part of the model so far (Junos, NX-OS): every feature they do not write yet goes to the
report, per port and per device, rather than being dropped or guessed at."""

from __future__ import annotations

from typing import AbstractSet, Callable, List, Tuple

from . import aaa as aaa_text
from . import dhcp as dhcp_text
from . import hosts as hosts_text
from . import igp as igp_text
from . import multicast as multicast_text
from . import routemap as routemap_text
from . import vpn as vpn_text
from . import wlan as wlan_text
from .model import Device, Interface
from .report import Report, Severity

CODE = "not-yet"

# Port features, by key: what the report calls them, and whether a port has them
PORT_FEATURES: List[Tuple[str, str, Callable[[Interface], bool]]] = [
    ("acl", "ACLs", lambda i: bool(i.acl_in or i.acl_out or i.acl6_in or i.acl6_out)),
    ("dhcp-relay", "DHCP relay", lambda i: bool(i.helper_addresses)),
    ("fhrp", "gateway redundancy (HSRP, VRRP)", lambda i: bool(i.fhrp)),
    ("voice", "the voice VLAN", lambda i: i.voice_vlan is not None),
    ("speed", "speed and duplex", lambda i: bool(i.speed or i.duplex not in ("", "auto"))),
    ("qos", "QoS", lambda i: bool(i.qos_trust or i.qos_policy_in or i.qos_policy_out)),
    ("mpls", "MPLS", lambda i: i.mpls),
    ("l2sec", "DHCP snooping, ARP inspection, source guard and port security",
     lambda i: i.dhcp_trust or i.arp_trust or i.source_guard or i.port_security),
    ("storm", "storm control", lambda i: bool(i.storm_control)),
    ("mlag", "the multi-chassis LAG", lambda i: i.mlag_id is not None),
    ("nat", "NAT", lambda i: bool(i.nat)),
    ("bfd", "BFD", lambda i: bool(i.ospf_bfd or i.bfd_interval or i.bfd_min_rx or i.bfd_multiplier)),
    ("isis", "IS-IS", lambda i: i.isis),
    ("multicast", "PIM and IGMP", lambda i: bool(i.pim or i.igmp_version)),
    ("monitor", "sFlow and flow monitoring", lambda i: bool(i.sflow or i.flow)),
    ("poe", "PoE", hosts_text.poe_stated),
    ("pbr", "policy-based routing", lambda i: bool(i.pbr)),
    ("vpn", "IPsec", lambda i: bool(i.crypto_map)),
    ("dot1x", "802.1X and MAC authentication", lambda i: i.dot1x or i.mab),
    ("stp-guards", "loop guard and BPDU filter", lambda i: i.stp_guard == "loop" or i.stp_bpdufilter),
]


def port(iface: Interface, report: Report, label: str, platform: str, written: AbstractSet[str] = frozenset()) -> None:
    """One finding listing what the port carries that the writer does not write (the keys in written it does)."""
    missing = [what for key, what, stated in PORT_FEATURES if key not in written and stated(iface)]
    if missing:
        report.add("interface", label, Severity.REVIEW, CODE,
                   f"not written for {platform} yet: {', '.join(missing)}; configure by hand")


def device(dev: Device, report: Report, platform: str, written: AbstractSet[str] = frozenset()) -> None:
    """Every device-wide feature the writer does not write (the keys in written it does)."""

    def skip(key: str, kind: str, label: str, what: str) -> None:
        if key not in written:
            report.skip(kind, label, CODE, f"{what} not written for {platform} yet; configure by hand")

    for name in dev.acls:
        skip("acl", "acl", name, "access lists are")
    if "policy" not in written:
        routemap_text.unsupported(dev, report, platform)
    for pool in dev.dhcp_pools:
        skip("dhcp", "dhcp", dhcp_text.label(pool), "the DHCP server is")
    for n, rule in enumerate(dev.nat_rules, 1):
        skip("nat", "nat", f"rule {n} ({rule.kind})", "NAT is")
    if vpn_text.has_vpn(dev):
        for p in dev.ipsec_peers:
            skip("vpn", "vpn", vpn_text.peer_label(p), "IPsec is")
    for policy in dev.qos_policies:
        skip("qos", "qos", f"policy {policy}", "QoS is")
    for session in dev.mirror_sessions:
        skip("monitor", "monitor", f"mirror session {session.name}", "port mirroring is")
    if dev.sflow is not None:
        skip("monitor", "monitor", "sFlow", "sFlow is")
    if dev.netflow is not None:
        skip("monitor", "monitor", "NetFlow", "flow monitoring is")
    if "wlan" not in written:
        wlan_text.unsupported(dev, report, platform)
    if dev.mpls.ldp or any(i.mpls for i in dev.interfaces.values()):
        skip("mpls", "mpls", "MPLS and LDP", "MPLS and LDP are")
    if dev.rip is not None:
        skip("rip", "rip", igp_text.RIP_LABEL, "RIP is")
    if dev.isis is not None:
        skip("isis", "isis", igp_text.isis_label(dev.isis), "IS-IS is")
    if dev.mlag is not None:
        skip("mlag", "interface", "multi-chassis LAG", "the multi-chassis LAG is")
    if dev.vxlan is not None:
        skip("vxlan", "interface", "VXLAN", "VXLAN is")
    for sla in dev.ip_slas:
        skip("track", "track", f"ip sla {sla}", "probes are")
    for track in dev.tracks:
        skip("track", "track", f"track {track}", "object tracking is")
    if multicast_text.stated(dev) or dev.multicast_routing or dev.pim_rps:
        skip("multicast", "vlan", multicast_text.LABEL, "IGMP snooping and PIM are")
    if dev.dhcp_snooping:
        skip("l2sec", "vlan", "DHCP snooping", "DHCP snooping is")
    for server in dev.aaa.servers:
        skip("aaa", "management", aaa_text.server_label(server), "RADIUS and TACACS+ servers are")
    for method in dev.aaa.methods:
        skip("aaa", "management", aaa_text.method_label(method), "authentication order and 802.1X are")
