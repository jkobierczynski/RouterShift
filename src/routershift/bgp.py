# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""BGP helpers that every reader and writer shares."""

from __future__ import annotations

import copy
import ipaddress
from typing import Dict, List, Optional, Set, Tuple

from .model import Bgp, BgpAggregate, BgpNeighbor, BgpVrf
from .aaa import PLACEHOLDER
from .report import Report, Severity

# Neighbor settings beyond the basics, as the report names them
OPTIONS = {"password": "the session password", "timers": "the keepalive and hold timers",
           "route_reflector_client": "route-reflector-client", "maximum_prefix": "the maximum-prefix limit",
           "maximum_prefix_warning": "the maximum-prefix warning threshold",
           "remove_private_as": "remove-private-as", "remove_private_as_mode": "remove-private-as all/replace-as",
           "allowas_in": "allowas-in", "local_as": "local-as", "ttl_security": "TTL security (GTSM)"}

REDISTRIBUTE = ("connected", "static", "ospf")


def family(address: str) -> str:
    """"ipv4" or "ipv6" for a neighbor address; "" for a peer group's name."""
    try:
        return "ipv6" if ipaddress.ip_address(address).version == 6 else "ipv4"
    except ValueError:
        return ""


class Builder:
    """Collects neighbor settings as a reader meets them, wherever the platform puts them (top level or inside an
    address family), and settles the address families at the end."""

    def __init__(self, local_as: str) -> None:
        self.bgp = Bgp(local_as)
        self.default_ipv4 = True  # IOS and EOS activate IPv4 neighbors in IPv4 unless told not to
        self.activated: Dict[str, Set[str]] = {}
        self.deactivated: Dict[str, Set[str]] = {}
        self.note: Optional[Tuple[str, str]] = None  # report group and reason for a line read only in part
        self.type7 = False  # IOS: "password 7 X" is the reversible type 7, read back to the clear text
        self.declared: Set[str] = set()  # peer groups this builder's configuration defines (not only refers to)

    def defined(self, name: str) -> bool:
        return name in self.declared

    def peer(self, name: str, group: bool = False) -> BgpNeighbor:
        if name in self.bgp.peer_groups:
            return self.bgp.peer_groups[name]
        for neighbor in self.bgp.neighbors:
            if neighbor.address == name:
                return neighbor
        neighbor = BgpNeighbor(name)
        if group or not family(name):
            self.bgp.peer_groups[name] = neighbor
        else:
            self.bgp.neighbors.append(neighbor)
        return neighbor

    def activate(self, name: str, af: str, on: bool = True) -> None:
        self.peer(name)
        (self.activated if on else self.deactivated).setdefault(name, set()).add(af)

    def finish(self) -> Bgp:
        for neighbor in list(self.bgp.peer_groups.values()) + self.bgp.neighbors:
            families = set(self.activated.get(neighbor.address, set()))
            group = self.bgp.peer_groups.get(neighbor.peer_group)
            if group is not None:
                families |= self.activated.get(group.address, set())
            if self.default_ipv4 and family(neighbor.address) == "ipv4":
                families.add("ipv4")
            families -= self.deactivated.get(neighbor.address, set())
            neighbor.families = sorted(families)
        return self.bgp


def effective(bgp: Bgp, neighbor: BgpNeighbor, vrf: Optional[BgpVrf] = None) -> BgpNeighbor:
    """A neighbor with the settings of its peer group filled in, for targets without peer groups (and for neighbors in a
    VRF, whose group may be the VRF's own or the process's)."""
    result = copy.deepcopy(neighbor)
    group = (vrf.peer_groups if vrf is not None else {}).get(neighbor.peer_group) or \
        bgp.peer_groups.get(neighbor.peer_group)
    if group is None:
        return result
    result.peer_group = ""
    result.remote_as = result.remote_as or group.remote_as
    result.description = result.description or group.description
    result.update_source = result.update_source or group.update_source
    result.shutdown = result.shutdown or group.shutdown
    result.ebgp_multihop = result.ebgp_multihop if result.ebgp_multihop is not None else group.ebgp_multihop
    result.next_hop_self = result.next_hop_self or group.next_hop_self
    result.send_community = result.send_community or group.send_community
    result.bfd = result.bfd or group.bfd
    for attr in ("route_map_in", "route_map_out", "prefix_list_in", "prefix_list_out", "password", "keepalive",
                 "hold", "route_reflector_client", "maximum_prefix", "maximum_prefix_warning", "remove_private_as",
                 "remove_private_as_mode", "allowas_in", "local_as", "local_as_options", "ttl_security"):
        setattr(result, attr, getattr(result, attr) or getattr(group, attr))
    result.families = sorted(set(result.families) | set(group.families))
    return result


def read_aggregate(aggregates: List[BgpAggregate], w: List[str]) -> bool:
    """aggregate-address PREFIX|ADDRESS MASK [summary-only] [as-set] (IOS, EOS, NX-OS)."""
    if len(w) >= 2 and "." in w[1] and "/" not in w[0]:
        prefix, rest = str(ipaddress.ip_network(f"{w[0]}/{w[1]}")), w[2:]
    else:
        prefix, rest = str(ipaddress.ip_network(w[0])), w[1:]
    if not set(rest) <= {"summary-only", "as-set"}:
        return False
    aggregates.append(BgpAggregate(prefix, "summary-only" in rest, "as-set" in rest))
    return True


def aggregate_line(a: BgpAggregate, ios: bool) -> str:
    net = ipaddress.ip_network(a.prefix)
    where = f"{net.network_address} {net.netmask}" if ios and net.version == 4 else str(net)
    return f"aggregate-address {where}" + (" as-set" if a.as_set else "") + (" summary-only" if a.summary_only else "")


def flat(bgp: Bgp) -> List[BgpNeighbor]:
    return [effective(bgp, n) for n in bgp.neighbors]


def remote_as(bgp: Bgp, neighbor: BgpNeighbor) -> Optional[str]:
    if neighbor.remote_as:
        return neighbor.remote_as
    group = bgp.peer_groups.get(neighbor.peer_group)
    return group.remote_as if group is not None and group.remote_as else None


def options(peer: BgpNeighbor) -> List[str]:
    """The OPTIONS keys a neighbor uses."""
    used = [k for k in OPTIONS if k != "timers" and getattr(peer, k) not in (None, False, "")]
    return used + (["timers"] if peer.keepalive is not None or peer.hold is not None else [])


def unwritten(peer: BgpNeighbor, written: Set[str], report: Report, label: str, platform: str) -> None:
    """Reports the neighbor settings a writer leaves out, and a password it has to write as a placeholder."""
    missing = [OPTIONS[k] for k in options(peer) if k not in written]
    if missing:
        report.add("bgp", label, Severity.REVIEW, "bgp-option",
                   f"{', '.join(missing)} not written for {platform}; set {'it' if len(missing) == 1 else 'them'} "
                   "by hand")
    if "password" in written and peer.password == PLACEHOLDER:
        report.add("bgp", label, Severity.REVIEW, "secret-placeholder",
                   f"the session password is stored encrypted in the source; replace {PLACEHOLDER} with it")


def vrf_neighbors(bgp: Bgp) -> List[BgpNeighbor]:
    return [n for v in bgp.vrfs.values() for n in v.neighbors]


def unwritten_vrfs(bgp: Bgp, report: Report, platform: str) -> None:
    """For writers that do not write BGP inside VRFs yet."""
    for name, v in bgp.vrfs.items():
        report.skip("bgp", f"bgp vrf {name}", "not-yet",
                    f"BGP in VRF {name} ({len(v.neighbors)} neighbors) is not written for {platform} yet; set it up "
                    "by hand")
