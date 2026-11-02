# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Junos routing tuning: BFD, ECMP hashing, OSPF authentication and options, and policy-based routing.

How the model maps to Junos:

* BFD has no interface timers of its own on Junos: each protocol session carries them (``bfd-liveness-detection``).
  An OSPF interface takes its port's timers, a BGP peer the timers of the port it is reached through, or the
  multihop timers when it is several hops away.
* The ECMP hash is ``forwarding-options enhanced-hash-key family inet``, which names the fields left out.
* OSPF authentication is MD5 (``authentication md5 N key``), the key a placeholder; a distribute list is an import
  policy, the SPF throttle ``spf-options``, the LSA limit ``database-protection``, graceful restart the routing
  options' one with ``graceful-restart disable`` where a protocol has none.
* Policy-based routing is filter-based forwarding: a filter ``<route map>-FBF`` whose terms send the packets an ACL
  entry picks to a forwarding instance ``<route map>-<entry>`` that routes them to the next hop.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import aaa as aaa_text
from . import bfd as bfd_text
from . import junospolicy
from .junostext import quote
from .model import Acl, AclAction, AclEntry, BgpNeighbor, Device, Interface, Ospf
from .report import Report, Severity

DEFAULT_BFD = (300, 300, 3)  # the EOS default, written where Junos needs an interval and the source has none
FBF = "-FBF"
FIELDS = {"source-ip": "no-ipv4-source-address", "destination-ip": "no-ipv4-destination-address",
          "source-port": "no-l4-source-port", "destination-port": "no-l4-destination-port"}
MIN_HOLDDOWN = 2000

Add = Callable[..., None]
Timers = Tuple[int, int, int]


# BFD ----------------------------------------------------------------------------------------------------------------

def port_timers(iface: Interface) -> Optional[Timers]:
    if not bfd_text.has_timers(iface):
        return None
    return (iface.bfd_interval or DEFAULT_BFD[0], iface.bfd_min_rx or iface.bfd_interval or DEFAULT_BFD[1],
            iface.bfd_multiplier or DEFAULT_BFD[2])


def detection(add: Add, path: Tuple[str, ...], timers: Timers) -> None:
    tx, rx, multiplier = timers
    base = path + ("bfd-liveness-detection",)
    if tx == rx:
        add(*base, f"minimum-interval {tx}")
    else:
        add(*base, "transmit-interval", f"minimum-interval {tx}")
        add(*base, f"minimum-receive-interval {rx}")
    add(*base, f"multiplier {multiplier}")


def read_detection(timers: Dict[str, int], w: List[str]) -> bool:
    if w[0] == "minimum-interval" and len(w) == 2:
        timers.setdefault("tx", int(w[1]))
        timers.setdefault("rx", int(w[1]))
    elif w[:2] == ["transmit-interval", "minimum-interval"] and len(w) == 3:
        timers["tx"] = int(w[2])
    elif w[0] == "minimum-receive-interval" and len(w) == 2:
        timers["rx"] = int(w[1])
    elif w[0] == "multiplier" and len(w) == 2:
        timers["multiplier"] = int(w[1])
    else:
        return False
    return True


def as_timers(timers: Dict[str, int]) -> Timers:
    tx = timers.get("tx", DEFAULT_BFD[0])
    return tx, timers.get("rx", tx), timers.get("multiplier", DEFAULT_BFD[2])


def reached_through(device: Device, address: str) -> Optional[Interface]:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    for iface in device.interfaces.values():
        for a in iface.ipv4 + iface.ipv6:
            net = ipaddress.ip_interface(a.split()[0]).network
            if net.version == ip.version and ip in net:
                return iface
    return None


def multihop(device: Device, p: BgpNeighbor, members: Sequence[BgpNeighbor]) -> bool:
    bgp = device.bgp
    group = bgp.peer_groups.get(p.peer_group) if bgp is not None and p.peer_group else None
    if p.ebgp_multihop or (group is not None and group.ebgp_multihop):
        return True
    source = p.update_source or (group.update_source if group is not None else "")
    if source and source.lower().startswith("loopback"):
        return True
    return bool(members) and all(multihop(device, m, ()) for m in members)


def bgp_timers(device: Device, p: BgpNeighbor, members: Sequence[BgpNeighbor]) -> Tuple[Timers, str, List[str]]:
    """The BFD timers a BGP peer (or a group, from its members) runs with, what they come from ("" = the default),
    and the ports whose timers they are."""
    if multihop(device, p, members):
        if device.bfd_multihop is not None:
            return device.bfd_multihop, "multihop", []
        return DEFAULT_BFD, "", []
    found = set()
    ports: List[str] = []
    for peer in list(members) or [p]:
        iface = reached_through(device, peer.address)
        timers = port_timers(iface) if iface is not None else None
        found.add(timers)
        if iface is not None and timers is not None:
            ports.append(iface.name)
    if len(found) == 1 and None not in found:
        return found.pop(), "port", ports  # type: ignore[return-value]
    return DEFAULT_BFD, "", []


def bfd_global(device: Device, report: Report, multihop_used: bool) -> None:
    hop, slow = device.bfd_multihop, device.bfd_slow_timer
    if hop is None and slow is None:
        return
    label = "BFD"
    report.item("system", label)
    if hop is not None and not multihop_used:
        report.add("system", label, Severity.APPROX, "bfd-multihop",
                   f"Junos sets BFD timers per session; no multihop BFD session uses {hop[0]}/{hop[1]} ms x{hop[2]}, "
                   "so they are left out")
    elif hop is not None:
        report.add("system", label, Severity.APPROX, "bfd-multihop",
                   "the multihop timers are written on each multihop BGP session (bfd-liveness-detection)")
    if slow is not None:
        report.add("system", label, Severity.APPROX, "bfd-slow-timer",
                   f"Junos has no BFD slow timer ({slow} ms); it backs off a session that is down by itself")


# ECMP ---------------------------------------------------------------------------------------------------------------

def ecmp(device: Device, add: Add, report: Report) -> None:
    fields = device.ecmp_hash
    if not fields:
        return
    label = "ECMP hashing"
    report.item("system", label)
    base = ("forwarding-options", "enhanced-hash-key", "family inet")
    add(*base, "no-incoming-port")
    for name, word in FIELDS.items():
        if name not in fields:
            add(*base, word)
    other = [f for f in fields if f not in FIELDS]
    if other:
        report.add("system", label, Severity.APPROX, "ecmp-fields",
                   f"the hash fields {', '.join(other)} have no Junos setting; left to the default")
    report.add("system", label, Severity.APPROX, "ecmp-junos",
               "written in the QFX and EX syntax: the hash leaves out the incoming port and the fields the source does "
               "not hash on; the protocol stays in it")


def read_ecmp(w: List[str], removed: List[str]) -> bool:
    """enhanced-hash-key family inet no-...: the fields left out of the hash."""
    if w[:2] != ["family", "inet"] or len(w) != 3:
        return False
    if w[2] == "no-incoming-port":
        return True
    names = {v: k for k, v in FIELDS.items()}
    if w[2] not in names:
        return False
    removed.append(names[w[2]])
    return True


# OSPF ---------------------------------------------------------------------------------------------------------------

def ospf_interface(device: Device, iface: Interface, path: Tuple[str, ...], add: Add, report: Report, label: str,
                   with_bfd: bool) -> None:
    if iface.ospf_auth == "simple":
        add(*path, "authentication", f"simple-password {quote(aaa_text.PLACEHOLDER)}")
    elif iface.ospf_auth:
        keys = iface.ospf_keys or {1: "md5"}
        for key in keys:
            add(*path, "authentication", f"md5 {key} key {quote(aaa_text.PLACEHOLDER)}")
        sha = sorted({a for a in keys.values() if a != "md5"})
        if sha:
            report.add("interface", label, Severity.APPROX, "ospf-sha",
                       f"the {', '.join(sha)} keys are written as MD5 keys: Junos OSPFv2 takes HMAC-SHA through a key "
                       "chain (authentication keychain)")
    if iface.ospf_auth:
        report.add("interface", label, Severity.REVIEW, "secret-placeholder",
                   f"the OSPF authentication key is not carried over; replace {aaa_text.PLACEHOLDER} with it")
    if with_bfd:
        timers = port_timers(iface)
        detection(add, path, timers or DEFAULT_BFD)
        if timers is None:
            report.add("interface", label, Severity.APPROX, "bfd-timers",
                       "Junos needs a BFD interval: 300 ms x3 written (the EOS default)")


def ospf_options(device: Device, p: Ospf, base: Tuple[str, ...], add: Add, report: Report, label: str) -> None:
    if p.distribute_list_in:
        add(*base, f"import {p.distribute_list_in}")
        report.add("ospf", label, Severity.APPROX, "ospf-import",
                   f"the distribute list is an import policy ({p.distribute_list_in}): Junos filters the external "
                   "routes OSPF installs with it, not the intra-area ones")
    if p.spf_timers is not None:
        initial, hold, maximum = p.spf_timers
        delay = min(max(initial, 50), 8000)
        holddown = min(max(maximum, MIN_HOLDDOWN), 20000)
        add(*base, "spf-options", f"delay {delay}")
        add(*base, "spf-options", f"holddown {holddown}")
        report.add("ospf", label, Severity.APPROX, "ospf-spf",
                   f"the SPF throttle is spf-options delay {delay} and holddown {holddown} ms: Junos has no "
                   f"separate hold time ({hold} ms) and runs three quick SPFs before holding down")
    if p.log_adjacency == "detail":
        report.add("ospf", label, Severity.APPROX, "ospf-log",
                   "Junos logs adjacency changes itself (RPD_OSPF_NBRUP and NBRDOWN); the detail of every state "
                   "change needs traceoptions, left out")
    if p.lsa_arrival is not None:
        report.add("ospf", label, Severity.APPROX, "ospf-lsa-arrival",
                   f"Junos has no LSA arrival timer ({p.lsa_arrival} ms); left out")
    if p.max_lsa:
        parsed = parse_max_lsa(p.max_lsa)
        if parsed is None:
            report.add("ospf", label, Severity.REVIEW, "ospf-max-lsa",
                       f"max-lsa {p.max_lsa} could not be translated; left out")
        else:
            for word in parsed:
                add(*base, "database-protection", word)
            report.add("ospf", label, Severity.APPROX, "ospf-max-lsa",
                       "max-lsa is database-protection (its times in seconds); Junos counts the non-self-generated "
                       "LSAs the same way, check the platform supports it")


def parse_max_lsa(text: str) -> Optional[List[str]]:
    """IOS and EOS max-lsa N [P] [warning-only] [ignore-time M] [ignore-count C] [reset-time M] as
    database-protection statements (the times from minutes to seconds)."""
    w = text.split()
    if not w or not w[0].isdigit():
        return None
    out = [f"maximum-lsa {w[0]}"]
    rest = w[1:]
    if rest and rest[0].isdigit():
        out.append(f"warning-threshold {rest[0]}")
        rest = rest[1:]
    while rest:
        if rest[0] == "warning-only":
            out.append("warning-only")
            rest = rest[1:]
        elif rest[0] in ("ignore-time", "reset-time") and len(rest) >= 2 and rest[1].isdigit():
            out.append(f"{rest[0]} {int(rest[1]) * 60}")
            rest = rest[2:]
        elif rest[0] == "ignore-count" and len(rest) >= 2 and rest[1].isdigit():
            out.append(f"ignore-count {rest[1]}")
            rest = rest[2:]
        else:
            return None
    return out


def max_lsa_text(settings: Dict[str, str]) -> str:
    words = [settings["maximum-lsa"]]
    if "warning-threshold" in settings:
        words.append(settings["warning-threshold"])
    if "warning-only" in settings:
        words.append("warning-only")
    for key in ("ignore-time", "ignore-count", "reset-time"):
        if key in settings:
            value = int(settings[key])
            words += [key, str(value // 60 if key != "ignore-count" else value)]
    return " ".join(words)


def graceful_restart(device: Device, add: Add, instance: Callable[[str], str]) -> None:
    """One graceful restart for the routing options; a protocol without it says so."""
    bgp = device.bgp
    if not any(p.graceful_restart for p in device.ospf) and not (bgp is not None and bgp.graceful_restart):
        return
    add("routing-options", "graceful-restart")
    if bgp is not None and not bgp.graceful_restart:
        add("protocols", "bgp", "graceful-restart", "disable")
    for p in device.ospf:
        if not p.graceful_restart:
            base = ("routing-instances", instance(p.vrf), "protocols", "ospf") if p.vrf else ("protocols", "ospf")
            add(*base, "graceful-restart", "disable")


# policy-based routing -------------------------------------------------------------------------------------------------

def fbf_name(route_map: str) -> str:
    return route_map + FBF


def pbr(device: Device, add: Add, report: Report, vrf_of: Callable[[str], str],
        instance: Callable[[str], str]) -> Dict[str, str]:
    """Each PBR route map as filter-based forwarding; returns route map -> filter."""
    names: Dict[str, str] = {}
    for name in bfd_text.pbr_only(device):
        label = f"route-map {name}"
        report.item("policy", label)
        entries = bfd_text.pbr_entries(device, name, report, "Junos")
        if not entries:
            continue
        vrfs = sorted({vrf_of(i.name) for i in device.interfaces.values() if i.pbr == name})
        filter_name = fbf_name(name)
        base = ("firewall", "family inet", f"filter {filter_name}")
        for seq, acls, next_hop in entries:
            target = f"{name}-{seq}"
            if not next_hop:
                report.add("policy", label, Severity.REVIEW, "pbr-next-hop",
                           f"entry {seq} sets no next hop; left out")
                continue
            n = 0
            for acl_name in acls:
                acl = device.acls.get(acl_name)
                if acl is None or acl.family == 6:
                    report.add("policy", label, Severity.REVIEW, "pbr-acl",
                               f"entry {seq}: ACL {acl_name} is missing or IPv6; left out")
                    continue
                for e in acl.entries:
                    if e.action == AclAction.REMARK:
                        continue
                    if e.unsupported:
                        report.add("policy", label, Severity.REVIEW, "pbr-acl",
                                   f"entry {seq}: '{e.unsupported}' of {acl_name} is not converted; left out")
                        continue
                    n += 1
                    term = base + (f"term {seq}-{n}",)
                    for word in junospolicy.from_words(e, 4, label, report):
                        add(*term, "from", word)
                    add(*term, "then", f"routing-instance {target}" if e.action == AclAction.PERMIT else "accept")
            ri = ("routing-instances", target)
            add(*ri, "instance-type forwarding")
            add(*ri, "routing-options", "static", "route 0.0.0.0/0", f"next-hop {next_hop}")
        add(*base, "term default", "then accept")
        names[name] = filter_name
        for vrf in vrfs:
            group = f"RS-PBR-{instance(vrf)}" if vrf else "RS-PBR"
            table = f"{instance(vrf)}.inet.0" if vrf else "inet.0"
            add("routing-options", "rib-groups", group, f"import-rib {table}")
            for seq, _, next_hop in entries:
                if next_hop:
                    add("routing-options", "rib-groups", group, f"import-rib {name}-{seq}.inet.0")
            where = ("routing-instances", instance(vrf), "routing-options") if vrf else ("routing-options",)
            add(*where, "interface-routes", "rib-group", f"inet {group}")
        report.add("policy", label, Severity.APPROX, "pbr-fbf",
                   f"written as filter-based forwarding: filter {filter_name} sends the packets each ACL entry picks "
                   "to a forwarding instance with a default route to the next hop; a rib group shares the interface "
                   "routes so the next hop resolves")
    return names


class PbrReader:
    """Filter-based forwarding back into PBR route maps and their ACLs."""

    def __init__(self, device: Device) -> None:
        self.device = device
        self.next_hops: Dict[str, str] = {}  # forwarding instance -> next hop
        self.forwarding: List[str] = []

    def instance(self, name: str, w: List[str]) -> bool:
        if w == ["instance-type", "forwarding"]:
            self.forwarding.append(name)
            return True
        if w[:4] == ["routing-options", "static", "route", "0.0.0.0/0"] and len(w) == 6 and w[4] == "next-hop":
            self.next_hops[name] = w[5]
            return True
        return False

    @staticmethod
    def rib_group(w: List[str]) -> bool:
        """The rib groups RouterShift writes for filter-based forwarding."""
        if w[0] == "rib-groups" and len(w) == 4 and w[1].startswith("RS-PBR") and w[2] == "import-rib":
            return True
        return w[:3] == ["interface-routes", "rib-group", "inet"] and len(w) == 4 and w[3].startswith("RS-PBR")

    def finish(self, filters: Dict[str, junospolicy.Policy], unread: Callable[[int, str, str], None]) -> Dict[str, str]:
        """Route maps rebuilt from the filters; returns filter -> route map."""
        from . import routemap as routemap_text
        dev = self.device
        out: Dict[str, str] = {}
        for fname, policy in filters.items():
            name = fname[:-len(FBF)] if fname.endswith(FBF) else fname
            rm = routemap_text.route_map(dev, name)
            per_entry: Dict[int, List[AclEntry]] = {}
            targets: Dict[int, str] = {}
            for term in policy.terms.values():
                if term.name == "default" and term.thens == [["accept"]] and not term.froms:
                    continue
                m = re.fullmatch(r"(\d+)-\d+", term.name)
                seq = int(m.group(1)) if m else 10 * (len(per_entry) + 1)
                target = next((t[1] for t in term.thens if t[0] == "routing-instance" and len(t) == 2), "")
                action = AclAction.PERMIT if target else AclAction.DENY
                entries = junospolicy.Reader._entries(term, "inet", action, False, None)
                if entries is None or (not target and term.thens != [["accept"]]):
                    unread(term.line, f"set firewall family inet filter {fname} term {term.name}",
                           "a filter-based forwarding term RouterShift cannot hold")
                    continue
                per_entry.setdefault(seq, []).extend(entries)
                if target:
                    targets[seq] = target
            for seq, entries in per_entry.items():
                e = routemap_text.entry(rm, seq, "permit")
                hop = self.next_hops.get(targets.get(seq, ""), "")
                if hop:
                    e.sets["next-hop"] = hop
                e.match_acls.append(self._acl(entries, f"{name}-{seq}"))
            out[fname] = name
        for name in self.forwarding:
            if name not in self.next_hops:
                unread(0, f"set routing-instances {name} instance-type forwarding",
                       "a forwarding instance without a default route")
        return out

    def _acl(self, entries: List[AclEntry], fallback: str) -> str:
        def key(es: List[AclEntry]) -> List[Tuple[object, ...]]:
            return [(e.action, e.protocol, e.source, e.destination, e.src_ports, e.dst_ports, e.icmp_type,
                     e.established) for e in es if e.action != AclAction.REMARK and not e.unsupported]
        for acl in self.device.acls.values():
            if acl.family == 4 and key(acl.entries) == key(entries):
                return acl.name
        acl = self.device.acls.setdefault(fallback, Acl(fallback, 4))
        acl.entries = entries
        return fallback



