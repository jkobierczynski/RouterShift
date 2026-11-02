# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Junos routing policy and firewall filters: prefix lists, route maps (policy statements), community and AS-path
lists, the export policies that stand in for IOS redistribution and network statements, and ACLs (firewall filters).

How the model maps to Junos:

* A prefix list whose entries all match one exact prefix is a ``prefix-list``; one with ``ge``/``le`` becomes a
  ``route-filter-list`` (``upto /N``, ``prefix-length-range /A-/B``). Junos has no deny entry in either.
* A route map is a ``policy-statement`` with one term per entry, named by its sequence number. IOS denies what no
  entry matches; Junos would fall through to the protocol's default, so a last term ``implicit-deny`` rejects.
* Redistribution into OSPF and BGP and BGP network statements are export policies (``OSPF-EXPORT``,
  ``BGP-EXPORT``, ``<VRF>-BGP-EXPORT``); a route map on a redistribution is called from the term as a subroutine.
* A prefix list on a BGP neighbor is a policy ``PREFIX-LIST-<name>`` that passes what the list matches on to the
  next policy and rejects the rest.
* An ACL is a firewall filter with one term per entry. Its implicit deny is Junos' own.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import AbstractSet, Callable, Dict, List, Optional, Sequence, Tuple

from . import acl as acl_text
from . import routemap as routemap_text
from .junostext import quote
from .model import (Acl, AclAction, AclEntry, AsPathList, BgpAggregate, CommunityList, Device, PrefixEntry, PrefixList,
                    RouteMap, RouteMapEntry)
from .report import Report, Severity

PROTOCOLS = {"connected": "direct", "static": "static", "ospf": "ospf", "bgp": "bgp", "rip": "rip", "isis": "isis"}
FROM_PROTOCOL = {v: k for k, v in PROTOCOLS.items()}
IMPLICIT = "implicit-deny"
PREFIX_POLICY = "PREFIX-LIST-"
_ICMP6 = {1: "destination-unreachable", 2: "packet-too-big", 3: "time-exceeded", 128: "echo-request",
          129: "echo-reply", 133: "router-solicit", 134: "router-advertisement", 135: "neighbor-solicit",
          136: "neighbor-advertisement"}
_ICMP4 = {0: "echo-reply", 3: "unreachable", 4: "source-quench", 5: "redirect", 8: "echo-request",
          11: "time-exceeded", 12: "parameter-problem", 13: "timestamp", 14: "timestamp-reply"}
_ICMP_READ = {"inet": {**{v: k for k, v in _ICMP4.items()}, "echo": 8, "destination-unreachable": 3},
              "inet6": {v: k for k, v in _ICMP6.items()}}

Add = Callable[..., None]
MAC_MATCHES = ("source-mac-address", "destination-mac-address", "ether-type", "learn-vlan-id", "user-vlan-id")


# writing ------------------------------------------------------------------------------------------------------------

def _match_type(prefix: str, ge: Optional[int], le: Optional[int]) -> str:
    """The route-filter match type of an IOS prefix-list entry."""
    net = ipaddress.ip_network(prefix)
    top = net.max_prefixlen
    low = ge if ge is not None else net.prefixlen
    high = le if le is not None else (top if ge is not None else net.prefixlen)
    if low == net.prefixlen and high == net.prefixlen:
        return "exact"
    if low == net.prefixlen and high == top:
        return "orlonger"
    if low == net.prefixlen:
        return f"upto /{high}"
    if low == net.prefixlen + 1 and high == top:
        return "longer"
    return f"prefix-length-range /{low}-/{high}"


def is_plain(pl: PrefixList) -> bool:
    return all(e.ge is None and e.le is None and e.action == AclAction.PERMIT for e in pl.entries)


def prefix_lists(device: Device, add: Add, report: Report) -> Dict[str, str]:
    """Each prefix list as a prefix-list or route-filter-list; returns name -> the word a policy matches it with."""
    kinds: Dict[str, str] = {}
    for pl in device.prefix_lists.values():
        label = routemap_text.label(pl.name, "prefix-list")
        report.item("policy", label)
        denies = [e for e in pl.entries if e.action == AclAction.DENY]
        if denies:
            report.add("policy", label, Severity.REVIEW, "pl-deny",
                       "Junos prefix lists have no deny entries; entries " + ", ".join(str(e.seq) for e in denies) +
                       " are left out, so the list matches more than before: exclude those prefixes in the policy "
                       "terms that use it")
        if is_plain(pl):
            kinds[pl.name] = "prefix-list"
            for e in pl.entries:
                add("policy-options", f"prefix-list {pl.name}", str(ipaddress.ip_network(e.prefix)))
            if not pl.entries:
                add("policy-options", f"prefix-list {pl.name}")
            continue
        kinds[pl.name] = "route-filter-list"
        for e in pl.entries:
            if e.action == AclAction.PERMIT:
                add("policy-options", f"route-filter-list {pl.name}",
                    f"{ipaddress.ip_network(e.prefix)} {_match_type(e.prefix, e.ge, e.le)}")
    return kinds


def as_path_regex(regex: str) -> str:
    """An IOS AS-path expression in Junos' form, which works on whole AS numbers: no anchors, '.' for any AS."""
    text = regex.strip()
    text = text[1:] if text.startswith("^") else text
    text = text[:-1] if text.endswith("$") else text
    text = re.sub(r"\[0-9\]\+|\\d\+|\[0-9\]\*", ".", text)
    text = text.replace("_", " ")
    text = re.sub(r"\(\s*", "(", re.sub(r"\s*\)", ")", text))
    text = re.sub(r"([)*+?}])(?=[\w.(])", r"\1 ", text)  # a space between one term and the next
    text = re.sub(r"(\w)\(", r"\1 (", text)
    return re.sub(r"\s+", " ", text).strip() or "()"


def lists(device: Device, add: Add, report: Report) -> Dict[str, List[str]]:
    """Community lists and AS-path lists; returns community list -> the Junos communities it became."""
    communities: Dict[str, List[str]] = {}
    for cl in device.community_lists.values():
        label = routemap_text.label(cl.name, "community-list")
        report.item("policy", label)
        names: List[str] = []
        permits = [value for action, value in cl.entries if action == "permit"]
        if len(permits) < len(cl.entries):
            report.add("policy", label, Severity.REVIEW, "community-deny",
                       "Junos communities have no deny entries; they are left out")
        for n, value in enumerate(permits):
            name = cl.name if n == 0 else f"{cl.name}-{n + 1}"
            names.append(name)
            if cl.expanded:
                add("policy-options", f"community {name}", f"members {quote(value)}")
                report.add("policy", label, Severity.APPROX, "community-regex",
                           "the regular expression is written as it is; check it against Junos' community syntax")
            else:
                for member in value.split():
                    add("policy-options", f"community {name}", f"members {member}")
        communities[cl.name] = names
    for apl in device.as_path_lists.values():
        label = routemap_text.label(apl.name, "as-path list")
        report.item("policy", label)
        permits = [regex for action, regex in apl.entries if action == "permit"]
        if len(permits) < len(apl.entries):
            report.add("policy", label, Severity.REVIEW, "as-path-deny",
                       "Junos AS paths have no deny entries; they are left out")
        if len(permits) == 1:
            add("policy-options", f"as-path {apl.name} {quote(as_path_regex(permits[0]))}")
        else:
            for n, regex in enumerate(permits, 1):
                add("policy-options", f"as-path-group {apl.name}", f"as-path {apl.name}-{n} {quote(as_path_regex(regex))}")
        report.add("policy", label, Severity.APPROX, "as-path-regex",
                   "Junos AS-path expressions match whole AS numbers; '" + "', '".join(permits) + "' is written as '" +
                   "', '".join(as_path_regex(r) for r in permits) + "': check it")
    return communities


def _community_name(device: Device, rm: RouteMap, e: RouteMapEntry, rt: bool) -> str:
    return f"{rm.name}-{e.seq}" + ("-RT" if rt else "")


def policies(device: Device, add: Add, report: Report, kinds: Dict[str, str],
             communities: Dict[str, List[str]], skip: AbstractSet[str] = frozenset()) -> None:
    """Each route map as a policy statement (those in skip are written another way)."""
    for rm in device.route_maps.values():
        if rm.name in skip:
            continue
        label = routemap_text.label(rm.name, "route-map")
        report.item("policy", label)
        if not rm.entries:
            report.skip("policy", label, "rm-empty", "no entry of it could be read; it is not written")
            continue
        base = ("policy-options", f"policy-statement {rm.name}")
        catch_all = False
        for e in rm.entries:
            matches = [c for c in e.unconverted if c.startswith("match")]
            sets = [c for c in e.unconverted if not c.startswith("match")]
            if e.match_acls:
                matches.append("match ip address " + " ".join(e.match_acls))
            if matches:
                routemap_text.skipped_entry(rm, e, matches, report, "#", "entry")
                continue
            if "weight" in e.sets:
                sets.append(f"set weight {e.sets['weight']}")
            routemap_text.unwritten_sets(rm, e, sets, report)
            term = base + (f"term {e.seq}",)
            froms = []
            for name in e.match_prefix_lists + e.match_prefix_lists6:
                froms.append(f"{kinds.get(name, 'prefix-list')} {name}")
            if e.match_tags:
                froms.append(f"tag {e.match_tags[0]}")
                if len(e.match_tags) > 1:
                    report.add("policy", label, Severity.REVIEW, "rm-match-many",
                               f"entry {e.seq} matches any of tags {e.match_tags}; Junos takes one, "
                               f"{e.match_tags[0]} is written")
            for name in e.match_as_paths:
                apl = device.as_path_lists.get(name)
                plain = apl is not None and len([a for a, _ in apl.entries if a == "permit"]) == 1
                froms.append(f"as-path {name}" if plain else f"as-path-group {name}")
            for name in e.match_communities:
                for junos_name in communities.get(name, [name]):
                    froms.append(f"community {junos_name}")
            if e.match_rpki:
                froms.append("validation-database " + {"not-found": "unknown"}.get(e.match_rpki, e.match_rpki))
                report.add("policy", label, Severity.REVIEW, "rm-rpki",
                           f"entry {e.seq} matches the RPKI state {e.match_rpki}; the RPKI servers (routing-options "
                           "validation) are not converted, so add them or the term matches nothing")
            for f in froms:
                add(*term, "from", f)
            if not froms:
                catch_all = True
            then = term + ("then",)
            for key in routemap_text.SET_KEYS:
                value = e.sets.get(key)
                if value is None or key == "weight":
                    continue
                if key in ("local-preference", "metric", "tag"):
                    add(*then, f"{key} {value}")
                elif key == "metric-type":
                    add(*then, f"external type {value[-1]}")
                elif key == "next-hop":
                    add(*then, f"next-hop {value}")
                elif key == "origin":
                    add(*then, f"origin {value}")
                elif key == "as-path-prepend":
                    add(*then, f"as-path-prepend {quote(value)}")
                elif key in ("community", "extcommunity-rt"):
                    rt = key == "extcommunity-rt"
                    name = _community_name(device, rm, e, rt)
                    for member in value.split():
                        add("policy-options", f"community {name}",
                            f"members {'target:' + member if rt else member}")
                    additive = e.extcommunity_additive if rt else e.community_additive
                    add(*then, f"community {'add' if additive else 'set'} {name}")
            add(*then, "accept" if e.action == AclAction.PERMIT else "reject")
            if e.description:
                report.add("policy", label, Severity.APPROX, "rm-description",
                           f"entry {e.seq}: Junos terms have no description; '{e.description}' is left out")
        if not catch_all:
            add(*base, f"term {IMPLICIT}", "then reject")


def prefix_policy(add: Add, name: str, kinds: Dict[str, str]) -> str:
    """A policy that passes the routes a prefix list matches on to the next policy and rejects the rest."""
    policy = f"{PREFIX_POLICY}{name}"
    base = ("policy-options", f"policy-statement {policy}")
    add(*base, "term match", "from", f"{kinds.get(name, 'prefix-list')} {name}")
    add(*base, "term match", "then next policy")
    add(*base, f"term {IMPLICIT}", "then reject")
    return policy


def export_policy(add: Add, name: str, sources: Sequence[str], maps: Dict[str, str], networks: Sequence[str] = (),
                  default: str = "", metric_type: str = "", ospf_match: Sequence[str] = (),
                  aggregates: Sequence[BgpAggregate] = ()) -> None:
    """The export policy that redistributes sources (connected, static, ...), announces networks and aggregates,
    and keeps the routes a summary-only aggregate covers to itself."""
    base = ("policy-options", f"policy-statement {name}")
    summary = [a for a in aggregates if a.summary_only]
    for a in summary:
        add(*base, "term summary-only", "from", f"route-filter {ipaddress.ip_network(a.prefix)} longer")
    if summary:
        add(*base, "term summary-only", "then reject")
    for a in aggregates:
        add(*base, "term aggregates", "from", f"route-filter {ipaddress.ip_network(a.prefix)} exact")
    if aggregates:
        add(*base, "term aggregates", "from", "protocol aggregate")
        add(*base, "term aggregates", "then accept")
    for source in sources:
        term = base + (f"term {source}",)
        add(*term, "from", f"protocol {PROTOCOLS.get(source, source)}")
        if source == "ospf":
            for kind in dict.fromkeys("internal" if k == "internal" else "external" for k in ospf_match):
                add(*term, "from", f"route-type {kind}")
        if source in maps:
            add(*term, "from", f"policy {maps[source]}")
        if metric_type:
            add(*term, "then", f"external type {metric_type}")
        add(*term, "then accept")
    if networks:
        for prefix in networks:
            add(*base, "term networks", "from", f"route-filter {ipaddress.ip_network(prefix)} exact")
        add(*base, "term networks", "then accept")
    if default:
        term = base + ("term default-route" + ("-always" if default == "always" else ""),)
        add(*term, "from", "route-filter 0.0.0.0/0 exact")
        add(*term, "then accept")


# firewall filters ---------------------------------------------------------------------------------------------------

def _ports(ports: str) -> List[str]:
    return [p for p in ports.split(",") if p]


def filters(device: Device, add: Add, report: Report, switching: Sequence[str] = ()) -> Dict[str, str]:
    """Each ACL as a firewall filter, and as an ethernet-switching filter too when it is on a switch port (named in
    ``switching``); returns ACL -> filter name."""
    names: Dict[str, str] = {}
    for acl in device.acls.values():
        name = acl_text.safe_name(acl.name)
        label = acl.name if name == acl.name else f"{acl.name} -> {name}"
        names[acl.name] = name
        report.item("acl", label)
        family = "inet6" if acl.family == 6 else "inet"
        _filter(acl, ("firewall", f"family {family}", f"filter {name}"), add, report, label, False)
        if acl.name in switching and acl.family != 6:
            _filter(acl, ("firewall", "family ethernet-switching", f"filter {name}"), add, report, label, True)
    return names


def _filter(acl: Acl, base: Tuple[str, ...], add: Add, report: Report, label: str, switch: bool) -> None:
    remarks = 0
    used = set()
    for n, entry in enumerate(acl.entries, 1):
        seq = entry.sequence or n * 10
        while seq in used:
            seq += 1
        used.add(seq)
        if entry.action == AclAction.REMARK:
            remarks += 1
            continue
        if entry.unsupported:
            report.add("acl", label, Severity.REVIEW, "acl-entry",
                       f"entry '{entry.unsupported}' not converted; add it to the filter by hand")
            continue
        term = base + (f"term {seq}",)
        words = from_words(entry, acl.family, label, report)
        for word in to_switching(words) if switch else words:
            add(*term, "from", word)
        if entry.log:
            add(*term, "then log")
        add(*term, "then", "accept" if entry.action == AclAction.PERMIT else "discard")
    if remarks and not switch:
        report.add("acl", label, Severity.APPROX, "acl-remark",
                   "Junos filter terms have no remarks; the remarks are left out")
    if not acl.entries:
        add(*base, "term default", "then discard")


def from_words(entry: AclEntry, family: int, label: str, report: Report) -> List[str]:
    out: List[str] = []
    if entry.source != "any":
        out.append(f"source-address {entry.source}")
    if entry.destination != "any":
        out.append(f"destination-address {entry.destination}")
    protocol = entry.protocol
    word = "next-header" if family == 6 else "protocol"
    if protocol not in ("ip", ""):
        name = "icmp6" if protocol in ("icmpv6", "icmp") and family == 6 else protocol
        out.append(f"{word} {name}")
    for port in _ports(entry.src_ports):
        out.append(f"source-port {port}")
    for port in _ports(entry.dst_ports):
        out.append(f"destination-port {port}")
    if entry.icmp_type is not None:
        names = _ICMP6 if family == 6 else _ICMP4
        out.append(f"icmp-type {names.get(entry.icmp_type, str(entry.icmp_type))}")
    if entry.established:
        out.append("tcp-established")
    return out


_TO_SWITCHING = {"source-address": "ip-source-address", "destination-address": "ip-destination-address",
                 "protocol": "ip-protocol"}


def to_switching(words: List[str]) -> List[str]:
    """The matches of an inet filter term in the words of an ethernet-switching filter."""
    out = []
    for word in words:
        key, _, value = word.partition(" ")
        out.append(f"{_TO_SWITCHING.get(key, key)} {value}".strip())
    return out


_FROM_SWITCHING = {"ip-source-address": "source-address", "ip-destination-address": "destination-address",
                   "ip-protocol": "protocol", "ip-address": "address"}


def to_inet(words: List[str]) -> List[str]:
    """A match of an ethernet-switching filter in the words of an inet one."""
    return [_FROM_SWITCHING.get(words[0], words[0])] + words[1:] if words else words


# reading ------------------------------------------------------------------------------------------------------------

@dataclass
class Term:
    name: str
    line: int = 0
    froms: List[List[str]] = field(default_factory=list)
    thens: List[List[str]] = field(default_factory=list)


@dataclass
class Policy:
    name: str
    line: int = 0
    terms: Dict[str, Term] = field(default_factory=dict)

    def term(self, name: str, line: int) -> Term:
        if name not in self.terms:
            self.terms[name] = Term(name, line)
        return self.terms[name]


class Reader:
    """Collects policy-options and firewall statements, and turns them into the model once the protocols that use
    them are known."""

    def __init__(self, device: Device) -> None:
        self.device = device
        self.policies: Dict[str, Policy] = {}
        self.communities: Dict[str, List[str]] = {}
        self.community_lines: Dict[str, int] = {}
        self.filters: Dict[Tuple[str, str], Policy] = {}  # (family, name)
        self.qos_filters: Dict[Tuple[str, str], Policy] = {}  # filters with QoS actions
        self.mac_filters: Dict[str, Policy] = {}  # ethernet-switching filters that match MAC addresses
        self.fbf_filters: Dict[str, Policy] = {}  # filter-based forwarding (policy-based routing)
        self.route_filters: Dict[str, str] = {}  # route-filter-list or prefix-list name -> kind
        self.used_as_export: Dict[str, str] = {}  # policy -> what exports it ("bgp", "ospf", ...)
        self.aggregates: Dict[str, List[BgpAggregate]] = {}  # export policy -> the aggregates it announces

    def policy_options(self, line: int, w: List[str]) -> bool:
        if not w:
            return False
        if w[0] == "prefix-list" and len(w) in (2, 3):
            family = "ipv6" if len(w) == 3 and ":" in w[2] else "ipv4"
            pl = routemap_text.prefix_list(self.device, w[1], family)
            pl.origin.line = pl.origin.line or line
            self.route_filters[w[1]] = "prefix-list"
            if len(w) == 3:
                prefix = str(ipaddress.ip_network(w[2]))
                pl.family = "ipv6" if ":" in prefix else "ipv4"
                pl.entries.append(PrefixEntry(10 * (len(pl.entries) + 1), AclAction.PERMIT, prefix))
            return True
        if w[0] == "route-filter-list" and len(w) >= 4:
            prefix = str(ipaddress.ip_network(w[2]))
            bounds = _read_match(prefix, w[3:])
            if bounds is None:
                return False
            pl = routemap_text.prefix_list(self.device, w[1], "ipv6" if ":" in prefix else "ipv4")
            pl.origin.line = pl.origin.line or line
            self.route_filters[w[1]] = "route-filter-list"
            pl.entries.append(PrefixEntry(10 * (len(pl.entries) + 1), AclAction.PERMIT, prefix, *bounds))
            return True
        if w[0] == "community" and len(w) == 4 and w[2] == "members":
            self.communities.setdefault(w[1], []).append(w[3])
            self.community_lines.setdefault(w[1], line)
            return True
        if w[0] == "as-path" and len(w) == 3:
            apl = self.device.as_path_lists.setdefault(w[1], AsPathList(w[1]))
            apl.origin.line = apl.origin.line or line
            apl.entries.append(("permit", w[2]))
            return True
        if w[0] == "as-path-group" and len(w) == 5 and w[2] == "as-path":
            apl = self.device.as_path_lists.setdefault(w[1], AsPathList(w[1]))
            apl.origin.line = apl.origin.line or line
            apl.entries.append(("permit", w[4]))
            return True
        if w[0] == "policy-statement" and len(w) >= 4 and w[2] in ("term", "from", "then"):
            policy = self.policies.setdefault(w[1], Policy(w[1], line))
            if w[2] == "term":
                term, rest = policy.term(w[3], line), w[4:]
            else:  # the policy's own final, unnamed term
                term, rest = policy.term("", line), w[2:]
            if rest[:1] == ["from"] and len(rest) >= 2:
                term.froms.append(rest[1:])
                return True
            if rest[:1] == ["then"] and len(rest) >= 2:
                term.thens.append(rest[1:])
                return True
            return not rest
        return False

    def firewall(self, line: int, w: List[str]) -> bool:
        if w[:1] == ["family"] and len(w) >= 2:
            family, w = w[1], w[2:]
        else:
            family = "inet"
        if family not in ("inet", "inet6", "ethernet-switching") or len(w) < 4 or w[0] != "filter" or \
                w[2] != "term":
            return False
        policy = self.filters.setdefault((family, w[1]), Policy(w[1], line))
        term = policy.term(w[3], line)
        rest = w[4:]
        if rest[:1] == ["from"] and len(rest) >= 2:
            term.froms.append(rest[1:])
        elif rest[:1] == ["then"] and len(rest) >= 2:
            term.thens.append(rest[1:])
        else:
            return False
        return True

    # turning statements into the model --------------------------------------------------------------------------

    def finish(self, unread: Callable[[int, str, str], None]) -> None:
        for (family, name), policy in self.filters.items():
            if any(t and t[0] in ("policer", "dscp", "forwarding-class", "loss-priority")
                   for term in policy.terms.values() for t in term.thens):
                self.qos_filters[(family, name)] = policy  # a QoS policy: read with class of service
                continue
            if family == "inet" and any(t and t[0] == "routing-instance" for term in policy.terms.values()
                                        for t in term.thens):
                self.fbf_filters[name] = policy  # policy-based routing: read once the forwarding instances are known
                continue
            if family == "ethernet-switching" and any(f and f[0] in MAC_MATCHES for term in policy.terms.values()
                                                      for f in term.froms):
                self.mac_filters[name] = policy  # a MAC ACL
                continue
            if family == "ethernet-switching":
                if ("inet", name) in self.filters:
                    continue  # the same ACL, written for switch ports too
                for term in policy.terms.values():
                    term.froms = [to_inet(f) for f in term.froms]
                family = "inet"
            self.acl(family, policy, unread)
        for name in self.communities:
            values = self.communities[name]
            if any(v.startswith("target:") for v in values) or self._generated_community(name) or \
                    re.match(r"^.+-RT-(IMPORT|EXPORT)$", name):
                continue
            cl = self.device.community_lists.setdefault(name, CommunityList(name))
            cl.origin.line = self.community_lines[name]
            if any(re.search(r"[\^$*+?\[\]|]", v) for v in values):
                cl.expanded = True
            cl.entries.append(("permit", " ".join(values)))
        self._merge_community_lists()
        for name, policy in self.policies.items():
            if name.startswith(PREFIX_POLICY) and name[len(PREFIX_POLICY):] in self.route_filters:
                continue
            if name in self.used_as_export:
                continue
            self.route_map(policy, unread)

    def _generated_community(self, name: str) -> bool:
        """A community a policy sets, written by RouterShift as ROUTEMAP-SEQ: read back as the set's values."""
        m = re.match(r"^(.+)-(\d+)(-RT)?$", name)
        return bool(m and m.group(1) in self.policies and m.group(2) in self.policies[m.group(1)].terms)

    def _merge_community_lists(self) -> None:
        """NAME, NAME-2, NAME-3 (one Junos community per entry of a list) are one community list again."""
        for name in list(self.device.community_lists):
            m = re.match(r"^(.+)-(\d+)$", name)
            if m and m.group(1) in self.device.community_lists and int(m.group(2)) >= 2:
                self.device.community_lists[m.group(1)].entries += self.device.community_lists.pop(name).entries

    def acl(self, family: str, policy: Policy, unread: Callable[[int, str, str], None]) -> None:
        acl = self.device.acls.setdefault(policy.name, Acl(policy.name, 6 if family == "inet6" else 4))
        for term in policy.terms.values():
            if term.name == "default" and not term.froms and term.thens == [["discard"]]:
                continue
            action: Optional[AclAction] = None
            log = False
            ok = True
            for t in term.thens:
                if t in (["accept"],):
                    action = AclAction.PERMIT
                elif t in (["discard"], ["reject"]):
                    action = AclAction.DENY
                elif t in (["log"], ["syslog"]):
                    log = True
                elif t[0] == "count" and len(t) == 2:
                    pass
                else:
                    ok = False
            seq = int(term.name) if term.name.isdigit() else None
            if not ok or action is None:
                acl.entries.append(acl_text.unsupported_entry(f"term {term.name}", seq))
                unread(term.line, f"set firewall family {family} filter {policy.name} term {term.name}",
                       "a filter term whose action RouterShift cannot hold")
                continue
            entries = self._entries(term, family, action, log, seq)
            if entries is None:
                acl.entries.append(acl_text.unsupported_entry(f"term {term.name}", seq))
                unread(term.line, f"set firewall family {family} filter {policy.name} term {term.name}",
                       "a filter term with a match RouterShift cannot hold")
                continue
            acl.entries += entries

    @staticmethod
    def _entries(term: Term, family: str, action: AclAction, log: bool, seq: Optional[int]) -> Optional[List[AclEntry]]:
        sources: List[str] = []
        destinations: List[str] = []
        protocol = "ip"
        src_ports: List[str] = []
        dst_ports: List[str] = []
        icmp: Optional[int] = None
        established = False
        for f in term.froms:
            if f[0] in ("source-address", "destination-address", "address") and len(f) == 2:
                net = str(ipaddress.ip_network(f[1], strict=False))
                (sources if f[0] == "source-address" else destinations).append(net)
            elif f[0] in ("protocol", "next-header") and len(f) == 2:
                protocol = {"icmp6": "icmpv6", "icmpv6": "icmpv6"}.get(f[1], f[1])
            elif f[0] in ("source-port", "destination-port") and len(f) == 2:
                value = f[1]
                if not re.match(r"^\d+(-\d+)?$", value):
                    value = str(acl_text.port_number(value))
                (src_ports if f[0] == "source-port" else dst_ports).append(value)
            elif f[0] in ("icmp-type", "icmp6-type") and len(f) == 2:
                icmp = int(f[1]) if f[1].isdigit() else _ICMP_READ[family].get(f[1])
                if icmp is None:
                    return None
            elif f == ["tcp-established"]:
                established = True
            else:
                return None
        if family == "inet6" and protocol == "icmp":
            protocol = "icmpv6"
        out: List[AclEntry] = []
        for source in sources or ["any"]:
            for destination in destinations or ["any"]:
                out.append(AclEntry(action, sequence=seq if not out else None, protocol=protocol, source=source,
                                    destination=destination, src_ports=",".join(src_ports),
                                    dst_ports=",".join(dst_ports), icmp_type=icmp, established=established, log=log))
        return out

    def route_map(self, policy: Policy, unread: Callable[[int, str, str], None]) -> None:
        rm = routemap_text.route_map(self.device, policy.name)
        rm.origin.line = policy.line
        for n, term in enumerate(policy.terms.values(), 1):
            if term.name == IMPLICIT and not term.froms and term.thens == [["reject"]]:
                continue
            seq = int(term.name) if term.name.isdigit() else n * 10
            action = "permit"
            if ["reject"] in term.thens:
                action = "deny"
            e = routemap_text.entry(rm, seq, action)
            for f in term.froms:
                if f[0] == "route-filter" and len(f) >= 3:
                    f = self.inline_filter(f"{policy.name}-{term.name or 'final'}", f[1:], policy.line)
                if not self.match(e, f):
                    e.unconverted.append("match " + " ".join(f))
                    unread(term.line, f"set policy-options policy-statement {policy.name} term {term.name} from "
                           + " ".join(f), "")
            for t in term.thens:
                if not self.then(e, t):
                    e.unconverted.append("set " + " ".join(t))
                    unread(term.line, f"set policy-options policy-statement {policy.name} term {term.name} then "
                           + " ".join(t), "")

    def inline_filter(self, name: str, w: List[str], line: int) -> List[str]:
        """A route-filter written in the term itself becomes a prefix list of its own (POLICY-TERM)."""
        try:
            prefix = str(ipaddress.ip_network(w[0]))
        except ValueError:
            return ["route-filter"] + w
        bounds = _read_match(prefix, w[1:])
        if bounds is None:
            return ["route-filter"] + w
        pl = routemap_text.prefix_list(self.device, name, "ipv6" if ":" in prefix else "ipv4")
        pl.origin.line = pl.origin.line or line
        pl.entries.append(PrefixEntry(10 * (len(pl.entries) + 1), AclAction.PERMIT, prefix, *bounds))
        self.route_filters[name] = "route-filter-list"
        return ["route-filter-list", name]

    def match(self, e: RouteMapEntry, f: List[str]) -> bool:
        if f[0] == "route-filter-list" and f[1:2] and f[1] in e.match_prefix_lists + e.match_prefix_lists6:
            return True
        if f[0] in ("prefix-list", "route-filter-list", "prefix-list-filter") and len(f) >= 2:
            if f[0] == "prefix-list-filter" and f[2:] not in ([], ["exact"]):
                return False
            pl = self.device.prefix_lists.get(f[1])
            (e.match_prefix_lists6 if pl is not None and pl.family == "ipv6" else e.match_prefix_lists).append(f[1])
            return True
        if f[0] == "tag" and len(f) == 2 and f[1].isdigit():
            e.match_tags.append(int(f[1]))
            return True
        if f[0] in ("as-path", "as-path-group") and len(f) == 2:
            e.match_as_paths.append(f[1])
            return True
        if f[0] == "community" and len(f) == 2:
            m = re.match(r"^(.+)-(\d+)$", f[1])
            name = m.group(1) if m and m.group(1) in self.communities and int(m.group(2)) >= 2 else f[1]
            if name not in e.match_communities:
                e.match_communities.append(name)
            return True
        if f[0] == "validation-database" and len(f) == 2 and f[1] in ("valid", "invalid", "unknown"):
            e.match_rpki = {"unknown": "not-found"}.get(f[1], f[1])
            return True
        return False

    def then(self, e: RouteMapEntry, t: List[str]) -> bool:
        if t in (["accept"], ["reject"]):
            return True
        if t[0] in ("local-preference", "metric", "tag") and len(t) == 2 and t[1].isdigit():
            e.sets[t[0]] = t[1]
        elif t[:2] == ["external", "type"] and len(t) == 3 and t[2] in ("1", "2"):
            e.sets["metric-type"] = f"type-{t[2]}"
        elif t[0] == "next-hop" and len(t) == 2 and t[1] not in ("self", "peer-address", "discard", "reject"):
            e.sets["next-hop"] = str(ipaddress.ip_address(t[1]))
        elif t[0] == "origin" and len(t) == 2 and t[1] in ("igp", "incomplete"):
            e.sets["origin"] = t[1]
        elif t[0] == "as-path-prepend" and len(t) == 2 and all(x.isdigit() for x in t[1].split()):
            e.sets["as-path-prepend"] = t[1]
        elif t[0] == "community" and len(t) == 3 and t[1] in ("add", "set") and t[2] in self.communities:
            values = self.communities[t[2]]
            if all(v.startswith("target:") for v in values):
                e.sets["extcommunity-rt"] = " ".join(v[len("target:"):] for v in values)
                e.extcommunity_additive = t[1] == "add"
            else:
                e.sets["community"] = " ".join(values)
                e.community_additive = t[1] == "add"
        else:
            return False
        return True

    def next_hop_self(self, name: str) -> bool:
        policy = self.policies.get(name)
        if policy is None or [t.thens for t in policy.terms.values()] != [[["next-hop", "self"]]] or any(
                t.froms for t in policy.terms.values()):
            return False
        self.used_as_export[name] = "next-hop-self"
        return True

    def vrf_policy(self, name: str, direction: str) -> Optional[Tuple[List[str], str]]:
        """A vrf-import or vrf-export policy RouterShift writes: (route targets, export route map)."""
        policy = self.policies.get(name)
        if policy is None:
            return None
        targets: List[str] = []
        rmap = ""
        for term in policy.terms.values():
            if term.name == IMPLICIT and term.thens == [["reject"]] and not term.froms:
                continue
            if term.thens[-1:] != [["accept"]]:
                return None
            for f in term.froms:
                if f[0] == "community" and len(f) == 2 and direction == "import":
                    targets += [v[len("target:"):] for v in self.communities.get(f[1], []) if v.startswith("target:")]
                elif f[0] == "policy" and len(f) == 2 and direction == "export":
                    rmap = f[1]
                else:
                    return None
            for t in term.thens[:-1]:
                if t[:2] == ["community", "add"] and len(t) == 3 and direction == "export":
                    targets += [v[len("target:"):] for v in self.communities.get(t[2], []) if v.startswith("target:")]
                else:
                    return None
        self.used_as_export[name] = f"vrf-{direction}"
        return targets, rmap

    def leak_policy(self, name: str) -> Optional[Dict[str, str]]:
        """An instance-import policy RouterShift writes: source instance -> route map."""
        policy = self.policies.get(name)
        if policy is None:
            return None
        leaks: Dict[str, str] = {}
        for term in policy.terms.values():
            if term.name == IMPLICIT and term.thens == [["reject"]] and not term.froms:
                continue
            if term.thens != [["accept"]]:
                return None
            source = next((f[1] for f in term.froms if f[0] == "instance" and len(f) == 2), "")
            rmap = next((f[1] for f in term.froms if f[0] == "policy" and len(f) == 2), "")
            if not source or len(term.froms) != (2 if rmap else 1):
                return None
            leaks[source] = rmap
        self.used_as_export[name] = "instance-import"
        return leaks

    # export policies --------------------------------------------------------------------------------------------

    def export(self, name: str) -> Optional[Tuple[List[str], Dict[str, str], List[str], str, str, List[str]]]:
        """An export policy read back as redistribution: (sources, route maps, networks, default route, metric type,
        OSPF route types); None when it is not one RouterShift writes."""
        policy = self.policies.get(name)
        if policy is None:
            return None
        sources: List[str] = []
        maps: Dict[str, str] = {}
        networks: List[str] = []
        default = ""
        metric_type = ""
        ospf_match: List[str] = []
        summary: List[str] = []
        aggregated: List[str] = []
        for term in policy.terms.values():
            if term.thens and term.thens[-1] != ["accept"] and term.name != "summary-only":
                return None
            if term.name in ("default-route", "default-route-always"):
                if term.froms != [["route-filter", "0.0.0.0/0", "exact"]]:
                    return None
                default = "always" if term.name.endswith("always") else "on"
                continue
            if term.name == "summary-only":
                if term.thens != [["reject"]]:
                    return None
                for f in term.froms:
                    if f[0] != "route-filter" or f[2:] != ["longer"]:
                        return None
                    summary.append(str(ipaddress.ip_network(f[1])))
                continue
            if term.name == "aggregates":
                for f in term.froms:
                    if f == ["protocol", "aggregate"]:
                        continue
                    if f[0] != "route-filter" or f[2:] != ["exact"]:
                        return None
                    aggregated.append(str(ipaddress.ip_network(f[1])))
                continue
            if term.name == "networks":
                for f in term.froms:
                    if f[0] != "route-filter" or f[2:] != ["exact"]:
                        return None
                    networks.append(str(ipaddress.ip_network(f[1])))
                continue
            protocol = next((f[1] for f in term.froms if f[0] == "protocol" and len(f) == 2), "")
            source = FROM_PROTOCOL.get(protocol)
            if source is None:
                return None
            sources.append(source)
            for f in term.froms:
                if f[0] == "policy" and len(f) == 2:
                    maps[source] = f[1]
                elif f[0] == "route-type" and len(f) == 2 and f[1] in ("internal", "external"):
                    ospf_match.append(f[1])
                elif f[0] != "protocol":
                    return None
            for t in term.thens[:-1]:
                if t[:2] == ["external", "type"] and len(t) == 3:
                    metric_type = t[2]
                else:
                    return None
        self.used_as_export[name] = "export"
        self.aggregates[name] = [BgpAggregate(prefix, prefix in summary) for prefix in aggregated]
        return sources, maps, networks, default, metric_type, ospf_match


def _read_match(prefix: str, w: List[str]) -> Optional[Tuple[Optional[int], Optional[int]]]:
    """ge and le of a route-filter match type."""
    net = ipaddress.ip_network(prefix)
    top = net.max_prefixlen
    if w == ["exact"]:
        return None, None
    if w == ["orlonger"]:
        return None, top
    if w == ["longer"]:
        return net.prefixlen + 1, None
    if w[0] == "upto" and len(w) == 2:
        return None, int(w[1].lstrip("/"))
    if w[0] == "prefix-length-range" and len(w) == 2:
        low, _, high = w[1].partition("-")
        a, b = int(low.lstrip("/")), int(high.lstrip("/"))
        if a == b:
            return a, b
        return (a, None) if b == top else (a, b)
    return None
