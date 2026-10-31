# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Prefix lists and route maps (Comware route policies): readers and writers for the IOS family (IOS, EOS, AOS-CX)
and Comware, and the reports every writer shares."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

from .acl import safe_name
from .model import AclAction, Device, PrefixEntry, PrefixList, RouteMap, RouteMapEntry
from .report import Report, Severity

SUPPORTED = ("ios", "eos", "aoscx", "comware")
SET_KEYS = ("local-preference", "metric", "weight", "tag", "next-hop", "origin", "as-path-prepend", "community")
_ORIGINS = ("igp", "incomplete")


def label(name: str, kind: str) -> str:
    return f"{kind} {name}"


def prefix_list(device: Device, name: str, family: str) -> PrefixList:
    pl = device.prefix_lists.get(name)
    if pl is None:
        pl = device.prefix_lists[name] = PrefixList(name, family)
    return pl


def route_map(device: Device, name: str) -> RouteMap:
    rm = device.route_maps.get(name)
    if rm is None:
        rm = device.route_maps[name] = RouteMap(name)
    return rm


def entry(rm: RouteMap, seq: int, action: str) -> RouteMapEntry:
    for e in rm.entries:
        if e.seq == seq:
            return e
    e = RouteMapEntry(seq, AclAction(action))
    rm.entries.append(e)
    rm.entries.sort(key=lambda x: x.seq)
    return e


def _next_seq(pl: PrefixList) -> int:
    return (max(e.seq for e in pl.entries) if pl.entries else 0) + 5


def _bounds(prefix: str, ge: Optional[int], le: Optional[int]) -> bool:
    length = ipaddress.ip_network(prefix).prefixlen
    top = 32 if ":" not in prefix else 128
    return all(b is None or length <= b <= top for b in (ge, le)) and (ge is None or le is None or ge <= le)


# IOS family ----------------------------------------------------------------------------------------------------------

def ios_prefix_entry(pl: PrefixList, w: List[str]) -> bool:
    """[seq N] permit|deny PREFIX [ge X] [le Y] (IOS, EOS and AOS-CX); description is read and dropped."""
    if w[0] == "description":
        return True
    seq = None
    if w[0] == "seq" and len(w) >= 2 and w[1].isdigit():
        seq, w = int(w[1]), w[2:]
    if len(w) < 2 or w[0] not in ("permit", "deny"):
        return False
    prefix = str(ipaddress.ip_network(w[1]))
    ge = le = None
    rest = w[2:]
    while rest:
        if rest[0] in ("ge", "le") and len(rest) >= 2 and rest[1].isdigit():
            if rest[0] == "ge":
                ge = int(rest[1])
            else:
                le = int(rest[1])
            rest = rest[2:]
        else:
            return False
    if not _bounds(prefix, ge, le):
        return False
    pl.entries.append(PrefixEntry(seq if seq is not None else _next_seq(pl), AclAction(w[0]), prefix, ge, le))
    return True


def ios_route_map_header(w: List[str]) -> Optional[Tuple[str, str, int]]:
    """route-map NAME [permit|deny] [N] (IOS, EOS) or route-map NAME permit|deny seq N (AOS-CX): (name, action, seq)."""
    if len(w) < 2:
        return None
    name, rest = w[1], w[2:]
    action = "permit"
    if rest and rest[0] in ("permit", "deny"):
        action, rest = rest[0], rest[1:]
    if rest[:1] == ["seq"]:
        rest = rest[1:]
    if rest and not (len(rest) == 1 and rest[0].isdigit()):
        return None
    return name, action, int(rest[0]) if rest else 10


def ios_route_map_line(e: RouteMapEntry, w: List[str]) -> bool:
    """match and set lines in the IOS, EOS and AOS-CX spellings."""
    n = len(w)
    if w[0] == "description" and n >= 2:
        e.description = " ".join(w[1:])
    elif w[:4] in (["match", "ip", "address", "prefix-list"], ["match", "ipv6", "address", "prefix-list"]) and n >= 5:
        (e.match_prefix_lists if w[1] == "ip" else e.match_prefix_lists6).extend(w[4:])
    elif w[:4] == ["match", "ip", "address", "access-list"] and n == 5:
        e.match_acls.append(w[4])
    elif w[:3] == ["match", "ip", "address"] and n >= 4:
        e.match_acls.extend(w[3:])
    elif w[:2] == ["match", "tag"] and n >= 3 and all(x.isdigit() for x in w[2:]):
        e.match_tags.extend(int(x) for x in w[2:])
    elif w[0] == "set" and n == 3 and w[1] in ("local-preference", "metric", "weight", "tag") and w[2].isdigit():
        e.sets[w[1]] = w[2]
    elif w[:3] == ["set", "ip", "next-hop"] and n == 4:
        e.sets["next-hop"] = str(ipaddress.ip_address(w[3]))
    elif w[:2] == ["set", "origin"] and n == 3 and w[2] in _ORIGINS:
        e.sets["origin"] = w[2]
    elif w[:3] == ["set", "as-path", "prepend"] and n >= 4 and all(x.isdigit() for x in w[3:]):
        e.sets["as-path-prepend"] = " ".join(w[3:])
    elif w[:2] == ["set", "community"] and n >= 3:
        values = w[2:]
        if values[-1] == "additive":
            e.community_additive, values = True, values[:-1]
        if not values:
            return False
        e.sets["community"] = " ".join(values)
    else:
        return False
    return True


def ios_prefix_lines(pl: PrefixList, platform: str) -> List[str]:
    """Prefix lists: one line per entry (IOS, AOS-CX), a block (EOS)."""
    family = "ipv6" if pl.family == "ipv6" else "ip"
    body = []
    for e in pl.entries:
        line = f"seq {e.seq} {e.action.value} {e.prefix}"
        if e.ge is not None:
            line += f" ge {e.ge}"
        if e.le is not None:
            line += f" le {e.le}"
        body.append(line)
    if platform == "eos":
        return [f"{family} prefix-list {pl.name}"] + ["   " + line for line in body] + ["!"]
    return [f"{family} prefix-list {pl.name} {line}" for line in body]


def ios_route_map_lines(rm: RouteMap, platform: str, report: Report, ind: str) -> List[str]:
    """route-map blocks for IOS, EOS and AOS-CX; what the target cannot match on is reported."""
    lab = label(rm.name, "route-map")
    out: List[str] = []
    one = platform in ("eos", "aoscx")  # one prefix list or tag per match line... and per entry
    for e in rm.entries:
        head = f"route-map {rm.name} {e.action.value} " + (f"seq {e.seq}" if platform == "aoscx" else str(e.seq))
        body = []
        if e.description:
            body.append(f"description {e.description}")
        for family, lists in (("ip", e.match_prefix_lists), ("ipv6", e.match_prefix_lists6)):
            if lists and one:
                body.append(f"match {family} address prefix-list {lists[0]}")
                if len(lists) > 1:
                    report.add("policy", lab, Severity.REVIEW, "rm-match-many",
                               f"entry {e.seq} matches any of prefix lists {', '.join(lists)}; the target takes one, "
                               f"{lists[0]} is written: merge the others into it")
            elif lists:
                body.append(f"match {family} address prefix-list {' '.join(lists)}")
        if e.match_acls:
            acls = [safe_name(a) for a in e.match_acls]
            if platform == "aoscx":
                report.add("policy", lab, Severity.REVIEW, "rm-match-acl",
                           f"entry {e.seq} matches ACL {', '.join(acls)}; AOS-CX route maps match prefix lists, so the "
                           "entry is written without it and applies to every route: turn the ACL into a prefix list")
            elif platform == "eos":
                body.append(f"match ip address access-list {acls[0]}")
                if len(acls) > 1:
                    report.add("policy", lab, Severity.REVIEW, "rm-match-many",
                               f"entry {e.seq} matches any of ACLs {', '.join(acls)}; EOS takes one, {acls[0]} is "
                               "written")
            else:
                body.append(f"match ip address {' '.join(acls)}")
        if e.match_tags:
            if one:
                body.append(f"match tag {e.match_tags[0]}")
                if len(e.match_tags) > 1:
                    report.add("policy", lab, Severity.REVIEW, "rm-match-many",
                               f"entry {e.seq} matches any of tags {e.match_tags}; one is written")
            else:
                body.append("match tag " + " ".join(str(t) for t in e.match_tags))
        for key in SET_KEYS:
            value = e.sets.get(key)
            if value is None:
                continue
            if key == "next-hop":
                body.append(f"set ip next-hop {value}")
            elif key == "as-path-prepend":
                body.append(f"set as-path prepend {value}")
            elif key == "community":
                body.append(f"set community {value}" + (" additive" if e.community_additive else ""))
            else:
                body.append(f"set {key} {value}")
        out.append(head)
        out += [ind + line for line in body]
        if platform != "aoscx":
            out.append("!")
    return out


# Comware --------------------------------------------------------------------------------------------------------------

def comware_prefix_entry(device: Device, w: List[str]) -> bool:
    """ip|ipv6 prefix-list NAME index N permit|deny ADDRESS LENGTH [greater-equal X] [less-equal Y]."""
    if len(w) < 4:
        return False
    family = "ipv6" if w[0] == "ipv6" else "ipv4"
    pl = prefix_list(device, w[2], family)
    rest = w[3:]
    if rest[0] == "description":
        return True
    seq = None
    if rest[0] == "index" and len(rest) >= 2 and rest[1].isdigit():
        seq, rest = int(rest[1]), rest[2:]
    if len(rest) < 3 or rest[0] not in ("permit", "deny") or not rest[2].isdigit():
        return False
    prefix = str(ipaddress.ip_network(f"{rest[1]}/{rest[2]}"))
    ge = le = None
    more = rest[3:]
    while more:
        if more[0] in ("greater-equal", "less-equal") and len(more) >= 2 and more[1].isdigit():
            if more[0] == "greater-equal":
                ge = int(more[1])
            else:
                le = int(more[1])
            more = more[2:]
        else:
            return False
    if not _bounds(prefix, ge, le):
        return False
    pl.entries.append(PrefixEntry(seq if seq is not None else _next_seq(pl), AclAction(rest[0]), prefix, ge, le))
    return True


def comware_route_policy_line(e: RouteMapEntry, w: List[str]) -> bool:
    n = len(w)
    if w[0] == "description" and n >= 2:
        e.description = " ".join(w[1:])
    elif w[:4] in (["if-match", "ip", "address", "prefix-list"], ["if-match", "ipv6", "address", "prefix-list"]) \
            and n == 5:
        (e.match_prefix_lists if w[1] == "ip" else e.match_prefix_lists6).append(w[4])
    elif w[:4] == ["if-match", "ip", "address", "acl"] and n in (5, 6) and (n == 5 or w[4] == "name"):
        e.match_acls.append(w[-1])
    elif w[:2] == ["if-match", "tag"] and n == 3 and w[2].isdigit():
        e.match_tags.append(int(w[2]))
    elif w[0] == "apply" and n == 3 and w[1] in _COMWARE_SETS and w[2].isdigit():
        e.sets[_COMWARE_SETS[w[1]]] = w[2]
    elif w[:3] == ["apply", "ip-address", "next-hop"] and n == 4:
        e.sets["next-hop"] = str(ipaddress.ip_address(w[3]))
    elif w[:2] == ["apply", "origin"] and n == 3 and w[2] in _ORIGINS:
        e.sets["origin"] = w[2]
    elif w[:2] == ["apply", "as-path"] and n >= 4 and w[-1] == "additive" and all(x.isdigit() for x in w[2:-1]):
        e.sets["as-path-prepend"] = " ".join(w[2:-1])
    elif w[:2] == ["apply", "community"] and n >= 3:
        values = w[2:]
        if values[-1] == "additive":
            e.community_additive, values = True, values[:-1]
        if not values:
            return False
        e.sets["community"] = " ".join(values)
    else:
        return False
    return True


_COMWARE_SETS: Dict[str, str] = {"local-preference": "local-preference", "cost": "metric",
                                 "preferred-value": "weight", "tag": "tag"}
_COMWARE_WRITE = {v: k for k, v in _COMWARE_SETS.items()}


def comware_prefix_lines(pl: PrefixList) -> List[str]:
    family = "ipv6" if pl.family == "ipv6" else "ip"
    out = []
    for e in pl.entries:
        net = ipaddress.ip_network(e.prefix)
        line = f"{family} prefix-list {pl.name} index {e.seq} {e.action.value} {net.network_address} {net.prefixlen}"
        if e.ge is not None:
            line += f" greater-equal {e.ge}"
        if e.le is not None:
            line += f" less-equal {e.le}"
        out.append(line)
    return out


def comware_route_policy_lines(rm: RouteMap, report: Report, ind: str) -> List[str]:
    lab = label(rm.name, "route-map")
    out: List[str] = []
    for e in rm.entries:
        body = []
        if e.description:
            body.append(f"description {e.description}")
        for family, lists in (("ip", e.match_prefix_lists), ("ipv6", e.match_prefix_lists6)):
            if lists:
                body.append(f"if-match {family} address prefix-list {lists[0]}")
                if len(lists) > 1:
                    report.add("policy", lab, Severity.REVIEW, "rm-match-many",
                               f"node {e.seq} matches any of prefix lists {', '.join(lists)}; Comware takes one per "
                               f"node, {lists[0]} is written: merge the others into it")
        if e.match_acls:
            body.append(f"if-match ip address acl name {safe_name(e.match_acls[0])}")
            if len(e.match_acls) > 1:
                report.add("policy", lab, Severity.REVIEW, "rm-match-many",
                           f"node {e.seq} matches any of ACLs {', '.join(e.match_acls)}; one is written")
        if e.match_tags:
            body.append(f"if-match tag {e.match_tags[0]}")
            if len(e.match_tags) > 1:
                report.add("policy", lab, Severity.REVIEW, "rm-match-many",
                           f"node {e.seq} matches any of tags {e.match_tags}; one is written")
        for key in SET_KEYS:
            value = e.sets.get(key)
            if value is None:
                continue
            if key == "next-hop":
                body.append(f"apply ip-address next-hop {value}")
            elif key == "origin":
                body.append(f"apply origin {value}")
            elif key == "as-path-prepend":
                body.append(f"apply as-path {value} additive")
            elif key == "community":
                body.append(f"apply community {value}" + (" additive" if e.community_additive else ""))
            else:
                body.append(f"apply {_COMWARE_WRITE[key]} {value}")
        out.append(f"route-policy {rm.name} {e.action.value} node {e.seq}")
        out += [ind + line for line in body]
        out.append("#")
    return out


# shared ---------------------------------------------------------------------------------------------------------------

def items(device: Device, report: Report) -> None:
    for pl in device.prefix_lists.values():
        report.item("policy", label(pl.name, "prefix-list"))
    for rm in device.route_maps.values():
        report.item("policy", label(rm.name, "route-map"))


def unsupported(device: Device, report: Report, platform: str) -> None:
    """A target that writes no prefix lists or route maps."""
    for pl in device.prefix_lists.values():
        report.skip("policy", label(pl.name, "prefix-list"), "policy-unsupported",
                    f"{platform}: prefix lists are not written; configure them by hand")
    for rm in device.route_maps.values():
        report.skip("policy", label(rm.name, "route-map"), "policy-unsupported",
                    f"{platform}: route maps are not written; configure them by hand")


def ospf_maps_unsupported(device: Device, report: Report, platform: str) -> None:
    for p in device.ospf:
        for source, name in p.redistribute_maps.items():
            report.add("ospf", f"ospf {p.process}", Severity.REVIEW, "rm-redistribute",
                       f"{platform}: redistribute {source} is written without route map {name}; every route is "
                       "redistributed")


def ios_prefix_list_node(device: Device, w: List[str], children: List[List[str]]) -> Optional[List[int]]:
    """ip|ipv6 prefix-list NAME [entry] with optional entries as children (EOS): None when the line is not
    understood, else the indexes of the children that are not."""
    if len(w) < 3 or w[1] != "prefix-list":
        return None
    pl = prefix_list(device, w[2], "ipv6" if w[0] == "ipv6" else "ipv4")
    try:
        if len(w) > 3 and not ios_prefix_entry(pl, w[3:]):
            return None
    except ValueError:
        return None
    bad = []
    for n, c in enumerate(children):
        try:
            ok = ios_prefix_entry(pl, c)
        except ValueError:
            ok = False
        if not ok:
            bad.append(n)
    return bad


def ios_route_map_node(device: Device, w: List[str], children: List[List[str]]) -> Optional[List[int]]:
    """route-map header with match and set children; as ios_prefix_list_node."""
    head = ios_route_map_header(w)
    if head is None:
        return None
    e = entry(route_map(device, head[0]), head[2], head[1])
    bad = []
    for n, c in enumerate(children):
        try:
            ok = ios_route_map_line(e, c)
        except ValueError:
            ok = False
        if not ok:
            bad.append(n)
    return bad


def neighbor_policy(peer: object, w: List[str]) -> bool:
    """route-map|prefix-list NAME in|out on a BGP neighbor (IOS family), import|export on a Comware peer."""
    if len(w) != 3 or w[0] not in ("route-map", "prefix-list", "route-policy") or \
            w[2] not in ("in", "out", "import", "export"):
        return False
    kind = "prefix_list" if w[0] == "prefix-list" else "route_map"
    direction = "in" if w[2] in ("in", "import") else "out"
    setattr(peer, f"{kind}_{direction}", w[1])
    return True
