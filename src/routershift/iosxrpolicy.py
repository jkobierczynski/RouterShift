# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""IOS-XR routing policy (RPL): prefix sets, community sets, AS-path sets and route policies, read and written.

The model holds IOS-style route maps: numbered entries, each with match and set clauses, where the first entry that
matches decides. A route policy says the same with one if / elseif / else chain: every entry is a branch whose
condition is its match clauses, whose body is its set clauses, ending in ``pass`` (permit) or ``drop`` (deny). A
route that no branch takes is dropped, as a route map denies what no entry permits.

IOS-XR sets hold no deny entries. A prefix list whose deny entries all come before its permit entries (the common
"deny these, permit the rest" list) becomes two sets, NAME with the permits and NAME-DENY with the denies, matched as
``destination in NAME and not destination in NAME-DENY``; the reader joins them again.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from .confparse import Node
from .model import (AclAction, AsPathList, BgpNeighbor, CommunityList, Device, Origin, PrefixEntry, PrefixList,
                    RouteMap, RouteMapEntry)
from .report import Report, Severity
from . import routemap as routemap_text

PLATFORM = "IOS-XR"
DENY_SUFFIX = "-DENY"
PASS_ALL = "RS-PASS-ALL"  # what an eBGP session without a policy gets: IOS-XR sends and takes nothing without one
PREFIX_POLICY = "RS-PL-"  # a prefix list applied straight to a BGP neighbor becomes the policy RS-PL-NAME
_RPKI = {"valid": "valid", "invalid": "invalid", "not-found": "not-found"}


# Reading -------------------------------------------------------------------------------------------------------------

def _set_body(node: Node) -> List[str]:
    """The element lines of a set block, without commas."""
    return [c.text.rstrip(",").strip() for c in node.children if c.text.rstrip(",").strip()]


def read_prefix_set(device: Device, node: Node) -> bool:
    """prefix-set NAME / A/len [ge N] [le N], ... / end-set"""
    if len(node.words) != 2:
        return False
    name = node.words[1]
    pl = PrefixList(name, origin=Origin(node.line, node.text))
    action = AclAction.DENY if name.endswith(DENY_SUFFIX) else AclAction.PERMIT
    for n, text in enumerate(_set_body(node), 1):
        w = text.split()
        prefix = str(ipaddress.ip_network(w[0], strict=False))
        entry = PrefixEntry(n * 10, action, prefix)
        rest = w[1:]
        while rest:
            if rest[0] in ("ge", "le") and len(rest) >= 2:
                setattr(entry, rest[0], int(rest[1]))
                rest = rest[2:]
            elif rest[0] == "eq" and len(rest) >= 2:
                entry.ge = entry.le = int(rest[1])
                rest = rest[2:]
            else:
                return False
        pl.entries.append(entry)
        if ":" in prefix:
            pl.family = "ipv6"
    device.prefix_lists[name] = pl
    return True


def join_deny_sets(device: Device) -> None:
    """NAME-DENY sets go back in front of NAME, as the deny entries of one prefix list."""
    for name in [n for n in device.prefix_lists if n.endswith(DENY_SUFFIX)]:
        base = device.prefix_lists.get(name[:-len(DENY_SUFFIX)])
        if base is None:
            continue
        deny = device.prefix_lists.pop(name)
        entries = deny.entries + base.entries
        for n, e in enumerate(entries, 1):
            e.seq = n * 10
        base.entries = entries


def read_community_set(device: Device, node: Node) -> bool:
    """community-set NAME / 65000:100, ios-regex '...' / end-set"""
    if len(node.words) != 2:
        return False
    cl = CommunityList(node.words[1], origin=Origin(node.line, node.text))
    values: List[str] = []
    for text in _set_body(node):
        m = re.match(r"ios-regex\s+'(.*)'$", text)
        if m:
            cl.expanded = True
            cl.entries.append(("permit", m.group(1)))
        else:
            values.append(text)
    if values:
        if cl.expanded:
            return False
        cl.entries.append(("permit", " ".join(values)))
    device.community_lists[cl.name] = cl
    return True


def read_as_path_set(device: Device, node: Node) -> bool:
    """as-path-set NAME / ios-regex '_65000$', ... / end-set"""
    if len(node.words) != 2:
        return False
    apl = AsPathList(node.words[1], origin=Origin(node.line, node.text))
    for text in _set_body(node):
        m = re.match(r"ios-regex\s+'(.*)'$", text)
        if not m:
            return False
        apl.entries.append(("permit", m.group(1)))
    device.as_path_lists[apl.name] = apl
    return True


def _terms(text: str) -> List[str]:
    """The parts of a condition joined by 'and' outside brackets."""
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    for word in re.findall(r"\(|\)|[^\s()]+", text):
        if word == "(":
            depth += 1
        elif word == ")":
            depth -= 1
        if word == "and" and depth == 0:
            parts.append(" ".join(current))
            current = []
        else:
            current.append(word)
    parts.append(" ".join(current))
    return [p.strip() for p in parts if p.strip()]


def _alternatives(term: str) -> List[str]:
    """The atoms of '( a or b )', or of a lone atom."""
    inner = term
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1].strip()
    return [a.strip() for a in re.split(r"\s+or\s+", inner)]


def _condition(e: RouteMapEntry, text: str) -> None:
    """The match clauses of an entry from an RPL condition; what does not fit goes to e.unconverted."""
    for term in _terms(text):
        atoms = _alternatives(term)
        kinds = set()
        values: List[str] = []
        for atom in atoms:
            w = atom.split()
            if len(w) == 3 and w[:2] == ["destination", "in"] and not w[2].startswith("("):
                kinds.add("prefix")
                values.append(w[2])
            elif len(w) == 3 and w[:2] == ["tag", "eq"] and w[2].isdigit():
                kinds.add("tag")
                values.append(w[2])
            elif len(w) == 3 and w[:2] == ["as-path", "in"] and not w[2].startswith("("):
                kinds.add("as-path")
                values.append(w[2])
            elif len(w) == 3 and w[:2] == ["community", "matches-any"] and not w[2].startswith("("):
                kinds.add("community")
                values.append(w[2])
            elif len(w) == 3 and w[:2] == ["validation-state", "is"] and w[2] in _RPKI and len(atoms) == 1:
                kinds.add("rpki")
                values.append(w[2])
            elif len(w) == 4 and w[:3] == ["not", "destination", "in"] and w[3].endswith(DENY_SUFFIX) and \
                    len(atoms) == 1:
                kinds.add("deny-set")
                values.append(w[3])
            else:
                kinds.add("other")
        if len(kinds) != 1 or "other" in kinds:
            e.unconverted.append(f"match {term}")
            continue
        kind = kinds.pop()
        if kind == "prefix":
            e.match_prefix_lists += values
        elif kind == "tag":
            e.match_tags += [int(v) for v in values]
        elif kind == "as-path":
            e.match_as_paths += values
        elif kind == "community":
            e.match_communities += values
        elif kind == "rpki":
            e.match_rpki = values[0]
        # deny-set: the NAME-DENY half of a prefix list, joined with NAME by join_deny_sets


def _statement(e: RouteMapEntry, text: str, prepends: List[str]) -> Optional[str]:
    """One statement of a branch body: a set clause, or pass / drop / done. Returns the verdict word, if any."""
    w = text.split()
    if w in (["pass"], ["done"]):
        return "pass"
    if w == ["drop"]:
        return "drop"
    if w[:1] == ["#"] or text.startswith("#"):
        return None
    sets = {"local-preference": "local-preference", "med": "metric", "weight": "weight", "tag": "tag",
            "next-hop": "next-hop", "origin": "origin", "metric-type": "metric-type"}
    if w[0] == "set" and len(w) == 3 and w[1] in sets:
        e.sets[sets[w[1]]] = w[2]
        return None
    if w[0] == "prepend" and w[1:2] == ["as-path"] and len(w) in (3, 4):
        count = int(w[3]) if len(w) == 4 else 1
        prepends[:0] = [w[2]] * count
        return None
    m = re.match(r"set (community|extcommunity rt) \((.*)\)( additive)?$", text)
    if m:
        values = " ".join(v.strip() for v in m.group(2).split(",") if v.strip())
        if m.group(1) == "community":
            e.sets["community"] = values
            e.community_additive = bool(m.group(3))
        else:
            e.sets["extcommunity-rt"] = values
            e.extcommunity_additive = bool(m.group(3))
        return None
    e.unconverted.append(f"set {text}" if not text.startswith("set ") else text)
    return None


def _branch(rm: RouteMap, seq: int, condition: str, body: List[Node]) -> Optional[RouteMapEntry]:
    e = RouteMapEntry(seq, AclAction.PERMIT)
    if condition:
        _condition(e, condition)
    prepends: List[str] = []
    verdict = None
    for node in body:
        if node.children or node.words[0] in ("if", "elseif", "else", "endif", "apply"):
            e.unconverted.append(f"match {node.text}" if node.words[0] in ("if", "apply") else node.text)
            continue
        found = _statement(e, node.text, prepends)
        verdict = found or verdict
    if prepends:
        e.sets["as-path-prepend"] = " ".join(prepends)
    if verdict == "drop":
        e.action = AclAction.DENY
    elif verdict is None and not e.sets and not e.unconverted:
        return None  # a branch that neither passes nor sets anything leaves the route to the next statement
    return e


def read_route_policy(device: Device, node: Node) -> bool:
    """route-policy NAME, its body as an if / elseif / else chain (or plain statements), end-policy."""
    if len(node.words) != 2:
        return False
    name = node.words[1]
    rm = RouteMap(name, origin=Origin(node.line, node.text))
    body = node.children
    seq = 10
    i = 0
    loose: List[Node] = []
    while i < len(body):
        n = body[i]
        w = n.words
        if w[0] == "if" and w[-1] == "then":
            chain = [(" ".join(w[1:-1]), n.children)]
            i += 1
            while i < len(body) and body[i].words[0] in ("elseif", "else"):
                b = body[i]
                if b.words[0] == "elseif" and b.words[-1] == "then":
                    chain.append((" ".join(b.words[1:-1]), b.children))
                else:
                    chain.append(("", b.children))
                i += 1
            if i < len(body) and body[i].words == ["endif"]:
                i += 1
            for cond, children in chain:
                if not cond and [c.words for c in children] == [["drop"]] and len(chain) > 1:
                    continue  # the implicit deny at the end of a route map
                e = _branch(rm, seq, cond, children)
                if e is not None:
                    rm.entries.append(e)
                    seq += 10
            continue
        loose.append(n)
        i += 1
    if loose:
        e = _branch(rm, seq, "", loose)
        if e is not None:
            rm.entries.append(e)
    device.route_maps[name] = rm
    return True


def finish(device: Device) -> None:
    """Join the deny halves of prefix lists, and drop the policies RouterShift writes for IOS-XR's own needs."""
    join_deny_sets(device)
    for rm in device.route_maps.values():
        for e in rm.entries:
            for clause in list(e.unconverted):
                m = re.match(r"set community (\S+)( additive)?$", clause)
                cl = device.community_lists.get(m.group(1)) if m else None
                if m and cl is not None and not cl.expanded and "community" not in e.sets:
                    e.sets["community"] = " ".join(v for _, v in cl.entries)
                    e.community_additive = bool(m.group(2))
                    e.unconverted.remove(clause)
            e.match_prefix_lists = [p for p in e.match_prefix_lists if not p.endswith(DENY_SUFFIX) or
                                    p[:-len(DENY_SUFFIX)] not in device.prefix_lists]
            six = [p for p in e.match_prefix_lists if p in device.prefix_lists and
                   device.prefix_lists[p].family == "ipv6"]
            if six:
                e.match_prefix_lists = [p for p in e.match_prefix_lists if p not in six]
                e.match_prefix_lists6 += six
    peers: List[BgpNeighbor] = []
    if device.bgp is not None:
        b = device.bgp
        peers = list(b.peer_groups.values()) + b.neighbors + [n for v in b.vrfs.values() for n in
                                                              v.neighbors + list(v.peer_groups.values())]
    for peer in peers:
        for direction in ("in", "out"):
            attr = f"route_map_{direction}"
            value = getattr(peer, attr)
            if value == PASS_ALL:
                setattr(peer, attr, "")
            elif value.startswith(PREFIX_POLICY) and value.endswith(f"-{direction.upper()}"):
                applied = ""
                generated = device.route_maps.get(value)
                for e in generated.entries if generated is not None else []:
                    applied = next((u.split()[-1] for u in e.unconverted if u.startswith("match apply ")), applied)
                setattr(peer, attr, applied)
                setattr(peer, f"prefix_list_{direction}", value[len(PREFIX_POLICY):-len(direction) - 1])
    used = {getattr(p, f"route_map_{d}") for p in peers for d in ("in", "out")}
    for name in list(device.route_maps):
        if (name == PASS_ALL or name.startswith(PREFIX_POLICY)) and name not in used:
            del device.route_maps[name]


# Writing -------------------------------------------------------------------------------------------------------------

def _split(pl: PrefixList) -> Optional[Tuple[List[PrefixEntry], List[PrefixEntry]]]:
    """(denies, permits) when every deny entry comes before every permit entry; None otherwise."""
    entries = list(pl.entries)
    denies = [e for e in entries if e.action == AclAction.DENY]
    permits = [e for e in entries if e.action == AclAction.PERMIT]
    if entries[:len(denies)] != denies:
        return None
    return denies, permits


def _element(e: PrefixEntry) -> str:
    words = [e.prefix]
    if e.ge is not None and e.le is not None and e.ge == e.le:
        words += ["eq", str(e.ge)]
    else:
        if e.ge is not None:
            words += ["ge", str(e.ge)]
        if e.le is not None:
            words += ["le", str(e.le)]
    return " ".join(words)


def _set_lines(kind: str, name: str, elements: List[str]) -> List[str]:
    body = [f"  {x}," for x in elements]
    if body:
        body[-1] = body[-1].rstrip(",")
    return [f"{kind} {name}"] + body + ["end-set", "!"]


def prefix_set_lines(device: Device, report: Report) -> Tuple[List[str], Dict[str, bool]]:
    """The prefix sets, and per prefix list whether it has a NAME-DENY half."""
    out: List[str] = []
    halves: Dict[str, bool] = {}
    for pl in device.prefix_lists.values():
        lab = routemap_text.label(pl.name, "prefix-list")
        split = _split(pl)
        if split is None:
            permits = [e for e in pl.entries if e.action == AclAction.PERMIT]
            denies = [e for e in pl.entries if e.action == AclAction.DENY]
            report.add("policy", lab, Severity.REVIEW, "prefix-set-order",
                       "IOS-XR prefix sets hold no deny entries; the deny entries come after permit entries here, so "
                       f"they are written as {pl.name}{DENY_SUFFIX} and checked first: check the order by hand")
        else:
            denies, permits = split
        out += _set_lines("prefix-set", pl.name, [_element(e) for e in permits])
        if denies:
            out += _set_lines("prefix-set", pl.name + DENY_SUFFIX, [_element(e) for e in denies])
            halves[pl.name] = True
            if split is not None:
                report.add("policy", lab, Severity.INFO, "prefix-set-deny",
                           f"its deny entries are the prefix set {pl.name}{DENY_SUFFIX}, which every policy that "
                           "matches the list excludes")
    return out, halves


def list_lines(device: Device, report: Report) -> List[str]:
    """community-set and as-path-set blocks."""
    out: List[str] = []
    for cl in device.community_lists.values():
        lab = routemap_text.label(cl.name, "community-list")
        report.item("policy", lab)
        elements: List[str] = []
        for action, value in cl.entries:
            if action != "permit":
                report.add("policy", lab, Severity.REVIEW, "set-deny",
                           f"the deny entry '{value}' is left out: IOS-XR community sets only list what matches")
                continue
            if cl.expanded:
                elements.append(f"ios-regex '{value}'")
            else:
                elements += value.split()
        out += _set_lines("community-set", cl.name, elements)
    for apl in device.as_path_lists.values():
        lab = routemap_text.label(apl.name, "as-path list")
        report.item("policy", lab)
        elements = []
        for action, regex in apl.entries:
            if action != "permit":
                report.add("policy", lab, Severity.REVIEW, "set-deny",
                           f"the deny entry '{regex}' is left out: IOS-XR AS-path sets only list what matches")
                continue
            elements.append(f"ios-regex '{regex}'")
        out += _set_lines("as-path-set", apl.name, elements)
    return out


def _any(atoms: List[str]) -> str:
    return atoms[0] if len(atoms) == 1 else "(" + " or ".join(atoms) + ")"


def _conditions(e: RouteMapEntry, halves: Dict[str, bool], rm: RouteMap, report: Report) -> List[str]:
    lab = routemap_text.label(rm.name, "route-map")
    terms: List[str] = []
    lists = e.match_prefix_lists + e.match_prefix_lists6
    if lists:
        terms.append(_any([f"destination in {p}" for p in lists]))
        with_denies = [p for p in lists if halves.get(p)]
        if len(lists) == 1 and with_denies:
            terms.append(f"not destination in {lists[0]}{DENY_SUFFIX}")
        elif with_denies:
            report.add("policy", lab, Severity.REVIEW, "prefix-set-deny",
                       f"entry {e.seq} matches several prefix lists, and {', '.join(with_denies)} has deny entries "
                       "that are not checked here: add 'not destination in NAME-DENY' to the condition by hand")
    if e.match_tags:
        terms.append(_any([f"tag eq {t}" for t in e.match_tags]))
    if e.match_as_paths:
        terms.append(_any([f"as-path in {x}" for x in e.match_as_paths]))
    if e.match_communities:
        terms.append(_any([f"community matches-any {x}" for x in e.match_communities]))
    if e.match_rpki:
        terms.append(f"validation-state is {e.match_rpki}")
    return terms


def _sets(e: RouteMapEntry) -> List[str]:
    lines: List[str] = []
    s = e.sets
    if "local-preference" in s:
        lines.append(f"set local-preference {s['local-preference']}")
    if "metric" in s:
        lines.append(f"set med {s['metric']}")
    if "metric-type" in s:
        lines.append(f"set metric-type {s['metric-type']}")
    if "weight" in s:
        lines.append(f"set weight {s['weight']}")
    if "tag" in s:
        lines.append(f"set tag {s['tag']}")
    if "next-hop" in s:
        lines.append(f"set next-hop {s['next-hop']}")
    if "origin" in s:
        lines.append(f"set origin {s['origin']}")
    if "as-path-prepend" in s:
        numbers = s["as-path-prepend"].split()
        if len(set(numbers)) == 1:
            lines.append(f"prepend as-path {numbers[0]}" + (f" {len(numbers)}" if len(numbers) > 1 else ""))
        else:  # each prepend goes in front of the last: the last number first
            lines += [f"prepend as-path {n}" for n in reversed(numbers)]
    if "community" in s:
        lines.append(f"set community ({', '.join(s['community'].split())})" +
                     (" additive" if e.community_additive else ""))
    if "extcommunity-rt" in s:
        lines.append(f"set extcommunity rt ({', '.join(s['extcommunity-rt'].split())})" +
                     (" additive" if e.extcommunity_additive else ""))
    return lines


def route_policy_lines(rm: RouteMap, halves: Dict[str, bool], report: Report) -> List[str]:
    """One route map as a route policy: an if / elseif / else chain, one branch per entry."""
    lab = routemap_text.label(rm.name, "route-map")
    branches: List[Tuple[List[str], List[str]]] = []  # (condition terms, body)
    for e in rm.entries:
        matches, sets = routemap_text.unwritable(e, "iosxr")
        if e.match_acls:
            matches.append(f"match ip address {' '.join(e.match_acls)}")
        if matches:
            report.add("policy", lab, Severity.REVIEW, "rm-match-unconverted",
                       f"entry {e.seq} ({e.action.value}) is left out: its {'; '.join(matches)} is not converted "
                       "(route policies match prefix sets, not ACLs), and without it the entry would apply to every "
                       "route; rebuild the branch by hand")
            continue
        routemap_text.unwritten_sets(rm, e, sets, report)
        if e.description:
            report.add("policy", lab, Severity.APPROX, "rm-description",
                       f"entry {e.seq}: its description '{e.description}' is not written (RPL branches have none)")
        body = _sets(e) + (["pass"] if e.action == AclAction.PERMIT else ["drop"])
        if e.action == AclAction.DENY:
            body = ["drop"]
        terms = _conditions(e, halves, rm, report)
        branches.append((terms, body))
        if not terms:
            break  # an entry without a match takes every route: the entries after it are never reached
    out = [f"route-policy {rm.name}"]
    if len(branches) == 1 and not branches[0][0]:
        out += ["  " + line for line in branches[0][1]]
    else:
        for n, (terms, body) in enumerate(branches):
            if not terms:
                out.append("  else")
            else:
                out.append(("  if " if n == 0 else "  elseif ") + " and ".join(terms) + " then")
            out += ["    " + line for line in body]
        if branches and branches[-1][0]:
            out += ["  else", "    drop"]
        if branches:
            out.append("  endif")
        else:
            out.append("  drop")
    out += ["end-policy", "!"]
    return out


def pass_all_lines() -> List[str]:
    return [f"route-policy {PASS_ALL}", "  pass", "end-policy", "!"]


def prefix_policy_lines(name: str, direction: str, route_map: str, halves: Dict[str, bool]) -> List[str]:
    """The policy a prefix list applied to a BGP neighbor becomes, with the neighbor's route map applied after it."""
    cond = f"destination in {name}" + (f" and not destination in {name}{DENY_SUFFIX}" if halves.get(name) else "")
    body = [f"apply {route_map}"] if route_map else ["pass"]
    return [f"route-policy {prefix_policy_name(name, direction)}", f"  if {cond} then"] + \
        ["    " + b for b in body] + ["  else", "    drop", "  endif", "end-policy", "!"]


def prefix_policy_name(name: str, direction: str) -> str:
    return f"{PREFIX_POLICY}{name}-{direction.upper()}"
