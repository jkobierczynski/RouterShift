# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""IOS-XR ACL-based forwarding (ABF): policy-based routing, read and written.

IOS-XR has no PBR route maps. It forwards by an ingress ACL whose permit entries carry a next hop
(``10 permit ipv4 any 203.0.113.80 0.0.0.15 nexthop1 vrf DMZ ipv4 10.255.200.1``). A permit entry without a next hop
is routed as usual, a deny entry drops the packet, and so does the ACL's implicit deny at the end.

A PBR route map is written as one ABF ACL, ``RS-ABF-NAME``: every entry of every ACL the route map matches, in order,
the permit entries with the next hop of their route map entry and the deny entries (which in a PBR ACL only mean
"not this one") as permits without one; then ``permit ipv4 any any`` so the rest is routed as usual. The interface
applies it as its ingress ACL.

The reader turns such an ACL back into a route map (``NAME`` for ``RS-ABF-NAME``): each run of entries up to the
next change of next hop becomes a route map entry matching an ACL with those entries, reusing an ACL the
configuration has when its entries are the same.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Callable, Dict, List, Tuple

from . import acl as acl_text
from . import bfd as bfd_text
from . import routemap as routemap_text
from .confparse import Node
from .model import Acl, AclAction, AclEntry, Device
from .report import Report, Severity

PREFIX = "RS-ABF-"
_NEXTHOP = re.compile(r"\s+nexthop1(?:\s+vrf\s+(\S+))?\s+ipv4\s+(\S+)\s*$")


def acl_name(route_map: str) -> str:
    return PREFIX + acl_text.safe_name(route_map)


# Writing -------------------------------------------------------------------------------------------------------------

def lines(device: Device, report: Report, vrf_of: Callable[[str], str]) -> Tuple[List[str], Dict[str, str]]:
    """The ABF ACLs of the PBR route maps; returns the lines and route map -> ACL name."""
    out: List[str] = []
    names: Dict[str, str] = {}
    for name in bfd_text.pbr_maps(device):
        label = routemap_text.label(name, "route-map")
        report.item("policy", label)
        entries = bfd_text.pbr_entries(device, name, report, "IOS-XR")
        vrfs = sorted({vrf_of(i.name) for i in device.interfaces.values() if i.pbr == name})
        vrf = vrfs[0] if len(vrfs) == 1 else ""
        if len(vrfs) > 1:
            report.add("policy", label, Severity.REVIEW, "abf-vrf",
                       f"the route map is applied in the VRFs {', '.join(v or 'default' for v in vrfs)}; the next "
                       "hops are written without a VRF, so they resolve in the VRF of each interface")
        body: List[str] = []
        denies = False
        for n, (seq, acls, next_hop) in enumerate(entries):
            if not next_hop:
                report.add("policy", label, Severity.REVIEW, "pbr-next-hop",
                           f"entry {seq} sets no next hop (ABF takes only a next hop); left out")
                continue
            hop = (f" nexthop1 vrf {vrf}" if vrf else " nexthop1") + f" ipv4 {next_hop}"
            for name_acl in acls:
                acl = device.acls.get(name_acl)
                if acl is None or acl.family == 6:
                    report.add("policy", label, Severity.REVIEW, "pbr-acl",
                               f"entry {seq}: ACL {name_acl} is missing or IPv6; left out")
                    continue
                if any(e.action == AclAction.DENY for e in acl.entries) and n + 1 < len(entries):
                    denies = True
                copy = Acl(acl.name, 4, [dataclasses.replace(e, action=AclAction.PERMIT, sequence=None)
                                         if e.action == AclAction.DENY else dataclasses.replace(e, sequence=None)
                                         for e in acl.entries if e.action != AclAction.REMARK])
                deny_at = [e.action == AclAction.DENY for e in acl.entries if e.action != AclAction.REMARK]
                rows = acl_text.numbered(copy)
                written = acl_text.cisco_lines(copy, report, label, "wildcard", any_protocol="ipv4", icmp6="icmpv6",
                                               icmp_names=True)
                index = {id(e): k for k, e in enumerate(copy.entries)}
                for (_, entry, _, _), text in zip(rows, written):
                    words = text.split(None, 1)[1]
                    plain = entry.unsupported or deny_at[index[id(entry)]]
                    body.append(words if plain else words + hop)
        if not body:
            continue
        body.append("permit ipv4 any any")
        abf_acl = acl_name(name)
        out += [f"ipv4 access-list {abf_acl}"] + [f" {10 * k} {text}" for k, text in enumerate(body, 1)] + ["!"]
        names[name] = abf_acl
        report.add("policy", label, Severity.APPROX, "pbr-abf",
                   f"written as ACL-based forwarding: ACL {abf_acl} sends the packets each permit entry picks to the "
                   "next hop of its route map entry, and routes the rest as usual; the interfaces take it as their "
                   "ingress ACL")
        if denies:
            report.add("policy", label, Severity.APPROX, "abf-deny",
                       "a deny in the ACL of an entry passes the packet on to the next route map entry; in the ABF "
                       "ACL it is a permit without a next hop, which routes the packet as usual at once")
    return out, names


# Reading -------------------------------------------------------------------------------------------------------------

class Reader:
    """ABF ACLs back into PBR route maps."""

    def __init__(self, device: Device) -> None:
        self.device = device
        self.hops: Dict[str, Dict[int, str]] = {}  # ACL -> line number of the entry -> next hop

    def strip(self, acl: str, children: List[Node]) -> None:
        """Takes the next hop off each entry line of an IPv4 ACL, remembered by the line number."""
        for child in children:
            m = _NEXTHOP.search(child.text)
            if m:
                self.hops.setdefault(acl, {})[child.line] = m.group(2)
                child.text = child.text[:m.start()]

    def finish(self) -> Dict[str, str]:
        """Route maps rebuilt from the ABF ACLs; returns ACL -> route map. The ABF ACLs themselves are removed."""
        dev = self.device
        out: Dict[str, str] = {}
        for name, hops in self.hops.items():
            acl = dev.acls.get(name)
            if acl is None:
                continue
            entries = list(acl.entries)
            last = entries[-1] if entries else None
            if last is not None and last.origin.line not in hops and last.action == AclAction.PERMIT and \
                    (last.protocol, last.source, last.destination, last.src_ports, last.dst_ports) == \
                    ("ip", "any", "any", "", ""):
                entries = entries[:-1]
            rm_name = name[len(PREFIX):] if name.startswith(PREFIX) else name
            rm = routemap_text.route_map(dev, rm_name)
            runs: List[Tuple[str, List[AclEntry]]] = []  # (next hop, entries) of each route map entry
            for e in entries:
                if e.action == AclAction.REMARK:
                    continue
                here = hops.get(e.origin.line, "")
                if not runs or here and runs[-1][0] not in ("", here):
                    runs.append((here, []))
                elif here and not runs[-1][0]:
                    runs[-1] = (here, runs[-1][1])
                # a permit without a next hop is a deny of the PBR ACL: "not this one"
                action = AclAction.DENY if not here and e.action == AclAction.PERMIT and not e.unsupported \
                    else e.action
                runs[-1][1].append(dataclasses.replace(e, action=action, sequence=None))
            for n, (next_hop, run) in enumerate(runs, 1):
                entry = routemap_text.entry(rm, 10 * n, "permit")
                if next_hop:
                    entry.sets["next-hop"] = next_hop
                entry.match_acls.append(self._acl(run, f"{rm_name}-{10 * n}"))
            del dev.acls[name]
            out[name] = rm_name
        return out

    def _acl(self, entries: List[AclEntry], fallback: str) -> str:
        def key(es: List[AclEntry]) -> List[Tuple[object, ...]]:
            return [(e.action, e.protocol, e.source, e.destination, e.src_ports, e.dst_ports, e.icmp_type,
                     e.established) for e in es if e.action != AclAction.REMARK and not e.unsupported]
        for acl in self.device.acls.values():
            if acl.family == 4 and acl.name not in self.hops and key(acl.entries) == key(entries):
                return acl.name
        acl = self.device.acls.setdefault(fallback, Acl(fallback, 4))
        acl.entries = entries
        return fallback

