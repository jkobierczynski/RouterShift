# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AOS-CX routing tuning: OSPF authentication and timers, GRE tunnels, policy-based routing.

How the model maps to AOS-CX:

* OSPF authentication is ``ip ospf authentication message-digest`` with ``ip ospf message-digest-key N md5`` (or
  ``simple-text`` with ``ip ospf authentication-key``); the SPF throttle is ``timers throttle spf``, the LSA arrival
  timer ``timers lsa-arrival``, graceful restart ``graceful-restart restart-interval``.
* A GRE tunnel is ``interface tunnel N`` with ``tunnel mode gre ipv4``, ``source ip`` and ``destination ip``.
* A route map used for policy-based routing is a classifier policy of its own name: each permit entry is a class
  ``<map>-<seq>`` (the entries of its ACL) with ``action pbr <map>-<seq>``, a PBR action list that sets the next hop;
  the interface applies it with ``apply policy NAME routed-in``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Callable, Dict, List, Optional, Tuple

from . import aaa as aaa_text
from . import bfd as bfd_text
from . import qos as qos_text
from .model import AclAction, Device, Interface, InterfaceKind, Ospf, RouteMapEntry
from .report import Report, Severity

GR_DEFAULT = 120
Add = Callable[[Severity, str, str], None]


# OSPF ---------------------------------------------------------------------------------------------------------------

def ospf_auth_lines(iface: Interface, add: Add) -> List[str]:
    if not iface.ospf_auth:
        return []
    if iface.ospf_auth == "simple":
        lines = ["ip ospf authentication simple-text", f"ip ospf authentication-key plaintext {aaa_text.PLACEHOLDER}"]
    else:
        keys = iface.ospf_keys or {1: "md5"}
        lines = ["ip ospf authentication message-digest"]
        lines += [f"ip ospf message-digest-key {key} md5 plaintext {aaa_text.PLACEHOLDER}" for key in keys]
        sha = sorted({a for a in keys.values() if a != "md5"})
        if sha:
            add(Severity.APPROX, "ospf-sha",
                f"the {', '.join(sha)} keys are written as MD5 keys; AOS-CX takes HMAC-SHA through a keychain")
    add(Severity.REVIEW, "secret-placeholder",
        f"the OSPF authentication key is not carried over; replace {aaa_text.PLACEHOLDER} with it")
    return lines


def ospf_option_lines(p: Ospf, report: Report, label: str) -> List[str]:
    lines: List[str] = []
    if p.spf_timers is not None:
        initial, hold, maximum = p.spf_timers
        lines.append(f"timers throttle spf start-time {initial} hold-time {hold} max-wait-time {maximum}")
    if p.lsa_arrival is not None:
        lines.append(f"timers lsa-arrival {p.lsa_arrival}")
    if p.graceful_restart:
        lines.append(f"graceful-restart restart-interval {GR_DEFAULT}")
    left = [what for what, stated in ((f"the distribute list {p.distribute_list_in}", p.distribute_list_in),
                                      (f"max-lsa {p.max_lsa}", p.max_lsa),
                                      ("logging every adjacency change", p.log_adjacency == "detail")) if stated]
    if left:
        report.add("ospf", label, Severity.APPROX, "ospf-options",
                   f"{'; '.join(left)}: not written for AOS-CX, which has no such OSPF setting RouterShift writes")
    return lines


def read_ospf_line(p: Ospf, w: List[str]) -> bool:
    n = len(w)
    if w[:3] == ["timers", "throttle", "spf"] and n == 9 and w[3::2] == ["start-time", "hold-time", "max-wait-time"]:
        p.spf_timers = (int(w[4]), int(w[6]), int(w[8]))
    elif w[:2] == ["timers", "lsa-arrival"] and n == 3:
        p.lsa_arrival = int(w[2])
    elif w[:2] == ["graceful-restart", "restart-interval"] and n == 3:
        p.graceful_restart = True
    else:
        return False
    return True


def read_ospf_interface(iface: Interface, w: List[str]) -> Optional[bool]:
    n = len(w)
    if w == ["ip", "ospf", "authentication", "message-digest"]:
        iface.ospf_auth = "message-digest"
    elif w == ["ip", "ospf", "authentication", "simple-text"]:
        iface.ospf_auth = "simple"
    elif w[:3] == ["ip", "ospf", "message-digest-key"] and n == 7 and w[4] == "md5":
        iface.ospf_keys[int(w[3])] = "md5"
    elif w[:3] == ["ip", "ospf", "authentication-key"] and n == 5:
        pass
    else:
        return None
    return True


def bfd_ecmp(device: Device, report: Report) -> None:
    if device.bfd_multihop is not None or device.bfd_slow_timer is not None:
        report.item("system", "BFD")
        report.add("system", "BFD", Severity.APPROX, "bfd-global",
                   "the BFD multihop and slow timers are left out: AOS-CX sets BFD timers per session and interface")
    if device.ecmp_hash:
        report.item("system", "ECMP hashing")
        report.add("system", "ECMP hashing", Severity.APPROX, "ecmp-hash",
                   f"the ECMP hash fields ({', '.join(device.ecmp_hash)}) are left out: AOS-CX hashes on the "
                   "addresses and ports by default")


# GRE tunnels --------------------------------------------------------------------------------------------------------

def tunnel_lines(device: Device, iface: Interface, add: Add, address: Callable[[Interface], str]) -> Optional[List[str]]:
    """The lines of a GRE tunnel interface; None when AOS-CX cannot hold the tunnel."""
    if iface.tunnel_mode == "ipsec" or iface.tunnel_profile:
        return None
    lines = ["tunnel mode gre ipv4"]
    source = iface.tunnel_source
    if source and not _is_ip(source):
        src = device.interfaces.get(source)
        resolved = address(src) if src is not None else ""
        if resolved:
            add(Severity.APPROX, "tunnel-source", f"the tunnel source {source} is written as its address {resolved}")
        else:
            add(Severity.REVIEW, "tunnel-source", f"the tunnel source {source} has no address; set it by hand")
        source = resolved
    if source:
        lines.append(f"source ip {source}")
    if iface.tunnel_destination:
        lines.append(f"destination ip {iface.tunnel_destination}")
    return lines


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def read_tunnel_line(iface: Interface, w: List[str]) -> Optional[bool]:
    if w == ["tunnel", "mode", "gre", "ipv4"]:
        iface.tunnel_mode = "gre"
    elif w[:2] in (["source", "ip"], ["destination", "ip"]) and len(w) == 3:
        setattr(iface, f"tunnel_{w[0]}", str(ipaddress.ip_address(w[2])))
    else:
        return None
    return True


# policy-based routing -----------------------------------------------------------------------------------------------

class PbrWriter:
    def __init__(self, device: Device, report: Report, ind: str) -> None:
        self.device, self.report, self.ind = device, report, ind
        self.written: List[str] = []

    def lines(self) -> List[str]:
        d = self.device
        out: List[str] = []
        for name in bfd_text.pbr_maps(d):
            label = f"route-map {name}"
            entries = bfd_text.pbr_entries(d, name, self.report, "AOS-CX")
            if not entries:
                continue
            self.report.item("policy", label)
            classes: List[str] = []
            policy: List[str] = []
            seq = 10
            for entry_seq, acls, next_hop in entries:
                action = f"{name}-{entry_seq}"
                out += [f"pbr-action-list {action}"] + ([f"{self.ind}10 nexthop {next_hop}"] if next_hop else [])
                if not next_hop:
                    self.report.add("policy", label, Severity.REVIEW, "pbr-next-hop",
                                    f"entry {entry_seq} sets no next hop; its action list is empty")
                for n, acl_name in enumerate(acls or [""], 1):
                    cls = action if len(acls) <= 1 else f"{action}-{n}"
                    acl = d.acls.get(acl_name)
                    if acl is None:
                        self.report.add("policy", label, Severity.REVIEW, "pbr-acl",
                                        f"entry {entry_seq}: ACL {acl_name or '(none)'} is not defined, so the class "
                                        "matches all IPv4 traffic")
                        body = [f"{self.ind}10 match any any any"]
                    else:
                        body = [self.ind + line for line in qos_text.class_lines(
                            acl, self.report, label, style="mask", any_protocol="any", icmp6="icmpv6",
                            icmp_names=True, icmp_keyword="icmp-type", remark="comment", established=False)]
                    classes += [f"class ip {cls}"] + body
                    policy.append(f"{self.ind}{seq} class ip {cls} action pbr {action}")
                    seq += 10
            out += classes + [f"policy {name}"] + policy
            self.written.append(name)
            self.report.add("policy", label, Severity.APPROX, "pbr-policy",
                            "written as a classifier policy: each entry is a class of its ACL's entries with a PBR "
                            "action list that sets the next hop")
        return out

    def interface(self, iface: Interface, add: Add) -> List[str]:
        if not iface.pbr or iface.pbr not in self.written:
            if iface.pbr:
                add(Severity.REVIEW, "pbr", f"policy-based routing with route map {iface.pbr} is not written")
            return []
        if iface.qos_policy_in:
            add(Severity.REVIEW, "pbr", f"AOS-CX applies one policy per direction: the QoS policy "
                f"{iface.qos_policy_in} is applied, the PBR policy {iface.pbr} is not")
            return []
        routed = "routed-in" if iface.kind == InterfaceKind.VLAN else "in"
        return [f"apply policy {iface.pbr} {routed}"]


class PbrReader:
    def __init__(self, device: Device) -> None:
        self.device = device
        self.entries: Dict[str, List[Tuple[int, str, str]]] = {}  # policy -> (seq, class, action list)
        self.next_hops: Dict[str, str] = {}  # action list -> next hop

    def action_list(self, name: str, children: List[List[str]]) -> List[int]:
        bad = []
        for n, w in enumerate(children):
            if len(w) == 3 and w[0].isdigit() and w[1] == "nexthop":
                self.next_hops[name] = str(ipaddress.ip_address(w[2]))
            else:
                bad.append(n)
        return bad

    def policy_entry(self, policy: str, w: List[str]) -> bool:
        if len(w) == 7 and w[0].isdigit() and w[1:3] == ["class", "ip"] and w[4:6] == ["action", "pbr"]:
            self.entries.setdefault(policy, []).append((int(w[0]), w[3], w[6]))
            return True
        return False

    def finish(self) -> None:
        """After the classes have found their ACLs: each PBR policy becomes a route map."""
        from . import routemap as routemap_text
        d = self.device
        for policy, items in self.entries.items():
            rm = routemap_text.route_map(d, policy)
            by_action: Dict[str, RouteMapEntry] = {}
            for seq, cls, action in items:
                e = by_action.get(action)
                if e is None:
                    m = re.match(rf"^{re.escape(policy)}-(\d+)$", action)
                    e = routemap_text.entry(rm, int(m.group(1)) if m else seq, AclAction.PERMIT.value)
                    if action in self.next_hops:
                        e.sets["next-hop"] = self.next_hops[action]
                    by_action[action] = e
                qos_class = d.qos_classes.pop(cls, None)
                if qos_class is not None and qos_class.acl:
                    e.match_acls.append(qos_class.acl)
            q = d.qos_policies.get(policy)
            if q is not None and not q.actions:
                del d.qos_policies[policy]
            for iface in d.interfaces.values():
                if iface.qos_policy_in == policy:
                    iface.pbr, iface.qos_policy_in = policy, ""

