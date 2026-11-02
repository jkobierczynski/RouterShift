# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NX-OS routing tuning: OSPF authentication and options, BFD, the ECMP hash, RIP, IS-IS, MPLS with LDP, GRE tunnels,
policy-based routing.

How the model maps to NX-OS:

* OSPF authentication is ``ip ospf authentication message-digest`` with ``ip ospf message-digest-key N md5 0 KEY``
  (``ip ospf authentication`` with ``ip ospf authentication-key 0 KEY`` for plain text); SHA keys go in a key chain
  (``cryptographic-algorithm HMAC-SHA-256``) named by ``ip ospf authentication key-chain``. The keys are secrets the
  source keeps encrypted, so they are placeholders.
* ``router ospf`` takes ``bfd`` (every interface), ``table-map NAME filter`` (the routes OSPF installs; the IOS
  distribute-list in), ``timers throttle spf``, ``timers lsa-arrival``, ``max-lsa``, ``graceful-restart`` and
  ``log-adjacency-changes``; an interface ``ip ospf bfd``.
* BFD is ``feature bfd``, ``bfd interval T min_rx R multiplier M`` on an interface, ``bfd multihop interval ...`` and
  ``bfd slow-timer`` globally.
* The ECMP hash is ``ip load-sharing address source|destination|source-destination [port ...]``.
* RIP and IS-IS run on the interfaces that name them (``ip router rip TAG``, ``ip router isis TAG``), not on network
  statements; NX-OS redistributes only through a route map.
* MPLS is the MPLS feature set (``install feature-set mpls``, ``feature-set mpls``, ``feature mpls ldp``) with ``mpls
  ldp configuration`` / ``router-id IF force``, and ``mpls ip`` on the interfaces.
* A GRE tunnel is ``feature tunnel`` and ``interface TunnelN`` with ``tunnel source``, ``tunnel destination`` and
  ``tunnel mode gre ip``. Policy-based routing is ``feature pbr`` and ``ip policy route-map NAME`` on the interface.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Optional, Set

from . import aaa as aaa_text
from . import bfd as bfd_text
from . import igp as igp_text
from . import mpls as mpls_text
from . import vpn as vpn_text
from .model import Device, Interface, Isis, Ospf, Rip
from .report import Report, Severity

Add = Callable[[Severity, str, str], None]
Name = Callable[[str], str]
PERMIT_ALL = "RS-PERMIT-ALL"
PLACEHOLDER = aaa_text.PLACEHOLDER


# OSPF ---------------------------------------------------------------------------------------------------------------

def ospf_options(p: Ospf) -> List[str]:
    lines: List[str] = []
    if p.bfd_all:
        lines.append("bfd")
    if p.distribute_list_in:
        lines.append(f"table-map {p.distribute_list_in} filter")
    if p.spf_timers:
        lines.append("timers throttle spf " + " ".join(str(x) for x in p.spf_timers))
    if p.lsa_arrival is not None:
        lines.append(f"timers lsa-arrival {p.lsa_arrival}")
    if p.max_lsa:
        lines.append(f"max-lsa {p.max_lsa}")
    if p.graceful_restart:
        lines.append("graceful-restart")
    if p.log_adjacency:
        lines.append("log-adjacency-changes" + (" detail" if p.log_adjacency == "detail" else ""))
    return lines


def ospf_interface(device: Device, iface: Interface, name: str, add: Add, chains: List[str], ind: str) -> List[str]:
    """Authentication and BFD of an OSPF interface; key chains for SHA keys are added to ``chains``."""
    lines: List[str] = []
    if iface.ospf_bfd:
        lines.append("ip ospf bfd")
    if not iface.ospf_auth:
        return lines
    add(Severity.REVIEW, "secret-placeholder",
        f"the OSPF authentication key is not carried over; replace {PLACEHOLDER} with it")
    if iface.ospf_auth == "simple":
        return lines + ["ip ospf authentication", f"ip ospf authentication-key 0 {PLACEHOLDER}"]
    sha = {k: a for k, a in iface.ospf_keys.items() if a != "md5"}
    if not sha:
        lines.append("ip ospf authentication message-digest")
        lines += [f"ip ospf message-digest-key {key} md5 0 {PLACEHOLDER}" for key in iface.ospf_keys]
        return lines
    chain = f"OSPF-{name.replace('/', '-')}"
    chains.append(f"key chain {chain}")
    for key, algorithm in iface.ospf_keys.items():
        chains += [f"{ind}key {key}", f"{ind * 2}key-string 0 {PLACEHOLDER}",
                   f"{ind * 2}cryptographic-algorithm HMAC-{algorithm.upper().replace('SHA', 'SHA-')}"]
    return lines + ["ip ospf authentication message-digest", f"ip ospf authentication key-chain {chain}"]


# BFD and ECMP -------------------------------------------------------------------------------------------------------

def bfd_interface(iface: Interface, report: Report, label: str) -> List[str]:
    return bfd_text.joined_line(iface, "ios", report, label)


def global_lines(device: Device, report: Report, features: Set[str]) -> List[str]:
    lines: List[str] = []
    hop, slow = device.bfd_multihop, device.bfd_slow_timer
    if bfd_text.uses_bfd(device) or hop is not None or slow is not None:
        features.add("bfd")
    if hop is not None or slow is not None:
        report.item("system", "BFD")
    if hop is not None:
        lines.append(f"bfd multihop interval {hop[0]} min_rx {hop[1]} multiplier {hop[2]}")
    if slow is not None:
        lines.append(f"bfd slow-timer {slow}")
    fields = device.ecmp_hash
    if fields:
        report.item("system", "ECMP hashing")
        words = ["ip", "load-sharing"]
        for kind, a, b in (("address", "source-ip", "destination-ip"), ("port", "source-port", "destination-port")):
            on = [x for x, f in (("source", a), ("destination", b)) if f in fields]
            if on:
                words += [kind, "source-destination" if len(on) == 2 else on[0]]
        if "port" in words and "address" not in words:
            words[2:2] = ["address", "source-destination"]
            report.add("system", "ECMP hashing", Severity.APPROX, "ecmp-fields",
                       "NX-OS hashes on addresses whenever it hashes on ports; both addresses are added")
        lines.append(" ".join(words))
        if device.ecmp_platform:
            report.add("system", "ECMP hashing", Severity.APPROX, "ecmp-platform",
                       f"the chip family ({device.ecmp_platform}) the source names is left out")
    return lines


# RIP and IS-IS ------------------------------------------------------------------------------------------------------

def _redistribute(source: str, rm: Optional[str], used: List[bool]) -> str:
    word = "direct" if source == "connected" else source
    if not rm:
        used.append(True)
    return f"redistribute {word} route-map {rm or PERMIT_ALL}"


def rip_tag(rip: Rip) -> str:
    return "RIP"


def rip_lines(device: Device, report: Report, ind: str, used: List[bool], features: Set[str]) -> List[str]:
    rip = device.rip
    if rip is None:
        return []
    features.add("rip")
    label = igp_text.RIP_LABEL
    report.item("rip", label)
    body: List[str] = []
    for source in rip.redistribute:
        written = source
        if source == "ospf":
            written = f"ospf {device.ospf[0].process if device.ospf else 1}"
        body.append(_redistribute(written, rip.redistribute_maps.get(source), used))
    if rip.default_metric is not None:
        body.append(f"default-metric {rip.default_metric}")
    if rip.default_originate:
        body.append("default-information originate")
    if rip.version == 1:
        report.add("rip", label, Severity.APPROX, "rip-version", "NX-OS runs RIP version 2 only")
    if rip.auto_summary:
        report.add("rip", label, Severity.APPROX, "rip-summary",
                   "NX-OS does not summarise RIP routes at class borders; add summary-address on the interfaces")
    if device.platform != "nxos" and rip.networks:
        report.add("rip", label, Severity.APPROX, "rip-networks",
                   "NX-OS runs RIP on the interfaces that name it: the interfaces in the networks "
                   + ", ".join(rip.networks) + " take 'ip router rip " + rip_tag(rip) + "'")
    return [f"router rip {rip_tag(rip)}", f"{ind}address-family ipv4 unicast"] + [ind * 2 + b for b in body]


def rip_interface(device: Device, iface: Interface) -> List[str]:
    rip = device.rip
    if rip is None or not _in_networks(iface, rip.networks):
        return []
    lines = [f"ip router rip {rip_tag(rip)}"]
    if _rip_passive(rip, iface.name):
        lines.append("ip rip passive-interface")
    return lines


def _rip_passive(rip: Rip, name: str) -> bool:
    return name not in rip.active_interfaces if rip.passive_default else name in rip.passive_interfaces


def _in_networks(iface: Interface, networks: List[str]) -> bool:
    for address in iface.ipv4:
        ip = ipaddress.ip_interface(address).ip
        if any(ip in ipaddress.ip_network(n, strict=False) for n in networks):
            return True
    return False


def isis_tag(isis: Isis) -> str:
    return isis.tag or "1"


def isis_lines(device: Device, report: Report, ind: str, used: List[bool], features: Set[str]) -> List[str]:
    isis = device.isis
    if isis is None:
        return []
    features.add("isis")
    label = igp_text.isis_label(isis)
    report.item("isis", label)
    lines = [f"router isis {isis_tag(isis)}"] + [f"{ind}net {net}" for net in isis.nets]
    if isis.level:
        lines.append(f"{ind}is-type {isis.level}")
    if not isis.wide_metrics:
        report.add("isis", label, Severity.APPROX, "isis-metric-style",
                   "NX-OS sends wide metrics; neighbours that only take narrow ones must change too")
    if not isis.tag:
        report.add("isis", label, Severity.APPROX, "isis-tag", "NX-OS names the IS-IS process: written as 1")
    lines.append(f"{ind}address-family ipv4 unicast")
    lines += [ind * 2 + _redistribute(s, isis.redistribute_maps.get(s), used) for s in isis.redistribute]
    return lines


def isis_interface(device: Device, iface: Interface) -> List[str]:
    isis = device.isis
    if isis is None or not iface.isis:
        return []
    lines = [f"ip router isis {isis_tag(isis)}"]
    if iface.isis_passive:
        lines.append("isis passive-interface level-1-2")
    if iface.isis_metric is not None:
        levels = ["level-1", "level-2"] if isis.level in ("", "level-1-2") else [isis.level]
        lines += [f"isis metric {iface.isis_metric} {level}" for level in levels]
    if iface.isis_network:
        lines.append(f"isis network {iface.isis_network}")
    return lines


# MPLS ---------------------------------------------------------------------------------------------------------------

def mpls_head(device: Device) -> List[str]:
    return ["install feature-set mpls", "feature-set mpls"] if mpls_text.has_mpls(device) else []


def mpls_lines(device: Device, report: Report, port: Name, ind: str, features: Set[str]) -> List[str]:
    if not mpls_text.has_mpls(device):
        return []
    features.add("mpls ldp")
    label = "MPLS and LDP"
    report.item("mpls", label)
    report.add("mpls", label, Severity.REVIEW, "mpls-platform",
               "MPLS runs on some Nexus 9000 models only, with the MPLS feature set and a licence; check the target")
    lines = ["mpls ldp configuration"]
    name = mpls_text.router_interface(device)
    if name:
        lines.append(f"{ind}router-id {port(name)} force")
    elif device.mpls.router_id or device.mpls.router_id_interface:
        mpls_text.router_id_missing(device, report, "interface")
    return lines


# GRE tunnels and PBR ------------------------------------------------------------------------------------------------

def tunnel_lines(iface: Interface, port: Name, add: Add, features: Set[str]) -> Optional[List[str]]:
    """The lines of a GRE tunnel; None when NX-OS cannot hold it (an IPsec tunnel)."""
    if iface.tunnel_mode == "ipsec" or iface.tunnel_profile:
        return None
    features.add("tunnel")
    lines: List[str] = []
    if iface.tunnel_source:
        source = iface.tunnel_source
        lines.append(f"tunnel source {source if vpn_text.is_address(source) else port(source)}")
    if iface.tunnel_destination:
        lines.append(f"tunnel destination {iface.tunnel_destination}")
    lines.append("tunnel mode gre ip")
    if iface.tunnel_mode not in ("", "gre"):
        add(Severity.APPROX, "tunnel-mode", f"tunnel mode {iface.tunnel_mode} is written as GRE")
    return lines


def pbr_interface(device: Device, iface: Interface, add: Add, features: Set[str]) -> List[str]:
    if not iface.pbr:
        return []
    if iface.pbr not in device.route_maps:
        add(Severity.REVIEW, "pbr", f"route map {iface.pbr} for policy-based routing is not defined; left out")
        return []
    features.add("pbr")
    return [f"ip policy route-map {iface.pbr}"]


# reading ------------------------------------------------------------------------------------------------------------

def read_ospf_line(p: Ospf, w: List[str]) -> bool:
    """The NX-OS router ospf lines the IOS reader does not take."""
    if w == ["bfd"]:
        p.bfd_all = True
    elif w[0] == "table-map" and len(w) == 3 and w[2] == "filter":
        p.distribute_list_in = w[1]
    elif w[:2] == ["timers", "lsa-arrival"] and len(w) == 3 and w[2].isdigit():
        p.lsa_arrival = int(w[2])
    else:
        return False
    return True


def read_load_sharing(device: Device, w: List[str]) -> bool:
    """ip load-sharing address source|destination|source-destination [port ...] (w starts after 'ip load-sharing')."""
    fields: List[str] = []
    rest = list(w)
    while rest:
        if len(rest) < 2 or rest[0] not in ("address", "port") or \
                rest[1] not in ("source", "destination", "source-destination"):
            return False
        suffix = "-ip" if rest[0] == "address" else "-port"
        fields += [f"{x}{suffix}" for x in ("source", "destination") if x in rest[1]]
        rest = rest[2:]
    device.ecmp_hash = fields
    return True


def read_bfd(device: Device, w: List[str]) -> bool:
    """bfd multihop interval T min_rx R multiplier M | bfd slow-timer N."""
    if w[1:3] == ["multihop", "interval"] and len(w) == 8 and w[4] == "min_rx" and w[6] == "multiplier":
        device.bfd_multihop = (int(w[3]), int(w[5]), int(w[7]))
    elif w[1] == "slow-timer" and len(w) == 3 and w[2].isdigit():
        device.bfd_slow_timer = int(w[2])
    else:
        return False
    return True


class IgpReader:
    """router rip TAG and router isis TAG with their address families, and the interfaces that name them."""

    def __init__(self, device: Device) -> None:
        self.device = device
        self.rip_ports: List[str] = []

    @staticmethod
    def _direct(w: List[str]) -> List[str]:
        if w[:2] == ["redistribute", "direct"]:
            w = [w[0], "connected"] + w[2:]
        if w[0] == "redistribute" and w[-2:] == ["route-map", PERMIT_ALL]:
            w = w[:-2]
        return w

    def rip(self, children: List[List[str]], nested: Dict[int, List[List[str]]]) -> List[str]:
        """The lines of router rip TAG (children, and the lines under each address family by index) not read."""
        rip = self.device.rip = self.device.rip or Rip()
        rip.version = 2
        bad: List[str] = []
        for k, c in enumerate(children):
            if c[:3] == ["address-family", "ipv4", "unicast"]:
                for line in nested.get(k, []):
                    if not igp_text.ios_rip_line(rip, self._direct(line)):
                        bad.append(" ".join(line))
            elif not igp_text.ios_rip_line(rip, self._direct(c)):
                bad.append(" ".join(c))
        return bad

    def isis(self, tag: str, children: List[List[str]], nested: Dict[int, List[List[str]]]) -> List[str]:
        isis = self.device.isis = self.device.isis or Isis(tag)
        isis.wide_metrics = True  # NX-OS sends wide metrics
        bad: List[str] = []
        for k, c in enumerate(children):
            if c[:3] == ["address-family", "ipv4", "unicast"]:
                for line in nested.get(k, []):
                    if not igp_text.ios_isis_line(self.device, isis, self._direct(line)):
                        bad.append(" ".join(line))
            elif not igp_text.ios_isis_line(self.device, isis, self._direct(c)):
                bad.append(" ".join(c))
        return bad

    def interface_line(self, iface: Interface, w: List[str]) -> bool:
        rip = self.device.rip
        if w[:3] == ["ip", "router", "rip"] and len(w) == 4:
            self.rip_ports.append(iface.name)
        elif w == ["ip", "rip", "passive-interface"]:
            if rip is None:
                rip = self.device.rip = Rip()
            rip.passive_interfaces.append(iface.name)
        elif w[:2] == ["isis", "passive-interface"] and len(w) == 3:
            iface.isis = iface.isis_passive = True
        else:
            return False
        return True

    def finish(self) -> None:
        rip = self.device.rip
        if rip is None:
            return
        for name in self.rip_ports:
            iface = self.device.interfaces.get(name)
            for address in iface.ipv4 if iface is not None else []:
                net = str(ipaddress.ip_interface(address).network)
                if net not in rip.networks:
                    rip.networks.append(net)


def read_mpls(device: Device, w: List[str], children: List[List[str]]) -> Optional[List[int]]:
    """mpls ldp configuration / router-id IF [force]: the children not read, or None if not that block."""
    if w[1:] != ["ldp", "configuration"]:
        return None
    from . import names
    device.mpls.ldp = True
    bad = []
    for k, c in enumerate(children):
        if c[0] == "router-id" and len(c) in (2, 3) and c[2:] in ([], ["force"]):
            device.mpls.router_id_interface = names.canonical(c[1])[0]
        else:
            bad.append(k)
    return bad
