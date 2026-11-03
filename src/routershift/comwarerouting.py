# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Comware 7 routing options: OSPF timers, filters, graceful restart and authentication, the global router ID, BFD
multihop timers and the ECMP hash. Written and read."""

from __future__ import annotations

from typing import Callable, List

from .aaa import PLACEHOLDER
from .model import Device, Interface, Ospf
from .report import Report, Severity

Add = Callable[[Severity, str, str], None]
_HASH = (("src-ip", "source-ip"), ("dest-ip", "destination-ip"), ("src-port", "source-port"),
         ("dest-port", "destination-port"))


# OSPF ------------------------------------------------------------------------------------------------------------

def ospf_lines(p: Ospf, report: Report, label: str) -> List[str]:
    lines = []
    if p.distribute_list_in:
        lines.append(f"filter-policy route-policy {p.distribute_list_in} import")
    if p.spf_timers:
        initial, hold, maximum = p.spf_timers
        seconds = max(1, min(60, round(maximum / 1000)))
        if seconds * 1000 != maximum:
            report.add("ospf", label, Severity.APPROX, "spf-timers",
                       f"Comware sets the longest SPF wait in seconds: {maximum} ms is written as {seconds} s")
        lines.append(f"spf-schedule-interval {seconds} {initial} {hold}")
    if p.lsa_arrival is not None:
        lines.append(f"lsa-arrival-interval {p.lsa_arrival}")
    if p.max_lsa:
        limit = p.max_lsa.split()[0]
        lines.append(f"lsdb-overflow-limit {limit}")
        if p.max_lsa != limit:
            report.add("ospf", label, Severity.APPROX, "max-lsa",
                       f"Comware limits the external LSAs only, without warning or ignore options: max-lsa "
                       f"{p.max_lsa} is written as lsdb-overflow-limit {limit}")
        else:
            report.add("ospf", label, Severity.APPROX, "max-lsa",
                       "Comware's lsdb-overflow-limit counts external LSAs only")
    if p.graceful_restart:
        lines.append("graceful-restart ietf")
    return lines


def read_ospf_line(p: Ospf, w: List[str]) -> bool:
    n = len(w)
    if w[:2] == ["filter-policy", "route-policy"] and n == 4 and w[3] == "import":
        p.distribute_list_in = w[2]
    elif w[0] == "spf-schedule-interval" and n == 4 and all(x.isdigit() for x in w[1:]):
        p.spf_timers = (int(w[2]), int(w[3]), int(w[1]) * 1000)
    elif w[0] == "lsa-arrival-interval" and n == 2:
        p.lsa_arrival = int(w[1])
    elif w[0] == "lsdb-overflow-limit" and n == 2 and w[1].isdigit():
        p.max_lsa = w[1]
    elif w[0] == "graceful-restart" and w[1:] in ([], ["ietf"]):
        p.graceful_restart = True
    else:
        return False
    return True


def ospf_interface(iface: Interface, add: Add) -> List[str]:
    if not iface.ospf_auth:
        return []
    add(Severity.REVIEW, "secret-placeholder",
        f"the OSPF authentication key is not carried over; replace {PLACEHOLDER} with it")
    if iface.ospf_auth == "simple":
        return [f"ospf authentication-mode simple plain {PLACEHOLDER}"]
    lines = []
    for key, algorithm in iface.ospf_keys.items() or {1: "md5"}.items():
        word = {"md5": "md5", "sha256": "hmac-sha-256"}.get(algorithm)
        if word is None:
            word = "hmac-sha-256"
            add(Severity.APPROX, "ospf-auth", f"Comware has no {algorithm.upper()} for OSPF; key {key} is written as "
                                              "HMAC-SHA-256")
        lines.append(f"ospf authentication-mode {word} {key} plain {PLACEHOLDER}")
    return lines


def read_ospf_interface(iface: Interface, w: List[str]) -> bool:
    """ospf authentication-mode simple|md5|hmac-md5|hmac-sha-256 [KEY-ID] plain|cipher KEY"""
    if w[:2] != ["ospf", "authentication-mode"] or len(w) < 4:
        return False
    if w[2] == "simple" and len(w) == 5 and w[3] in ("plain", "cipher"):
        iface.ospf_auth = "simple"
        return True
    if w[2] in ("md5", "hmac-md5", "hmac-sha-256") and len(w) == 6 and w[3].isdigit() and w[4] in ("plain", "cipher"):
        iface.ospf_auth = "message-digest"
        iface.ospf_keys[int(w[3])] = "sha256" if w[2] == "hmac-sha-256" else "md5"
        return True
    return False


# global routing settings -------------------------------------------------------------------------------------------

def global_lines(device: Device, report: Report) -> List[str]:
    lines = []
    if device.system.router_id:
        report.item("system", "router ID")
        lines.append(f"router id {device.system.router_id}")
    hop, slow = device.bfd_multihop, device.bfd_slow_timer
    if hop is not None or slow is not None:
        report.item("system", "BFD")
    if hop is not None:
        lines += [f"bfd multi-hop min-transmit-interval {hop[0]}", f"bfd multi-hop min-receive-interval {hop[1]}",
                  f"bfd multi-hop detect-multiplier {hop[2]}"]
    if slow is not None:
        report.add("system", "BFD", Severity.APPROX, "bfd-slow-timer",
                   f"Comware has no BFD slow timer ({slow} ms); left out")
    if device.ecmp_hash:
        report.item("system", "ECMP hashing")
        words = [cw for cw, field in _HASH if field in device.ecmp_hash]
        lines.append("ip load-sharing mode per-flow " + " ".join(words))
        if device.ecmp_platform:
            report.add("system", "ECMP hashing", Severity.APPROX, "ecmp-platform",
                       f"the chip family ({device.ecmp_platform}) the source names is left out")
    return lines


def read_global(device: Device, w: List[str]) -> bool:
    n = len(w)
    if w[:2] == ["router", "id"] and n == 3:
        device.system.router_id = w[2]
    elif w[:2] == ["bfd", "multi-hop"] and n == 4 and w[3].isdigit():
        hop = list(device.bfd_multihop or (300, 300, 3))
        index = {"min-transmit-interval": 0, "min-receive-interval": 1, "detect-multiplier": 2}.get(w[2])
        if index is None:
            return False
        hop[index] = int(w[3])
        device.bfd_multihop = (hop[0], hop[1], hop[2])
    elif w[:4] == ["ip", "load-sharing", "mode", "per-flow"] and n > 4:
        names = dict(_HASH)
        if any(x not in names for x in w[4:]):
            return False
        device.ecmp_hash = [names[x] for x in w[4:]]
    else:
        return False
    return True
