# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""RIP and IS-IS: readers and writers for IOS, EOS and Comware, and the reports every writer shares."""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Optional

from . import names
from .acl import wildcard_prefix
from .model import Device, Isis, Rip
from .report import Report, Severity

SUPPORTED = ("ios", "eos", "comware")
RIP_REDISTRIBUTE = ("connected", "static", "ospf")
ISIS_REDISTRIBUTE = ("connected", "static")
LEVELS = ("level-1", "level-2", "level-1-2")
RIP_LABEL = "rip"


def isis_label(isis: Isis) -> str:
    return f"isis {isis.tag}".strip()


def classful(prefix: str) -> str:
    """The classful network that holds a prefix: 10.1.0.0/16 -> 10.0.0.0/8."""
    net = ipaddress.ip_network(prefix)
    first = int(str(net.network_address).split(".")[0])
    length = 8 if first < 128 else 16 if first < 192 else 24
    return str(ipaddress.ip_network(f"{net.network_address}/{length}", strict=False))


def rip_network(word: str) -> str:
    """A RIP network statement's address as a prefix: classful (IOS, Comware) or with its length (EOS)."""
    if "/" in word:
        return str(ipaddress.ip_network(word, strict=False))
    return classful(f"{ipaddress.IPv4Address(word)}/32")


def _redistribute(target_list: List[str], maps: Dict[str, str], source: str, rest: List[str], map_word: str) -> bool:
    if rest[:1] == [map_word] and len(rest) == 2:
        maps[source] = rest[1]
    elif rest:
        return False
    target_list.append(source)
    return True


# readers -------------------------------------------------------------------------------------------------------------

def ios_rip_line(rip: Rip, w: List[str]) -> bool:
    """router rip lines in the IOS and EOS spellings."""
    n = len(w)
    if w[0] == "version" and n == 2 and w[1] in ("1", "2"):
        rip.version = int(w[1])
    elif w[0] == "network" and n == 2:
        rip.networks.append(rip_network(w[1]))
    elif w == ["passive-interface", "default"]:
        rip.passive_default = True
    elif w[0] == "passive-interface" and n >= 2:
        rip.passive_interfaces.append(names.canonical(" ".join(w[1:]))[0])
    elif w[:2] == ["no", "passive-interface"] and n >= 3:
        rip.active_interfaces.append(names.canonical(" ".join(w[2:]))[0])
    elif w[0] == "redistribute" and n >= 2 and w[1] in RIP_REDISTRIBUTE:
        rest = w[3:] if w[1] == "ospf" and n >= 3 and w[2].isdigit() else w[2:]
        return _redistribute(rip.redistribute, rip.redistribute_maps, w[1], rest, "route-map")
    elif w[0] == "default-metric" and n == 2:
        rip.default_metric = int(w[1])
    elif w == ["default-information", "originate"]:
        rip.default_originate = True
    elif w in (["auto-summary"], ["no", "auto-summary"]):
        rip.auto_summary = w[0] != "no"
    elif w == ["no", "shutdown"]:  # EOS: RIP runs
        pass
    else:
        return False
    return True


def comware_rip_line(rip: Rip, w: List[str], canonical: Callable[[str], str]) -> bool:
    """rip lines; ``canonical`` turns a Comware interface name into the model's."""
    n = len(w)
    if w[0] == "version" and n == 2 and w[1] in ("1", "2"):
        rip.version = int(w[1])
    elif w[0] == "network" and n in (2, 3):
        rip.networks.append(wildcard_prefix(w[1], w[2]) if n == 3 else rip_network(w[1]))
    elif w == ["silent-interface", "all"]:
        rip.passive_default = True
    elif w[0] == "silent-interface" and n == 2:
        rip.passive_interfaces.append(canonical(w[1]))
    elif w[:2] == ["undo", "silent-interface"] and n == 3:
        rip.active_interfaces.append(canonical(w[2]))
    elif w[0] == "import-route" and n >= 2 and w[1] in ("direct", "static", "ospf"):
        rest = w[3:] if w[1] == "ospf" and n >= 3 and w[2].isdigit() else w[2:]
        source = "connected" if w[1] == "direct" else w[1]
        return _redistribute(rip.redistribute, rip.redistribute_maps, source, rest, "route-policy")
    elif w[:2] == ["default", "cost"] and n == 3:
        rip.default_metric = int(w[2])
    elif w == ["default-route", "originate"]:
        rip.default_originate = True
    elif w in (["summary"], ["undo", "summary"]):
        rip.auto_summary = w[0] != "undo"
    else:
        return False
    return True


def ios_isis_line(device: Device, isis: Isis, w: List[str]) -> bool:
    """router isis lines in the IOS and EOS spellings."""
    n = len(w)
    if w[0] == "net" and n == 2:
        isis.nets.append(w[1])
    elif w[0] == "is-type" and n == 2 and w[1] in ("level-1", "level-1-2", "level-2-only", "level-2"):
        isis.level = "level-2" if w[1].startswith("level-2") else w[1]
    elif w[:2] == ["metric-style", "wide"] and n == 2:
        isis.wide_metrics = True
    elif w[0] == "passive-interface" and n >= 2:
        iface = device.interfaces.get(names.canonical(" ".join(w[1:]))[0])
        if iface is None:
            return False
        iface.isis = iface.isis_passive = True
    elif w[0] == "redistribute" and n >= 2 and w[1] in ISIS_REDISTRIBUTE:
        rest = w[2:]
        if rest[:1] == ["ip"]:
            rest = rest[1:]
        return _redistribute(isis.redistribute, isis.redistribute_maps, w[1], rest, "route-map")
    elif w == ["log-adjacency-changes"]:
        pass
    else:
        return False
    return True


def comware_isis_line(isis: Isis, w: List[str]) -> bool:
    n = len(w)
    if w[0] == "network-entity" and n == 2:
        isis.nets.append(w[1])
    elif w[0] == "is-level" and n == 2 and w[1] in LEVELS:
        isis.level = w[1]
    elif w[:2] == ["cost-style", "wide"] and n == 2:
        isis.wide_metrics = True
    elif w[0] == "import-route" and n >= 2 and w[1] in ("direct", "static"):
        source = "connected" if w[1] == "direct" else w[1]
        return _redistribute(isis.redistribute, isis.redistribute_maps, source, w[2:], "route-policy")
    else:
        return False
    return True


# writers -------------------------------------------------------------------------------------------------------------

def rip_networks(rip: Rip, report: Report, platform: str) -> List[str]:
    """The network statements of a target: classful addresses (IOS), prefixes (EOS), address and wildcard where
    the prefix is not classful (Comware)."""
    out: List[str] = []
    for prefix in rip.networks:
        net = ipaddress.ip_network(prefix)
        if platform == "eos":
            line = f"network {net}"
        elif platform == "comware" and str(net) != classful(prefix):
            line = f"network {net.network_address} {net.hostmask}"
        else:
            line = f"network {ipaddress.ip_network(classful(prefix)).network_address}"
            if classful(prefix) != str(net):
                report.add(RIP_LABEL, RIP_LABEL, Severity.APPROX, "rip-classful",
                           f"network {net} written as classful {classful(prefix)}: RIP runs on every interface in it")
        if line not in out:
            out.append(line)
    return out


def isis_level(isis: Isis, platform: str) -> Optional[str]:
    if not isis.level:
        return None
    if platform == "ios" and isis.level == "level-2":
        return "level-2-only"
    return isis.level


def isis_tag(isis: Isis, platform: str, report: Report) -> str:
    """The process tag a target takes: any word (IOS, EOS needs one) or a number (Comware)."""
    tag = isis.tag
    if platform == "comware" and not tag.isdigit():
        if tag:
            report.add("isis", isis_label(isis), Severity.APPROX, "isis-tag",
                       f"IS-IS process {tag} written as process 1: Comware numbers its processes")
        return "1"
    if platform == "eos" and not tag:
        return "1"
    return tag


def unsupported(device: Device, report: Report, platform: str) -> None:
    """A target that writes neither RIP nor IS-IS."""
    if device.rip is not None:
        report.skip("rip", RIP_LABEL, "rip-unsupported", f"{platform}: RIP is not written; configure it by hand")
    if device.isis is not None:
        report.skip("isis", isis_label(device.isis), "isis-unsupported", f"{platform} has no IS-IS; left out")
