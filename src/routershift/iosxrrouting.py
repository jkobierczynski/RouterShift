# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""RIP and the DHCP server for IOS-XR, written and read back.

IOS-XR runs RIP on the interfaces listed under ``router rip``, not on networks, so the networks of the source become
the interfaces that have an address in them, and the reader turns those interfaces back into their networks. The
DHCP server is a ``pool vrf V ipv4 NAME`` with the address ranges, and a server profile under ``dhcp ipv4`` with the
options, bound to the interfaces in the pool's network.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Optional, Tuple

from . import dhcp as dhcp_text
from . import igp as igp_text
from .confparse import Node
from .model import Device, DhcpPool, Interface, Rip
from .report import Report, Severity

IND = " "
Children = Callable[[Node, Callable[[List[str], Node], bool], str], None]


def _in(iface: Interface, network: str) -> bool:
    net = ipaddress.ip_network(network, strict=False)
    return any(ipaddress.ip_interface(a).ip in net for a in iface.ipv4)


def _passive(rip: Rip, name: str) -> bool:
    return name not in rip.active_interfaces if rip.passive_default else name in rip.passive_interfaces


# RIP --------------------------------------------------------------------------------------------------------------


def rip_lines(device: Device, report: Report, port: Callable[[str], str],
              redistribute: Callable[[str, Optional[str]], str]) -> List[str]:
    rip = device.rip
    if rip is None:
        return []
    label = igp_text.RIP_LABEL
    report.item("rip", label)
    body: List[str] = []
    for iface in device.interfaces.values():
        if iface.vrf or not any(_in(iface, n) for n in rip.networks):
            continue
        body.append(f"interface {port(iface.name)}")
        if _passive(rip, iface.name):
            body.append(f"{IND}passive-interface")
        body.append("!")
    for source in rip.redistribute:
        body.append(redistribute(source, rip.redistribute_maps.get(source)))
    if rip.default_metric is not None:
        body.append(f"default-metric {rip.default_metric}")
    if rip.default_originate:
        body.append("default-information originate")
    if rip.version == 1:
        report.add("rip", label, Severity.APPROX, "rip-version",
                   "IOS-XR sends RIP version 2; set 'send version 1' on the interfaces if the neighbors need it")
    if rip.auto_summary:
        report.add("rip", label, Severity.APPROX, "rip-summary",
                   "IOS-XR does not summarise RIP routes at class borders; the auto-summary is left out")
    if rip.networks and device.platform != "iosxr":
        report.add("rip", label, Severity.APPROX, "rip-networks",
                   "IOS-XR runs RIP on the interfaces it lists: the interfaces with an address in "
                   + ", ".join(rip.networks) + " are listed")
    return ["router rip"] + [IND + b for b in body] + ["!"]


def read_rip(device: Device, node: Node, canonical: Callable[[str], str], children: Children,
             names: List[str]) -> bool:
    """router rip; the interfaces it lists go to names, for finish_rip."""
    if node.words != ["router", "rip"]:
        return False
    rip = device.rip = Rip(version=2, auto_summary=False)

    def iface_line(name: str, c: List[str]) -> bool:
        if c == ["passive-interface"]:
            rip.passive_interfaces.append(name)
            return True
        return False

    def line(c: List[str], n: Node) -> bool:
        if c[0] == "interface" and len(c) == 2:
            name = canonical(c[1])
            names.append(name)
            children(n, lambda cc, nn: iface_line(name, cc), f"router rip / {n.text}")
            return True
        if c[0] == "redistribute" and len(c) in (2, 3, 4, 5):
            source = c[1]
            rest = c[2:]
            if source in ("ospf", "bgp", "isis") and rest:
                rest = rest[1:]
            if rest[:1] == ["route-policy"] and len(rest) == 2:
                rip.redistribute_maps[source] = rest[1]
            elif rest:
                return False
            rip.redistribute.append(source)
            return True
        if c[0] == "default-metric" and len(c) == 2:
            rip.default_metric = int(c[1])
            return True
        if c == ["default-information", "originate"]:
            rip.default_originate = True
            return True
        return False

    children(node, line, "router rip")
    return True


def finish_rip(device: Device, names: List[str]) -> None:
    """The networks of the interfaces under router rip, once the interfaces are read."""
    rip = device.rip
    if rip is None:
        return
    active = [n for n in names if n not in rip.passive_interfaces]
    if len(rip.passive_interfaces) > len(active):  # most interfaces passive: passive by default, as IOS writes it
        rip.passive_default, rip.passive_interfaces, rip.active_interfaces = True, [], active
    for name in names:
        iface = device.interfaces.get(name)
        for address in iface.ipv4 if iface is not None else []:
            network = str(ipaddress.ip_interface(address).network)
            if network not in rip.networks:
                rip.networks.append(network)


# DHCP server ------------------------------------------------------------------------------------------------------


def served(device: Device) -> List[DhcpPool]:
    """The pools with a network; a host binding has none and is not written."""
    return [p for p in device.dhcp_pools if p.network]


def _profile(pool: DhcpPool) -> str:
    return pool.name


def pool_lines(device: Device, report: Report) -> List[str]:
    """The address pools, written at the top level."""
    out: List[str] = []
    for pool in served(device):
        report.item("dhcp", dhcp_text.label(pool))
        out.append(f"pool vrf {pool.vrf or 'default'} ipv4 {pool.name}")
        out.append(f"{IND}network {pool.network}")
        ranges = pool.ranges or [_hosts(pool.network)]
        out += [f"{IND}address-range {first} {last}" for first, last in ranges]
        out.append("!")
    return out


def _hosts(network: str) -> Tuple[str, str]:
    net = ipaddress.ip_network(network, strict=False)
    if net.num_addresses <= 2:
        return str(net[0]), str(net[-1])
    return str(net[1]), str(net[-2])


def server_lines(device: Device, report: Report, port: Callable[[str], str]) -> Tuple[List[str], List[str]]:
    """The server profiles, and the interfaces bound to them, for the 'dhcp ipv4' block."""
    profiles: List[str] = []
    bound: List[str] = []
    for pool in device.dhcp_pools:
        if not pool.network:
            report.skip("dhcp", dhcp_text.label(pool), "dhcp-network",
                        "a pool without a network (a host binding) is not written")
    for pool in served(device):
        name = _profile(pool)
        body = [f"pool {pool.name}"]
        if pool.default_routers:
            body.append("default-router " + " ".join(pool.default_routers))
        if pool.dns_servers:
            body.append("dns-server " + " ".join(pool.dns_servers))
        if pool.domain_name:
            body.append(f"domain-name {pool.domain_name}")
        if pool.lease_seconds == 0:
            body.append("lease infinite")
        elif pool.lease_seconds is not None:
            days, hours, minutes = dhcp_text.lease_parts(pool.lease_seconds)
            body.append(f"lease {days} {hours} {minutes}")
        profiles += [f"profile {name} server"] + [IND + b for b in body] + ["!"]
        ifaces = [i for i in device.interfaces.values()
                  if i.vrf == pool.vrf and _in(i, pool.network) and not i.helper_addresses]
        if not ifaces:
            report.add("dhcp", dhcp_text.label(pool), Severity.REVIEW, "dhcp-interface",
                       "no interface has an address in the pool's network; bind the server profile to the "
                       "interface by hand ('interface X server profile " + name + "')")
        bound += [f"interface {port(i.name)} server profile {name}" for i in ifaces]
    return profiles, bound


def read_pool(device: Device, node: Node, children: Children) -> bool:
    w = node.words
    if len(w) != 5 or w[1] != "vrf" or w[3] != "ipv4":
        return False
    pool = DhcpPool(name=w[4], vrf="" if w[2] == "default" else w[2])

    def line(c: List[str], n: Node) -> bool:
        if c[0] == "network" and len(c) == 2:
            pool.network = str(ipaddress.ip_network(c[1], strict=False))
            return True
        if c[0] == "address-range" and len(c) == 3:
            pool.ranges.append((c[1], c[2]))
            return True
        return False

    children(node, line, node.text)
    if pool.network and pool.ranges == [_hosts(pool.network)]:
        pool.ranges = []
    device.dhcp_pools.append(pool)
    return True


def read_server_profile(device: Device, name: str, node: Node, children: Children) -> None:
    settings: Dict[str, List[str]] = {}

    def line(c: List[str], n: Node) -> bool:
        if c[0] in ("pool", "default-router", "dns-server", "domain-name", "lease") and len(c) >= 2:
            settings[c[0]] = c[1:]
            return True
        return False

    children(node, line, node.text)
    pool_name = (settings.get("pool") or [name])[0]
    pool = next((p for p in device.dhcp_pools if p.name == pool_name), None)
    if pool is None:
        pool = DhcpPool(name=pool_name)
        device.dhcp_pools.append(pool)
    pool.default_routers = settings.get("default-router", [])
    pool.dns_servers = settings.get("dns-server", [])
    pool.domain_name = " ".join(settings.get("domain-name", []))
    lease = settings.get("lease")
    if lease == ["infinite"]:
        pool.lease_seconds = 0
    elif lease:
        parts = [int(x) for x in lease] + [0, 0]
        pool.lease_seconds = dhcp_text.lease_seconds(parts[0], parts[1], parts[2])
