# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""DHCP server helpers: address ranges and exclusions, and lease times."""

from __future__ import annotations

import ipaddress
from typing import List, Optional, Tuple

from .model import DhcpPool

Range = Tuple[str, str]


def _span(network: str) -> Tuple[int, int]:
    net = ipaddress.ip_network(network)
    if net.prefixlen >= 31:
        return int(net.network_address), int(net.broadcast_address)
    return int(net.network_address) + 1, int(net.broadcast_address) - 1


def _text(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def subtract(network: str, ranges: List[Range], excluded: List[Range]) -> List[Range]:
    """The ranges (the whole network when there are none) without the excluded addresses."""
    first, last = _span(network)
    spans = [(int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))) for a, b in ranges] or [(first, last)]
    cuts = sorted((int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))) for a, b in excluded)
    result: List[Tuple[int, int]] = []
    for low, high in spans:
        for cut_low, cut_high in cuts:
            if cut_high < low or cut_low > high:
                continue
            if cut_low > low:
                result.append((low, cut_low - 1))
            low = cut_high + 1
            if low > high:
                break
        if low <= high:
            result.append((low, high))
    return [(_text(a), _text(b)) for a, b in result]


def exclusions(pool: DhcpPool) -> List[Range]:
    """The addresses of the pool's network that its ranges leave out, as ranges."""
    if not pool.network or not pool.ranges:
        return []
    return subtract(pool.network, [], pool.ranges)


def lease_parts(seconds: int) -> Tuple[int, int, int]:
    """Days, hours, minutes."""
    return seconds // 86400, seconds % 86400 // 3600, seconds % 3600 // 60


def lease_seconds(days: int = 0, hours: int = 0, minutes: int = 0) -> int:
    return days * 86400 + hours * 3600 + minutes * 60


def label(pool: DhcpPool) -> str:
    return pool.name + (f" (vrf {pool.vrf})" if pool.vrf else "")


def prefix_len(pool: DhcpPool) -> Optional[int]:
    return ipaddress.ip_network(pool.network).prefixlen if pool.network else None
