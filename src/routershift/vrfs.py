# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""VRF route leaking and multi-chassis LAG helpers that every reader and writer shares."""

from __future__ import annotations

from typing import List, Tuple

from .model import Device, VrfInfo
from .report import Report, Severity


def info(device: Device, vrf: str) -> VrfInfo:
    return device.vrf_info.setdefault(vrf, VrfInfo())


def route_target(info_: VrfInfo, direction: str, value: str) -> bool:
    """Add a route target read as import, export or both; False when the direction is unknown."""
    if direction not in ("import", "export", "both"):
        return False
    if direction in ("import", "both") and value not in info_.rt_import:
        info_.rt_import.append(value)
    if direction in ("export", "both") and value not in info_.rt_export:
        info_.rt_export.append(value)
    return True


def targets(info_: VrfInfo) -> List[Tuple[str, str]]:
    """(direction, value) pairs to write: 'both' where a value is imported and exported."""
    pairs = []
    for value in info_.rt_import:
        pairs.append(("both" if value in info_.rt_export else "import", value))
    pairs += [("export", value) for value in info_.rt_export if value not in info_.rt_import]
    return pairs


def has_leaking(device: Device) -> bool:
    return any(i.rd or i.rt_import or i.rt_export for i in device.vrf_info.values())


def no_vrfs(device: Device, report: Report, platform: str) -> None:
    for name, i in device.vrf_info.items():
        if i.rd or i.rt_import or i.rt_export:
            report.add("system", f"vrf {name}", Severity.REVIEW, "vrf-leaking",
                       f"{platform} has no VRFs; route distinguisher and route targets left out")


def mlag_members(device: Device) -> List[str]:
    return [i.name for i in device.interfaces.values() if i.mlag_id is not None]


def mlag_unsupported(device: Device, report: Report, platform: str, alternative: str) -> None:
    """Report a multi-chassis LAG pair on a target that has none the converter writes."""
    m = device.mlag
    if m is None and not mlag_members(device):
        return
    members = ", ".join(mlag_members(device)) or "no LAGs"
    report.add("interface", "multi-chassis LAG", Severity.REVIEW, "mlag-unsupported",
               f"{platform}: {alternative}; the pair (peer link {m.peer_link if m else '?'}, shared LAGs {members}) "
               "is left out")
