# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Spanning tree helpers that every writer shares: bridge priorities for the mode the target runs."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .model import Device, Interface, StpMode
from .report import Report, Severity

PER_VLAN = (StpMode.PVST, StpMode.RAPID_PVST)


def priorities(device: Device, written: Optional[StpMode], report: Report) -> Tuple[Dict[int, int], Dict[int, int]]:
    """(MST instance -> priority, VLAN -> priority) to write for the mode the target runs."""
    s = device.stp
    if written in PER_VLAN:
        if s.vlan_priority or not s.priority:
            return {}, defined_vlan_priorities(device, report)
        result = {}
        for vlan in sorted(device.vlans) or [1]:
            instance = next((n for n, vlans in s.instances.items() if vlan in vlans), 0)
            priority = s.priority.get(instance, s.priority.get(0))
            if priority is not None:
                result[vlan] = priority
        report.add("system", "bridge priority", Severity.APPROX, "stp-priority",
                   "the instance priorities are written per VLAN for the VLANs defined; a VLAN added later takes the "
                   "default priority")
        return {}, result
    if s.priority:
        result = dict(s.priority)
        if written in (StpMode.STP, StpMode.RSTP) and set(result) - {0}:
            report.add("system", "bridge priority", Severity.REVIEW, "stp-priority",
                       f"{written.value} runs one tree: only the priority of instance 0 is written")
            result = {0: result[0]} if 0 in result else {}
        return result, {}
    if s.vlan_priority:
        values = set(s.vlan_priority.values())
        lowest = min(values)
        if len(values) == 1:
            report.add("system", "bridge priority", Severity.APPROX, "stp-priority",
                       f"the per-VLAN priority {lowest} is written for the one tree the target runs")
        else:
            report.add("system", "bridge priority", Severity.REVIEW, "stp-priority",
                       f"the VLANs had different priorities (load sharing per VLAN); the lowest, {lowest}, is written "
                       "for all; use MST instances to share the load")
        return {0: lowest}, {}
    return {}, {}


def defined_vlan_priorities(device: Device, report: Report) -> Dict[int, int]:
    """Per-VLAN priorities for the VLANs the configuration defines (and VLAN 1): a source that sets them for a whole
    range ("spanning-tree vlan 1-4094 priority 4096") would otherwise become thousands of lines."""
    s = device.stp
    keep = set(device.vlans) | {1}
    result = {v: p for v, p in s.vlan_priority.items() if v in keep}
    dropped = len(s.vlan_priority) - len(result)
    if dropped:
        report.add("system", "bridge priority", Severity.APPROX, "stp-priority",
                   f"the per-VLAN priorities are written for the {len(result)} VLANs defined, not for the {dropped} "
                   "other VLANs of the range; a VLAN added later takes the default priority")
    return result


def region(device: Device, written: Optional[StpMode], report: Report) -> bool:
    """Whether to write the MST region; a note when the target runs another mode."""
    s = device.stp
    if not (s.region or s.revision is not None or s.instances):
        return False
    if written == StpMode.MSTP:
        report.item("system", "mst region")
        return True
    report.add("system", "mst region", Severity.REVIEW, "stp-region",
               f"the MST region is not written: the target runs {written.value if written else 'its default mode'}")
    return False


def has_port_settings(iface: Interface) -> bool:
    return bool(iface.stp_guard or iface.stp_bpdufilter or iface.stp_cost is not None
                or iface.stp_port_priority is not None)


def vlan_text(vlans: List[int]) -> str:
    """10,20,30-40"""
    parts: List[str] = []
    ordered = sorted(set(vlans))
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        parts.append(str(ordered[i]) if i == j else f"{ordered[i]}-{ordered[j]}")
        i = j + 1
    return ",".join(parts)
